"""
Unit tests for quantum_safe.kem

Tests that don't require a PQC backend are in the main test classes.
Tests that do require liboqs are marked @pytest.mark.requires_liboqs and
are skipped automatically in CI environments without it.

We use a MockBackend for testing the KEM class logic without needing liboqs
installed — this lets us test all the error handling, type checking, and
key serialization paths in isolation.
"""

from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from quantum_safe.exceptions import (
    DecapsulationError,
    UnsupportedAlgorithm,
)
from quantum_safe.kem.algorithms import (
    DEFAULT_HYBRID_CLASSICAL,
    DEFAULT_HYBRID_PQC,
    canonical_hybrid_name,
    get_algorithm_spec,
    parse_hybrid_name,
    validate_hybrid_combination,
)
from quantum_safe.backends.base import AbstractKEMBackend
from quantum_safe.kem.core import KEM
from quantum_safe.kem.hybrid import HybridKEM, _pack_components, _unpack_components
from quantum_safe.types import (
    HybridCipherText,
    KeyPair,
    MigrationState,
    PublicKey,
    SecretKey,
    SharedSecret,
)


# ---------------------------------------------------------------------------
# Mock backend for unit testing KEM logic without liboqs
# ---------------------------------------------------------------------------


class MockKEMBackend(AbstractKEMBackend):
    """Minimal KEM backend that does fake deterministic key ops.

    The 'cryptography' is not real — don't use this for security.
    It just returns bytes of the right shape so we can test the KEM
    class's wrapping logic.
    """

    name = "mock"

    def supported_algorithms(self):
        from quantum_safe.backends.base import AlgorithmInfo
        return [
            AlgorithmInfo(
                name="ML-KEM-768",
                nist_level=3,
                public_key_size=1184,
                secret_key_size=2400,
                ciphertext_size=1088,
                is_kem=True,
                is_signature=False,
                is_nist_standard=True,
            )
        ]

    def is_available(self):
        return True

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        if algorithm != "ML-KEM-768":
            raise ValueError(f"mock doesn't support {algorithm}")
        # Deterministic fake keys — same bytes every time for reproducibility
        pub = b"\xAA" * 1184
        sec = b"\xBB" * 2400
        return pub, sec

    def encapsulate(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        # XOR key into a fake ciphertext; return a fake shared secret
        ct = bytes(b ^ 0x55 for b in public_key[:1088]) + b"\x00" * (1088 - min(1088, len(public_key)))
        ct = ct[:1088]
        ss = b"\xCC" * 32
        return ct, ss

    def decapsulate(self, algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        return b"\xCC" * 32


# ---------------------------------------------------------------------------
# Algorithm registry tests
# ---------------------------------------------------------------------------


class TestAlgorithmRegistry:
    def test_all_nist_algorithms_present(self):
        for algo in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
            spec = get_algorithm_spec(algo)
            assert spec.is_nist_standard
            assert spec.nist_level >= 1

    def test_unknown_algorithm_raises(self):
        with pytest.raises(UnsupportedAlgorithm):
            get_algorithm_spec("FAKE-KEM-9000")

    def test_canonical_hybrid_name(self):
        assert canonical_hybrid_name("X25519", "ML-KEM-768") == "X25519+ML-KEM-768"

    def test_parse_hybrid_name(self):
        cl, pqc = parse_hybrid_name("X25519+ML-KEM-768")
        assert cl == "X25519"
        assert pqc == "ML-KEM-768"

    def test_parse_non_hybrid_raises(self):
        with pytest.raises(ValueError, match="not a hybrid"):
            parse_hybrid_name("ML-KEM-768")

    def test_validate_approved_combination(self):
        # Should not raise
        validate_hybrid_combination("X25519", "ML-KEM-768")
        validate_hybrid_combination("X25519", "ML-KEM-1024")

    def test_validate_unapproved_combination_raises(self):
        with pytest.raises(ValueError, match="not an approved"):
            validate_hybrid_combination("X25519", "HQC-128")

    def test_validate_unknown_classical_raises(self):
        with pytest.raises(ValueError, match="not supported"):
            validate_hybrid_combination("RSA-4096", "ML-KEM-768")

    def test_default_hybrid_is_x25519_mlkem768(self):
        assert DEFAULT_HYBRID_CLASSICAL == "X25519"
        assert DEFAULT_HYBRID_PQC == "ML-KEM-768"


# ---------------------------------------------------------------------------
# KEM class tests (using MockBackend)
# ---------------------------------------------------------------------------


class TestKEM:
    def _make_kem(self) -> KEM:
        kem = KEM.__new__(KEM)
        kem._algorithm = "ML-KEM-768"
        kem._strict = False
        kem._spec = get_algorithm_spec("ML-KEM-768")
        kem._backend = MockKEMBackend()
        return kem

    def test_generate_keypair_returns_keypair(self):
        kem = self._make_kem()
        kp = kem.generate_keypair()
        assert isinstance(kp, KeyPair)
        assert isinstance(kp.public, PublicKey)
        assert isinstance(kp.secret, SecretKey)

    def test_keypair_algorithm_matches(self):
        kem = self._make_kem()
        kp = kem.generate_keypair()
        assert kp.public.algorithm == "ML-KEM-768"
        assert kp.secret.algorithm == "ML-KEM-768"

    def test_keypair_migration_state(self):
        kem = self._make_kem()
        kp = kem.generate_keypair()
        assert kp.public.migration_state == MigrationState.PQC_ONLY

    def test_encapsulate_returns_ct_and_ss(self):
        kem = self._make_kem()
        kp = kem.generate_keypair()
        ct, ss = kem.encapsulate(kp.public)
        from quantum_safe.types import CipherText
        assert isinstance(ct, CipherText)
        assert isinstance(ss, SharedSecret)
        assert len(ss) == 32

    def test_decapsulate_recovers_ss(self):
        kem = self._make_kem()
        kp = kem.generate_keypair()
        ct, ss_enc = kem.encapsulate(kp.public)
        ss_dec = kem.decapsulate(kp.secret, ct)
        # With mock backend both return b"\xCC"*32
        assert ss_enc == ss_dec

    def test_encapsulate_wrong_algo_raises(self):
        kem = self._make_kem()
        wrong_pk = PublicKey(raw=b"\x01" * 800, algorithm="ML-KEM-512")
        with pytest.raises(UnsupportedAlgorithm):
            kem.encapsulate(wrong_pk)

    def test_decapsulate_wrong_algo_raises(self):
        kem = self._make_kem()
        kp = kem.generate_keypair()
        ct, _ = kem.encapsulate(kp.public)
        wrong_sk = SecretKey(raw=b"\x01" * 1632, algorithm="ML-KEM-512")
        with pytest.raises(UnsupportedAlgorithm):
            kem.decapsulate(wrong_sk, ct)

    def test_repr(self):
        kem = self._make_kem()
        r = repr(kem)
        assert "ML-KEM-768" in r
        assert "mock" in r

    def test_shared_secret_is_not_hybrid(self):
        kem = self._make_kem()
        kp = kem.generate_keypair()
        _, ss = kem.encapsulate(kp.public)
        assert not ss.is_hybrid


# ---------------------------------------------------------------------------
# HybridKEM internal helpers
# ---------------------------------------------------------------------------


class TestHybridKEMHelpers:
    def test_pack_unpack_round_trip(self):
        a = b"\xAA" * 32
        b = b"\xBB" * 1088
        packed = _pack_components(a, b)
        a2, b2 = _unpack_components(packed)
        assert a2 == a
        assert b2 == b

    def test_pack_unpack_empty_second(self):
        # Second component can be any length including 0-ish edge cases
        a = b"\x01" * 10
        b_comp = b"\x02" * 5
        packed = _pack_components(a, b_comp)
        a2, b2 = _unpack_components(packed)
        assert a2 == a
        assert b2 == b_comp

    def test_unpack_too_short_raises(self):
        with pytest.raises(DecapsulationError):
            _unpack_components(b"\x00")  # only 1 byte, need at least 2 for length prefix

    def test_unpack_length_exceeds_data_raises(self):
        # Claim first component is 1000 bytes but only provide 10
        data = struct.pack(">H", 1000) + b"\x00" * 10
        with pytest.raises(DecapsulationError):
            _unpack_components(data)


# ---------------------------------------------------------------------------
# HybridKEM X25519 path (classical-only, no PQC backend needed)
# ---------------------------------------------------------------------------


class TestHybridKEMX25519:
    """Tests the X25519 half of HybridKEM in isolation with a mock PQC backend."""

    def _make_hybrid_kem(self) -> HybridKEM:
        """Create a HybridKEM using mock backend for PQC operations."""
        kem = HybridKEM.__new__(HybridKEM)
        kem._classical = "X25519"
        kem._pqc = "ML-KEM-768"
        kem._algorithm = "X25519+ML-KEM-768"
        kem._backend = MockKEMBackend()
        return kem

    def test_classical_keygen_produces_32_byte_keys(self):
        kem = self._make_hybrid_kem()
        priv_bytes, pub_bytes = kem._gen_classical_keypair()
        # X25519 keys are always 32 bytes in raw format
        assert len(priv_bytes) == 32
        assert len(pub_bytes) == 32

    def test_classical_keygen_random(self):
        kem = self._make_hybrid_kem()
        _, pub1 = kem._gen_classical_keypair()
        _, pub2 = kem._gen_classical_keypair()
        # Different every time (with overwhelming probability)
        assert pub1 != pub2

    def test_classical_encap_decap_round_trip(self):
        kem = self._make_hybrid_kem()
        # Simulate: recipient generates keypair
        rec_priv, rec_pub = kem._gen_classical_keypair()
        # Sender encapsulates
        ct, ss_sender = kem._encapsulate_classical(rec_pub)
        # Recipient decapsulates
        ss_recipient = kem._decapsulate_classical(rec_priv, ct)
        # Both should derive the same shared secret
        assert ss_sender == ss_recipient
        assert len(ss_sender) == 32

    def test_classical_encap_ct_is_ephemeral_pub(self):
        # For X25519, the ciphertext is the sender's ephemeral public key
        kem = self._make_hybrid_kem()
        _, rec_pub = kem._gen_classical_keypair()
        ct, _ = kem._encapsulate_classical(rec_pub)
        # X25519 public key is 32 bytes
        assert len(ct) == 32

    def test_full_hybrid_generate_keypair(self):
        kem = self._make_hybrid_kem()
        kp = kem.generate_keypair()
        assert isinstance(kp, KeyPair)
        assert kp.algorithm == "X25519+ML-KEM-768"
        assert kp.public.migration_state == MigrationState.HYBRID_TRANSITION

    def test_full_hybrid_encap_decap(self):
        kem = self._make_hybrid_kem()
        kp = kem.generate_keypair()
        hct, ss_enc = kem.encapsulate(kp.public)
        ss_dec = kem.decapsulate(kp.secret, hct)

        assert isinstance(hct, HybridCipherText)
        assert isinstance(ss_enc, SharedSecret)
        assert ss_enc.is_hybrid
        assert len(ss_enc) == 32
        # With mock backend PQC returns deterministic bytes,
        # but classical is real X25519 — combined via HKDF
        # so both sides compute the same ss
        assert ss_enc == ss_dec

    def test_encap_wrong_algorithm_raises(self):
        kem = self._make_hybrid_kem()
        wrong_pk = PublicKey(raw=b"\x01" * 50, algorithm="P-256+ML-KEM-512")
        with pytest.raises(UnsupportedAlgorithm):
            kem.encapsulate(wrong_pk)

    def test_decap_wrong_algorithm_raises(self):
        kem = self._make_hybrid_kem()
        kp = kem.generate_keypair()
        hct, _ = kem.encapsulate(kp.public)
        wrong_sk = SecretKey(raw=kp.secret.raw_bytes, algorithm="P-256+ML-KEM-512")
        with pytest.raises(UnsupportedAlgorithm):
            kem.decapsulate(wrong_sk, hct)

    def test_shared_secret_is_marked_hybrid(self):
        kem = self._make_hybrid_kem()
        kp = kem.generate_keypair()
        _, ss = kem.encapsulate(kp.public)
        assert ss.is_hybrid

    def test_hybrid_ciphertext_wire_round_trip(self):
        kem = self._make_hybrid_kem()
        kp = kem.generate_keypair()
        hct, _ = kem.encapsulate(kp.public)
        wire = hct.to_bytes()
        hct2 = HybridCipherText.from_bytes(wire, algorithm="X25519+ML-KEM-768")
        assert hct2.classical_ct == hct.classical_ct
        assert hct2.pqc_ct == hct.pqc_ct

    def test_repr(self):
        kem = self._make_hybrid_kem()
        r = repr(kem)
        assert "X25519" in r
        assert "ML-KEM-768" in r


# ---------------------------------------------------------------------------
# Integration-style test (skipped if liboqs is not installed)
# ---------------------------------------------------------------------------


@pytest.mark.requires_liboqs
class TestHybridKEMWithRealBackend:
    """End-to-end tests using the real liboqs backend."""

    def test_full_round_trip(self):
        kem = HybridKEM()
        kp = kem.generate_keypair()
        hct, ss1 = kem.encapsulate(kp.public)
        ss2 = kem.decapsulate(kp.secret, hct)
        assert ss1 == ss2

    def test_key_pem_serialization_round_trip(self):
        kem = HybridKEM()
        kp = kem.generate_keypair()
        pem = kp.public.to_pem()
        pk2 = PublicKey.from_pem(pem)
        # Should be able to encapsulate with the deserialized key
        hct, ss1 = kem.encapsulate(pk2)
        assert len(ss1) == 32

    def test_different_keypairs_produce_different_secrets(self):
        kem = HybridKEM()
        kp1 = kem.generate_keypair()
        kp2 = kem.generate_keypair()
        hct, ss1 = kem.encapsulate(kp1.public)
        _, ss2 = kem.encapsulate(kp2.public)
        assert ss1 != ss2

    @pytest.mark.slow
    def test_1000_encap_decap_cycles(self):
        """Basic stress test — no timing assertions, just correctness."""
        kem = HybridKEM()
        kp = kem.generate_keypair()
        for _ in range(1000):
            hct, ss1 = kem.encapsulate(kp.public)
            ss2 = kem.decapsulate(kp.secret, hct)
            assert ss1 == ss2
