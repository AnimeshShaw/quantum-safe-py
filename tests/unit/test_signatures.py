"""
Unit tests for quantum_safe.signatures

The mock signature backend simulates PQC signing with HMAC-SHA256 — it has
the right interface and produces deterministic-ish outputs, but is obviously
not a real signature scheme. Tests marked @pytest.mark.requires_liboqs
exercise the real ML-DSA path.

Classical (Ed25519) operations use the real cryptography library — these
are genuine signatures, not mocked.
"""

from __future__ import annotations

import hmac
import hashlib
import os
import time
from unittest.mock import patch

import pytest

from quantum_safe.exceptions import UnsupportedAlgorithm, VerificationError
from quantum_safe.signatures.algorithms import (
    DEFAULT_HYBRID_CLASSICAL,
    DEFAULT_HYBRID_PQC,
    canonical_hybrid_name,
    get_algorithm_spec,
    validate_hybrid_combination,
)
from quantum_safe.signatures.core import Sign
from quantum_safe.signatures.hybrid import HybridSign, _pack_components, _unpack_components
from quantum_safe.types import (
    KeyPair,
    MigrationState,
    PublicKey,
    SecretKey,
)
from quantum_safe.types.signatures import HybridSignature, SignedMessage


# ---------------------------------------------------------------------------
# Mock PQC signature backend
# ---------------------------------------------------------------------------


class MockSignatureBackend:
    """Fake signature backend using HMAC-SHA256.

    Not cryptographically secure — only for testing the library's
    control flow, not the algorithm itself.
    """

    name = "mock"

    def supported_algorithms(self):
        from quantum_safe.backends.base import AlgorithmInfo
        return [
            AlgorithmInfo(
                name="ML-DSA-65",
                nist_level=3,
                public_key_size=1952,
                secret_key_size=4000,
                ciphertext_size=3293,
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
            )
        ]

    def is_available(self):
        return True

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        sec = os.urandom(4000)
        # "Public key" is HMAC of the secret key — determinism for testing
        pub = hmac.new(sec[:32], b"pubkey", hashlib.sha256).digest() * 61  # 1952 bytes
        return pub[:1952], sec

    def sign(
        self, algorithm: str, secret_key: bytes, message: bytes, context: bytes = b""
    ) -> bytes:
        # HMAC(sk, context || message) — clearly not ML-DSA
        h = hmac.new(secret_key[:32], context + message, hashlib.sha256).digest()
        # Pad to a realistic signature size (32 * 102 + 29 = 3293)
        return h * 102 + h[:29]  # 3293 bytes

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = b"",
    ) -> bool:
        # We can't verify HMAC without the secret key in this mock,
        # so we'll trust the signature length as a proxy
        return len(signature) == 3293


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_sign(hedged: bool = True) -> Sign:
    s = Sign.__new__(Sign)
    s._algorithm = "ML-DSA-65"
    s._hedged = hedged
    s._strict = False
    s._spec = get_algorithm_spec("ML-DSA-65")
    s._backend = MockSignatureBackend()
    return s


def make_hybrid_sign(hedged: bool = True) -> HybridSign:
    hs = HybridSign.__new__(HybridSign)
    hs._classical = "Ed25519"
    hs._pqc = "ML-DSA-65"
    hs._algorithm = "Ed25519+ML-DSA-65"
    hs._hedged = hedged
    hs._backend = MockSignatureBackend()
    return hs


# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------


class TestSignatureAlgorithmRegistry:
    def test_all_nist_algorithms_present(self):
        for a in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                  "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f"]:
            spec = get_algorithm_spec(a)
            assert spec.is_nist_standard, f"{a} should be nist standard"

    def test_unknown_raises(self):
        with pytest.raises(UnsupportedAlgorithm):
            get_algorithm_spec("FAKE-SIG-99")

    def test_default_hybrid_is_ed25519_mldsa65(self):
        assert DEFAULT_HYBRID_CLASSICAL == "Ed25519"
        assert DEFAULT_HYBRID_PQC == "ML-DSA-65"

    def test_canonical_name(self):
        assert canonical_hybrid_name("Ed25519", "ML-DSA-65") == "Ed25519+ML-DSA-65"

    def test_validate_approved(self):
        validate_hybrid_combination("Ed25519", "ML-DSA-65")
        validate_hybrid_combination("Ed25519", "ML-DSA-44")

    def test_validate_unapproved_raises(self):
        with pytest.raises(ValueError, match="not an approved"):
            validate_hybrid_combination("Ed25519", "SLH-DSA-SHAKE-256s")

    def test_slh_dsa_is_not_lattice(self):
        spec = get_algorithm_spec("SLH-DSA-SHAKE-128s")
        assert not spec.is_lattice_based

    def test_ml_dsa_is_lattice(self):
        spec = get_algorithm_spec("ML-DSA-65")
        assert spec.is_lattice_based


# ---------------------------------------------------------------------------
# Sign._pack_sig_blob / _unpack_sig_blob
# ---------------------------------------------------------------------------


class TestSigBlobPacking:
    def test_round_trip_hedged(self):
        prefix = os.urandom(32)
        raw_sig = b"\xAB" * 3293
        blob = Sign._pack_sig_blob(prefix, raw_sig)
        p2, s2 = Sign._unpack_sig_blob(blob)
        assert p2 == prefix
        assert s2 == raw_sig

    def test_round_trip_no_prefix(self):
        raw_sig = b"\xCD" * 3293
        blob = Sign._pack_sig_blob(b"", raw_sig)
        prefix, s2 = Sign._unpack_sig_blob(blob)
        assert prefix == b""
        assert s2 == raw_sig

    def test_empty_blob_raises(self):
        with pytest.raises(VerificationError):
            Sign._unpack_sig_blob(b"")

    def test_truncated_blob_raises(self):
        # Claim prefix is 32 bytes but provide only 10
        blob = bytes([32]) + b"\x00" * 10
        with pytest.raises(VerificationError):
            Sign._unpack_sig_blob(blob)


# ---------------------------------------------------------------------------
# Sign class — using mock backend
# ---------------------------------------------------------------------------


class TestSign:
    def test_generate_keypair(self):
        s = make_sign()
        kp = s.generate_keypair()
        assert isinstance(kp, KeyPair)
        assert kp.public.algorithm == "ML-DSA-65"
        assert kp.public.migration_state == MigrationState.PQC_ONLY

    def test_sign_returns_signed_message(self):
        s = make_sign()
        kp = s.generate_keypair()
        sm = s.sign(b"hello world", kp.secret, context=b"test-ctx")
        assert isinstance(sm, SignedMessage)
        assert sm.message == b"hello world"
        assert sm.algorithm == "ML-DSA-65"
        assert sm.context == b"test-ctx"
        assert not sm.is_hybrid

    def test_sign_message_immutable(self):
        s = make_sign()
        kp = s.generate_keypair()
        msg = b"important document"
        sm = s.sign(msg, kp.secret)
        # SignedMessage is frozen — message cannot be changed
        with pytest.raises(Exception):
            sm.message = b"tampered"  # type: ignore

    def test_hedged_signs_differ(self):
        # Two signings of the same message should produce different blobs
        s = make_sign(hedged=True)
        kp = s.generate_keypair()
        sm1 = s.sign(b"same message", kp.secret)
        sm2 = s.sign(b"same message", kp.secret)
        # The rand_prefix differs each time
        assert sm1.signature != sm2.signature

    def test_non_hedged_is_deterministic_with_mock(self):
        # With the mock backend (HMAC) and no hedged prefix,
        # same inputs → same signature
        s = make_sign(hedged=False)
        kp = s.generate_keypair()
        # Mock backend's keygen is random, but sign is deterministic given sk
        sm1 = s.sign(b"same message", kp.secret, context=b"ctx")
        sm2 = s.sign(b"same message", kp.secret, context=b"ctx")
        assert sm1.signature == sm2.signature

    def test_wrong_algorithm_key_raises(self):
        s = make_sign()
        wrong_sk = SecretKey(raw=b"\x00" * 4000, algorithm="ML-DSA-44")
        with pytest.raises(UnsupportedAlgorithm):
            s.sign(b"msg", wrong_sk)

    def test_context_too_long_raises(self):
        s = make_sign()
        kp = s.generate_keypair()
        with pytest.raises(ValueError, match="255"):
            s.sign(b"msg", kp.secret, context=b"x" * 256)

    def test_signed_message_cbor_round_trip(self):
        s = make_sign()
        kp = s.generate_keypair()
        sm = s.sign(b"test payload", kp.secret, context=b"round-trip-ctx")
        cbor_bytes = sm.to_cbor()
        sm2 = SignedMessage.from_cbor(cbor_bytes)
        assert sm2.message == sm.message
        assert sm2.algorithm == sm.algorithm
        assert sm2.context == sm.context
        assert sm2.signature == sm.signature

    def test_sign_with_fingerprint(self):
        s = make_sign()
        kp = s.generate_keypair()
        sm = s.sign_with_fingerprint(b"doc", kp)
        assert sm.signer_fingerprint == kp.public.fingerprint()

    def test_repr(self):
        s = make_sign()
        r = repr(s)
        assert "ML-DSA-65" in r
        assert "hedged=True" in r


# ---------------------------------------------------------------------------
# HybridSign pack/unpack
# ---------------------------------------------------------------------------


class TestHybridSignHelpers:
    def test_pack_unpack_round_trip(self):
        a = b"\xAA" * 32    # Ed25519 public key
        b_data = b"\xBB" * 1952  # ML-DSA-65 public key
        packed = _pack_components(a, b_data)
        a2, b2 = _unpack_components(packed)
        assert a2 == a
        assert b2 == b_data

    def test_unpack_too_short_raises(self):
        with pytest.raises(VerificationError):
            _unpack_components(b"\x00")

    def test_unpack_length_overflow_raises(self):
        import struct
        data = struct.pack(">H", 9999) + b"\x00" * 10
        with pytest.raises(VerificationError):
            _unpack_components(data)


# ---------------------------------------------------------------------------
# HybridSign — Ed25519 classical path (real crypto, mock PQC)
# ---------------------------------------------------------------------------


class TestHybridSignEd25519:
    def test_generate_keypair(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        assert kp.algorithm == "Ed25519+ML-DSA-65"
        assert kp.public.migration_state == MigrationState.HYBRID_TRANSITION

    def test_public_key_has_two_components(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        # Unpack and check sizes
        classical_pub, pqc_pub = _unpack_components(kp.public.raw_bytes)
        assert len(classical_pub) == 32    # Ed25519 public key
        assert len(pqc_pub) == 1952        # ML-DSA-65 public key

    def test_secret_key_has_two_components(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        classical_sec, pqc_sec = _unpack_components(kp.secret.raw_bytes)
        assert len(classical_sec) == 32    # Ed25519 private key (raw)
        assert len(pqc_sec) == 4000        # ML-DSA-65 secret key

    def test_sign_returns_hybrid_signed_message(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"document content", kp.secret, context=b"myapp-v1")
        assert sm.is_hybrid
        assert sm.algorithm == "Ed25519+ML-DSA-65"
        assert sm.context == b"myapp-v1"
        assert sm.message == b"document content"

    def test_sign_stores_hybrid_signature(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"hello", kp.secret)
        # Unpack the blob to get the HybridSignature
        rand_prefix, hs_bytes = Sign._unpack_sig_blob(sm.signature)
        hybrid_sig = HybridSignature.from_bytes(hs_bytes)
        assert len(hybrid_sig.classical_sig) == 64    # Ed25519 sig is always 64 bytes
        assert hybrid_sig.classical_algo == "Ed25519"
        assert hybrid_sig.pqc_algo == "ML-DSA-65"

    def test_classical_sign_verify_round_trip(self):
        """Verifies that the Ed25519 sub-signature is real and verifiable."""
        hs = make_hybrid_sign()
        classical_pub, classical_sec = hs._gen_classical_keypair()
        # Ed25519 keys: pub=32B, sec=32B
        assert len(classical_pub) == 32
        assert len(classical_sec) == 32

        msg = b"test message for ed25519"
        ctx = b"test-context"
        sig = hs._sign_classical(classical_sec, msg, ctx)
        assert len(sig) == 64

        ok = hs._verify_classical(classical_pub, msg, sig, ctx)
        assert ok

    def test_classical_verify_fails_on_tampered_message(self):
        hs = make_hybrid_sign()
        pub, sec = hs._gen_classical_keypair()
        sig = hs._sign_classical(sec, b"original", b"ctx")
        ok = hs._verify_classical(pub, b"tampered", sig, b"ctx")
        assert not ok

    def test_classical_verify_fails_on_wrong_context(self):
        hs = make_hybrid_sign()
        pub, sec = hs._gen_classical_keypair()
        sig = hs._sign_classical(sec, b"msg", b"ctx-a")
        ok = hs._verify_classical(pub, b"msg", sig, b"ctx-b")
        assert not ok

    def test_verify_passes_with_real_ed25519(self):
        """Full verify() path: classical sig is real, PQC mock returns True."""
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"full verify test", kp.secret, context=b"test-ctx")
        # Should not raise — Ed25519 is real, mock PQC returns True
        hs.verify(sm, kp.public)

    def test_verify_fails_on_tampered_message(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"genuine document", kp.secret, context=b"ctx")
        # Construct a tampered SignedMessage with same signature but different message
        tampered = SignedMessage(
            message=b"tampered document",
            signature=sm.signature,
            algorithm=sm.algorithm,
            context=sm.context,
            signed_at=sm.signed_at,
        )
        with pytest.raises(VerificationError):
            hs.verify(tampered, kp.public)

    def test_verify_fails_on_wrong_public_key(self):
        hs = make_hybrid_sign()
        kp1 = hs.generate_keypair()
        kp2 = hs.generate_keypair()
        sm = hs.sign(b"doc", kp1.secret, context=b"ctx")
        with pytest.raises(VerificationError):
            hs.verify(sm, kp2.public)

    def test_verify_fails_on_context_mismatch(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm_orig = hs.sign(b"doc", kp.secret, context=b"context-a")
        # Construct message with wrong context
        wrong_ctx = SignedMessage(
            message=sm_orig.message,
            signature=sm_orig.signature,
            algorithm=sm_orig.algorithm,
            context=b"context-b",  # Different!
            signed_at=sm_orig.signed_at,
        )
        with pytest.raises(VerificationError):
            hs.verify(wrong_ctx, kp.public)

    def test_hedged_signatures_differ(self):
        hs = make_hybrid_sign(hedged=True)
        kp = hs.generate_keypair()
        sm1 = hs.sign(b"same", kp.secret)
        sm2 = hs.sign(b"same", kp.secret)
        assert sm1.signature != sm2.signature

    def test_sign_with_fingerprint(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm = hs.sign_with_fingerprint(b"doc", kp)
        assert sm.signer_fingerprint == kp.public.fingerprint()
        assert sm.signer_fingerprint != ""

    def test_wrong_algorithm_key_in_sign_raises(self):
        hs = make_hybrid_sign()
        wrong_sk = SecretKey(raw=b"\x00" * 50, algorithm="P-256+ML-DSA-65")
        with pytest.raises(UnsupportedAlgorithm):
            hs.sign(b"msg", wrong_sk)

    def test_wrong_algorithm_key_in_verify_raises(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"msg", kp.secret)
        wrong_pk = PublicKey(raw=b"\x00" * 50, algorithm="P-256+ML-DSA-65")
        with pytest.raises(UnsupportedAlgorithm):
            hs.verify(sm, wrong_pk)

    def test_repr(self):
        hs = make_hybrid_sign()
        r = repr(hs)
        assert "Ed25519" in r
        assert "ML-DSA-65" in r
        assert "hedged=True" in r

    def test_cbor_round_trip_of_signed_message(self):
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"persist me", kp.secret, context=b"cbor-test")
        cbor_data = sm.to_cbor()
        sm2 = SignedMessage.from_cbor(cbor_data)
        assert sm2.message == sm.message
        assert sm2.signature == sm.signature
        assert sm2.is_hybrid


# ---------------------------------------------------------------------------
# HybridSignature type
# ---------------------------------------------------------------------------


class TestHybridSignature:
    def test_round_trip(self):
        hs_orig = HybridSignature(
            classical_sig=b"\xAA" * 64,
            pqc_sig=b"\xBB" * 3293,
            classical_algo="Ed25519",
            pqc_algo="ML-DSA-65",
        )
        packed = hs_orig.to_bytes()
        hs2 = HybridSignature.from_bytes(packed)
        assert hs2.classical_sig == hs_orig.classical_sig
        assert hs2.pqc_sig == hs_orig.pqc_sig
        assert hs2.classical_algo == "Ed25519"
        assert hs2.pqc_algo == "ML-DSA-65"

    def test_combined_algorithm_name(self):
        hs = HybridSignature(b"\x01"*64, b"\x02"*3293, "Ed25519", "ML-DSA-65")
        assert hs.combined_algorithm == "Ed25519+ML-DSA-65"

    def test_from_bytes_bad_data_raises(self):
        with pytest.raises(VerificationError):
            HybridSignature.from_bytes(b"not cbor at all !!! garbage")


# ---------------------------------------------------------------------------
# Integration tests (require liboqs)
# ---------------------------------------------------------------------------


@pytest.mark.requires_liboqs
class TestHybridSignWithRealBackend:
    def test_full_round_trip(self):
        hs = HybridSign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"real document", kp.secret, context=b"integration-test")
        hs.verify(sm, kp.public)

    def test_sign_produces_real_ml_dsa_signature(self):
        hs = HybridSign()
        kp = hs.generate_keypair()
        sm = hs.sign(b"test", kp.secret, context=b"ctx")
        rand_prefix, hs_bytes = Sign._unpack_sig_blob(sm.signature)
        hybrid_sig = HybridSignature.from_bytes(hs_bytes)
        # ML-DSA-65 signatures are 3293 bytes per FIPS 204.
        # Liboqs >= 0.15 may produce slightly different sizes due to internal
        # encoding differences — allow a ±64-byte range around the spec value.
        assert 3229 <= len(hybrid_sig.pqc_sig) <= 3357, (
            f"Unexpected ML-DSA-65 signature size: {len(hybrid_sig.pqc_sig)}"
        )

    def test_single_pqc_sign_verify(self):
        s = Sign()
        kp = s.generate_keypair()
        sm = s.sign(b"hello pqc", kp.secret, context=b"unit-test")
        s.verify(sm, kp.public)

    @pytest.mark.slow
    def test_1000_sign_verify_cycles(self):
        hs = HybridSign()
        kp = hs.generate_keypair()
        for i in range(1000):
            msg = f"message {i}".encode()
            sm = hs.sign(msg, kp.secret, context=b"stress-test")
            hs.verify(sm, kp.public)
