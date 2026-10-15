"""
P-384 hybrids: ``P-384+ML-KEM-1024`` and ``P-384+ML-DSA-87`` (and its ``-v2`` form), for estates that
hold CNSA 1.0 P-384 keys. Same conventions as the P-256 hybrids, with the curve's own sizes:
public key = SEC1 point (97 B) / raw ``x || y`` (96 B), secret key = PKCS#8 PEM text, the ECDH output
is used whole (48 B), ECDSA signs with SHA-384, and the ``-v2`` classical half is raw ``r || s`` (96 B, low-S).
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP384R1,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from quantum_safe import HybridKEM, HybridSign
from quantum_safe.exceptions import VerificationError
from quantum_safe.protocols.envelope import Envelope
from quantum_safe.signatures import _v2

pytestmark = pytest.mark.requires_liboqs

P384_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973


class TestKem:
    def test_round_trip_and_sizes(self) -> None:
        kem = HybridKEM("P-384", "ML-KEM-1024")
        assert kem.algorithm == "P-384+ML-KEM-1024"
        pair = kem.generate_keypair()
        ct, secret = kem.encapsulate(pair.public)
        assert kem.decapsulate(pair.secret, ct) == secret
        # packed: u16 length || 97-byte SEC1 point || ML-KEM-1024 public key (1568)
        assert len(pair.public.raw_bytes) == 2 + 97 + 1568

    def test_other_combinations_are_not_offered(self) -> None:
        with pytest.raises(ValueError):
            HybridKEM("P-384", "ML-KEM-768")
        with pytest.raises(ValueError):
            HybridKEM("P-384", "ML-KEM-512")

    def test_envelope_seal_and_open(self) -> None:
        pair = HybridKEM("P-384", "ML-KEM-1024").generate_keypair()
        sealed = Envelope.seal(b"secret", pair.public, aad=b"x")
        assert sealed.algorithm == "P-384+ML-KEM-1024"
        assert Envelope.open(sealed, pair.secret, expected_aad=b"x") == b"secret"
        with pytest.raises(InvalidTag):
            Envelope.open(sealed, pair.secret, expected_aad=b"y")

    def test_rewrap_from_p256_to_p384(self) -> None:
        old = HybridKEM("P-256", "ML-KEM-768").generate_keypair()
        new = HybridKEM("P-384", "ML-KEM-1024").generate_keypair()
        sealed = Envelope.seal(b"migrate", old.public)
        moved = Envelope.rewrap(sealed, old.secret, new.public)
        assert Envelope.open(moved, new.secret) == b"migrate"

    def test_a_ciphertext_for_another_key_does_not_decapsulate(self) -> None:
        kem = HybridKEM("P-384", "ML-KEM-1024")
        a, b = kem.generate_keypair(), kem.generate_keypair()
        ct, secret = kem.encapsulate(a.public)
        try:
            other = kem.decapsulate(b.secret, ct)
        except Exception:  # noqa: BLE001 - an error is also a correct outcome
            return
        assert other != secret


class TestSignatures:
    def test_v1_round_trip_context_and_independent_ecdsa_check(self) -> None:
        signer = HybridSign("P-384", "ML-DSA-87")
        assert signer.algorithm == "P-384+ML-DSA-87"
        pair = signer.generate_keypair()
        sm = signer.sign(b"payload", pair.secret, context=b"ctx")
        signer.verify(sm, pair.public, context=b"ctx")
        with pytest.raises(VerificationError):
            signer.verify(sm, pair.public, context=b"other")

    def test_v2_round_trip_blob_layout_and_independent_ecdsa_check(self) -> None:
        signer = HybridSign("P-384", "ML-DSA-87-v2")
        assert signer.algorithm == "P-384+ML-DSA-87-v2"
        pair = signer.generate_keypair()
        sm = signer.sign(b"payload", pair.secret, context=b"ctx")
        signer.verify(sm, pair.public, context=b"ctx")
        blob = sm.signature
        c_sig, p_sig = blob[:96], blob[96:]
        assert len(c_sig) == 96 and len(p_sig) == 4627
        # the classical half verifies with a plain ECDSA P-384 / SHA-384 implementation
        c_pub, _ = _v2.unpack_components(pair.public.raw_bytes)
        point = EllipticCurvePublicNumbers(
            int.from_bytes(c_pub[:48], "big"), int.from_bytes(c_pub[48:], "big"), SECP384R1()
        ).public_key()
        m2 = _v2.signed_input("P-384+ML-DSA-87-v2", b"ctx", b"payload")
        r, s = int.from_bytes(c_sig[:48], "big"), int.from_bytes(c_sig[48:], "big")
        assert s <= P384_ORDER // 2  # low-S only
        point.verify(encode_dss_signature(r, s), _v2._classical_input(m2), ECDSA(hashes.SHA384()))

    def test_v2_refuses_the_high_s_twin_and_tampering(self) -> None:
        signer = HybridSign("P-384", "ML-DSA-87-v2")
        pair = signer.generate_keypair()
        sm = signer.sign(b"payload", pair.secret)
        blob = sm.signature
        s = int.from_bytes(blob[48:96], "big")
        twin = blob[:48] + (P384_ORDER - s).to_bytes(48, "big") + blob[96:]
        with pytest.raises(VerificationError):
            signer.verify(replace(sm, signature=twin), pair.public)
        flipped = bytearray(blob)
        flipped[-1] ^= 1
        with pytest.raises(VerificationError):
            signer.verify(replace(sm, signature=bytes(flipped)), pair.public)

    def test_other_combinations_are_not_offered(self) -> None:
        with pytest.raises(ValueError):
            HybridSign("P-384", "ML-DSA-65")
        with pytest.raises(ValueError):
            HybridSign("P-384", "ML-DSA-44")

    def test_default_suite_is_unchanged(self) -> None:
        assert HybridSign().algorithm == "Ed25519+ML-DSA-65-v2"
