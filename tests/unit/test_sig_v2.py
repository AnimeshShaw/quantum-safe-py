"""Signature format ``-v2`` (finding F1), byte-compatible with quantum-safe-ts.

Spec (quantum-safe-ts ``sig/v2.rs``):
  M2 = u8(len(algo)) || algo || u8(len(ctx)) || ctx || message
  ML-DSA half: plain FIPS 204 ML-DSA.Sign with native context b"quantum-safe-sig-v2" over M2.
  classical half: signs LABEL || 0x00 || M2 (Ed25519, or ECDSA P-256/SHA-256, raw r||s, low-S only).
  hybrid blob = classical signature (64 bytes) || ML-DSA signature. No prefix, no CBOR wrapper.
  keys: the same material as the base suite, tagged ``<base>-v2``.
"""

from __future__ import annotations

import warnings

import pytest

from quantum_safe import HybridSign
from quantum_safe.exceptions import UnsupportedAlgorithm, VerificationError
from quantum_safe.signatures import Sign
from quantum_safe.types import PublicKey
from quantum_safe.types.signatures import SignedMessage

pytestmark = pytest.mark.requires_liboqs

LABEL = b"quantum-safe-sig-v2"
MLDSA = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}
SINGLE = [f"{p}-v2" for p in MLDSA]
HYBRID = [
    ("Ed25519", "ML-DSA-44"),
    ("Ed25519", "ML-DSA-65"),
    ("Ed25519", "ML-DSA-87"),
    ("P-256", "ML-DSA-44"),
    ("P-256", "ML-DSA-65"),
]
HYBRID_IDS = [f"{c}+{p}-v2" for c, p in HYBRID]
MESSAGE = b"PAY alice 5 USD\nPAY mallory 1000000 USD\n"


def _make(name: str) -> Sign | HybridSign:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if "+" in name:
            classical, pqc = name.split("+", 1)
            return HybridSign(classical, pqc)
        return Sign(name)


def m2(algo: str, ctx: bytes, message: bytes) -> bytes:
    a = algo.encode()
    return bytes([len(a)]) + a + bytes([len(ctx)]) + ctx + message


ALL = SINGLE + HYBRID_IDS


@pytest.mark.parametrize("name", ALL)
def test_round_trip_and_key_tagging(name: str) -> None:
    s = _make(name)
    kp = s.generate_keypair()
    assert kp.public.algorithm == name and kp.secret.algorithm == name
    sm = s.sign(MESSAGE, kp.secret, context=b"app")
    assert sm.algorithm == name
    s.verify(sm, kp.public, context=b"app")


@pytest.mark.parametrize("name", ALL)
def test_blob_has_no_prefix_and_a_fixed_length(name: str) -> None:
    s = _make(name)
    kp = s.generate_keypair()
    sm = s.sign(MESSAGE, kp.secret)
    pqc = name.split("+")[-1].removesuffix("-v2")
    expected = MLDSA[pqc] + (64 if "+" in name else 0)
    assert len(sm.signature) == expected
    assert sm.is_hybrid == ("+" in name)


@pytest.mark.parametrize("name", ALL)
def test_ml_dsa_half_is_plain_fips_204_with_the_label_as_context(name: str) -> None:
    """Rebuild M2 and verify the ML-DSA half with liboqs directly."""
    import oqs

    from quantum_safe.signatures._v2 import unpack_components

    s = _make(name)
    kp = s.generate_keypair()
    sm = s.sign(MESSAGE, kp.secret, context=b"app")
    pqc = name.split("+")[-1].removesuffix("-v2")
    blob = sm.signature[64:] if "+" in name else sm.signature
    pub = unpack_components(kp.public.raw_bytes)[1] if "+" in name else kp.public.raw_bytes
    v = oqs.Signature(pqc)
    msg = m2(name, b"app", MESSAGE)
    assert v.verify_with_ctx_str(msg, blob, LABEL, pub)
    assert not v.verify_with_ctx_str(msg, blob, b"", pub)  # not the empty context
    assert not v.verify(msg, blob, pub)


@pytest.mark.parametrize("classical", ["Ed25519", "P-256"])
def test_classical_half_signs_label_then_m2(classical: str) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        EllipticCurvePublicNumbers,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    from quantum_safe.signatures._v2 import unpack_components

    name = f"{classical}+ML-DSA-44-v2"
    s = _make(name)
    kp = s.generate_keypair()
    sm = s.sign(MESSAGE, kp.secret, context=b"c")
    c_sig = sm.signature[:64]
    c_pub = unpack_components(kp.public.raw_bytes)[0]
    signed = LABEL + b"\x00" + m2(name, b"c", MESSAGE)
    if classical == "Ed25519":
        Ed25519PublicKey.from_public_bytes(c_pub).verify(c_sig, signed)
    else:
        pub = EllipticCurvePublicNumbers(
            int.from_bytes(c_pub[:32], "big"), int.from_bytes(c_pub[32:], "big"), SECP256R1()
        ).public_key()
        r, s_val = int.from_bytes(c_sig[:32], "big"), int.from_bytes(c_sig[32:], "big")
        pub.verify(encode_dss_signature(r, s_val), signed, ECDSA(hashes.SHA256()))
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        assert s_val <= order // 2  # low-S


@pytest.mark.parametrize("name", ["ML-DSA-44-v2", "Ed25519+ML-DSA-44-v2", "P-256+ML-DSA-44-v2"])
def test_message_suffix_forgery_is_impossible(name: str) -> None:
    s = _make(name)
    kp = s.generate_keypair()
    sm = s.sign(MESSAGE, kp.secret)
    for k in range(1, len(MESSAGE)):
        forged = SignedMessage(
            message=MESSAGE[k:], signature=sm.signature, algorithm=name, context=sm.context
        )
        with pytest.raises(VerificationError):
            s.verify(forged, kp.public, context=b"")


@pytest.mark.parametrize("name", ["ML-DSA-65-v2", "Ed25519+ML-DSA-65-v2"])
def test_tampering_and_context_are_detected(name: str) -> None:
    s = _make(name)
    kp = s.generate_keypair()
    sm = s.sign(MESSAGE, kp.secret, context=b"login")
    bad = bytearray(sm.signature)
    bad[len(bad) // 2] ^= 1
    for forged in (
        SignedMessage(
            message=MESSAGE + b"!", signature=sm.signature, algorithm=name, context=b"login"
        ),
        SignedMessage(message=MESSAGE, signature=bytes(bad), algorithm=name, context=b"login"),
        SignedMessage(
            message=MESSAGE, signature=sm.signature + b"\x00", algorithm=name, context=b"login"
        ),
        SignedMessage(
            message=MESSAGE, signature=sm.signature[1:], algorithm=name, context=b"login"
        ),
        SignedMessage(message=MESSAGE, signature=sm.signature, algorithm=name, context=b"payments"),
    ):
        with pytest.raises(VerificationError):
            s.verify(forged, kp.public, context=forged.context)
    with pytest.raises(VerificationError):
        s.verify(sm, kp.public, context=b"payments")  # expected context differs


def test_v1_and_v2_do_not_cross() -> None:
    s1, s2 = _make("ML-DSA-44"), _make("ML-DSA-44-v2")
    k1, k2 = s1.generate_keypair(), s2.generate_keypair()
    sm1 = s1.sign(MESSAGE, k1.secret)
    sm2 = s2.sign(MESSAGE, k2.secret)
    with pytest.raises(UnsupportedAlgorithm):
        s2.verify(sm1, k1.public, context=b"")
    with pytest.raises(UnsupportedAlgorithm):
        s1.verify(sm2, k2.public, context=b"")
    # the same key material under the other tag must not verify the other format
    as_v1 = PublicKey(raw=k2.public.raw_bytes, algorithm="ML-DSA-44")
    relabelled = SignedMessage(message=MESSAGE, signature=sm2.signature, algorithm="ML-DSA-44")
    with pytest.raises(VerificationError):
        s1.verify(relabelled, as_v1, context=b"")


@pytest.mark.parametrize(
    "bad", ["SLH-DSA-SHAKE-128f-v2", "ML-DSA-65-v3", "P-256+ML-DSA-87-v2", "ML-DSA-65-v2-v2"]
)
def test_unsupported_v2_identifiers(bad: str) -> None:
    with pytest.raises((UnsupportedAlgorithm, ValueError)):
        _make(bad)


def test_v2_is_always_hedged_inside_ml_dsa() -> None:
    with pytest.raises(ValueError, match="hedged"):
        Sign("ML-DSA-65-v2", hedged=False)
    s = _make("ML-DSA-65-v2")
    kp = s.generate_keypair()
    assert s.sign(MESSAGE, kp.secret).signature != s.sign(MESSAGE, kp.secret).signature


def test_p256_high_s_twin_is_rejected() -> None:
    s = _make("P-256+ML-DSA-44-v2")
    kp = s.generate_keypair()
    sm = s.sign(MESSAGE, kp.secret)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    r = sm.signature[:32]
    high = (order - int.from_bytes(sm.signature[32:64], "big")).to_bytes(32, "big")
    twin = SignedMessage(
        message=MESSAGE, signature=r + high + sm.signature[64:], algorithm=sm.algorithm
    )
    s.verify(sm, kp.public, context=b"")
    with pytest.raises(VerificationError):
        s.verify(twin, kp.public, context=b"")


def test_serialization_round_trip() -> None:
    s = _make("Ed25519+ML-DSA-65-v2")
    kp = s.generate_keypair()
    sm = s.sign(MESSAGE, kp.secret, context=b"ctx")
    again = SignedMessage.from_cbor(sm.to_cbor())
    pub = PublicKey.from_cbor(kp.public.to_cbor())
    assert pub.algorithm == "Ed25519+ML-DSA-65-v2"
    s.verify(again, pub, context=b"ctx")
