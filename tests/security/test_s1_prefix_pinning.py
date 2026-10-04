"""S1: the signature prefix length must match the verifier's hedging mode.

The signed bytes are ``len(ctx) || ctx || prefix || message`` and the blob is
``len(prefix) (1 byte) || prefix || payload``. The length byte is not signed,
so before the fix whoever supplied the blob chose where the prefix ended and
the message began: moving bytes from the message into the prefix produced a
signature that verified for a suffix of the signed message.

These tests use real liboqs; the mock backend accepts every signature and
would make the forgery test meaningless.
"""

from __future__ import annotations

import dataclasses
import warnings

import pytest

from quantum_safe.exceptions import VerificationError
from quantum_safe.signatures.core import Sign
from quantum_safe.signatures.hybrid import HybridSign
from quantum_safe.types.signatures import SignedMessage

pytestmark = pytest.mark.requires_liboqs

MESSAGE = b"PAY alice 5 USD\nPAY mallory 1000000 USD\n"


def _signer(kind: str, hedged: bool) -> Sign | HybridSign:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if kind == "single":
            return Sign("ML-DSA-44", hedged=hedged)
        return HybridSign("Ed25519", "ML-DSA-44", hedged=hedged)


def _shift(sm: SignedMessage, k: int) -> SignedMessage:
    """Move the first k message bytes into the prefix (the S1 forgery)."""
    blob = sm.signature
    plen = blob[0]
    prefix = blob[1 : 1 + plen]
    payload = blob[1 + plen :]
    forged_blob = bytes([plen + k]) + prefix + sm.message[:k] + payload
    return dataclasses.replace(sm, message=sm.message[k:], signature=forged_blob)


def _unshift(sm: SignedMessage, k: int) -> SignedMessage:
    """Move the last k prefix bytes into the message (the reverse forgery)."""
    blob = sm.signature
    plen = blob[0]
    prefix = blob[1 : 1 + plen]
    payload = blob[1 + plen :]
    forged_blob = bytes([plen - k]) + prefix[: plen - k] + payload
    return dataclasses.replace(sm, message=prefix[plen - k :] + sm.message, signature=forged_blob)


@pytest.fixture(scope="module", params=["single", "hybrid"])
def kind(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.mark.parametrize("hedged", [True, False])
def test_honest_signature_verifies_on_matching_verifier(kind: str, hedged: bool) -> None:
    signer = _signer(kind, hedged)
    kp = signer.generate_keypair()
    sm = signer.sign(MESSAGE, kp.secret)
    signer.verify(sm, kp.public)


@pytest.mark.parametrize("hedged", [True, False])
def test_suffix_forgery_is_rejected_for_every_shift(kind: str, hedged: bool) -> None:
    signer = _signer(kind, hedged)
    kp = signer.generate_keypair()
    sm = signer.sign(MESSAGE, kp.secret)
    # k = len(MESSAGE) would leave an empty message, which SignedMessage
    # refuses at construction; that case is covered through verify_bytes.
    for k in range(1, len(MESSAGE)):
        with pytest.raises(VerificationError):
            signer.verify(_shift(sm, k), kp.public)


def test_prefixed_message_forgery_is_rejected(kind: str) -> None:
    """A zero-length prefix makes ``R || M`` the 'message'; must be rejected."""
    signer = _signer(kind, True)
    kp = signer.generate_keypair()
    sm = signer.sign(MESSAGE, kp.secret)
    for k in (1, 16, 32):
        with pytest.raises(VerificationError):
            signer.verify(_unshift(sm, k), kp.public)


def test_hedged_signature_fails_on_unhedged_verifier(kind: str) -> None:
    signer = _signer(kind, True)
    kp = signer.generate_keypair()
    sm = signer.sign(MESSAGE, kp.secret)
    with pytest.raises(VerificationError):
        _signer(kind, False).verify(sm, kp.public)


def test_unhedged_signature_fails_on_hedged_verifier(kind: str) -> None:
    signer = _signer(kind, False)
    kp = signer.generate_keypair()
    sm = signer.sign(MESSAGE, kp.secret)
    with pytest.raises(VerificationError):
        _signer(kind, True).verify(sm, kp.public)


@pytest.mark.parametrize("hedged", [True, False])
def test_verify_bytes_pins_prefix_length(hedged: bool) -> None:
    signer = _signer("single", hedged)
    kp = signer.generate_keypair()
    sm = signer.sign(MESSAGE, kp.secret, context=b"ctx")
    signer.verify_bytes(sm.message, sm.signature, kp.public, context=b"ctx")
    forged = _shift(sm, 5)
    with pytest.raises(VerificationError):
        signer.verify_bytes(forged.message, forged.signature, kp.public, context=b"ctx")
    # Whole message moved into the prefix: empty message must not verify.
    plen = sm.signature[0]
    whole = bytes([plen + len(MESSAGE)]) + sm.signature[1 : 1 + plen] + MESSAGE
    whole += sm.signature[1 + plen :]
    with pytest.raises(VerificationError):
        signer.verify_bytes(b"", whole, kp.public, context=b"ctx")
    with pytest.raises(VerificationError):
        _signer("single", not hedged).verify_bytes(
            sm.message, sm.signature, kp.public, context=b"ctx"
        )


@pytest.mark.parametrize("blob", [b"", b"\x05abc", b"\x20" + b"\x00" * 31])
def test_truncated_blob_is_rejected(blob: bytes) -> None:
    signer = _signer("single", True)
    kp = signer.generate_keypair()
    with pytest.raises(VerificationError):
        signer.verify_bytes(MESSAGE, blob, kp.public)


# ---------------------------------------------------------------------------
# JWT path: the verifier is told its hedging mode, mirroring JWTSigner.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hedged", [True, False])
def test_jwt_round_trip_with_matching_mode(hedged: bool) -> None:
    from quantum_safe.protocols.jwt import JWTSigner, JWTVerifier

    signer = _signer("single", hedged)
    kp = signer.generate_keypair()
    token = JWTSigner(kp, hedged=hedged).sign({"sub": "u1"})
    assert JWTVerifier(kp.public, hedged=hedged).verify(token)["sub"] == "u1"


@pytest.mark.parametrize("hedged", [True, False])
def test_x509_cosig_verifies_in_the_signer_mode(kind: str, hedged: bool) -> None:
    """HybridCertificateBuilder.build(signer=...) accepts any signer, so the
    co-signature verifier must be told the mode, like JWTVerifier."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from quantum_safe.protocols.x509 import HybridCertificateBuilder

    signer = _signer(kind, hedged)
    kp = signer.generate_keypair()
    builder = HybridCertificateBuilder(
        subject_cn="svc.internal",
        classical_private_key=Ed25519PrivateKey.generate(),
        pqc_keypair=kp,
    )
    cert_pem, bundle = builder.build(signer=signer)
    HybridCertificateBuilder.verify_cosig(cert_pem, bundle, kp.public, hedged=hedged)
    with pytest.raises(VerificationError):
        HybridCertificateBuilder.verify_cosig(cert_pem, bundle, kp.public, hedged=not hedged)


def test_jwt_unhedged_token_needs_unhedged_verifier() -> None:
    from quantum_safe.protocols.jwt import JWTSigner, JWTVerifier

    kp = _signer("single", False).generate_keypair()
    token = JWTSigner(kp, hedged=False).sign({"sub": "u1"})
    with pytest.raises(VerificationError):
        JWTVerifier(kp.public).verify(token)
