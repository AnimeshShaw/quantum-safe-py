"""S2: the verifier states the context it expects.

Before the fix, verify(signed_message, public_key) took the context from the
SignedMessage itself, so a signature made for one purpose (context b"login")
verified for any application that called verify(), because the message
carries its own context. The documented domain separation was not enforced.

Now verify(..., context=...) compares the message's context with the
expected one (constant time) and raises VerificationError on mismatch.
Omitting context keeps the old behaviour for one release and emits a
DeprecationWarning.
"""

from __future__ import annotations

import warnings

import pytest

from quantum_safe.exceptions import VerificationError
from quantum_safe.signatures.core import Sign
from quantum_safe.signatures.hybrid import HybridSign

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module", params=["single", "hybrid"])
def setup(request: pytest.FixtureRequest):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        signer = (
            Sign("ML-DSA-44") if request.param == "single" else HybridSign("Ed25519", "ML-DSA-44")
        )
    kp = signer.generate_keypair()
    sm = signer.sign(b"transfer 5", kp.secret, context=b"login")
    return signer, kp, sm


def test_expected_context_passes_without_warning(setup) -> None:
    signer, kp, sm = setup
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        signer.verify(sm, kp.public, context=b"login")


@pytest.mark.parametrize("expected", [b"payments", b"", b"login\x00", b"LOGIN"])
def test_other_context_is_rejected(setup, expected: bytes) -> None:
    """A signature made for "login" must not verify for another purpose."""
    signer, kp, sm = setup
    with pytest.raises(VerificationError):
        signer.verify(sm, kp.public, context=expected)


def test_omitting_context_warns_and_keeps_old_behaviour(setup) -> None:
    signer, kp, sm = setup
    with pytest.warns(DeprecationWarning, match="context"):
        signer.verify(sm, kp.public)


def test_empty_context_round_trip() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        signer = Sign("ML-DSA-44")
    kp = signer.generate_keypair()
    sm = signer.sign(b"m", kp.secret)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        signer.verify(sm, kp.public, context=b"")
    with pytest.raises(VerificationError):
        signer.verify(sm, kp.public, context=b"app")


def test_jwt_verifier_states_its_context() -> None:
    """JWTVerifier passes its own context, so it emits no warning, and a token
    signed under another context is rejected."""
    from quantum_safe.protocols.jwt import JWTSigner, JWTVerifier

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        kp = Sign("ML-DSA-44").generate_keypair()
    good = JWTSigner(kp).sign({"sub": "u"})
    other = JWTSigner(kp).sign({"sub": "u"}, context=b"not-jwt")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert JWTVerifier(kp.public).verify(good)["sub"] == "u"
        with pytest.raises(VerificationError):
            JWTVerifier(kp.public).verify(other)


def test_x509_cosig_requires_the_cosig_context() -> None:
    """A bundle that declares another context (a signature the same key made
    for another purpose) must not verify as a certificate co-signature."""
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509 import load_pem_x509_certificate

    from quantum_safe.protocols.x509 import _COSIG_INFO_PREFIX, HybridCertificateBuilder

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        signer = Sign("ML-DSA-44")
    kp = signer.generate_keypair()
    cert_pem, bundle = HybridCertificateBuilder(
        subject_cn="svc", classical_private_key=Ed25519PrivateKey.generate(), pqc_keypair=kp
    ).build()
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        HybridCertificateBuilder.verify_cosig(cert_pem, bundle, kp.public)

    cert_der = load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    other = signer.sign(_COSIG_INFO_PREFIX + cert_der, kp.secret, context=b"documents")
    forged = cbor2.loads(bundle)
    forged["sig"], forged["context"] = other.signature, b"documents"
    with pytest.raises(VerificationError):
        HybridCertificateBuilder.verify_cosig(cert_pem, cbor2.dumps(forged), kp.public)
