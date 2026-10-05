"""``sign_raw`` / ``verify_raw`` are plain FIPS 204 ML-DSA (GitHub issues #1 and #2).

``verify_raw`` used to verify ``len(ctx) || ctx || message`` under an empty FIPS 204
context, so it rejected every standard signature, including one made with an empty
context. These tests use liboqs's own FIPS 204 interface directly, not this
library's wrappers, as the independent side.
"""

from __future__ import annotations

import warnings

import pytest

from quantum_safe import Sign
from quantum_safe.exceptions import VerificationError
from quantum_safe.types import PublicKey

pytestmark = pytest.mark.requires_liboqs

ALGORITHMS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
CONTEXTS = [b"", b"example", bytes(range(255))]
MESSAGE = b"a message signed somewhere else"


def _oqs():
    return pytest.importorskip("oqs")


def _signer(algorithm: str) -> Sign:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return Sign(algorithm)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("context", CONTEXTS, ids=["empty", "short", "255-bytes"])
class TestExternalSignaturesVerify:
    def test_verify_raw_accepts_a_standard_signature(self, algorithm: str, context: bytes) -> None:
        oqs = _oqs()
        ext = oqs.Signature(algorithm)
        pub = ext.generate_keypair()
        sig = ext.sign_with_ctx_str(MESSAGE, context)
        _signer(algorithm).verify_raw(
            MESSAGE, bytes(sig), PublicKey(raw=bytes(pub), algorithm=algorithm), context
        )

    def test_a_standard_verifier_accepts_sign_raw(self, algorithm: str, context: bytes) -> None:
        oqs = _oqs()
        signer = _signer(algorithm)
        kp = signer.generate_keypair()
        sig = signer.sign_raw(MESSAGE, kp.secret, context)
        assert len(sig) == signer._spec.signature_bytes  # nothing wrapped around it
        assert oqs.Signature(algorithm).verify_with_ctx_str(
            MESSAGE, sig, context, kp.public.raw_bytes
        )

    def test_round_trip(self, algorithm: str, context: bytes) -> None:
        signer = _signer(algorithm)
        kp = signer.generate_keypair()
        signer.verify_raw(MESSAGE, signer.sign_raw(MESSAGE, kp.secret, context), kp.public, context)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
class TestSemantics:
    def test_context_and_message_are_bound(self, algorithm: str) -> None:
        signer = _signer(algorithm)
        kp = signer.generate_keypair()
        sig = signer.sign_raw(MESSAGE, kp.secret, b"ctx-a")
        with pytest.raises(VerificationError):
            signer.verify_raw(MESSAGE, sig, kp.public, b"ctx-b")
        with pytest.raises(VerificationError):
            signer.verify_raw(MESSAGE, sig, kp.public, b"")
        with pytest.raises(VerificationError):
            signer.verify_raw(MESSAGE + b"x", sig, kp.public, b"ctx-a")

    def test_signing_is_randomized_by_fips_204_not_by_changing_the_message(
        self, algorithm: str
    ) -> None:
        signer = _signer(algorithm)
        kp = signer.generate_keypair()
        a = signer.sign_raw(MESSAGE, kp.secret, b"c")
        b = signer.sign_raw(MESSAGE, kp.secret, b"c")
        assert a != b  # hedged (random rnd) ...
        signer.verify_raw(MESSAGE, a, kp.public, b"c")  # ... yet both verify over the plain message
        signer.verify_raw(MESSAGE, b, kp.public, b"c")

    def test_a_256_byte_context_is_refused(self, algorithm: str) -> None:
        signer = _signer(algorithm)
        kp = signer.generate_keypair()
        with pytest.raises(ValueError):
            signer.sign_raw(MESSAGE, kp.secret, bytes(256))
        sig = signer.sign_raw(MESSAGE, kp.secret, b"")
        with pytest.raises(VerificationError):
            signer.verify_raw(MESSAGE, sig, kp.public, bytes(256))

    def test_the_library_formats_are_not_plain_fips_204(self, algorithm: str) -> None:
        """sign() signs a different byte string; verify_raw must not accept it."""
        signer = _signer(algorithm)
        kp = signer.generate_keypair()
        sm = signer.sign(MESSAGE, kp.secret, context=b"c")
        blob = sm.signature
        raw_part = blob[1 + blob[0] :]
        with pytest.raises(VerificationError):
            signer.verify_raw(MESSAGE, raw_part, kp.public, b"c")
        signer.verify(sm, kp.public, context=b"c")  # and verify() still works
