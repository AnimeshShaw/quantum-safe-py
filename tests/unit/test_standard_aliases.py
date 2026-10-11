"""``sign_standard`` / ``verify_standard`` are the clear names for ``sign_raw`` / ``verify_raw``.

``sign()`` is the library's own construction; the standard FIPS 204 signature is the one another
implementation can verify from (message, context). The aliases say so in the name and are
interchangeable with the originals, which are not deprecated.
"""

from __future__ import annotations

import pytest

from quantum_safe.exceptions import VerificationError

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module")
def pair():
    from quantum_safe.signatures.core import Sign

    s = Sign("ML-DSA-44")
    return s, s.generate_keypair()


def test_standard_names_are_interchangeable_with_raw(pair) -> None:
    s, kp = pair
    sig = s.sign_standard(b"message", kp.secret, context=b"ctx")
    s.verify_raw(b"message", sig, kp.public, context=b"ctx")
    s.verify_standard(
        b"message", s.sign_raw(b"message", kp.secret, context=b"ctx"), kp.public, context=b"ctx"
    )


def test_standard_signature_is_bare_fips_204_and_checks_the_context(pair) -> None:
    s, kp = pair
    sig = s.sign_standard(b"message", kp.secret, context=b"ctx")
    assert len(sig) == 2420  # ML-DSA-44: nothing wrapped around the FIPS 204 signature
    with pytest.raises(VerificationError):
        s.verify_standard(b"message", sig, kp.public, context=b"other")
    with pytest.raises(VerificationError):
        s.verify_standard(b"different", sig, kp.public, context=b"ctx")


def test_context_longer_than_255_is_refused(pair) -> None:
    s, kp = pair
    with pytest.raises(ValueError):
        s.sign_standard(b"m", kp.secret, context=b"x" * 256)


def test_hybrid_exposes_no_standard_signature() -> None:
    """A hybrid has no single FIPS 204 signature; the standard pair belongs to the plain ML-DSA class."""
    from quantum_safe.signatures.hybrid import HybridSign

    assert not hasattr(HybridSign, "sign_standard")
