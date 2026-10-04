"""S6: an envelope must be openable only for the AAD the opener expects.

Envelope.open authenticates the AAD carried in the message (any change
fails GCM), but anyone holding the recipient's public key can seal a message
with any AAD, and the opener used to have no way to say which AAD it expected.
A message sealed for "user-A" therefore opened in "user-B"'s context.

Now open(..., expected_aad=...) requires the message's AAD to equal it. When
it is omitted and the message carries AAD, a DeprecationWarning is emitted
(an AAD-less message needs nothing to compare). Mirrors quantum-safe-ts's
``expectedAad``.
"""

from __future__ import annotations

import warnings

import pytest
from cryptography.exceptions import InvalidTag

from quantum_safe import HybridKEM
from quantum_safe.protocols.envelope import Envelope

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module")
def kp():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return HybridKEM().generate_keypair()


def test_matching_expected_aad_opens_without_warning(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public, aad=b"user-A")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert Envelope.open(sealed, kp.secret, expected_aad=b"user-A") == b"payload"


@pytest.mark.parametrize("expected", [b"user-B", b"", b"user-A\x00", b"USER-A"])
def test_other_aad_is_rejected(kp, expected: bytes) -> None:
    """A message sealed for user-A must not open in another context."""
    sealed = Envelope.seal(b"payload", kp.public, aad=b"user-A")
    with pytest.raises(InvalidTag):
        Envelope.open(sealed, kp.secret, expected_aad=expected)


def test_expected_aad_on_an_aad_less_message(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public)
    assert Envelope.open(sealed, kp.secret, expected_aad=b"") == b"payload"
    with pytest.raises(InvalidTag):
        Envelope.open(sealed, kp.secret, expected_aad=b"user-B")


def test_omitting_expected_aad_warns_when_the_message_has_aad(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public, aad=b"user-A")
    with pytest.warns(DeprecationWarning, match="expected_aad"):
        assert Envelope.open(sealed, kp.secret) == b"payload"


def test_omitting_expected_aad_is_silent_without_aad(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert Envelope.open(sealed, kp.secret) == b"payload"


def test_tampered_aad_still_fails_authentication(kp) -> None:
    import dataclasses

    sealed = Envelope.seal(b"payload", kp.public, aad=b"user-A")
    forged = dataclasses.replace(sealed, aad=b"user-B")
    with pytest.raises(InvalidTag):
        Envelope.open(forged, kp.secret, expected_aad=b"user-B")
