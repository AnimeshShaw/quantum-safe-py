"""
What happens when ``context`` / ``expected_aad`` is left out (decision D4, audit item X-C1).

Signatures: omitted ``context`` means "I expect an empty context". A message that carries a
non-empty context is rejected (fail closed), and a developer-facing warning says why, so the rejection
is not a silent mystery. The wire error stays the opaque ``VerificationError``.

Envelopes: omitted ``expected_aad`` means "accept any AAD" (the AAD is authenticated, so it cannot be
tampered with), and a warning is emitted when the message actually carries AAD, because the opener
then did not check what it was bound to.

Both arguments stay optional. Neither warning fires when the argument is passed, and neither fires
when nothing is bound (empty context / empty AAD). Both are ordinary UserWarning subclasses, so they
are visible by default and can be silenced with the standard ``warnings`` filters.
"""

from __future__ import annotations

import warnings

import pytest

from quantum_safe.exceptions import (
    AadOmittedWarning,
    ContextOmittedWarning,
    QuantumSafeWarning,
    VerificationError,
)

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module")
def signer():
    from quantum_safe.signatures.core import Sign

    s = Sign("ML-DSA-44")
    return s, s.generate_keypair()


@pytest.fixture(scope="module")
def hybrid_signer():
    from quantum_safe.signatures.hybrid import HybridSign

    s = HybridSign("Ed25519", "ML-DSA-44")
    return s, s.generate_keypair()


class TestWarningTypes:
    def test_are_visible_user_warnings(self) -> None:
        assert issubclass(ContextOmittedWarning, QuantumSafeWarning)
        assert issubclass(AadOmittedWarning, QuantumSafeWarning)
        assert issubclass(QuantumSafeWarning, UserWarning)  # UserWarning is shown by default
        assert not issubclass(QuantumSafeWarning, DeprecationWarning)


@pytest.mark.parametrize("which", ["plain", "hybrid"])
class TestSignatureContext:
    def _pair(self, which, signer, hybrid_signer):
        return signer if which == "plain" else hybrid_signer

    def test_omitted_context_rejects_a_message_that_carries_one_and_says_why(
        self, which, signer, hybrid_signer
    ) -> None:
        s, kp = self._pair(which, signer, hybrid_signer)
        sm = s.sign(b"pay alice", kp.secret, context=b"payments")
        with pytest.warns(ContextOmittedWarning, match="non-empty context"):
            with pytest.raises(VerificationError):
                s.verify(sm, kp.public)

    def test_the_warning_does_not_leak_the_context(self, which, signer, hybrid_signer) -> None:
        s, kp = self._pair(which, signer, hybrid_signer)
        sm = s.sign(b"m", kp.secret, context=b"super-secret-purpose")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with pytest.raises(VerificationError):
                s.verify(sm, kp.public)
        assert caught and "super-secret-purpose" not in str(caught[0].message)

    def test_omitted_context_accepts_an_empty_context_silently(
        self, which, signer, hybrid_signer
    ) -> None:
        s, kp = self._pair(which, signer, hybrid_signer)
        sm = s.sign(b"no purpose bound", kp.secret)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            s.verify(sm, kp.public)

    def test_right_context_passes_silently(self, which, signer, hybrid_signer) -> None:
        s, kp = self._pair(which, signer, hybrid_signer)
        sm = s.sign(b"m", kp.secret, context=b"payments")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            s.verify(sm, kp.public, context=b"payments")

    def test_wrong_context_fails_without_the_omission_warning(
        self, which, signer, hybrid_signer
    ) -> None:
        s, kp = self._pair(which, signer, hybrid_signer)
        sm = s.sign(b"m", kp.secret, context=b"payments")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with pytest.raises(VerificationError):
                s.verify(sm, kp.public, context=b"refunds")

    def test_warning_can_be_silenced_with_a_standard_filter(
        self, which, signer, hybrid_signer
    ) -> None:
        s, kp = self._pair(which, signer, hybrid_signer)
        sm = s.sign(b"m", kp.secret, context=b"payments")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            warnings.filterwarnings("ignore", category=ContextOmittedWarning)
            with pytest.raises(VerificationError):
                s.verify(sm, kp.public)

    def test_warns_once_per_call_site_under_the_default_filter(
        self, which, signer, hybrid_signer
    ) -> None:
        s, kp = self._pair(which, signer, hybrid_signer)
        sm = s.sign(b"m", kp.secret, context=b"payments")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("default")
            for _ in range(5):
                with pytest.raises(VerificationError):
                    s.verify(sm, kp.public)  # one source line, five calls
        assert len([w for w in caught if issubclass(w.category, ContextOmittedWarning)]) == 1


class TestEnvelopeAad:
    @pytest.fixture(scope="class")
    def kp(self):
        from quantum_safe.kem.hybrid import HybridKEM

        return HybridKEM().generate_keypair()

    def test_omitted_aad_accepts_and_warns_when_the_message_carries_aad(self, kp) -> None:
        from quantum_safe.protocols.envelope import Envelope

        sealed = Envelope.seal(b"data", kp.public, aad=b"user-42")
        with pytest.warns(AadOmittedWarning, match="expected_aad"):
            assert Envelope.open(sealed, kp.secret) == b"data"

    def test_omitted_aad_is_silent_when_there_is_no_aad(self, kp) -> None:
        from quantum_safe.protocols.envelope import Envelope

        sealed = Envelope.seal(b"data", kp.public)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert Envelope.open(sealed, kp.secret) == b"data"

    def test_passing_aad_is_silent_and_checked(self, kp) -> None:
        from cryptography.exceptions import InvalidTag

        from quantum_safe.protocols.envelope import Envelope

        sealed = Envelope.seal(b"data", kp.public, aad=b"user-42")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert Envelope.open(sealed, kp.secret, expected_aad=b"user-42") == b"data"
            with pytest.raises(InvalidTag):
                Envelope.open(sealed, kp.secret, expected_aad=b"user-43")

    def test_warning_does_not_leak_the_aad_and_can_be_silenced(self, kp) -> None:
        from quantum_safe.protocols.envelope import Envelope

        sealed = Envelope.seal(b"data", kp.public, aad=b"tenant-secret-id")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            Envelope.open(sealed, kp.secret)
        assert caught and "tenant-secret-id" not in str(caught[0].message)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            warnings.filterwarnings("ignore", category=AadOmittedWarning)
            Envelope.open(sealed, kp.secret)
