"""
The default hybrid signature suite is ``Ed25519+ML-DSA-65-v2`` (roadmap 0.4.0, decision D5).

The ``-v2`` format has no hedging prefix, signs a domain-separated wrapped message with FIPS 204's
native context, and is byte-compatible with quantum-safe-ts. The previous default format is not
removed: it stays reachable under its own identifier, and its signatures keep verifying when it is
named. The two formats are never confused with each other.
"""

from __future__ import annotations

import warnings

import pytest

from quantum_safe.exceptions import UnsupportedAlgorithm, VerificationError
from quantum_safe.signatures import DEFAULT_HYBRID_CLASSICAL, DEFAULT_HYBRID_PQC

pytestmark = pytest.mark.requires_liboqs


def test_default_constants() -> None:
    assert DEFAULT_HYBRID_CLASSICAL == "Ed25519"
    assert DEFAULT_HYBRID_PQC == "ML-DSA-65-v2"


def test_hybridsign_defaults_to_the_v2_suite() -> None:
    from quantum_safe.signatures.hybrid import HybridSign

    assert HybridSign().algorithm == "Ed25519+ML-DSA-65-v2"


def test_default_roundtrip_and_blob_has_no_prefix() -> None:
    from quantum_safe.signatures.hybrid import HybridSign

    s = HybridSign()
    kp = s.generate_keypair()
    sm = s.sign(b"hello", kp.secret, context=b"ctx")
    assert sm.algorithm == "Ed25519+ML-DSA-65-v2"
    s.verify(sm, kp.public, context=b"ctx")
    with pytest.raises(VerificationError):
        s.verify(sm, kp.public, context=b"other")


def test_previous_default_stays_reachable_by_name() -> None:
    from quantum_safe.signatures.hybrid import HybridSign

    old = HybridSign("Ed25519", "ML-DSA-65")
    assert old.algorithm == "Ed25519+ML-DSA-65"
    kp = old.generate_keypair()
    sm = old.sign(b"legacy", kp.secret, context=b"c")
    old.verify(sm, kp.public, context=b"c")


def test_formats_are_not_confused() -> None:
    """A v1 signature must not verify under the v2 default verifier, and vice versa."""
    from quantum_safe.signatures.hybrid import HybridSign

    old, new = HybridSign("Ed25519", "ML-DSA-65"), HybridSign()
    kp_old, kp_new = old.generate_keypair(), new.generate_keypair()
    sm_old = old.sign(b"m", kp_old.secret, context=b"c")
    sm_new = new.sign(b"m", kp_new.secret, context=b"c")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # Keys carry their format tag; a signer refuses a key of the other format outright.
        with pytest.raises((VerificationError, UnsupportedAlgorithm)):
            new.verify(sm_old, kp_old.public, context=b"c")
        with pytest.raises((VerificationError, UnsupportedAlgorithm)):
            old.verify(sm_new, kp_new.public, context=b"c")
        with pytest.raises((VerificationError, UnsupportedAlgorithm)):
            new.sign(b"m", kp_old.secret, context=b"c")


class TestUnhedgedKeepsTheOriginalFormat:
    """``-v2`` is always hedged inside ML-DSA, so ``HybridSign(hedged=False)`` with no explicit
    suite resolves to the original format, which is the only one with an unhedged mode. Code that
    built verifiers this way for old signatures keeps working."""

    def test_unhedged_without_a_suite_is_the_original_format(self) -> None:
        from quantum_safe.signatures.hybrid import HybridSign

        s = HybridSign(hedged=False)
        assert s.algorithm == "Ed25519+ML-DSA-65"
        assert s.is_hedged is False

    def test_unhedged_roundtrip(self) -> None:
        from quantum_safe.signatures.hybrid import HybridSign

        s = HybridSign(hedged=False)
        kp = s.generate_keypair()
        sm = s.sign(b"m", kp.secret, context=b"c")
        s.verify(sm, kp.public, context=b"c")

    def test_explicit_v2_with_unhedged_is_still_an_error(self) -> None:
        from quantum_safe.signatures.hybrid import HybridSign

        with pytest.raises(ValueError, match="hedged"):
            HybridSign("Ed25519", "ML-DSA-65-v2", hedged=False)
