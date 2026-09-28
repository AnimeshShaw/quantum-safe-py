"""Pytest wrapper for the ACVP known-answer conformance run.

Skipped unless liboqs is installed and the pinned vectors can be fetched or are
already cached, so a normal ``pytest`` run on a machine without the ``[liboqs]``
extra or without network access stays green.

Mark with ``-m conformance`` to select or deselect these explicitly.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import acvp_kat  # noqa: E402

pytestmark = pytest.mark.conformance

oqs_required = pytest.mark.skipif(
    not acvp_kat.liboqs_available(),
    reason="liboqs-python not installed (install the [liboqs] extra)",
)


@pytest.fixture(scope="module")
def vectors() -> dict:
    try:
        return acvp_kat.fetch_vectors()
    except Exception as exc:  # network unavailable or upstream changed
        pytest.skip(f"ACVP vectors unavailable: {type(exc).__name__}: {exc}")


@oqs_required
def test_ml_kem_decapsulation_matches_nist_vectors(vectors: dict) -> None:
    """Every runnable ML-KEM decapsulation vector must produce the exact secret.

    These cases include deliberately malformed ciphertexts, whose expected output
    is the FIPS 203 implicit-rejection value rather than an error, so this also
    pins the rejection behaviour.
    """
    suite = vectors["ML-KEM-encapDecap-FIPS203"]
    result = acvp_kat.run_ml_kem_decap(suite["prompt"], suite["expectedResults"])

    assert result.runnable, "expected runnable ML-KEM decapsulation cases"
    assert result.errors == 0, f"errors during decapsulation: {result.failures[:3]}"
    assert result.total_passed == result.total_run, (
        f"{result.total_run - result.total_passed} of {result.total_run} "
        f"vectors mismatched: {result.failures[:3]}"
    )


@oqs_required
def test_ml_dsa_sigver_scope_is_reported_not_silently_passed(vectors: dict) -> None:
    """Guards the honesty of the ML-DSA result rather than a pass rate.

    The published sigVer vectors currently contain no case this binding can run
    as a positive test: acceptance cases require either a context parameter or
    verification from mu. That is a scope limit, and the run must report it as
    such instead of reporting a vacuous pass. If upstream later publishes
    runnable cases, this test requires them to actually pass.
    """
    suite = vectors["ML-DSA-sigVer-FIPS204"]
    interface = acvp_kat.detect_ml_dsa_interface(suite["prompt"], suite["expectedResults"])
    result = acvp_kat.run_ml_dsa_sigver(suite["prompt"], suite["expectedResults"], interface)

    if not result.runnable:
        assert result.out_of_scope > 0, "no cases ran and none were accounted for"
        assert any("FINDING" in note for note in result.notes), (
            "a suite with no runnable cases must say so explicitly"
        )
        assert result.verdict() == "NO RUNNABLE CASES"
        return

    assert result.errors == 0, f"errors during verification: {result.failures[:3]}"
    assert result.total_passed == result.total_run, (
        f"{result.total_run - result.total_passed} of {result.total_run} "
        f"vectors mismatched: {result.failures[:3]}"
    )


@oqs_required
def test_conformance_run_never_claims_validation(vectors: dict) -> None:
    """The output must not let a reader mistake this for CAVP/CMVP validation.

    The distinction is load-bearing for anyone operating under CNSA 2.0, where
    compliance runs through validated modules, so it is asserted rather than
    left to reviewer discipline.
    """
    suite = vectors["ML-KEM-encapDecap-FIPS203"]
    result = acvp_kat.run_ml_kem_decap(suite["prompt"], suite["expectedResults"])
    rendered = " ".join([str(result), *result.notes]).lower()
    assert "validated" not in rendered
    assert "cavp" not in rendered
    assert "certified" not in rendered


@oqs_required
def test_ml_kem_keygen_matches_nist_vectors(vectors: dict) -> None:
    """Seeded keygen must reproduce both halves of the expected keypair."""
    suite = vectors["ML-KEM-keyGen-FIPS203"]
    result = acvp_kat.run_ml_kem_keygen(suite["prompt"], suite["expectedResults"])
    assert result.runnable, "expected runnable ML-KEM keyGen cases"
    assert result.errors == 0, f"errors during keygen: {result.failures[:3]}"
    assert result.total_passed == result.total_run, (
        f"{result.total_run - result.total_passed} of {result.total_run} "
        f"vectors mismatched: {result.failures[:3]}"
    )


@oqs_required
def test_ml_kem_encapsulation_matches_nist_vectors(vectors: dict) -> None:
    """Derandomised encapsulation must reproduce the ciphertext and the secret.

    Skipped rather than failed when liboqs does not export
    OQS_KEM_encaps_derand: without it the ACVP-supplied m cannot be injected,
    which is a build limitation and not a conformance failure.
    """
    if not acvp_kat._encaps_derand_available():
        pytest.skip("liboqs build does not export OQS_KEM_encaps_derand")
    suite = vectors["ML-KEM-encapDecap-FIPS203"]
    result = acvp_kat.run_ml_kem_encaps(suite["prompt"], suite["expectedResults"])
    assert result.runnable, "expected runnable ML-KEM encapsulation cases"
    assert result.errors == 0, f"errors during encapsulation: {result.failures[:3]}"
    assert result.total_passed == result.total_run, (
        f"{result.total_run - result.total_passed} of {result.total_run} "
        f"vectors mismatched: {result.failures[:3]}"
    )
