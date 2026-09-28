"""Tests for the CNSA 2.0 compliance profile and the FIPS 205 algorithm mapping."""

from __future__ import annotations

import pytest

from quantum_safe.compliance import cnsa2


class TestKemChecks:
    def test_required_parameter_set_passes(self) -> None:
        assert cnsa2.check_kem("ML-KEM-1024").ok

    def test_hybrid_with_compliant_pqc_half_passes(self) -> None:
        assert cnsa2.check_kem("X25519+ML-KEM-1024").ok

    @pytest.mark.parametrize("alg", ["ML-KEM-512", "ML-KEM-768", "X25519+ML-KEM-768"])
    def test_lower_parameter_sets_fail(self, alg: str) -> None:
        """A FIPS 203 algorithm below ML-KEM-1024 is not CNSA 2.0."""
        result = cnsa2.check_kem(alg)
        assert not result.ok
        assert "ML-KEM-1024" in result.detail


class TestSignatureChecks:
    def test_required_parameter_set_passes(self) -> None:
        assert cnsa2.check_signature("ML-DSA-87").ok

    def test_hybrid_with_compliant_pqc_half_passes(self) -> None:
        assert cnsa2.check_signature("Ed25519+ML-DSA-87").ok

    @pytest.mark.parametrize("alg", ["ML-DSA-44", "ML-DSA-65", "Ed25519+ML-DSA-65"])
    def test_lower_parameter_sets_fail(self, alg: str) -> None:
        assert not cnsa2.check_signature(alg).ok


class TestHashChecks:
    @pytest.mark.parametrize("alg", ["SHA-384", "SHA-512", "sha384"])
    def test_permitted_hashes(self, alg: str) -> None:
        assert cnsa2.check_hash(alg).ok

    @pytest.mark.parametrize("alg", ["SHA-256", "SHA-1"])
    def test_rejected_hashes(self, alg: str) -> None:
        assert not cnsa2.check_hash(alg).ok


class TestReport:
    def test_library_defaults_are_not_compliant(self) -> None:
        """The library's own defaults sit below the suite; the report must say so.

        This is the gap that motivated the profile. If this test ever passes
        trivially, the defaults changed and the paper's claim needs revisiting.
        """
        rep = cnsa2.report(
            kem="X25519+ML-KEM-768",
            signature="Ed25519+ML-DSA-65",
            hash_algorithm="SHA-256",
        )
        assert not rep.compliant
        assert len(rep.failures) >= 3

    def test_compliant_selection_still_flags_code_signing(self) -> None:
        """Compliant parameters are necessary, not sufficient.

        SP 800-208 software/firmware signing is reported as PARTIAL when LMS is
        installed and NOT_COVERED when it is not. Either way it counts against
        compliance: LMS alone does not satisfy the requirement, because SP 800-208
        also requires key generation inside a validated module, and XMSS is absent.
        """
        rep = cnsa2.report(
            kem="X25519+ML-KEM-1024",
            signature="Ed25519+ML-DSA-87",
            hash_algorithm="SHA-512",
            include_code_signing=True,
        )
        assert not rep.compliant
        signing = [c for c in rep.checks if "800-208" in c.requirement]
        assert len(signing) == 1
        assert signing[0].finding in (cnsa2.Finding.PARTIAL, cnsa2.Finding.NOT_COVERED)
        assert not signing[0].ok

    def test_code_signing_status_tracks_lms_availability(self) -> None:
        """The report must reflect whether the optional dependency is present."""
        rep = cnsa2.report(signature="ML-DSA-87", include_code_signing=True)
        signing = next(c for c in rep.checks if "800-208" in c.requirement)
        if cnsa2.lms_available():
            assert signing.finding is cnsa2.Finding.PARTIAL
            assert "LMS" in (signing.actual or "")
        else:
            assert signing.finding is cnsa2.Finding.NOT_COVERED
            assert "quantum-safe-py[lms]" in signing.detail

    def test_parameter_only_report_can_be_clean(self) -> None:
        rep = cnsa2.report(
            kem="ML-KEM-1024",
            signature="ML-DSA-87",
            hash_algorithm="SHA-384",
            include_code_signing=False,
        )
        assert rep.compliant

    def test_render_never_claims_validation(self) -> None:
        """Output must not let a reader infer FIPS 140-3 validation."""
        rendered = cnsa2.report(
            kem="ML-KEM-1024", signature="ML-DSA-87", include_code_signing=False
        ).render()
        assert "not a validated module" in rendered
        assert "is not a validation" in rendered


class TestEnforce:
    def test_raises_below_requirements(self) -> None:
        with pytest.raises(ValueError, match="not CNSA 2.0 compliant"):
            cnsa2.enforce(kem="ML-KEM-768", signature="ML-DSA-87")

    def test_passes_at_requirements(self) -> None:
        cnsa2.enforce(kem="X25519+ML-KEM-1024", signature="Ed25519+ML-DSA-87")


class TestFips205Mapping:
    """SLH-DSA names must reach FIPS 205, not pre-standard SPHINCS+.

    These were previously mapped to ``SPHINCS+-...-simple``, the round-3
    submission. The two share parameter sizes but are not interchangeable, so the
    mismatch silently produced non-FIPS-205 signatures under a FIPS 205 name.
    """

    def test_slh_dsa_maps_to_fips205_mechanisms(self) -> None:
        from quantum_safe.backends.liboqs import _SIG_LIBOQS_NAMES

        slh = {k: v for k, v in _SIG_LIBOQS_NAMES.items() if k.startswith("SLH-DSA")}
        assert slh, "no SLH-DSA names registered"
        for canonical, liboqs_name in slh.items():
            assert liboqs_name.startswith("SLH_DSA_"), (
                f"{canonical} maps to {liboqs_name}, which is not a FIPS 205 mechanism"
            )
            assert "SPHINCS" not in liboqs_name

    def test_legacy_sphincs_reachable_under_its_own_name(self) -> None:
        """Round-3 SPHINCS+ stays available, but only when asked for explicitly."""
        from quantum_safe.backends.liboqs import _SIG_LIBOQS_NAMES

        legacy = {k: v for k, v in _SIG_LIBOQS_NAMES.items() if k.startswith("SPHINCS+")}
        assert legacy
        for canonical, liboqs_name in legacy.items():
            assert "SPHINCS" in liboqs_name, f"{canonical} should map to SPHINCS+"
