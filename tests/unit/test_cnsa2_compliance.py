"""Tests for the CNSA 2.0 compliance profile and the FIPS 205 algorithm mapping."""

from __future__ import annotations

import pytest

from quantum_safe.compliance import cnsa2


class TestKemChecks:
    def test_required_parameter_set_passes(self) -> None:
        assert cnsa2.check_kem("ML-KEM-1024").ok

    @pytest.mark.parametrize("alg", ["X25519+ML-KEM-1024", "P-256+ML-KEM-1024"])
    def test_hybrid_with_non_cnsa_classical_half_is_partial(self, alg: str) -> None:
        """A hybrid has the right PQC half but is outside what CNSA 2.0 prescribes.

        NSA's FAQ says hybrids are not required and not to be used on NSS mission
        systems except NSA-specified exceptions, so the verdict is PARTIAL.
        """
        result = cnsa2.check_kem(alg)
        assert result.finding is cnsa2.Finding.PARTIAL
        assert not result.ok
        assert "ML-KEM-1024" in result.detail and "FAQ" in result.detail

    def test_p384_hybrid_is_partial_too(self) -> None:
        """P-384 has the shape of NSA's IKEv2 exception, which is IKEv2-specific."""
        result = cnsa2.check_kem("P-384+ML-KEM-1024")
        assert result.finding is cnsa2.Finding.PARTIAL
        assert "IKEv2" in result.detail

    @pytest.mark.parametrize(
        "alg",
        ["RSA-1024+ML-KEM-1024", "FOO+ML-KEM-1024", "X25519+P-384+ML-KEM-1024", "+ML-KEM-1024"],
    )
    def test_unrecognised_classical_half_is_non_compliant(self, alg: str) -> None:
        assert cnsa2.check_kem(alg).finding is cnsa2.Finding.NON_COMPLIANT

    @pytest.mark.parametrize("alg", ["ML-KEM-512", "ML-KEM-768", "X25519+ML-KEM-768"])
    def test_lower_parameter_sets_fail(self, alg: str) -> None:
        """A FIPS 203 algorithm below ML-KEM-1024 is not CNSA 2.0."""
        result = cnsa2.check_kem(alg)
        assert result.finding is cnsa2.Finding.NON_COMPLIANT
        assert "ML-KEM-1024" in result.detail


class TestSignatureChecks:
    def test_required_parameter_set_passes(self) -> None:
        assert cnsa2.check_signature("ML-DSA-87").ok

    @pytest.mark.parametrize("alg", ["Ed25519+ML-DSA-87", "P-256+ML-DSA-87"])
    def test_hybrid_with_non_cnsa_classical_half_is_partial(self, alg: str) -> None:
        result = cnsa2.check_signature(alg)
        assert result.finding is cnsa2.Finding.PARTIAL
        assert not result.ok

    def test_p384_hybrid_is_partial_too(self) -> None:
        assert cnsa2.check_signature("P-384+ML-DSA-87").finding is cnsa2.Finding.PARTIAL

    @pytest.mark.parametrize(
        "alg", ["RSA-1024+ML-DSA-87", "Ed448+Ed25519+ML-DSA-87", "x+ML-DSA-87"]
    )
    def test_unrecognised_classical_half_is_non_compliant(self, alg: str) -> None:
        assert cnsa2.check_signature(alg).finding is cnsa2.Finding.NON_COMPLIANT

    @pytest.mark.parametrize("alg", ["ML-DSA-44", "ML-DSA-65", "Ed25519+ML-DSA-65"])
    def test_lower_parameter_sets_fail(self, alg: str) -> None:
        assert cnsa2.check_signature(alg).finding is cnsa2.Finding.NON_COMPLIANT


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
            kem="ML-KEM-1024",
            signature="ML-DSA-87",
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


class TestKeyDerivation:
    """CNSA 2.0 requires SHA-384/512; this library's hybrids derive with SHA-256."""

    def test_pure_ml_kem_1024_is_compliant(self) -> None:
        r = cnsa2.check_key_derivation("ML-KEM-1024")
        assert r.ok and r.actual == "SHA-384"

    @pytest.mark.parametrize(
        "alg", ["X25519+ML-KEM-1024", "X25519+ML-KEM-768", "P-256+ML-KEM-768", "ML-KEM-768"]
    )
    def test_everything_else_is_not(self, alg: str) -> None:
        r = cnsa2.check_key_derivation(alg)
        assert r.finding is cnsa2.Finding.NON_COMPLIANT and r.actual == "SHA-256"

    def test_report_includes_the_row_and_can_exclude_it(self) -> None:
        with_row = cnsa2.report(kem="X25519+ML-KEM-1024", include_code_signing=False)
        assert any("Key-derivation" in c.requirement for c in with_row.checks)
        without = cnsa2.report(
            kem="X25519+ML-KEM-1024", include_code_signing=False, include_key_derivation=False
        )
        assert not any("Key-derivation" in c.requirement for c in without.checks)

    def test_pure_selection_report_can_be_clean(self) -> None:
        rep = cnsa2.report(kem="ML-KEM-1024", signature="ML-DSA-87", include_code_signing=False)
        assert rep.compliant

    def test_enforce_default_is_unaffected_by_the_row(self) -> None:
        cnsa2.enforce(kem="X25519+ML-KEM-1024")  # parameter-set guard only


class TestEnforce:
    def test_raises_below_requirements(self) -> None:
        with pytest.raises(ValueError, match="not CNSA 2.0 compliant"):
            cnsa2.enforce(kem="ML-KEM-768", signature="ML-DSA-87")

    def test_passes_at_requirements(self) -> None:
        cnsa2.enforce(kem="ML-KEM-1024", signature="ML-DSA-87")

    def test_default_is_a_parameter_set_guard(self) -> None:
        """By default only the post-quantum parameter set is enforced, as in
        quantum-safe-ts: a hybrid with the right PQC half passes, although
        report() calls it PARTIAL."""
        cnsa2.enforce(kem="X25519+ML-KEM-1024", signature="Ed25519+ML-DSA-87")
        assert cnsa2.check_kem("X25519+ML-KEM-1024").finding is cnsa2.Finding.PARTIAL

    def test_strict_refuses_partial(self) -> None:
        with pytest.raises(ValueError, match="not CNSA 2.0 compliant"):
            cnsa2.enforce(kem="X25519+ML-KEM-1024", strict=True)
        with pytest.raises(ValueError, match="not CNSA 2.0 compliant"):
            cnsa2.enforce(signature="Ed25519+ML-DSA-87", strict=True)
        cnsa2.enforce(kem="ML-KEM-1024", signature="ML-DSA-87", strict=True)

    @pytest.mark.parametrize("strict", [False, True])
    def test_unrecognised_names_always_fail(self, strict: bool) -> None:
        with pytest.raises(ValueError, match="not CNSA 2.0 compliant"):
            cnsa2.enforce(signature="RSA-1024+ML-DSA-87", strict=strict)
        with pytest.raises(ValueError, match="not CNSA 2.0 compliant"):
            cnsa2.enforce(kem="X25519+ML-KEM-768", strict=strict)


class TestConstructors:
    def test_hybrid_kem_no_longer_offers_p384(self) -> None:
        """HybridKEM does not implement P-384, so the helper must not offer it."""
        assert "P-384" not in cnsa2.CNSA2_HYBRID_CLASSICAL
        with pytest.raises(ValueError):
            cnsa2.hybrid_kem(classical="P-384")

    @pytest.mark.requires_liboqs
    def test_pure_constructors_use_the_required_parameter_sets(self) -> None:
        assert cnsa2.pqc_kem().algorithm == "ML-KEM-1024"
        assert cnsa2.pqc_sign().algorithm == "ML-DSA-87"

    def test_describe_leads_with_the_compliant_pure_configuration(self) -> None:
        text = cnsa2.describe()
        assert "pqc_kem()" in text and "pqc_sign()" in text
        assert "PARTIAL" in text
        # LMS has been available since 0.3.0; the text must not say otherwise.
        assert "implements neither" not in text


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
