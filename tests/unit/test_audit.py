"""
Unit tests for quantum_safe.audit

All tests run without a PQC backend or external dependencies.
The scanner underlying the auditor uses real AST parsing on in-memory strings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quantum_safe.audit.auditor import AuditReport, Auditor
from quantum_safe.audit.compliance import (
    ComplianceLevel,
    ComplianceReport,
    NISTComplianceChecker,
)
from quantum_safe.audit.policy import AuditPolicy, PolicyViolation
from quantum_safe.audit.sbom import PQCReadiness, SBOMEnricher, _assess_component, _version_ge
from quantum_safe.migrate.scanner import Finding, ScanReport, Severity


# ---------------------------------------------------------------------------
# AuditPolicy
# ---------------------------------------------------------------------------


class TestAuditPolicy:
    def test_default_policy(self):
        p = AuditPolicy()
        assert p.min_security_level == 3
        assert not p.allow_classical_only
        assert p.hybrid_required
        assert "HIGH" in p.fail_on
        assert "CRITICAL" in p.fail_on

    def test_preset_strict(self):
        p = AuditPolicy.strict()
        assert "MEDIUM" in p.fail_on
        assert not p.allow_classical_only

    def test_preset_transition(self):
        p = AuditPolicy.transition()
        assert p.allow_classical_only
        assert p.fail_on == ["CRITICAL"]

    def test_preset_permissive(self):
        p = AuditPolicy.permissive()
        assert p.allow_classical_only
        assert not p.hybrid_required

    def test_invalid_security_level_raises(self):
        with pytest.raises(ValueError, match="min_security_level"):
            AuditPolicy(min_security_level=6)

    def test_invalid_severity_in_fail_on_raises(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            AuditPolicy(fail_on=["SUPER_CRITICAL"])

    def test_is_exempt_glob(self):
        p = AuditPolicy(exempt_paths=["tests/**", "legacy_compat.py"])
        assert p.is_exempt("tests/unit/test_crypto.py")
        assert p.is_exempt("legacy_compat.py")
        assert not p.is_exempt("src/auth.py")

    def test_evaluate_no_findings_passes(self):
        p = AuditPolicy()
        violations = p.evaluate([])
        assert violations == []

    def test_evaluate_high_finding_creates_violation(self):
        p = AuditPolicy(allow_classical_only=False)
        finding = Finding(
            file="auth.py", line=10, col=1,
            severity=Severity.HIGH,
            rule_id="QS001",
            message="RSA detected",
        )
        violations = p.evaluate([finding])
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH

    def test_evaluate_medium_finding_no_violation_by_default(self):
        p = AuditPolicy()  # default fail_on = ["CRITICAL", "HIGH"]
        finding = Finding(
            file="auth.py", line=10, col=1,
            severity=Severity.MEDIUM,
            rule_id="QS020",
            message="AES-128",
        )
        violations = p.evaluate([finding])
        assert violations == []

    def test_evaluate_exempt_path_skipped(self):
        p = AuditPolicy(exempt_paths=["tests/**"])
        finding = Finding(
            file="tests/conftest.py", line=5, col=1,
            severity=Severity.HIGH,
            rule_id="QS001",
            message="RSA",
        )
        violations = p.evaluate([finding])
        assert violations == []

    def test_from_dict_round_trip(self):
        p = AuditPolicy(
            min_security_level=5,
            allow_classical_only=True,
            fail_on=["CRITICAL"],
            exempt_paths=["tests/**"],
        )
        d = p.to_dict()
        p2 = AuditPolicy.from_dict(d)
        assert p2.min_security_level == 5
        assert p2.allow_classical_only
        assert p2.fail_on == ["CRITICAL"]
        assert p2.exempt_paths == ["tests/**"]

    def test_fail_severity_levels(self):
        p = AuditPolicy(fail_on=["HIGH", "CRITICAL"])
        levels = p.fail_severity_levels
        assert Severity.HIGH in levels
        assert Severity.CRITICAL in levels
        assert Severity.MEDIUM not in levels

    def test_from_file_json(self, tmp_path):
        policy_data = {
            "min_security_level": 5,
            "allow_classical_only": True,
            "hybrid_required": False,
            "fail_on": ["CRITICAL"],
            "exempt_paths": [],
        }
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps(policy_data))
        p = AuditPolicy.from_file(policy_file)
        assert p.min_security_level == 5
        assert p.allow_classical_only


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------


class TestAuditor:
    _CLEAN_SRC = "from quantum_safe import HybridKEM\nkem = HybridKEM()\n"
    _RSA_SRC = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(65537, 2048)\n"
    )

    def test_audit_source_clean_passes(self):
        report = Auditor.audit_source(self._CLEAN_SRC)
        assert report.passed
        assert report.policy_violations == []

    def test_audit_source_rsa_fails(self):
        report = Auditor.audit_source(self._RSA_SRC)
        assert not report.passed
        assert len(report.policy_violations) >= 1

    def test_audit_source_returns_audit_report(self):
        report = Auditor.audit_source(self._CLEAN_SRC)
        assert isinstance(report, AuditReport)
        assert report.audit_id
        assert report.timestamp
        assert report.target

    def test_audit_report_summary_line(self):
        report = Auditor.audit_source(self._RSA_SRC)
        line = report.summary_line()
        assert "FAILED" in line or "PASSED" in line
        assert report.audit_id[:8] in line

    def test_audit_report_to_json(self):
        report = Auditor.audit_source(self._RSA_SRC)
        j = json.loads(report.to_json())
        assert "audit_id" in j
        assert "findings" in j
        assert "policy_violations" in j
        assert "passed" in j

    def test_audit_report_to_sarif(self):
        report = Auditor.audit_source(self._RSA_SRC)
        sarif = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif

    def test_audit_report_to_github_summary(self):
        report = Auditor.audit_source(self._RSA_SRC)
        md = report.to_github_summary()
        assert "##" in md
        assert "PASSED" in md or "FAILED" in md

    def test_audit_with_custom_policy(self):
        # Permissive policy should pass even with RSA
        permissive = AuditPolicy.permissive()
        report = Auditor.audit_source(self._RSA_SRC, policy=permissive)
        assert report.passed

    def test_audit_report_metadata(self):
        report = Auditor.audit_source(
            self._CLEAN_SRC,
            metadata={"branch": "main", "commit": "abc123"},
        )
        assert report.metadata["branch"] == "main"
        assert report.metadata["commit"] == "abc123"

    def test_audit_directory(self, tmp_path):
        (tmp_path / "clean.py").write_text(self._CLEAN_SRC)
        report = Auditor.audit(tmp_path)
        assert isinstance(report, AuditReport)
        assert report.files_scanned >= 1

    def test_audit_directory_rsa_fails(self, tmp_path):
        (tmp_path / "classical.py").write_text(self._RSA_SRC)
        report = Auditor.audit(tmp_path)
        assert not report.passed

    def test_ci_gate_returns_zero_on_clean(self, tmp_path):
        (tmp_path / "clean.py").write_text(self._CLEAN_SRC)
        code = Auditor.ci_gate(tmp_path)
        assert code == 0

    def test_ci_gate_returns_one_on_violation(self, tmp_path):
        (tmp_path / "bad.py").write_text(self._RSA_SRC)
        code = Auditor.ci_gate(tmp_path)
        assert code == 1

    def test_ci_gate_writes_sarif(self, tmp_path):
        (tmp_path / "src.py").write_text(self._RSA_SRC)
        sarif_path = tmp_path / "output" / "audit.sarif"
        Auditor.ci_gate(tmp_path, output_sarif=str(sarif_path))
        assert sarif_path.exists()
        data = json.loads(sarif_path.read_text())
        assert data["version"] == "2.1.0"

    def test_ci_gate_writes_json(self, tmp_path):
        (tmp_path / "src.py").write_text(self._CLEAN_SRC)
        json_path = tmp_path / "output" / "audit.json"
        Auditor.ci_gate(tmp_path, output_json=str(json_path))
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert "audit_id" in data


# ---------------------------------------------------------------------------
# PolicyViolation
# ---------------------------------------------------------------------------


class TestPolicyViolation:
    def test_str_format(self):
        v = PolicyViolation(
            rule="classical_crypto_detected",
            detail="auth.py:42 — RSA key generation detected",
            severity=Severity.HIGH,
        )
        s = str(v)
        assert "HIGH" in s
        assert "classical_crypto_detected" in s

    def test_to_dict(self):
        v = PolicyViolation(
            rule="critical_vulnerability",
            detail="src/hash.py:7 — MD5 detected",
            severity=Severity.CRITICAL,
        )
        d = v.to_dict()
        assert d["rule"] == "critical_vulnerability"
        assert d["severity"] == "CRITICAL"
        assert "finding" not in d or d["finding"] is None


# ---------------------------------------------------------------------------
# SBOM enrichment
# ---------------------------------------------------------------------------


class TestVersionComparison:
    def test_version_ge_equal(self):
        assert _version_ge("44.0.0", "44.0.0")

    def test_version_ge_greater(self):
        assert _version_ge("44.1.0", "44.0.0")
        assert _version_ge("45.0.0", "44.0.0")

    def test_version_ge_less(self):
        assert not _version_ge("43.9.9", "44.0.0")

    def test_version_ge_with_v_prefix(self):
        assert _version_ge("v44.0.0", "44.0.0")


class TestComponentAssessment:
    def test_cryptography_old_not_ready(self):
        a = _assess_component("cryptography", "43.0.0")
        assert a.readiness == PQCReadiness.NOT_READY
        assert a.since_version == "44.0.0"

    def test_cryptography_new_partial(self):
        a = _assess_component("cryptography", "44.0.5")
        assert a.readiness == PQCReadiness.PARTIAL

    def test_quantum_safe_ready(self):
        a = _assess_component("quantum-safe", "0.1.0")
        assert a.readiness == PQCReadiness.READY

    def test_pycryptodome_not_ready(self):
        a = _assess_component("pycryptodome", "3.20.0")
        assert a.readiness == PQCReadiness.NOT_READY
        assert "replace" in a.action.lower()

    def test_unknown_library(self):
        a = _assess_component("some-exotic-lib", "1.0.0")
        assert a.readiness == PQCReadiness.UNKNOWN

    def test_no_version_unknown(self):
        a = _assess_component("cryptography", None)
        assert a.readiness == PQCReadiness.UNKNOWN

    def test_pycrypto_not_ready_action(self):
        a = _assess_component("pycrypto", "2.6.1")
        assert a.readiness == PQCReadiness.NOT_READY
        assert "abandoned" in a.action.lower()


class TestSBOMEnricher:
    def _make_sbom(self, components: list[dict]) -> dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": components,
        }

    def test_enrich_adds_properties(self):
        sbom = self._make_sbom([
            {"name": "cryptography", "version": "44.0.5", "type": "library"},
        ])
        enriched, assessments = SBOMEnricher.enrich(sbom)
        assert len(assessments) == 1
        props = enriched["components"][0]["properties"]
        prop_names = [p["name"] for p in props]
        assert "quantum-safe:pqc-readiness" in prop_names
        assert "quantum-safe:reason" in prop_names
        assert "quantum-safe:action" in prop_names

    def test_enrich_adds_metadata_summary(self):
        sbom = self._make_sbom([
            {"name": "pycryptodome", "version": "3.20.0"},
            {"name": "quantum-safe", "version": "0.1.0"},
        ])
        enriched, _ = SBOMEnricher.enrich(sbom)
        meta_props = enriched["metadata"]["properties"]
        summary_prop = next(
            (p for p in meta_props if p["name"] == "quantum-safe:summary"), None
        )
        assert summary_prop is not None
        assert "READY=1" in summary_prop["value"]
        assert "NOT_READY=1" in summary_prop["value"]

    def test_enrich_idempotent(self):
        sbom = self._make_sbom([{"name": "cryptography", "version": "44.0.5"}])
        enriched1, _ = SBOMEnricher.enrich(sbom)
        enriched2, _ = SBOMEnricher.enrich(enriched1)
        # Properties should not be duplicated
        props = enriched2["components"][0]["properties"]
        qs_names = [p["name"] for p in props if p["name"].startswith("quantum-safe:")]
        # Each property name should appear exactly once
        assert len(qs_names) == len(set(qs_names))

    def test_from_requirements(self):
        req_txt = """
# a comment
cryptography==44.0.5
pycryptodome>=3.20.0
quantum-safe==0.1.0
requests>=2.31.0
"""
        assessments = SBOMEnricher.from_requirements(req_txt)
        names = [a.name for a in assessments]
        assert "cryptography" in names
        assert "pycryptodome" in names
        assert "quantum-safe" in names
        assert "requests" in names

        qs = next(a for a in assessments if a.name == "quantum-safe")
        assert qs.readiness == PQCReadiness.READY

        pycrypto = next(a for a in assessments if a.name == "pycryptodome")
        assert pycrypto.readiness == PQCReadiness.NOT_READY

    def test_from_requirements_handles_extras(self):
        req_txt = "cryptography[legacy]==44.0.5\n"
        assessments = SBOMEnricher.from_requirements(req_txt)
        assert assessments[0].name == "cryptography"
        assert assessments[0].version == "44.0.5"

    def test_from_requirements_handles_env_markers(self):
        req_txt = "cryptography==44.0.5; python_version >= '3.10'\n"
        assessments = SBOMEnricher.from_requirements(req_txt)
        assert assessments[0].name == "cryptography"


# ---------------------------------------------------------------------------
# NIST Compliance checker
# ---------------------------------------------------------------------------


class TestNISTComplianceChecker:
    _RSA_SRC = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(65537, 2048)\n"
    )
    _CLEAN_SRC = "from quantum_safe import HybridKEM, HybridSign\n"
    _MD5_SRC = 'import hashlib\nhashlib.md5(b"data")\nalgo = "MD5"\n'

    def _scan(self, src: str) -> ScanReport:
        from quantum_safe.migrate.scanner import Scanner
        return Scanner.scan_source(src, filename="test.py")

    def test_clean_code_is_compliant(self):
        scan = self._scan(self._CLEAN_SRC)
        report = NISTComplianceChecker.check(scan, target="test.py")
        assert report.overall_level in (
            ComplianceLevel.COMPLIANT,
            ComplianceLevel.NOT_APPLICABLE,
        )

    def test_rsa_code_is_non_compliant(self):
        scan = self._scan(self._RSA_SRC)
        report = NISTComplianceChecker.check(scan, target="test.py")
        assert report.overall_level == ComplianceLevel.NON_COMPLIANT

    def test_md5_code_triggers_sp800208(self):
        scan = self._scan(self._MD5_SRC)
        report = NISTComplianceChecker.check(scan)
        sp800 = next(
            (c for c in report.controls if c.control_id == "SP800208-3.1"), None
        )
        assert sp800 is not None
        assert sp800.level == ComplianceLevel.NON_COMPLIANT

    def test_report_has_all_controls(self):
        scan = self._scan(self._CLEAN_SRC)
        report = NISTComplianceChecker.check(scan)
        control_ids = {c.control_id for c in report.controls}
        # Spot-check key controls are present
        assert "FIPS203-2.1" in control_ids
        assert "FIPS204-2.1" in control_ids
        assert "CISA-PQC-2" in control_ids

    def test_report_to_json(self):
        scan = self._scan(self._RSA_SRC)
        report = NISTComplianceChecker.check(scan, target="./src")
        j = json.loads(report.to_json())
        assert "controls" in j
        assert "overall_level" in j
        assert "summary" in j
        assert j["summary"]["total"] == len(report.controls)

    def test_report_summary_lines(self):
        scan = self._scan(self._RSA_SRC)
        report = NISTComplianceChecker.check(scan)
        lines = report.summary_lines()
        assert any("NIST" in l for l in lines)
        assert any("NON_COMPLIANT" in l for l in lines)

    def test_non_compliant_controls_accessor(self):
        scan = self._scan(self._RSA_SRC)
        report = NISTComplianceChecker.check(scan)
        nc = report.non_compliant_controls
        assert all(c.level == ComplianceLevel.NON_COMPLIANT for c in nc)

    def test_control_has_evidence(self):
        scan = self._scan(self._RSA_SRC)
        report = NISTComplianceChecker.check(scan)
        nc = report.non_compliant_controls
        assert nc
        assert nc[0].evidence  # should have at least one evidence item
        assert nc[0].remediation  # should have a remediation suggestion

    def test_report_with_metadata(self):
        scan = self._scan(self._CLEAN_SRC)
        report = NISTComplianceChecker.check(scan, metadata={"env": "prod"})
        assert report.metadata["env"] == "prod"
