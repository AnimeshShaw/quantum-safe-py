"""Corrections found while documenting the library: each test fails on the code it replaced."""

from __future__ import annotations

from pathlib import Path

import pytest

from quantum_safe import __version__
from quantum_safe.audit.compliance import ComplianceLevel, NISTComplianceChecker
from quantum_safe.audit.inventory import AlgorithmKind, classify_algorithm
from quantum_safe.audit.policy import AuditPolicy
from quantum_safe.audit.sbom import SBOMEnricher, _assess_component, _version_ge
from quantum_safe.migrate.scanner import Finding, Scanner, Severity


def _finding(severity: Severity, file: str = "app.py") -> Finding:
    return Finding(
        rule_id="QS000",
        severity=severity,
        file=file,
        line=1,
        col=0,
        message="m",
        fix_hint="h",
        snippet="s",
    )


class TestPolicyFailOn:
    def test_medium_in_fail_on_is_a_violation(self) -> None:
        violations = AuditPolicy.strict().evaluate([_finding(Severity.MEDIUM)])
        assert [v.rule for v in violations] == ["classical_crypto_detected"]

    def test_medium_is_ignored_when_it_is_not_in_fail_on(self) -> None:
        assert AuditPolicy().evaluate([_finding(Severity.MEDIUM)]) == []

    def test_allow_classical_only_still_tolerates_medium(self) -> None:
        policy = AuditPolicy(fail_on=["CRITICAL", "HIGH", "MEDIUM"], allow_classical_only=True)
        assert policy.evaluate([_finding(Severity.MEDIUM), _finding(Severity.HIGH)]) == []

    def test_high_and_critical_are_unchanged(self) -> None:
        rules = [v.rule for v in AuditPolicy().evaluate([_finding(Severity.HIGH)])]
        assert rules == ["classical_crypto_detected"]
        permissive = AuditPolicy(allow_classical_only=True)
        assert [v.rule for v in permissive.evaluate([_finding(Severity.CRITICAL)])] == [
            "critical_vulnerability"
        ]


class TestInventoryV2Names:
    @pytest.mark.parametrize(
        ("name", "kind"),
        [
            ("Ed25519+ML-DSA-65-v2", AlgorithmKind.HYBRID),
            ("P-384+ML-DSA-87-v2", AlgorithmKind.HYBRID),
            ("ML-DSA-65-v2", AlgorithmKind.PQC),
            ("Ed25519+ML-DSA-65", AlgorithmKind.HYBRID),
            ("X25519+ML-KEM-768-v2", AlgorithmKind.UNKNOWN),  # -v2 is a signature format only
            ("ML-KEM-768-v2", AlgorithmKind.UNKNOWN),
            ("ML-DSA-65-v2-v2", AlgorithmKind.UNKNOWN),
        ],
    )
    def test_kind(self, name: str, kind: AlgorithmKind) -> None:
        assert classify_algorithm(name).kind is kind

    def test_level_is_that_of_the_base_algorithm(self) -> None:
        assert classify_algorithm("Ed25519+ML-DSA-87-v2").nist_level == 5
        assert classify_algorithm("ML-DSA-44-v2").nist_level == 2


class TestScannerRules:
    def test_sha224_is_not_reported_as_sha1(self) -> None:
        assert Scanner.scan_source("import hashlib\nhashlib.sha224(b'x')\n").findings == []

    def test_sha1_is_still_reported(self) -> None:
        found = Scanner.scan_source("import hashlib\nhashlib.sha1(b'x')\n").findings
        assert [f.rule_id for f in found] == ["QS030"]

    def test_scan_source_findings_are_sorted(self) -> None:
        src = "import hashlib\nhashlib.md5(b'a')\nhashlib.sha1(b'b')\nhashlib.md5(b'c')\n"
        findings = Scanner.scan_source(src).findings
        assert [(f.line, f.col) for f in findings] == sorted((f.line, f.col) for f in findings)

    def test_sarif_names_the_installed_version(self) -> None:
        report = Scanner.scan_source("import hashlib\nhashlib.md5(b'a')\n")
        driver = report.to_sarif()["runs"][0]["tool"]["driver"]
        assert driver["version"] == __version__


class TestExcludePatterns:
    CODE = "import hashlib\nhashlib.md5(b'x')\n"

    @pytest.fixture
    def tree(self, tmp_path: Path) -> Path:
        for name in (
            "src/a.py",
            "tests/t.py",
            "tests/sub/u.py",
            "scripts/s.py",
            "pkg.egg-info/e.py",
            "gen_x.py",
        ):
            f = tmp_path / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(self.CODE)
        return tmp_path

    @staticmethod
    def _files(root: Path, **kw: object) -> list[str]:
        report = Scanner.scan_directory(root, **kw)  # type: ignore[arg-type]
        return sorted({Path(f.file).relative_to(root).as_posix() for f in report.findings})

    def test_defaults_skip_egg_info_directories(self, tree: Path) -> None:
        assert "pkg.egg-info/e.py" not in self._files(tree)

    def test_directory_name(self, tree: Path) -> None:
        got = self._files(tree, exclude=["tests"])
        assert not any(f.startswith("tests/") for f in got)

    @pytest.mark.parametrize("pattern", ["tests/**", "tests/*", "tests/"])
    def test_directory_path_patterns(self, tree: Path, pattern: str) -> None:
        got = self._files(tree, exclude=[pattern])
        assert not any(f.startswith("tests/") for f in got), got
        assert "src/a.py" in got

    def test_nested_directory_path(self, tree: Path) -> None:
        got = self._files(tree, exclude=["tests/sub"])
        assert "tests/t.py" in got
        assert "tests/sub/u.py" not in got

    def test_file_path_and_file_glob(self, tree: Path) -> None:
        got = self._files(tree, exclude=["scripts/s.py", "gen_*.py"])
        assert "scripts/s.py" not in got
        assert "gen_x.py" not in got
        assert "src/a.py" in got

    def test_nothing_else_disappears(self, tree: Path) -> None:
        assert set(self._files(tree)) == {
            "src/a.py",
            "tests/t.py",
            "tests/sub/u.py",
            "scripts/s.py",
            "gen_x.py",
        }


class TestComplianceCoverage:
    @staticmethod
    def _levels(src: str) -> dict[str, ComplianceLevel]:
        report = NISTComplianceChecker.check(Scanner.scan_source(src, filename="t.py"))
        return {c.control_id: c.level for c in report.controls}

    def test_3des_is_a_deprecated_algorithm_finding(self) -> None:
        src = (
            "from cryptography.hazmat.primitives.ciphers import algorithms\n"
            "algorithms.TripleDES(b'k' * 24)\n"
        )
        assert self._levels(src)["SP800131A-1"] is not ComplianceLevel.COMPLIANT

    def test_pycryptodome_rsa_counts_against_the_encapsulation_and_signature_controls(self) -> None:
        src = "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n"
        scan = Scanner.scan_source(src, filename="t.py")
        assert [f.rule_id for f in scan.findings] == ["QS050"]
        levels = self._levels(src)
        assert levels["FIPS203-2.1"] is ComplianceLevel.NON_COMPLIANT
        assert levels["FIPS204-2.1"] is ComplianceLevel.NON_COMPLIANT

    def test_every_scanner_rule_belongs_to_a_control(self) -> None:
        from quantum_safe.migrate.scanner import _RULES

        covered = set().union(*(c["check_rule_ids"] for c in NISTComplianceChecker._CONTROLS))
        assert {r["id"] for r in _RULES} <= covered


class TestPycryptodomeRules:
    @pytest.mark.parametrize(
        ("src", "rule"),
        [
            ("from Crypto.PublicKey import RSA\nRSA.generate(2048)\n", "QS050"),
            ("from Cryptodome.PublicKey import RSA\nRSA.import_key(data)\n", "QS050"),
            ("import Crypto.PublicKey.RSA as R\nR.construct((1, 2))\n", "QS050"),
            ("from Crypto.PublicKey import ECC\nECC.generate(curve='P-256')\n", "QS051"),
            ("from Cryptodome.PublicKey import ECC\nECC.import_key(data)\n", "QS051"),
        ],
    )
    def test_usage_is_reported(self, src: str, rule: str) -> None:
        assert [f.rule_id for f in Scanner.scan_source(src).findings] == [rule]

    def test_importing_alone_is_not_a_finding(self) -> None:
        assert Scanner.scan_source("from Crypto.PublicKey import RSA\n").findings == []

    def test_other_pycryptodome_modules_are_not_reported(self) -> None:
        src = "from Crypto.Cipher import AES\nAES.new(b'k' * 32, AES.MODE_GCM)\n"
        assert Scanner.scan_source(src).findings == []


class TestSbomKnowledgeBase:
    @pytest.mark.parametrize(
        "name", ["quantum-safe-py", "quantum_safe_py", "Quantum-Safe-Py", "quantum-safe"]
    )
    def test_this_library_is_recognised_by_its_names(self, name: str) -> None:
        assert _assess_component(name, "0.4.0").readiness.value == "READY"

    @pytest.mark.parametrize("name", ["pyjwt", "PyJWT", "PYJWT"])
    def test_names_are_matched_the_way_pip_matches_them(self, name: str) -> None:
        assert "knowledge base" not in _assess_component(name, "2.8.0").reason

    def test_underscore_and_hyphen_are_the_same_package(self) -> None:
        assert "knowledge base" not in _assess_component("liboqs_python", "0.9.1").reason

    def test_cryptography_before_48_has_no_ml_kem(self) -> None:
        assert _assess_component("cryptography", "47.9.0").readiness.value == "NOT_READY"
        assert _assess_component("cryptography", "48.0.0").readiness.value == "PARTIAL"

    def test_two_part_versions_compare_as_three_part(self) -> None:
        assert _version_ge("48.0", "48.0.0")
        assert _version_ge("48", "48.0.0")
        assert not _version_ge("47.9", "48.0.0")

    @pytest.mark.parametrize(
        ("line", "version"),
        [
            ("cryptography==48.0.1", "48.0.1"),
            ("cryptography>=48.0", "48.0"),
            ("cryptography~=48.0", "48.0"),
            ("cryptography>47", "47"),
            ("cryptography==48.*", "48"),
            ("cryptography>=48,<50", "48"),
            ("cryptography<50,>=48", "48"),
            ("cryptography<=50", None),
            ("cryptography<50", None),
            ("cryptography!=47.0", None),
            ("cryptography", None),
            ('cryptography[ssh]>=48;python_version>"3.9"', "48"),
        ],
    )
    def test_requirement_versions(self, line: str, version: str | None) -> None:
        (assessment,) = SBOMEnricher.from_requirements(line)
        assert assessment.name == "cryptography"
        assert assessment.version == version

    def test_an_upper_bound_never_claims_readiness(self) -> None:
        (assessment,) = SBOMEnricher.from_requirements("cryptography<=99")
        assert assessment.readiness.value == "UNKNOWN"

    def test_enriched_sbom_names_the_installed_version(self) -> None:
        enriched, _ = SBOMEnricher.enrich({"bomFormat": "CycloneDX", "components": []})
        values = [p["value"] for p in enriched["metadata"]["properties"]]
        assert f"quantum-safe v{__version__}" in values


class TestAuditCli:
    def _invoke(self, tmp_path: Path, *extra: str):  # type: ignore[no-untyped-def]
        pytest.importorskip("click")
        from click.testing import CliRunner

        from quantum_safe.audit.cli import _cli  # type: ignore[attr-defined]

        src = tmp_path / "a.py"
        src.write_text("x = 1\n")
        return CliRunner().invoke(_cli, ["scan", str(src), *extra])

    def test_metadata_without_equals_is_an_error(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, "--metadata", "branch")
        assert result.exit_code == 2
        assert "KEY=VALUE" in result.output

    def test_metadata_pair_is_accepted(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, "--metadata", "branch=main")
        assert result.exit_code == 0, result.output


class TestBadCosigBundle:
    @pytest.mark.requires_liboqs
    def test_a_bundle_that_is_not_a_map_is_a_parse_error(self) -> None:
        from quantum_safe._internal import serialization as ser
        from quantum_safe.exceptions import KeyParseError
        from quantum_safe.protocols.x509 import (
            HybridCertificateBuilder,
            generate_classical_keypair_for_cert,
        )
        from quantum_safe.signatures.hybrid import HybridSign

        pair = HybridSign().generate_keypair()
        cert_pem, _ = HybridCertificateBuilder(
            subject_cn="t.example",
            classical_private_key=generate_classical_keypair_for_cert("Ed25519"),
            pqc_keypair=pair,
        ).build()
        with pytest.raises(KeyParseError):
            HybridCertificateBuilder.verify_cosig(cert_pem, ser.dumps([1, 2, 3]), pair.public)


class TestPycaSignErrors:
    def test_an_unknown_algorithm_is_unsupported_not_a_signing_failure(self) -> None:
        from quantum_safe.backends.pyca import PycaSignatureBackend
        from quantum_safe.exceptions import UnsupportedAlgorithm

        backend = PycaSignatureBackend()
        with pytest.raises(UnsupportedAlgorithm):
            backend.sign("ML-DSA-99", b"\x00" * 32, b"message")
        with pytest.raises(UnsupportedAlgorithm):
            backend.sign_native_context("ML-DSA-99", b"\x00" * 32, b"message", b"")
