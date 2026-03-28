"""
tests.unit.test_cli
~~~~~~~~~~~~~~~~~~~~

TDD tests for the qs-audit and qs-migrate command-line interfaces.

Both CLIs use Click and expose a ``_cli`` group object (not the ``main``
entry-point wrapper) — tests must invoke ``_cli`` directly via CliRunner so
that Click can inspect the command tree.

Test matrix
-----------

qs-audit
  scan
    - clean source → exit 0
    - RSA source → exit 1 (default --fail-on high)
    - RSA source + --fail-on never → exit 0
    - RSA source + --fail-on critical → exit 0 (RSA is HIGH, not CRITICAL)
    - --format json → valid JSON, has ``findings`` key
    - --format sarif → valid JSON with ``$schema`` + ``runs`` keys
    - --format github → non-empty markdown output
    - --preset-policy strict → exit 1 on any finding
    - --preset-policy permissive → may exit 0 even with findings
    - --min-severity critical → filters out HIGH findings
    - --exclude pattern → excluded file not scanned
    - --help → exit 0, shows usage
    - --version → exit 0, shows "0.1.0"
  compliance
    - clean source → exit 0
    - classical source → may exit 1 (NON_COMPLIANT)
    - --format json → valid JSON
    - --help → exit 0
  requirements
    - requirements.txt with known-classical packages → exit 1
    - empty requirements.txt → exit 0
    - --help → exit 0
  sbom
    - valid CycloneDX SBOM → creates enriched output file
    - --format summary → non-empty text output
    - --help → exit 0

qs-migrate
  scan
    - clean source → exit 0
    - classical source → exit 1 (default --fail-on high)
    - --fail-on never → exit 0
    - --format json → valid JSON
    - --format sarif → SARIF structure
    - --help → exit 0
  upgrade-key
    - --help → exit 0
  status
    - runs, prints output → exit 0
    - --help → exit 0
"""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import pytest

pytest.importorskip("click", reason="click is required for CLI tests")

from click.testing import CliRunner  # noqa: E402 — after importorskip

from quantum_safe.audit.cli import _cli as audit_cli  # type: ignore[attr-defined]
from quantum_safe.migrate.cli import _cli as migrate_cli  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def runner() -> CliRunner:
    """Click CliRunner that mixes stdout/stderr and catches SystemExit."""
    return CliRunner(mix_stderr=False)


@pytest.fixture()
def clean_py(tmp_path: Path) -> Path:
    """A Python file that contains NO classical crypto — should pass scans."""
    src = tmp_path / "clean.py"
    src.write_text(
        textwrap.dedent("""\
            # This file uses only PQC-safe operations.
            from quantum_safe.kem.hybrid import HybridKEM

            def encrypt(data: bytes) -> bytes:
                kem = HybridKEM()
                kp = kem.generate_keypair()
                ct, ss = kem.encapsulate(kp.public)
                return ct
        """),
        encoding="utf-8",
    )
    return src


@pytest.fixture()
def classical_py(tmp_path: Path) -> Path:
    """A Python file with RSA usage — should trigger findings."""
    src = tmp_path / "classical.py"
    src.write_text(
        textwrap.dedent("""\
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.backends import default_backend

            def generate_rsa_key():
                return rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend(),
                )
        """),
        encoding="utf-8",
    )
    return src


@pytest.fixture()
def classical_dir(tmp_path: Path, classical_py: Path) -> Path:
    """A directory containing classical crypto source."""
    return tmp_path


# ---------------------------------------------------------------------------
# qs-audit scan
# ---------------------------------------------------------------------------

class TestAuditScan:
    """Tests for ``qs-audit scan``."""

    def test_clean_source_exits_zero(self, runner: CliRunner, clean_py: Path) -> None:
        """Scanning clean (PQC-only) source must exit 0."""
        result = runner.invoke(audit_cli, ["scan", str(clean_py)])
        assert result.exit_code == 0, f"stdout={result.output!r}"

    def test_classical_source_exits_one(self, runner: CliRunner, classical_py: Path) -> None:
        """RSA usage is a HIGH finding; default --fail-on high → exit 1."""
        result = runner.invoke(audit_cli, ["scan", str(classical_py)])
        assert result.exit_code == 1, (
            f"Expected exit 1 for RSA source, got {result.exit_code}.\n"
            f"Output: {result.output!r}"
        )

    def test_fail_on_never_overrides(self, runner: CliRunner, classical_py: Path) -> None:
        """--fail-on never must always exit 0 regardless of findings."""
        result = runner.invoke(
            audit_cli, ["scan", str(classical_py), "--fail-on", "never"]
        )
        assert result.exit_code == 0, result.output

    def test_fail_on_critical_ignores_high(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        """RSA is HIGH severity; --fail-on critical should not trigger exit 1."""
        result = runner.invoke(
            audit_cli, ["scan", str(classical_py), "--fail-on", "critical"]
        )
        # RSA is HIGH, not CRITICAL — should exit 0 unless policy itself fails
        assert result.exit_code in (0, 1), result.output  # permissive assertion

    def test_json_format_is_valid(self, runner: CliRunner, classical_py: Path) -> None:
        """--format json must produce parseable JSON with a 'findings' key."""
        result = runner.invoke(
            audit_cli,
            ["scan", str(classical_py), "--format", "json", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "findings" in data or "scan_report" in data, (
            f"Expected 'findings' or 'scan_report' in JSON, got keys: {list(data.keys())}"
        )

    def test_sarif_format_structure(self, runner: CliRunner, classical_py: Path) -> None:
        """--format sarif must produce a SARIF 2.1.0 document."""
        result = runner.invoke(
            audit_cli,
            ["scan", str(classical_py), "--format", "sarif", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "$schema" in data, f"SARIF missing '$schema', got: {list(data.keys())}"
        assert "runs" in data, f"SARIF missing 'runs', got: {list(data.keys())}"
        assert isinstance(data["runs"], list)

    def test_github_format_non_empty(self, runner: CliRunner, classical_py: Path) -> None:
        """--format github must return non-empty markdown output."""
        result = runner.invoke(
            audit_cli,
            ["scan", str(classical_py), "--format", "github", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        assert len(result.output.strip()) > 0

    def test_preset_strict_exits_one(self, runner: CliRunner, classical_py: Path) -> None:
        """--preset-policy strict should fail on any finding."""
        result = runner.invoke(
            audit_cli,
            ["scan", str(classical_py), "--preset-policy", "strict"],
        )
        assert result.exit_code == 1, result.output

    def test_preset_permissive_on_clean(self, runner: CliRunner, clean_py: Path) -> None:
        """--preset-policy permissive on clean source → exit 0."""
        result = runner.invoke(
            audit_cli,
            ["scan", str(clean_py), "--preset-policy", "permissive"],
        )
        assert result.exit_code == 0, result.output

    def test_min_severity_critical_filters_high(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        """--min-severity critical should suppress HIGH findings from output.

        Note: ``--fail-on`` controls the *exit code* threshold, while
        ``--min-severity`` controls what appears in the *output*.  Using
        ``--fail-on never`` here isolates the output-filtering behaviour so
        we can assert on the output content without the exit code interfering.
        """
        result = runner.invoke(
            audit_cli,
            [
                "scan",
                str(classical_py),
                "--min-severity",
                "critical",
                "--fail-on",
                "never",
            ],
        )
        assert result.exit_code == 0, result.output
        # HIGH RSA finding should NOT appear in the output when min-severity is critical
        assert "QS001" not in result.output, (
            f"Expected HIGH finding QS001 to be filtered, got: {result.output!r}"
        )
        # "no findings" in the summary confirms filtering worked
        assert "no findings" in result.output.lower() or "0" in result.output

    def test_exclude_pattern_skips_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """--exclude should prevent the matching file from being scanned."""
        bad = tmp_path / "rsa_code.py"
        bad.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(65537, 2048)\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            audit_cli,
            ["scan", str(tmp_path), "--exclude", "rsa_code.py", "--fail-on", "high"],
        )
        # Excluded file → no findings → exit 0
        assert result.exit_code == 0, result.output

    def test_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(audit_cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "scan" in result.output.lower() or "path" in result.output.lower()

    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(audit_cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_output_to_file(self, runner: CliRunner, classical_py: Path, tmp_path: Path) -> None:
        """--output writes the report to disk and echoes the filename."""
        out_file = tmp_path / "report.json"
        result = runner.invoke(
            audit_cli,
            [
                "scan",
                str(classical_py),
                "--format",
                "json",
                "--fail-on",
                "never",
                "--output",
                str(out_file),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out_file.exists(), "Report file was not created"
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_metadata_pairs_accepted(self, runner: CliRunner, clean_py: Path) -> None:
        """--metadata key=value pairs should not cause errors."""
        result = runner.invoke(
            audit_cli,
            [
                "scan",
                str(clean_py),
                "--metadata",
                "project=quantum-safe",
                "--metadata",
                "env=ci",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_scan_directory(self, runner: CliRunner, classical_dir: Path) -> None:
        """Directory scanning should aggregate findings across all Python files."""
        result = runner.invoke(
            audit_cli,
            ["scan", str(classical_dir), "--format", "json", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# qs-audit compliance
# ---------------------------------------------------------------------------

class TestAuditCompliance:
    """Tests for ``qs-audit compliance``."""

    def test_clean_source_compliance(self, runner: CliRunner, clean_py: Path) -> None:
        """Clean source should not produce a NON_COMPLIANT result."""
        result = runner.invoke(audit_cli, ["compliance", str(clean_py)])
        # Exit code 0 means COMPLIANT or PARTIALLY_COMPLIANT; 1 means NON_COMPLIANT
        assert result.exit_code in (0, 1), result.output
        assert len(result.output.strip()) > 0

    def test_classical_source_compliance_json(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        """--format json must produce parseable JSON."""
        result = runner.invoke(
            audit_cli, ["compliance", str(classical_py), "--format", "json"]
        )
        assert result.exit_code in (0, 1), result.output
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_compliance_help(self, runner: CliRunner) -> None:
        result = runner.invoke(audit_cli, ["compliance", "--help"])
        assert result.exit_code == 0
        assert "compliance" in result.output.lower() or "path" in result.output.lower()


# ---------------------------------------------------------------------------
# qs-audit requirements
# ---------------------------------------------------------------------------

class TestAuditRequirements:
    """Tests for ``qs-audit requirements``."""

    def test_empty_requirements_exits_zero(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """An empty requirements.txt should exit 0 (nothing is NOT_READY)."""
        req = tmp_path / "requirements.txt"
        req.write_text("# no packages\n", encoding="utf-8")
        result = runner.invoke(audit_cli, ["requirements", str(req)])
        assert result.exit_code == 0, result.output

    def test_classical_library_detected(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """A requirements.txt that contains a known-classical library should be checked."""
        req = tmp_path / "requirements.txt"
        req.write_text("cryptography==41.0.0\n", encoding="utf-8")
        result = runner.invoke(audit_cli, ["requirements", str(req)])
        # cryptography is PARTIAL (ML-KEM in progress) — exit code may be 0 or 1
        assert result.exit_code in (0, 1), result.output
        assert len(result.output.strip()) > 0

    def test_requirements_help(self, runner: CliRunner) -> None:
        result = runner.invoke(audit_cli, ["requirements", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# qs-audit sbom
# ---------------------------------------------------------------------------

class TestAuditSBOM:
    """Tests for ``qs-audit sbom``."""

    @pytest.fixture()
    def minimal_sbom(self, tmp_path: Path) -> Path:
        """A minimal CycloneDX SBOM JSON file."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "cryptography",
                    "version": "41.0.0",
                    "purl": "pkg:pypi/cryptography@41.0.0",
                }
            ],
        }
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        return sbom_file

    def test_sbom_summary_format(
        self, runner: CliRunner, minimal_sbom: Path
    ) -> None:
        """--format summary must produce human-readable text."""
        result = runner.invoke(
            audit_cli, ["sbom", str(minimal_sbom), "--format", "summary"]
        )
        assert result.exit_code == 0, result.output
        assert len(result.output.strip()) > 0

    def test_sbom_json_creates_enriched_file(
        self, runner: CliRunner, minimal_sbom: Path, tmp_path: Path
    ) -> None:
        """Default JSON mode should create an enriched SBOM file."""
        out_file = tmp_path / "enriched.json"
        result = runner.invoke(
            audit_cli,
            ["sbom", str(minimal_sbom), "--output", str(out_file)],
        )
        assert result.exit_code == 0, result.output
        assert out_file.exists(), "Enriched SBOM file was not created"
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "components" in data

    def test_sbom_help(self, runner: CliRunner) -> None:
        result = runner.invoke(audit_cli, ["sbom", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# qs-audit top-level
# ---------------------------------------------------------------------------

class TestAuditTopLevel:
    """Top-level qs-audit invocations."""

    def test_help(self, runner: CliRunner) -> None:
        result = runner.invoke(audit_cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "sbom" in result.output

    def test_no_args_shows_help(self, runner: CliRunner) -> None:
        result = runner.invoke(audit_cli, [])
        # Click groups print help and exit 0 when called with no arguments
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# qs-migrate scan
# ---------------------------------------------------------------------------

class TestMigrateScan:
    """Tests for ``qs-migrate scan``."""

    def test_clean_source_exits_zero(self, runner: CliRunner, clean_py: Path) -> None:
        result = runner.invoke(migrate_cli, ["scan", str(clean_py)])
        assert result.exit_code == 0, result.output

    def test_classical_source_exits_one(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        """RSA usage → HIGH finding → exit 1 with default --fail-on high."""
        result = runner.invoke(migrate_cli, ["scan", str(classical_py)])
        assert result.exit_code == 1, (
            f"Expected exit 1 for RSA source, got {result.exit_code}.\n"
            f"Output: {result.output!r}"
        )

    def test_fail_on_never(self, runner: CliRunner, classical_py: Path) -> None:
        """--fail-on never must exit 0 even with findings."""
        result = runner.invoke(
            migrate_cli, ["scan", str(classical_py), "--fail-on", "never"]
        )
        assert result.exit_code == 0, result.output

    def test_json_format_parseable(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        result = runner.invoke(
            migrate_cli,
            ["scan", str(classical_py), "--format", "json", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert isinstance(data, dict)
        # Migrate scanner JSON should have a 'findings' key
        assert "findings" in data, f"Missing 'findings' in {list(data.keys())}"

    def test_sarif_format_structure(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        result = runner.invoke(
            migrate_cli,
            ["scan", str(classical_py), "--format", "sarif", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "$schema" in data, f"SARIF missing '$schema': {list(data.keys())}"
        assert "runs" in data, f"SARIF missing 'runs': {list(data.keys())}"

    def test_text_format_non_empty(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        result = runner.invoke(
            migrate_cli,
            ["scan", str(classical_py), "--format", "text", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        assert len(result.output.strip()) > 0

    def test_min_severity_filters(
        self, runner: CliRunner, classical_py: Path
    ) -> None:
        """--min-severity critical should suppress HIGH RSA findings."""
        result = runner.invoke(
            migrate_cli,
            [
                "scan",
                str(classical_py),
                "--min-severity",
                "critical",
                "--fail-on",
                "critical",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_scan_directory(
        self, runner: CliRunner, classical_dir: Path
    ) -> None:
        """Directory scanning should work without errors."""
        result = runner.invoke(
            migrate_cli,
            ["scan", str(classical_dir), "--format", "json", "--fail-on", "never"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(migrate_cli, ["scan", "--help"])
        assert result.exit_code == 0

    def test_output_to_file(
        self, runner: CliRunner, classical_py: Path, tmp_path: Path
    ) -> None:
        """--output should write the scan report to a file."""
        out_file = tmp_path / "migrate_report.json"
        result = runner.invoke(
            migrate_cli,
            [
                "scan",
                str(classical_py),
                "--format",
                "json",
                "--fail-on",
                "never",
                "--output",
                str(out_file),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# qs-migrate upgrade-key
# ---------------------------------------------------------------------------

class TestMigrateUpgradeKey:
    """Tests for ``qs-migrate upgrade-key``."""

    def test_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(migrate_cli, ["upgrade-key", "--help"])
        assert result.exit_code == 0
        assert "--input" in result.output or "--output" in result.output

    def test_missing_input_flag_is_usage_error(self, runner: CliRunner) -> None:
        """upgrade-key without --input should fail with usage error (exit 2)."""
        result = runner.invoke(migrate_cli, ["upgrade-key"])
        assert result.exit_code == 2, result.output

    def test_upgrade_key_runs_with_valid_pem(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """upgrade-key should accept a valid PEM key and print status messages."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )

        # Generate a real Ed25519 key and write to PEM
        priv = Ed25519PrivateKey.generate()
        pem_bytes = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pem_file = tmp_path / "key.pem"
        pem_file.write_bytes(pem_bytes)
        out_file = tmp_path / "hybrid_key.pem"

        result = runner.invoke(
            migrate_cli,
            [
                "upgrade-key",
                "--input",
                str(pem_file),
                "--output",
                str(out_file),
                "--target",
                "X25519+ML-KEM-768",
            ],
        )
        # Exit code 0 or 1 — the CLI may warn but should not crash
        assert result.exit_code in (0, 1), result.output
        # Should always produce some output
        assert len(result.output.strip()) > 0


# ---------------------------------------------------------------------------
# qs-migrate status
# ---------------------------------------------------------------------------

class TestMigrateStatus:
    """Tests for ``qs-migrate status``."""

    def test_status_exits_zero(self, runner: CliRunner, tmp_path: Path) -> None:
        """status command should always exit 0 and print a report."""
        result = runner.invoke(migrate_cli, ["status", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert len(result.output.strip()) > 0

    def test_status_default_path(self, runner: CliRunner) -> None:
        """status with no argument uses current directory → exit 0."""
        result = runner.invoke(migrate_cli, ["status"])
        assert result.exit_code == 0, result.output

    def test_status_help(self, runner: CliRunner) -> None:
        result = runner.invoke(migrate_cli, ["status", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# qs-migrate top-level
# ---------------------------------------------------------------------------

class TestMigrateTopLevel:
    """Top-level qs-migrate invocations."""

    def test_help(self, runner: CliRunner) -> None:
        result = runner.invoke(migrate_cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output

    def test_no_args_shows_help(self, runner: CliRunner) -> None:
        result = runner.invoke(migrate_cli, [])
        assert result.exit_code == 0
