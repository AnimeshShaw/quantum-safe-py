"""
quantum_safe.audit.auditor
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Auditor class: the single entry point for a full PQC compliance audit.

It orchestrates:
  1. Scanning source code with migrate.Scanner
  2. Evaluating findings against an AuditPolicy
  3. Optionally enriching an SBOM with PQC-readiness data
  4. Producing a structured AuditReport

The AuditReport is the primary artefact — it contains everything
needed for a security review, a CI gate check, or an audit trail.

Design choice: Auditor is a class with only classmethods. You don't
hold state between audits. Each call to Auditor.audit() is independent.
This makes it safe to call from parallel CI jobs without shared mutable state.
"""

from __future__ import annotations

import datetime
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quantum_safe.audit.policy import AuditPolicy, PolicyViolation
from quantum_safe.migrate.scanner import Scanner, ScanReport


@dataclass
class AuditReport:
    """Complete audit report for a codebase or key store.

    Attributes:
        audit_id:           Unique identifier for this audit run.
        timestamp:          ISO 8601 timestamp of when the audit ran.
        target:             What was audited (directory path, key store ID, etc.).
        scan_report:        The underlying ScanReport from the scanner.
        policy:             The AuditPolicy that was evaluated.
        policy_violations:  List of policy violations found.
        passed:             True if no policy violations exist.
        metadata:           Arbitrary key-value pairs (CI job ID, branch, etc.).
    """

    audit_id: str
    timestamp: str
    target: str
    scan_report: ScanReport
    policy: AuditPolicy
    policy_violations: list[PolicyViolation]
    passed: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def critical_count(self) -> int:
        return len(self.scan_report.critical)

    @property
    def high_count(self) -> int:
        return len(self.scan_report.high)

    @property
    def medium_count(self) -> int:
        return len(self.scan_report.medium)

    @property
    def files_scanned(self) -> int:
        return self.scan_report.files_scanned

    def summary_line(self) -> str:
        """One-line status for logging."""
        status = "PASSED" if self.passed else "FAILED"
        return (
            f"[{status}] Audit {self.audit_id[:8]}... | "
            f"{self.files_scanned} files | "
            f"{self.critical_count}C {self.high_count}H {self.medium_count}M findings | "
            f"{len(self.policy_violations)} violations"
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "passed": self.passed,
            "files_scanned": self.files_scanned,
            "finding_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "info": len(self.scan_report.info),
            },
            "policy_violations": [v.to_dict() for v in self.policy_violations],
            "policy": self.policy.to_dict(),
            "findings": [f.to_dict() for f in self.scan_report.findings],
            "errors": self.scan_report.errors,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_sarif(self) -> dict[str, Any]:
        """Produce SARIF 2.1.0 output (for GitHub Code Scanning)."""
        return self.scan_report.to_sarif()

    def to_github_summary(self) -> str:
        """Markdown summary suitable for GitHub Actions $GITHUB_STEP_SUMMARY."""
        icon = "✅" if self.passed else "❌"
        lines = [
            f"## {icon} PQC Audit - {'PASSED' if self.passed else 'FAILED'}",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Files scanned | {self.files_scanned} |",
            f"| Critical findings | {self.critical_count} |",
            f"| High findings | {self.high_count} |",
            f"| Medium findings | {self.medium_count} |",
            f"| Policy violations | {len(self.policy_violations)} |",
            f"| Audit ID | `{self.audit_id[:16]}` |",
            "",
        ]

        if self.policy_violations:
            lines.append("### Policy violations")
            lines.append("")
            for v in self.policy_violations[:10]:  # cap at 10 for readability
                lines.append(f"- **{v.severity.name}**: {v.detail}")
            if len(self.policy_violations) > 10:
                lines.append(f"- ... and {len(self.policy_violations) - 10} more")
            lines.append("")

        return "\n".join(lines)


class Auditor:
    """Orchestrates PQC compliance auditing.

    All methods are classmethods — no instantiation needed.

    Example::

        from quantum_safe.audit import Auditor, AuditPolicy

        report = Auditor.audit(
            "./src",
            policy=AuditPolicy.strict(),
            metadata={"branch": "main", "commit": "abc123"},
        )
        print(report.summary_line())
        if not report.passed:
            print(report.to_json())
            sys.exit(1)
    """

    @classmethod
    def audit(
        cls,
        target: str | Path,
        policy: AuditPolicy | None = None,
        metadata: dict[str, Any] | None = None,
        exclude: list[str] | None = None,
    ) -> AuditReport:
        """Run a full audit on a directory or file.

        Args:
            target:     Directory or file path to audit.
            policy:     Compliance policy. Defaults to AuditPolicy() (standard).
            metadata:   Arbitrary metadata for the report (CI job ID, etc.).
            exclude:    Directory/file patterns to exclude from scanning.

        Returns:
            AuditReport with all findings and policy evaluation.
        """
        if policy is None:
            policy = AuditPolicy()

        target = Path(target)
        audit_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        # Run the scanner
        if target.is_file():
            scan_report = Scanner.scan_file(target)
        else:
            scan_report = Scanner.scan_directory(target, exclude=exclude)

        # Evaluate policy
        violations = policy.evaluate(scan_report.findings)
        passed = len(violations) == 0

        return AuditReport(
            audit_id=audit_id,
            timestamp=timestamp,
            target=str(target),
            scan_report=scan_report,
            policy=policy,
            policy_violations=violations,
            passed=passed,
            metadata=metadata or {},
        )

    @classmethod
    def audit_source(
        cls,
        source: str,
        filename: str = "<string>",
        policy: AuditPolicy | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditReport:
        """Audit a source string directly (useful in tests and CI hooks).

        Args:
            source:     Python source code as a string.
            filename:   Virtual filename for error messages.
            policy:     Compliance policy. Defaults to AuditPolicy().

        Returns:
            AuditReport.
        """
        if policy is None:
            policy = AuditPolicy()

        scan_report = Scanner.scan_source(source, filename=filename)
        violations = policy.evaluate(scan_report.findings)

        return AuditReport(
            audit_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            target=filename,
            scan_report=scan_report,
            policy=policy,
            policy_violations=violations,
            passed=len(violations) == 0,
            metadata=metadata or {},
        )

    @classmethod
    def ci_gate(
        cls,
        target: str | Path,
        policy: AuditPolicy | None = None,
        output_sarif: str | None = None,
        output_json: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Run audit and return a shell exit code.

        Designed to be called directly from CI pipeline steps::

            exit_code = Auditor.ci_gate("./src", output_sarif="audit.sarif")
            sys.exit(exit_code)

        Args:
            target:         Directory or file to audit.
            policy:         Compliance policy. Defaults to AuditPolicy().
            output_sarif:   If set, write SARIF to this path.
            output_json:    If set, write full JSON report to this path.
            metadata:       Arbitrary metadata for the report.

        Returns:
            0 if all policies pass, 1 if any violations found.
        """
        report = cls.audit(target, policy=policy, metadata=metadata)

        if output_sarif:
            sarif_path = Path(output_sarif)
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            sarif_path.write_text(json.dumps(report.to_sarif(), indent=2), encoding="utf-8")

        if output_json:
            json_path = Path(output_json)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(report.to_json(), encoding="utf-8")

        return 0 if report.passed else 1
