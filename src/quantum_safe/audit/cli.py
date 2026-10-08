"""
quantum_safe.audit.cli
~~~~~~~~~~~~~~~~~~~~~~~

Command-line interface for the qs-audit tool.

Installation::

    pip install quantum-safe
    qs-audit --help

Subcommands::

    qs-audit scan ./src                     # text output
    qs-audit scan ./src --format sarif      # SARIF for GitHub
    qs-audit scan ./src --format json       # JSON report
    qs-audit scan ./src --policy policy.json  # with custom policy
    qs-audit sbom sbom.json                 # enrich a CycloneDX SBOM
    qs-audit requirements requirements.txt  # quick check from requirements.txt
    qs-audit compliance ./src               # NIST SP 800-208 report

Exit codes:
    0   All policies pass / no blocking findings
    1   Policy violations or blocking findings found
    2   Usage error
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import click

    _HAS_CLICK = True
except ImportError:
    _HAS_CLICK = False


def main() -> None:
    """Entry point for qs-audit CLI."""
    if not _HAS_CLICK:
        print(
            "Error: click is required for the CLI. Install with: pip install 'quantum-safe[dev]'",
            file=sys.stderr,
        )
        sys.exit(2)
    _cli()


if _HAS_CLICK:

    @click.group(no_args_is_help=True)
    @click.version_option(version="0.1.0", prog_name="qs-audit")
    def _cli() -> None:
        """quantum-safe PQC audit tools."""

    # ------------------------------------------------------------------
    # scan subcommand
    # ------------------------------------------------------------------

    @_cli.command("scan")
    @click.argument("path", default=".", type=click.Path(exists=True))
    @click.option(
        "--format",
        "fmt",
        default="text",
        type=click.Choice(["text", "json", "sarif", "github"]),
        help="Output format.",
    )
    @click.option("--output", "-o", default=None, help="Output file. Default: stdout.")
    @click.option(
        "--policy",
        "policy_file",
        default=None,
        type=click.Path(exists=True),
        help="Path to a policy JSON/YAML file (quantum-safe.yaml).",
    )
    @click.option(
        "--preset-policy",
        type=click.Choice(["standard", "strict", "transition", "permissive"]),
        default="standard",
        help="Use a built-in policy preset.",
    )
    @click.option(
        "--inventory",
        "inventory_file",
        default=None,
        type=click.Path(exists=True),
        help=(
            "JSON key inventory ([{key_id, algorithm, migration_state}, ...]). Needed to "
            "enforce min_security_level, hybrid_required, allow_non_nist_standard, "
            "require_migration_state and max_classical_only_keys."
        ),
    )
    @click.option(
        "--min-severity",
        default="info",
        type=click.Choice(["info", "medium", "high", "critical"]),
        help="Minimum severity to include in output.",
    )
    @click.option(
        "--fail-on",
        default="high",
        type=click.Choice(["info", "medium", "high", "critical", "never"]),
        help="Exit code 1 if findings at this severity or above exist.",
    )
    @click.option("--exclude", "-e", multiple=True, help="Path pattern to exclude (repeatable).")
    @click.option(
        "--metadata",
        "-m",
        multiple=True,
        help="key=value metadata pairs for the report (repeatable).",
    )
    def scan_cmd(
        path: str,
        fmt: str,
        output: str | None,
        policy_file: str | None,
        preset_policy: str,
        inventory_file: str | None,
        min_severity: str,
        fail_on: str,
        exclude: tuple[str, ...],
        metadata: tuple[str, ...],
    ) -> None:
        """Scan PATH for classical cryptography usage."""
        from quantum_safe.audit.auditor import Auditor
        from quantum_safe.audit.inventory import load_inventory
        from quantum_safe.audit.policy import AuditPolicy
        from quantum_safe.migrate.scanner import Severity

        # Resolve policy. A policy or inventory that cannot be read must stop the
        # run with a non-zero exit, never fall back to a weaker one.
        if policy_file:
            try:
                policy = AuditPolicy.from_file(policy_file)
            except (ValueError, OSError) as exc:
                raise click.ClickException(f"invalid policy file {policy_file}: {exc}") from exc
        elif preset_policy == "strict":
            policy = AuditPolicy.strict()
        elif preset_policy == "transition":
            policy = AuditPolicy.transition()
        elif preset_policy == "permissive":
            policy = AuditPolicy.permissive()
        else:
            policy = AuditPolicy()

        # Parse metadata pairs
        meta: dict[str, str] = {}
        for item in metadata:
            if "=" in item:
                k, _, val = item.partition("=")
                meta[k.strip()] = val.strip()

        inventory = None
        if inventory_file:
            try:
                inventory = load_inventory(inventory_file)
            except (ValueError, OSError) as exc:
                raise click.ClickException(f"invalid inventory {inventory_file}: {exc}") from exc

        report = Auditor.audit(
            path,
            policy=policy,
            metadata=meta,
            exclude=list(exclude) or None,
            inventory=inventory,
        )

        # Filter by min_severity for output
        min_sev = Severity[min_severity.upper()]
        filtered_findings = [f for f in report.scan_report.findings if f.severity >= min_sev]
        report.scan_report.findings = filtered_findings

        # Produce output
        if fmt == "text":
            lines = [report.scan_report.summary(), ""]
            for f in filtered_findings:
                lines.append(str(f))
                if f.fix_hint:
                    lines.append(f"  -> {f.fix_hint}")
            if report.policy_violations:
                lines.append("\nPolicy violations:")
                for v in report.policy_violations:
                    lines.append(f"  {v}")
            if report.unevaluated_controls:
                lines.append(
                    "\nNot evaluated (pass --inventory to enforce): "
                    + ", ".join(report.unevaluated_controls)
                )
            lines.append(f"\nResult: {'PASSED' if report.passed else 'FAILED'}")
            out = "\n".join(lines)

        elif fmt == "json":
            out = report.to_json()

        elif fmt == "sarif":
            out = json.dumps(report.to_sarif(), indent=2)

        elif fmt == "github":
            out = report.to_github_summary()

        else:
            out = report.to_json()

        # Write output
        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(out, encoding="utf-8")
            click.echo(f"Report written to {output}")
        else:
            click.echo(out)

        # Exit code based on fail_on.
        # ``--fail-on never`` suppresses ALL non-zero exits from this command,
        # including policy-level failures.  Any other value causes exit 1 when
        # either (a) a finding at or above the threshold exists, or (b) the
        # policy evaluator marks the audit as failed.
        if fail_on != "never":
            fail_sev = Severity[fail_on.upper()]
            if any(f.severity >= fail_sev for f in filtered_findings):
                sys.exit(1)
            if not report.passed:
                sys.exit(1)

    # ------------------------------------------------------------------
    # sbom subcommand
    # ------------------------------------------------------------------

    @_cli.command("sbom")
    @click.argument("sbom_file", type=click.Path(exists=True))
    @click.option("--output", "-o", default=None, help="Output file. Default: <input>-pqc.json")
    @click.option(
        "--format",
        "fmt",
        default="json",
        type=click.Choice(["json", "summary"]),
        help="Output format.",
    )
    def sbom_cmd(sbom_file: str, output: str | None, fmt: str) -> None:
        """Enrich a CycloneDX SBOM with PQC-readiness annotations."""
        from quantum_safe.audit.sbom import PQCReadiness, SBOMEnricher

        with open(sbom_file, encoding="utf-8") as fh:
            sbom = json.load(fh)

        enriched, assessments = SBOMEnricher.enrich(sbom)

        if fmt == "summary":
            click.echo(f"\nSBOM PQC Readiness Summary for: {sbom_file}")
            click.echo("-" * 50)
            for a in assessments:
                icon = {"READY": "+", "PARTIAL": "~", "NOT_READY": "x", "UNKNOWN": "?"}.get(
                    a.readiness.value, "?"
                )
                ver = f" {a.version}" if a.version else ""
                click.echo(f"  {icon} {a.name}{ver}: {a.readiness.value}")
                if a.readiness != PQCReadiness.READY:
                    click.echo(f"    -> {a.action}")
            click.echo()
            return

        # JSON output
        out_json = json.dumps(enriched, indent=2)
        if output:
            Path(output).write_text(out_json, encoding="utf-8")
            click.echo(f"Enriched SBOM written to {output}")
        else:
            out_path = Path(sbom_file).stem + "-pqc.json"
            Path(out_path).write_text(out_json, encoding="utf-8")
            click.echo(f"Enriched SBOM written to {out_path}")

    # ------------------------------------------------------------------
    # requirements subcommand
    # ------------------------------------------------------------------

    @_cli.command("requirements")
    @click.argument("req_file", type=click.Path(exists=True))
    def requirements_cmd(req_file: str) -> None:
        """Check PQC readiness of packages in a requirements.txt file."""
        from quantum_safe.audit.sbom import PQCReadiness, SBOMEnricher

        text = Path(req_file).read_text(encoding="utf-8")
        assessments = SBOMEnricher.from_requirements(text)

        not_ready = [a for a in assessments if a.readiness == PQCReadiness.NOT_READY]

        click.echo(f"\nPQC readiness for {req_file}:")
        click.echo(f"  {len(assessments)} packages checked")

        for a in assessments:
            icon = {"READY": "+", "PARTIAL": "~", "NOT_READY": "x", "UNKNOWN": "?"}.get(
                a.readiness.value, "?"
            )
            ver = f" {a.version}" if a.version else ""
            click.echo(f"  {icon} {a.name}{ver}: {a.readiness.value}")

        if not_ready:
            click.echo(f"\n{len(not_ready)} packages are NOT PQC-ready. Consider replacing:")
            for a in not_ready:
                click.echo(f"  - {a.name}: {a.action}")
            sys.exit(1)

    # ------------------------------------------------------------------
    # compliance subcommand
    # ------------------------------------------------------------------

    @_cli.command("compliance")
    @click.argument("path", default=".", type=click.Path(exists=True))
    @click.option(
        "--format",
        "fmt",
        default="text",
        type=click.Choice(["text", "json"]),
        help="Output format.",
    )
    @click.option("--output", "-o", default=None, help="Output file. Default: stdout.")
    def compliance_cmd(path: str, fmt: str, output: str | None) -> None:
        """Generate a NIST SP 800-208 compliance report for PATH."""
        from quantum_safe.audit.compliance import ComplianceLevel, NISTComplianceChecker
        from quantum_safe.migrate.scanner import Scanner

        p = Path(path)
        if p.is_file():
            scan = Scanner.scan_file(p)
        else:
            scan = Scanner.scan_directory(p)

        report = NISTComplianceChecker.check(scan, target=str(p))

        if fmt == "json":
            out = report.to_json()
        else:
            out = "\n".join(report.summary_lines())

        if output:
            Path(output).write_text(out, encoding="utf-8")
            click.echo(f"Compliance report written to {output}")
        else:
            click.echo(out)

        if report.overall_level == ComplianceLevel.NON_COMPLIANT:
            sys.exit(1)

    # ------------------------------------------------------------------
    # cnsa2 subcommand
    # ------------------------------------------------------------------

    @_cli.command("cnsa2")
    @click.option(
        "--kem",
        default="X25519+ML-KEM-768",
        show_default=True,
        help="KEM or hybrid KEM selection to evaluate.",
    )
    @click.option(
        "--signature",
        default="Ed25519+ML-DSA-65",
        show_default=True,
        help="Signature or hybrid signature selection to evaluate.",
    )
    @click.option(
        "--hash",
        "hash_algorithm",
        default="SHA-256",
        show_default=True,
        help="Hash used for derivation and signing.",
    )
    @click.option(
        "--skip-code-signing",
        is_flag=True,
        help=(
            "Omit the SP 800-208 software/firmware signing requirement. Only use "
            "this if the deployment provably does not sign software or firmware; "
            "otherwise the report looks cleaner than the deployment is."
        ),
    )
    @click.option("--output", "-o", default=None, help="Output file. Default: stdout.")
    def cnsa2_cmd(
        kem: str,
        signature: str,
        hash_algorithm: str,
        skip_code_signing: bool,
        output: str | None,
    ) -> None:
        """Check a configuration against CNSA 2.0 parameter requirements.

        Defaults deliberately mirror this library's own defaults, so running the
        command with no arguments shows what an unconfigured deployment scores.
        It does not score compliant: CNSA 2.0 requires ML-KEM-1024 and ML-DSA-87.

        This reports parameter selection only. CNSA 2.0 compliance for National
        Security Systems runs through FIPS 140-3 validated modules, and no
        self-assessment produces one.
        """
        from quantum_safe.compliance import cnsa2

        report = cnsa2.report(
            kem=kem,
            signature=signature,
            hash_algorithm=hash_algorithm,
            include_code_signing=not skip_code_signing,
        )
        out = report.render()

        if output:
            Path(output).write_text(out, encoding="utf-8")
            click.echo(f"CNSA 2.0 report written to {output}")
        else:
            click.echo(out)

        if not report.compliant:
            sys.exit(1)

    # ------------------------------------------------------------------
    # cbom subcommand
    # ------------------------------------------------------------------

    @_cli.command("cbom")
    @click.argument("path", default=".", type=click.Path(exists=True))
    @click.option("--output", "-o", default=None, help="Output file. Default: stdout.")
    @click.option(
        "--no-provided",
        is_flag=True,
        help=(
            "Omit the post-quantum algorithms this library provides, listing only "
            "what the scan detected. Useful when the consumer wants current usage "
            "rather than migration options."
        ),
    )
    @click.option(
        "--exclude",
        multiple=True,
        help="Glob pattern to exclude. Repeatable.",
    )
    def cbom_cmd(
        path: str, output: str | None, no_provided: bool, exclude: tuple[str, ...]
    ) -> None:
        """Emit a CycloneDX 1.6 Cryptographic Bill of Materials for PATH.

        Produces machine-readable cryptographic inventory: every detected
        classical algorithm with its location and quantum-vulnerability
        assessment, plus the post-quantum algorithms available to migrate to.

        This is an inventory, not a compliance verdict. For CNSA 2.0 parameter
        requirements use `qs-audit cnsa2`.
        """
        from quantum_safe.audit.cbom import build_cbom, to_json
        from quantum_safe.migrate.scanner import Scanner

        p = Path(path)
        if p.is_file():
            scan = Scanner.scan_file(p)
        else:
            scan = Scanner.scan_directory(p, exclude=list(exclude) if exclude else None)

        cbom = build_cbom(
            scan,
            include_provided=not no_provided,
            application_name=p.name or str(p),
        )
        out = to_json(cbom)

        if output:
            Path(output).write_text(out, encoding="utf-8")
            n = len(cbom["components"])
            click.echo(f"CBOM written to {output} ({n} cryptographic assets)")
        else:
            click.echo(out)
