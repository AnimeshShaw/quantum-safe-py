"""
quantum_safe.migrate.cli
~~~~~~~~~~~~~~~~~~~~~~~~~

Command-line interface for the qs-migrate tool.

Usage::

    # Scan a directory for classical crypto
    qs-migrate scan ./src --format json

    # Scan with SARIF output for GitHub Code Scanning
    qs-migrate scan ./src --format sarif --output audit.sarif

    # Show migration progress for a key store
    qs-migrate status ./keys/

    # Upgrade a key file
    qs-migrate upgrade-key --input key.pem --target X25519+ML-KEM-768
"""

from __future__ import annotations

import json
import sys

try:
    import click

    _HAS_CLICK = True
except ImportError:
    _HAS_CLICK = False


def main() -> None:
    """Entry point for qs-migrate CLI."""
    if not _HAS_CLICK:
        print(  # noqa: T201
            "Error: click is required for the CLI. Install with: pip install click",
            file=sys.stderr,
        )
        sys.exit(1)
    _cli()


if _HAS_CLICK:

    @click.group(no_args_is_help=True)
    def _cli() -> None:
        """quantum-safe migration tools."""

    @_cli.command("scan")
    @click.argument("path", default=".", type=click.Path(exists=True))
    @click.option(
        "--format",
        "fmt",
        default="text",
        type=click.Choice(["text", "json", "sarif"]),
        help="Output format",
    )
    @click.option("--output", "-o", default=None, help="Output file (default: stdout)")
    @click.option(
        "--min-severity",
        default="info",
        type=click.Choice(["info", "medium", "high", "critical"]),
        help="Minimum severity to report",
    )
    @click.option(
        "--fail-on",
        default="high",
        type=click.Choice(["info", "medium", "high", "critical", "never"]),
        help="Exit with code 1 if findings at this severity or above exist",
    )
    def scan_cmd(path: str, fmt: str, output: str | None, min_severity: str, fail_on: str) -> None:
        """Scan PATH for classical cryptography usage."""
        import pathlib

        from quantum_safe.migrate.scanner import Scanner, Severity

        p = pathlib.Path(path)
        if p.is_file():
            report = Scanner.scan_file(p)
        else:
            report = Scanner.scan_directory(p)

        # Filter by minimum severity
        min_sev = Severity[min_severity.upper()]
        filtered = [f for f in report.findings if f.severity >= min_sev]
        report.findings = filtered

        # Produce output
        if fmt == "text":
            out = report.summary() + "\n\n"
            for f in report.findings:
                out += str(f) + "\n"
                if f.fix_hint:
                    out += f"  -> {f.fix_hint}\n"
        elif fmt == "json":
            out = report.to_json()
        else:  # sarif
            out = json.dumps(report.to_sarif(), indent=2)

        if output:
            with open(output, "w") as fh:
                fh.write(out)
            click.echo(f"Written to {output}")
        else:
            click.echo(out)

        # Exit code
        if fail_on != "never":
            fail_sev = Severity[fail_on.upper()]
            if any(f.severity >= fail_sev for f in report.findings):
                sys.exit(1)

    @_cli.command("upgrade-key")
    @click.option(
        "--input",
        "-i",
        "input_path",
        required=True,
        type=click.Path(exists=True),
        help="Input PEM key file",
    )
    @click.option(
        "--output", "-o", required=True, help="Output PEM file for the upgraded hybrid key"
    )
    @click.option(
        "--target",
        default="X25519+ML-KEM-768",
        help="Target hybrid algorithm (default: X25519+ML-KEM-768)",
    )
    @click.option(
        "--key-type",
        default="kem",
        type=click.Choice(["kem", "sign"]),
        help="Whether to upgrade a KEM or signing key",
    )
    def upgrade_key_cmd(input_path: str, output: str, target: str, key_type: str) -> None:
        """Upgrade a classical key to a hybrid PQC key."""
        import pathlib

        from quantum_safe.types import PublicKey, SecretKey

        pem_data = pathlib.Path(input_path).read_text()

        click.echo(f"Loading key from {input_path}...")

        key: SecretKey | PublicKey
        try:
            # Try loading as secret key first
            key = SecretKey.from_pem(pem_data)
            click.echo(f"Loaded secret key: algo={key.algorithm}")
        except Exception:
            try:
                key = PublicKey.from_pem(pem_data)
                click.echo(f"Loaded public key: algo={key.algorithm}")
            except Exception as exc:
                click.echo(f"Error: could not parse key: {exc}", err=True)
                sys.exit(1)

        click.echo(f"Upgrading to {target}...")
        # For a full upgrade we'd need both pub+sec components.
        # This CLI path is illustrative — production use needs the full keypair.
        click.echo(
            "Note: full key upgrade requires a KeyPair (public + secret). "
            "Use Upgrader.upgrade_kem_key() / upgrade_signing_key() from Python directly."
        )

    @_cli.command("status")
    @click.argument("store-path", default=".", type=click.Path())
    def status_cmd(store_path: str) -> None:
        """Show migration progress summary."""
        click.echo("Migration status report")
        click.echo("-" * 40)
        click.echo("(Connect to your key store via MigrationStateManager for live data)")
        click.echo("\nExample Python usage:")
        click.echo("  from quantum_safe.migrate import MigrationStateManager")
        click.echo("  mgr = MigrationStateManager(your_store)")
        click.echo("  print(mgr.migration_progress())")
