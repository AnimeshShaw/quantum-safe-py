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

    # Upgrade a classical secret key to a hybrid key pair
    qs-migrate upgrade-key --input x25519.pem --output hybrid.pem
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
        type=click.Path(exists=True, dir_okay=False),
        help="Classical SECRET key: a PKCS#8 'PRIVATE KEY' PEM or a library secret-key PEM.",
    )
    @click.option(
        "--output",
        "-o",
        required=True,
        type=click.Path(dir_okay=False),
        help="Where to write the hybrid SECRET key (mode 0600 on POSIX).",
    )
    @click.option(
        "--public-output",
        default=None,
        type=click.Path(dir_okay=False),
        help="Where to write the hybrid public key. Default: <output>.pub",
    )
    @click.option(
        "--target",
        default=None,
        help=(
            "Hybrid algorithm to produce. Default: X25519+ML-KEM-768 for an X25519 key, "
            "Ed25519+ML-DSA-65-v2 for an Ed25519 key."
        ),
    )
    @click.option(
        "--key-type",
        default=None,
        type=click.Choice(["kem", "sign"]),
        help="Optional check: fail unless the input is a KEM (X25519) or signing (Ed25519) key.",
    )
    @click.option("--force", is_flag=True, help="Replace --output / --public-output if they exist.")
    def upgrade_key_cmd(
        input_path: str,
        output: str,
        public_output: str | None,
        target: str | None,
        key_type: str | None,
        force: bool,
    ) -> None:
        """Upgrade a classical X25519 / Ed25519 secret key to a hybrid PQC key pair.

        Writes the hybrid secret key to --output and the hybrid public key next to it.
        The input file is never modified or deleted; keep it for classical-only clients
        until the migration is finished. Exits non-zero, having written nothing, if the
        key cannot be upgraded.
        """
        from quantum_safe.migrate.keyfile import KeyUpgradeError, upgrade_key_file

        try:
            done = upgrade_key_file(
                input_path,
                output,
                public_output,
                target=target,
                key_type=key_type,
                force=force,
            )
        except KeyUpgradeError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        click.echo(f"Upgraded {done.old_algorithm} -> {done.new_algorithm} ({done.key_type} key).")
        click.echo(f"  hybrid secret key: {done.secret_path}")
        click.echo(f"  hybrid public key: {done.public_path}")
        click.echo(f"  {done.notes}")
        click.echo(f"The original key {input_path} was not changed.")

    @_cli.command("rewrap")
    @click.argument("source", type=click.Path(exists=True, file_okay=False))
    @click.argument("destination", required=False, type=click.Path(file_okay=False))
    @click.option(
        "--old-secret",
        required=True,
        type=click.Path(exists=True, dir_okay=False),
        help="Library secret-key PEM the envelopes are sealed to today.",
    )
    @click.option(
        "--new-public",
        required=True,
        type=click.Path(exists=True, dir_okay=False),
        help="Library public-key PEM to seal them to.",
    )
    @click.option(
        "--new-secret",
        default=None,
        type=click.Path(exists=True, dir_okay=False),
        help="The matching new secret-key PEM: each result is opened again and compared.",
    )
    @click.option("--aad", default=None, help="The AAD every envelope must carry (UTF-8 text).")
    @click.option(
        "--aad-from-path",
        is_flag=True,
        help="Expect each envelope's AAD to be its path relative to SOURCE (UTF-8).",
    )
    @click.option(
        "--in-place", is_flag=True, help="Replace files in SOURCE (atomic, one at a time)."
    )
    @click.option("--dry-run", is_flag=True, help="Check everything, write nothing.")
    @click.option(
        "--report", default=None, type=click.Path(dir_okay=False), help="Write the JSON report."
    )
    @click.option(
        "--cbom", default=None, type=click.Path(dir_okay=False), help="Write a CycloneDX report."
    )
    def rewrap_cmd(
        source: str,
        destination: str | None,
        old_secret: str,
        new_public: str,
        new_secret: str | None,
        aad: str | None,
        aad_from_path: bool,
        in_place: bool,
        dry_run: bool,
        report: str | None,
        cbom: str | None,
    ) -> None:
        """Re-wrap every sealed envelope under SOURCE to a new recipient key.

        Writes to DESTINATION (the source is not touched), or replaces files with --in-place.
        Safe to run again: files already migrated are recognised and left alone. Exits 1 if any
        file failed or did not verify.
        """
        import json
        from pathlib import Path

        from quantum_safe.migrate.rewrap import rewrap_directory
        from quantum_safe.types import PublicKey, SecretKey

        if aad is not None and aad_from_path:
            click.echo("Error: use --aad or --aad-from-path, not both.", err=True)
            sys.exit(2)
        expected: bytes | None | object = None
        if aad is not None:
            expected = aad.encode("utf-8")
        elif aad_from_path:
            expected = lambda rel: rel.encode("utf-8")  # noqa: E731
        try:
            result = rewrap_directory(
                source,
                None if in_place else destination,
                old_secret=SecretKey.from_pem(Path(old_secret).read_text(encoding="utf-8")),
                new_public=PublicKey.from_pem(Path(new_public).read_text(encoding="utf-8")),
                new_secret=(
                    SecretKey.from_pem(Path(new_secret).read_text(encoding="utf-8"))
                    if new_secret
                    else None
                ),
                expected_aad=expected,  # type: ignore[arg-type]
                in_place=in_place,
                dry_run=dry_run,
            )
        except (ValueError, OSError) as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(2)

        counts = result.counts
        click.echo(
            f"{'Would re-wrap' if dry_run else 'Re-wrapped'} to {result.new_algorithm}: "
            + ", ".join(f"{k} {v}" for k, v in counts.items())
        )
        for item in result.items:
            if item.status == "failed":
                click.echo(f"  FAILED {item.name}: {item.error}", err=True)
        if not result.aad_checked:
            click.echo("  note: no --aad given, so each message's own AAD was accepted and kept.")
        if report:
            Path(report).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        if cbom:
            Path(cbom).write_text(json.dumps(result.to_cbom(), indent=2), encoding="utf-8")
        sys.exit(0 if result.ok else 1)

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
