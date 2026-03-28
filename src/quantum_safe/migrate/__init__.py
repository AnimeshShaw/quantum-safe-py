"""
quantum_safe.migrate
~~~~~~~~~~~~~~~~~~~~~

Tools for migrating existing classical-crypto codebases and key stores
to post-quantum cryptography.

This module addresses the hardest part of PQC adoption: the real-world gap
between "we should use PQC" and "our 50,000 existing users have X25519 keys
and we can't break them."

Submodules
----------
scanner     AST-based static analysis — finds classical crypto usage in code
upgrader    Key upgrade tooling — migrates keys from classical to hybrid
shims       Drop-in replacement shims for common classical crypto libraries
state       Migration state machine — tracks per-key migration progress
cli         Command-line interface (qs-migrate)

Quick start::

    # Scan a codebase for classical crypto
    from quantum_safe.migrate import Scanner
    report = Scanner.scan_directory("./src")
    for finding in report.findings:
        print(f"{finding.file}:{finding.line} — {finding.severity}: {finding.message}")

    # Upgrade an existing X25519 key to hybrid
    from quantum_safe.migrate import Upgrader
    old_kp = load_my_x25519_keypair()
    new_kp = Upgrader.upgrade(old_kp, target="X25519+ML-KEM-768")
"""

from quantum_safe.migrate.scanner import Finding, ScanReport, Scanner, Severity
from quantum_safe.migrate.state import MigrationRecord, MigrationStateManager
from quantum_safe.migrate.upgrader import UpgradeResult, Upgrader

__all__ = [
    # Scanner
    "Scanner",
    "ScanReport",
    "Finding",
    "Severity",
    # Upgrader
    "Upgrader",
    "UpgradeResult",
    # State machine
    "MigrationStateManager",
    "MigrationRecord",
]
