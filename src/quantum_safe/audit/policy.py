"""
quantum_safe.audit.policy
~~~~~~~~~~~~~~~~~~~~~~~~~~

Policy-as-code for PQC compliance.

An AuditPolicy defines what the organization requires from its cryptographic
posture. The policy can be loaded from a YAML/JSON file (quantum-safe.yaml)
so it lives in source control alongside the code it governs.

Example quantum-safe.yaml::

    version: 1
    min_security_level: 3        # NIST level 3 minimum (ML-KEM-768, ML-DSA-65)
    allow_classical_only: false  # no classical-only keys in production
    hybrid_required: true        # all PQC must be in hybrid mode
    allow_non_nist_standard: false
    fail_on:
      - CRITICAL
      - HIGH
    exempt_paths:
      - "tests/**"
      - "scripts/legacy_compat.py"
    require_migration_state: hybrid_transition   # minimum acceptable state

The policy is evaluated against a ScanReport to produce a list of
PolicyViolation objects. A non-empty violations list means the policy
is not met — fail the CI gate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quantum_safe.migrate.scanner import Finding, Severity


@dataclass
class PolicyViolation:
    """A single policy rule that was violated.

    Attributes:
        rule:       Human-readable rule description.
        detail:     Specific detail about what violated the rule.
        severity:   Severity level of the underlying finding.
        finding:    The Finding that triggered this violation, if any.
    """

    rule: str
    detail: str
    severity: Severity = Severity.HIGH
    finding: Finding | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule": self.rule,
            "detail": self.detail,
            "severity": self.severity.name,
        }
        if self.finding:
            d["finding"] = self.finding.to_dict()
        return d

    def __str__(self) -> str:
        return f"[{self.severity.name}] {self.rule}: {self.detail}"


@dataclass
class AuditPolicy:
    """Configurable policy for PQC compliance.

    Args:
        min_security_level:     Minimum NIST security level (1-5).
                                Default 3 (ML-KEM-768 / ML-DSA-65 equivalent).
        allow_classical_only:   If False, any classical-only crypto finding
                                at HIGH or above is a violation. Default False.
        hybrid_required:        If True, PQC must always be in hybrid mode.
                                Default True (matches transition-period guidance).
        allow_non_nist_standard: If False, non-NIST-standard algorithms
                                (BIKE, HQC, etc.) are violations. Default False.
        fail_on:                Severity levels that cause policy failure.
                                Default ["CRITICAL", "HIGH"].
        exempt_paths:           File path patterns that are exempt from policy.
                                Supports glob-style wildcards.
        require_migration_state: Minimum acceptable migration state for keys.
                                 Default "hybrid_transition".
        max_classical_only_keys: If set, more than this many CLASSICAL_ONLY keys
                                 in the store is a violation. Default None (no limit).
    """

    min_security_level: int = 3
    allow_classical_only: bool = False
    hybrid_required: bool = True
    allow_non_nist_standard: bool = False
    fail_on: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    exempt_paths: list[str] = field(default_factory=list)
    require_migration_state: str = "hybrid_transition"
    max_classical_only_keys: int | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.min_security_level <= 5:
            raise ValueError(f"min_security_level must be 1-5, got {self.min_security_level}")
        valid_severities = {s.name for s in Severity}
        for s in self.fail_on:
            if s.upper() not in valid_severities:
                raise ValueError(
                    f"Invalid severity in fail_on: '{s}'. Valid: {sorted(valid_severities)}"
                )
        # Normalise to uppercase
        self.fail_on = [s.upper() for s in self.fail_on]

    @property
    def fail_severity_levels(self) -> set[Severity]:
        return {Severity[s] for s in self.fail_on}

    def is_exempt(self, filepath: str) -> bool:
        """Return True if the given filepath matches any exempt pattern."""
        import fnmatch

        for pattern in self.exempt_paths:
            if fnmatch.fnmatch(filepath, pattern):
                return True
            # Also check just the filename
            if fnmatch.fnmatch(Path(filepath).name, pattern):
                return True
        return False

    def evaluate(self, findings: list[Finding]) -> list[PolicyViolation]:
        """Evaluate findings against this policy.

        Returns a list of violations. Empty list = policy satisfied.
        """
        violations: list[PolicyViolation] = []
        fail_severities = self.fail_severity_levels

        for finding in findings:
            # Skip exempt paths
            if self.is_exempt(finding.file):
                continue

            # Check if this finding's severity triggers a policy failure
            if finding.severity in fail_severities:
                if not self.allow_classical_only and finding.severity >= Severity.HIGH:
                    violations.append(
                        PolicyViolation(
                            rule="classical_crypto_detected",
                            detail=f"{finding.file}:{finding.line} - {finding.message}",
                            severity=finding.severity,
                            finding=finding,
                        )
                    )
                elif finding.severity >= Severity.CRITICAL:
                    violations.append(
                        PolicyViolation(
                            rule="critical_vulnerability",
                            detail=f"{finding.file}:{finding.line} - {finding.message}",
                            severity=finding.severity,
                            finding=finding,
                        )
                    )

        return violations

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_security_level": self.min_security_level,
            "allow_classical_only": self.allow_classical_only,
            "hybrid_required": self.hybrid_required,
            "allow_non_nist_standard": self.allow_non_nist_standard,
            "fail_on": self.fail_on,
            "exempt_paths": self.exempt_paths,
            "require_migration_state": self.require_migration_state,
            "max_classical_only_keys": self.max_classical_only_keys,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditPolicy:
        return cls(
            min_security_level=d.get("min_security_level", 3),
            allow_classical_only=d.get("allow_classical_only", False),
            hybrid_required=d.get("hybrid_required", True),
            allow_non_nist_standard=d.get("allow_non_nist_standard", False),
            fail_on=d.get("fail_on", ["CRITICAL", "HIGH"]),
            exempt_paths=d.get("exempt_paths", []),
            require_migration_state=d.get("require_migration_state", "hybrid_transition"),
            max_classical_only_keys=d.get("max_classical_only_keys"),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> AuditPolicy:
        """Load policy from a JSON or YAML file.

        YAML support requires PyYAML (pip install pyyaml). Falls back to
        JSON if PyYAML is not installed.
        """
        path = Path(path)
        text = path.read_text(encoding="utf-8")

        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore[import]

                data = yaml.safe_load(text)
            except ImportError:
                # Try JSON anyway — YAML is a superset of JSON
                data = json.loads(text)
        else:
            data = json.loads(text)

        return cls.from_dict(data)

    @classmethod
    def strict(cls) -> AuditPolicy:
        """Pre-built strict policy: no classical crypto at all."""
        return cls(
            min_security_level=3,
            allow_classical_only=False,
            hybrid_required=True,
            allow_non_nist_standard=False,
            fail_on=["CRITICAL", "HIGH", "MEDIUM"],
        )

    @classmethod
    def transition(cls) -> AuditPolicy:
        """Pre-built transition-period policy: hybrid required, classical tolerated."""
        return cls(
            min_security_level=1,
            allow_classical_only=True,
            hybrid_required=True,
            allow_non_nist_standard=False,
            fail_on=["CRITICAL"],
        )

    @classmethod
    def permissive(cls) -> AuditPolicy:
        """Pre-built permissive policy: only critical findings fail."""
        return cls(
            min_security_level=1,
            allow_classical_only=True,
            hybrid_required=False,
            allow_non_nist_standard=True,
            fail_on=["CRITICAL"],
        )
