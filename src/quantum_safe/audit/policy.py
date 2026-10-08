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

What each field enforces
------------------------
Source-code controls, evaluated against the scanner's findings:

``fail_on``, ``exempt_paths``, ``allow_classical_only``
    Findings at a ``fail_on`` severity are violations unless their file matches
    ``exempt_paths``. With ``allow_classical_only=True`` only CRITICAL findings
    are violations.

Key controls, evaluated against a key inventory (see
:mod:`quantum_safe.audit.inventory`) that you pass to ``evaluate`` /
``Auditor.audit``. The scanner reads code, not your key store, so these cannot
be checked without one:

``min_security_level``
    An entry whose post-quantum component has a NIST level below this is a violation.
``hybrid_required``
    A post-quantum-only entry is a violation.
``allow_non_nist_standard``
    With ``False``, an entry whose post-quantum algorithm is not a NIST standard
    (BIKE, HQC) is a violation.
``require_migration_state``
    The minimum :class:`~quantum_safe.types.keys.MigrationState` a key must have
    reached. A lower state is a violation; so is a missing state, unless the
    minimum is ``classical_only``.
``max_classical_only_keys``
    More classical-only entries than this is one violation. When it is set it
    governs classical-only keys; when it is ``None``, ``allow_classical_only=False``
    makes every classical-only entry a violation.

Entries whose algorithm is not in the registries are violations, never skipped.
When a control that needs an inventory is active and no inventory is given, it
is listed in :meth:`AuditPolicy.unevaluated_controls` (and so in the audit
report) instead of passing silently; ``require_inventory=True`` turns that into
a violation. Exemptions apply to source findings only and never exempt an
inventory entry from a key control.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quantum_safe.audit.inventory import (
    MIGRATION_STATE_ORDER,
    AlgorithmKind,
    InventoryEntry,
    classify_algorithm,
)
from quantum_safe.migrate.scanner import Finding, Severity
from quantum_safe.types.keys import MigrationState


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
        max_classical_only_keys: If set, more than this many classical-only keys
                                 in the inventory is a violation. Default None (no limit).
        require_inventory:       If True, evaluating without a key inventory is itself
                                 a violation whenever a key control is active, instead
                                 of those controls being reported as not evaluated.
                                 Default False.

    The key controls (``min_security_level``, ``hybrid_required``,
    ``allow_non_nist_standard``, ``require_migration_state`` and
    ``max_classical_only_keys``) are enforced against a key inventory; see the
    module documentation. A malformed value raises ``ValueError`` at
    construction, so a typo cannot silently weaken the policy.
    """

    min_security_level: int = 3
    allow_classical_only: bool = False
    hybrid_required: bool = True
    allow_non_nist_standard: bool = False
    fail_on: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    exempt_paths: list[str] = field(default_factory=list)
    require_migration_state: str = "hybrid_transition"
    max_classical_only_keys: int | None = None
    require_inventory: bool = False

    def __post_init__(self) -> None:
        # Type checks first: a YAML value such as `allow_classical_only: "false"` is a
        # non-empty string, which is truthy, and would silently loosen the policy.
        for name in (
            "allow_classical_only",
            "hybrid_required",
            "allow_non_nist_standard",
            "require_inventory",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be true or false, got {getattr(self, name)!r}")
        if isinstance(self.min_security_level, bool) or not isinstance(
            self.min_security_level, int
        ):
            raise ValueError(
                f"min_security_level must be an integer 1-5, got {self.min_security_level!r}"
            )
        m = self.max_classical_only_keys
        if m is not None and (isinstance(m, bool) or not isinstance(m, int) or m < 0):
            raise ValueError(
                f"max_classical_only_keys must be a non-negative integer or null, got {m!r}"
            )
        for name in ("fail_on", "exempt_paths"):
            value = getattr(self, name)
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"{name} must be a list of strings, got {value!r}")
        try:
            MigrationState(self.require_migration_state)
        except ValueError:
            valid = [st.value for st in MigrationState]
            raise ValueError(
                f"require_migration_state must be one of {valid}, "
                f"got {self.require_migration_state!r}"
            ) from None
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

    def unevaluated_controls(self, inventory: list[InventoryEntry] | None) -> list[str]:
        """Names of active key controls that cannot be checked without an inventory.

        Empty when an inventory is given. A control is active when it can reject
        something: a ``min_security_level`` above 1, ``hybrid_required``, a
        disallowed non-NIST algorithm, a ``require_migration_state`` above
        ``classical_only``, or a ``max_classical_only_keys`` limit.
        """
        if inventory is not None:
            return []
        active: list[str] = []
        if self.min_security_level > 1:
            active.append("min_security_level")
        if self.hybrid_required:
            active.append("hybrid_required")
        if not self.allow_non_nist_standard:
            active.append("allow_non_nist_standard")
        if MigrationState(self.require_migration_state) is not MigrationState.CLASSICAL_ONLY:
            active.append("require_migration_state")
        if self.max_classical_only_keys is not None:
            active.append("max_classical_only_keys")
        return active

    def evaluate(
        self,
        findings: list[Finding],
        inventory: list[InventoryEntry] | None = None,
    ) -> list[PolicyViolation]:
        """Evaluate findings, and optionally a key inventory, against this policy.

        Returns a list of violations. Empty list = policy satisfied.

        Without an ``inventory`` the key controls are not evaluated; see
        :meth:`unevaluated_controls`. Passing an empty list means "there are no
        keys" and is evaluated as such.
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

        if inventory is None:
            missing = self.unevaluated_controls(None)
            if self.require_inventory and missing:
                violations.append(
                    PolicyViolation(
                        rule="inventory_required",
                        detail=(
                            "no key inventory was provided, so these controls could not be "
                            f"evaluated: {', '.join(missing)}"
                        ),
                    )
                )
        else:
            violations.extend(self._evaluate_inventory(inventory))

        return violations

    def _evaluate_inventory(self, inventory: list[InventoryEntry]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        floor = MIGRATION_STATE_ORDER.index(MigrationState(self.require_migration_state))
        classical_only: list[str] = []

        for entry in inventory:
            info = classify_algorithm(entry.algorithm)
            who = f"key '{entry.key_id}' ({entry.algorithm})"

            if info.kind is AlgorithmKind.UNKNOWN:
                violations.append(
                    PolicyViolation(
                        rule="unknown_algorithm",
                        detail=(
                            f"{who}: algorithm is not in the registry, so the policy "
                            "cannot be evaluated for it"
                        ),
                    )
                )
                continue

            is_classical = (
                info.kind is AlgorithmKind.CLASSICAL
                or entry.migration_state is MigrationState.CLASSICAL_ONLY
            )
            if is_classical:
                classical_only.append(entry.key_id)
                if self.max_classical_only_keys is None and not self.allow_classical_only:
                    violations.append(
                        PolicyViolation(
                            rule="classical_only_key",
                            detail=f"{who} has no post-quantum component",
                        )
                    )

            if info.nist_level is not None and info.nist_level < self.min_security_level:
                violations.append(
                    PolicyViolation(
                        rule="min_security_level",
                        detail=(
                            f"{who} is NIST level {info.nist_level}, below the required "
                            f"{self.min_security_level}"
                        ),
                    )
                )

            if self.hybrid_required and info.kind is AlgorithmKind.PQC:
                violations.append(
                    PolicyViolation(
                        rule="hybrid_required",
                        detail=f"{who} is post-quantum only; the policy requires a hybrid",
                    )
                )

            if not self.allow_non_nist_standard and info.is_nist_standard is False:
                violations.append(
                    PolicyViolation(
                        rule="allow_non_nist_standard",
                        detail=f"{who} is not a NIST-standardised algorithm",
                    )
                )

            if entry.migration_state is None:
                if floor > 0:
                    violations.append(
                        PolicyViolation(
                            rule="require_migration_state",
                            detail=(
                                f"{who} has no migration state; the policy requires at least "
                                f"'{self.require_migration_state}'"
                            ),
                        )
                    )
            elif MIGRATION_STATE_ORDER.index(entry.migration_state) < floor:
                violations.append(
                    PolicyViolation(
                        rule="require_migration_state",
                        detail=(
                            f"{who} is '{entry.migration_state.value}'; the policy requires at "
                            f"least '{self.require_migration_state}'"
                        ),
                    )
                )

        limit = self.max_classical_only_keys
        if limit is not None and len(classical_only) > limit:
            violations.append(
                PolicyViolation(
                    rule="max_classical_only_keys",
                    detail=(
                        f"{len(classical_only)} classical-only keys, more than the allowed "
                        f"{limit}: {', '.join(classical_only)}"
                    ),
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
            "require_inventory": self.require_inventory,
        }

    #: Keys accepted by :meth:`from_dict`. ``version`` is the file-format marker.
    _FIELDS = frozenset(
        {
            "version",
            "min_security_level",
            "allow_classical_only",
            "hybrid_required",
            "allow_non_nist_standard",
            "fail_on",
            "exempt_paths",
            "require_migration_state",
            "max_classical_only_keys",
            "require_inventory",
        }
    )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditPolicy:
        """Build a policy from a mapping.

        Raises ``ValueError`` for an unknown key (a misspelt control would
        otherwise be ignored and the policy would be weaker than written) or a
        value of the wrong type.
        """
        if not isinstance(d, dict):
            raise ValueError(f"a policy must be a mapping, got {type(d).__name__}")
        unknown = set(d) - cls._FIELDS
        if unknown:
            raise ValueError(
                f"unknown policy field(s): {sorted(unknown)}. Valid fields: {sorted(cls._FIELDS)}"
            )
        return cls(
            min_security_level=d.get("min_security_level", 3),
            allow_classical_only=d.get("allow_classical_only", False),
            hybrid_required=d.get("hybrid_required", True),
            allow_non_nist_standard=d.get("allow_non_nist_standard", False),
            fail_on=d.get("fail_on", ["CRITICAL", "HIGH"]),
            exempt_paths=d.get("exempt_paths", []),
            require_migration_state=d.get("require_migration_state", "hybrid_transition"),
            max_classical_only_keys=d.get("max_classical_only_keys"),
            require_inventory=d.get("require_inventory", False),
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
                import yaml  # type: ignore[import-untyped]

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
            require_migration_state="classical_only",
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
            require_migration_state="classical_only",
        )
