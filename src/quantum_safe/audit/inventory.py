"""
quantum_safe.audit.inventory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A key inventory: the facts an :class:`~quantum_safe.audit.policy.AuditPolicy`
needs in order to enforce its key-level controls.

The source scanner looks at *code*. It can tell you that a file calls
``rsa.generate_private_key`` but not which algorithm a key in your key store
uses, what NIST level that algorithm has, or how far its migration has got.
Those facts live in your key store and migration state, so the policy controls
that depend on them (``min_security_level``, ``hybrid_required``,
``allow_non_nist_standard``, ``require_migration_state`` and
``max_classical_only_keys``) are evaluated against an inventory you provide:

    inventory = [
        InventoryEntry("signing-2026", "Ed25519+ML-DSA-65", MigrationState.HYBRID_TRANSITION),
        InventoryEntry("legacy-tls", "P-256"),
    ]
    report = Auditor.audit("./src", policy=AuditPolicy.strict(), inventory=inventory)

An algorithm name that is not in the registries cannot be classified, and the
policy then reports it as a violation rather than skipping it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from quantum_safe.kem.algorithms import CLASSICAL_KEM_ALGORITHMS, KEM_ALGORITHMS
from quantum_safe.signatures.algorithms import (
    CLASSICAL_SIGNATURE_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
)
from quantum_safe.types.keys import MigrationState

#: Migration states from least to most migrated. Used for ``require_migration_state``.
MIGRATION_STATE_ORDER: tuple[MigrationState, ...] = (
    MigrationState.CLASSICAL_ONLY,
    MigrationState.HYBRID_TRANSITION,
    MigrationState.PQC_PREFERRED,
    MigrationState.PQC_ONLY,
)


class AlgorithmKind(Enum):
    """How an algorithm name is classified for policy purposes."""

    CLASSICAL = "classical"  # X25519, Ed25519, P-256: no post-quantum component
    PQC = "pqc"  # ML-KEM-768, ML-DSA-65, ...: post-quantum only
    HYBRID = "hybrid"  # X25519+ML-KEM-768, Ed25519+ML-DSA-65, ...
    UNKNOWN = "unknown"  # not in any registry


@dataclass(frozen=True)
class AlgorithmInfo:
    """Policy-relevant facts about one algorithm name.

    ``nist_level`` and ``is_nist_standard`` describe the post-quantum component;
    they are ``None`` for a classical or unknown algorithm.
    """

    name: str
    kind: AlgorithmKind
    nist_level: int | None = None
    is_nist_standard: bool | None = None


def classify_algorithm(name: str) -> AlgorithmInfo:
    """Classify an algorithm name using the library's own registries.

    A hybrid name is ``<classical>+<pqc>``. It is only classified as hybrid if
    both halves are known and the classical half belongs to the same family
    (KEM or signature) as the post-quantum half; anything else is ``UNKNOWN``.
    """
    if not isinstance(name, str):
        return AlgorithmInfo(str(name), AlgorithmKind.UNKNOWN)
    if "+" in name:
        classical, _, pqc = name.partition("+")
        for classical_registry, pqc_registry in (
            (CLASSICAL_KEM_ALGORITHMS, KEM_ALGORITHMS),
            (CLASSICAL_SIGNATURE_ALGORITHMS, SIGNATURE_ALGORITHMS),
        ):
            if classical in classical_registry and pqc in pqc_registry:
                spec = pqc_registry[pqc]
                return AlgorithmInfo(
                    name, AlgorithmKind.HYBRID, int(spec.nist_level), spec.is_nist_standard
                )
        return AlgorithmInfo(name, AlgorithmKind.UNKNOWN)
    for pqc_registry in (KEM_ALGORITHMS, SIGNATURE_ALGORITHMS):
        if name in pqc_registry:
            spec = pqc_registry[name]
            return AlgorithmInfo(
                name, AlgorithmKind.PQC, int(spec.nist_level), spec.is_nist_standard
            )
    if name in CLASSICAL_KEM_ALGORITHMS or name in CLASSICAL_SIGNATURE_ALGORITHMS:
        return AlgorithmInfo(name, AlgorithmKind.CLASSICAL)
    return AlgorithmInfo(name, AlgorithmKind.UNKNOWN)


@dataclass(frozen=True)
class InventoryEntry:
    """One key (or key type) in the inventory.

    Attributes:
        key_id:           Your identifier for the key.
        algorithm:        Algorithm name as the library spells it, for example
                          ``"X25519+ML-KEM-768"``, ``"ML-DSA-65"`` or ``"Ed25519"``.
        migration_state:  The key's :class:`~quantum_safe.types.keys.MigrationState`,
                          or ``None`` if you do not track it.
    """

    key_id: str
    algorithm: str
    migration_state: MigrationState | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "migration_state": self.migration_state.value if self.migration_state else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InventoryEntry:
        """Build an entry from a mapping. Raises ``ValueError`` on anything malformed."""
        if not isinstance(d, dict):
            raise ValueError(f"inventory entry must be an object, got {type(d).__name__}")
        unknown = set(d) - {"key_id", "algorithm", "migration_state"}
        if unknown:
            raise ValueError(f"inventory entry has unknown field(s): {sorted(unknown)}")
        key_id = d.get("key_id")
        algorithm = d.get("algorithm")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("inventory entry needs a non-empty string 'key_id'")
        if not isinstance(algorithm, str) or not algorithm:
            raise ValueError(f"inventory entry {key_id!r} needs a non-empty string 'algorithm'")
        raw_state = d.get("migration_state")
        state: MigrationState | None = None
        if raw_state is not None:
            try:
                state = MigrationState(raw_state)
            except ValueError:
                valid = [s.value for s in MigrationState]
                raise ValueError(
                    f"inventory entry {key_id!r}: migration_state {raw_state!r} "
                    f"is not one of {valid}"
                ) from None
        return cls(key_id=key_id, algorithm=algorithm, migration_state=state)


def load_inventory(path: str | Path) -> list[InventoryEntry]:
    """Load an inventory from a JSON file.

    The file is either a list of entries or ``{"keys": [...]}``. Each entry has
    ``key_id``, ``algorithm`` and, optionally, ``migration_state``. Raises
    ``ValueError`` if the file is not valid, so a CI gate cannot pass on an
    inventory it could not read.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"inventory file {path} is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        if set(data) != {"keys"}:
            raise ValueError("inventory file must be a list, or an object with only a 'keys' list")
        data = data["keys"]
    if not isinstance(data, list):
        raise ValueError("inventory file must contain a list of entries")
    return [InventoryEntry.from_dict(item) for item in data]
