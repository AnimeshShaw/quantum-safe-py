"""
quantum_safe.migrate.state
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Migration state machine for tracking PQC migration progress across a key store.

The real-world migration problem is not "upgrade all keys at once" — it's
"upgrade keys gradually, without breaking existing users, and track where
everything is." This module provides the state machine and audit log for that.

Migration states (from types/keys.py MigrationState):
    CLASSICAL_ONLY     → Key uses only classical crypto. Not yet migrated.
    HYBRID_TRANSITION  → Key has both classical and PQC components. This is
                         the recommended transition state — both components
                         work, so you maintain backward compatibility while
                         gaining PQC protection.
    PQC_PREFERRED      → Hybrid key, but the system now treats the PQC
                         component as authoritative. The classical component
                         is still present for legacy verifiers.
    PQC_ONLY           → Classical component has been removed. Fully migrated.
                         Not backward compatible with classical-only clients.

Valid transitions:
    CLASSICAL_ONLY → HYBRID_TRANSITION          (first upgrade)
    HYBRID_TRANSITION → PQC_PREFERRED           (gain confidence in PQC)
    PQC_PREFERRED → PQC_ONLY                    (remove classical component)
    HYBRID_TRANSITION → CLASSICAL_ONLY          (rollback — logged as warning)

Downgrade transitions (anything that goes toward less PQC) are allowed but
logged as warnings with a mandatory reason string.

Each state change creates a MigrationRecord that can be stored in a database,
an audit log, or a file. The records are immutable once created.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from quantum_safe._internal import serialization as _ser
from quantum_safe.types.keys import MigrationState

# Valid forward and backward transitions.
# Forward = toward more PQC. Backward = toward less PQC (requires reason).
_FORWARD_TRANSITIONS: dict[MigrationState, set[MigrationState]] = {
    MigrationState.CLASSICAL_ONLY: {MigrationState.HYBRID_TRANSITION},
    MigrationState.HYBRID_TRANSITION: {MigrationState.PQC_PREFERRED},
    MigrationState.PQC_PREFERRED: {MigrationState.PQC_ONLY},
    MigrationState.PQC_ONLY: set(),  # terminal state
}

_BACKWARD_TRANSITIONS: dict[MigrationState, set[MigrationState]] = {
    MigrationState.HYBRID_TRANSITION: {MigrationState.CLASSICAL_ONLY},
    MigrationState.PQC_PREFERRED: {MigrationState.HYBRID_TRANSITION},
    # PQC_ONLY → anything is intentionally not allowed without a manual override
}


@dataclass(frozen=True)
class MigrationRecord:
    """An immutable record of a single migration state transition.

    Attributes:
        record_id:      Unique identifier for this record (UUID string).
        key_id:         Application-level identifier for the key being migrated.
                        This is whatever your app uses to identify keys (user ID,
                        key fingerprint, database row ID, etc.).
        from_state:     The state before the transition.
        to_state:       The state after the transition.
        algorithm:      The key algorithm after transition.
        timestamp:      Unix timestamp of the transition.
        actor:          Who initiated the migration (service name, user ID, etc.).
        reason:         Required for backward transitions. Optional for forward.
        metadata:       Arbitrary additional data for audit purposes.
    """

    record_id: str
    key_id: str
    from_state: MigrationState
    to_state: MigrationState
    algorithm: str
    timestamp: float
    actor: str = "system"
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_forward(self) -> bool:
        """True if this transition moves toward more PQC."""
        forward_set = _FORWARD_TRANSITIONS.get(self.from_state, set())
        return self.to_state in forward_set

    @property
    def is_backward(self) -> bool:
        return not self.is_forward

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "key_id": self.key_id,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "algorithm": self.algorithm,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "reason": self.reason,
            "metadata": self.metadata,
            "is_forward": self.is_forward,
        }

    def to_bytes(self) -> bytes:
        return _ser.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MigrationRecord:
        return cls(
            record_id=d["record_id"],
            key_id=d["key_id"],
            from_state=MigrationState(d["from_state"]),
            to_state=MigrationState(d["to_state"]),
            algorithm=d["algorithm"],
            timestamp=float(d["timestamp"]),
            actor=d.get("actor", "system"),
            reason=d.get("reason", ""),
            metadata=d.get("metadata", {}),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> MigrationRecord:
        return cls.from_dict(_ser.loads(data))


class MigrationStateManager:
    """Manages migration state for a collection of keys.

    This class is storage-agnostic — it takes a dict-like store and
    wraps it with validation, history, and audit logging. You provide
    the storage; we provide the business logic.

    Args:
        store:  A dict-like object for persistent state storage.
                Keys are string key_ids; values are MigrationRecord bytes.
                In production, back this with Redis, DynamoDB, Postgres, etc.
                In tests, a plain dict works fine.

    Example::

        store = {}  # replace with your database abstraction
        mgr = MigrationStateManager(store)

        # First time we see this key
        rec = mgr.transition(
            key_id="user-123",
            from_state=MigrationState.CLASSICAL_ONLY,
            to_state=MigrationState.HYBRID_TRANSITION,
            algorithm="X25519+ML-KEM-768",
            actor="key-rotation-job-v1",
        )
        # rec is stored in `store["user-123_current"]`
        # Full history in `store["user-123_history"]`
    """

    def __init__(self, store: dict[str, bytes]) -> None:
        self._store = store
        # Per-key locks prevent concurrent transitions from racing past the
        # read-then-write check. For multi-process deployments, callers must
        # additionally hold an external distributed lock (e.g. Redis SETNX,
        # database row-level lock) on the key_id before calling transition().
        self._key_locks: dict[str, threading.Lock] = {}
        self._meta_lock = threading.Lock()  # guards _key_locks dict itself

    def _lock_for(self, key_id: str) -> threading.Lock:
        """Return (creating if needed) the per-key lock for key_id."""
        with self._meta_lock:
            if key_id not in self._key_locks:
                self._key_locks[key_id] = threading.Lock()
            return self._key_locks[key_id]

    def transition(
        self,
        key_id: str,
        from_state: MigrationState,
        to_state: MigrationState,
        algorithm: str,
        actor: str = "system",
        reason: str = "",
        metadata: dict[str, Any] | None = None,
        allow_backward: bool = False,
    ) -> MigrationRecord:
        """Record a state transition for a key.

        Args:
            key_id:         Application key identifier.
            from_state:     Expected current state (for optimistic concurrency check).
            to_state:       New target state.
            algorithm:      Key algorithm after this transition.
            actor:          Who is performing the migration.
            reason:         Why (required for backward transitions).
            metadata:       Arbitrary key-value pairs for audit.
            allow_backward: Set True to explicitly permit backward transitions.
                            Still requires a non-empty reason string.

        Returns:
            The created MigrationRecord.

        Raises:
            ValueError: if the transition is not valid or current state
                        doesn't match from_state.
        """
        # Validate the transition
        forward_targets = _FORWARD_TRANSITIONS.get(from_state, set())
        backward_targets = _BACKWARD_TRANSITIONS.get(from_state, set())
        all_targets = forward_targets | backward_targets

        if to_state not in all_targets:
            raise ValueError(
                f"Invalid transition from {from_state.value!r} to {to_state.value!r}. "
                f"Valid targets: {[s.value for s in all_targets]}"
            )

        is_backward = to_state in backward_targets
        if is_backward:
            if not allow_backward:
                raise ValueError(
                    f"Backward transition from {from_state.value!r} to "
                    f"{to_state.value!r} requires allow_backward=True"
                )
            if not reason:
                raise ValueError("Backward transition requires a non-empty reason string")

        with self._lock_for(key_id):
            # Check current state matches expected from_state
            current = self.get_current_state(key_id)
            if current is not None and current != from_state:
                raise ValueError(
                    f"Key '{key_id}' is in state {current.value!r} but "
                    f"transition expected {from_state.value!r}. "
                    f"Concurrent modification or stale state?"
                )

            record = MigrationRecord(
                record_id=str(uuid.uuid4()),
                key_id=key_id,
                from_state=from_state,
                to_state=to_state,
                algorithm=algorithm,
                timestamp=time.time(),
                actor=actor,
                reason=reason,
                metadata=metadata or {},
            )

            # Store current state and append to history
            self._store[f"{key_id}_current"] = record.to_bytes()
            history_key = f"{key_id}_history"
            history = self._load_history(key_id)
            history.append(record.to_dict())
            self._store[history_key] = _ser.dumps(history)

        return record

    def get_current_state(self, key_id: str) -> MigrationState | None:
        """Return the current migration state for a key, or None if unknown."""
        current_key = f"{key_id}_current"
        if current_key not in self._store:
            return None
        try:
            rec = MigrationRecord.from_bytes(self._store[current_key])
            return rec.to_state
        except Exception:  # noqa: BLE001
            return None

    def get_current_record(self, key_id: str) -> MigrationRecord | None:
        """Return the full current record for a key."""
        current_key = f"{key_id}_current"
        if current_key not in self._store:
            return None
        try:
            return MigrationRecord.from_bytes(self._store[current_key])
        except Exception:  # noqa: BLE001
            return None

    def get_history(self, key_id: str) -> list[MigrationRecord]:
        """Return full migration history for a key, oldest first."""
        history_dicts = self._load_history(key_id)
        records = []
        for d in history_dicts:
            try:
                records.append(MigrationRecord.from_dict(d))
            except Exception:  # noqa: BLE001, S110
                pass  # skip malformed records
        return records

    def keys_by_state(self, state: MigrationState) -> list[str]:
        """Return all key IDs currently in the given migration state.

        This is a full scan — in production, maintain a secondary index.
        """
        result = []
        for store_key in self._store:
            if not store_key.endswith("_current"):
                continue
            key_id = store_key[: -len("_current")]
            current = self.get_current_state(key_id)
            if current == state:
                result.append(key_id)
        return sorted(result)

    def needs_migration(self) -> list[str]:
        """Return key IDs that are not yet in HYBRID_TRANSITION or better."""
        not_migrated = []
        for store_key in self._store:
            if not store_key.endswith("_current"):
                continue
            key_id = store_key[: -len("_current")]
            state = self.get_current_state(key_id)
            if state in (MigrationState.CLASSICAL_ONLY, None):
                not_migrated.append(key_id)
        return sorted(not_migrated)

    def migration_progress(self) -> dict[str, int]:
        """Return a count of keys in each migration state."""
        counts: dict[str, int] = {s.value: 0 for s in MigrationState}
        counts["unknown"] = 0
        for store_key in self._store:
            if not store_key.endswith("_current"):
                continue
            key_id = store_key[: -len("_current")]
            state = self.get_current_state(key_id)
            if state:
                counts[state.value] += 1
            else:
                counts["unknown"] += 1
        return counts

    def _load_history(self, key_id: str) -> list[dict[str, Any]]:
        history_key = f"{key_id}_history"
        if history_key not in self._store:
            return []
        try:
            data = _ser.loads(self._store[history_key])
            return data if isinstance(data, list) else []
        except Exception:  # noqa: BLE001
            return []
