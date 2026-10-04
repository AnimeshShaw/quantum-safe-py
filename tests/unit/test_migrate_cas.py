"""D11: the migration store's optional compare-and-set removes the need for an external lock.

``transition()`` used to rely on a per-key ``threading.Lock``, which covers
threads in ONE process. Several processes sharing a store raced past the
read-check-write. With a store that implements ``compare_and_set`` the manager
commits through one atomic operation on the history entry, so exactly one of
any number of concurrent writers wins and the others get a stale-state error.

The store layout is unchanged (``<id>_current`` and ``<id>_history``).
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from quantum_safe.migrate import MemoryMigrationStore, MigrationStateManager
from quantum_safe.types import MigrationState

C, H, P = (
    MigrationState.CLASSICAL_ONLY,
    MigrationState.HYBRID_TRANSITION,
    MigrationState.PQC_PREFERRED,
)


class TestMemoryStore:
    def test_compare_and_set_semantics(self) -> None:
        s = MemoryMigrationStore()
        assert s.compare_and_set("k", None, b"1") is True  # absent: create
        assert s.compare_and_set("k", None, b"2") is False  # already exists
        assert s.compare_and_set("k", b"0", b"2") is False  # wrong expected value
        assert s.compare_and_set("k", b"1", b"2") is True
        assert s["k"] == b"2"

    def test_is_a_dict(self) -> None:
        s = MemoryMigrationStore()
        s["a"] = b"x"
        assert dict(s) == {"a": b"x"} and "a" in s


class TestRaces:
    def test_exactly_one_of_many_concurrent_managers_wins(self) -> None:
        """Separate managers share only the store, like separate processes."""
        store = MemoryMigrationStore()
        managers = [MigrationStateManager(store) for _ in range(16)]
        barrier = threading.Barrier(len(managers))
        outcomes: list[str] = []
        lock = threading.Lock()

        def run(m: MigrationStateManager, n: int) -> None:
            barrier.wait()
            try:
                m.transition("k", C, H, "X25519+ML-KEM-768", actor=f"w{n}")
                result = "won"
            except ValueError:
                result = "lost"
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=run, args=(m, i)) for i, m in enumerate(managers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes.count("won") == 1 and outcomes.count("lost") == 15
        history = managers[0].get_history("k")
        assert len(history) == 1  # no duplicated or overwritten record
        assert managers[0].get_current_state("k") == H

    def test_a_chain_of_transitions_from_competing_managers_has_no_lost_updates(self) -> None:
        store = MemoryMigrationStore()
        a, b = MigrationStateManager(store), MigrationStateManager(store)
        a.transition("k", C, H, "X25519+ML-KEM-768")
        b.transition("k", H, P, "ML-KEM-768")
        with pytest.raises(ValueError, match="stale"):
            a.transition("k", H, P, "ML-KEM-768")  # a's view is behind: refused, not overwritten
        assert [r.to_state for r in a.get_history("k")] == [H, P]

    def test_a_lost_cas_re_reads_and_reports_the_new_state(self) -> None:
        """Another writer commits between our read and our compare-and-set."""

        class Racing(MemoryMigrationStore):
            injected = False

            def compare_and_set(self, key: str, expected: Any, value: bytes) -> bool:  # noqa: ANN401
                if key.endswith("_history") and not self.injected:
                    self.injected = True
                    MigrationStateManager(self).transition("k", C, H, "X25519+ML-KEM-768")
                return super().compare_and_set(key, expected, value)

        store = Racing()
        with pytest.raises(ValueError, match="Concurrent modification or stale state"):
            MigrationStateManager(store).transition("k", C, H, "X25519+ML-KEM-768")
        assert [r.to_state for r in MigrationStateManager(store).get_history("k")] == [H]

    def test_gives_up_after_too_many_lost_races(self) -> None:
        class AlwaysLoses(MemoryMigrationStore):
            def compare_and_set(self, key: str, expected: Any, value: bytes) -> bool:  # noqa: ANN401
                return False

        with pytest.raises(ValueError, match="too contended"):
            MigrationStateManager(AlwaysLoses()).transition("k", C, H, "X25519+ML-KEM-768")


class TestLayoutAndOrdering:
    def test_the_store_layout_is_unchanged_and_a_plain_dict_manager_can_read_it(self) -> None:
        store = MemoryMigrationStore()
        mgr = MigrationStateManager(store)
        mgr.transition("user-1", C, H, "X25519+ML-KEM-768", actor="job")
        mgr.transition("user-1", H, P, "ML-KEM-768")
        assert sorted(store) == ["user-1_current", "user-1_history"]
        legacy = MigrationStateManager(dict(store))  # a 0.3.0-style reader of the same bytes
        assert legacy.get_current_state("user-1") == P
        assert [r.actor for r in legacy.get_history("user-1")] == ["job", "system"]

    def test_a_cas_manager_continues_a_history_written_without_cas(self) -> None:
        plain: dict[str, bytes] = {}
        MigrationStateManager(plain).transition("k", C, H, "X25519+ML-KEM-768", actor="old")
        mgr = MigrationStateManager(MemoryMigrationStore(plain))
        mgr.transition("k", H, P, "ML-KEM-768", actor="new")
        assert [r.actor for r in mgr.get_history("k")] == ["old", "new"]

    def test_a_crash_after_the_commit_leaves_the_history_authoritative(self) -> None:
        """The CAS commits the history; _current is a derived copy written after it."""

        class CrashOnCurrent(MemoryMigrationStore):
            armed = False

            def __setitem__(self, key: str, value: bytes) -> None:
                if self.armed and key.endswith("_current"):
                    raise RuntimeError("crash between the commit and the _current write")
                super().__setitem__(key, value)

        store = CrashOnCurrent()
        mgr = MigrationStateManager(store)
        mgr.transition("k", C, H, "X25519+ML-KEM-768")
        store.armed = True
        with pytest.raises(RuntimeError):
            mgr.transition("k", H, P, "ML-KEM-768")
        store.armed = False
        # The commit is durable and the manager reads it from the history, not the stale copy.
        assert mgr.get_current_state("k") == P
        assert mgr.get_current_record("k").to_state == P  # type: ignore[union-attr]
        assert len(mgr.get_history("k")) == 2
        # A later transition builds on the committed state.
        mgr.transition("k", P, MigrationState.PQC_ONLY, "ML-KEM-768")
        assert mgr.get_current_state("k") == MigrationState.PQC_ONLY

    def test_without_cas_the_history_is_written_before_the_current_state(self) -> None:
        """A crash between the two writes now leaves _current behind the audit log,
        not the audit log behind the state."""
        order: list[str] = []

        class Recording(dict):  # type: ignore[type-arg]
            def __setitem__(self, key: str, value: bytes) -> None:
                order.append(key)
                super().__setitem__(key, value)

        MigrationStateManager(Recording()).transition("k", C, H, "X25519+ML-KEM-768")
        assert order == ["k_history", "k_current"]

    def test_the_manager_reports_whether_it_is_cross_process_safe(self) -> None:
        assert MigrationStateManager(MemoryMigrationStore()).cross_process_safe is True
        assert MigrationStateManager({}).cross_process_safe is False


def test_validation_is_unchanged() -> None:
    mgr = MigrationStateManager(MemoryMigrationStore())
    with pytest.raises(ValueError, match="Invalid transition"):
        mgr.transition("k", C, MigrationState.PQC_ONLY, "ML-KEM-768")
    mgr.transition("k", C, H, "X25519+ML-KEM-768")
    with pytest.raises(ValueError, match="requires allow_backward"):
        mgr.transition("k", H, C, "X25519")
