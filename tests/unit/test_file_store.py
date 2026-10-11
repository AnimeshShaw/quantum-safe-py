"""
FileMigrationStore (audit item PY-X3): a directory-backed migration store with an atomic
``compare_and_set`` that is safe across processes on one host, so ``MigrationStateManager`` can run
in several worker processes without an external lock.

Modelled on quantum-safe-ts's ``FileMigrationStore`` (same layout rules: one file per key named by the
hex of the key, a ``mkdir`` lock stamped with an owner token and kept fresh by a heartbeat, writes
through a temporary file that is fsynced and renamed, files 0600 in a 0700 directory).
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from quantum_safe.migrate.file_store import FileMigrationStore


def _race(args: tuple[str, int]) -> bool:
    """Child process: try to create the key. Exactly one racer may win."""
    directory, who = args
    store = FileMigrationStore(directory)
    return store.compare_and_set("contested", None, f"winner-{who}".encode())


def _increment(args: tuple[str, int]) -> int:
    """Child process: add one to a counter, retrying on a lost race. Returns the retries used."""
    directory, n = args
    store = FileMigrationStore(directory)
    retries = 0
    done = 0
    while done < n:
        raw = store.get("counter")
        value = int(raw.decode()) if raw is not None else 0
        if store.compare_and_set("counter", raw, str(value + 1).encode()):
            done += 1
        else:
            retries += 1
    return retries


class TestMappingBehaviour:
    def test_set_get_contains_iter_len_delete(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path / "store")
        assert s.get("a") is None and "a" not in s and len(s) == 0
        s["a"] = b"1"
        s["b/odd key ✓"] = b"2"
        assert s["a"] == b"1" and "a" in s
        assert s["b/odd key ✓"] == b"2"
        assert set(s) == {"a", "b/odd key ✓"} and len(s) == 2
        del s["a"]
        assert "a" not in s and set(s) == {"b/odd key ✓"}
        with pytest.raises(KeyError):
            s["missing"]
        with pytest.raises(KeyError):
            del s["missing"]

    def test_values_must_be_bytes(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path)
        with pytest.raises(TypeError):
            s["k"] = "text"  # type: ignore[assignment]

    def test_key_limits(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path)
        s["k" * 100] = b"ok"
        with pytest.raises(ValueError):
            s["k" * 101] = b"too long"
        with pytest.raises(TypeError):
            s[3] = b"x"  # type: ignore[index]

    def test_persists_across_instances(self, tmp_path: Path) -> None:
        FileMigrationStore(tmp_path)["k"] = b"v"
        assert FileMigrationStore(tmp_path)["k"] == b"v"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
    def test_private_modes_and_no_leftovers(self, tmp_path: Path) -> None:
        d = tmp_path / "s"
        s = FileMigrationStore(d)
        s["k"] = b"v"
        assert (os.stat(d).st_mode & 0o777) == 0o700
        files = list(d.iterdir())
        assert len(files) == 1 and (os.stat(files[0]).st_mode & 0o777) == 0o600
        assert not any(".tmp" in f.name or f.name.endswith(".lock") for f in files)

    def test_file_names_are_hex_and_case_safe(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path)
        s["Key"] = b"1"
        s["key"] = b"2"  # differs only by case: must be two entries even on case-insensitive disks
        assert s["Key"] == b"1" and s["key"] == b"2"
        assert all(
            c in "0123456789abcdef" for f in tmp_path.iterdir() for c in f.name.split(".")[0]
        )


class TestCompareAndSet:
    def test_semantics(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path)
        assert s.compare_and_set("k", None, b"1") is True  # absent -> create
        assert s.compare_and_set("k", None, b"2") is False  # now it exists
        assert s.compare_and_set("k", b"wrong", b"2") is False
        assert s.compare_and_set("k", b"1", b"2") is True
        assert s["k"] == b"2"

    def test_threads_exactly_one_winner(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path)
        results: list[bool] = []
        barrier = threading.Barrier(8)

        def worker(i: int) -> None:
            barrier.wait()
            results.append(s.compare_and_set("t", None, f"{i}".encode()))

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert results.count(True) == 1

    def test_processes_exactly_one_winner(self, tmp_path: Path) -> None:
        ctx = mp.get_context("spawn")
        with ctx.Pool(6) as pool:
            results = pool.map(_race, [(str(tmp_path), i) for i in range(6)])
        assert results.count(True) == 1
        assert FileMigrationStore(tmp_path)["contested"].startswith(b"winner-")

    def test_processes_lose_no_increments(self, tmp_path: Path) -> None:
        ctx = mp.get_context("spawn")
        with ctx.Pool(4) as pool:
            pool.map(_increment, [(str(tmp_path), 15)] * 4)
        assert FileMigrationStore(tmp_path)["counter"] == b"60"


class TestLocks:
    def test_stale_lock_is_broken(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path, stale_lock_seconds=0.2, lock_timeout_seconds=5)
        s["k"] = b"v"
        # A crashed process left a lock behind (no owner heartbeat).
        lock = next(
            p for p in [tmp_path / (n + ".lock") for n in [f.name for f in tmp_path.iterdir()]]
        )
        lock.mkdir()
        (lock / "owner").write_text("dead-process")
        time.sleep(0.4)
        assert s.compare_and_set("k", b"v", b"w") is True
        assert s["k"] == b"w"
        assert not lock.exists()

    def test_fresh_lock_times_out_instead_of_being_stolen(self, tmp_path: Path) -> None:
        s = FileMigrationStore(tmp_path, stale_lock_seconds=60, lock_timeout_seconds=0.3)
        s["k"] = b"v"
        lock = next(
            p for p in [tmp_path / (n + ".lock") for n in [f.name for f in tmp_path.iterdir()]]
        )
        lock.mkdir()
        (lock / "owner").write_text("someone-else")
        with pytest.raises(TimeoutError):
            s.compare_and_set("k", b"v", b"w")
        assert s["k"] == b"v"


class TestWithTheStateManager:
    def test_is_cross_process_safe_and_drives_the_state_machine(self, tmp_path: Path) -> None:
        from quantum_safe.migrate.state import MigrationStateManager
        from quantum_safe.types.keys import MigrationState

        store = FileMigrationStore(tmp_path)
        mgr = MigrationStateManager(store)
        assert mgr.cross_process_safe is True
        mgr.transition(
            "user-1",
            MigrationState.CLASSICAL_ONLY,
            MigrationState.HYBRID_TRANSITION,
            "X25519+ML-KEM-768",
            actor="test",
        )
        mgr.transition(
            "user-1",
            MigrationState.HYBRID_TRANSITION,
            MigrationState.PQC_PREFERRED,
            "X25519+ML-KEM-768",
            actor="test",
        )
        # A second manager over the same directory sees the same state.
        again = MigrationStateManager(FileMigrationStore(tmp_path))
        assert again.get_current_state("user-1") is MigrationState.PQC_PREFERRED
        assert len(again.get_history("user-1")) == 2
