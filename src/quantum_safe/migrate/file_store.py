"""
quantum_safe.migrate.file_store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``FileMigrationStore``: a directory-backed store for
:class:`~quantum_safe.migrate.state.MigrationStateManager` whose ``compare_and_set`` is atomic
across **processes on one host**. It is the file counterpart of quantum-safe-ts's
``FileMigrationStore`` and follows the same design:

* one file per store key, named by the lowercase hex of the key (not base64: file names that differ
  only by case would be one file on case-insensitive filesystems);
* a per-key lock taken with ``mkdir`` (atomic on local filesystems) and stamped with an owner
  token, kept fresh by a heartbeat while held;
* the value is compared, then written to a temporary file, fsynced and renamed over the old one, so
  a reader never sees a partial value; ownership is re-checked immediately before the rename, and a
  lock is only released by its owner;
* a lock left by a crashed process (no heartbeat for ``stale_lock_seconds``) is broken by
  atomically renaming it away;
* files are mode 0600 in a 0700 directory.

It is a ``MutableMapping[str, bytes]``, so it drops in wherever the manager takes a dict-like
store.

Limits, stated plainly: this is not distributed. Network filesystems (NFS, SMB, some container
volume drivers) may not give atomic ``mkdir`` or ``rename``; do not share one directory across
machines, and use a database or Redis store with a real compare-and-set there. A process frozen
for longer than ``stale_lock_seconds`` may have its lock taken; it then fails with "lock lost"
instead of writing, except in a window of microseconds between the final ownership check and the
rename. The history has no integrity protection: anyone who can write the directory can rewrite
it. Keys are at most 100 bytes (the file name is twice that in hex).
"""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import threading
import time
from collections.abc import Callable, Iterator, MutableMapping
from pathlib import Path

_MAX_KEY_BYTES = (
    100  # 2 hex chars per byte plus suffixes must stay under the 255-character file-name limit
)
_SUFFIX = ".bin"
_TRANSIENT_WINDOWS_ERRNO = {5, 13, 32}  # access denied / sharing violation on a concurrent rename


class FileMigrationStore(MutableMapping[str, bytes]):
    """A migration store backed by a directory. See the module documentation.

    Args:
        directory:             Where the files live (created, mode 0700, if missing).
        stale_lock_seconds:    A lock not refreshed for this long is considered abandoned.
        lock_timeout_seconds:  Give up acquiring a lock after this long (``TimeoutError``).
    """

    def __init__(
        self,
        directory: str | os.PathLike[str],
        stale_lock_seconds: float = 30.0,
        lock_timeout_seconds: float = 10.0,
    ) -> None:
        """Open the store at ``directory``; nothing is created on disk until the first write.

        Args:
            directory: where the files live. Must be a non-empty path.
            stale_lock_seconds: a lock not refreshed for this long is considered abandoned. The
                holder refreshes its lock every third of this interval (at least every 5 ms).
            lock_timeout_seconds: give up acquiring a lock after this long.

        Raises:
            ValueError: ``directory`` is an empty path.
        """
        if not str(directory):
            raise ValueError("directory must be a non-empty path")
        self._dir = Path(directory)
        self._stale = float(stale_lock_seconds)
        self._timeout = float(lock_timeout_seconds)

    # ------------------------------------------------------------------ names

    @staticmethod
    def _check_key(key: object) -> str:
        """Return ``key`` if it is a ``str`` of at most 100 UTF-8 bytes, else raise.

        Raises ``TypeError`` for a non-string and ``ValueError`` for an over-long key.
        """
        if not isinstance(key, str):
            raise TypeError("FileMigrationStore keys must be strings")
        if len(key.encode("utf-8")) > _MAX_KEY_BYTES:
            raise ValueError(
                f"FileMigrationStore keys are at most {_MAX_KEY_BYTES} bytes (the file name is hex)"
            )
        return key

    def _file(self, key: str) -> Path:
        """The path of the file for ``key``: the lowercase hex of its UTF-8 bytes plus ``.bin``."""
        return self._dir / (self._check_key(key).encode("utf-8").hex() + _SUFFIX)

    def _ensure_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # --------------------------------------------------------------- mapping

    def __getitem__(self, key: str) -> bytes:
        for attempt in range(100):
            try:
                return self._file(key).read_bytes()
            except FileNotFoundError:
                raise KeyError(key) from None
            except PermissionError:
                # A concurrent atomic rename on Windows can briefly deny reads.
                if attempt >= 99:
                    raise
                time.sleep(0.005)
        raise KeyError(key)  # pragma: no cover

    def __setitem__(self, key: str, value: bytes) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("FileMigrationStore values must be bytes")
        data = bytes(value)
        with self._locked(key) as owns:
            self._write(key, data, owns)

    def __delitem__(self, key: str) -> None:
        with self._locked(key) as owns:
            owns()
            try:
                self._file(key).unlink()
            except FileNotFoundError:
                raise KeyError(key) from None

    def __iter__(self) -> Iterator[str]:
        try:
            names = sorted(p.name for p in self._dir.iterdir())
        except FileNotFoundError:
            return
        for name in names:
            if name.endswith(_SUFFIX):
                with contextlib.suppress(ValueError):
                    yield bytes.fromhex(name[: -len(_SUFFIX)]).decode("utf-8")

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        try:
            return self._file(key).exists()
        except ValueError:
            return False

    def compare_and_set(self, key: str, expected: bytes | None, value: bytes) -> bool:
        """Set ``key`` to ``value`` only if its current value is exactly ``expected``.

        ``expected=None`` means "the key must not exist". Atomic across processes on one host.
        Returns whether the write happened.

        Args:
            key: the store key (a ``str`` of at most 100 UTF-8 bytes).
            expected: the exact bytes the key must currently hold, or ``None`` if it must not
                exist.
            value: the bytes to store.

        Returns:
            ``True`` if the value was written; ``False`` if the current value differed from
            ``expected`` (nothing is written then).

        Raises:
            TypeError: ``value`` is not bytes, or ``key`` is not a string.
            ValueError: ``key`` is longer than 100 UTF-8 bytes.
            TimeoutError: the per-key lock could not be acquired within ``lock_timeout_seconds``.
            RuntimeError: the lock was lost (broken as stale) before the write; nothing was
                written.
        """
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("FileMigrationStore values must be bytes")
        with self._locked(key) as owns:
            if self.get(key) != (None if expected is None else bytes(expected)):
                return False
            self._write(key, bytes(value), owns)
            return True

    # ----------------------------------------------------------------- write

    def _write(self, key: str, data: bytes, owns: Callable[[], None]) -> None:
        """Write ``data`` for ``key`` via a 0600 temporary file, fsync and rename.

        The caller must hold the key's lock; ``owns`` is called before every rename attempt and
        raises if the lock has been lost. The temporary file is removed on any failure.
        """
        target = self._file(key)
        tmp = target.with_name(f"{target.name}.{secrets.token_hex(6)}.tmp")
        try:
            fd = os.open(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600
            )
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            for attempt in range(50):
                owns()  # re-checked before EVERY rename attempt
                try:
                    os.replace(tmp, target)
                    break
                except PermissionError:
                    if attempt >= 49:
                        raise
                    time.sleep(0.005 + attempt * 0.001)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
        # Make the rename durable; not supported on every platform (Windows), so best effort.
        with contextlib.suppress(OSError):
            dfd = os.open(self._dir, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    # ------------------------------------------------------------------ lock

    @contextlib.contextmanager
    def _locked(self, key: str) -> Iterator[Callable[[], None]]:
        """Hold the per-key lock for the ``with`` block and yield an ``owns`` check.

        The lock is a ``<file>.lock`` directory containing an ``owner`` file with a random token.
        A heartbeat thread refreshes its mtime while held. ``owns()`` raises ``RuntimeError`` if
        the token on disk is no longer ours; on exit the lock is removed only if it still is.
        Raises ``TimeoutError`` if the lock is not acquired within ``lock_timeout_seconds``.
        """
        self._ensure_dir()
        lock = self._file(key).with_name(self._file(key).name + ".lock")
        owner_file = lock / "owner"
        token = secrets.token_hex(12)
        deadline = time.monotonic() + self._timeout
        attempt = 0
        while True:
            try:
                lock.mkdir(mode=0o700)
                try:
                    owner_file.write_text(token, encoding="ascii")
                except BaseException:
                    shutil.rmtree(lock, ignore_errors=True)  # never leave our own ownerless lock
                    raise
                break
            except FileExistsError:
                self._break_if_stale(lock)
            except (PermissionError, FileNotFoundError):
                pass
            if time.monotonic() > deadline:
                raise TimeoutError("FileMigrationStore: timed out waiting for a lock")
            time.sleep(min(0.002 + attempt * 0.001, 0.025) + secrets.randbelow(3) / 1000)
            attempt += 1

        stop = threading.Event()

        def beat() -> None:
            interval = max(0.005, self._stale / 3)
            while not stop.wait(interval):
                with contextlib.suppress(OSError):
                    os.utime(lock)

        heartbeat = threading.Thread(target=beat, daemon=True)
        heartbeat.start()

        def owns() -> None:
            try:
                current = owner_file.read_text(encoding="ascii")
            except OSError:
                current = ""
            if current != token:
                raise RuntimeError(
                    "FileMigrationStore: the lock was lost (it was broken as stale); "
                    "nothing was written"
                )

        try:
            yield owns
        finally:
            stop.set()
            heartbeat.join(timeout=1.0)
            # Release only a lock we still own, so a stalled holder never deletes a successor's.
            with contextlib.suppress(OSError):
                if owner_file.read_text(encoding="ascii") == token:
                    shutil.rmtree(lock, ignore_errors=True)

    @staticmethod
    def _lock_age(path: Path) -> float:
        """Seconds since ``path`` was last modified."""
        return time.time() - path.stat().st_mtime

    def _break_if_stale(self, lock: Path) -> None:
        """Remove a lock not refreshed for ``stale_lock_seconds``. Removal is a rename to a unique
        name, so only one waiter wins it.

        Checking the age and renaming are two steps. Between them another waiter may have broken the
        stale lock and a third process taken a fresh one at the same path, which our rename would
        then move away. So the age is checked again on what was actually moved: a lock that turns
        out to be live is put back (if its path is still free). If it cannot be, its holder fails
        with "lock lost" before writing, never with a corrupt write.
        """
        try:
            if self._lock_age(lock) <= self._stale:
                return
            graveyard = lock.with_name(f"{lock.name}.stale.{secrets.token_hex(6)}")
            os.rename(lock, graveyard)
            try:
                moved_live = self._lock_age(graveyard) <= self._stale
            except OSError:
                moved_live = False
            if moved_live:
                try:
                    os.rename(graveyard, lock)
                    return
                except OSError:
                    pass  # the path is taken again: the holder will notice and fail safely
            shutil.rmtree(graveyard, ignore_errors=True)
        except OSError:
            pass  # released, or another waiter broke it first: just retry
