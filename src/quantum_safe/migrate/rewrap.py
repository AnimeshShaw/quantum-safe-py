"""
quantum_safe.migrate.rewrap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Move a store of sealed envelopes from one recipient key to another, safely and verifiably.

:func:`rewrap_directory` walks a directory, and for every file that is a
:class:`SealedMessage` (raw CBOR or hex) opens it under the old secret key, seals the plaintext
to the new public key keeping the AAD, and writes the result. Around that it adds what a real
migration needs:

* **Never destructive by default.** Output goes to a separate destination directory; the source
  is not touched. ``in_place=True`` replaces files one at a time through a temporary file and an
  atomic rename.
* **Resumable and idempotent.** A file whose output already exists and is a valid migrated copy
  is reported ``already_migrated`` and left alone, so a second run does nothing and an
  interrupted run picks up where it stopped.
* **Verified.** Give ``new_secret`` and every written file is opened again and its plaintext
  compared (by SHA-256) with the original. Without it the item says ``verified=None``: nothing
  was checked.
* **One failure does not stop the run.** Each file ends in ``rewrapped``, ``skipped`` (not an
  envelope), ``already_migrated``, ``would_rewrap`` (dry run) or ``failed`` with a reason that
  contains no secret.
* **A report** (:class:`RewrapReport`) as JSON and as a CycloneDX 1.6 document that lists the
  algorithms migrated from and to, with the counts.

Only envelopes (``SealedMessage``) are handled. A streaming envelope (format v3) is a different
container; re-wrap it by reading it with :mod:`quantum_safe.protocols.stream` and sealing a new
stream.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from quantum_safe.protocols.envelope import Envelope, SealedMessage
from quantum_safe.types import PublicKey, SecretKey

ExpectedAad = bytes | Callable[[str], bytes] | None


@dataclass
class RewrapItem:
    """What happened to one file.

    Attributes:
        name: the file's path relative to the source directory, with ``/`` separators.
        status: one of ``rewrapped``, ``skipped``, ``already_migrated``, ``would_rewrap`` or
            ``failed``.
        from_algorithm: the algorithm of the envelope as found, or ``None`` when the file is not an
            envelope.
        to_algorithm: the algorithm of the envelope after re-wrapping (or of the existing migrated
            copy), when known.
        verified: ``True`` or ``False`` after the result was opened under ``new_secret`` and
            compared; ``None`` when no check was made.
        error: a reason without secrets for ``skipped`` and ``failed`` items, otherwise ``None``.
    """

    name: str
    status: str
    from_algorithm: str | None = None
    to_algorithm: str | None = None
    verified: bool | None = None
    error: str | None = None


@dataclass
class RewrapReport:
    """The outcome of a run. Contains names, algorithms and counts; never a key or a plaintext."""

    items: list[RewrapItem] = field(default_factory=list)
    new_algorithm: str = ""
    dry_run: bool = False
    in_place: bool = False
    aad_checked: bool = True
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def counts(self) -> dict[str, int]:
        """Item counts by outcome: ``rewrapped``, ``skipped`` and ``failed``, plus ``would_rewrap``.

        ``skipped`` includes ``already_migrated`` items. ``would_rewrap`` is present only when a
        dry run produced at least one such item.
        """
        out = {"rewrapped": 0, "skipped": 0, "failed": 0}
        for item in self.items:
            if item.status == "rewrapped":
                out["rewrapped"] += 1
            elif item.status == "failed":
                out["failed"] += 1
            elif item.status == "would_rewrap":
                out["would_rewrap"] = out.get("would_rewrap", 0) + 1
            else:
                out["skipped"] += 1
        return out

    @property
    def ok(self) -> bool:
        """True when nothing failed and every rewrapped item that could be verified was."""
        return self.counts["failed"] == 0 and all(
            item.verified is not False for item in self.items if item.status == "rewrapped"
        )

    def to_dict(self) -> dict[str, Any]:
        """The report as a JSON-serialisable dict: run settings, ``counts`` and every item."""
        return {
            "started_at": self.started_at,
            "new_algorithm": self.new_algorithm,
            "dry_run": self.dry_run,
            "in_place": self.in_place,
            "aad_checked": self.aad_checked,
            "counts": self.counts,
            "items": [asdict(i) for i in self.items],
        }

    def to_cbom(self, *, application_name: str = "envelope-store") -> dict[str, Any]:
        """A CycloneDX 1.6 document: the algorithms migrated from and to, with counts and status."""
        from quantum_safe.audit.cbom import (
            CYCLONEDX_SPEC_VERSION,
            CryptoAssetSpec,
            _crypto_component,
        )

        def spec(name: str, vulnerable: bool) -> CryptoAssetSpec:
            return CryptoAssetSpec(
                name=name,
                primitive="kem",
                quantum_level=0 if vulnerable else 3,
                quantum_vulnerable=vulnerable,
            )

        from_counts: dict[str, int] = {}
        for item in self.items:
            if item.status in ("rewrapped", "would_rewrap") and item.from_algorithm:
                from_counts[item.from_algorithm] = from_counts.get(item.from_algorithm, 0) + 1
        components: list[dict[str, Any]] = []
        for name, n in sorted(from_counts.items()):
            components.append(
                _crypto_component(
                    spec(name, name != self.new_algorithm),
                    f"migrated-from/{name.lower().replace('+', '-')}",
                    properties=[
                        {"name": "quantum-safe:migration-status", "value": "migrated-from"},
                        {"name": "quantum-safe:items", "value": str(n)},
                    ],
                )
            )
        components.append(
            _crypto_component(
                spec(self.new_algorithm, False),
                f"migrated-to/{self.new_algorithm.lower().replace('+', '-')}",
                properties=[
                    {"name": "quantum-safe:migration-status", "value": "migrated-to"},
                    {"name": "quantum-safe:items", "value": str(self.counts.get("rewrapped", 0))},
                ],
            )
        )
        counts = self.counts
        return {
            "bomFormat": "CycloneDX",
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "quantum-safe qs-migrate rewrap",
                            "description": "Envelope re-wrap migration report",
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "bom-ref": "subject",
                    "name": application_name,
                },
                "properties": [
                    {"name": "quantum-safe:items-rewrapped", "value": str(counts["rewrapped"])},
                    {"name": "quantum-safe:items-skipped", "value": str(counts["skipped"])},
                    {"name": "quantum-safe:items-failed", "value": str(counts["failed"])},
                    {"name": "quantum-safe:new-algorithm", "value": self.new_algorithm},
                    {
                        "name": "quantum-safe:verified-items",
                        "value": str(sum(1 for i in self.items if i.verified is True)),
                    },
                ],
            },
            "components": components,
        }


def _parse(raw: bytes) -> tuple[SealedMessage, str] | None:
    """The envelope in ``raw`` and how it was encoded ('bytes' or 'hex'), or ``None``."""
    # Anything that is not an envelope is skipped, not fatal, so any parse error means "no".
    with contextlib.suppress(Exception):
        return SealedMessage.from_bytes(raw), "bytes"
    with contextlib.suppress(Exception):
        return SealedMessage.from_hex(raw.decode("ascii").strip()), "hex"
    return None


def _encode(sealed: SealedMessage, encoding: str) -> bytes:
    """Serialise ``sealed`` in the encoding it was read in: ASCII hex for ``"hex"``, else CBOR."""
    return sealed.to_hex().encode("ascii") if encoding == "hex" else sealed.to_bytes()


def _write_atomic(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` through a flushed, fsynced temporary file and ``os.replace``.

    Creates missing parent directories. The temporary file is a hidden ``.<name>.<pid>.tmp``
    sibling that is removed if the write fails.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def rewrap_directory(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str] | None = None,
    *,
    old_secret: SecretKey,
    new_public: PublicKey,
    new_secret: SecretKey | None = None,
    expected_aad: ExpectedAad = None,
    pattern: str = "**/*",
    in_place: bool = False,
    dry_run: bool = False,
) -> RewrapReport:
    """Re-wrap every envelope under ``source`` from ``old_secret`` to ``new_public``.

    Args:
        source: directory to read.
        destination: directory to write, mirroring the relative paths. Required unless ``in_place``.
        old_secret: the secret key the envelopes are sealed to today.
        new_public: the public key to seal them to.
        new_secret: the matching new secret key. When given, every written file is opened again and
            its plaintext compared with the original, and files already under the new key are
            recognised. Strongly recommended.
        expected_aad: the AAD each envelope must carry: ``bytes`` for all, or a callable taking the
            relative path (``"sub/a.sealed"``) and returning the AAD. ``None`` accepts whatever AAD
            the message carries (it is authenticated) and keeps it; the report says ``aad_checked``
            is false.
        pattern: glob under ``source`` (default every file).
        in_place: replace files in ``source`` (each through a temporary file and an atomic rename).
        dry_run: decrypt and check, write nothing; items are ``would_rewrap``.

    Returns:
        A :class:`RewrapReport`. The function never raises for a bad file; it raises ``ValueError``
        for an unusable argument combination.

    Raises:
        ValueError: ``source`` is not a directory; ``in_place`` is true and ``destination`` names
            a different directory; ``in_place`` is false and ``destination`` is missing or is the
            source directory.
    """
    src = Path(source)
    if not src.is_dir():
        raise ValueError(f"source is not a directory: {src}")
    if in_place:
        if destination is not None and Path(destination).resolve() != src.resolve():
            raise ValueError(
                "in_place=True rewrites the source directory; do not pass another destination"
            )
        dst = src
    else:
        if destination is None:
            raise ValueError("destination is required unless in_place=True")
        dst = Path(destination)
        if dst.resolve() == src.resolve():
            raise ValueError(
                "destination is the source directory; pass in_place=True to replace files there"
            )

    report = RewrapReport(
        new_algorithm=new_public.algorithm,
        dry_run=dry_run,
        in_place=in_place,
        aad_checked=expected_aad is not None,
    )

    def aad_for(rel: str, sealed: SealedMessage) -> bytes:
        if expected_aad is None:
            return bytes(sealed.aad)
        return expected_aad(rel) if callable(expected_aad) else bytes(expected_aad)

    for path in sorted(p for p in src.glob(pattern) if p.is_file()):
        rel = path.relative_to(src).as_posix()
        if path.name.startswith(".") and path.name.endswith(".tmp"):
            continue
        item = RewrapItem(name=rel, status="skipped")
        report.items.append(item)
        try:
            raw = path.read_bytes()
            parsed = _parse(raw)
            if parsed is None:
                item.error = "not an envelope"
                continue
            sealed, encoding = parsed
            item.from_algorithm = sealed.algorithm
            aad = aad_for(rel, sealed)
            target = path if in_place else dst / rel

            # Already under the new key (in place), or an existing migrated copy (separate
            # destination).
            if in_place and new_secret is not None:
                under_new_key = True
                try:
                    Envelope.open(sealed, new_secret, expected_aad=aad)
                except Exception:  # noqa: BLE001 - not under the new key: re-wrap it
                    under_new_key = False
                if under_new_key:
                    item.status, item.to_algorithm = "already_migrated", sealed.algorithm
                    continue
            if not in_place and target.exists():
                existing = _parse(target.read_bytes())
                existing_msg = existing[0] if existing is not None else None
                ok = existing_msg is not None and existing_msg.algorithm == new_public.algorithm
                if ok and existing_msg is not None and new_secret is not None:
                    try:
                        Envelope.open(existing_msg, new_secret, expected_aad=aad)
                    except Exception:  # noqa: BLE001
                        ok = False
                if ok:
                    item.status, item.to_algorithm = "already_migrated", new_public.algorithm
                    continue
                item.status = "failed"
                item.error = "the destination file exists and is not a copy migrated to the new key"
                continue

            moved = Envelope.rewrap(sealed, old_secret, new_public, expected_aad=aad)
            item.to_algorithm = moved.algorithm
            if new_secret is not None:
                original = Envelope.open(sealed, old_secret, expected_aad=aad)
                again = Envelope.open(moved, new_secret, expected_aad=moved.aad)
                item.verified = hashlib.sha256(original).digest() == hashlib.sha256(again).digest()
                if not item.verified:
                    item.status, item.error = (
                        "failed",
                        "the re-wrapped copy did not match the original",
                    )
                    continue
            if dry_run:
                item.status = "would_rewrap"
                continue
            _write_atomic(target, _encode(moved, encoding))
            item.status = "rewrapped"
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the run
            item.status = "failed"
            item.error = (
                f"{type(exc).__name__}: could not open under the old key or write the result"
            )
    return report
