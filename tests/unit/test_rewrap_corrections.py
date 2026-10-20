"""Corrections to the re-wrap driver found while documenting it."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module")
def pairs():
    from quantum_safe.kem.hybrid import HybridKEM

    return HybridKEM().generate_keypair(), HybridKEM(pqc="ML-KEM-1024").generate_keypair()


def _seal(pair, text: bytes = b"hello") -> bytes:
    from quantum_safe.protocols.envelope import Envelope

    return Envelope.seal(text, pair.public).to_bytes()


def test_destination_inside_the_source_is_refused(tmp_path: Path, pairs) -> None:
    from quantum_safe.migrate.rewrap import rewrap_directory

    old, new = pairs
    (tmp_path / "out").mkdir()
    with pytest.raises(ValueError, match="inside the source"):
        rewrap_directory(tmp_path, tmp_path / "out", old_secret=old.secret, new_public=new.public)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_in_place_rewrite_keeps_the_file_mode(tmp_path: Path, pairs) -> None:
    from quantum_safe.migrate.rewrap import rewrap_directory

    old, new = pairs
    f = tmp_path / "a.sealed"
    f.write_bytes(_seal(old))
    f.chmod(0o600)
    report = rewrap_directory(
        tmp_path, in_place=True, old_secret=old.secret, new_public=new.public, new_secret=new.secret
    )
    assert report.ok
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.sealed"]


def test_cbom_does_not_call_a_post_quantum_source_vulnerable(tmp_path: Path, pairs) -> None:
    from quantum_safe.migrate.rewrap import rewrap_directory

    old, new = pairs
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    (src / "a.sealed").write_bytes(_seal(old))
    report = rewrap_directory(
        src, dst, old_secret=old.secret, new_public=new.public, new_secret=new.secret
    )
    cbom = report.to_cbom()
    by_name = {c["name"]: c for c in cbom["components"] if c["name"].startswith("X25519+")}
    source = by_name["X25519+ML-KEM-768"]
    target = by_name["X25519+ML-KEM-1024"]

    def prop(component: dict, name: str) -> str:
        return next(p["value"] for p in component["properties"] if p["name"] == name)

    assert prop(source, "quantum-safe:quantum-vulnerable") == "false"
    assert source["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert target["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 5
