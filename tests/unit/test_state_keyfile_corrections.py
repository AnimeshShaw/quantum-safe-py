"""Corrections to the migration state manager, ``upgrade-key --force`` and v2 key stripping."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from quantum_safe._internal import serialization as ser
from quantum_safe.migrate import MemoryMigrationStore, MigrationStateManager
from quantum_safe.types import MigrationState

C, H = MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION


def _go(manager: MigrationStateManager, key_id: str = "k1") -> None:
    manager.transition(key_id, C, H, algorithm="X25519+ML-KEM-768", actor="test")


class TestUnreadableHistoryIsNeverOverwritten:
    @pytest.mark.parametrize("store_type", [dict, MemoryMigrationStore])
    @pytest.mark.parametrize(
        "damaged",
        [b"\xff\xfe not cbor", ser.dumps({"not": "a list"}), ser.dumps("text")],
    )
    def test_transition_refuses_and_leaves_the_bytes_alone(
        self, store_type: type, damaged: bytes
    ) -> None:
        store = store_type()
        store["k1_history"] = damaged
        with pytest.raises(ValueError, match="refusing to overwrite"):
            _go(MigrationStateManager(store))
        assert store["k1_history"] == damaged
        assert "k1_current" not in store

    @pytest.mark.parametrize("store_type", [dict, MemoryMigrationStore])
    def test_an_absent_history_is_a_new_key(self, store_type: type) -> None:
        store = store_type()
        manager = MigrationStateManager(store)
        _go(manager)
        assert [r.to_state for r in manager.get_history("k1")] == [H]

    @pytest.mark.parametrize("store_type", [dict, MemoryMigrationStore])
    def test_a_readable_history_is_appended_to(self, store_type: type) -> None:
        store = store_type()
        manager = MigrationStateManager(store)
        _go(manager)
        manager.transition("k1", H, MigrationState.PQC_PREFERRED, algorithm="X25519+ML-KEM-768")
        assert len(manager.get_history("k1")) == 2

    def test_other_keys_are_not_affected(self) -> None:
        store: dict[str, bytes] = {"bad_history": b"\xff"}
        manager = MigrationStateManager(store)
        _go(manager, "good")
        assert [r.to_state for r in manager.get_history("good")] == [H]

    def test_reading_a_damaged_history_still_returns_nothing_instead_of_raising(self) -> None:
        manager = MigrationStateManager({"k1_history": b"\xff"})
        assert manager.get_history("k1") == []


pytest.importorskip("click")
from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from quantum_safe.migrate.keyfile import KeyUpgradeError, upgrade_key_file  # noqa: E402


@pytest.fixture
def x25519_pem(tmp_path: Path) -> Path:
    p = tmp_path / "in.pem"
    key = x25519.X25519PrivateKey.generate()
    p.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return p


@pytest.mark.requires_liboqs
class TestForceRestoresWhatItReplaced:
    def _fail_on_public_key(self, monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
        real_replace = os.replace

        def flaky(src, dst):  # type: ignore[no-untyped-def]
            if Path(dst) == target and str(src).endswith(".tmp"):
                raise OSError(28, "No space left on device")
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", flaky)

    def test_old_pair_is_back_after_a_failure_placing_the_public_key(
        self, tmp_path: Path, x25519_pem: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out, pub = tmp_path / "o.pem", tmp_path / "o.pem.pub"
        out.write_text("OLD SECRET")
        pub.write_text("OLD PUBLIC")
        self._fail_on_public_key(monkeypatch, pub)
        with pytest.raises(KeyUpgradeError, match="could not write"):
            upgrade_key_file(x25519_pem, out, force=True)
        assert out.read_text() == "OLD SECRET"
        assert pub.read_text() == "OLD PUBLIC"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["in.pem", "o.pem", "o.pem.pub"]

    def test_only_the_secret_key_existed(
        self, tmp_path: Path, x25519_pem: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out, pub = tmp_path / "o.pem", tmp_path / "o.pem.pub"
        out.write_text("OLD SECRET")
        self._fail_on_public_key(monkeypatch, pub)
        with pytest.raises(KeyUpgradeError):
            upgrade_key_file(x25519_pem, out, force=True)
        assert out.read_text() == "OLD SECRET"
        assert not pub.exists()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["in.pem", "o.pem"]

    def test_a_successful_force_run_leaves_no_backup(
        self, tmp_path: Path, x25519_pem: Path
    ) -> None:
        out, pub = tmp_path / "o.pem", tmp_path / "o.pem.pub"
        out.write_text("OLD SECRET")
        pub.write_text("OLD PUBLIC")
        upgrade_key_file(x25519_pem, out, force=True)
        assert "OLD SECRET" not in out.read_text() and "OLD PUBLIC" not in pub.read_text()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["in.pem", "o.pem", "o.pem.pub"]

    def test_backups_are_private(self, tmp_path: Path) -> None:
        if os.name != "posix":
            pytest.skip("POSIX permission bits")
        from quantum_safe.migrate.keyfile import _copy_private

        f = tmp_path / "k"
        f.write_text("secret")
        backup = _copy_private(f)
        assert backup.stat().st_mode & 0o777 == 0o600
        assert backup.read_text() == "secret"


@pytest.mark.requires_liboqs
def test_stripping_a_v2_hybrid_gives_a_pure_v2_key_that_signs() -> None:
    import warnings

    from quantum_safe import HybridSign, Sign
    from quantum_safe.migrate.upgrader import Upgrader

    pair = HybridSign().generate_keypair()
    assert pair.algorithm == "Ed25519+ML-DSA-65-v2"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pq = Upgrader.strip_classical_component(pair)
    assert pq.algorithm == "ML-DSA-65-v2"
    signer = Sign("ML-DSA-65-v2")
    signed = signer.sign(b"message", pq.secret, context=b"ctx")
    signer.verify(signed, pq.public, context=b"ctx")
