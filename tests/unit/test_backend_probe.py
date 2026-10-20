"""The optional-backend probe is remembered, so constructing a KEM or signer does not search sys.path."""

from __future__ import annotations

import builtins
import sys
import types
from typing import Any

import pytest

from quantum_safe.backends import clear_backend_cache
from quantum_safe.backends import rustcrypto as rc
from quantum_safe.exceptions import BackendNotAvailable


@pytest.fixture(autouse=True)
def _fresh_probe() -> Any:
    rc.reset_import_probe()
    yield
    rc.reset_import_probe()


def _count_import_attempts(monkeypatch: pytest.MonkeyPatch, name: str) -> list[str]:
    attempts: list[str] = []
    real_import = builtins.__import__

    def spy(module: str, *args: Any, **kwargs: Any) -> Any:
        if module == name:
            attempts.append(module)
        return real_import(module, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", spy)
    return attempts


def test_failed_import_is_attempted_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "quantum_safe_py", None)  # makes the import fail
    attempts = _count_import_attempts(monkeypatch, "quantum_safe_py")
    for _ in range(20):
        with pytest.raises(BackendNotAvailable):
            rc._import_qs_py()
    assert len(attempts) == 1


def test_failure_keeps_its_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "quantum_safe_py", None)
    for _ in range(2):
        with pytest.raises(BackendNotAvailable) as info:
            rc._import_qs_py()
        assert isinstance(info.value.__cause__, ImportError)


def test_availability_answers_are_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "quantum_safe_py", None)
    for _ in range(3):
        assert rc.RustCryptoKEMBackend().is_available() is False
        assert rc.RustCryptoSignatureBackend().is_available() is False


def test_clear_backend_cache_looks_again(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "quantum_safe_py", None)
    with pytest.raises(BackendNotAvailable):
        rc._import_qs_py()
    fake = types.ModuleType("quantum_safe_py")
    monkeypatch.setitem(sys.modules, "quantum_safe_py", fake)
    with pytest.raises(BackendNotAvailable):  # still remembered
        rc._import_qs_py()
    clear_backend_cache()
    assert rc._import_qs_py() is fake
    assert rc.RustCryptoKEMBackend().is_available() is True


def test_construction_does_not_search_the_import_path(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("oqs")
    from quantum_safe import KEM, HybridKEM, HybridSign, Sign

    monkeypatch.setitem(sys.modules, "quantum_safe_py", None)
    HybridKEM()  # first construction may probe
    attempts = _count_import_attempts(monkeypatch, "quantum_safe_py")
    for _ in range(10):
        HybridKEM()
        KEM("ML-KEM-768")
        HybridSign()
        Sign("ML-DSA-65")
    assert attempts == []
