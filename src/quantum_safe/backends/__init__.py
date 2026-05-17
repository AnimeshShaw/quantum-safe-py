"""
quantum_safe.backends
~~~~~~~~~~~~~~~~~~~~~

Backend registry and auto-selection logic.

Backends are loaded lazily — we don't import liboqs until someone actually
needs it. This keeps the import time fast even when liboqs isn't installed.

The selection priority for auto mode:
  1. rustcrypto  — preferred for FIPS-subset algorithms (ML-KEM, ML-DSA,
                   SLH-DSA). Fastest on native Python, WASM-compatible.
  2. liboqs      — fallback for the full algorithm set (includes BIKE,
                   FrodoKEM, HQC, etc. that RustCrypto doesn't have yet).
  3. noble       — JS/WASM environments only. Never selected in native Python.

You can override selection with the QUANTUM_SAFE_BACKEND environment variable
or the `backend=` parameter on KEM/Sign constructors.
"""

from __future__ import annotations

import os
from functools import cache
from typing import TYPE_CHECKING

from quantum_safe.exceptions import BackendNotAvailable

if TYPE_CHECKING:
    from quantum_safe.backends.base import AbstractKEMBackend, AbstractSignatureBackend


# All known backend names (for validation)
_KNOWN_BACKENDS = {"liboqs", "rustcrypto", "noble", "auto"}


@cache
def _load_liboqs_kem() -> AbstractKEMBackend:
    """Load and return the liboqs KEM backend. Cached after first load."""
    from quantum_safe.backends.liboqs import LiboqsKEMBackend

    return LiboqsKEMBackend()


@cache
def _load_rustcrypto_kem() -> AbstractKEMBackend:
    from quantum_safe.backends.rustcrypto import RustCryptoKEMBackend

    return RustCryptoKEMBackend()


@cache
def _load_liboqs_sig() -> AbstractSignatureBackend:
    from quantum_safe.backends.liboqs import LiboqsSignatureBackend

    return LiboqsSignatureBackend()


@cache
def _load_rustcrypto_sig() -> AbstractSignatureBackend:
    from quantum_safe.backends.rustcrypto import RustCryptoSignatureBackend

    return RustCryptoSignatureBackend()


def get_kem_backend(name: str = "auto") -> AbstractKEMBackend:
    """Return the KEM backend for the given name.

    Args:
        name: "auto", "liboqs", or "rustcrypto".
              Falls back through the priority list if "auto".

    Raises:
        BackendNotAvailable: if the requested backend is not installed.
        ValueError: if the backend name is unknown.
    """
    env_override = os.environ.get("QUANTUM_SAFE_BACKEND", "").strip().lower()
    if env_override and name == "auto":
        name = env_override

    if name not in _KNOWN_BACKENDS:
        raise ValueError(f"Unknown backend '{name}'. Valid options: {sorted(_KNOWN_BACKENDS)}")

    if name == "auto":
        return _auto_select_kem_backend()

    if name == "rustcrypto":
        b = _load_rustcrypto_kem()
        if not b.is_available():
            raise BackendNotAvailable("rustcrypto")
        return b

    if name == "liboqs":
        b = _load_liboqs_kem()
        if not b.is_available():
            raise BackendNotAvailable("liboqs")
        return b

    if name == "noble":
        raise BackendNotAvailable("noble")  # noble is JS-only

    raise BackendNotAvailable(name)


def get_signature_backend(name: str = "auto") -> AbstractSignatureBackend:
    """Return the signature backend for the given name."""
    env_override = os.environ.get("QUANTUM_SAFE_BACKEND", "").strip().lower()
    if env_override and name == "auto":
        name = env_override

    if name not in _KNOWN_BACKENDS:
        raise ValueError(f"Unknown backend '{name}'. Valid options: {sorted(_KNOWN_BACKENDS)}")

    if name == "auto":
        return _auto_select_sig_backend()

    if name == "rustcrypto":
        b = _load_rustcrypto_sig()
        if not b.is_available():
            raise BackendNotAvailable("rustcrypto")
        return b

    if name == "liboqs":
        b = _load_liboqs_sig()
        if not b.is_available():
            raise BackendNotAvailable("liboqs")
        return b

    raise BackendNotAvailable(name)


def _auto_select_kem_backend() -> AbstractKEMBackend:
    """Try backends in priority order, return the first available one."""
    for loader in (_load_rustcrypto_kem, _load_liboqs_kem):
        try:
            b = loader()
            if b.is_available():
                return b
        except Exception:  # noqa: BLE001, S112
            continue

    raise BackendNotAvailable("auto")


def _auto_select_sig_backend() -> AbstractSignatureBackend:
    """Try signature backends in priority order."""
    for loader in (_load_rustcrypto_sig, _load_liboqs_sig):
        try:
            b = loader()
            if b.is_available():
                return b
        except Exception:  # noqa: BLE001, S112
            continue

    raise BackendNotAvailable("auto")


def list_available_backends() -> dict[str, bool]:
    """Return availability status for all known backends.

    Useful for diagnostics: `python -c "from quantum_safe.backends import
    list_available_backends; print(list_available_backends())"`.
    """
    results: dict[str, bool] = {}
    for name, loader in [("rustcrypto", _load_rustcrypto_kem), ("liboqs", _load_liboqs_kem)]:
        try:
            b = loader()
            results[name] = b.is_available()
        except Exception:  # noqa: BLE001
            results[name] = False
    results["noble"] = False  # always False in Python
    return results
