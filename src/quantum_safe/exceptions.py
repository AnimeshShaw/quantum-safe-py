"""
quantum_safe.exceptions
~~~~~~~~~~~~~~~~~~~~~~~

All exceptions raised by this library live here. We keep a strict hierarchy
so callers can catch at whatever granularity they need:

    QuantumSafeError
    ├── CryptoError
    │   ├── DecapsulationError
    │   ├── VerificationError
    │   ├── KeyGenerationError
    │   └── InsecureOperationError
    ├── SerializationError
    │   ├── KeyParseError
    │   └── UnsupportedFormatError
    ├── BackendError
    │   ├── BackendNotAvailable
    │   └── BackendMismatch
    ├── MigrationError
    │   ├── ClassicalKeyDetected
    │   └── IncompatibleKeyVersion
    └── ConfigurationError
        └── UnsupportedAlgorithm

Design notes:
- Every exception carries a machine-readable `code` so callers can branch
  on error type without parsing message strings. Codes are stable across
  patch versions.
- We never put sensitive material (raw key bytes, shared secrets) in
  exception messages. If you see "*** REDACTED ***" in a message, something
  upstream accidentally tried to include key material.
"""

from __future__ import annotations

from typing import Any


class QuantumSafeError(Exception):
    """Base class for all quantum-safe library errors."""

    code: str = "QS_ERROR"

    def __init__(self, message: str, **context: Any) -> None:  # noqa: ANN401
        super().__init__(message)
        self.message = message
        # Extra context (file paths, algorithm names, etc.) for structured
        # logging — never put secret material here.
        self.context: dict[str, Any] = context

    def __repr__(self) -> str:
        ctx = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
        return f"{type(self).__name__}({self.message!r}{', ' + ctx if ctx else ''})"


# ---------------------------------------------------------------------------
# Crypto errors — something went wrong at the primitive level
# ---------------------------------------------------------------------------


class CryptoError(QuantumSafeError):
    """Raised when a cryptographic operation fails."""

    code = "QS_CRYPTO"


class DecapsulationError(CryptoError):
    """Decapsulation failed — usually means wrong secret key or tampered ciphertext.

    Do NOT log ciphertexts or key material when catching this; the failure
    itself is the only safe thing to propagate.
    """

    code = "QS_DECAP_FAILED"

    def __init__(self, algo: str | None = None) -> None:
        super().__init__(
            "Decapsulation failed: ciphertext may be malformed or the wrong secret key was used",
            algo=algo,
        )


class VerificationError(CryptoError):
    """Signature verification failed."""

    code = "QS_VERIFY_FAILED"

    def __init__(self, algo: str | None = None, context_mismatch: bool = False) -> None:
        if context_mismatch:
            msg = "Signature verification failed: signing context does not match"
        else:
            msg = "Signature verification failed: signature is invalid or message was tampered"
        super().__init__(msg, algo=algo, context_mismatch=context_mismatch)


class KeyGenerationError(CryptoError):
    """Key generation failed — usually an RNG or backend issue."""

    code = "QS_KEYGEN_FAILED"


class InsecureOperationError(CryptoError):
    """Attempted operation is insecure and has been blocked.

    Examples:
    - Using an algorithm below the required security level
    - Disabling hybrid mode without an explicit override
    - Reusing a nonce in a scheme that prohibits it
    """

    code = "QS_INSECURE_OP"


# ---------------------------------------------------------------------------
# Serialization errors
# ---------------------------------------------------------------------------


class SerializationError(QuantumSafeError):
    """Raised when key/ciphertext serialization or deserialization fails."""

    code = "QS_SERIAL"


class KeyParseError(SerializationError):
    """Failed to parse a key from PEM, DER, CBOR, or JWK.

    `field` indicates which part of the structure was malformed, if known.
    """

    code = "QS_KEY_PARSE"

    def __init__(self, fmt: str, reason: str, field: str | None = None) -> None:
        super().__init__(
            f"Failed to parse {fmt} key: {reason}",
            format=fmt,
            field=field,
        )


class UnsupportedFormatError(SerializationError):
    """The requested serialization format is not supported for this key type."""

    code = "QS_FMT_UNSUPPORTED"

    def __init__(self, fmt: str, key_type: str) -> None:
        super().__init__(
            f"Format '{fmt}' is not supported for key type '{key_type}'",
            format=fmt,
            key_type=key_type,
        )


# ---------------------------------------------------------------------------
# Backend errors
# ---------------------------------------------------------------------------


class BackendError(QuantumSafeError):
    """Errors related to cryptographic backend selection or execution."""

    code = "QS_BACKEND"


class BackendNotAvailable(BackendError):
    """A required backend is not installed or could not be loaded.

    The `install_hint` attribute contains a pip command the user can run
    to fix the problem.
    """

    code = "QS_BACKEND_MISSING"

    # Maps backend names to install instructions
    _INSTALL_HINTS: dict[str, str] = {
        "liboqs": "pip install 'quantum-safe[liboqs]'",
        "rustcrypto": "pip install 'quantum-safe[rustcrypto]'",
    }

    def __init__(self, backend: str) -> None:
        hint = self._INSTALL_HINTS.get(backend, f"install the '{backend}' backend")
        super().__init__(
            f"Backend '{backend}' is not available. To install: {hint}",
            backend=backend,
        )
        self.install_hint = hint


class BackendMismatch(BackendError):
    """A key was created with one backend but an operation requires another."""

    code = "QS_BACKEND_MISMATCH"

    def __init__(self, key_backend: str, op_backend: str) -> None:
        super().__init__(
            f"Key was created with backend '{key_backend}' but this operation "
            f"requires '{op_backend}'",
            key_backend=key_backend,
            op_backend=op_backend,
        )


# ---------------------------------------------------------------------------
# Migration errors
# ---------------------------------------------------------------------------


class MigrationError(QuantumSafeError):
    """Errors raised during key migration or classical-crypto scanning."""

    code = "QS_MIGRATE"


class ClassicalKeyDetected(MigrationError):
    """A pure classical (non-hybrid) key was used where PQC is required.

    This is raised in strict mode when a classical-only key is passed to
    an operation that requires at least hybrid security.
    """

    code = "QS_CLASSICAL_KEY"

    def __init__(self, algo: str, min_required: str = "hybrid") -> None:
        super().__init__(
            f"Classical algorithm '{algo}' does not meet the minimum required "
            f"security level '{min_required}'. Use a hybrid or PQC-only key.",
            detected_algo=algo,
            required=min_required,
        )


class IncompatibleKeyVersion(MigrationError):
    """The key's qs-version field is not supported by this library version."""

    code = "QS_KEY_VERSION"

    def __init__(self, key_version: int, supported_max: int) -> None:
        super().__init__(
            f"Key uses format version {key_version} but this library only "
            f"supports up to version {supported_max}. Upgrade quantum-safe.",
            key_version=key_version,
            supported_max=supported_max,
        )


# ---------------------------------------------------------------------------
# Configuration errors
# ---------------------------------------------------------------------------


class ConfigurationError(QuantumSafeError):
    """Raised when the library is misconfigured."""

    code = "QS_CONFIG"


class UnsupportedAlgorithm(ConfigurationError):
    """The requested algorithm is not supported.

    `available` contains the list of valid algorithm names so callers
    can suggest alternatives without hard-coding the list.
    """

    code = "QS_ALGO_UNSUPPORTED"

    def __init__(self, algo: str, available: list[str] | None = None) -> None:
        hint = ""
        if available:
            hint = f" Available: {', '.join(available)}"
        super().__init__(
            f"Algorithm '{algo}' is not supported.{hint}",
            algo=algo,
            available=available or [],
        )
