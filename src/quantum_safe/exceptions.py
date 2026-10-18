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


class QuantumSafeWarning(UserWarning):
    """Base class for the library's runtime advisories.

    A ``UserWarning`` (shown by default, unlike ``DeprecationWarning``), so a developer sees it the
    first time it happens at each call site. Silence a category with the standard ``warnings``
    filters, for example ``warnings.filterwarnings("ignore", category=ContextOmittedWarning)``.
    """


class ContextOmittedWarning(QuantumSafeWarning):
    """``verify()`` was called without ``context=`` for a message that carries a non-empty context.

    Omitting ``context`` means "expect an empty context", so the message is rejected. The warning
    exists so the rejection is not a silent mystery: pass the context you expect.
    """


class AadOmittedWarning(QuantumSafeWarning):
    """``Envelope.open()`` was called without ``expected_aad=`` for a message that carries AAD.

    The message was opened, but the opener did not check what the AAD was bound to. Pass the AAD you
    expect so a message sealed for another record or user cannot be accepted here.
    """


class QuantumSafeError(Exception):
    """Base class for all quantum-safe library errors.

    Attributes:
        code: Stable machine-readable identifier of the error type, such as ``"QS_CRYPTO"``.
            Each subclass sets its own value.
        message: The human-readable message, also the single argument of the exception.
        context: Keyword arguments given at construction (algorithm names, formats, file
            paths and similar), for structured logging. Never contains secret material.
    """

    code: str = "QS_ERROR"

    def __init__(self, message: str, **context: Any) -> None:  # noqa: ANN401
        """Create the error.

        Args:
            message: Human-readable description of the failure.
            **context: Extra structured details, stored in :attr:`context`.
        """
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

    The ``context`` dict carries ``algo``, the algorithm name if the caller supplied one.
    """

    code = "QS_DECAP_FAILED"

    def __init__(self, algo: str | None = None) -> None:
        """Create the error with a fixed message.

        Args:
            algo: Name of the KEM algorithm that failed, recorded in ``context["algo"]``.
        """
        super().__init__(
            "Decapsulation failed: ciphertext may be malformed or the wrong secret key was used",
            algo=algo,
        )


class VerificationError(CryptoError):
    """Signature verification failed.

    The ``context`` dict carries ``algo`` and ``context_mismatch``. The message names a
    signing-context mismatch when ``context_mismatch`` is true and an invalid signature or
    tampered message otherwise.
    """

    code = "QS_VERIFY_FAILED"

    def __init__(self, algo: str | None = None, context_mismatch: bool = False) -> None:
        """Create the error.

        Args:
            algo: Name of the signature algorithm, recorded in ``context["algo"]``.
            context_mismatch: ``True`` when verification failed because the signing context did
                not match; selects the message and is recorded in ``context``.
        """
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

    The message reads ``Failed to parse <fmt> key: <reason>``; the ``context`` dict carries
    ``format`` and ``field``.
    """

    code = "QS_KEY_PARSE"

    def __init__(self, fmt: str, reason: str, field: str | None = None) -> None:
        """Create the error.

        Args:
            fmt: Name of the format being parsed, e.g. ``"pem"``, ``"cbor"`` or ``"jwk"``.
            reason: What was wrong with the input.
            field: The malformed part of the structure, if known.
        """
        super().__init__(
            f"Failed to parse {fmt} key: {reason}",
            format=fmt,
            field=field,
        )


class UnsupportedFormatError(SerializationError):
    """The requested serialization format is not supported for this key type.

    Raised, for example, when a secret key is serialized to JWK. The ``context`` dict carries
    ``format`` and ``key_type``.
    """

    code = "QS_FMT_UNSUPPORTED"

    def __init__(self, fmt: str, key_type: str) -> None:
        """Create the error.

        Args:
            fmt: The unsupported format name, e.g. ``"jwk"``.
            key_type: Identifier of the key (the library passes the key's algorithm name).
        """
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
    to fix the problem. The ``context`` dict carries ``backend``.
    """

    code = "QS_BACKEND_MISSING"

    # Maps backend names to install instructions
    _INSTALL_HINTS: dict[str, str] = {
        "liboqs": "pip install 'quantum-safe[liboqs]'",
        "rustcrypto": "pip install 'quantum-safe[rustcrypto]'",
    }

    def __init__(self, backend: str) -> None:
        """Create the error with an install hint for ``backend``.

        Args:
            backend: Name of the missing backend, e.g. ``"liboqs"`` or ``"rustcrypto"``.
        """
        hint = self._INSTALL_HINTS.get(backend, f"install the '{backend}' backend")
        super().__init__(
            f"Backend '{backend}' is not available. To install: {hint}",
            backend=backend,
        )
        self.install_hint = hint


class BackendMismatch(BackendError):
    """A key was created with one backend but an operation requires another.

    The ``context`` dict carries ``key_backend`` and ``op_backend``.
    """

    code = "QS_BACKEND_MISMATCH"

    def __init__(self, key_backend: str, op_backend: str) -> None:
        """Create the error.

        Args:
            key_backend: Name of the backend that created the key.
            op_backend: Name of the backend the operation requires.
        """
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
    an operation that requires at least hybrid security. The ``context`` dict carries
    ``detected_algo`` and ``required``.
    """

    code = "QS_CLASSICAL_KEY"

    def __init__(self, algo: str, min_required: str = "hybrid") -> None:
        """Create the error.

        Args:
            algo: Name of the classical algorithm that was found.
            min_required: The minimum security level that was required. Defaults to
                ``"hybrid"``.
        """
        super().__init__(
            f"Classical algorithm '{algo}' does not meet the minimum required "
            f"security level '{min_required}'. Use a hybrid or PQC-only key.",
            detected_algo=algo,
            required=min_required,
        )


class IncompatibleKeyVersion(MigrationError):
    """The key's qs-version field is not supported by this library version.

    The library raises it when a serialized key carries a format version above the highest it
    reads. The ``context`` dict carries ``key_version`` and ``supported_max``.
    """

    code = "QS_KEY_VERSION"

    def __init__(self, key_version: int, supported_max: int) -> None:
        """Create the error.

        Args:
            key_version: The format version found in the key.
            supported_max: The highest format version this library reads.
        """
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
    can suggest alternatives without hard-coding the list. Both are stored in the ``context``
    dict as ``algo`` and ``available`` (an empty list when none were given).
    """

    code = "QS_ALGO_UNSUPPORTED"

    def __init__(self, algo: str, available: list[str] | None = None) -> None:
        """Create the error.

        Args:
            algo: The algorithm name that was requested.
            available: Valid algorithm names; when given, they are listed in the message.
        """
        hint = ""
        if available:
            hint = f" Available: {', '.join(available)}"
        super().__init__(
            f"Algorithm '{algo}' is not supported.{hint}",
            algo=algo,
            available=available or [],
        )
