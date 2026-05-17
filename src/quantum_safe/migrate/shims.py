"""
quantum_safe.migrate.shims
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Drop-in replacement shims for common classical cryptography APIs.

These shims let you migrate a codebase incrementally: replace the import
and the rest of your code works unchanged, but now has PQC protection.

Every shim call is logged so you can see exactly which code paths are
still using the shim vs. direct quantum-safe calls. Once a path is fully
migrated to native quantum-safe calls, the shim is no longer needed.

Available shims
---------------
FernetShim     — Replaces cryptography.fernet.Fernet
                 (symmetric encryption with HMAC)
                 → Envelope.seal() / Envelope.open() with HybridKEM

JWTShim        — Replaces PyJWT's jwt.encode() / jwt.decode()
                 → JWTSigner / JWTVerifier with ML-DSA

Usage::

    # Before migration:
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(data)

    # During migration — drop-in replacement, logs every call:
    from quantum_safe.migrate.shims import FernetShim as Fernet
    # ... rest of code unchanged ...

    # After full migration:
    from quantum_safe.protocols import Envelope
    sealed = Envelope.seal(data, recipient_public_key)
    # ... use native API ...

Note on FernetShim semantics
----------------------------
Fernet uses a symmetric key, which means anyone with the key can both
encrypt and decrypt. Envelope.seal() uses asymmetric KEM — you encrypt
to a public key, and only the holder of the secret key can decrypt.

The FernetShim cannot be a true drop-in for Fernet because the security
model is fundamentally different. Instead, it:
  1. Auto-generates a keypair on construction (stateful)
  2. Encrypts to that keypair's public key
  3. Decrypts with that keypair's secret key

This maintains the same interface (encrypt/decrypt with the same object)
while upgrading the underlying construction to PQC.

For code that shares a Fernet key between processes, use the
quantum_safe.protocols.Envelope API directly with explicit key management.
"""

from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from quantum_safe.types import PublicKey, SecretKey

_logger = logging.getLogger(__name__)


class _ShimBase:
    """Common behavior for all shims: logging, deprecation warnings, call counting."""

    _shim_name: str = "ShimBase"
    _call_count: int = 0

    @classmethod
    def _log_shim_call(cls, method: str, note: str = "") -> None:
        cls._call_count += 1
        _logger.debug(
            "[quantum-safe shim] %s.%s() called (total calls: %d)%s",
            cls._shim_name,
            method,
            cls._call_count,
            f" - {note}" if note else "",
        )

    @classmethod
    def shim_stats(cls) -> dict[str, Any]:
        return {
            "shim": cls._shim_name,
            "call_count": cls._call_count,
        }


class FernetShim(_ShimBase):
    """Drop-in replacement for cryptography.fernet.Fernet.

    Replaces the symmetric Fernet construction with asymmetric hybrid KEM +
    AES-256-GCM encryption. See module docstring for semantic differences.

    The interface is intentionally similar to Fernet but not identical:
      - No `generate_key()` class method (keys are asymmetric now)
      - `encrypt(data)` → bytes  (SealedMessage serialized)
      - `decrypt(token)` → bytes

    Call shim_stats() to see how often this shim is being used.
    """

    _shim_name = "FernetShim"

    def __init__(self, backend: str = "auto") -> None:
        warnings.warn(
            "FernetShim: you are using a migration shim. "
            "This replaces Fernet with quantum-safe encryption (HybridKEM + AES-256-GCM). "
            "The security model is different — see quantum_safe.migrate.shims docstring. "
            "Migrate to quantum_safe.protocols.Envelope when ready.",
            DeprecationWarning,
            stacklevel=2,
        )
        from quantum_safe.kem.hybrid import HybridKEM

        self._kem = HybridKEM(backend=backend)
        self._keypair = self._kem.generate_keypair()
        self._log_shim_call("__init__")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data. Returns a SealedMessage serialized to bytes."""
        from quantum_safe.protocols.envelope import Envelope

        self._log_shim_call("encrypt")
        sealed = Envelope.seal(data, self._keypair.public, kem=self._kem)
        return sealed.to_bytes()

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt a token produced by encrypt()."""
        from quantum_safe.protocols.envelope import Envelope, SealedMessage

        self._log_shim_call("decrypt")
        sealed = SealedMessage.from_bytes(token)
        return Envelope.open(sealed, self._keypair.secret, kem=self._kem)

    @property
    def public_key(self) -> PublicKey:
        """The public key used for encryption. Share this with senders."""
        return self._keypair.public

    @property
    def secret_key(self) -> SecretKey:
        """The secret key used for decryption. Keep this private."""
        return self._keypair.secret


class JWTShim(_ShimBase):
    """Drop-in replacement for PyJWT's jwt.encode() / jwt.decode().

    Replaces classical JWT signing (RS256, ES256, HS256) with hybrid
    PQC signing (Ed25519+ML-DSA-65).

    Usage::

        # Before:
        import jwt
        token = jwt.encode({"sub": "user"}, private_key, algorithm="RS256")
        claims = jwt.decode(token, public_key, algorithms=["RS256"])

        # After (drop-in):
        from quantum_safe.migrate.shims import JWTShim as jwt
        token = jwt.encode({"sub": "user"}, keypair, algorithm="Ed25519+ML-DSA-65")
        claims = jwt.decode(token, public_key, algorithms=["Ed25519+ML-DSA-65"])

    The `key` parameter accepts a quantum_safe.types.KeyPair for encoding
    and a quantum_safe.types.PublicKey for decoding.
    """

    _shim_name = "JWTShim"

    @staticmethod
    def encode(
        payload: dict[str, Any],
        key: Any,  # noqa: ANN401
        algorithm: str = "Ed25519+ML-DSA-65",
        **kwargs: Any,  # noqa: ANN401
    ) -> str:
        """Sign a JWT payload.

        Args:
            payload:    Claims dict.
            key:        quantum_safe.types.KeyPair for signing.
            algorithm:  Hybrid or PQC algorithm string.

        Returns:
            JWT token string.
        """
        JWTShim._log_shim_call("encode")
        warnings.warn(
            "JWTShim.encode() is a migration shim. "
            "Migrate to quantum_safe.protocols.jwt.JWTSigner when ready.",
            DeprecationWarning,
            stacklevel=2,
        )
        from quantum_safe.protocols.jwt import JWTSigner
        from quantum_safe.types import KeyPair

        if not isinstance(key, KeyPair):
            raise TypeError(
                f"JWTShim.encode() requires a quantum_safe KeyPair, got {type(key).__name__}. "
                f"Generate one with HybridSign().generate_keypair()."
            )

        signer = JWTSigner(key, issuer=payload.get("iss"))
        # Pass claims without duplicating iss (JWTSigner adds it from keypair issuer param)
        claims = {k: v for k, v in payload.items() if k != "iss"}
        expires_in = 0
        if "exp" in payload:
            import time

            exp_delta = int(payload["exp"]) - int(time.time())
            expires_in = max(exp_delta, 1)
        return signer.sign(claims, expires_in=expires_in)

    @staticmethod
    def decode(
        token: str,
        key: Any,  # noqa: ANN401
        algorithms: list[str] | None = None,
        **kwargs: Any,  # noqa: ANN401
    ) -> dict[str, Any]:
        """Verify and decode a JWT.

        Args:
            token:      JWT string from encode().
            key:        quantum_safe.types.PublicKey for verification.
            algorithms: Ignored — algorithm is inferred from the token header.

        Returns:
            Verified claims dict.
        """
        JWTShim._log_shim_call("decode")
        warnings.warn(
            "JWTShim.decode() is a migration shim. "
            "Migrate to quantum_safe.protocols.jwt.JWTVerifier when ready.",
            DeprecationWarning,
            stacklevel=2,
        )
        from quantum_safe.protocols.jwt import JWTVerifier
        from quantum_safe.types import PublicKey

        if not isinstance(key, PublicKey):
            raise TypeError(
                f"JWTShim.decode() requires a quantum_safe PublicKey, got {type(key).__name__}."
            )

        verifier = JWTVerifier(key)
        return verifier.verify(token)
