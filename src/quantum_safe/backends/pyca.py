"""
quantum_safe.backends.pyca
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional backend on pyca/``cryptography`` (>= 48): ML-KEM-768 and ML-KEM-1024, ML-DSA-44, ML-DSA-65
and ML-DSA-87. It needs no compiler and no liboqs.

Its distinguishing property is **seeded** keys. A key here *is* its seed, FIPS's native secret-key
form: 32 bytes for ML-DSA, 64 bytes (``d || z``) for ML-KEM. So a key can be exported as a seed,
rebuilt from it, shared with quantum-safe-ts, and used in RFC 9964 private JWKs and COSE keys, none
of which liboqs can do for ML-DSA (it has no seeded key generation).

Keys made by liboqs are *expanded* (4,032 bytes for ML-DSA-65, 2,400 for ML-KEM-768). The two forms
are told apart by length, and each backend hands a key of the other form to the other backend, so a
key works with whichever backend the caller selected, as long as both are installed.

What it does not have: ML-KEM-512, SLH-DSA, BIKE, HQC, LMS (liboqs only).
"""

from __future__ import annotations

from typing import Any, ClassVar

from quantum_safe.backends.base import AbstractKEMBackend, AbstractSignatureBackend, AlgorithmInfo
from quantum_safe.exceptions import (
    BackendNotAvailable,
    CryptoError,
    DecapsulationError,
    KeyGenerationError,
    UnsupportedAlgorithm,
)

_DSA_SEED_BYTES = 32
_KEM_SEED_BYTES = 64
_DSA_NAMES = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
_KEM_NAMES = ("ML-KEM-768", "ML-KEM-1024")
_DSA_EXPANDED = {"ML-DSA-44": 2560, "ML-DSA-65": 4032, "ML-DSA-87": 4896}
_KEM_EXPANDED = {"ML-KEM-768": 2400, "ML-KEM-1024": 3168}


def _dsa_classes(algorithm: str) -> tuple[Any, Any]:
    """Return the pyca ``(private_key_class, public_key_class)`` pair for an ML-DSA name.

    Raises ``UnsupportedAlgorithm`` for a name outside ML-DSA-44/65/87 and
    ``BackendNotAvailable`` when the installed ``cryptography`` has no ``mldsa`` module.
    """
    if algorithm not in _DSA_NAMES:
        raise UnsupportedAlgorithm(algorithm, available=list(_DSA_NAMES))
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:  # cryptography < 48
        raise BackendNotAvailable("pyca") from exc
    suffix = algorithm.removeprefix("ML-DSA-")
    return getattr(mldsa, f"MLDSA{suffix}PrivateKey"), getattr(mldsa, f"MLDSA{suffix}PublicKey")


def _kem_classes(algorithm: str) -> tuple[Any, Any]:
    """Return the pyca ``(private_key_class, public_key_class)`` pair for an ML-KEM name.

    Raises ``UnsupportedAlgorithm`` for a name outside ML-KEM-768/1024 and
    ``BackendNotAvailable`` when the installed ``cryptography`` has no ``mlkem`` module.
    """
    if algorithm not in _KEM_NAMES:
        raise UnsupportedAlgorithm(algorithm, available=list(_KEM_NAMES))
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem
    except ImportError as exc:
        raise BackendNotAvailable("pyca") from exc
    suffix = algorithm.removeprefix("ML-KEM-")
    return getattr(mlkem, f"MLKEM{suffix}PrivateKey"), getattr(mlkem, f"MLKEM{suffix}PublicKey")


def _liboqs_sig() -> Any:  # noqa: ANN401
    from quantum_safe.backends import get_signature_backend

    return get_signature_backend("liboqs")


def _liboqs_kem() -> Any:  # noqa: ANN401
    from quantum_safe.backends import get_kem_backend

    return get_kem_backend("liboqs")


class PycaSignatureBackend(AbstractSignatureBackend):
    """ML-DSA through pyca/cryptography, with seed keys."""

    name: ClassVar[str] = "pyca"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
        """Return ML-DSA-44, ML-DSA-65 and ML-DSA-87, or an empty list without ``mldsa``."""
        from quantum_safe.backends.liboqs import _SIGNATURE_ALGORITHM_INFO

        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        except ImportError:
            return []
        return [_SIGNATURE_ALGORITHM_INFO[n] for n in _DSA_NAMES]

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Returns ``(public_key, seed)``; the 32-byte seed is the secret key.

        Args:
            algorithm: "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".

        Raises:
            UnsupportedAlgorithm: if the name is not an ML-DSA parameter set.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-DSA support.
            KeyGenerationError: if pyca fails to generate the key.
        """
        private_cls, _ = _dsa_classes(algorithm)
        try:
            key = private_cls.generate()
            return bytes(key.public_key().public_bytes_raw()), bytes(key.private_bytes_raw())
        except Exception as exc:
            raise KeyGenerationError(
                f"pyca ML-DSA keygen failed for {algorithm}: {exc}", algorithm=algorithm
            ) from exc

    def keygen_from_seed(self, algorithm: str, seed: bytes) -> tuple[bytes, bytes]:
        """Deterministic key generation from the 32-byte FIPS 204 seed (``xi``).

        Args:
            algorithm: "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".
            seed: The 32-byte seed.

        Returns:
            ``(public_key, seed)``: the seed itself is the secret key.

        Raises:
            UnsupportedAlgorithm: if the name is not an ML-DSA parameter set.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-DSA support.
            ValueError: if ``seed`` is not exactly 32 bytes.
        """
        private_cls, _ = _dsa_classes(algorithm)
        if len(seed) != _DSA_SEED_BYTES:
            raise ValueError(f"an ML-DSA seed is exactly {_DSA_SEED_BYTES} bytes, got {len(seed)}")
        key = private_cls.from_seed_bytes(bytes(seed))
        return bytes(key.public_key().public_bytes_raw()), bytes(seed)

    def _private(self, algorithm: str, secret_key: bytes) -> Any:  # noqa: ANN401
        """Build the pyca private key from a 32-byte seed key; any other length is a ValueError."""
        private_cls, _ = _dsa_classes(algorithm)
        if len(secret_key) != _DSA_SEED_BYTES:
            raise ValueError(
                f"the pyca backend signs from a {_DSA_SEED_BYTES}-byte seed key; this key is "
                f"{len(secret_key)} bytes (an expanded key made by liboqs)"
            )
        return private_cls.from_seed_bytes(bytes(secret_key))

    def _is_expanded(self, algorithm: str, secret_key: bytes) -> bool:
        """True when ``secret_key`` has the length of an expanded (liboqs-made) key."""
        return len(secret_key) == _DSA_EXPANDED.get(algorithm, -1)

    def sign(
        self, algorithm: str, secret_key: bytes, message: bytes, context: bytes = b""
    ) -> bytes:
        """The library's prefix construction: ML-DSA (empty FIPS 204 context) over
        ``len(context) || context || message``, identical to the liboqs backend.

        An expanded key (made by liboqs) is signed through the liboqs backend.

        Args:
            algorithm: "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".
            secret_key: The 32-byte seed key, or an expanded key.
            message: The message to sign.
            context: Domain-separation context, at most 255 bytes.

        Returns:
            The signature bytes.

        Raises:
            ValueError: if ``context`` is longer than 255 bytes, or ``secret_key`` is neither a
                32-byte seed nor an expanded key.
            CryptoError: if pyca fails to sign.
        """
        if len(context) > 255:
            raise ValueError(f"context must be <=255 bytes, got {len(context)}")
        if self._is_expanded(algorithm, secret_key):
            return bytes(_liboqs_sig().sign(algorithm, secret_key, message, context))
        try:
            return bytes(
                self._private(algorithm, secret_key).sign(bytes([len(context)]) + context + message)
            )
        except ValueError:
            raise
        except Exception as exc:
            raise CryptoError(
                f"pyca signing failed for {algorithm}: {exc}", algorithm=algorithm
            ) from exc

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = b"",
    ) -> bool:
        """Verify a signature made by :meth:`sign` (or by the liboqs backend's ``sign``).

        Args:
            algorithm: "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".
            public_key: The signer's public key bytes.
            message: The signed message.
            signature: The signature bytes.
            context: Must match the context used when signing. A context longer than 255 bytes
                returns False.

        Returns:
            True if the signature is valid. False for an invalid signature or a malformed key
            or signature.

        Raises:
            UnsupportedAlgorithm: if the name is not an ML-DSA parameter set.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-DSA support.
        """
        if len(context) > 255:
            return False
        return self._verify(
            algorithm, public_key, bytes([len(context)]) + context + message, signature, b""
        )

    def _verify(
        self, algorithm: str, public_key: bytes, data: bytes, signature: bytes, ctx: bytes
    ) -> bool:
        """Verify ``signature`` over ``data`` with FIPS 204 context ``ctx`` (empty means none)."""
        _, public_cls = _dsa_classes(algorithm)
        try:
            public_cls.from_public_bytes(bytes(public_key)).verify(
                bytes(signature), bytes(data), bytes(ctx) if ctx else None
            )
            return True
        except Exception:  # noqa: BLE001  (an invalid signature, or a malformed key or signature)
            return False

    def sign_native_context(
        self, algorithm: str, secret_key: bytes, message: bytes, context: bytes
    ) -> bytes:
        """``ML-DSA.Sign`` with FIPS 204's native context string.

        An expanded key (made by liboqs) is signed through the liboqs backend.

        Args:
            algorithm: "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".
            secret_key: The 32-byte seed key, or an expanded key.
            message: The message to sign, passed to ML-DSA.Sign unchanged.
            context: The FIPS 204 context string, at most 255 bytes.

        Returns:
            The signature bytes.

        Raises:
            ValueError: if ``context`` is longer than 255 bytes, or ``secret_key`` is neither a
                32-byte seed nor an expanded key.
            CryptoError: if pyca fails to sign.
        """
        if len(context) > 255:
            raise ValueError(f"context must be <=255 bytes, got {len(context)}")
        if self._is_expanded(algorithm, secret_key):
            return bytes(_liboqs_sig().sign_native_context(algorithm, secret_key, message, context))
        try:
            return bytes(
                self._private(algorithm, secret_key).sign(bytes(message), bytes(context) or None)
            )
        except ValueError:
            raise
        except Exception as exc:
            raise CryptoError(
                f"pyca native-context signing failed for {algorithm}: {exc}", algorithm=algorithm
            ) from exc

    def verify_native_context(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        """Verify a signature made with :meth:`sign_native_context`.

        Args:
            algorithm: "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".
            public_key: The signer's public key bytes.
            message: The signed message.
            signature: The signature bytes.
            context: The FIPS 204 context string used when signing. A context longer than
                255 bytes returns False.

        Returns:
            True if the signature is valid. False for an invalid signature or a malformed key
            or signature.

        Raises:
            UnsupportedAlgorithm: if the name is not an ML-DSA parameter set.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-DSA support.
        """
        if len(context) > 255:
            return False
        return self._verify(algorithm, public_key, message, signature, context)


class PycaKEMBackend(AbstractKEMBackend):
    """ML-KEM-768 and ML-KEM-1024 through pyca/cryptography, with seed keys."""

    name: ClassVar[str] = "pyca"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
        """Return ML-KEM-768 and ML-KEM-1024, or an empty list without ``mlkem``."""
        from quantum_safe.backends.liboqs import _KEM_ALGORITHM_INFO

        try:
            from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: F401
        except ImportError:
            return []
        return [_KEM_ALGORITHM_INFO[n] for n in _KEM_NAMES]

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Returns ``(public_key, seed)``; the 64-byte seed ``d || z`` is the secret key.

        Args:
            algorithm: "ML-KEM-768" or "ML-KEM-1024".

        Raises:
            UnsupportedAlgorithm: if the name is not ML-KEM-768 or ML-KEM-1024.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-KEM support.
            KeyGenerationError: if pyca fails to generate the key.
        """
        private_cls, _ = _kem_classes(algorithm)
        try:
            key = private_cls.generate()
            return bytes(key.public_key().public_bytes_raw()), bytes(key.private_bytes_raw())
        except Exception as exc:
            raise KeyGenerationError(
                f"pyca ML-KEM keygen failed for {algorithm}: {exc}", algorithm=algorithm
            ) from exc

    def keygen_from_seed(self, algorithm: str, seed: bytes) -> tuple[bytes, bytes]:
        """Deterministic key generation from the 64-byte FIPS 203 seed ``d || z``.

        Args:
            algorithm: "ML-KEM-768" or "ML-KEM-1024".
            seed: The 64-byte seed.

        Returns:
            ``(public_key, seed)``: the seed itself is the secret key.

        Raises:
            UnsupportedAlgorithm: if the name is not ML-KEM-768 or ML-KEM-1024.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-KEM support.
            ValueError: if ``seed`` is not exactly 64 bytes.
        """
        private_cls, _ = _kem_classes(algorithm)
        if len(seed) != _KEM_SEED_BYTES:
            raise ValueError(f"an ML-KEM seed is exactly {_KEM_SEED_BYTES} bytes, got {len(seed)}")
        key = private_cls.from_seed_bytes(bytes(seed))
        return bytes(key.public_key().public_bytes_raw()), bytes(seed)

    def encapsulate(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret under the given public key.

        Args:
            algorithm: "ML-KEM-768" or "ML-KEM-1024".
            public_key: The recipient's public key bytes.

        Returns:
            (ciphertext_bytes, shared_secret_bytes).

        Raises:
            UnsupportedAlgorithm: if the name is not ML-KEM-768 or ML-KEM-1024.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-KEM support.
            CryptoError: if pyca rejects the public key or fails to encapsulate.
        """
        _, public_cls = _kem_classes(algorithm)
        try:
            shared_secret, ciphertext = public_cls.from_public_bytes(
                bytes(public_key)
            ).encapsulate()
        except Exception as exc:
            raise CryptoError(
                f"pyca encapsulation failed for {algorithm}: {exc}", algorithm=algorithm
            ) from exc
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret from a ciphertext.

        An expanded key (made by liboqs) is decapsulated through the liboqs backend.

        Args:
            algorithm: "ML-KEM-768" or "ML-KEM-1024".
            secret_key: The 64-byte seed key, or an expanded key.
            ciphertext: The ciphertext produced by encapsulation.

        Returns:
            The shared secret bytes.

        Raises:
            UnsupportedAlgorithm: if the name is not ML-KEM-768 or ML-KEM-1024.
            BackendNotAvailable: if the installed ``cryptography`` has no ML-KEM support.
            ValueError: if ``secret_key`` is neither a 64-byte seed nor an expanded key.
            DecapsulationError: if pyca fails to decapsulate.
        """
        private_cls, _ = _kem_classes(algorithm)
        if len(secret_key) == _KEM_EXPANDED.get(algorithm, -1):
            return bytes(_liboqs_kem().decapsulate(algorithm, secret_key, ciphertext))
        if len(secret_key) != _KEM_SEED_BYTES:
            raise ValueError(
                f"the pyca backend decapsulates from a {_KEM_SEED_BYTES}-byte seed key; "
                f"this key is {len(secret_key)} bytes"
            )
        try:
            return bytes(
                private_cls.from_seed_bytes(bytes(secret_key)).decapsulate(bytes(ciphertext))
            )
        except Exception as exc:
            raise DecapsulationError(algo=algorithm) from exc
