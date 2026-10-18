"""
quantum_safe.backends.rustcrypto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Backend adapter for quantum-safe-py, our thin PyO3 wrapper around the
RustCrypto ml-kem and ml-dsa crates.

The RustCrypto crates implement exactly the NIST standardized algorithms:
  - ml-kem (ML-KEM-512/768/1024, FIPS 203)
  - ml-dsa (ML-DSA-44/65/87, FIPS 204)
  - slh-dsa (SLH-DSA variants, FIPS 205)

They are faster than liboqs on native x86-64 (AVX2 optimizations),
WASM-compatible (via wasm-bindgen on the Rust side), and have a smaller
attack surface because they're pure Rust with no C dependency.

The trade-off: they don't support research algorithms (BIKE, HQC, FrodoKEM).
If you need those, use the liboqs backend.

Installation::

    pip install 'quantum-safe-py[rustcrypto]'

Status: The quantum-safe-py PyO3 crate is currently in development.
This module will be fully functional when the crate reaches 0.1.0.
Until then, is_available() returns False and the liboqs backend is used.
"""

from __future__ import annotations

from typing import Any, ClassVar, cast

from quantum_safe.backends.base import AbstractKEMBackend, AbstractSignatureBackend, AlgorithmInfo
from quantum_safe.exceptions import BackendNotAvailable

# The ImportError from the one failed attempt to import the extension, remembered so that later
# probes do not search ``sys.path`` again: Python does not cache failed imports, and every
# ``HybridKEM()`` / ``Sign()`` construction asks this backend first (see ``backends/__init__.py``).
# ``reset_import_probe()`` forgets it, for a process that installs the extension while running.
_import_failure: ImportError | None = None


def reset_import_probe() -> None:
    """Forget a remembered failed import so the next probe looks for the extension again."""
    global _import_failure
    _import_failure = None


def _import_qs_py() -> Any:  # noqa: ANN401
    """Import the quantum_safe_py native extension or raise BackendNotAvailable.

    A failed import is remembered for the life of the process (see ``reset_import_probe``); a
    successful one is cached by Python itself.
    """
    global _import_failure
    if _import_failure is not None:
        raise BackendNotAvailable("rustcrypto") from _import_failure
    try:
        import quantum_safe_py as _qs_py  # type: ignore[import-not-found]

        return _qs_py
    except ImportError as exc:
        _import_failure = exc
        raise BackendNotAvailable("rustcrypto") from exc


class RustCryptoKEMBackend(AbstractKEMBackend):
    """KEM backend using the RustCrypto ml-kem crate via PyO3.

    This backend will be populated fully when quantum-safe-py hits PyPI.
    The interface mirrors LiboqsKEMBackend exactly so switching is a one-liner.
    """

    name: ClassVar[str] = "rustcrypto"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
        """Return the static list: ML-KEM-512, ML-KEM-768 and ML-KEM-1024 (FIPS 203).

        The list does not depend on the extension being installed.
        """
        # When quantum-safe-py is available, this will delegate to it.
        # For now return the static list — these are stable FIPS algorithms.
        return [
            AlgorithmInfo(
                name="ML-KEM-512",
                nist_level=1,
                public_key_size=800,
                secret_key_size=1632,
                ciphertext_size=768,
                is_kem=True,
                is_signature=False,
                is_nist_standard=True,
            ),
            AlgorithmInfo(
                name="ML-KEM-768",
                nist_level=3,
                public_key_size=1184,
                secret_key_size=2400,
                ciphertext_size=1088,
                is_kem=True,
                is_signature=False,
                is_nist_standard=True,
                notes="Recommended default.",
            ),
            AlgorithmInfo(
                name="ML-KEM-1024",
                nist_level=5,
                public_key_size=1568,
                secret_key_size=3168,
                ciphertext_size=1568,
                is_kem=True,
                is_signature=False,
                is_nist_standard=True,
            ),
        ]

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate a KEM key pair with the native extension's ``kem_keygen``.

        Args:
            algorithm: Algorithm name, e.g. "ML-KEM-768".

        Returns:
            (public_key_bytes, secret_key_bytes), as returned by the extension.

        Raises:
            BackendNotAvailable: if the ``quantum_safe_py`` extension cannot be imported.
        """
        qs = _import_qs_py()
        return cast(tuple[bytes, bytes], qs.kem_keygen(algorithm))

    def encapsulate(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret with the native extension's ``kem_encapsulate``.

        Args:
            algorithm: Algorithm name, e.g. "ML-KEM-768".
            public_key: The recipient's public key bytes.

        Returns:
            (ciphertext_bytes, shared_secret_bytes), as returned by the extension.

        Raises:
            BackendNotAvailable: if the ``quantum_safe_py`` extension cannot be imported.
        """
        qs = _import_qs_py()
        return cast(tuple[bytes, bytes], qs.kem_encapsulate(algorithm, public_key))

    def decapsulate(self, algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret with the native extension's ``kem_decapsulate``.

        Args:
            algorithm: Algorithm name, e.g. "ML-KEM-768".
            secret_key: The recipient's secret key bytes.
            ciphertext: The ciphertext produced by encapsulation.

        Returns:
            The shared secret bytes, as returned by the extension.

        Raises:
            BackendNotAvailable: if the ``quantum_safe_py`` extension cannot be imported.
        """
        qs = _import_qs_py()
        return cast(bytes, qs.kem_decapsulate(algorithm, secret_key, ciphertext))

    def is_available(self) -> bool:
        """Return True if the ``quantum_safe_py`` extension can be imported."""
        try:
            _import_qs_py()
            return True
        except BackendNotAvailable:
            return False


class RustCryptoSignatureBackend(AbstractSignatureBackend):
    """Signature backend using the RustCrypto ml-dsa/slh-dsa crates via PyO3."""

    name: ClassVar[str] = "rustcrypto"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
        """Return the static list: ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204).

        The list does not depend on the extension being installed.
        """
        return [
            AlgorithmInfo(
                name="ML-DSA-44",
                nist_level=2,
                public_key_size=1312,
                secret_key_size=2560,
                ciphertext_size=2420,
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
            ),
            AlgorithmInfo(
                name="ML-DSA-65",
                nist_level=3,
                public_key_size=1952,
                secret_key_size=4032,
                ciphertext_size=3309,
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
                notes="Recommended default.",
            ),
            AlgorithmInfo(
                name="ML-DSA-87",
                nist_level=5,
                public_key_size=2592,
                secret_key_size=4896,
                ciphertext_size=4627,
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
            ),
        ]

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate a signing key pair with the native extension's ``sig_keygen``.

        Args:
            algorithm: Algorithm name, e.g. "ML-DSA-65".

        Returns:
            (public_key_bytes, secret_key_bytes), as returned by the extension.

        Raises:
            BackendNotAvailable: if the ``quantum_safe_py`` extension cannot be imported.
        """
        qs = _import_qs_py()
        return cast(tuple[bytes, bytes], qs.sig_keygen(algorithm))

    def sign(
        self,
        algorithm: str,
        secret_key: bytes,
        message: bytes,
        context: bytes = b"",
    ) -> bytes:
        """Sign a message with the native extension's ``sig_sign``.

        Args:
            algorithm: Algorithm name, e.g. "ML-DSA-65".
            secret_key: The signer's secret key bytes.
            message: The message to sign.
            context: Domain-separation context, passed to the extension unchanged.

        Returns:
            The signature bytes, as returned by the extension.

        Raises:
            BackendNotAvailable: if the ``quantum_safe_py`` extension cannot be imported.
        """
        qs = _import_qs_py()
        return cast(bytes, qs.sig_sign(algorithm, secret_key, message, context))

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = b"",
    ) -> bool:
        """Verify a signature with the native extension's ``sig_verify``.

        Args:
            algorithm: Algorithm name, e.g. "ML-DSA-65".
            public_key: The signer's public key bytes.
            message: The signed message.
            signature: The signature bytes.
            context: Must match the context used when signing.

        Returns:
            True if the extension reports the signature valid. False for an invalid signature
            and for any exception, including the extension being unavailable.
        """
        try:
            qs = _import_qs_py()
            return bool(qs.sig_verify(algorithm, public_key, message, signature, context))
        except Exception:  # noqa: BLE001
            return False

    def is_available(self) -> bool:
        """Return True if the ``quantum_safe_py`` extension can be imported."""
        try:
            _import_qs_py()
            return True
        except BackendNotAvailable:
            return False
