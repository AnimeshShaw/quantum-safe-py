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

    pip install 'quantum-safe[rustcrypto]'

Status: The quantum-safe-py PyO3 crate is currently in development.
This module will be fully functional when the crate reaches 0.1.0.
Until then, is_available() returns False and the liboqs backend is used.
"""

from __future__ import annotations

from typing import Any, ClassVar, cast

from quantum_safe.backends.base import AbstractKEMBackend, AbstractSignatureBackend, AlgorithmInfo
from quantum_safe.exceptions import BackendNotAvailable


def _import_qs_py() -> Any:  # noqa: ANN401
    """Import the quantum_safe_py native extension or raise BackendNotAvailable."""
    try:
        import quantum_safe_py as _qs_py  # type: ignore[import-not-found]

        return _qs_py
    except ImportError as exc:
        raise BackendNotAvailable("rustcrypto") from exc


class RustCryptoKEMBackend(AbstractKEMBackend):
    """KEM backend using the RustCrypto ml-kem crate via PyO3.

    This backend will be populated fully when quantum-safe-py hits PyPI.
    The interface mirrors LiboqsKEMBackend exactly so switching is a one-liner.
    """

    name: ClassVar[str] = "rustcrypto"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
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
        qs = _import_qs_py()
        return cast(tuple[bytes, bytes], qs.kem_keygen(algorithm))

    def encapsulate(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        qs = _import_qs_py()
        return cast(tuple[bytes, bytes], qs.kem_encapsulate(algorithm, public_key))

    def decapsulate(self, algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        qs = _import_qs_py()
        return cast(bytes, qs.kem_decapsulate(algorithm, secret_key, ciphertext))

    def is_available(self) -> bool:
        try:
            _import_qs_py()
            return True
        except BackendNotAvailable:
            return False


class RustCryptoSignatureBackend(AbstractSignatureBackend):
    """Signature backend using the RustCrypto ml-dsa/slh-dsa crates via PyO3."""

    name: ClassVar[str] = "rustcrypto"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
        return [
            AlgorithmInfo(
                name="ML-DSA-44",
                nist_level=2,
                public_key_size=1312,
                secret_key_size=2528,
                ciphertext_size=2420,
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
            ),
            AlgorithmInfo(
                name="ML-DSA-65",
                nist_level=3,
                public_key_size=1952,
                secret_key_size=4000,
                ciphertext_size=3293,
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
                notes="Recommended default.",
            ),
            AlgorithmInfo(
                name="ML-DSA-87",
                nist_level=5,
                public_key_size=2592,
                secret_key_size=4864,
                ciphertext_size=4595,
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
            ),
        ]

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        qs = _import_qs_py()
        return cast(tuple[bytes, bytes], qs.sig_keygen(algorithm))

    def sign(
        self,
        algorithm: str,
        secret_key: bytes,
        message: bytes,
        context: bytes = b"",
    ) -> bytes:
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
        try:
            qs = _import_qs_py()
            return bool(qs.sig_verify(algorithm, public_key, message, signature, context))
        except Exception:  # noqa: BLE001
            return False

    def is_available(self) -> bool:
        try:
            _import_qs_py()
            return True
        except BackendNotAvailable:
            return False
