"""
quantum_safe.backends.base
~~~~~~~~~~~~~~~~~~~~~~~~~~

Abstract base class for cryptographic backends.

Every concrete backend (liboqs, rustcrypto, noble) must implement this
interface. The KEM and signature classes depend only on this interface —
they never import from a specific backend directly. Backend selection
happens at construction time (or via environment detection).

Adding a new backend:
  1. Create a module in quantum_safe/backends/
  2. Subclass AbstractBackend
  3. Register it in quantum_safe/backends/__init__.py
  4. It'll appear in KEM(backend="yourname") and in benchmarks automatically

Thread safety: backends are expected to be stateless (no mutable shared
state). Each operation gets fresh inputs and returns fresh outputs. If a
backend needs internal state (e.g. an OpenSSL context), it should create
and destroy it within each method call, not share it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class AlgorithmInfo:
    """Metadata about a specific algorithm on a specific backend.

    Used for capability discovery and benchmark reporting.
    """

    name: str            # e.g. "ML-KEM-768"
    nist_level: int      # NIST security level 1-5
    public_key_size: int  # bytes
    secret_key_size: int  # bytes
    ciphertext_size: int  # bytes (for KEMs); signature_size for signatures
    is_kem: bool
    is_signature: bool
    is_nist_standard: bool  # True if standardized in FIPS 203/204/205
    notes: str = ""


class AbstractKEMBackend(ABC):
    """Interface for KEM (Key Encapsulation Mechanism) backends.

    Implementations wrap a specific cryptographic library (liboqs, RustCrypto,
    etc.) and expose a uniform interface for keygen, encap, and decap.

    All methods are synchronous. If you need async, call from a thread pool.
    """

    # Subclasses must set this to identify themselves in logs and benchmarks
    name: ClassVar[str] = "abstract"

    @abstractmethod
    def supported_algorithms(self) -> list[AlgorithmInfo]:
        """Return metadata for all KEM algorithms this backend supports."""
        ...

    @abstractmethod
    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate a key pair.

        Args:
            algorithm: Algorithm name, e.g. "ML-KEM-768"

        Returns:
            (public_key_bytes, secret_key_bytes)

        Raises:
            UnsupportedAlgorithm: if the algorithm is not supported
            KeyGenerationError: if keygen fails (RNG failure, etc.)
        """
        ...

    @abstractmethod
    def encapsulate(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate: generate a ciphertext and shared secret.

        Args:
            algorithm:  Algorithm name
            public_key: Recipient's public key bytes

        Returns:
            (ciphertext_bytes, shared_secret_bytes)

        Raises:
            UnsupportedAlgorithm: if the algorithm is not supported
            CryptoError: if encapsulation fails
        """
        ...

    @abstractmethod
    def decapsulate(
        self, algorithm: str, secret_key: bytes, ciphertext: bytes
    ) -> bytes:
        """Decapsulate: recover the shared secret from a ciphertext.

        Args:
            algorithm:  Algorithm name
            secret_key: Recipient's secret key bytes
            ciphertext: Ciphertext from encapsulate()

        Returns:
            shared_secret_bytes (32 bytes for all standardized algorithms)

        Raises:
            DecapsulationError: if decapsulation fails — NEVER reveal why
            UnsupportedAlgorithm: if the algorithm is not supported
        """
        ...

    def is_available(self) -> bool:
        """Return True if this backend is installed and functional.

        Default implementation tries to generate a key with the first
        supported algorithm. Override if there's a cheaper availability check.
        """
        try:
            algos = self.supported_algorithms()
            if not algos:
                return False
            kem_algos = [a for a in algos if a.is_kem]
            if not kem_algos:
                return False
            self.keygen(kem_algos[0].name)
            return True
        except Exception:  # noqa: BLE001
            return False


class AbstractSignatureBackend(ABC):
    """Interface for digital signature backends."""

    name: ClassVar[str] = "abstract"

    @abstractmethod
    def supported_algorithms(self) -> list[AlgorithmInfo]:
        """Return metadata for all signature algorithms this backend supports."""
        ...

    @abstractmethod
    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate a signing key pair.

        Returns:
            (public_key_bytes, secret_key_bytes)
        """
        ...

    @abstractmethod
    def sign(
        self,
        algorithm: str,
        secret_key: bytes,
        message: bytes,
        context: bytes = b"",
    ) -> bytes:
        """Sign a message.

        Args:
            algorithm:  Algorithm name, e.g. "ML-DSA-65"
            secret_key: Signer's secret key bytes
            message:    Message to sign (arbitrary length)
            context:    Domain-separation context (up to 255 bytes, per FIPS 204)

        Returns:
            signature_bytes

        Raises:
            UnsupportedAlgorithm: if the algorithm is not supported
            CryptoError: if signing fails
        """
        ...

    @abstractmethod
    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = b"",
    ) -> bool:
        """Verify a signature.

        Args:
            algorithm:  Algorithm name
            public_key: Signer's public key bytes
            message:    The signed message
            signature:  Signature bytes from sign()
            context:    Must match the context used during signing

        Returns:
            True if valid, False if invalid.

        Note: This returns bool rather than raising on invalid signatures.
        The caller (Sign.verify()) is responsible for raising VerificationError.
        Backends should NOT raise on invalid signatures — return False.
        """
        ...

    def is_available(self) -> bool:
        """Return True if this backend is installed and functional."""
        try:
            algos = self.supported_algorithms()
            sig_algos = [a for a in algos if a.is_signature]
            if not sig_algos:
                return False
            pk, sk = self.keygen(sig_algos[0].name)
            sig = self.sign(sig_algos[0].name, sk, b"test")
            return self.verify(sig_algos[0].name, pk, b"test", sig)
        except Exception:  # noqa: BLE001
            return False
