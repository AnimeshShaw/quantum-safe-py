"""
quantum_safe
~~~~~~~~~~~~

Production-grade post-quantum cryptography for Python.

Quick start::

    from quantum_safe import HybridKEM, HybridSign

    # Key encapsulation (hybrid X25519 + ML-KEM-768 by default)
    kem = HybridKEM()
    kp  = kem.generate_keypair()
    ct, shared_secret = kem.encapsulate(kp.public)
    ss2 = kem.decapsulate(kp.secret, ct)
    assert shared_secret == ss2

    # Digital signatures (hybrid Ed25519 + ML-DSA-65 by default)
    signer  = HybridSign()
    sig_kp  = signer.generate_keypair()
    sm      = signer.sign(b"hello world", sig_kp.secret, context=b"myapp-v1")
    signer.verify(sm, sig_kp.public)

See the full documentation at https://quantum-safe-py.readthedocs.io/en/latest/
"""

from quantum_safe._version import __version__, __version_info__
from quantum_safe.exceptions import (
    BackendError,
    BackendNotAvailable,
    ClassicalKeyDetected,
    ConfigurationError,
    CryptoError,
    DecapsulationError,
    IncompatibleKeyVersion,
    InsecureOperationError,
    KeyGenerationError,
    KeyParseError,
    MigrationError,
    QuantumSafeError,
    SerializationError,
    UnsupportedAlgorithm,
    VerificationError,
)
from quantum_safe.kem import KEM, HybridKEM
from quantum_safe.signatures import HybridSign, Sign
from quantum_safe.types import (
    CipherText,
    HybridCipherText,
    KeyPair,
    KeyType,
    MigrationState,
    PublicKey,
    SecretKey,
    SharedSecret,
    SignedMessage,
    generate_nonce,
)

__all__ = [
    # Version
    "__version__",
    "__version_info__",
    # Main classes (most users only need these two)
    "HybridKEM",
    "HybridSign",
    # Single-algorithm variants
    "KEM",
    "Sign",
    # Types
    "PublicKey",
    "SecretKey",
    "KeyPair",
    "KeyType",
    "MigrationState",
    "SharedSecret",
    "CipherText",
    "HybridCipherText",
    "SignedMessage",
    "generate_nonce",
    # Exceptions
    "QuantumSafeError",
    "CryptoError",
    "DecapsulationError",
    "VerificationError",
    "KeyGenerationError",
    "InsecureOperationError",
    "SerializationError",
    "KeyParseError",
    "BackendError",
    "BackendNotAvailable",
    "MigrationError",
    "ClassicalKeyDetected",
    "IncompatibleKeyVersion",
    "ConfigurationError",
    "UnsupportedAlgorithm",
]
