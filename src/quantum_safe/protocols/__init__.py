"""
quantum_safe.protocols
~~~~~~~~~~~~~~~~~~~~~~~

Protocol-level helpers that connect PQC primitives to real-world formats.

This is the layer most production applications actually use. Instead of
calling HybridKEM.encapsulate() and then hand-rolling an authenticated
encryption wrapper, you call Envelope.seal() and get a self-describing,
versioned, authenticated ciphertext blob that works across languages.

Submodules
----------
envelope  Authenticated encryption envelope (AEAD + KEM-wrapped key)
jwt       PQC-aware JWT sign/verify (ML-DSA algorithm identifiers)
tls       TLS hybrid key exchange configuration helpers
x509      Hybrid X.509 certificate generation

Typical usage::

    # Seal a secret to a recipient's public key
    from quantum_safe.protocols import Envelope
    sealed = Envelope.seal(plaintext, recipient_public_key)
    plaintext = Envelope.open(sealed, recipient_keypair.secret)

    # Sign a JWT with ML-DSA
    from quantum_safe.protocols import JWTSigner
    token  = JWTSigner(keypair).sign({"sub": "user123"})
    claims = JWTSigner.verify(token, public_key)

    # Configure TLS hybrid key exchange
    from quantum_safe.protocols import tls
    ssl_ctx = tls.configure_hybrid_context(ssl.create_default_context())
"""

from quantum_safe.protocols.envelope import Envelope, SealedMessage
from quantum_safe.protocols.jwt import JWTSigner, JWTVerifier
from quantum_safe.protocols.tls import HybridTLSConfig, configure_hybrid_context
from quantum_safe.protocols.x509 import HybridCertificateBuilder

__all__ = [
    "Envelope",
    "SealedMessage",
    "JWTSigner",
    "JWTVerifier",
    "HybridTLSConfig",
    "configure_hybrid_context",
    "HybridCertificateBuilder",
]
