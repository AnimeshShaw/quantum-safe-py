Protocols (``quantum_safe.protocols``)
=======================================

Higher-level protocol helpers built on top of the KEM and signature primitives.

Envelope
--------

.. autoclass:: quantum_safe.protocols.envelope.Envelope
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.protocols.envelope.SealedMessage
   :members:
   :show-inheritance:

JWT
---

.. autoclass:: quantum_safe.protocols.jwt.JWTSigner
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.protocols.jwt.JWTVerifier
   :members:
   :show-inheritance:

TLS
---

.. autoclass:: quantum_safe.protocols.tls.HybridTLSConfig
   :members:
   :show-inheritance:

.. autofunction:: quantum_safe.protocols.tls.configure_hybrid_context

X.509
-----

.. autoclass:: quantum_safe.protocols.x509.HybridCertificateBuilder
   :members:
   :show-inheritance:

.. autofunction:: quantum_safe.protocols.x509.generate_classical_keypair_for_cert
