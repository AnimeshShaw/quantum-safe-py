Protocol helpers
================

Envelope
--------

See :doc:`kem` for the full Envelope API.

JWT (PQC-aware)
---------------

:class:`~quantum_safe.protocols.jwt.JWTSigner` and
:class:`~quantum_safe.protocols.jwt.JWTVerifier` produce and verify
JSON Web Tokens signed with a hybrid PQC key.

The algorithm identifier follows the ``draft-ietf-jose-pqc-signatures``
naming scheme.

.. code-block:: python

   from quantum_safe import HybridSign
   from quantum_safe.protocols.jwt import JWTSigner, JWTVerifier

   kp = HybridSign().generate_keypair()

   # Signing
   signer = JWTSigner(kp, issuer="auth.myapp.com")
   token  = signer.sign({"sub": "user123", "role": "admin"})

   # Verification
   verifier = JWTVerifier(kp.public, issuer="auth.myapp.com")
   claims   = verifier.verify(token)
   # Raises VerificationError on invalid, expired, or wrong issuer

   # Custom expiry (default: 1 hour)
   token = signer.sign({"sub": "user123"}, expires_in=3600)

``JWTVerifier`` verifies with its own ``context`` (default ``b"jwt"``), never
one read from the token.  Tokens from a ``JWTSigner(..., hedged=False)``
verify only with ``JWTVerifier(..., hedged=False)``.

.. important::

   **These tokens verify only with quantum-safe** (or a byte-compatible
   implementation such as quantum-safe-ts), in either hedging mode.  They are
   not RFC 9964 ML-DSA JWS: the signature field is this library's signature
   blob, and what is signed is ``len(context) || context || prefix ||
   header.payload``.  A standard JOSE library will reject them, including with
   ``hedged=False``.  Use ``StandardJwt`` (below) for tokens any JOSE library
   can verify.

Standard (RFC 9964) ML-DSA JWTs
-------------------------------

:class:`~quantum_safe.protocols.standard_jwt.StandardJwt` produces and verifies
tokens that **any compliant JOSE implementation can verify**: the header is
``{"alg": "ML-DSA-65", "typ": "JWT"}`` and the signature is a raw FIPS 204
ML-DSA signature over ``header.payload`` with an empty context.  The public key
is an ``AKP`` JWK.  quantum-safe-ts implements the same format, so the two
libraries verify each other's tokens.

.. code-block:: python

   from quantum_safe.protocols import StandardJwt

   kp    = StandardJwt.generate_keypair("ML-DSA-65")     # ML-DSA-44 / 65 / 87
   token = StandardJwt.sign({"sub": "user123"}, kp.secret, issuer="auth.myapp.com")

   jwk    = StandardJwt.public_jwk(kp.public, kid="2026-10")   # publish this
   claims = StandardJwt.verify(token, jwk, issuer="auth.myapp.com", require_exp=True)

Verification is strict: the key's algorithm must equal the header ``alg``,
``crit`` headers are rejected, and the signature must be canonical unpadded
base64url.  Only the pure ML-DSA algorithms are defined by the RFC; hybrids are
not.

.. note::

   RFC 9964's private JWK member ``priv`` is the 32-byte ML-DSA *seed*.  The
   liboqs backend cannot derive a key pair from a seed, so this class neither
   writes nor reads private AKP JWKs: keys are ordinary quantum-safe key pairs,
   and a private JWK made elsewhere (for example by quantum-safe-ts) cannot be
   used to sign here.  Its public JWK verifies as usual.

TLS hybrid key exchange
-----------------------

:func:`~quantum_safe.protocols.tls.configure_hybrid_context` patches
an :class:`ssl.SSLContext` to prefer hybrid key exchange groups when
the OQS-patched OpenSSL is available.  It degrades gracefully to
standard X25519 if the OQS provider is not present.

.. code-block:: python

   import ssl
   from quantum_safe.protocols.tls import configure_hybrid_context, HybridTLSConfig

   ctx = ssl.create_default_context()
   configure_hybrid_context(ctx, HybridTLSConfig(
       kem_algorithm="X25519+ML-KEM-768",
       fallback_classical=True,      # include X25519 as fallback group
   ))

   # Use ctx with any ssl / aiohttp / httpx / requests call
   with ssl.wrap_socket(sock, ssl_context=ctx) as tls_sock:
       ...

.. note::

   Full hybrid TLS requires an OQS-patched OpenSSL.  See the
   `Open Quantum Safe project <https://openquantumsafe.org/>`_ for
   pre-built binaries.  Without it, the library falls back to standard
   X25519.

Hybrid X.509 certificates
--------------------------

:class:`~quantum_safe.protocols.x509.HybridCertificateBuilder` builds
hybrid X.509 certificates that carry a classical signature (Ed25519 or
ECDSA) plus a PQC co-signature stored in a non-critical extension.

Classical verifiers ignore the unknown extension.
Post-quantum-aware verifiers check both.

.. code-block:: python

   from quantum_safe import HybridSign
   from quantum_safe.protocols.x509 import (
       HybridCertificateBuilder,
       generate_classical_keypair_for_cert,
   )

   classical_key = generate_classical_keypair_for_cert("Ed25519")
   hybrid_kp     = HybridSign().generate_keypair()

   builder = HybridCertificateBuilder(
       subject_cn="service.internal",
       classical_private_key=classical_key,
       pqc_keypair=hybrid_kp,
       dns_names=["api.service.internal", "service.internal"],
       ip_addresses=["10.0.0.1"],
       organization="My Org",
       country="US",
       validity_days=365,
   )
   cert_pem, cosig_bundle = builder.build()

Verifying the co-signature:

.. code-block:: python

   from quantum_safe.protocols.x509 import HybridCertificateBuilder

   HybridCertificateBuilder.verify_cosig(
       cert_pem,
       cosig_bundle,
       hybrid_kp.public,             # raises VerificationError if invalid
   )

``verify_cosig`` requires the fixed co-signature context rather than reading
it from the bundle.  If ``build(signer=...)`` was given a ``hedged=False``
signer, verify with ``verify_cosig(..., hedged=False)``.

Issuing from a CA certificate:

.. code-block:: python

   from cryptography import x509 as cx509
   from cryptography.hazmat.backends import default_backend

   ca_classical_key = generate_classical_keypair_for_cert("Ed25519")
   ca_hybrid_kp     = HybridSign().generate_keypair()

   # Build the CA cert first (is_ca=True)
   ca_builder = HybridCertificateBuilder(
       subject_cn="My Root CA",
       classical_private_key=ca_classical_key,
       pqc_keypair=ca_hybrid_kp,
       is_ca=True,
       validity_days=3650,
   )
   ca_pem, _ = ca_builder.build()
   ca_cert = cx509.load_pem_x509_certificate(ca_pem, default_backend())

   # Issue an end-entity certificate signed by the CA
   ee_classical_key = generate_classical_keypair_for_cert("Ed25519")
   ee_hybrid_kp     = HybridSign().generate_keypair()

   ee_builder = HybridCertificateBuilder(
       subject_cn="service.internal",
       classical_private_key=ee_classical_key,
       pqc_keypair=ee_hybrid_kp,
       issuer_cert=ca_cert,
       issuer_key=ca_classical_key,
       dns_names=["service.internal"],
       validity_days=365,
   )
   cert_pem, cosig_bundle = ee_builder.build()

.. warning::

   The PQC co-signature extension OID ``1.3.6.1.4.1.99999.1`` is a
   placeholder.  Register a private enterprise OID before using in
   production.
