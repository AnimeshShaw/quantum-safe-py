Protocol helpers
================

Envelope
--------

See :doc:`kem` for the full Envelope API.

COSE_Sign1 (CBOR signatures, RFC 9964)
--------------------------------------

:mod:`quantum_safe.protocols.cose` signs and verifies **COSE_Sign1** messages with ML-DSA, the
CBOR counterpart of a compact JWS (CBOR Web Tokens, WebAuthn, attestation formats). It is the COSE
half of RFC 9964; :class:`~quantum_safe.protocols.standard_jwt.StandardJwt` is the JOSE half. The
signed bytes are ``["Signature1", protected, external_aad, payload]`` under plain FIPS 204 with the
empty context, so any compliant COSE library verifies the result.

.. code-block:: python

   from quantum_safe.protocols.cose import sign1, verify_sign1
   from quantum_safe.signatures import Sign

   kp = Sign("ML-DSA-65").generate_keypair()
   message = sign1(b"hello", kp.secret, kid=b"key-1", external_aad=b"myapp-v1")
   payload = verify_sign1(message, kp.public, external_aad=b"myapp-v1")
   assert payload == b"hello"

- Algorithms: ML-DSA-44 = -48, ML-DSA-65 = -49, ML-DSA-87 = -50.
- ``detached=True`` leaves the payload out (``verify_sign1(..., detached_payload=...)``);
  ``tagged=False`` omits CBOR tag 18.
- ``encode_cose_key`` / ``decode_cose_key`` read and write AKP public keys.
- Verification is strict: the algorithm must be protected and known, ``crit`` is refused, CBOR must
  be minimal with unique labels and no trailing bytes.
- Checked against RFC 9964 Appendix A (all three levels) and against quantum-safe-ts in both
  directions.

Streaming envelope (large or incremental data)
----------------------------------------------

An :class:`~quantum_safe.protocols.envelope.Envelope` encrypts one buffer. For files, uploads and
pipes that do not fit in memory or arrive in pieces, the streaming envelope (format v3) encrypts
with **one** KEM encapsulation per stream and AES-256-GCM per chunk, using the STREAM construction:
chunks cannot be reordered, dropped, duplicated or truncated without detection. It is
byte-compatible with quantum-safe-ts (``sealStream`` / ``openStream``).

.. code-block:: python

   from quantum_safe import HybridKEM
   from quantum_safe.protocols.stream import open_stream, seal_stream

   kp = HybridKEM().generate_keypair()

   with open("report.bin", "rb") as src, open("report.bin.qss", "wb") as dst:
       for piece in seal_stream(kp.public, src, aad=b"report-2026", chunk_size=64 * 1024):
           dst.write(piece)

   with open("report.bin.qss", "rb") as enc, open("report.out", "wb") as out:
       for chunk in open_stream(kp.secret, enc, expected_aad=b"report-2026"):
           out.write(chunk)

- Suites: any hybrid (for example ``X25519+ML-KEM-768``), X-Wing, and pure ``ML-KEM-1024``
  (key derivation with HKDF-SHA-384, the CNSA 2.0 profile).
- ``chunk_size`` is 1,024 to 16,777,216 bytes (default 65,536). Every chunk but the last is exactly
  that size; the last may be shorter or empty.
- ``aad`` is bound to every chunk and is **not stored** in the stream: the opener must pass the same
  ``expected_aad``. A different value fails authentication.
- ``open_stream`` raises on the first bad chunk (``cryptography.exceptions.InvalidTag`` for
  authentication, ``ValueError`` for a malformed prelude or frame); a truncated or extended stream
  never completes silently.
- Like envelopes, a stream is anonymous: it does not say who sent it. Sign the data separately when
  that matters.
- Low level: :class:`~quantum_safe.protocols.stream.StreamSealer` and
  :class:`~quantum_safe.protocols.stream.StreamOpener` seal and open chunk by chunk;
  ``seal_bytes`` / ``open_bytes`` handle a whole buffer.

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

Private JWKs
~~~~~~~~~~~~

RFC 9964's private JWK member ``priv`` is the 32-byte ML-DSA *seed*. liboqs cannot derive a key
from a seed, so private JWKs use the optional ``cryptography`` backend
(``pip install 'quantum-safe-py[pyca]'``):

.. code-block:: python

   from quantum_safe.protocols.standard_jwt import StandardJwt

   private = StandardJwt.generate_private_jwk("ML-DSA-65", kid="k1")   # a secret: priv is the seed
   public = StandardJwt.public_jwk(private)                              # share this one
   token = StandardJwt.sign({"sub": "alice"}, private, issuer="https://issuer.example")
   claims = StandardJwt.verify(token, public, issuer="https://issuer.example")

``StandardJwt.keypair_from_private_jwk`` and ``StandardJwt.private_jwk`` convert between a JWK and
a ``KeyPair``. A private JWK made by quantum-safe-ts signs here and the reverse; RFC 9964's
all-zero example key derives the RFC's public key (checked in the test suite).

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
