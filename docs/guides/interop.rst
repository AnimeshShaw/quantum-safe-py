Interoperating with quantum-safe-ts and other ecosystems
========================================================

quantum-safe has a TypeScript counterpart,
`quantum-safe-ts <https://github.com/AnimeshShaw/quantum-safe-ts>`_, for Node.js,
Deno, Bun, browsers and edge runtimes. The two libraries are **byte-compatible**: data
written by one opens in the other, in both directions. This is checked against the real
Python library (liboqs backend) in the TypeScript CI, and against data written by the
TypeScript package in this repository's ``tests/interop``, not against a re-implementation.

.. contents:: On this page
   :local:
   :depth: 2

What is compatible
------------------

.. list-table::
   :header-rows: 1
   :widths: 50 25 25

   * - Data
     - With 0.3.0
     - With 0.3.1+
   * - Hybrid KEM keys, ciphertexts, shared secrets
     - Yes
     - Yes
   * - Envelopes (v1, hybrid keys)
     - Yes
     - Yes
   * - Envelopes v2 (pure ML-KEM-1024, HKDF-SHA-384)
     - No
     - Yes
   * - Keys: CBOR, PEM, public JWK, fingerprints, bundles
     - Yes
     - Yes
   * - Signatures and ``SignedMessage`` (default format; ML-DSA, hybrids, shared SLH-DSA sets)
     - Yes
     - Yes
   * - Signature format ``-v2`` (all eight identifiers)
     - No
     - Yes
   * - Quantum-safe JWTs (``JWTSigner``)
     - Yes
     - Yes
   * - RFC 9964 ``StandardJwt`` tokens and public ``AKP`` JWKs
     - No
     - Yes
   * - Migration ``Upgrader`` output and store layout
     - Yes (through converters for the store)
     - Yes

Not shared: X-Wing, streaming encryption and nine of the twelve SLH-DSA parameter sets
(TypeScript only); LMS *signing* and the hybrid X.509 builder (Python only); RFC 9964
**private** JWKs, whose ``priv`` member is a seed that liboqs cannot turn back into a key
pair (so Python can verify a TypeScript-made token but cannot sign with a TypeScript-made
private JWK).

Settings that must match
------------------------

The verifiers state what they expect, in both libraries:

.. list-table::
   :header-rows: 1
   :widths: 25 37 38

   * - What
     - quantum-safe-ts
     - quantum-safe (Python)
   * - Signature context
     - ``verify(signed, pub, { expectedContext })``
     - ``verify(sm, pub, context=...)``
   * - Hedging mode (default format)
     - ``new Sign(algo, { hedged })``
     - ``Sign(algo, hedged=...)``, ``JWTVerifier(..., hedged=)``
   * - Envelope AAD
     - ``Envelope.open(sealed, sk, { expectedAad })``
     - ``Envelope.open(sealed, sk, expected_aad=...)``

A signature made with ``hedged=False`` verifies only on a verifier built with
``hedged=False``: the prefix length is not covered by the signature, so each verifier
requires the one its own mode produces. The ``-v2`` format has no hedging mode.

Example: Python signs, Node.js verifies
---------------------------------------

Python:

.. code-block:: python

   import pathlib
   import tempfile

   from quantum_safe import HybridSign

   signer = HybridSign("Ed25519", "ML-DSA-65-v2")
   keys = signer.generate_keypair()
   signed = signer.sign(b"deploy build 4711", keys.secret, context=b"deploys-v1")

   out = pathlib.Path(tempfile.mkdtemp())
   (out / "signed.cbor").write_bytes(signed.to_cbor())
   (out / "public.cbor").write_bytes(keys.public.to_cbor())
   print("wrote", sorted(p.name for p in out.iterdir()))

Node.js (quantum-safe-ts):

.. code-block:: javascript

   import { readFileSync } from 'node:fs';
   import { HybridSign, SignedMessage, PublicKey, utf8 } from 'quantum-safe-ts';

   const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
   const signed = SignedMessage.fromBytes(readFileSync('signed.cbor'));
   const pub = PublicKey.fromCbor(readFileSync('public.cbor'));
   signer.verify(signed, pub, { expectedContext: utf8('deploys-v1') });   // throws if invalid

Example: Node.js encrypts, Python decrypts
------------------------------------------

Node.js:

.. code-block:: javascript

   import { writeFileSync } from 'node:fs';
   import { HybridKEM, Envelope, utf8 } from 'quantum-safe-ts';

   const pair = new HybridKEM().generateKeyPair();
   const sealed = Envelope.seal(utf8('hello from node'), pair.publicKey, { aad: utf8('demo') });
   writeFileSync('sealed.bin', sealed.toBytes());
   writeFileSync('secret.cbor', pair.secretKey.toCbor());

Python:

.. code-block:: python

   from quantum_safe import HybridKEM, SecretKey
   from quantum_safe.protocols import Envelope, SealedMessage

   # In real use these bytes come from sealed.bin and secret.cbor; here we make a pair.
   kp = HybridKEM().generate_keypair()
   sealed_bytes = Envelope.seal(b"hello from node", kp.public, aad=b"demo").to_bytes()
   secret = SecretKey.from_cbor(kp.secret.to_cbor())

   plaintext = Envelope.open(SealedMessage.from_bytes(sealed_bytes), secret, expected_aad=b"demo")
   assert plaintext == b"hello from node"

Compatible is not the same as standard
--------------------------------------

Matching quantum-safe-ts means matching quantum-safe's own constructions: an HKDF-SHA-256
hybrid key combiner, and an ML-DSA "context" that is a message prefix signed under an empty
FIPS 204 context. They are sound engineering choices but they are **not** X-Wing, **not** the
TLS ``X25519MLKEM768`` group and **not** FIPS 204's native context, and they have not been
reviewed against NIST SP 800-227's key-combiner guidance.

- Use the **defaults** when both ends are quantum-safe or quantum-safe-ts.
- Use ``Sign.sign_raw()`` / ``Sign.verify_raw()`` when the other side is a standard FIPS 204
  ML-DSA implementation: they pass your message and context natively and exchange the bare
  signature (new in 0.3.2). Use ``StandardJwt`` when a JOSE library must read the token.
  ``-v2`` is for quantum-safe and quantum-safe-ts: a standard library could verify it only
  by rebuilding the wrapped message ``M2``.
- A third-party X-Wing or TLS-hybrid implementation cannot read quantum-safe envelopes.

Staying in step
---------------

Both libraries run each other's vectors in CI. If you vendor both, upgrade them together:
the ``-v2`` formats and envelope v2 need quantum-safe 0.3.1 or later and quantum-safe-ts
0.1.0 or later.
