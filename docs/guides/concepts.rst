Core concepts
=============

Why hybrid cryptography
-----------------------

ML-KEM and ML-DSA were standardized by NIST in 2024 (FIPS 203/204).
They are believed to be secure against both classical and quantum
computers.  However, novel cryptographic standards have historically
taken years to accumulate confidence — lattice-based schemes are no
exception.

Every major security authority (NIST, CISA, BSI, NCSC) therefore
recommends a *hybrid* approach during the transition period:

- Combine a well-understood classical algorithm (X25519, Ed25519) with a
  PQC algorithm (ML-KEM-768, ML-DSA-65).
- An attacker would need to break **both** simultaneously.
- If ML-KEM is later found to have a weakness, X25519 still protects you.
- If a quantum computer arrives, ML-KEM still protects you.

``quantum-safe`` makes hybrid mode the **default**.  Pure PQC or
pure classical is available but requires an explicit opt-in.

Typed outputs
-------------

Raw bytes are never returned from key operations.  Every output is a
distinct Python type:

.. list-table::
   :widths: 25 75
   :header-rows: 1

   * - Type
     - Purpose
   * - :class:`~quantum_safe.types.KeyPair`
     - Holds ``.public`` and ``.secret`` — pass to all operations
   * - :class:`~quantum_safe.types.PublicKey`
     - Public key with algorithm metadata — safe to distribute
   * - :class:`~quantum_safe.types.SecretKey`
     - Secret key — zeroized on deletion
   * - :class:`~quantum_safe.types.HybridCipherText`
     - KEM output — pass to ``decapsulate()``
   * - :class:`~quantum_safe.types.SharedSecret`
     - KEM result — call ``.derive_key()`` rather than using bytes directly
   * - :class:`~quantum_safe.types.SignedMessage`
     - Self-describing signed message — carries algorithm, context, timestamp

This prevents the entire class of bug where a ``SharedSecret`` is
passed where a ``CipherText`` is expected.

Key metadata
------------

Every key knows its algorithm, version, and migration state:

.. code-block:: python

   pub = kp.public
   print(pub.algorithm)         # "X25519+ML-KEM-768"
   print(pub.migration_state)   # MigrationState.HYBRID_TRANSITION
   print(pub.fingerprint())     # "3a7f1c2e..." (SHA-256 hex, first 16 chars)
   print(pub.qs_version)        # 1

The :class:`~quantum_safe.types.MigrationState` enum tracks where a key
sits in the classical → hybrid → PQC-only migration path:

- ``CLASSICAL_ONLY`` — original classical key, no PQC component
- ``HYBRID_TRANSITION`` — classical + PQC combined key (recommended)
- ``PQC_ONLY`` — pure PQC (future state, after classical deprecation)

Hedged signing
--------------

:class:`~quantum_safe.signatures.HybridSign` and
:class:`~quantum_safe.signatures.core.Sign` default to **hedged mode**:
a 32-byte random prefix is prepended to the message before signing.
This prevents fault-injection attacks that have been demonstrated on
lattice signatures in lab conditions.

Hedged mode means two signings of the same message produce different
signatures — this is intentional and does not affect verification:

.. code-block:: python

   sm1 = signer.sign(b"same", kp.secret)
   sm2 = signer.sign(b"same", kp.secret)
   assert sm1.signature != sm2.signature  # different random prefix
   signer.verify(sm1, kp.public)          # both are valid
   signer.verify(sm2, kp.public)

Disable with ``hedged=False`` only when deterministic signatures are
required (e.g., reproducible test vectors).

Serialization format
--------------------

Keys use a PEM envelope with custom headers that carry metadata:

.. code-block:: text

   -----BEGIN QUANTUM SAFE PUBLIC KEY-----
   qs-version: 1
   qs-algo: X25519+ML-KEM-768
   qs-migration: HYBRID_TRANSITION

   <base64-encoded payload>
   -----END QUANTUM SAFE PUBLIC KEY-----

The payload is a CBOR-encoded struct:

.. code-block:: text

   {
     "algo":  "X25519+ML-KEM-768",
     "pub":   <2-byte-length-prefix + classical bytes + PQC bytes>,
     "v":     1,
   }

Payloads larger than **10 MB** are rejected by the serialization layer before
parsing, guarding against memory-exhaustion via deeply nested or padded
structures.  Payloads with ``v < 1`` are also rejected to prevent
version-rollback attacks on stored key material.

Classical and PQC material is packed as:
``<2-byte big-endian length of classical bytes> + <classical bytes> + <PQC bytes>``

This format is byte-for-byte identical between Python, TypeScript, and
Rust, enabling cross-language interoperability.

Backend architecture
--------------------

The library dispatches to a cryptographic backend for all PQC operations:

- **liboqs** — reference implementation of ML-KEM, ML-DSA, SLH-DSA.
  Ships a pre-built binary for common platforms.
- **rustcrypto** — stub awaiting a PyO3 crate (``is_available()`` returns
  ``False`` until published).

Auto-selection prefers rustcrypto then falls back to liboqs.
Force a specific backend with ``get_kem_backend("liboqs")``.

For classical operations (X25519, Ed25519, AES-GCM, HKDF, X.509) the
library always uses the ``cryptography`` package directly.

HKDF combiner
-------------

The hybrid shared secret uses an HKDF-SHA256 combiner following
``draft-ietf-tls-hybrid-design``:

.. code-block:: text

   combined = HKDF(
       salt     = classical_shared_secret,
       input    = pqc_shared_secret,
       info     = b"quantum-safe-hybrid-kem-v1",
       length   = 32,
   )

This ensures the combined secret is at least as strong as the stronger
of the two components.
