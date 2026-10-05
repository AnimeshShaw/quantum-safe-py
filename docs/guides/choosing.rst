Choosing what to use
====================

quantum-safe offers several ways to do each job. This page tells you which to pick
for a given situation, and, just as important, when **not** to use something. Every
recommendation here is the one the maintainers would give you in person.

.. contents:: On this page
   :local:
   :depth: 2

Start here: the decision in one table
-------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - You want to...
     - Use
     - Do not use
   * - Encrypt data to someone's public key
     - ``Envelope.seal`` with a hybrid key (``HybridKEM``)
     - Raw ``HybridKEM.encapsulate`` plus your own AES code
   * - Encrypt data under a CNSA 2.0 profile
     - ``Envelope.seal`` with a pure ``ML-KEM-1024`` key (envelope v2)
     - A hybrid key (reported ``PARTIAL``); ``ML-KEM-768``
   * - Sign data that only quantum-safe libraries verify
     - ``HybridSign`` (default) with ``context=``
     - A signature without a context
   * - Sign data that other ecosystems must verify
     - ``Sign("ML-DSA-65-v2")`` or ``HybridSign("Ed25519", "ML-DSA-65-v2")``
     - The default format (a generic ML-DSA library cannot verify it)
   * - Issue login or API tokens verified only by your services
     - ``JWTSigner`` / ``JWTVerifier``
     - Hand-built tokens
   * - Issue tokens that other JOSE libraries must verify
     - ``StandardJwt`` (RFC 9964)
     - ``JWTSigner`` (only quantum-safe can verify it)
   * - Move existing keys to post-quantum safely
     - ``Upgrader`` plus ``MigrationStateManager``
     - Swapping keys atomically in one deploy
   * - Find classical cryptography in a codebase
     - ``qs-audit scan`` in CI
     - Grep
   * - Check a configuration against CNSA 2.0 parameters
     - ``cnsa2.report`` and ``cnsa2.pqc_kem()`` / ``pqc_sign()``
     - ``cnsa2.hybrid_kem()`` as a compliance claim

The same decision as code:

.. code-block:: python

   from quantum_safe import HybridKEM, HybridSign
   from quantum_safe.compliance import cnsa2
   from quantum_safe.protocols import Envelope

   def encryption_keys(cnsa2_profile: bool = False):
       """Pure ML-KEM-1024 (envelope v2) under CNSA 2.0, otherwise the hybrid default."""
       return cnsa2.pqc_kem().generate_keypair() if cnsa2_profile else HybridKEM().generate_keypair()

   def signer(verifiers_are_all_0_3_1_or_later: bool = False):
       """-v2 when every verifier can read it, the default format otherwise."""
       return HybridSign("Ed25519", "ML-DSA-65-v2") if verifiers_are_all_0_3_1_or_later else HybridSign()

   for profile in (False, True):
       keys = encryption_keys(profile)
       sealed = Envelope.seal(b"data", keys.public)
       assert sealed.version == (2 if profile else 1)         # chosen by the key, not by you

   for modern in (False, True):
       s = signer(modern)
       kp = s.generate_keypair()
       sm = s.sign(b"data", kp.secret, context=b"example-v1")
       s.verify(sm, kp.public, context=b"example-v1")

Key exchange and encryption
---------------------------

Hybrid or pure?
~~~~~~~~~~~~~~~

**Use hybrid (the default)** for new deployments during the transition. A hybrid
(``X25519+ML-KEM-768``) stays secure if *either* component holds, which is the position
NIST, CISA, BSI and NCSC take for the transition period. You pay a few tens of
microseconds and 34 extra bytes of ciphertext (1122 bytes instead of 1088 for ML-KEM-768) and 34 of public key.

**Use pure ML-KEM** when a standard or a contract requires it. CNSA 2.0 is the main
case: NSA accepts standalone ``ML-KEM-1024`` and says hybrids are not required (see
:doc:`compliance`).

**Do not use** pure ML-KEM merely to save bytes. If you are bandwidth-constrained, measure
first (see :doc:`benchmarks`); the hybrid overhead is small next to a network round trip.

Which security level?
~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Parameter set
     - NIST level
     - Pick it when
   * - ``ML-KEM-512``
     - 1
     - Almost never. Only when you must interoperate with something that fixes it.
   * - ``ML-KEM-768``
     - 3
     - The default. Right for most applications.
   * - ``ML-KEM-1024``
     - 5
     - CNSA 2.0, or long-lived secrets where you want margin.

Envelope v1 or v2?
~~~~~~~~~~~~~~~~~~

Both are authenticated encryption (KEM, HKDF, AES-256-GCM).

- **v1** takes a hybrid key and derives the AES key with HKDF-SHA-256.
- **v2** takes a pure ``ML-KEM-1024`` key and derives with HKDF-SHA-384, which is what
  CNSA 2.0 asks of key derivation.

You do not choose a version: ``Envelope.seal`` picks it from the key you give it.
quantum-safe-ts reads and writes the same bytes for both.

Signatures
----------

Hybrid or pure?
~~~~~~~~~~~~~~~

**Use hybrid** (``HybridSign``, Ed25519 + ML-DSA-65) while classical signatures still carry
trust in your ecosystem. Both signatures must verify.

**Use pure ML-DSA** (``Sign``) for CNSA 2.0 (``ML-DSA-87``) or when signature size matters
more than belt-and-braces. Measured sizes for ML-DSA-65: the raw signature is 3309 bytes; a
default-format ``SignedMessage`` signature is 3342 bytes (hedging prefix) and 3476 for the
hybrid; with ``-v2`` it is 3309 (pure) and 3373 (hybrid).

Default format or ``-v2``?
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 37 38

   * -
     - Default (v1)
     - ``-v2``
   * - Who can verify
     - quantum-safe (Python 0.2.1+ and TypeScript)
     - quantum-safe 0.3.1+ and quantum-safe-ts; the ML-DSA half is plain FIPS 204, so any
       FIPS 204 library can verify it given the bytes
   * - Structure
     - Hedging prefix and an unsigned length byte, CBOR wrapper
     - No prefix; fixed-length blob
   * - Hedging
     - Your choice (``hedged=``); a verifier must match
     - Always hedged inside ML-DSA; nothing to match
   * - Algorithm and context signed
     - Context yes; algorithm no
     - Both, for both halves
   * - Available for
     - Every ML-DSA suite, hybrids, SLH-DSA
     - ML-DSA-44/65/87, Ed25519 and P-256 hybrids (no SLH-DSA)

**Recommendation.** For *new* signatures where every verifier you control runs 0.3.1 or
later, use ``-v2``. Keep the default while an older verifier is in the loop. The default
will move to ``-v2`` in a later minor release.

.. warning::

   Never use the same key material in both formats. The ML-DSA halves are separated by
   FIPS 204's context, but the classical halves are not.

Always give signatures a context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A context such as ``b"myapp-v1-release"`` ties a signature to one purpose. Pass the *same*
value to ``sign(context=...)`` and ``verify(context=...)``. A signature made for one purpose
then cannot be replayed for another.

Tokens (JWT)
------------

- **``JWTSigner``**: tokens verifiable only by quantum-safe (Python or TypeScript). Supports
  hybrid keys. Pick it when every verifier is yours.
- **``StandardJwt``** (RFC 9964): tokens any JOSE library can verify, pure ML-DSA only. Pick it
  when other ecosystems, gateways or third parties verify your tokens.

**Do not** put a ``JWTSigner`` token in front of a generic JWT gateway: it will be rejected
even with ``hedged=False``.

Migration
---------

Use ``Upgrader`` to produce a hybrid key that *contains* the classical key, and
``MigrationStateManager`` to track each key through
``CLASSICAL_ONLY → HYBRID_TRANSITION → PQC_PREFERRED → PQC_ONLY``.

.. note::

   An upgraded hybrid key is **not** backward compatible: classical-only software cannot
   parse it. Keep publishing the original classical key to such clients during the
   transition.

Give the manager a store with ``compare_and_set`` whenever more than one process shares it
(see :doc:`migration`).

Where quantum-safe is not the right tool
-----------------------------------------

Being straightforward about limits is part of being safe to adopt:

- **You need a validated module.** quantum-safe is not FIPS 140-3 validated and is not a
  CAVP or CMVP result. Its conformance evidence (ACVP known-answer tests) is evidence, not
  validation. If a procurement rule requires a certificate, use a validated module.
- **You need constant-time guarantees.** Python gives none. liboqs is the constant-time
  layer; this library adds Python code around it. See :doc:`security`.
- **You need hardware or embedded targets.** This is a Python library. Use liboqs,
  mlkem-native or a vendor SDK there.
- **You need stateful hash-based signing at scale.** LMS is available as an optional extra
  with a write-ahead state store, but stateful signing is hard to operate safely; read the
  ``quantum_safe.signatures.stateful`` documentation before relying on it.
- **You need browser or edge runtimes.** Use quantum-safe-ts, which is byte-compatible.
