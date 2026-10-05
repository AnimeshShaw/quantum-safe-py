Digital signatures
==================

Choosing an algorithm
---------------------

.. list-table::
   :widths: 30 15 15 40
   :header-rows: 1

   * - Algorithm
     - Type
     - NIST level
     - Notes
   * - ``Ed25519+ML-DSA-65``
     - Hybrid Sign
     - —
     - **Recommended default.** Classical + PQC.
   * - ``ML-DSA-44``
     - Pure PQC
     - 2
     - Smallest ML-DSA.
   * - ``ML-DSA-65``
     - Pure PQC
     - 3
     - Recommended pure-PQC choice.
   * - ``ML-DSA-87``
     - Pure PQC
     - 5
     - Maximum security.
   * - ``SLH-DSA-SHAKE-128s``
     - Pure PQC (hash-based)
     - 1
     - Small signatures, very slow to sign.
   * - ``SLH-DSA-SHAKE-128f``
     - Pure PQC (hash-based)
     - 1
     - Faster signing, larger signatures.

HybridSign
----------

:class:`~quantum_safe.signatures.hybrid.HybridSign` is the high-level
hybrid signer.  It produces a combined Ed25519 + ML-DSA signature.
Both sub-signatures must verify for the overall verification to pass.

.. note::

   Verification is **timing-safe**: both the classical and PQC sub-signatures
   are always verified unconditionally before the combined result is checked.
   Early-return on first failure would create a timing oracle revealing which
   component was invalid — this implementation avoids that.

.. code-block:: python

   from quantum_safe import HybridSign

   signer = HybridSign()               # Ed25519 + ML-DSA-65 by default
   kp     = signer.generate_keypair()

   # Sign a message
   sm = signer.sign(b"document", kp.secret, context=b"myapp-v1")

   # Verify — state the context you expect; raises VerificationError if invalid
   signer.verify(sm, kp.public, context=b"myapp-v1")

   # Include signer fingerprint for key lookup
   sm = signer.sign_with_fingerprint(b"document", kp, context=b"myapp-v1")
   print(sm.signer_fingerprint)        # "3a7f..." (SHA-256 of public key)

Custom algorithm combination:

.. code-block:: python

   signer = HybridSign(classical="Ed25519", pqc="ML-DSA-87")

Sign (pure PQC)
---------------

:class:`~quantum_safe.signatures.core.Sign` uses a single PQC algorithm:

.. code-block:: python

   from quantum_safe import Sign

   signer = Sign("ML-DSA-65")
   kp     = signer.generate_keypair()
   sm     = signer.sign(b"document", kp.secret, context=b"myapp")
   signer.verify(sm, kp.public, context=b"myapp")

Context strings
---------------

The ``context`` parameter provides domain separation between applications
and protocol versions.  It is bound by prefixing ``len(context) || context``
to the signed bytes; it is not FIPS 204's native context input (the ML-DSA
signature uses an empty FIPS 204 context), so other ML-DSA implementations
verify these signatures only if they reproduce the same prefix.  Always use
a unique context string for each signing context:

.. code-block:: python

   # Different contexts — same key, completely isolated
   sm_docs  = signer.sign(b"doc",   kp.secret, context=b"myapp-docs-v1")
   sm_auth  = signer.sign(b"token", kp.secret, context=b"myapp-auth-v1")

   # The verifier states the context it expects
   signer.verify(sm_docs, kp.public, context=b"myapp-docs-v1")   # OK
   signer.verify(sm_auth, kp.public, context=b"myapp-docs-v1")   # VerificationError

Always pass ``context=`` to ``verify()``.  The context stored in a
``SignedMessage`` comes from whoever supplied the message, so a verifier that
takes it from there would accept a signature made for one purpose as valid for
another.  Calling ``verify()`` without ``context=`` still works in this
release but emits a ``DeprecationWarning``; it will be required (default
``b""``) in the next minor release.

Standard FIPS 204 signatures (interoperating with other libraries)
-------------------------------------------------------------------

``sign()``, the default hedging and the ``-v2`` format are this library's own
constructions: a signature from them is not a plain ``ML-DSA.Sign(sk, message, ctx)``
and another ML-DSA implementation cannot verify it from the message and context alone.
When the other side is a standard FIPS 204 implementation, use the raw pair, which
passes your message and context to ML-DSA unchanged and returns only the signature:

.. code-block:: python

   from quantum_safe import Sign

   signer = Sign("ML-DSA-65")
   kp = signer.generate_keypair()

   sig = signer.sign_raw(b"release 1.2.3", kp.secret, context=b"myapp-release")
   # sig is a bare FIPS 204 ML-DSA-65 signature (3309 bytes). Any FIPS 204 library
   # verifies it with the same message, context and public key.

   signer.verify_raw(b"release 1.2.3", sig, kp.public, context=b"myapp-release")

``verify_raw()`` likewise verifies signatures made elsewhere (``ML-DSA.Sign`` with
FIPS 204's context string). The randomness is FIPS 204's own hedged ``rnd`` input,
generated inside liboqs, and the message is never modified. There is no hedging
prefix, no metadata and no fingerprint, so you carry the algorithm, context and
public key yourself. Before 0.3.2, ``verify_raw()`` verified the library's
length-prefixed construction and so rejected every standard signature.

Hedged mode
-----------

Both :class:`~quantum_safe.signatures.hybrid.HybridSign` and
:class:`~quantum_safe.signatures.core.Sign` default to **hedged mode**:
a 32-byte random prefix is prepended before signing.

This prevents fault-injection attacks demonstrated on lattice signatures.
Two signings of the same message will produce different signatures, but
both verify correctly:

.. code-block:: python

   sm1 = signer.sign(b"same message", kp.secret)
   sm2 = signer.sign(b"same message", kp.secret)
   assert sm1.signature != sm2.signature   # different random prefix
   signer.verify(sm1, kp.public, context=b"")   # both valid
   signer.verify(sm2, kp.public, context=b"")

Disable with ``hedged=False`` only when you need deterministic signatures:

.. code-block:: python

   signer = HybridSign(hedged=False)
   sm1 = signer.sign(b"same", kp.secret)
   sm2 = signer.sign(b"same", kp.secret)
   assert sm1.signature == sm2.signature   # deterministic

.. important::

   **A verifier accepts only signatures made in its own hedging mode.**  The
   prefix length is not covered by the signature, so the verifier does not
   read it from the signature: a hedged verifier (the default) requires a
   32-byte prefix, and a ``hedged=False`` verifier requires none.  Build the
   verifier with the same ``hedged`` value as the signer, and use one mode per
   key.  The same applies to ``JWTVerifier(..., hedged=)`` and
   ``HybridCertificateBuilder.verify_cosig(..., hedged=)``.

   .. code-block:: python

      signer = HybridSign(hedged=False)
      sm = signer.sign(b"msg", kp.secret)
      HybridSign(hedged=False).verify(sm, kp.public, context=b"")   # OK
      HybridSign().verify(sm, kp.public, context=b"")               # VerificationError

Signature format v2 (``-v2``)
-----------------------------

The default signatures (above) sign ``len(context) || context || prefix ||
message`` under an empty FIPS 204 context, with an optional 32-byte hedging
prefix.  The ``-v2`` format is a cleaner construction, byte-compatible with
quantum-safe-ts, selected by an identifier suffix:

.. code-block:: python

   from quantum_safe import HybridSign
   from quantum_safe.signatures import Sign

   signer = Sign("ML-DSA-65-v2")                    # pure ML-DSA
   hybrid = HybridSign("Ed25519", "ML-DSA-65-v2")   # Ed25519+ML-DSA-65-v2
   kp = hybrid.generate_keypair()
   sm = hybrid.sign(b"document", kp.secret, context=b"myapp-v1")
   hybrid.verify(sm, kp.public, context=b"myapp-v1")

Supported identifiers: ``ML-DSA-44/65/87-v2``, ``Ed25519+ML-DSA-44/65/87-v2``
and ``P-256+ML-DSA-44/65-v2`` (no SLH-DSA).  What differs:

- **No prefix and no prefix length** in the signature, so there is no
  message/prefix boundary to move.  A hybrid signature is exactly
  ``classical signature (64 bytes) || ML-DSA signature``.
- The ML-DSA half is **plain FIPS 204** ``ML-DSA.Sign`` with the *native*
  context ``quantum-safe-sig-v2`` over
  ``M2 = u8(len(algo)) || algo || u8(len(ctx)) || ctx || message``, so any
  FIPS 204 library can verify it given ``M2``.  The algorithm identifier and
  your context are inside the signed bytes.
- The classical half signs ``"quantum-safe-sig-v2" || 0x00 || M2`` (Ed25519, or
  ECDSA P-256/SHA-256 as raw ``r || s``, low-S only).
- ML-DSA signing is always hedged inside ML-DSA, so ``hedged=False`` does not
  exist for ``-v2``.
- Keys carry the ``-v2`` tag, but the tag is advisory: v1 and v2 keys have
  identical bytes.  **Never use the same key in both formats.**

``-v2`` is not the default in this release; the default will move to it in the
next minor release.  Versions of quantum-safe before this one cannot read
``-v2`` signatures.

SignedMessage
-------------

:class:`~quantum_safe.types.SignedMessage` is self-describing — it carries
the original message, signature, algorithm, and context:

.. code-block:: python

   print(sm.algorithm)   # "Ed25519+ML-DSA-65"
   print(sm.context)     # b"myapp-v1"

   # Serialize for storage or transport
   cbor_bytes = sm.to_cbor()
   sm2 = SignedMessage.from_cbor(cbor_bytes)
   signer.verify(sm2, kp.public, context=b"myapp-v1")   # round-trips perfectly

``SignedMessage.from_cbor`` checks that it received a map of the expected
version with correctly typed fields and raises
:class:`~quantum_safe.exceptions.KeyParseError` otherwise.

HybridSignature
---------------

A :class:`~quantum_safe.types.HybridSignature` exposes the individual
sub-signatures for hybrid messages:

.. code-block:: python

   from quantum_safe.types import HybridSignature

   # sm.signature is prefix_len (1 byte) || prefix || HybridSignature payload
   prefix_len = sm.signature[0]
   hybrid_sig = HybridSignature.from_bytes(sm.signature[1 + prefix_len :])
   print(len(hybrid_sig.classical_sig))    # Ed25519: 64 bytes
   print(len(hybrid_sig.pqc_sig))          # ML-DSA-65: 3309 bytes (FIPS 204)

The payload must be exactly the four documented entries (``classical_sig``,
``pqc_sig``, ``classical_algo``, ``pqc_algo``) with no duplicates or trailing
bytes, and ``HybridSign.verify`` also requires the algorithm names to match
its own components.
