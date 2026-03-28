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

.. code-block:: python

   from quantum_safe import HybridSign

   signer = HybridSign()               # Ed25519 + ML-DSA-65 by default
   kp     = signer.generate_keypair()

   # Sign a message
   sm = signer.sign(b"document", kp.secret, context=b"myapp-v1")

   # Verify — raises VerificationError if invalid
   signer.verify(sm, kp.public)

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
   signer.verify(sm, kp.public)

Context strings
---------------

The ``context`` parameter provides domain separation between applications
and protocol versions, following FIPS 204 §5.2.  Always use a unique
context string for each signing context:

.. code-block:: python

   # Different contexts — same key, completely isolated
   sm_docs  = signer.sign(b"doc",   kp.secret, context=b"myapp-docs-v1")
   sm_auth  = signer.sign(b"token", kp.secret, context=b"myapp-auth-v1")

   # Verification must use the same context
   signer.verify(sm_docs, kp.public)   # OK
   # signer.verify(sm_auth, kp.public) would fail with VerificationError
   # if verified with sm_docs' context

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
   signer.verify(sm1, kp.public)           # both valid
   signer.verify(sm2, kp.public)

Disable with ``hedged=False`` only when you need deterministic signatures:

.. code-block:: python

   signer = HybridSign(hedged=False)
   sm1 = signer.sign(b"same", kp.secret)
   sm2 = signer.sign(b"same", kp.secret)
   assert sm1.signature == sm2.signature   # deterministic

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
   signer.verify(sm2, kp.public)           # round-trips perfectly

HybridSignature
---------------

A :class:`~quantum_safe.types.HybridSignature` exposes the individual
sub-signatures for hybrid messages:

.. code-block:: python

   from quantum_safe.types import HybridSignature

   hybrid_sig = HybridSignature.from_bytes(sm.signature)
   print(len(hybrid_sig.classical_sig))    # Ed25519: 64 bytes
   print(len(hybrid_sig.pqc_sig))          # ML-DSA-65: ~3293-3309 bytes
