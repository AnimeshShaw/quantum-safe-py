Upgrading to 1.0.0
==================

1.0.0 is the release that settles the behaviours announced in 0.3.1. Each section below says what
changed, what you need to do, and how to keep the old behaviour where that is possible.

Omitted ``context=`` now means "expect an empty context"
---------------------------------------------------------

Before 1.0.0, ``verify()`` without ``context=`` accepted whatever context the message carried and
emitted a ``DeprecationWarning``. Now it expects an empty context:

.. code-block:: python

   import warnings
   from quantum_safe.exceptions import ContextOmittedWarning, VerificationError
   from quantum_safe.signatures.hybrid import HybridSign

   signer = HybridSign()
   kp = signer.generate_keypair()
   sm = signer.sign(b"pay alice", kp.secret, context=b"payments-v1")

   # 0.3.x: accepted, with a DeprecationWarning.  1.0.0: rejected, with a ContextOmittedWarning.
   with warnings.catch_warnings(record=True) as caught:
       warnings.simplefilter("always")
       try:
           signer.verify(sm, kp.public)
       except VerificationError:
           print("rejected")
   assert caught and issubclass(caught[0].category, ContextOmittedWarning)

   # The fix is to say what you expect.
   signer.verify(sm, kp.public, context=b"payments-v1")

**What you need to do.** Add ``context=`` to every ``verify()`` that checks a message signed with a
context. Messages signed without a context keep verifying without one. See :doc:`context-and-aad`.

Omitted ``expected_aad=`` still accepts, and now warns with a visible category
-------------------------------------------------------------------------------

``Envelope.open()`` without ``expected_aad=`` still opens messages that carry AAD, and the warning is
now an ``AadOmittedWarning`` (a ``UserWarning``, shown by default) instead of a ``DeprecationWarning``
(hidden by default). Pass ``expected_aad=`` to check what the message is bound to.

liboqs 0.16.0
-------------

The ``[liboqs]`` extra requires ``liboqs-python>=0.16.0,<0.17`` and the wheels bundle liboqs 0.16.0.
liboqs-python warns at import when the two differ; 0.16.0 and its matching liboqs-python do not.
``quantum_safe.backends.liboqs.liboqs_versions()`` reports the pair. HQC is named ``HQC-1/3/5`` in
liboqs 0.16 (``HQC-128/192/256`` in 0.15); the library's names are unchanged, and the HQC sizes follow
the 2025 specification (secret key 2321 bytes, shared secret 32 bytes for HQC-128).

The default hybrid signature is ``-v2``
---------------------------------------

``HybridSign()`` is now ``Ed25519+ML-DSA-65-v2`` (no hedging prefix, FIPS 204 native context,
byte-compatible with quantum-safe-ts). Signatures it makes verify on quantum-safe 0.3.1 and later and
on quantum-safe-ts, and **not** on 0.3.0 or earlier.

.. code-block:: python

   from quantum_safe import HybridSign

   new = HybridSign()                              # Ed25519+ML-DSA-65-v2
   old = HybridSign("Ed25519", "ML-DSA-65")        # the original format, unchanged
   assert new.algorithm == "Ed25519+ML-DSA-65-v2"
   assert old.algorithm == "Ed25519+ML-DSA-65"

**What you need to do.**

* Verifying signatures that already exist: build the verifier with the original suite
  (``HybridSign("Ed25519", "ML-DSA-65")``). A default verifier refuses them, because keys carry their
  format tag.
* Signing for verifiers that are older than 0.3.1: name the original suite.
* ``HybridSign(hedged=False)`` without a suite keeps selecting the original format (``-v2`` is always
  hedged), so existing unhedged verifiers need no change.
* Never use the same key material in both formats.

Audit and scanner corrections
-----------------------------

These change what ``qs-audit`` and the scanner report; the output formats are unchanged.

* ``fail_on`` now applies to every severity it names. A policy with ``MEDIUM`` in ``fail_on``
  (``AuditPolicy.strict()``) reports MEDIUM findings as ``classical_crypto_detected`` violations
  unless ``allow_classical_only`` is set; before, they were ignored.
* ``--exclude`` and the ``exclude`` argument match a path below the scanned directory as well as a
  name, so ``tests/**`` works as documented, and ``*.egg-info`` directories are skipped.
* ``QS050`` and ``QS051`` (pycryptodome RSA and ECC) report ``generate``, ``construct`` and
  ``import_key`` calls; before they could not fire. ``QS030`` no longer reports ``hashlib.sha224``.
* The compliance control for broken hashes and 3DES is ``SP800131A-1`` (NIST SP 800-131A); it was
  labelled ``SP800208-3.1``. It now includes ``QS021``, and the RSA/ECC rules ``QS050`` and ``QS051``
  count against the FIPS 203 and FIPS 204 controls.
* ``Ed25519+ML-DSA-65-v2`` and the other ``-v2`` signature names are recognised by the key
  inventory instead of being reported as unknown algorithms.
* ``qs-audit scan --metadata`` requires ``KEY=VALUE`` and exits with a usage error otherwise.
* The SBOM knowledge base lists ``cryptography`` ML-KEM and ML-DSA support from 48.0, knows the
  library as ``quantum-safe-py``, matches package names the way pip does, and reads only the lower
  bounds (``==``, ``~=``, ``>=``, ``>``) of a requirement as its version.
