Upgrading to 0.4.0
==================

.. contents:: On this page
   :local:
   :depth: 2

0.4.0 is the release that settles the behaviours announced in 0.3.1. Each section below says what
changed, what you need to do, and how to keep the old behaviour where that is possible.

Omitted ``context=`` now means "expect an empty context"
---------------------------------------------------------

Before 0.4.0, ``verify()`` without ``context=`` accepted whatever context the message carried and
emitted a ``DeprecationWarning``. Now it expects an empty context:

.. code-block:: python

   import warnings
   from quantum_safe.exceptions import ContextOmittedWarning, VerificationError
   from quantum_safe.signatures.hybrid import HybridSign

   signer = HybridSign()
   kp = signer.generate_keypair()
   sm = signer.sign(b"pay alice", kp.secret, context=b"payments-v1")

   # 0.3.x: accepted, with a DeprecationWarning.  0.4.0: rejected, with a ContextOmittedWarning.
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
