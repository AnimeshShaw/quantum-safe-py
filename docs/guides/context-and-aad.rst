Context and AAD: binding a message to its purpose
==================================================

A signature or an encrypted message is only as useful as what it is bound to. The same key may sign a
login challenge, a payment instruction and a software release; one recipient key may receive messages
about many users. **Context** (for signatures) and **AAD** (for envelopes) are how a message says what it
is *for*, and how the verifier says what it *expects*. This page explains both, with the situations
where they matter, and exactly what happens when you leave the argument out.

The one-line rule
-----------------

Pass ``context=`` to ``verify()`` and ``expected_aad=`` to ``Envelope.open()``. Both are optional, and
both do something sensible when omitted, but passing them is what makes the check mean something.

What each one is
----------------

``context`` (signatures)
   Up to 255 bytes, chosen by the signer, covered by the signature, stored in the ``SignedMessage``.
   The verifier states the context it expects. A signature made for ``b"payments"`` does not verify
   as ``b"refunds"``, even with the same key and the same message bytes.

``aad`` (envelopes)
   *Additional authenticated data*: bytes that are not encrypted but are authenticated with the
   ciphertext. Tampering with them makes ``open()`` fail. They travel with the message and are
   typically an identifier: a user id, a record id, a tenant.

Neither one is secret. Neither one tells you *who* sent the message; sign the payload when the sender
matters.

Why it matters: four situations
-------------------------------

**One key, several purposes (signatures).** A service signs login tokens and also signs payment
instructions with the same key. Without a context, a token signature whose bytes happen to be a valid
payment instruction is a valid payment signature. With ``context=b"auth-v1"`` and
``context=b"payments-v1"`` the two can never be confused.

**Multi-tenant records (envelopes).** A database stores one envelope per customer, all sealed to the
same recipient key. If an attacker can copy customer A's envelope into customer B's row, B's service
opens it successfully. Sealing with ``aad=b"tenant-A"`` and opening with ``expected_aad=b"tenant-B"``
makes the copy fail.

**Replay across purposes (both).** A message signed for the *staging* environment must not be accepted
by *production*. Put the environment in the context (``b"myapp-prod-v1"``).

**File signing.** Signing a release artifact with ``context=b"release-v1"`` means the same signature
cannot be presented as, say, a configuration-file approval signed by the same key.

Choose contexts that are stable, specific and versioned (``b"myapp-docs-v1"``), and keep them in one
constants module so signer and verifier cannot drift.

What happens if you leave it out
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Call
     - Message carries a context / AAD
     - Message carries none
   * - ``verify(sm, pk)``  (no ``context=``)
     - **Rejected** with ``VerificationError``, and a ``ContextOmittedWarning`` says why
     - Accepted, silently
   * - ``verify(sm, pk, context=b"x")``
     - Accepted only if equal to ``b"x"``; otherwise ``VerificationError``
     - Rejected unless ``b"x"`` is empty
   * - ``Envelope.open(sealed, sk)``  (no ``expected_aad=``)
     - **Accepted**, with an ``AadOmittedWarning``: the AAD was not checked against anything
     - Accepted, silently
   * - ``Envelope.open(sealed, sk, expected_aad=b"x")``
     - Accepted only if equal to ``b"x"``; otherwise ``InvalidTag``
     - Rejected unless ``b"x"`` is empty

In words: omitting ``context=`` means "I expect no context", so a message made for a purpose is refused
rather than silently accepted for the wrong one. Omitting ``expected_aad=`` means "I do not check the
AAD", which is accepted but flagged, because the opener did not verify what the message was bound to.

The error on the wire stays opaque (``VerificationError`` / ``InvalidTag``): it does not say whether the
context or the signature was wrong. The warning is local, for the developer, and never contains the
context or AAD value.

Working example
---------------

.. code-block:: python

   from quantum_safe.exceptions import VerificationError
   from quantum_safe.signatures.hybrid import HybridSign
   from quantum_safe.kem.hybrid import HybridKEM
   from quantum_safe.protocols.envelope import Envelope

   signer = HybridSign()
   kp = signer.generate_keypair()

   sm = signer.sign(b"transfer 5", kp.secret, context=b"payments-v1")
   signer.verify(sm, kp.public, context=b"payments-v1")          # accepted
   try:
       signer.verify(sm, kp.public, context=b"auth-v1")          # a different purpose
   except VerificationError:
       print("refused: made for another purpose")

   kem = HybridKEM()
   rk = kem.generate_keypair()
   sealed = Envelope.seal(b"card on file", rk.public, aad=b"tenant-A")
   assert Envelope.open(sealed, rk.secret, expected_aad=b"tenant-A") == b"card on file"

Controlling the warnings
------------------------

Both warnings are ``UserWarning`` subclasses (``QuantumSafeWarning``), so they are shown by default and
once per call site. Turn them into errors in your test suite, or silence them where omission is
deliberate:

.. code-block:: python

   import warnings
   from quantum_safe.exceptions import AadOmittedWarning, ContextOmittedWarning

   warnings.filterwarnings("error", category=ContextOmittedWarning)   # CI: no omissions
   warnings.filterwarnings("ignore", category=AadOmittedWarning)      # a deliberate "any AAD" opener

The same behaviour holds in quantum-safe-ts (``expectedContext`` / ``expectedAad``), so a service in one
language can verify what the other signed.
