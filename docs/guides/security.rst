Security model and reporting
============================

What quantum-safe protects, what it assumes, where its limits are, and how to report a
problem. Read this before relying on the library for anything sensitive.

.. contents:: On this page
   :local:
   :depth: 2

What the library does
---------------------

quantum-safe is a *thin, opinionated layer* over standardised post-quantum algorithms. The
cryptographic primitives (ML-KEM, ML-DSA, SLH-DSA) come from **liboqs**; classical
primitives (X25519, Ed25519, ECDSA P-256, AES-GCM, HKDF) come from the ``cryptography``
package. This library adds typed keys and messages, hybrid constructions, envelopes, a
signature format, JWTs, migration tooling and audit tools. Bugs in the additions are this
project's; bugs in the primitives belong upstream.

What it defends against
-----------------------

- **A quantum adversary who breaks classical key exchange or signatures.** Hybrid
  constructions stay secure if *either* component holds.
- **Misuse by construction.** Keys, ciphertexts, secrets and signed messages are distinct
  types; verifiers state the context and AAD they expect; loaders reject ambiguous input
  with one typed error.
- **Fault attacks on lattice signing,** through hedged signing (a fresh 32-byte prefix in the
  default format; hedging inside ML-DSA for ``-v2``).
- **Cross-context replay:** a signature made for one purpose does not verify for another when
  the verifier states its context, and an envelope sealed for one record does not open for
  another when the opener states its AAD.

What it does not defend against
-------------------------------

- **A compromised host.** Secret keys live in process memory. They are zeroised on deletion,
  but Python gives no guarantee about copies made by the interpreter.
- **Side channels in Python.** The library's own Python code is not written to be
  constant-time. The timing of liboqs operations is liboqs's property. The repository's
  leakage harness (see :doc:`benchmarks`) screens for gross dependence on secrets and
  explains its own sensitivity limits; it is not a proof.
- **Sender impersonation in envelopes.** An envelope is anonymous public-key encryption.
  Sign the payload if the sender matters.
- **Validation requirements.** The library is not FIPS 140-3 validated (see :doc:`compliance`).

Practices that matter most
--------------------------

#. Pass ``context=`` to ``verify()`` and ``expected_aad=`` to ``Envelope.open()``.
#. Use **one hedging mode and one signature format per key.**
#. Store secret keys in a secrets manager; never log keys, shared secrets or PEM bodies.
#. Catch ``KeyParseError`` around the parsing of untrusted keys and messages.
#. Run ``qs-audit scan`` in CI and keep the CBOM current.
#. Pin dependencies with hashes in production (the ``pyproject.toml`` shows how).

The safe pattern, in one place:

.. code-block:: python

   from cryptography.exceptions import InvalidTag
   from quantum_safe import HybridKEM, HybridSign, KeyParseError, PublicKey, VerificationError
   from quantum_safe.protocols import Envelope, SealedMessage

   CONTEXT = b"billing-exports-v1"          # one value per purpose, the same on both sides

   # Signing and verifying: the verifier states the context it expects.
   signer = HybridSign()
   keys = signer.generate_keypair()
   signed = signer.sign(b"invoice 42: 100.00", keys.secret, context=CONTEXT)
   signer.verify(signed, keys.public, context=CONTEXT)

   # Encrypting and decrypting: the opener states the AAD it expects.
   recipient = HybridKEM().generate_keypair()
   sealed = Envelope.seal(b"invoice 42", recipient.public, aad=b"customer:7")
   wire = sealed.to_bytes()
   assert Envelope.open(SealedMessage.from_bytes(wire), recipient.secret, expected_aad=b"customer:7")

   # Untrusted input: one typed error to catch, and every failure is a refusal, not a crash.
   def accept_public_key(data: bytes):
       try:
           return PublicKey.from_cbor(data)
       except KeyParseError:
           return None

   assert accept_public_key(b"not a key") is None
   for attempt in (
       lambda: signer.verify(signed, keys.public, context=b"another-purpose"),
       lambda: Envelope.open(SealedMessage.from_bytes(wire), recipient.secret, expected_aad=b"customer:8"),
   ):
       try:
           attempt()
       except (VerificationError, InvalidTag):
           pass
       else:
           raise AssertionError("a mismatched context or AAD must be refused")

Security history
----------------

0.3.1
~~~~~

Found by a cross-implementation review against quantum-safe-ts, which already enforced
each of these:

- **Signature prefix forgery** (High; every release up to 0.3.0): the unsigned prefix-length
  byte allowed bytes to be moved between a signed message and its prefix, forging a
  signature for a suffix or prefixed variant of a signed message.
- **Verifier read the context from the message** (Medium): domain separation was not enforced
  by ``verify()``.
- **Envelope AAD not bindable by the opener** (Medium): a message sealed for one context
  opened in another.
- **Hybrid payload malleability, lenient key loaders and untyped parser errors** (Low).

Details and the upgrade steps are in :doc:`upgrading`.

0.3.0
~~~~~

- ``SLH-DSA-*`` names resolved to pre-standard SPHINCS+ rather than FIPS 205 (the two are not
  interchangeable); corrected.
- A benchmark harness defect caused a decapsulation benchmark to measure the implicit
  rejection path; corrected, with the affected published figure re-measured.

Reporting a vulnerability
-------------------------

Please report security problems **privately**, not in a public issue:

- Use GitHub's *Report a vulnerability* button on the repository's **Security** tab, or
- email the maintainer at the address in ``SECURITY.md`` / ``CITATION.cff``.

Include the version, a minimal reproduction and what you believe the impact to be. You will
get an acknowledgement, and fixes are published with an advisory describing the affected
versions and the fixed version.
