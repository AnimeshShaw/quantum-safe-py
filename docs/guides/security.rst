Security model and reporting
============================

What quantum-safe protects, what it assumes, where its limits are, and how to report a
problem. Read this before relying on the library for anything sensitive.

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

Design notes
------------

Memory handling
~~~~~~~~~~~~~~~

``SecretKey`` and ``SharedSecret`` zero their memory on deletion with ``ctypes.memset`` against the
live ``bytearray`` buffer; a Python byte loop can be removed by the optimiser, ``memset`` runs at
the C level. Python's garbage collector still makes hard guarantees impossible, but this keeps the
window in which secret material is visible in a heap dump short. To zero a copy right after use,
take ``SecretKey._raw_bytearray`` (a fresh ``bytearray``) and zero it with ``ctypes.memset`` in a
``try``/``finally``. For high-security deployments, keep keys in an HSM or a secrets manager.

Constant-time behaviour
~~~~~~~~~~~~~~~~~~~~~~~

Secret comparisons use ``hmac.compare_digest()``. Hybrid signature verification evaluates both
sub-signatures unconditionally before combining the results, so the time does not reveal which
component failed. The liboqs implementations are designed for constant-time operation.

Two measurements back this and they answer different questions. The coefficient of variation is
taken with the secret held fixed and shows timing stability under repetition. The fixed-versus-random
test needs controls to be read: a random-versus-random control, a public-data calibration and a
positive control that reports the smallest deliberate leak the harness detects. On the development
host, encapsulation, which uses no secret, reproduces the fixed-versus-random decapsulation signal,
so that signal on its own is a measurement artefact. See :doc:`benchmarks`. The harness screens for
gross secret dependence; a formal check (``dudect`` or ``ct-verif`` against the compiled backend)
is a different tool, and everything here is measured through the Python binding.

Serialization
~~~~~~~~~~~~~

The ``_internal.serialization`` layer caps incoming payloads at 10 MB before parsing, which bounds
memory use for deeply nested or padded CBOR and JSON. Key payloads with ``version < 1`` are rejected
at once, so a version-rollback payload never reaches the key loaders.

Threads and processes
~~~~~~~~~~~~~~~~~~~~~

``MigrationStateManager`` is safe across processes and hosts when its store has a
``compare_and_set(key, expected, value) -> bool`` method (``MemoryMigrationStore`` is the in-process
reference, ``FileMigrationStore`` works across processes on one host; ``manager.cross_process_safe``
tells you which mode you are in): exactly one concurrent writer wins, with no external lock. With a
plain dict it holds a per-key ``threading.Lock``, which covers the threads of one process; with
several workers sharing a store (Gunicorn and Redis, for example) hold a distributed lock on the
``key_id`` around ``transition()``. See :doc:`migration`.

Hedged signing
~~~~~~~~~~~~~~

``HybridSign()`` defaults to the ``-v2`` format: ML-DSA hedges internally (FIPS 204's own fresh
randomness) and there is no prefix. In the original format (``HybridSign("Ed25519", "ML-DSA-65")``,
and ``Sign`` by default) hedged mode prepends a 32-byte random prefix before signing, which guards
against the fault-injection attacks shown on lattice signatures in laboratory conditions. Opt out
with ``hedged=False`` only when you need deterministic signatures.

A verifier accepts only signatures made in its own hedging mode, because the prefix length is not
covered by the signature and is therefore not read from it. Build the verifier with the signer's
``hedged`` value and use one mode per key. The ``-v2`` format has no prefix and no hedging mode.

State the context and AAD you expect
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``verify(sm, public_key, context=...)`` and ``Envelope.open(sealed, secret_key, expected_aad=...)``
state what the verifier expects. The context and AAD inside a message come from whoever supplied
it, so without them a signature made for one purpose verifies for another and a ciphertext sealed
for one record opens for another. Omitting the context means "expect an empty context" and emits a
``ContextOmittedWarning``; omitting the AAD accepts any AAD and emits an ``AadOmittedWarning``. See
:doc:`context-and-aad`.

Why hybrid by default
~~~~~~~~~~~~~~~~~~~~~

If ML-KEM is broken, X25519 still protects the data; if X25519 is broken by a quantum computer,
ML-KEM still protects it; both would have to fail together. This is the position of NIST, CISA,
BSI, NCSC and the TLS libraries that have added post-quantum support.

Reporting a vulnerability
-------------------------

Please report security problems **privately**, not in a public issue:

- Use GitHub's *Report a vulnerability* button on the repository's **Security** tab, or
- email the maintainer at the address in ``SECURITY.md`` / ``CITATION.cff``.

Include the version, a minimal reproduction and what you believe the impact to be. You will
get an acknowledgement, and fixes are published with an advisory describing the affected
versions and the fixed version.
