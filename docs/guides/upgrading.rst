Upgrading from 0.3.0 to 0.3.1
=============================

0.3.1 is a security and quality release. It fixes a signature forgery
(:ref:`S1 below <upgrade-s1>`), tightens what the library accepts as input,
makes verifiers say what they expect, and adds capability: the ``-v2`` signature
format, envelope v2, RFC 9964 JWTs and a compare-and-set migration store.

**Nothing that 0.3.0 wrote stops working.** Every key, signature, envelope, JWT and
certificate co-signature written by 0.3.0 still loads and verifies on 0.3.1. What
changes is what the library *refuses* (input it should never have accepted) and what
you must now *state* when verifying. This page lists every change, why it was made,
and what to do about it.

.. contents:: On this page
   :local:
   :depth: 2

The short version
-----------------

1. Pass ``context=`` to every ``verify()`` and ``expected_aad=`` to every
   ``Envelope.open()``. Without them you get a ``DeprecationWarning`` now and an
   error in the next minor release.
2. If you ever signed with ``hedged=False``, build the verifier with
   ``hedged=False`` too. This applies to ``Sign``, ``HybridSign``, ``JWTVerifier``
   and ``HybridCertificateBuilder.verify_cosig``.
3. If you check CNSA 2.0 compliance with ``cnsa2.hybrid_kem()`` or
   ``cnsa2.hybrid_sign()``, switch to ``cnsa2.pqc_kem()`` / ``cnsa2.pqc_sign()``:
   hybrids are now reported ``PARTIAL``.
4. Run your tests with the two new deprecations turned into errors, so nothing is
   missed:

.. code-block:: python

   import warnings

   warnings.filterwarnings("error", message=r"verify\(\) without context=")
   warnings.filterwarnings("error", message=r"Envelope.open\(\) without expected_aad=")

.. _upgrade-s1:

Security fixes
--------------

S1: signature prefix forgery (High)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*Affected: every release up to and including 0.3.0.*

A signature blob is ``prefix_len (1 byte) || prefix || signature``. The signed bytes
were ``len(ctx) || ctx || prefix || message``, but the length byte itself was **not**
signed, and the verifier believed whatever it said. Anyone who held a valid
``SignedMessage`` for message ``M`` could move bytes between the message and the
prefix and obtain a signature that verifies for a *suffix* of ``M`` (or, with a zero
prefix, for ``prefix || M``). The signed bytes were identical, so verification passed.

For example, from a signed ``b"PAY alice 5 USD\nPAY mallory 1000000 USD\n"`` an
attacker could produce a valid signature for ``b"PAY mallory 1000000 USD\n"``.

**Fix.** The verifier no longer reads the prefix length from the blob. It requires the
length its *own* mode produces: 32 bytes when hedged (the default), 0 when
``hedged=False``. Any other value raises ``VerificationError``.

**What you need to do.** If everything you sign uses the default (hedged), nothing.
If you signed with ``hedged=False``, build the verifier the same way:

.. code-block:: python

   from quantum_safe import HybridSign

   signer = HybridSign(hedged=False)            # deterministic signatures
   kp = signer.generate_keypair()
   sm = signer.sign(b"release 1.2.3", kp.secret, context=b"releases-v1")

   HybridSign(hedged=False).verify(sm, kp.public, context=b"releases-v1")   # OK

   from quantum_safe import VerificationError
   try:
       HybridSign().verify(sm, kp.public, context=b"releases-v1")           # hedged verifier
   except VerificationError:
       print("an unhedged signature does not verify on a hedged verifier")

Use **one hedging mode per key**. A key used in both modes has two valid prefix
lengths in circulation, which is the residue of this problem; the durable fix is the
:doc:`-v2 format <signatures>`, which has no prefix at all.

S2: the context came from the message being verified (Medium)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``verify(sm, public_key)`` took the context from ``sm.context``, which is supplied by
whoever supplied the message. A signature made for purpose A (``context=b"login"``)
therefore verified for any application that simply called ``verify()``: the domain
separation the documentation promised was not enforced by the verifier.

**Fix.** ``verify()`` gains ``context=``. When given, the message's context must equal
it (constant-time comparison) or ``VerificationError`` is raised:

.. code-block:: python

   from quantum_safe import Sign, VerificationError

   signer = Sign("ML-DSA-65")
   kp = signer.generate_keypair()
   sm = signer.sign(b"transfer 5", kp.secret, context=b"login")

   signer.verify(sm, kp.public, context=b"login")           # OK: the context you expect

   try:
       signer.verify(sm, kp.public, context=b"payments")    # a different purpose
   except VerificationError:
       print("a signature made for 'login' is refused for 'payments'")

**What you need to do.** Add ``context=`` to every ``verify()``. Omitting it still
works in this release, emits a ``DeprecationWarning``, and becomes an error (with a
default of ``b""``) in the next minor release. ``JWTVerifier`` and
``HybridCertificateBuilder.verify_cosig`` now pass their own context, so nothing to
change there.

S3: hybrid signature payloads accepted unsigned extra data (Low)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The hybrid payload is a CBOR map of two signatures and two algorithm names. Extra
entries, duplicate keys and trailing bytes were ignored, so several different byte
strings verified as the same signature. Anything that uses signature *bytes* as an
identifier or a replay key could be fooled.

**Fix.** The payload must be exactly the four documented entries with the documented
types, no duplicates and no trailing bytes, and the algorithm names must name the
verifier's own components. Every payload the library writes is accepted. **Nothing to
do** unless you built hybrid signatures by hand.

S4 and S5: strict loaders and typed errors (Low)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Key loaders accepted ambiguous input: a key map without ``ktype`` loaded as either type,
a JWK with any ``kty`` (or none) loaded, ``v: true`` was read as version 1, and malformed
documents raised ``AttributeError`` / ``TypeError`` / ``KeyError`` / ``IndexError``, which
escape ``except KeyParseError``. Some wrong-typed fields were silently coerced: an
integer ``msg`` became that many zero bytes.

**Fix.** ``ktype`` is required and must match the loader, JWKs need ``kty: "AKP"``,
the version must be an integer, and every key, signed-message and sealed-message loader
checks types and raises :class:`~quantum_safe.exceptions.KeyParseError`. Every key this
library has written since 0.1.0 meets these rules.

.. code-block:: python

   import cbor2
   from quantum_safe import KeyParseError, PublicKey

   try:
       PublicKey.from_cbor(cbor2.dumps([1, 2]))     # not even a map
   except KeyParseError as exc:
       print("typed error:", type(exc).__name__)

S6: envelopes did not bind a message to a context (Medium)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An envelope is anonymous public-key encryption: anyone holding the recipient's public
key can seal a message, with any AAD, and the AAD travels inside the message.
``Envelope.open()`` authenticated the AAD against tampering but could not be told
which AAD to expect, so a message sealed for user A opened in user B's context.

**Fix.** ``Envelope.open(..., expected_aad=...)``:

.. code-block:: python

   from cryptography.exceptions import InvalidTag
   from quantum_safe import HybridKEM
   from quantum_safe.protocols import Envelope

   kp = HybridKEM().generate_keypair()
   sealed = Envelope.seal(b"invoice 42", kp.public, aad=b"user:alice")

   print(Envelope.open(sealed, kp.secret, expected_aad=b"user:alice"))   # OK

   try:
       Envelope.open(sealed, kp.secret, expected_aad=b"user:bob")        # wrong context
   except InvalidTag:
       print("sealed for alice, refused in bob's context")

**What you need to do.** Pass ``expected_aad=`` whenever you seal with ``aad=``. An
envelope that carries no AAD needs nothing. Remember that an envelope does **not**
authenticate the sender; sign the payload separately if the sender matters.

Behaviour changes you may notice
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Area
     - Before (0.3.0)
     - Now (0.3.1)
   * - CNSA 2.0 report
     - ``X25519+ML-KEM-1024`` reported compliant
     - Every hybrid is ``PARTIAL`` (see :doc:`compliance`); new key-derivation row
   * - ``cnsa2.enforce()``
     - Raised below the parameter sets
     - Same by default; ``strict=True`` also refuses ``PARTIAL``
   * - ML-DSA sizes in the registry and backends
     - Round-3 Dilithium sizes (4864, 4595, ...)
     - FIPS 204 sizes (4896, 4627, ...); keys and signatures were always correct
   * - ``Upgrader`` result
     - ``backward_compat=True``
     - ``backward_compat=False``: classical-only software cannot parse a hybrid key
   * - Missing ``cbor2``
     - Silently wrote an unreadable JSON format
     - ``ImportError`` at import
   * - Migration store writes (plain dict)
     - ``_current`` then ``_history``
     - ``_history`` then ``_current``
   * - Docstrings
     - The context was "FIPS 204's"; the combiner "exactly what TLS uses"
     - Both corrected: see :doc:`concepts`

What is new
-----------

- :doc:`The -v2 signature format <signatures>`: no prefix, plain FIPS 204 with a native
  context, byte-compatible with quantum-safe-ts.
- Envelope v2 (CNSA 2.0 profile) for pure ``ML-KEM-1024``: see :doc:`kem`.
- RFC 9964 ``StandardJwt``: see :doc:`protocols`.
- A compare-and-set migration store: see :doc:`migration`.
- A leakage harness with a positive control and public-data calibrations: see
  :doc:`benchmarks`.
- :doc:`cookbook`, :doc:`choosing`, :doc:`interop`, :doc:`compliance` and
  :doc:`security`.

An upgrade checklist
--------------------

#. ``pip install -U quantum-safe-py`` (and ``quantum-safe-py[liboqs]`` or your usual extra).
#. Run your tests with the two deprecations turned into errors (above) and add the
   missing ``context=`` / ``expected_aad=`` arguments.
#. Search your code for ``hedged=False``; make the verifier match.
#. Search for ``cnsa2.hybrid_kem`` / ``cnsa2.hybrid_sign``; decide whether pure
   ``pqc_kem()`` / ``pqc_sign()`` is what you want (it usually is).
#. If several worker processes share one migration store, give it a ``compare_and_set``
   (see :doc:`migration`).
#. Rotate nothing: no key, signature or envelope needs to be re-created.
#. Plan to move new signatures to ``-v2`` when every verifier you control is on 0.3.1 or
   later (and quantum-safe-ts 0.1.0+); the default will switch in the next minor release.
