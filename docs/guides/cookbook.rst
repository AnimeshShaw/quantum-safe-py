Cookbook: real-world recipes
============================

Worked examples for the jobs people actually have. Every Python block on this page is
executed by the test suite, so it runs as written. Where a recipe needs something you
supply (a database, a web framework) it uses a small stand-in and says so.

.. contents:: On this page
   :local:
   :depth: 1

1. Encrypt a file for a recipient
---------------------------------

*Use when:* you hand data to someone whose public key you hold: backups, exports, uploads.
*Not for:* proving who sent it (an envelope is anonymous; see recipe 3).

.. code-block:: python

   import pathlib
   import tempfile

   from quantum_safe import HybridKEM, PublicKey, SecretKey
   from quantum_safe.protocols import Envelope, SealedMessage

   # The recipient generates a key pair once and publishes the PUBLIC key.
   recipient = HybridKEM().generate_keypair()
   published_public_key_pem = recipient.public.to_pem()
   private_key_pem = recipient.secret.to_pem()          # stays with the recipient

   with tempfile.TemporaryDirectory() as tmp:
       tmp = pathlib.Path(tmp)
       (tmp / "report.csv").write_bytes(b"id,total\n1,100\n2,250\n")

       # The sender encrypts to the published key.
       public_key = PublicKey.from_pem(published_public_key_pem)
       sealed = Envelope.seal((tmp / "report.csv").read_bytes(), public_key, aad=b"report.csv")
       (tmp / "report.csv.qs").write_bytes(sealed.to_bytes())

       # The recipient decrypts. expected_aad binds the file to its name.
       blob = (tmp / "report.csv.qs").read_bytes()
       secret_key = SecretKey.from_pem(private_key_pem)
       data = Envelope.open(SealedMessage.from_bytes(blob), secret_key, expected_aad=b"report.csv")
       assert data == b"id,total\n1,100\n2,250\n"

Store the private key like any other secret (a secrets manager, an encrypted volume).
``to_pem()`` on a secret key returns the key material: do not log it.

2. Bind a ciphertext to a user or record
----------------------------------------

*Use when:* ciphertexts live in a database and must not be swappable between rows or users.
This is what ``expected_aad`` is for.

.. code-block:: python

   from cryptography.exceptions import InvalidTag
   from quantum_safe import HybridKEM
   from quantum_safe.protocols import Envelope

   service = HybridKEM().generate_keypair()

   def store_secret(user_id: str, value: bytes) -> bytes:
       # The AAD is visible but authenticated: it names the owner.
       return Envelope.seal(value, service.public, aad=f"user:{user_id}".encode()).to_bytes()

   def load_secret(user_id: str, blob: bytes) -> bytes:
       from quantum_safe.protocols import SealedMessage
       return Envelope.open(
           SealedMessage.from_bytes(blob), service.secret, expected_aad=f"user:{user_id}".encode()
       )

   alice_blob = store_secret("alice", b"alice's api key")
   assert load_secret("alice", alice_blob) == b"alice's api key"

   try:
       load_secret("bob", alice_blob)           # a row copied into bob's record
   except InvalidTag:
       print("refused: this ciphertext belongs to alice")

3. Sign and verify a release artifact
-------------------------------------

*Use when:* you publish files and users must check they are yours.

.. code-block:: python

   from quantum_safe import HybridSign, SignedMessage, VerificationError

   RELEASE_CONTEXT = b"acme-releases-v1"            # one fixed value for this purpose

   signer = HybridSign()                             # Ed25519 + ML-DSA-65
   keys = signer.generate_keypair()                  # publish keys.public; guard keys.secret

   artifact = b"binary contents of acme-1.2.3.tar.gz"
   signed = signer.sign_with_fingerprint(artifact, keys, context=RELEASE_CONTEXT)
   shipped = signed.to_cbor()                        # ship this next to the artifact

   # A user verifies with the published public key and the SAME context.
   received = SignedMessage.from_cbor(shipped)
   signer.verify(received, keys.public, context=RELEASE_CONTEXT)
   assert received.message == artifact

   try:
       signer.verify(received, keys.public, context=b"acme-login-v1")   # another purpose
   except VerificationError:
       print("a release signature cannot be replayed as a login signature")

The context is not a secret and need not be random. It only has to be *different for each
purpose* and *the same on both sides*.

4. Signatures other ecosystems can verify (``-v2``)
---------------------------------------------------

*Use when:* a Node.js service, a gateway or a third party verifies what you sign.

.. code-block:: python

   from quantum_safe import HybridSign

   signer = HybridSign("Ed25519", "ML-DSA-65-v2")    # identifier: Ed25519+ML-DSA-65-v2
   keys = signer.generate_keypair()
   signed = signer.sign(b"order #1001 approved", keys.secret, context=b"orders-v1")

   assert signed.algorithm == "Ed25519+ML-DSA-65-v2"
   assert len(signed.signature) == 64 + 3309        # classical || ML-DSA, nothing else
   signer.verify(signed, keys.public, context=b"orders-v1")

   # Hand signed.to_cbor() and keys.public.to_cbor() to quantum-safe-ts, which verifies it
   # with  new HybridSign('Ed25519+ML-DSA-65-v2').verify(..., { expectedContext })

See :doc:`interop` for the other direction and for the settings that must match.

5. Tokens: your services, or anyone's
-------------------------------------

*Your own services verify* (hybrid keys, quantum-safe only):

.. code-block:: python

   from quantum_safe import HybridSign
   from quantum_safe.protocols import JWTSigner, JWTVerifier

   keys = HybridSign().generate_keypair()
   token = JWTSigner(keys, issuer="auth.acme.example").sign({"sub": "user-17", "role": "admin"})

   claims = JWTVerifier(keys.public, issuer="auth.acme.example").verify(token)
   assert claims["sub"] == "user-17"

*Anyone's JOSE library verifies* (RFC 9964, pure ML-DSA):

.. code-block:: python

   from quantum_safe.protocols import StandardJwt

   keys = StandardJwt.generate_keypair("ML-DSA-65")
   token = StandardJwt.sign({"sub": "user-17"}, keys.secret, issuer="auth.acme.example", kid="2026-10")

   jwk = StandardJwt.public_jwk(keys.public, kid="2026-10")     # publish this at /.well-known/jwks
   claims = StandardJwt.verify(token, jwk, issuer="auth.acme.example", require_exp=True)
   assert claims["sub"] == "user-17"

Always pass ``require_exp=True`` for tokens that should expire: by default a token without
``exp`` is accepted.

6. Rotate keys through the migration state machine
--------------------------------------------------

*Use when:* you have many classical keys and need to move them to hybrid and then to pure
post-quantum without a flag day. Several workers may run the job, so give the manager a
store with ``compare_and_set``.

.. code-block:: python

   from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
   from cryptography.hazmat.primitives.serialization import (
       Encoding, NoEncryption, PrivateFormat, PublicFormat,
   )
   from quantum_safe.migrate import MemoryMigrationStore, MigrationStateManager, Upgrader
   from quantum_safe.types import MigrationState

   # An existing classical X25519 key.
   old = X25519PrivateKey.generate()
   old_private = old.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
   old_public = old.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

   # 1. Wrap it in a hybrid key. The classical key is retained inside the new key.
   result = Upgrader.upgrade_kem_key(
       classical_secret_bytes=old_private,
       classical_public_bytes=old_public,
       classical_algorithm="X25519",
       target_pqc="ML-KEM-768",
   )
   assert result.new_algorithm == "X25519+ML-KEM-768"
   assert result.backward_compat is False     # classical-only clients keep using the old key

   # 2. Record the transition. In production the store is Redis, Postgres, DynamoDB...
   #    MemoryMigrationStore is the in-process reference with an atomic compare_and_set.
   manager = MigrationStateManager(MemoryMigrationStore())
   assert manager.cross_process_safe

   manager.transition(
       "service-api-key", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION,
       "X25519+ML-KEM-768", actor="rotation-job-7",
   )

   # 3. Report progress.
   print(manager.migration_progress())
   assert manager.get_current_state("service-api-key") == MigrationState.HYBRID_TRANSITION

Two workers racing to move the same key: exactly one wins and the other receives a
``ValueError`` saying the state is stale, which the loser should treat as "someone else
already did it".

7. Check a configuration against CNSA 2.0 parameters
----------------------------------------------------

.. code-block:: python

   from quantum_safe.compliance import cnsa2

   kem = cnsa2.pqc_kem()            # ML-KEM-1024
   signer = cnsa2.pqc_sign()        # ML-DSA-87

   report = cnsa2.report(kem=kem.algorithm, signature=signer.algorithm, hash_algorithm="SHA-384")
   print(report.render())

   # A hybrid is reported PARTIAL, not compliant: see the compliance guide.
   hybrid = cnsa2.report(kem="X25519+ML-KEM-1024", include_code_signing=False)
   assert not hybrid.compliant

   # In CI, fail hard if a service drifts below the parameter sets.
   cnsa2.enforce(kem="ML-KEM-1024", signature="ML-DSA-87")

*Note:* this reports parameter selection: which algorithms, key sizes and hashes are in use.

8. Find classical cryptography in CI
------------------------------------

.. code-block:: bash

   # fail the build on HIGH or worse; upload findings to GitHub code scanning
   qs-audit scan ./src --fail-on high --format sarif --output audit.sarif

   # an inventory of the cryptography a project uses (CycloneDX 1.6 CBOM)
   qs-audit cbom ./src --output cbom.json

   # what an unconfigured deployment scores against CNSA 2.0 (it will not pass)
   qs-audit cnsa2

See :doc:`audit` and :doc:`cli` for every option.

9. Serialise keys and messages safely
-------------------------------------

.. code-block:: python

   import cbor2
   from quantum_safe import HybridKEM, KeyParseError, PublicKey

   kp = HybridKEM().generate_keypair()
   wire = kp.public.to_cbor()                       # compact binary
   assert PublicKey.from_cbor(wire) == kp.public

   # Untrusted input raises one typed error, never AttributeError or TypeError.
   for hostile in (b"\x00", cbor2.dumps([1, 2]), cbor2.dumps({"v": True})):
       try:
           PublicKey.from_cbor(hostile)
       except KeyParseError:
           pass
       except Exception as exc:                     # an unexpected exception type is a bug
           raise AssertionError(type(exc)) from exc

Catch ``KeyParseError`` once around the code that parses untrusted keys. Compare keys by
value or by ``fingerprint()``, never by their serialised bytes (the CBOR decoder accepts
non-minimal encodings, so two byte strings can decode to the same key).

10. Keep secret keys wrapped by a KMS
--------------------------------------

A secret key on disk in clear is the weakest link. Envelope encryption fixes that with any key
management service: ask the KMS for a fresh **data key**, encrypt the library's secret key with it
locally, and store the KMS-wrapped data key next to the result. Only the KMS can unwrap the data
key, and it works for any key size (a direct KMS ``Encrypt`` call has a small input limit that
ML-DSA-87 secret keys exceed).

.. code-block:: python

   import os
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   from quantum_safe import HybridKEM
   from quantum_safe.types import SecretKey

   class Kms:
       """Stands in for your KMS client; AWS KMS, GCP KMS and Vault transit offer these two calls."""
       def __init__(self):
           self._master = AESGCM.generate_key(bit_length=256)
       def generate_data_key(self, context: bytes):          # -> (plaintext key, wrapped key)
           plain, nonce = os.urandom(32), os.urandom(12)
           return plain, nonce + AESGCM(self._master).encrypt(nonce, plain, context)
       def decrypt(self, wrapped: bytes, context: bytes):    # -> plaintext key
           return AESGCM(self._master).decrypt(wrapped[:12], wrapped[12:], context)

   def wrap_secret_key(kms, secret: SecretKey, name: str) -> bytes:
       context = name.encode()                                # binds the result to this key's name
       data_key, wrapped_key = kms.generate_data_key(context)
       nonce = os.urandom(12)
       sealed = AESGCM(data_key).encrypt(nonce, secret.to_cbor(), context)
       return len(wrapped_key).to_bytes(2, "big") + wrapped_key + nonce + sealed   # store this

   def unwrap_secret_key(kms, stored: bytes, name: str) -> SecretKey:
       context = name.encode()
       n = int.from_bytes(stored[:2], "big")
       wrapped_key, nonce, sealed = stored[2:2 + n], stored[2 + n:14 + n], stored[14 + n:]
       data_key = kms.decrypt(wrapped_key, context)
       return SecretKey.from_cbor(AESGCM(data_key).decrypt(nonce, sealed, context))

   kms = Kms()
   pair = HybridKEM().generate_keypair()
   stored = wrap_secret_key(kms, pair.secret, "orders-service/recipient-key")
   secret = unwrap_secret_key(kms, stored, "orders-service/recipient-key")   # fails for another name

With a real service replace ``Kms`` by a thin adapter: in AWS KMS ``generate_data_key`` is
``kms.generate_data_key(KeyId=..., KeySpec="AES_256", EncryptionContext={"name": name})`` (use
``Plaintext`` and ``CiphertextBlob`` from the response) and ``decrypt`` is
``kms.decrypt(CiphertextBlob=..., EncryptionContext={"name": name})``; the encryption context
plays the role of the ``context`` above. The same shape works for the LMS signing key's
``protection`` in quantum-safe-ts (the data key becomes ``{ key }``). Unwrap once at start-up,
keep the key object for the life of the process, and do not log it. A key that must never leave
a hardware module cannot be used through this library; keep it in the module and use the
module's own signer.

Patterns to avoid
-----------------

- **Verifying without a context.** An omitted ``context`` means "expect an empty context" and
  warns; the context in a message is supplied by whoever supplied the message.
- **Sealing with AAD and opening without** ``expected_aad``: the ciphertext is then not
  bound to the context you meant.
- **Using one key in two signature formats**, or in both hedging modes.
- **Treating an envelope as authentication.** It is encryption to a public key; anyone can
  create one.
- **Logging keys, shared secrets or PEM bodies.** Secret keys zeroise on deletion, but a
  string you printed does not.
