Key encapsulation (KEM)
=======================

Key encapsulation mechanisms (KEMs) let two parties establish a shared
secret without transmitting the secret itself.  The sender *encapsulates*
a random secret using the recipient's public key; the recipient
*decapsulates* it using their secret key.

Choosing an algorithm
---------------------

.. list-table::
   :widths: 30 15 15 40
   :header-rows: 1

   * - Algorithm
     - Type
     - NIST level
     - Notes
   * - ``X25519+ML-KEM-768``
     - Hybrid KEM
     - —
     - **Recommended default.** Classical + PQC.
   * - ``ML-KEM-512``
     - Pure PQC KEM
     - 1
     - Smallest key/ciphertext.  Use ML-KEM-768 for new deployments.
   * - ``ML-KEM-768``
     - Pure PQC KEM
     - 3
     - Recommended pure-PQC choice.
   * - ``ML-KEM-1024``
     - Pure PQC KEM
     - 5
     - Maximum security.
   * - ``X25519+ML-KEM-1024``
     - Hybrid KEM
     - —
     - Higher security margin.
   * - ``P-256+ML-KEM-768``
     - Hybrid KEM
     - —
     - When P-256 compatibility is required.

HybridKEM
---------

:class:`~quantum_safe.kem.hybrid.HybridKEM` is the high-level hybrid KEM.
It combines X25519 (or P-256) with an ML-KEM variant and derives the shared
secret with a library-specific HKDF-SHA256 combiner::

   HKDF-SHA256(ikm  = ss_classical || ss_pqc,
               salt = ct_classical || ct_pqc,
               info = "quantum-safe hybrid KEM v1" || 0x00 || algorithm)

This is not the TLS 1.3 hybrid construction (RFC 10024 concatenates the two
secrets into the TLS key schedule) and not X-Wing, so ciphertexts and
envelopes from this library are readable only by implementations of this
construction, such as quantum-safe-ts.  The default pair, X25519 +
ML-KEM-768, uses the same component algorithms as TLS's X25519MLKEM768.

.. code-block:: python

   from quantum_safe import HybridKEM

   # Default: X25519 + ML-KEM-768
   kem = HybridKEM()

   # Generate a keypair for the recipient
   kp = kem.generate_keypair()

   # Sender: encapsulate — ct goes to recipient, ss is used locally
   ct, ss = kem.encapsulate(kp.public)

   # Recipient: decapsulate
   ss2 = kem.decapsulate(kp.secret, ct)

   assert ss == ss2

Choosing a different combination:

.. code-block:: python

   kem = HybridKEM(classical="X25519", pqc="ML-KEM-1024")
   kem = HybridKEM(classical="P-256",  pqc="ML-KEM-768")

KEM (pure PQC)
--------------

:class:`~quantum_safe.kem.core.KEM` uses a single PQC algorithm.
Not recommended for new deployments — prefer :class:`~quantum_safe.kem.hybrid.HybridKEM`.

.. code-block:: python

   from quantum_safe import KEM

   kem = KEM("ML-KEM-768")
   kp  = kem.generate_keypair()
   ct, ss = kem.encapsulate(kp.public)
   ss2    = kem.decapsulate(kp.secret, ct)

SharedSecret
------------

:class:`~quantum_safe.types.SharedSecret` is not a plain ``bytes`` object.
Call :meth:`~quantum_safe.types.SharedSecret.derive_key` to produce
symmetric key material:

.. code-block:: python

   # Derive separate keys for encryption and MAC
   enc_key = ss.derive_key(32, info=b"myapp-enc-v1")
   mac_key = ss.derive_key(32, info=b"myapp-mac-v1")

   # Or a single key for AES-256-GCM
   aes_key = ss.derive_key(32, info=b"myapp-aes-v1")

The ``info`` parameter provides domain separation — use a unique value for
each derived key in your application.

Envelope (high-level encryption)
---------------------------------

:class:`~quantum_safe.protocols.envelope.Envelope` wraps KEM + AES-256-GCM
into a single ``seal`` / ``open`` API.  This is the recommended way to
encrypt data:

.. code-block:: python

   from quantum_safe import HybridKEM
   from quantum_safe.protocols import Envelope

   kp = HybridKEM().generate_keypair()

   # Encrypt
   sealed = Envelope.seal(b"secret payload", kp.public)

   # Decrypt
   plain = Envelope.open(sealed, kp.secret)

   # With authenticated additional data (visible but authenticated)
   sealed = Envelope.seal(b"payload", kp.public, aad=b"recipient:user-42")
   plain  = Envelope.open(sealed, kp.secret)
   # open() authenticates the AAD carried in the message but does not compare
   # it with anything: check it yourself before trusting the plaintext.
   if sealed.aad != b"recipient:user-42":
       raise ValueError("envelope was sealed for a different context")

   # Serialize for transport
   wire   = sealed.to_bytes()
   sealed = sealed.__class__.from_bytes(wire)

.. note::

   An envelope is public-key encryption: anyone holding the recipient's
   public key can seal a message, with any AAD.  It does **not** authenticate
   the sender; sign the payload separately when the sender matters.

Key serialization
-----------------

.. code-block:: python

   # Serialize
   pem  = kp.public.to_pem()
   cbor = kp.public.to_cbor()
   jwk  = kp.public.to_jwk()
   pem_sec = kp.secret.to_pem()

   # Deserialize
   from quantum_safe.types import PublicKey, SecretKey
   pub = PublicKey.from_pem(pem)
   sec = SecretKey.from_pem(pem_sec)

.. note::

   ``SecretKey`` zeros its memory buffer on deletion using ``ctypes.memset``
   against the live ``bytearray`` — a Python byte-loop is subject to
   dead-store elimination by the optimizer and is not used here.
   Python's garbage collector still makes hard guarantees impossible, but
   this reduces the window during which secret material is visible in heap
   dumps.  Callers that need to zero a copy immediately after use should
   call ``secret_key._raw_bytearray`` and zero it with ``ctypes.memset``
   in a ``try/finally`` block.
