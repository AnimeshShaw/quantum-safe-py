Quick start
===========

Five-minute tour of the library's most important features.

Key exchange
------------

.. code-block:: python

   from quantum_safe import HybridKEM

   kem = HybridKEM()                    # X25519 + ML-KEM-768 by default
   kp  = kem.generate_keypair()

   # Sender — encapsulate a shared secret
   ct, shared_secret = kem.encapsulate(kp.public)

   # Recipient — recover the same shared secret
   shared_secret2 = kem.decapsulate(kp.secret, ct)

   assert shared_secret == shared_secret2

   # Derive symmetric keys
   enc_key = shared_secret.derive_key(32, info=b"enc-v1")
   mac_key = shared_secret.derive_key(32, info=b"mac-v1")

Encrypted envelopes (recommended high-level API)
-------------------------------------------------

.. code-block:: python

   from quantum_safe.protocols import Envelope

   kp = HybridKEM().generate_keypair()

   sealed = Envelope.seal(b"secret payload", kp.public)
   plain  = Envelope.open(sealed, kp.secret)

   # Serialize for network or storage
   wire   = sealed.to_bytes()
   sealed = sealed.__class__.from_bytes(wire)

Digital signatures
------------------

.. code-block:: python

   from quantum_safe import HybridSign

   signer = HybridSign()               # Ed25519 + ML-DSA-65 by default
   kp     = signer.generate_keypair()

   sm = signer.sign(b"document", kp.secret, context=b"myapp-v1")
   signer.verify(sm, kp.public)        # raises VerificationError if invalid

Key serialization
-----------------

.. code-block:: python

   pub = kp.public

   pem  = pub.to_pem()                 # PEM string (human-readable, with headers)
   cbor = pub.to_cbor()                # CBOR bytes (compact binary)
   jwk  = pub.to_jwk()                 # JSON Web Key dict

   from quantum_safe.types import PublicKey
   pub2 = PublicKey.from_pem(pem)
   pub3 = PublicKey.from_cbor(cbor)

Scan a codebase for classical crypto
-------------------------------------

.. code-block:: python

   from quantum_safe.migrate import Scanner
   import sys

   report = Scanner.scan_directory("./src")
   print(report.summary())

   if report.has_blocking_findings:
       sys.exit(1)

.. code-block:: bash

   # Or via CLI
   qs-audit scan ./src --format sarif --output audit.sarif

Next steps
----------

- :doc:`concepts` — architectural decisions and design principles
- :doc:`kem` — full KEM and Envelope API
- :doc:`signatures` — full signature API including hedged mode
- :doc:`protocols` — JWT, TLS, and X.509 protocol helpers
- :doc:`migration` — upgrading keys, tracking migration state
- :doc:`audit` — compliance, SBOM enrichment, CI gate
