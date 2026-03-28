quantum-safe
============

Production-grade post-quantum cryptography for Python.
Hybrid KEM, hybrid signatures, migration tooling, protocol helpers,
and a CI-ready audit scanner — all in one library.

.. code-block:: python

   from quantum_safe import HybridKEM, HybridSign

   # Hybrid key exchange — X25519 + ML-KEM-768
   kem = HybridKEM()
   kp  = kem.generate_keypair()
   ct, ss = kem.encapsulate(kp.public)
   ss2    = kem.decapsulate(kp.secret, ct)
   assert ss == ss2

   # Hybrid signatures — Ed25519 + ML-DSA-65
   signer = HybridSign()
   kp     = signer.generate_keypair()
   sm     = signer.sign(b"document", kp.secret, context=b"myapp-v1")
   signer.verify(sm, kp.public)


.. admonition:: Why hybrid?

   During the NIST transition period, every major security body (NIST, CISA, BSI, NCSC)
   recommends combining a classical algorithm with a PQC algorithm.
   Both would need to be broken simultaneously for an attacker to succeed.
   This library makes hybrid mode the **default** — you must explicitly opt out.

----

.. toctree::
   :maxdepth: 1
   :caption: Getting started

   guides/installation
   guides/quickstart
   guides/concepts

.. toctree::
   :maxdepth: 1
   :caption: Guides

   guides/kem
   guides/signatures
   guides/protocols
   guides/migration
   guides/audit
   guides/cli
   guides/benchmarks

.. toctree::
   :maxdepth: 1
   :caption: API reference

   api/types
   api/kem
   api/signatures
   api/protocols
   api/migrate
   api/audit
   api/backends
   api/exceptions

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog
