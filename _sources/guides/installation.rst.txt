Installation
============

Requirements
------------

- Python 3.10 or later
- ``cryptography >= 42.0``
- ``cbor2 >= 5.6``
- ``pydantic >= 2.5``
- ``click >= 8.1``
- ``rich >= 13.0``

Core install (no PQC backend)
------------------------------

The core package works without liboqs.  Key generation, serialization,
hybrid construction, Envelope, JWT, TLS helpers, scanner, auditor, and
SBOM enrichment all work using the classical (X25519/Ed25519) components.

.. code-block:: bash

   pip install quantum-safe

With liboqs backend (full ML-KEM / ML-DSA)
-------------------------------------------

.. code-block:: bash

   pip install 'quantum-safe[liboqs]'

This installs ``liboqs-python``, which vendors a pre-built liboqs binary
for Linux x86-64, macOS ARM/x86, and Windows x86-64.
On other architectures, build liboqs from source first.

Verify the install:

.. code-block:: bash

   python -c "from quantum_safe.backends import list_available_backends; print(list_available_backends())"
   # → {'rustcrypto': False, 'liboqs': True, 'noble': False}

Development install
-------------------

.. code-block:: bash

   git clone https://github.com/quantum-safe/quantum-safe-py
   cd quantum-safe-py
   pip install -e '.[dev]'
   pre-commit install

Running the test suite:

.. code-block:: bash

   # Unit tests only (no liboqs required)
   python -m pytest tests/unit/ -v

   # Full suite, skip slow tests
   python -m pytest tests/ -v -m "not slow"

   # Skip liboqs-dependent tests
   python -m pytest tests/ -v -m "not requires_liboqs"

Windows notes
-------------

On Windows, ``liboqs-python`` ships a pre-built DLL so no compiler is
required.  If you see a version mismatch warning between ``liboqs`` and
``liboqs-python`` at import time, it is informational only — the library
functions correctly.
