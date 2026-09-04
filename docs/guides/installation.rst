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

   pip install quantum-safe-py

With liboqs backend (full ML-KEM / ML-DSA)
-------------------------------------------

.. code-block:: bash

   pip install 'quantum-safe-py[liboqs]'

``liboqs-python`` itself does **not** ship a prebuilt liboqs binary on any
platform — on its own, the first ``import oqs`` downloads and compiles
liboqs from source, needing ``git``, ``CMake``, and a C compiler (on
Windows, MSVC Build Tools with the C++ workload).

Our own released wheels work around that for common platforms — Linux
x86_64, Windows x64, and macOS arm64 (14+) — by compiling liboqs ourselves at
release time and bundling the binary into the wheel. On those platforms,
installation is compiler-free. Elsewhere (32-bit, other architectures, Intel
Mac, macOS <14), liboqs-python's normal build-from-source path applies.

.. note::

   Tested against ``liboqs-python`` 0.10.x – 0.15.x.  The library emits a
   version-mismatch warning at import time if the native liboqs binary version
   differs from the Python wrapper; this is informational only.

Verify the install:

.. code-block:: bash

   python -c "from quantum_safe.backends import list_available_backends; print(list_available_backends())"
   # → {'rustcrypto': False, 'liboqs': True, 'noble': False}

Development install
-------------------

.. code-block:: bash

   git clone https://github.com/AnimeshShaw/quantum-safe
   cd quantum-safe
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

On Windows, our released wheel bundles a precompiled liboqs DLL, so no
compiler is required. If you see a version mismatch warning between
``liboqs`` and ``liboqs-python`` at import time, it is informational only —
the library functions correctly.
