Reproducible build and the artifact record
===========================================

Every release carries a small **artifact record** that says what is in it, and the wheels'
vendored liboqs can be rebuilt from pinned inputs. This page is the recipe for both.

What a wheel contains
---------------------

A release wheel is the pure-Python package plus a compiled liboqs under
``quantum_safe/_vendor/liboqs/``. Three pins decide what that liboqs is, and they live in one file,
``src/quantum_safe/_liboqs_version.py``:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Pin
     - Meaning
   * - ``LIBOQS_VERSION``
     - The liboqs release that is compiled and bundled (``0.16.0``).
   * - ``LIBOQS_PYTHON_SPEC``
     - The ``liboqs-python`` range that loads it (``>=0.16.0,<0.17``).
   * - The ``Dockerfile`` argument ``LIBOQS_TAG``
     - The same release, for the benchmark and test image. A test fails if the three disagree.

Check what you have
-------------------

.. code-block:: python

   from quantum_safe.backends.liboqs import liboqs_versions
   print(liboqs_versions())     # the native liboqs and the liboqs-python that loaded it

At build and at import the pair is checked; a mismatch is an error, not a silent downgrade.

The artifact record
-------------------

``scripts/artifact_record.py`` writes one JSON file for a release: for each wheel and source
distribution its SHA-256 and size, the package version, the git commit and tag, and the liboqs pins.

.. code-block:: bash

   python -m build                                   # or the release workflow's wheels
   python scripts/artifact_record.py dist/ --out artifact-record-1.0.0.json
   sha256sum dist/*                                  # compare with the record

Attach ``artifact-record-<version>.json`` to the GitHub release. The release is archived by Zenodo,
which assigns it a DOI (the concept DOI in the README always resolves to the latest release, and each
release has its own); the record next to the files lets anyone check a download against what the
release says it contains.

Rebuild the vendored liboqs
---------------------------

From a clean checkout of the release tag:

.. code-block:: bash

   git checkout v1.0.0
   QUANTUM_SAFE_VENDOR_LIBOQS=1 python -m build --wheel

The build hook runs the ``liboqs-python`` installer at the pinned release into a staging directory and
copies the resulting library into the wheel. ``pyproject.toml`` and the release workflow
(``.github/workflows/build-wheels.yml``) set the same environment, so a local build uses the inputs the
published wheels used. Compilers and the operating system image differ between machines, so compare
**contents** (the liboqs version, the exported algorithm list and the test suite results) rather than
expecting byte-identical wheels across machines.

The build needs ``git``, CMake, Ninja and a C compiler (the project image installs them). To run
the NIST known-answer vectors against exactly the pinned liboqs, use the project image:

.. code-block:: bash

   docker build -t quantum-safe-liboqs --build-arg LIBOQS_TAG=0.16.0 .
   docker run --rm quantum-safe-liboqs python tests/conformance/acvp_kat.py
