"""
The liboqs release this version of quantum-safe is built against and tested with.

One place, read by the build hook (``hatch_build.py``), checked by the tests against
``pyproject.toml``, the ``Dockerfile`` and the workflows, and reported at runtime by
``quantum_safe.backends.liboqs.liboqs_versions()``. liboqs-python must be the same major.minor as
liboqs: it prints a warning at import otherwise, and that was the "0.16.0.1 with 0.15.0" pairing
in 0.3.2. Change both lines together.
"""

LIBOQS_VERSION = "0.16.0"
LIBOQS_PYTHON_SPEC = ">=0.16.0,<0.17"
