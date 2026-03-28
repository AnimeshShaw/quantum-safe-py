Backends (``quantum_safe.backends``)
=====================================

Cryptographic backend adapters.  You rarely need to interact with these
directly — use :func:`~quantum_safe.backends.get_kem_backend` and
:func:`~quantum_safe.backends.get_signature_backend` only when you need
to force a specific backend.

.. autofunction:: quantum_safe.backends.get_kem_backend

.. autofunction:: quantum_safe.backends.get_signature_backend

.. autofunction:: quantum_safe.backends.list_available_backends

Abstract base classes
---------------------

.. autoclass:: quantum_safe.backends.base.AbstractKEMBackend
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.backends.base.AbstractSignatureBackend
   :members:
   :show-inheritance:

liboqs backend
--------------

.. autoclass:: quantum_safe.backends.liboqs.LiboqsKEMBackend
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.backends.liboqs.LiboqsSignatureBackend
   :members:
   :show-inheritance:
