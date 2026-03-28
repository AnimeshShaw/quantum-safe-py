Types (``quantum_safe.types``)
==============================

Core data types returned by all key and signature operations.
Raw bytes are never returned directly — every output is a distinct type
that prevents accidental misuse (e.g. passing a ``SharedSecret`` where
a ``CipherText`` is expected).

.. autoclass:: quantum_safe.types.PublicKey
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.SecretKey
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.KeyPair
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.MigrationState
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.kem.CipherText
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.kem.HybridCipherText
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.kem.SharedSecret
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.SignedMessage
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.signatures.HybridSignature
   :members:
   :show-inheritance:
