Exceptions (``quantum_safe.exceptions``)
=========================================

All exceptions inherit from :class:`~quantum_safe.exceptions.QuantumSafeError`
so you can catch the entire hierarchy with a single ``except`` clause.
Every exception carries a machine-readable ``code`` string for programmatic
handling.

Exception hierarchy
-------------------

.. code-block:: text

   QuantumSafeError
   ├── CryptoError
   │   ├── VerificationError
   │   ├── DecapsulationError
   │   └── KeyGenerationError
   ├── SerializationError
   │   ├── KeyParseError
   │   └── IncompatibleKeyVersion
   ├── BackendError
   │   └── BackendNotAvailable
   ├── ConfigurationError
   │   └── UnsupportedAlgorithm
   ├── MigrationError
   │   └── ClassicalKeyDetected
   └── InsecureOperationError

Reference
---------

.. autoexception:: quantum_safe.exceptions.QuantumSafeError
   :members:

.. autoexception:: quantum_safe.exceptions.CryptoError
   :members:

.. autoexception:: quantum_safe.exceptions.VerificationError
   :members:

.. autoexception:: quantum_safe.exceptions.DecapsulationError
   :members:

.. autoexception:: quantum_safe.exceptions.KeyGenerationError
   :members:

.. autoexception:: quantum_safe.exceptions.SerializationError
   :members:

.. autoexception:: quantum_safe.exceptions.KeyParseError
   :members:

.. autoexception:: quantum_safe.exceptions.IncompatibleKeyVersion
   :members:

.. autoexception:: quantum_safe.exceptions.BackendError
   :members:

.. autoexception:: quantum_safe.exceptions.BackendNotAvailable
   :members:

.. autoexception:: quantum_safe.exceptions.ConfigurationError
   :members:

.. autoexception:: quantum_safe.exceptions.UnsupportedAlgorithm
   :members:

.. autoexception:: quantum_safe.exceptions.MigrationError
   :members:

.. autoexception:: quantum_safe.exceptions.ClassicalKeyDetected
   :members:

.. autoexception:: quantum_safe.exceptions.InsecureOperationError
   :members:
