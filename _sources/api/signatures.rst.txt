Signatures (``quantum_safe.signatures``)
=========================================

Digital signature operations.  The high-level entry point is
:class:`~quantum_safe.signatures.hybrid.HybridSign`.

.. autoclass:: quantum_safe.signatures.hybrid.HybridSign
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.core.Sign
   :members:
   :show-inheritance:

Algorithm registry
------------------

.. autofunction:: quantum_safe.signatures.algorithms.get_algorithm_spec

.. autofunction:: quantum_safe.signatures.algorithms.canonical_hybrid_name

.. autofunction:: quantum_safe.signatures.algorithms.parse_hybrid_name

.. autofunction:: quantum_safe.signatures.algorithms.validate_hybrid_combination

