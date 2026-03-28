KEM (``quantum_safe.kem``)
==========================

Key encapsulation mechanisms.  The high-level entry point is
:class:`~quantum_safe.kem.hybrid.HybridKEM`.

.. autoclass:: quantum_safe.kem.hybrid.HybridKEM
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.kem.core.KEM
   :members:
   :show-inheritance:

Algorithm registry
------------------

.. autofunction:: quantum_safe.kem.algorithms.get_algorithm_spec

.. autofunction:: quantum_safe.kem.algorithms.canonical_hybrid_name

.. autofunction:: quantum_safe.kem.algorithms.parse_hybrid_name

.. autofunction:: quantum_safe.kem.algorithms.validate_hybrid_combination

