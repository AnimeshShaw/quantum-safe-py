"""
quantum_safe.signatures
~~~~~~~~~~~~~~~~~~~~~~~~

Digital signature schemes — classical, PQC, and hybrid.

Public API:
  HybridSign  — hybrid Ed25519+ML-DSA (recommended for production)
  Sign        — single PQC algorithm (benchmarking / protocol testing)
"""

from quantum_safe.signatures.algorithms import (
    SIGNATURE_ALGORITHMS,
    HYBRID_SIGNATURE_COMBINATIONS,
    DEFAULT_HYBRID_CLASSICAL,
    DEFAULT_HYBRID_PQC,
    DEFAULT_SINGLE_PQC,
    canonical_hybrid_name,
    get_algorithm_spec,
)
from quantum_safe.signatures.core import Sign
from quantum_safe.signatures.hybrid import HybridSign

__all__ = [
    "Sign",
    "HybridSign",
    "SIGNATURE_ALGORITHMS",
    "HYBRID_SIGNATURE_COMBINATIONS",
    "DEFAULT_HYBRID_CLASSICAL",
    "DEFAULT_HYBRID_PQC",
    "DEFAULT_SINGLE_PQC",
    "canonical_hybrid_name",
    "get_algorithm_spec",
]
