"""
quantum_safe.kem
~~~~~~~~~~~~~~~~

Key Encapsulation Mechanisms (KEMs) — classical, PQC, and hybrid.

Public API:
  HybridKEM  — hybrid X25519+ML-KEM (recommended for production)
  KEM        — single PQC algorithm (benchmarking / protocol testing)
"""

from quantum_safe.kem.algorithms import (
    DEFAULT_HYBRID_CLASSICAL,
    DEFAULT_HYBRID_PQC,
    HYBRID_COMBINATIONS,
    KEM_ALGORITHMS,
    canonical_hybrid_name,
    get_algorithm_spec,
)
from quantum_safe.kem.core import KEM
from quantum_safe.kem.hybrid import HybridKEM

__all__ = [
    "KEM",
    "HybridKEM",
    "KEM_ALGORITHMS",
    "HYBRID_COMBINATIONS",
    "DEFAULT_HYBRID_CLASSICAL",
    "DEFAULT_HYBRID_PQC",
    "canonical_hybrid_name",
    "get_algorithm_spec",
]
