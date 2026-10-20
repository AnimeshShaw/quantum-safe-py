"""
quantum_safe.kem
~~~~~~~~~~~~~~~~

Key Encapsulation Mechanisms (KEMs) — classical, PQC, and hybrid.

Public API:
  HybridKEM  — hybrid X25519+ML-KEM (recommended for production)
  KEM        — single PQC algorithm (benchmarking / protocol testing)
  XWing      — X-Wing (draft-connolly-cfrg-xwing-kem), ML-KEM-768 + X25519
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
from quantum_safe.kem.xwing import XWing

__all__ = [
    "KEM",
    "HybridKEM",
    "XWing",
    "KEM_ALGORITHMS",
    "HYBRID_COMBINATIONS",
    "DEFAULT_HYBRID_CLASSICAL",
    "DEFAULT_HYBRID_PQC",
    "canonical_hybrid_name",
    "get_algorithm_spec",
]
