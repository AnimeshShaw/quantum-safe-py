"""
quantum_safe.kem.algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Algorithm registry and security policy for KEM operations.

This module is the single source of truth for:
  - Which algorithms are supported
  - What their security levels are
  - Which combinations are valid for hybrid mode
  - What the minimum acceptable security level is

If you want to allow or disallow an algorithm library-wide, this is where
to do it — not scattered across multiple backend files.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class NISTLevel(IntEnum):
    """NIST security categories from FIPS 203/204/205.

    Each level is defined as "at least as hard to break as":
      L1 → AES-128 key search
      L2 → SHA-256 / SHA3-256 collision search
      L3 → AES-192 key search
      L4 → SHA-384 / SHA3-384 collision search
      L5 → AES-256 key search
    """
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4
    L5 = 5


@dataclass(frozen=True)
class KEMAlgorithmSpec:
    """Everything the library needs to know about a KEM algorithm."""
    name: str
    nist_level: NISTLevel
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    is_nist_standard: bool          # True = FIPS 203
    suitable_for_hybrid: bool       # True = approved classical companion
    notes: str = ""


@dataclass(frozen=True)
class ClassicalKEMSpec:
    """Spec for a classical KEM used as the hybrid companion.

    We only support X25519 and P-256 as classical companions. RSA-OAEP is
    deliberately excluded — it's larger and slower and provides no meaningful
    additional security in the hybrid context.
    """
    name: str
    public_key_bytes: int       # ephemeral public key sent in ciphertext
    shared_secret_bytes: int    # X25519 and ECDH both produce 32 bytes


# ---------------------------------------------------------------------------
# PQC KEM algorithm registry
# ---------------------------------------------------------------------------

KEM_ALGORITHMS: dict[str, KEMAlgorithmSpec] = {
    "ML-KEM-512": KEMAlgorithmSpec(
        name="ML-KEM-512",
        nist_level=NISTLevel.L1,
        public_key_bytes=800,
        secret_key_bytes=1632,
        ciphertext_bytes=768,
        shared_secret_bytes=32,
        is_nist_standard=True,
        suitable_for_hybrid=True,
        notes=(
            "Smallest ML-KEM variant. Security level 1 is generally considered "
            "adequate for most applications today, but ML-KEM-768 is preferred "
            "for new deployments since the size difference is small."
        ),
    ),
    "ML-KEM-768": KEMAlgorithmSpec(
        name="ML-KEM-768",
        nist_level=NISTLevel.L3,
        public_key_bytes=1184,
        secret_key_bytes=2400,
        ciphertext_bytes=1088,
        shared_secret_bytes=32,
        is_nist_standard=True,
        suitable_for_hybrid=True,
        notes="Recommended default. Security level 3 matches X25519.",
    ),
    "ML-KEM-1024": KEMAlgorithmSpec(
        name="ML-KEM-1024",
        nist_level=NISTLevel.L5,
        public_key_bytes=1568,
        secret_key_bytes=3168,
        ciphertext_bytes=1568,
        shared_secret_bytes=32,
        is_nist_standard=True,
        suitable_for_hybrid=True,
        notes="Maximum security. Use when long-term key confidentiality is critical.",
    ),
    # Research / non-standard algorithms — not recommended for production
    "BIKE-L1": KEMAlgorithmSpec(
        name="BIKE-L1",
        nist_level=NISTLevel.L1,
        public_key_bytes=1541,
        secret_key_bytes=3114,
        ciphertext_bytes=1573,
        shared_secret_bytes=32,
        is_nist_standard=False,
        suitable_for_hybrid=False,
        notes="NIST Round 4 candidate. Not standardized.",
    ),
    "HQC-128": KEMAlgorithmSpec(
        name="HQC-128",
        nist_level=NISTLevel.L1,
        public_key_bytes=2249,
        secret_key_bytes=2289,
        ciphertext_bytes=4433,
        shared_secret_bytes=64,
        is_nist_standard=False,
        suitable_for_hybrid=False,
        notes="NIST Round 4 candidate. Not standardized.",
    ),
}

# Classical companion specs
CLASSICAL_KEM_ALGORITHMS: dict[str, ClassicalKEMSpec] = {
    "X25519": ClassicalKEMSpec(
        name="X25519",
        public_key_bytes=32,
        shared_secret_bytes=32,
    ),
    "P-256": ClassicalKEMSpec(
        name="P-256",
        public_key_bytes=65,   # uncompressed point
        shared_secret_bytes=32,
    ),
}

# Valid hybrid combinations: classical_name -> [pqc_name, ...]
# The IETF hybrid-design draft specifies exactly these combinations.
HYBRID_COMBINATIONS: dict[str, list[str]] = {
    "X25519": ["ML-KEM-768", "ML-KEM-512", "ML-KEM-1024"],
    "P-256":  ["ML-KEM-512", "ML-KEM-768"],
}

# The default hybrid: X25519 + ML-KEM-768, as recommended by
# NIST, CISA, BSI, and NCSC transition guidance documents.
DEFAULT_HYBRID_CLASSICAL = "X25519"
DEFAULT_HYBRID_PQC = "ML-KEM-768"

# Minimum NIST level we'll use in non-strict mode.
# Algorithms below this need explicit opt-in via allow_low_security=True.
MINIMUM_NIST_LEVEL = NISTLevel.L1


def canonical_hybrid_name(classical: str, pqc: str) -> str:
    """Return the canonical algorithm string for a hybrid combination.

    Example: canonical_hybrid_name("X25519", "ML-KEM-768") -> "X25519+ML-KEM-768"
    """
    return f"{classical}+{pqc}"


def parse_hybrid_name(name: str) -> tuple[str, str]:
    """Parse a hybrid algorithm name into (classical, pqc) components.

    Raises ValueError if the name doesn't look like a hybrid name.
    """
    if "+" not in name:
        raise ValueError(
            f"'{name}' is not a hybrid algorithm name (expected 'Classical+PQC')"
        )
    parts = name.split("+", 1)
    return parts[0], parts[1]


def validate_hybrid_combination(classical: str, pqc: str) -> None:
    """Raise ValueError if the combination is not approved.

    We don't block unapproved combinations entirely (a researcher might have
    a legitimate reason), but we raise by default so callers have to be
    explicit about using a non-standard combination.
    """
    if classical not in CLASSICAL_KEM_ALGORITHMS:
        raise ValueError(
            f"Classical KEM '{classical}' is not supported. "
            f"Valid options: {list(CLASSICAL_KEM_ALGORITHMS)}"
        )
    if pqc not in KEM_ALGORITHMS:
        raise ValueError(
            f"PQC KEM '{pqc}' is not in the algorithm registry. "
            f"Valid options: {list(KEM_ALGORITHMS)}"
        )
    approved_pqc = HYBRID_COMBINATIONS.get(classical, [])
    if pqc not in approved_pqc:
        raise ValueError(
            f"Combination '{classical}+{pqc}' is not an approved hybrid combination. "
            f"Approved PQC algorithms for {classical}: {approved_pqc}. "
            f"Pass validate=False to override."
        )


def get_algorithm_spec(name: str) -> KEMAlgorithmSpec:
    """Return the spec for a PQC algorithm, raising UnsupportedAlgorithm if unknown."""
    spec = KEM_ALGORITHMS.get(name)
    if spec is None:
        from quantum_safe.exceptions import UnsupportedAlgorithm
        raise UnsupportedAlgorithm(name, available=list(KEM_ALGORITHMS))
    return spec
