"""
quantum_safe.signatures.algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Algorithm registry and security policy for signature operations.

Mirrors the structure of kem/algorithms.py — one canonical registry, one
source of truth for key sizes, one place to add new algorithms.

A note on SLH-DSA (SPHINCS+):
  SLH-DSA has two variants per security level: "small" (s) and "fast" (f).
  - Small variant: smaller signatures, much slower to sign (~10-100x).
  - Fast variant: larger signatures, fast to sign.
  For most applications, use ML-DSA. SLH-DSA is valuable when you want
  a backup signature scheme with completely different mathematical foundations
  (hash-based rather than lattice-based).

A note on hedged signing:
  FIPS 204 §5.2 allows both deterministic and randomized (hedged) signing.
  We default to hedged: sign(H(rand || msg)) rather than sign(msg).
  This prevents fault injection attacks where an attacker induces computation
  errors to recover the secret key from two signatures on the same message.
  Hedged mode is the safer default; pure deterministic mode requires
  explicit opt-in.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class NISTLevel(IntEnum):
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4
    L5 = 5


@dataclass(frozen=True)
class SignatureAlgorithmSpec:
    """Everything the library needs to know about a signature algorithm."""

    name: str
    nist_level: NISTLevel
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int  # maximum signature size
    is_nist_standard: bool  # True = FIPS 204 or FIPS 205
    is_lattice_based: bool  # ML-DSA = True, SLH-DSA = False
    supports_context: bool  # True if context param is part of the standard
    sign_speed: str  # "fast", "medium", "slow" — indicative only
    notes: str = ""


@dataclass(frozen=True)
class ClassicalSignatureSpec:
    """Spec for a classical signature used as the hybrid companion."""

    name: str
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int


# ---------------------------------------------------------------------------
# PQC signature algorithm registry
# ---------------------------------------------------------------------------

SIGNATURE_ALGORITHMS: dict[str, SignatureAlgorithmSpec] = {
    # ML-DSA (FIPS 204) — lattice-based, fast
    "ML-DSA-44": SignatureAlgorithmSpec(
        name="ML-DSA-44",
        nist_level=NISTLevel.L2,
        public_key_bytes=1312,
        secret_key_bytes=2560,
        signature_bytes=2420,
        is_nist_standard=True,
        is_lattice_based=True,
        supports_context=True,
        sign_speed="fast",
        notes="FIPS 204 level 2. Smallest ML-DSA variant. Use when key/sig size matters most.",
    ),
    "ML-DSA-65": SignatureAlgorithmSpec(
        name="ML-DSA-65",
        nist_level=NISTLevel.L3,
        public_key_bytes=1952,
        secret_key_bytes=4032,
        signature_bytes=3309,
        is_nist_standard=True,
        is_lattice_based=True,
        supports_context=True,
        sign_speed="fast",
        notes="FIPS 204 level 3. Recommended default for most applications.",
    ),
    "ML-DSA-87": SignatureAlgorithmSpec(
        name="ML-DSA-87",
        nist_level=NISTLevel.L5,
        public_key_bytes=2592,
        secret_key_bytes=4896,
        signature_bytes=4627,
        is_nist_standard=True,
        is_lattice_based=True,
        supports_context=True,
        sign_speed="fast",
        notes="FIPS 204 level 5. Maximum security.",
    ),
    # SLH-DSA (FIPS 205) — hash-based, large sigs, different math than ML-DSA.
    # All twelve parameter sets (2 hash families x 3 security levels x 2 variants) are added below
    # from _SLH_DSA_SETS, in the order SHAKE then SHA2.
}

# FIPS 205, Table 2 (sizes in bytes). Public key, secret key, signature, NIST level.
_SLH_DSA_SETS: dict[str, tuple[int, int, int, NISTLevel]] = {
    "128s": (32, 64, 7856, NISTLevel.L1),
    "128f": (32, 64, 17088, NISTLevel.L1),
    "192s": (48, 96, 16224, NISTLevel.L3),
    "192f": (48, 96, 35664, NISTLevel.L3),
    "256s": (64, 128, 29792, NISTLevel.L5),
    "256f": (64, 128, 49856, NISTLevel.L5),
}


def _register_slh_dsa() -> None:
    for family in ("SHAKE", "SHA2"):
        for variant, (pk, sk, sig, level) in _SLH_DSA_SETS.items():
            name = f"SLH-DSA-{family}-{variant}"
            small = variant.endswith("s")
            SIGNATURE_ALGORITHMS[name] = SignatureAlgorithmSpec(
                name=name,
                nist_level=level,
                public_key_bytes=pk,
                secret_key_bytes=sk,
                signature_bytes=sig,
                is_nist_standard=True,
                is_lattice_based=False,
                supports_context=True,
                sign_speed="slow" if small else "medium",
                notes=(
                    f"FIPS 205, {'small' if small else 'fast'} variant, level {int(level)}, "
                    f"{family}. "
                    + (
                        "Smaller signatures, very slow to sign (verification is fast)."
                        if small
                        else "Faster signing than the small variant, about 2x larger signatures."
                    )
                ),
            )


_register_slh_dsa()

# Classical signature companions for hybrid mode
CLASSICAL_SIGNATURE_ALGORITHMS: dict[str, ClassicalSignatureSpec] = {
    "Ed25519": ClassicalSignatureSpec(
        name="Ed25519",
        public_key_bytes=32,
        secret_key_bytes=32,
        signature_bytes=64,
    ),
    "P-256": ClassicalSignatureSpec(
        name="P-256",
        public_key_bytes=64,  # raw (x, y) coordinates
        secret_key_bytes=32,
        signature_bytes=72,  # DER-encoded ECDSA, max
    ),
}

# Valid hybrid combinations: classical -> [pqc, ...]
HYBRID_SIGNATURE_COMBINATIONS: dict[str, list[str]] = {
    "Ed25519": ["ML-DSA-65", "ML-DSA-44", "ML-DSA-87"],
    "P-256": ["ML-DSA-44", "ML-DSA-65"],
}

DEFAULT_HYBRID_CLASSICAL = "Ed25519"
# The default hybrid suite is the -v2 format (no hedging prefix, FIPS 204 native context,
# byte-compatible with quantum-safe-ts). The previous default, "ML-DSA-65" (the library's original
# prefix format), is unchanged and reachable under that identifier.
DEFAULT_HYBRID_PQC = "ML-DSA-65-v2"
DEFAULT_SINGLE_PQC = "ML-DSA-65"

# Hedged signing injects this many random bytes before the message.
# 32 bytes = 256 bits, well above any NIST requirement.
HEDGED_RANDOMNESS_BYTES = 32


def canonical_hybrid_name(classical: str, pqc: str) -> str:
    return f"{classical}+{pqc}"


def parse_hybrid_name(name: str) -> tuple[str, str]:
    if "+" not in name:
        raise ValueError(
            f"'{name}' is not a hybrid signature algorithm name (expected 'Classical+PQC')"
        )
    parts = name.split("+", 1)
    return parts[0], parts[1]


def validate_hybrid_combination(classical: str, pqc: str) -> None:
    if classical not in CLASSICAL_SIGNATURE_ALGORITHMS:
        raise ValueError(
            f"Classical signature algorithm '{classical}' is not supported. "
            f"Valid options: {list(CLASSICAL_SIGNATURE_ALGORITHMS)}"
        )
    if pqc not in SIGNATURE_ALGORITHMS:
        raise ValueError(
            f"PQC signature algorithm '{pqc}' is not in the registry. "
            f"Valid options: {list(SIGNATURE_ALGORITHMS)}"
        )
    approved = HYBRID_SIGNATURE_COMBINATIONS.get(classical, [])
    if pqc not in approved:
        raise ValueError(
            f"Combination '{classical}+{pqc}' is not an approved hybrid. "
            f"Approved PQC algorithms for {classical}: {approved}. "
            f"Pass validate=False to override."
        )


def get_algorithm_spec(name: str) -> SignatureAlgorithmSpec:
    spec = SIGNATURE_ALGORITHMS.get(name)
    if spec is None:
        from quantum_safe.exceptions import UnsupportedAlgorithm

        raise UnsupportedAlgorithm(name, available=list(SIGNATURE_ALGORITHMS))
    return spec
