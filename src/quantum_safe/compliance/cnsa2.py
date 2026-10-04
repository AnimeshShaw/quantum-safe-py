"""
CNSA 2.0 compliance profile.

The NSA's Commercial National Security Algorithm Suite 2.0 mandates specific
parameter sets, not merely specific algorithm families. A deployment that selects
ML-KEM-768 is using a FIPS 203 algorithm and is still not CNSA 2.0 compliant,
because the suite requires ML-KEM-1024.

This module makes that distinction enforceable rather than a documentation note.
It exists because the library's own defaults (ML-KEM-768, ML-DSA-65) sit below
the suite, so "uses post-quantum algorithms" and "meets CNSA 2.0" are different
claims and the library previously had no way to express the difference.

Requirements encoded here
-------------------------
======================  =========================================
Purpose                 CNSA 2.0 requirement
======================  =========================================
Key establishment       ML-KEM-1024 (FIPS 203)
Signatures              ML-DSA-87 (FIPS 204)
Symmetric encryption    AES-256
Hashing                 SHA-384 or SHA-512
Software/firmware sign  LMS or XMSS (SP 800-208)
======================  =========================================

Deadlines, for reporting rather than enforcement: software and firmware signing
and networking equipment exclusively CNSA 2.0 by 2030; web, cloud and operating
systems by 2033; the National Security Systems transition complete by 2035.

Scope limit, stated plainly
---------------------------
Selecting compliant parameter sets is necessary for CNSA 2.0 and nowhere near
sufficient. CNSA 2.0 compliance for National Security Systems runs through
FIPS 140-3 validated modules, which is a CMVP outcome from an accredited
laboratory. This library is not a validated module and this profile does not make
it one. What the profile does is stop a deployment from silently sitting below
the mandated parameter sets. :func:`report` says so in its output rather than
leaving a reader to infer it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance at runtime
    from quantum_safe.kem.core import KEM
    from quantum_safe.kem.hybrid import HybridKEM
    from quantum_safe.signatures.core import Sign
    from quantum_safe.signatures.hybrid import HybridSign

# Key establishment and signature parameter sets required by the suite.
CNSA2_KEM = "ML-KEM-1024"
CNSA2_SIGNATURE = "ML-DSA-87"
CNSA2_SYMMETRIC = "AES-256"
CNSA2_HASHES = ("SHA-384", "SHA-512")

# SP 800-208 stateful hash-based schemes, required for software and firmware
# signing. Not implemented by this library; see UNSUPPORTED_REQUIREMENTS.
CNSA2_CODE_SIGNING = ("LMS", "XMSS")

# Hybrid operation is optional under CNSA 2.0: NSA accepts standalone
# ML-KEM-1024 / ML-DSA-87. Where a National Security System does use a hybrid,
# its classical half must itself be a CNSA (1.0) algorithm, i.e. ECDH / ECDSA
# on P-384. X25519, P-256 and Ed25519 are not CNSA algorithms, so a hybrid
# built on them meets the post-quantum requirement but not the suite as a whole
# and is reported PARTIAL. Classical names outside both sets are reported
# NON_COMPLIANT rather than guessed.
_CNSA1_CLASSICAL = frozenset({"P-384"})
_NON_CNSA_CLASSICAL = frozenset({"X25519", "X448", "P-256", "Ed25519", "Ed448"})

# Classical partners hybrid_kem() can build. HybridKEM implements X25519 and
# P-256 only; P-384 is not offered until it is implemented. Note that these
# hybrids are reported PARTIAL (see above); pqc_kem() is the compliant choice.
CNSA2_HYBRID_CLASSICAL = ("X25519",)

#: Why the software/firmware signing requirement is still only partly met.
CODE_SIGNING_STATUS: dict[str, str] = {
    "lms": (
        "LMS (RFC 8554) is available via the optional [lms] extra, in "
        "quantum_safe.signatures.stateful. LMS is stateful: reusing a one-time "
        "key index compromises every signature under that key, so the wrapper "
        "requires a durable state store and refuses rewound keys."
    ),
    "xmss": (
        "XMSS (RFC 8391) is not implemented. SP 800-208 approves both LMS and "
        "XMSS, so either satisfies the algorithm requirement; only LMS is offered "
        "here."
    ),
    "validation": (
        "SP 800-208 also requires that key generation occur inside a validated "
        "cryptographic module. That is a property of the deployment, not of this "
        "library, and providing the algorithm does not satisfy it."
    ),
}


def lms_available() -> bool:
    """Whether the optional LMS dependency is installed."""
    try:
        import pyhsslms  # noqa: F401
    except ImportError:
        return False
    return True


class Finding(str, Enum):
    """Outcome for one checked requirement."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non-compliant"
    NOT_COVERED = "not-covered"
    #: Capability present, but not on its own sufficient for the requirement.
    #: Counts against compliance, because reporting it as a pass would overstate
    #: what the library establishes.
    PARTIAL = "partial"


@dataclass(frozen=True)
class CheckResult:
    requirement: str
    finding: Finding
    detail: str
    expected: str | None = None
    actual: str | None = None

    @property
    def ok(self) -> bool:
        return self.finding is Finding.COMPLIANT


@dataclass
class ComplianceReport:
    """Result of evaluating a configuration against CNSA 2.0."""

    checks: list[CheckResult] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        """True only if every checked requirement passed.

        Requirements recorded as NOT_COVERED count against compliance. Treating
        an unimplemented requirement as neutral would let a report read as a
        pass while a mandated capability is absent.
        """
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.ok]

    def render(self) -> str:
        lines = [
            "CNSA 2.0 parameter-set report",
            "=" * 60,
        ]
        for c in self.checks:
            mark = {
                Finding.COMPLIANT: "PASS",
                Finding.NON_COMPLIANT: "FAIL",
                Finding.NOT_COVERED: "GAP ",
                Finding.PARTIAL: "PART",
            }[c.finding]
            lines.append(f"  [{mark}] {c.requirement}")
            lines.append(f"         {c.detail}")
        lines.append("=" * 60)
        lines.append(
            "OVERALL: compliant parameter selection"
            if self.compliant
            else f"OVERALL: NOT compliant ({len(self.failures)} issue(s))"
        )
        lines.append(
            "This reports parameter selection only. CNSA 2.0 compliance for "
            "National Security Systems runs through FIPS 140-3 validated modules; "
            "this library is not a validated module and this report is not a "
            "validation."
        )
        return "\n".join(lines)


def _check_pqc_selection(
    requirement: str, algorithm: str, required: str, lower_note: str = ""
) -> CheckResult:
    """Evaluate a pure or ``classical+pqc`` algorithm name against one requirement.

    The whole name is validated: the PQC half must be the required parameter
    set, and a hybrid's classical half must be a CNSA 1.0 algorithm (P-384) to
    pass, a known non-CNSA algorithm to be PARTIAL, and anything else is
    NON_COMPLIANT.
    """
    parts = algorithm.split("+")
    if len(parts) > 2 or any(not p for p in parts):
        return CheckResult(
            requirement=requirement,
            finding=Finding.NON_COMPLIANT,
            detail=f"{algorithm!r} is not a recognised algorithm or classical+pqc hybrid name.",
            expected=required,
            actual=algorithm,
        )
    pqc = parts[-1]
    if pqc != required:
        return CheckResult(
            requirement=requirement,
            finding=Finding.NON_COMPLIANT,
            detail=f"{algorithm} resolves to {pqc}; CNSA 2.0 requires {required}.{lower_note}",
            expected=required,
            actual=pqc,
        )
    if len(parts) == 1:
        return CheckResult(
            requirement=requirement,
            finding=Finding.COMPLIANT,
            detail=f"{algorithm} is the required parameter set.",
            expected=required,
            actual=pqc,
        )
    classical = parts[0]
    if classical in _CNSA1_CLASSICAL:
        return CheckResult(
            requirement=requirement,
            finding=Finding.COMPLIANT,
            detail=(
                f"{algorithm} pairs {required} with {classical}, a CNSA 1.0 algorithm. "
                f"(Hybrids with {classical} are not implemented by this library.)"
            ),
            expected=required,
            actual=algorithm,
        )
    if classical in _NON_CNSA_CLASSICAL:
        return CheckResult(
            requirement=requirement,
            finding=Finding.PARTIAL,
            detail=(
                f"{algorithm}: the post-quantum half is {required}, as required, but "
                f"{classical} is not a CNSA algorithm. Hybrid operation is optional "
                f"under CNSA 2.0; where used, the classical half must be CNSA 1.0 "
                f"(P-384). Standalone {required} meets the requirement."
            ),
            expected=required,
            actual=algorithm,
        )
    return CheckResult(
        requirement=requirement,
        finding=Finding.NON_COMPLIANT,
        detail=f"{algorithm}: classical component {classical!r} is not a recognised algorithm.",
        expected=required,
        actual=algorithm,
    )


def check_kem(algorithm: str) -> CheckResult:
    """Check a KEM selection (pure ``ML-KEM-1024`` or a ``classical+pqc`` hybrid)."""
    return _check_pqc_selection(
        "Key establishment",
        algorithm,
        CNSA2_KEM,
        " Lower parameter sets are FIPS 203 algorithms but are not this suite.",
    )


def check_signature(algorithm: str) -> CheckResult:
    """Check a signature selection (pure ``ML-DSA-87`` or a ``classical+pqc`` hybrid)."""
    return _check_pqc_selection("Signatures", algorithm, CNSA2_SIGNATURE)


def check_key_derivation(kem: str) -> CheckResult:
    """Check the hash this library uses to derive keys for a KEM selection.

    CNSA 2.0 requires SHA-384 or SHA-512 wherever a hash is used. This library's
    hybrid combiner and v1 envelopes use HKDF-SHA-256, so any hybrid selection
    fails this requirement. A pure ML-KEM-1024 envelope (envelope v2) derives its
    key with HKDF-SHA-384.
    """
    requirement = "Key-derivation hash (this library)"
    expected = " or ".join(CNSA2_HASHES)
    if kem == CNSA2_KEM:
        return CheckResult(
            requirement=requirement,
            finding=Finding.COMPLIANT,
            detail="A pure ML-KEM-1024 envelope (envelope v2) derives its key with HKDF-SHA-384.",
            expected=expected,
            actual="SHA-384",
        )
    return CheckResult(
        requirement=requirement,
        finding=Finding.NON_COMPLIANT,
        detail=(
            f"{kem}: this library's hybrid combiner and v1 envelopes derive keys with "
            "HKDF-SHA-256, kept for byte-compatibility, but CNSA 2.0 requires SHA-384 or "
            "SHA-512. A pure ML-KEM-1024 envelope (envelope v2) uses HKDF-SHA-384."
        ),
        expected=expected,
        actual="SHA-256",
    )


def check_hash(algorithm: str) -> CheckResult:
    normalised = algorithm.upper().replace("SHA", "SHA-").replace("SHA--", "SHA-")
    if normalised in CNSA2_HASHES:
        return CheckResult(
            requirement="Hashing",
            finding=Finding.COMPLIANT,
            detail=f"{algorithm} is permitted.",
            expected=" or ".join(CNSA2_HASHES),
            actual=normalised,
        )
    return CheckResult(
        requirement="Hashing",
        finding=Finding.NON_COMPLIANT,
        detail=f"{algorithm} is not permitted; CNSA 2.0 requires SHA-384 or SHA-512.",
        expected=" or ".join(CNSA2_HASHES),
        actual=normalised,
    )


def report(
    kem: str | None = None,
    signature: str | None = None,
    hash_algorithm: str | None = None,
    include_code_signing: bool = True,
    include_key_derivation: bool = True,
) -> ComplianceReport:
    """Evaluate a configuration against the CNSA 2.0 parameter requirements.

    Args:
        kem: KEM or hybrid KEM algorithm name, e.g. ``"X25519+ML-KEM-1024"``.
        signature: signature or hybrid signature algorithm name.
        hash_algorithm: hash used for key derivation and signing.
        include_code_signing: whether to evaluate the SP 800-208 software and
            firmware signing requirement. Leave enabled unless the deployment
            provably does not sign software or firmware, since omitting it
            produces a report that looks cleaner than the deployment is.
        include_key_derivation: whether to evaluate this library's own key
            derivation hash for the ``kem`` selection (default True when
            ``kem`` is given); see :func:`check_key_derivation`.
    """
    rep = ComplianceReport()
    if kem is not None:
        rep.checks.append(check_kem(kem))
    if signature is not None:
        rep.checks.append(check_signature(signature))
    if hash_algorithm is not None:
        rep.checks.append(check_hash(hash_algorithm))
    if kem is not None and include_key_derivation:
        rep.checks.append(check_key_derivation(kem))
    if include_code_signing:
        if lms_available():
            rep.checks.append(
                CheckResult(
                    requirement="Software/firmware signing (SP 800-208)",
                    finding=Finding.PARTIAL,
                    detail=(f"{CODE_SIGNING_STATUS['lms']} {CODE_SIGNING_STATUS['validation']}"),
                    expected=" or ".join(CNSA2_CODE_SIGNING),
                    actual="LMS (available)",
                )
            )
        else:
            rep.checks.append(
                CheckResult(
                    requirement="Software/firmware signing (SP 800-208)",
                    finding=Finding.NOT_COVERED,
                    detail=(
                        "CNSA 2.0 requires LMS or XMSS (SP 800-208). LMS is supported "
                        "but its optional dependency is not installed: "
                        "pip install 'quantum-safe-py[lms]'. " + CODE_SIGNING_STATUS["validation"]
                    ),
                    expected=" or ".join(CNSA2_CODE_SIGNING),
                    actual=None,
                )
            )
    return rep


def enforce(
    kem: str | None = None,
    signature: str | None = None,
    strict: bool = False,
) -> None:
    """Raise if the given selections fall below CNSA 2.0 parameter requirements.

    By default this is a guard on the post-quantum *parameter sets*: it raises
    for ML-KEM-768 / ML-DSA-65 and for unrecognised names, and lets a hybrid
    whose post-quantum half is right (``X25519+ML-KEM-1024``) pass, although
    :func:`report` calls that PARTIAL. Pass ``strict=True`` to also refuse
    anything :func:`report` does not call compliant, for example in a CI gate.
    The behaviour matches ``cnsa2.enforce`` in quantum-safe-ts.

    Code signing and key-derivation hashes are not evaluated here; this is not
    a compliance certificate (see :func:`report`).

    Raises:
        ValueError: if a selection does not meet the requirement.
    """
    failures: list[str] = []
    for check, selection in ((check_kem, kem), (check_signature, signature)):
        if selection is None:
            continue
        result = check(selection)
        if result.finding is Finding.NON_COMPLIANT or (strict and not result.ok):
            failures.append(result.detail)
    if failures:
        raise ValueError(f"configuration is not CNSA 2.0 compliant: {'; '.join(failures)}")


# ---------------------------------------------------------------------------
# Configured constructors
# ---------------------------------------------------------------------------
#
# A report that says "not compliant" without handing back a compliant
# configuration leaves the reader to work out the parameter names themselves,
# which is where mistakes happen. These build the objects directly.


def pqc_kem(backend: str = "auto") -> KEM:
    """Return a standalone ML-KEM-1024 KEM: the compliant key-establishment choice.

    CNSA 2.0 accepts standalone ML-KEM-1024; hybrid operation is optional.
    """
    from quantum_safe.kem.core import KEM

    return KEM(CNSA2_KEM, backend=backend)


def pqc_sign(backend: str = "auto", hedged: bool = True) -> Sign:
    """Return a standalone ML-DSA-87 signer: the compliant signature choice."""
    from quantum_safe.signatures.core import Sign

    return Sign(CNSA2_SIGNATURE, backend=backend, hedged=hedged)


def hybrid_kem(classical: str = "X25519", backend: str = "auto") -> HybridKEM:
    """Return a HybridKEM with ML-KEM-1024 as its post-quantum half.

    Equivalent to ``HybridKEM(classical=classical, pqc="ML-KEM-1024")``, with the
    parameter set pinned so that a future change to the library default cannot
    silently move a CNSA-2.0-targeted deployment below the suite.

    The result is reported PARTIAL, not compliant: CNSA 2.0 requires a hybrid's
    classical half to be a CNSA 1.0 algorithm (P-384), which HybridKEM does not
    implement. Use :func:`pqc_kem` for a compliant configuration.

    Args:
        classical: classical partner; a value from :data:`CNSA2_HYBRID_CLASSICAL`.
        backend: backend selector, forwarded unchanged.
    """
    from quantum_safe.kem.hybrid import HybridKEM

    if classical not in CNSA2_HYBRID_CLASSICAL:
        raise ValueError(
            f"classical partner {classical!r} is not available for a CNSA 2.0 hybrid "
            f"here; choose from {CNSA2_HYBRID_CLASSICAL}, or use pqc_kem()"
        )
    return HybridKEM(classical=classical, pqc=CNSA2_KEM, backend=backend)


def hybrid_sign(
    classical: str = "Ed25519", backend: str = "auto", hedged: bool = True
) -> HybridSign:
    """Return a HybridSign with ML-DSA-87 as its post-quantum half.

    Equivalent to ``HybridSign(classical=classical, pqc="ML-DSA-87")`` with the
    parameter set pinned. Reported PARTIAL, not compliant: Ed25519 and P-256
    are not CNSA algorithms. Use :func:`pqc_sign` for a compliant
    configuration. Hedged signing is left enabled by default.
    """
    from quantum_safe.signatures.hybrid import HybridSign

    return HybridSign(classical=classical, pqc=CNSA2_SIGNATURE, backend=backend, hedged=hedged)


def describe() -> str:
    """Return the concrete steps to move a deployment onto CNSA 2.0 parameters."""
    return "\n".join(
        [
            "To select CNSA 2.0 parameter sets:",
            "",
            "  from quantum_safe.compliance import cnsa2",
            "  kem    = cnsa2.pqc_kem()         # ML-KEM-1024",
            "  signer = cnsa2.pqc_sign()        # ML-DSA-87",
            "",
            "Or explicitly, without this module:",
            "",
            f'  KEM("{CNSA2_KEM}")',
            f'  Sign("{CNSA2_SIGNATURE}")',
            "",
            "Hybrids (cnsa2.hybrid_kem(), cnsa2.hybrid_sign()) carry the required",
            "post-quantum parameter set but are reported PARTIAL: CNSA 2.0 makes",
            "hybrid optional and requires a hybrid's classical half to be CNSA 1.0",
            "(P-384); X25519, P-256 and Ed25519 are not.",
            "",
            f"Use {' or '.join(CNSA2_HASHES)} for hashing and {CNSA2_SYMMETRIC} for",
            "symmetric encryption.",
            "",
            "Two things this does NOT give you:",
            "",
            f"  1. Software and firmware signing in full. CNSA 2.0 requires "
            f"{' or '.join(CNSA2_CODE_SIGNING)} (SP 800-208);",
            "     LMS is available via the optional [lms] extra, XMSS is not, and",
            "     SP 800-208 key generation must happen in a validated module.",
            "  2. Validation. CNSA 2.0 compliance for National Security Systems runs",
            "     through FIPS 140-3 validated modules. Selecting the right parameters",
            "     is necessary and not sufficient, and no self-assessment produces a",
            "     CMVP certificate.",
        ]
    )
