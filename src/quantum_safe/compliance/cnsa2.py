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
    from quantum_safe.kem.hybrid import HybridKEM
    from quantum_safe.signatures.hybrid import HybridSign

# Key establishment and signature parameter sets required by the suite.
CNSA2_KEM = "ML-KEM-1024"
CNSA2_SIGNATURE = "ML-DSA-87"
CNSA2_SYMMETRIC = "AES-256"
CNSA2_HASHES = ("SHA-384", "SHA-512")

# SP 800-208 stateful hash-based schemes, required for software and firmware
# signing. Not implemented by this library; see UNSUPPORTED_REQUIREMENTS.
CNSA2_CODE_SIGNING = ("LMS", "XMSS")

# Classical partners permitted in a hybrid construction during the transition.
# CNSA 2.0 does not mandate hybrid operation, but does not forbid it either, and
# the transition guidance expects hybrid deployment in this period.
CNSA2_HYBRID_CLASSICAL = ("X25519", "P-384")

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


def check_kem(algorithm: str) -> CheckResult:
    """Check a KEM selection, accepting a hybrid whose PQC half is compliant."""
    pqc = algorithm.split("+")[-1] if "+" in algorithm else algorithm
    if pqc == CNSA2_KEM:
        return CheckResult(
            requirement="Key establishment",
            finding=Finding.COMPLIANT,
            detail=f"{algorithm} uses {CNSA2_KEM}.",
            expected=CNSA2_KEM,
            actual=pqc,
        )
    return CheckResult(
        requirement="Key establishment",
        finding=Finding.NON_COMPLIANT,
        detail=(
            f"{algorithm} resolves to {pqc}; CNSA 2.0 requires {CNSA2_KEM}. "
            f"Lower parameter sets are FIPS 203 algorithms but are not this suite."
        ),
        expected=CNSA2_KEM,
        actual=pqc,
    )


def check_signature(algorithm: str) -> CheckResult:
    """Check a signature selection, accepting a hybrid whose PQC half complies."""
    pqc = algorithm.split("+")[-1] if "+" in algorithm else algorithm
    if pqc == CNSA2_SIGNATURE:
        return CheckResult(
            requirement="Signatures",
            finding=Finding.COMPLIANT,
            detail=f"{algorithm} uses {CNSA2_SIGNATURE}.",
            expected=CNSA2_SIGNATURE,
            actual=pqc,
        )
    return CheckResult(
        requirement="Signatures",
        finding=Finding.NON_COMPLIANT,
        detail=(f"{algorithm} resolves to {pqc}; CNSA 2.0 requires {CNSA2_SIGNATURE}."),
        expected=CNSA2_SIGNATURE,
        actual=pqc,
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
    """
    rep = ComplianceReport()
    if kem is not None:
        rep.checks.append(check_kem(kem))
    if signature is not None:
        rep.checks.append(check_signature(signature))
    if hash_algorithm is not None:
        rep.checks.append(check_hash(hash_algorithm))
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


def enforce(kem: str | None = None, signature: str | None = None) -> None:
    """Raise if the given selections fall below CNSA 2.0 parameter requirements.

    Intended for a deployment that has decided it must be CNSA 2.0 aligned and
    wants a hard failure rather than a report. Code signing is not evaluated
    here: it cannot be satisfied by any selection this library offers, so
    including it would make every call raise.
    """
    rep = report(kem=kem, signature=signature, include_code_signing=False)
    if not rep.compliant:
        problems = "; ".join(c.detail for c in rep.failures)
        raise ValueError(f"configuration is not CNSA 2.0 compliant: {problems}")


# ---------------------------------------------------------------------------
# Configured constructors
# ---------------------------------------------------------------------------
#
# A report that says "not compliant" without handing back a compliant
# configuration leaves the reader to work out the parameter names themselves,
# which is where mistakes happen. These build the compliant objects directly.


def hybrid_kem(classical: str = "X25519", backend: str = "auto") -> HybridKEM:
    """Return a HybridKEM using the CNSA 2.0 key-establishment parameter set.

    Equivalent to ``HybridKEM(classical=classical, pqc="ML-KEM-1024")``, with the
    parameter set pinned so that a future change to the library default cannot
    silently move a CNSA-2.0-targeted deployment below the suite.

    Args:
        classical: classical partner for the hybrid construction. CNSA 2.0 does
            not mandate hybrid operation, but the transition guidance expects it
            in this period; pass a value from :data:`CNSA2_HYBRID_CLASSICAL`.
        backend: backend selector, forwarded unchanged.
    """
    from quantum_safe.kem.hybrid import HybridKEM

    if classical not in CNSA2_HYBRID_CLASSICAL:
        raise ValueError(
            f"classical partner {classical!r} is not in the CNSA 2.0 transition set "
            f"{CNSA2_HYBRID_CLASSICAL}"
        )
    return HybridKEM(classical=classical, pqc=CNSA2_KEM, backend=backend)


def hybrid_sign(
    classical: str = "Ed25519", backend: str = "auto", hedged: bool = True
) -> HybridSign:
    """Return a HybridSign using the CNSA 2.0 signature parameter set.

    Equivalent to ``HybridSign(classical=classical, pqc="ML-DSA-87")`` with the
    parameter set pinned. Hedged signing is left enabled by default: FIPS 204
    specifies it, and the timing variance it produces is key-independent.
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
            "  kem    = cnsa2.hybrid_kem()      # X25519 + ML-KEM-1024",
            "  signer = cnsa2.hybrid_sign()     # Ed25519 + ML-DSA-87",
            "",
            "Or explicitly, without this module:",
            "",
            f'  HybridKEM(pqc="{CNSA2_KEM}")',
            f'  HybridSign(pqc="{CNSA2_SIGNATURE}")',
            "",
            f"Use {' or '.join(CNSA2_HASHES)} for hashing and {CNSA2_SYMMETRIC} for",
            "symmetric encryption.",
            "",
            "Two things this does NOT give you:",
            "",
            f"  1. Software and firmware signing. CNSA 2.0 requires "
            f"{' or '.join(CNSA2_CODE_SIGNING)} (SP 800-208); this library",
            "     implements neither, so that requirement must be met elsewhere.",
            "  2. Validation. CNSA 2.0 compliance for National Security Systems runs",
            "     through FIPS 140-3 validated modules. Selecting the right parameters",
            "     is necessary and not sufficient, and no self-assessment produces a",
            "     CMVP certificate.",
        ]
    )
