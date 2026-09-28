"""
Compliance profiles for externally-mandated cryptographic requirements.

Each profile encodes requirements from a named external source rather than this
project's own judgement about what is appropriate, so that a claim of the form
"this configuration meets X" can be checked instead of asserted.

Currently provided:

``cnsa2``
    NSA Commercial National Security Algorithm Suite 2.0 parameter sets.

Every profile in this package reports parameter selection only. None of them
constitutes a FIPS 140-3 / CMVP validation, which is an outcome of testing by an
accredited laboratory and cannot be produced by self-assessment.
"""

from quantum_safe.compliance.cnsa2 import (
    CNSA2_HASHES,
    CNSA2_KEM,
    CNSA2_SIGNATURE,
    CNSA2_SYMMETRIC,
    CheckResult,
    ComplianceReport,
    Finding,
    enforce,
    report,
)

__all__ = [
    "CNSA2_HASHES",
    "CNSA2_KEM",
    "CNSA2_SIGNATURE",
    "CNSA2_SYMMETRIC",
    "CheckResult",
    "ComplianceReport",
    "Finding",
    "enforce",
    "report",
]
