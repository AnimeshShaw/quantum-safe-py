"""
quantum_safe.audit
~~~~~~~~~~~~~~~~~~~

Compliance auditing, SBOM enrichment, and CI gate tooling.

This module sits above the migrate.scanner — it takes scan results and
turns them into structured compliance artefacts that security teams,
auditors, and CI pipelines can consume directly.

Submodules
----------
auditor     Core Auditor class — orchestrates scanning and report generation
policy      Policy-as-code: configurable rules for what constitutes a failure
sbom        CycloneDX SBOM enrichment with PQC-readiness annotations
compliance  NIST SP 800-208 and FIPS 203/204/205 compliance report generation
cli         qs-audit command-line interface

Quick start::

    from quantum_safe.audit import Auditor, AuditPolicy

    policy = AuditPolicy(
        min_security_level=3,
        allow_classical_only=False,
        hybrid_required=True,
        fail_on=["HIGH", "CRITICAL"],
    )
    report = Auditor.audit("./src", policy=policy)

    if report.policy_violations:
        print(report.to_json())
        sys.exit(1)
"""

from quantum_safe.audit.auditor import Auditor, AuditReport
from quantum_safe.audit.compliance import ComplianceReport, NISTComplianceChecker
from quantum_safe.audit.policy import AuditPolicy, PolicyViolation
from quantum_safe.audit.sbom import PQCReadiness, SBOMEnricher

__all__ = [
    "Auditor",
    "AuditReport",
    "AuditPolicy",
    "PolicyViolation",
    "SBOMEnricher",
    "PQCReadiness",
    "ComplianceReport",
    "NISTComplianceChecker",
]
