"""
quantum_safe.audit.compliance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

NIST SP 800-208 and FIPS 203/204/205 compliance report generation.

This module maps scanner findings to specific NIST guidance documents
so that a security team or auditor can trace each finding to a published
requirement. The output is a structured compliance report that maps to
the CISA Post-Quantum Cryptography Migration checklist.

References
----------
NIST SP 800-208:    Recommendation for Stateful Hash-Based Signature Schemes
FIPS 203:           Module-Lattice-Based Key-Encapsulation Mechanism Standard
FIPS 204:           Module-Lattice-Based Digital Signature Standard
FIPS 205:           Stateless Hash-Based Digital Signature Standard
CISA PQC Checklist: https://www.cisa.gov/quantum

Compliance levels
-----------------
COMPLIANT:          Meets all applicable requirements
PARTIAL:            Meets some requirements; specific gaps identified
NON_COMPLIANT:      Does not meet applicable requirements
NOT_APPLICABLE:     Requirement does not apply to this deployment
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

from quantum_safe.migrate.scanner import Finding, ScanReport, Severity


class ComplianceLevel(str, Enum):
    COMPLIANT = "COMPLIANT"
    PARTIAL = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class ComplianceControl:
    """A single compliance control / requirement.

    Attributes:
        control_id:     Identifier from the source standard (e.g. "FIPS203-6.1").
        standard:       The standard or guidance document.
        title:          Short title of the control.
        description:    Full description of the requirement.
        level:          Compliance level assessed for this control.
        evidence:       Specific evidence supporting the level assessment.
        remediation:    Steps to achieve compliance if not already compliant.
    """

    control_id: str
    standard: str
    title: str
    description: str
    level: ComplianceLevel
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "standard": self.standard,
            "title": self.title,
            "description": self.description,
            "level": self.level.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ComplianceReport:
    """Full NIST compliance report for a codebase.

    Attributes:
        generated_at:   ISO 8601 timestamp.
        target:         What was assessed.
        controls:       All evaluated controls.
        overall_level:  Rolled-up compliance level.
    """

    generated_at: str
    target: str
    controls: list[ComplianceControl]
    overall_level: ComplianceLevel
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def non_compliant_controls(self) -> list[ComplianceControl]:
        return [c for c in self.controls if c.level == ComplianceLevel.NON_COMPLIANT]

    @property
    def partial_controls(self) -> list[ComplianceControl]:
        return [c for c in self.controls if c.level == ComplianceLevel.PARTIAL]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "target": self.target,
            "overall_level": self.overall_level.value,
            "controls": [c.to_dict() for c in self.controls],
            "summary": {
                "total": len(self.controls),
                "compliant": sum(1 for c in self.controls if c.level == ComplianceLevel.COMPLIANT),
                "partial": len(self.partial_controls),
                "non_compliant": len(self.non_compliant_controls),
                "not_applicable": sum(
                    1 for c in self.controls if c.level == ComplianceLevel.NOT_APPLICABLE
                ),
            },
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def summary_lines(self) -> list[str]:
        """Human-readable summary for terminal output."""
        lines = [
            "NIST PQC Compliance Report",
            f"Target:   {self.target}",
            f"Generated: {self.generated_at}",
            f"Overall:  {self.overall_level.value}",
            "",
        ]
        d = self.to_dict()["summary"]
        lines.append(
            f"Controls: {d['total']} total, {d['compliant']} compliant, "
            f"{d['partial']} partial, {d['non_compliant']} non-compliant"
        )
        lines.append("")

        if self.non_compliant_controls:
            lines.append("Non-compliant controls:")
            for c in self.non_compliant_controls:
                lines.append(f"  [{c.control_id}] {c.title}")
                lines.append(f"    -> {c.remediation}")
        return lines


class NISTComplianceChecker:
    """Evaluates NIST SP 800-208 / FIPS 203/204/205 compliance.

    Takes a ScanReport and produces a ComplianceReport that maps each
    finding to a specific NIST control.

    Usage::

        from quantum_safe.audit.compliance import NISTComplianceChecker
        from quantum_safe.migrate.scanner import Scanner

        scan = Scanner.scan_directory("./src")
        report = NISTComplianceChecker.check(scan, target="./src")
        print(report.to_json())
    """

    # NIST controls we evaluate. Each has a check function.
    # The structure is intentionally readable so auditors can review it.
    _CONTROLS: ClassVar[list[dict[str, Any]]] = [
        {
            "id": "FIPS203-2.1",
            "standard": "FIPS 203",
            "title": "ML-KEM key encapsulation",
            "description": "Key encapsulation shall use ML-KEM-512, ML-KEM-768, or ML-KEM-1024 "
            "as specified in FIPS 203. RSA and ECDH are not quantum-safe.",
            "check_rule_ids": {"QS001", "QS002", "QS003", "QS011", "QS016"},
            "remediation": "Replace RSA/ECDH key exchange with HybridKEM() "
            "(X25519+ML-KEM-768 by default).",
        },
        {
            "id": "FIPS204-2.1",
            "standard": "FIPS 204",
            "title": "ML-DSA digital signatures",
            "description": "Digital signatures shall use ML-DSA-44, ML-DSA-65, or ML-DSA-87 "
            "as specified in FIPS 204. RSA-PSS, ECDSA, DSA are not quantum-safe.",
            "check_rule_ids": {"QS001", "QS010", "QS015"},
            "remediation": "Replace ECDSA/RSA/DSA signatures with HybridSign() "
            "(Ed25519+ML-DSA-65 by default).",
        },
        {
            "id": "FIPS205-2.1",
            "standard": "FIPS 205",
            "title": "SLH-DSA stateless hash-based signatures",
            "description": "Where long-term signing keys with hash-based security are required, "
            "SLH-DSA variants from FIPS 205 should be considered as an alternative "
            "to ML-DSA.",
            "check_rule_ids": set(),  # No specific scanner rule for SLH-DSA absence
            "remediation": "Consider SLH-DSA for long-lived code-signing keys as a "
            "non-lattice alternative.",
            "informational": True,
        },
        {
            "id": "SP800208-3.1",
            "standard": "NIST SP 800-208",
            "title": "Deprecated algorithm deprecation",
            "description": "SHA-1 and MD5 must not be used for any cryptographic purpose. "
            "AES-128 should be phased out in favor of AES-256.",
            "check_rule_ids": {"QS030", "QS031", "QS020"},
            "remediation": "Replace SHA-1/MD5 with SHA-256 or SHA3-256. "
            "Replace AES-128 with AES-256.",
        },
        {
            "id": "CISA-PQC-1",
            "standard": "CISA PQC Migration Checklist",
            "title": "Cryptographic inventory",
            "description": "Organizations shall maintain an inventory of all cryptographic "
            "assets, including algorithm, key size, and usage context.",
            "check_rule_ids": set(),
            "remediation": "Run qs-audit scan regularly and store results in your SBOM. "
            "Use SBOMEnricher.enrich() to annotate dependencies.",
            "informational": True,
        },
        {
            "id": "CISA-PQC-2",
            "standard": "CISA PQC Migration Checklist",
            "title": "Hybrid transition",
            "description": "During the transition period, hybrid classical+PQC algorithms "
            "should be used to maintain backward compatibility while gaining "
            "quantum resistance.",
            "check_rule_ids": {"QS001", "QS010", "QS011"},
            "remediation": "Use HybridKEM() and HybridSign() which combine classical and "
            "PQC algorithms per IETF hybrid-design draft.",
        },
        {
            "id": "CISA-PQC-3",
            "standard": "CISA PQC Migration Checklist",
            "title": "JWT and token security",
            "description": "JWT tokens signed with RS256, ES256, or HS256 are not quantum-safe. "
            "Transition to ML-DSA-based JWT signing.",
            "check_rule_ids": {"QS040"},
            "remediation": "Replace jwt.encode(..., algorithm='RS256') with "
            "JWTSigner from quantum_safe.protocols.jwt.",
        },
    ]

    @classmethod
    def check(
        cls,
        scan_report: ScanReport,
        target: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ComplianceReport:
        """Generate a NIST compliance report from a ScanReport.

        Args:
            scan_report:    Results from Scanner.scan_file/directory/source.
            target:         What was scanned (for the report header).
            metadata:       Arbitrary metadata to include in the report.

        Returns:
            ComplianceReport with one ComplianceControl per NIST requirement.
        """
        # Index findings by rule_id for fast lookup
        findings_by_rule: dict[str, list[Finding]] = {}
        for f in scan_report.findings:
            findings_by_rule.setdefault(f.rule_id, []).append(f)

        controls: list[ComplianceControl] = []

        for ctrl_def in cls._CONTROLS:
            rule_ids = ctrl_def["check_rule_ids"]
            is_info = ctrl_def.get("informational", False)

            # Collect findings that triggered this control
            triggered_findings: list[Finding] = []
            for rule_id in rule_ids:
                triggered_findings.extend(findings_by_rule.get(rule_id, []))

            # Determine compliance level
            if is_info and not triggered_findings:
                level = ComplianceLevel.NOT_APPLICABLE
                evidence = ["Informational control - no specific check performed"]
            elif not rule_ids:
                # No rules to check — mark as informational
                level = ComplianceLevel.NOT_APPLICABLE
                evidence = ["Manual review required"]
            elif not triggered_findings:
                level = ComplianceLevel.COMPLIANT
                evidence = ["No classical crypto usage detected for this control"]
            else:
                # Have findings — is it PARTIAL or NON_COMPLIANT?
                critical_or_high = [f for f in triggered_findings if f.severity >= Severity.HIGH]
                if critical_or_high:
                    level = ComplianceLevel.NON_COMPLIANT
                else:
                    level = ComplianceLevel.PARTIAL

                evidence = [
                    f"{f.file}:{f.line} [{f.rule_id}] {f.message}"
                    for f in triggered_findings[:5]  # cap evidence list
                ]
                if len(triggered_findings) > 5:
                    evidence.append(f"... and {len(triggered_findings) - 5} more findings")

            controls.append(
                ComplianceControl(
                    control_id=ctrl_def["id"],
                    standard=ctrl_def["standard"],
                    title=ctrl_def["title"],
                    description=ctrl_def["description"],
                    level=level,
                    evidence=evidence,
                    remediation=ctrl_def.get("remediation", ""),
                )
            )

        # Roll up overall level
        levels = [c.level for c in controls]
        if any(lvl == ComplianceLevel.NON_COMPLIANT for lvl in levels):
            overall = ComplianceLevel.NON_COMPLIANT
        elif any(lvl == ComplianceLevel.PARTIAL for lvl in levels):
            overall = ComplianceLevel.PARTIAL
        else:
            overall = ComplianceLevel.COMPLIANT

        return ComplianceReport(
            generated_at=datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            target=target or scan_report.root,
            controls=controls,
            overall_level=overall,
            metadata=metadata or {},
        )
