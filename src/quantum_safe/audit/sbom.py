"""
quantum_safe.audit.sbom
~~~~~~~~~~~~~~~~~~~~~~~~

CycloneDX Software Bill of Materials (SBOM) enrichment.

Takes an existing CycloneDX SBOM (JSON format, spec 1.4+) and adds a
pqc-readiness property to each component that tells you whether that
dependency uses quantum-safe cryptography.

What it checks
--------------
For each component in the SBOM, we check:
  1. Is it a known cryptography library? (cryptography, pycryptodome, etc.)
  2. If so, which version? PQC support was added at specific versions.
  3. Does the component name match our knowledge base of PQC-ready libs?

This is necessarily best-effort — we can't run the code of each dependency.
The output is tagged READY / PARTIAL / NOT_READY / UNKNOWN.

CycloneDX 1.4+ component properties
-------------------------------------
We add a property named "quantum-safe:pqc-readiness" with value
READY | PARTIAL | NOT_READY | UNKNOWN.

We also add:
  "quantum-safe:reason"     — why we assigned that status
  "quantum-safe:since"      — version at which PQC support was added (if known)
  "quantum-safe:action"     — recommended action

CycloneDX spec: https://cyclonedx.org/docs/1.4/json/
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from quantum_safe._version import __version__


class PQCReadiness(str, Enum):
    """PQC readiness assessment for a software component."""

    READY = "READY"  # Component is PQC-ready
    PARTIAL = "PARTIAL"  # Component has some PQC support (hybrid, etc.)
    NOT_READY = "NOT_READY"  # Component uses only classical crypto
    UNKNOWN = "UNKNOWN"  # Cannot determine


@dataclass
class ComponentAssessment:
    """PQC readiness assessment for a single SBOM component.

    Attributes:
        name: the component or package name.
        version: the version taken from the SBOM or requirement, or ``None`` if there is none.
        readiness: the assessed :class:`PQCReadiness`.
        reason: why that status was assigned.
        since_version: the version at which PQC support was added, when the knowledge base
            records one.
        action: the recommended action.
    """

    name: str
    version: str | None
    readiness: PQCReadiness
    reason: str
    since_version: str | None = None  # version at which PQC was added
    action: str = ""


# Knowledge base of known library PQC support.
# Format: {package_name: {min_version: PQCReadiness, reason, since, action}}
# Versions use simple string comparison — this works for well-formatted semver.
_KNOWN_LIBRARIES: dict[str, dict[str, Any]] = {
    # cryptography (PyCA) — ML-KEM and ML-DSA are available from 48.0 (the [pyca] extra)
    "cryptography": {
        "pqc_since": "48.0.0",
        "status_before": PQCReadiness.NOT_READY,
        "status_at_or_after": PQCReadiness.PARTIAL,
        "reason_before": "cryptography < 48.0.0 has no ML-KEM or ML-DSA",
        "reason_after": "cryptography >= 48.0.0 includes ML-KEM and ML-DSA",
        "since": "48.0.0",
        "action_before": "Upgrade to cryptography >= 48.0.0 or use quantum-safe-py with liboqs",
        "action_after": "Use quantum_safe.HybridKEM/HybridSign for hybrid mode",
    },
    # quantum-safe-py (this library, formerly listed as quantum-safe) — always READY
    "quantum-safe-py": {
        "pqc_since": "0.1.0",
        "status_before": PQCReadiness.NOT_READY,
        "status_at_or_after": PQCReadiness.READY,
        "reason_before": "quantum-safe < 0.1.0 is pre-release",
        "reason_after": "quantum-safe provides HybridKEM, HybridSign, and migration tooling",
        "since": "0.1.0",
        "action_before": "Upgrade to quantum-safe >= 0.1.0",
        "action_after": "No action required",
    },
    # liboqs-python — full PQC, no hybrid
    "liboqs-python": {
        "pqc_since": "0.9.0",
        "status_before": PQCReadiness.NOT_READY,
        "status_at_or_after": PQCReadiness.PARTIAL,
        "reason_before": "liboqs-python < 0.9.0 predates ML-KEM standardization",
        "reason_after": "liboqs-python provides ML-KEM/ML-DSA but no hybrid combiner",
        "since": "0.9.0",
        "action_before": "Upgrade to liboqs-python >= 0.9.0",
        "action_after": "Wrap with quantum_safe for hybrid mode and typed API",
    },
    # pycryptodome / pycrypto — classical only
    "pycryptodome": {
        "pqc_since": None,  # no PQC support yet
        "status_before": PQCReadiness.NOT_READY,
        "status_at_or_after": PQCReadiness.NOT_READY,
        "reason_before": "pycryptodome has no PQC support",
        "reason_after": "pycryptodome has no PQC support",
        "since": None,
        "action_before": "Replace with quantum_safe",
        "action_after": "Replace with quantum_safe",
    },
    "pycrypto": {
        "pqc_since": None,
        "status_before": PQCReadiness.NOT_READY,
        "status_at_or_after": PQCReadiness.NOT_READY,
        "reason_before": "pycrypto is unmaintained and has no PQC support",
        "reason_after": "pycrypto is unmaintained and has no PQC support",
        "since": None,
        "action_before": "Replace with quantum_safe immediately — pycrypto is abandoned",
        "action_after": "Replace with quantum_safe immediately — pycrypto is abandoned",
    },
    # PyJWT — classical JWT signing only
    "PyJWT": {
        "pqc_since": None,
        "status_before": PQCReadiness.NOT_READY,
        "status_at_or_after": PQCReadiness.NOT_READY,
        "reason_before": "PyJWT supports only classical JWT algorithms (RS256, ES256, HS256)",
        "reason_after": "PyJWT supports only classical JWT algorithms",
        "since": None,
        "action_before": "Replace with quantum_safe.protocols.jwt.JWTSigner/JWTVerifier",
        "action_after": "Replace with quantum_safe.protocols.jwt.JWTSigner/JWTVerifier",
    },
    # paramiko (SSH) — classical only
    "paramiko": {
        "pqc_since": None,
        "status_before": PQCReadiness.NOT_READY,
        "status_at_or_after": PQCReadiness.NOT_READY,
        "reason_before": "paramiko uses classical RSA/ECDSA for SSH key exchange",
        "reason_after": "paramiko uses classical RSA/ECDSA for SSH key exchange",
        "since": None,
        "action_before": "Consider quantum-safe SSH alternatives for long-lived connections",
        "action_after": "Consider quantum-safe SSH alternatives",
    },
    # requests / httpx — depends on underlying TLS stack
    "requests": {
        "pqc_since": None,
        "status_before": PQCReadiness.UNKNOWN,
        "status_at_or_after": PQCReadiness.UNKNOWN,
        "reason_before": "requests delegates TLS to urllib3 and the system OpenSSL",
        "reason_after": "requests delegates TLS to urllib3 and the system OpenSSL",
        "since": None,
        "action_before": "Enable hybrid TLS at the OpenSSL/OQS level; requests inherits it",
        "action_after": "Enable hybrid TLS at the OpenSSL/OQS level",
    },
    "httpx": {
        "pqc_since": None,
        "status_before": PQCReadiness.UNKNOWN,
        "status_at_or_after": PQCReadiness.UNKNOWN,
        "reason_before": "httpx delegates TLS to the system SSL stack",
        "reason_after": "httpx delegates TLS to the system SSL stack",
        "since": None,
        "action_before": "Enable hybrid TLS at the OpenSSL/OQS level",
        "action_after": "Enable hybrid TLS at the OpenSSL/OQS level",
    },
}


def _normalize(name: str) -> str:
    """The PEP 503 form of a package name: lower case, runs of ``-_.`` become one ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


_KNOWN_BY_NORMALIZED_NAME: dict[str, dict[str, Any]] = {
    _normalize(_name): _info for _name, _info in _KNOWN_LIBRARIES.items()
}
# The library's former knowledge-base name still resolves to it.
_KNOWN_BY_NORMALIZED_NAME.setdefault("quantum-safe", _KNOWN_LIBRARIES["quantum-safe-py"])


def _lowest_version(specifiers: str) -> str | None:
    """The lowest version a requirement allows: its ``==``, ``===``, ``~=``, ``>=`` or ``>`` bound.

    ``specifiers`` is the text after the package name, for example ``>=1.0,<2``. An upper bound
    (``<``, ``<=``) or ``!=`` says nothing about which version is installed and gives ``None``,
    as does a requirement with no version. A trailing ``.*`` of an ``==`` pin is dropped.
    """
    for spec in specifiers.split(","):
        found = re.match(r"^\s*(===|==|~=|>=|>)\s*(\S+)\s*$", spec)
        if found:
            return found.group(2).removesuffix(".*")
    return None


def _version_ge(v1: str, v2: str) -> bool:
    """Simple version comparison: return True if v1 >= v2.

    Handles semver-ish strings (major.minor.patch). Not robust for
    pre-release tags — good enough for the SBOM use case.
    """

    def parts(v: str) -> tuple[int, ...]:
        cleaned = v.strip().lstrip("v")
        try:
            numbers = tuple(int(x) for x in cleaned.split(".")[:3])
        except ValueError:
            return (0, 0, 0)
        return numbers + (0,) * (3 - len(numbers))  # "48.0" is "48.0.0"

    return parts(v1) >= parts(v2)


def _assess_component(name: str, version: str | None) -> ComponentAssessment:
    """Assess PQC readiness for a single component."""
    info = _KNOWN_LIBRARIES.get(name) or _KNOWN_BY_NORMALIZED_NAME.get(_normalize(name))

    if info is None:
        return ComponentAssessment(
            name=name,
            version=version,
            readiness=PQCReadiness.UNKNOWN,
            reason=f"'{name}' is not in the PQC knowledge base",
            action="Check manually whether this library uses cryptographic primitives",
        )

    if info["pqc_since"] is None:
        # No PQC support expected ever
        return ComponentAssessment(
            name=name,
            version=version,
            readiness=info["status_at_or_after"],  # still NOT_READY or UNKNOWN
            reason=info["reason_after"],
            since_version=None,
            action=info["action_after"],
        )

    if version is None:
        return ComponentAssessment(
            name=name,
            version=None,
            readiness=PQCReadiness.UNKNOWN,
            reason=f"Version unknown - cannot determine PQC readiness for '{name}'",
            since_version=info["pqc_since"],
            action=f"Pin to a specific version and check if >= {info['pqc_since']}",
        )

    if _version_ge(version, info["pqc_since"]):
        return ComponentAssessment(
            name=name,
            version=version,
            readiness=info["status_at_or_after"],
            reason=info["reason_after"],
            since_version=info["pqc_since"],
            action=info["action_after"],
        )
    else:
        return ComponentAssessment(
            name=name,
            version=version,
            readiness=info["status_before"],
            reason=info["reason_before"],
            since_version=info["pqc_since"],
            action=info["action_before"],
        )


class SBOMEnricher:
    """Enriches a CycloneDX SBOM with PQC-readiness annotations.

    Usage::

        with open("sbom.json") as f:
            sbom = json.load(f)

        enriched, assessments = SBOMEnricher.enrich(sbom)

        with open("sbom-pqc.json", "w") as f:
            json.dump(enriched, f, indent=2)

        for a in assessments:
            if a.readiness == PQCReadiness.NOT_READY:
                print(f"NOT READY: {a.name} {a.version} - {a.action}")
    """

    @classmethod
    def enrich(
        cls,
        sbom: dict[str, Any],
    ) -> tuple[dict[str, Any], list[ComponentAssessment]]:
        """Enrich a CycloneDX SBOM with PQC-readiness properties.

        Args:
            sbom:   Parsed CycloneDX JSON SBOM (dict).

        Returns:
            (enriched_sbom, assessments):
                enriched_sbom:  The input SBOM with pqc-readiness properties added.
                assessments:    One ComponentAssessment per component.
        """
        import copy

        enriched = copy.deepcopy(sbom)
        assessments: list[ComponentAssessment] = []

        components = enriched.get("components", [])
        for component in components:
            name = component.get("name", "")
            version = component.get("version")

            assessment = _assess_component(name, version)
            assessments.append(assessment)

            # Add properties to the component
            props = component.setdefault("properties", [])

            # Remove any existing qs properties (idempotent enrichment)
            props[:] = [p for p in props if not p.get("name", "").startswith("quantum-safe:")]

            props.append(
                {
                    "name": "quantum-safe:pqc-readiness",
                    "value": assessment.readiness.value,
                }
            )
            props.append({"name": "quantum-safe:reason", "value": assessment.reason})
            props.append({"name": "quantum-safe:action", "value": assessment.action})
            if assessment.since_version:
                props.append({"name": "quantum-safe:since", "value": assessment.since_version})

        # Add a top-level metadata note
        meta = enriched.setdefault("metadata", {})
        meta_props = meta.setdefault("properties", [])
        meta_props[:] = [p for p in meta_props if not p.get("name", "").startswith("quantum-safe:")]
        meta_props.append(
            {
                "name": "quantum-safe:enriched-by",
                "value": f"quantum-safe v{__version__}",
            }
        )

        ready_count = sum(1 for a in assessments if a.readiness == PQCReadiness.READY)
        partial_count = sum(1 for a in assessments if a.readiness == PQCReadiness.PARTIAL)
        not_ready_count = sum(1 for a in assessments if a.readiness == PQCReadiness.NOT_READY)
        meta_props.append(
            {
                "name": "quantum-safe:summary",
                "value": f"READY={ready_count},PARTIAL={partial_count},NOT_READY={not_ready_count}",
            }
        )

        return enriched, assessments

    @classmethod
    def from_requirements(
        cls,
        requirements_txt: str,
    ) -> list[ComponentAssessment]:
        """Assess PQC readiness from a requirements.txt string.

        Does not require a full SBOM — useful as a quick check during CI.
        Parses lines of the form::

            cryptography==44.0.5
            pycryptodome>=3.20.0
            quantum-safe==0.1.0

        Blank lines and ``#`` comment lines are skipped, and extras (``[crypto]``) and environment
        markers (after ``;``) are removed. The version is the lowest one the line guarantees: the
        first ``==``, ``===``, ``~=``, ``>=`` or ``>`` specifier, so for ``pkg>=1.0,<2`` it is
        ``1.0``. An upper bound (``<``, ``<=``), ``!=`` or a line without a specifier gives no
        version, and the component is then reported as UNKNOWN.

        Args:
            requirements_txt:   Contents of a requirements.txt file.

        Returns:
            List of ComponentAssessment objects, one per package line, in file order.
        """
        assessments = []
        for line in requirements_txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip extras like [crypto] and environment markers
            line = line.split(";")[0].strip()
            line = re.sub(r"\[.*?\]", "", line).strip()

            # Parse name and version
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", line)
            if match is None:
                name, version = line, None
            else:
                name, version = match.group(1), _lowest_version(match.group(2))

            if name:
                assessments.append(_assess_component(name, version))

        return assessments
