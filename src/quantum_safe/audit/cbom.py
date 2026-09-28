"""
CycloneDX Cryptographic Bill of Materials (CBOM) generation.

CycloneDX 1.6 added the ``cryptographic-asset`` component type with a
``cryptoProperties`` object, which is the standardised way to express "what
cryptography does this codebase contain, and is any of it quantum-vulnerable".
This module emits that, so a discovery result can be consumed by tooling that
speaks CycloneDX rather than only by a human reading a scan report.

Why this exists
---------------
The TNO CADI market survey (TNO 2025 P11921) treats machine-readable inventory
output as a requirement for discovery tooling, not a nicety: an inventory that
only a person can read does not compose into an organisation-wide migration
programme. Emitting a recognised format is what makes the scanner's output
usable by something else.

What it reports
---------------
Two kinds of asset, deliberately distinguished:

*Detected* assets come from scanning source code and represent cryptography the
codebase actually uses. Each carries the file and line it was found at, and a
quantum-vulnerability assessment.

*Provided* assets are the post-quantum algorithms this library makes available.
These are included because a migration inventory that lists only the problems is
half an inventory: a reader comparing "what I use" against "what I could use"
needs both sides, and the NIST quantum security levels are what make the
comparison meaningful.

Honest limits
-------------
* Static analysis sees what the source names. Cryptography reached through
  configuration, a plugin, or a dependency's internals will be missed, so an
  empty result is not evidence of absence.
* ``nistQuantumSecurityLevel`` is 0 for every classical asset here. That is the
  CycloneDX encoding for "no security against a quantum adversary", and it is a
  statement about the algorithm, not a measurement of a specific deployment.
* This is an inventory, not a compliance verdict. For CNSA 2.0 parameter
  requirements see :mod:`quantum_safe.compliance.cnsa2`.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from quantum_safe.migrate.scanner import ScanReport

CYCLONEDX_SPEC_VERSION = "1.6"


@dataclass(frozen=True)
class CryptoAssetSpec:
    """How one algorithm is described in CBOM terms.

    Attributes:
        name: algorithm name as it should appear in the inventory.
        primitive: CycloneDX ``primitive`` enum value (``pke``, ``signature``,
            ``kem``, ``block-cipher``, ``hash``, ``key-agree``).
        oid: object identifier where a standard one exists.
        classical_level: approximate classical security level in bits.
        quantum_level: CycloneDX ``nistQuantumSecurityLevel``. 0 means no
            security against a quantum adversary.
        quantum_vulnerable: whether a cryptographically relevant quantum
            computer breaks this outright.
        replacement: what to migrate to, for detected classical assets.
    """

    name: str
    primitive: str
    oid: str | None = None
    classical_level: int | None = None
    quantum_level: int = 0
    quantum_vulnerable: bool = True
    replacement: str | None = None


# Scanner rule -> the algorithm that rule detects. Rules that flag the same
# algorithm through different APIs map to the same spec on purpose: the
# inventory should list the algorithm once per location, not once per API shape.
_RULE_TO_ASSET: dict[str, CryptoAssetSpec] = {
    "QS001": CryptoAssetSpec(
        "RSA", "pke", "1.2.840.113549.1.1.1", 112, 0, True, "ML-KEM-1024 or ML-DSA-87"
    ),
    "QS002": CryptoAssetSpec(
        "RSA-PKCS1v15", "pke", "1.2.840.113549.1.1.1", 112, 0, True, "Envelope.seal()"
    ),
    "QS003": CryptoAssetSpec(
        "RSA-OAEP", "pke", "1.2.840.113549.1.1.7", 112, 0, True, "Envelope.seal()"
    ),
    "QS010": CryptoAssetSpec(
        "ECDSA", "signature", "1.2.840.10045.4", 128, 0, True, "HybridSign (Ed25519+ML-DSA-87)"
    ),
    "QS011": CryptoAssetSpec(
        "ECDH", "key-agree", "1.3.132.1.12", 128, 0, True, "HybridKEM (X25519+ML-KEM-1024)"
    ),
    "QS015": CryptoAssetSpec(
        "DSA", "signature", "1.2.840.10040.4.1", 112, 0, True, "HybridSign (Ed25519+ML-DSA-87)"
    ),
    "QS016": CryptoAssetSpec(
        "DH", "key-agree", "1.2.840.113549.1.3.1", 112, 0, True, "HybridKEM (X25519+ML-KEM-1024)"
    ),
    # AES-128 and SHA-1/MD5 are not broken by a quantum computer in the way RSA
    # and ECC are. They are flagged for different reasons -- insufficient margin
    # under Grover, and classical breakage -- and conflating the two would
    # misrepresent the inventory.
    "QS020": CryptoAssetSpec(
        "AES-128", "block-cipher", "2.16.840.1.101.3.4.1.2", 128, 1, False, "AES-256"
    ),
    "QS021": CryptoAssetSpec(
        "TripleDES", "block-cipher", "1.2.840.113549.3.7", 112, 0, False, "AES-256"
    ),
    "QS030": CryptoAssetSpec("SHA-1", "hash", "1.3.14.3.2.26", 0, 0, False, "SHA-384 or SHA-512"),
    "QS031": CryptoAssetSpec(
        "MD5", "hash", "1.2.840.113549.2.5", 0, 0, False, "SHA-384 or SHA-512"
    ),
    "QS040": CryptoAssetSpec(
        "JWT classical algorithm", "signature", None, 112, 0, True, "HybridSign"
    ),
    "QS050": CryptoAssetSpec(
        "RSA", "pke", "1.2.840.113549.1.1.1", 112, 0, True, "ML-KEM-1024 or ML-DSA-87"
    ),
    "QS051": CryptoAssetSpec("ECC", "signature", "1.2.840.10045.2.1", 128, 0, True, "HybridSign"),
}

#: Post-quantum algorithms this library provides, with NIST security categories.
PROVIDED_ASSETS: tuple[CryptoAssetSpec, ...] = (
    CryptoAssetSpec("ML-KEM-512", "kem", "2.16.840.1.101.3.4.4.1", 128, 1, False),
    CryptoAssetSpec("ML-KEM-768", "kem", "2.16.840.1.101.3.4.4.2", 192, 3, False),
    CryptoAssetSpec("ML-KEM-1024", "kem", "2.16.840.1.101.3.4.4.3", 256, 5, False),
    CryptoAssetSpec("ML-DSA-44", "signature", "2.16.840.1.101.3.4.3.17", 128, 2, False),
    CryptoAssetSpec("ML-DSA-65", "signature", "2.16.840.1.101.3.4.3.18", 192, 3, False),
    CryptoAssetSpec("ML-DSA-87", "signature", "2.16.840.1.101.3.4.3.19", 256, 5, False),
    CryptoAssetSpec("SLH-DSA-SHAKE-128s", "signature", "2.16.840.1.101.3.4.3.20", 128, 1, False),
    CryptoAssetSpec("SLH-DSA-SHAKE-256s", "signature", "2.16.840.1.101.3.4.3.24", 256, 5, False),
)


def _bom_ref(prefix: str, name: str, suffix: str = "") -> str:
    slug = name.lower().replace(" ", "-").replace("+", "-")
    return f"{prefix}/{slug}{suffix}"


def _crypto_component(
    spec: CryptoAssetSpec,
    bom_ref: str,
    *,
    detected_at: str | None = None,
    properties: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build one CycloneDX cryptographic-asset component."""
    algorithm_properties: dict[str, Any] = {
        "primitive": spec.primitive,
        "executionEnvironment": "software-plain-ram",
        "implementationPlatform": "generic",
        "nistQuantumSecurityLevel": spec.quantum_level,
    }
    if spec.classical_level is not None:
        algorithm_properties["classicalSecurityLevel"] = spec.classical_level

    crypto_properties: dict[str, Any] = {
        "assetType": "algorithm",
        "algorithmProperties": algorithm_properties,
    }
    if spec.oid:
        crypto_properties["oid"] = spec.oid

    props = list(properties or [])
    props.append(
        {
            "name": "quantum-safe:quantum-vulnerable",
            "value": "true" if spec.quantum_vulnerable else "false",
        }
    )
    if spec.replacement:
        props.append({"name": "quantum-safe:recommended-replacement", "value": spec.replacement})
    if detected_at:
        props.append({"name": "quantum-safe:detected-at", "value": detected_at})

    return {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": spec.name,
        "cryptoProperties": crypto_properties,
        "properties": props,
    }


def build_cbom(
    scan: ScanReport | None = None,
    *,
    include_provided: bool = True,
    application_name: str = "scanned-application",
    serial_number: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 CBOM document.

    Args:
        scan: a scan report whose findings become *detected* assets. Omit to emit
            only the provided-algorithm inventory.
        include_provided: whether to include the post-quantum algorithms this
            library offers. Keep enabled for migration planning; disable when the
            consumer only wants what the codebase currently uses.
        application_name: name recorded for the scanned application.
        serial_number: CycloneDX serial number. Generated if omitted.
        timestamp: ISO-8601 timestamp. Current UTC time if omitted.
    """
    components: list[dict[str, Any]] = []
    detected_count = 0

    if scan is not None:
        # One component per (algorithm, location) so a reader can see every site
        # that needs changing, rather than a deduplicated algorithm list that
        # hides how much work the migration is.
        for index, finding in enumerate(scan.findings):
            spec = _RULE_TO_ASSET.get(finding.rule_id)
            if spec is None:
                continue
            detected_count += 1
            location = f"{finding.file}:{finding.line}"
            components.append(
                _crypto_component(
                    spec,
                    _bom_ref("detected", spec.name, f"-{index}"),
                    detected_at=location,
                    properties=[
                        {"name": "quantum-safe:rule-id", "value": finding.rule_id},
                        {"name": "quantum-safe:severity", "value": finding.severity.name},
                    ],
                )
            )

    if include_provided:
        for spec in PROVIDED_ASSETS:
            components.append(
                _crypto_component(
                    spec,
                    _bom_ref("provided", spec.name),
                    properties=[
                        {"name": "quantum-safe:availability", "value": "provided-by-library"}
                    ],
                )
            )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "quantum-safe qs-audit",
                        "description": "Static cryptographic asset discovery for Python",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "subject",
                "name": application_name,
            },
            "properties": [
                {
                    "name": "quantum-safe:detected-asset-count",
                    "value": str(detected_count),
                },
                {
                    "name": "quantum-safe:scope-note",
                    "value": (
                        "Static analysis of Python source. Cryptography reached via "
                        "configuration, plugins, or dependency internals is not "
                        "visible here, so an empty result is not evidence of absence."
                    ),
                },
                {
                    "name": "quantum-safe:not-a-compliance-verdict",
                    "value": (
                        "Inventory only. Parameter-set compliance is evaluated "
                        "separately by quantum_safe.compliance.cnsa2; neither is a "
                        "FIPS 140-3 validation."
                    ),
                },
            ],
        },
        "components": components,
    }


def to_json(cbom: dict[str, Any], indent: int = 2) -> str:
    return json.dumps(cbom, indent=indent, sort_keys=False)
