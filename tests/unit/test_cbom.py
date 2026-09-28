"""Tests for CycloneDX CBOM generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quantum_safe.audit.cbom import (
    CYCLONEDX_SPEC_VERSION,
    PROVIDED_ASSETS,
    build_cbom,
    to_json,
)
from quantum_safe.migrate.scanner import Scanner

LEGACY_SOURCE = """
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import hashlib


def make_keys():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    e = ec.generate_private_key(ec.SECP256R1())
    return k, e


def weak(data):
    return hashlib.md5(data).hexdigest()
"""


@pytest.fixture
def legacy_scan(tmp_path: Path):
    (tmp_path / "legacy.py").write_text(LEGACY_SOURCE, encoding="utf-8")
    return Scanner.scan_directory(tmp_path)


class TestDocumentShape:
    def test_emits_valid_cyclonedx_envelope(self, legacy_scan) -> None:
        cbom = build_cbom(legacy_scan)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == CYCLONEDX_SPEC_VERSION
        assert cbom["serialNumber"].startswith("urn:uuid:")
        assert cbom["version"] == 1

    def test_serialises_to_json(self, legacy_scan) -> None:
        parsed = json.loads(to_json(build_cbom(legacy_scan)))
        assert parsed["bomFormat"] == "CycloneDX"

    def test_every_component_is_a_cryptographic_asset(self, legacy_scan) -> None:
        for component in build_cbom(legacy_scan)["components"]:
            assert component["type"] == "cryptographic-asset"
            assert component["cryptoProperties"]["assetType"] == "algorithm"
            assert "primitive" in component["cryptoProperties"]["algorithmProperties"]


class TestDetectedAssets:
    def test_detects_the_classical_algorithms_present(self, legacy_scan) -> None:
        cbom = build_cbom(legacy_scan)
        names = {c["name"] for c in cbom["components"] if c["bom-ref"].startswith("detected/")}
        assert "RSA" in names
        assert any("ECDSA" in n or "ECC" in n for n in names)
        assert "MD5" in names

    def test_records_location_per_occurrence(self, legacy_scan) -> None:
        """One component per site, so the inventory shows the size of the job."""
        cbom = build_cbom(legacy_scan)
        detected = [c for c in cbom["components"] if c["bom-ref"].startswith("detected/")]
        assert detected
        for component in detected:
            locations = [
                p["value"]
                for p in component["properties"]
                if p["name"] == "quantum-safe:detected-at"
            ]
            assert len(locations) == 1
            assert ":" in locations[0], "expected file:line"

    def test_quantum_vulnerable_flag_distinguishes_break_from_weakness(self, legacy_scan) -> None:
        """RSA is broken by a quantum computer; MD5 is classically broken.

        Marking both simply 'bad' would misrepresent the inventory, so the flag
        must separate them.
        """
        cbom = build_cbom(legacy_scan)

        def flag(name: str) -> str | None:
            for c in cbom["components"]:
                if c["name"] == name and c["bom-ref"].startswith("detected/"):
                    for p in c["properties"]:
                        if p["name"] == "quantum-safe:quantum-vulnerable":
                            return p["value"]
            return None

        assert flag("RSA") == "true"
        assert flag("MD5") == "false"

    def test_classical_assets_have_zero_quantum_security_level(self, legacy_scan) -> None:
        cbom = build_cbom(legacy_scan)
        rsa = next(
            c
            for c in cbom["components"]
            if c["name"] == "RSA" and c["bom-ref"].startswith("detected/")
        )
        props = rsa["cryptoProperties"]["algorithmProperties"]
        assert props["nistQuantumSecurityLevel"] == 0


class TestProvidedAssets:
    def test_included_by_default(self, legacy_scan) -> None:
        cbom = build_cbom(legacy_scan)
        provided = [c for c in cbom["components"] if c["bom-ref"].startswith("provided/")]
        assert len(provided) == len(PROVIDED_ASSETS)

    def test_can_be_omitted(self, legacy_scan) -> None:
        cbom = build_cbom(legacy_scan, include_provided=False)
        assert not [c for c in cbom["components"] if c["bom-ref"].startswith("provided/")]

    def test_cnsa2_parameter_sets_carry_category_five(self, legacy_scan) -> None:
        """ML-KEM-1024 and ML-DSA-87 must report NIST category 5."""
        cbom = build_cbom(legacy_scan)
        for name in ("ML-KEM-1024", "ML-DSA-87"):
            component = next(c for c in cbom["components"] if c["name"] == name)
            level = component["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
            assert level == 5, f"{name} should be NIST category 5, got {level}"

    def test_provided_assets_are_not_quantum_vulnerable(self, legacy_scan) -> None:
        cbom = build_cbom(legacy_scan)
        for component in cbom["components"]:
            if not component["bom-ref"].startswith("provided/"):
                continue
            flags = [
                p["value"]
                for p in component["properties"]
                if p["name"] == "quantum-safe:quantum-vulnerable"
            ]
            assert flags == ["false"], f"{component['name']} marked quantum-vulnerable"


class TestHonesty:
    def test_states_static_analysis_scope_limit(self, legacy_scan) -> None:
        """An empty result must not read as proof of absence."""
        values = " ".join(p["value"] for p in build_cbom(legacy_scan)["metadata"]["properties"])
        assert "not evidence of absence" in values

    def test_disclaims_being_a_compliance_verdict(self, legacy_scan) -> None:
        values = " ".join(p["value"] for p in build_cbom(legacy_scan)["metadata"]["properties"])
        assert "Inventory only" in values
        assert "FIPS 140-3 validation" in values

    def test_works_with_no_scan_at_all(self) -> None:
        """Inventory of what is provided, with nothing detected, is still valid."""
        cbom = build_cbom(None)
        assert cbom["bomFormat"] == "CycloneDX"
        assert len(cbom["components"]) == len(PROVIDED_ASSETS)
        counts = [
            p["value"]
            for p in cbom["metadata"]["properties"]
            if p["name"] == "quantum-safe:detected-asset-count"
        ]
        assert counts == ["0"]
