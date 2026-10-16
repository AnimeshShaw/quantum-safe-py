"""The CBOM names each SLH-DSA parameter set with its own FIPS 205 / RFC 9909 OID.

The 0.3.x table listed ``SLH-DSA-SHAKE-128s`` as 2.16.840.1.101.3.4.3.20 and ``SLH-DSA-SHAKE-256s``
as ...3.24, which are the SHA2 variants; the SHAKE sets are ...3.26 and ...3.30. quantum-safe-ts
already had the right values, so the two inventories disagreed about the same algorithm.
"""

from __future__ import annotations

import pytest

from quantum_safe.audit.cbom import PROVIDED_ASSETS
from quantum_safe.signatures.algorithms import SIGNATURE_ALGORITHMS

# id-slh-dsa-<family>-<level><variant> under 2.16.840.1.101.3.4.3 (FIPS 205 / RFC 9909)
OIDS = {
    "SLH-DSA-SHA2-128s": 20,
    "SLH-DSA-SHA2-128f": 21,
    "SLH-DSA-SHA2-192s": 22,
    "SLH-DSA-SHA2-192f": 23,
    "SLH-DSA-SHA2-256s": 24,
    "SLH-DSA-SHA2-256f": 25,
    "SLH-DSA-SHAKE-128s": 26,
    "SLH-DSA-SHAKE-128f": 27,
    "SLH-DSA-SHAKE-192s": 28,
    "SLH-DSA-SHAKE-192f": 29,
    "SLH-DSA-SHAKE-256s": 30,
    "SLH-DSA-SHAKE-256f": 31,
}


def _slh_assets() -> dict[str, object]:
    return {a.name: a for a in PROVIDED_ASSETS if a.name.startswith("SLH-DSA-")}


def test_all_twelve_sets_are_listed() -> None:
    assert set(_slh_assets()) == set(OIDS)
    assert set(OIDS) == {n for n in SIGNATURE_ALGORITHMS if n.startswith("SLH-DSA-")}


@pytest.mark.parametrize("name", sorted(OIDS))
def test_oid_and_levels(name: str) -> None:
    a = _slh_assets()[name]
    assert a.oid == f"2.16.840.1.101.3.4.3.{OIDS[name]}"
    level = int(name.split("-")[3][:3])
    assert a.classical_level == level
    assert a.quantum_level == {128: 1, 192: 3, 256: 5}[level]


def test_oids_are_unique() -> None:
    oids = [a.oid for a in PROVIDED_ASSETS if a.oid]
    assert len(oids) == len(set(oids))
