"""
Seed keys shared with quantum-safe-ts: its private AKP JWKs and private COSE keys (the 32-byte seed),
with a token and a COSE_Sign1 signed by TypeScript. Python (pyca backend) must derive the same public
keys, verify TypeScript's messages, and sign with TypeScript's keys.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.mldsa",
    reason="needs cryptography >= 48 (seeded ML-DSA)",
)

VECTORS = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1]
        / "interop"
        / "vectors"
        / "ts_private_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.mark.parametrize("v", VECTORS, ids=[v["algorithm"] for v in VECTORS])
class TestTypeScriptSeedKeys:
    def test_the_private_jwk_derives_the_same_public_key(self, v) -> None:
        from quantum_safe.protocols.standard_jwt import StandardJwt

        kp = StandardJwt.keypair_from_private_jwk(v["private_jwk"])
        assert kp.public.raw_bytes == _b64u(v["public_jwk"]["pub"])
        assert StandardJwt.public_jwk(v["private_jwk"])["pub"] == v["public_jwk"]["pub"]

    def test_verifies_the_typescript_token_and_signs_one_that_typescript_can_verify(
        self, v
    ) -> None:
        from quantum_safe.protocols.standard_jwt import StandardJwt

        claims = StandardJwt.verify(v["token"], v["public_jwk"])
        assert claims["sub"] == "from-typescript"
        mine = StandardJwt.sign({"sub": "from-python-with-ts-key"}, v["private_jwk"], expires_in=0)
        assert StandardJwt.verify(mine, v["public_jwk"])["sub"] == "from-python-with-ts-key"

    def test_private_cose_key_and_cose_sign1(self, v) -> None:
        from quantum_safe.protocols.cose import keypair_from_cose_key, sign1, verify_sign1

        kp = keypair_from_cose_key(bytes.fromhex(v["cose_private_key"]))
        assert kp.public.raw_bytes == _b64u(v["public_jwk"]["pub"])
        assert kp.secret.raw_bytes == _b64u(v["private_jwk"]["priv"])
        payload = verify_sign1(bytes.fromhex(v["cose_sign1"]), kp.public)
        assert payload == bytes.fromhex(v["cose_payload"])
        mine = sign1(b"signed in python", kp.secret)
        assert verify_sign1(mine, kp.public) == b"signed in python"


def test_vectors_cover_all_levels() -> None:
    assert {v["algorithm"] for v in VECTORS} == {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
