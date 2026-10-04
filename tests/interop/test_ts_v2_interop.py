"""Interop for the formats added in 0.3.1: data written by quantum-safe-ts must load and verify here.

``vectors/ts_v2_vectors.json`` was produced by the quantum-safe-ts npm package (its
``scripts/gen_ts_v2_vectors.mjs``): envelope v2 (pure ML-KEM-1024, HKDF-SHA-384), the ``-v2``
signature format (all eight identifiers, with and without a context) and RFC 9964 ``StandardJwt``
tokens (no ``exp``, so they never expire). Regenerate there and copy the file here.

The reverse direction (Python-made data verified by TypeScript) lives in quantum-safe-ts:
``scripts/generate_py_v2_vectors.py`` and ``test/py-v2-interop.test.ts``.
"""

from __future__ import annotations

import json
import pathlib
import warnings

import pytest
from cryptography.exceptions import InvalidTag

from quantum_safe import HybridSign
from quantum_safe.exceptions import VerificationError
from quantum_safe.protocols.envelope import Envelope, SealedMessage
from quantum_safe.protocols.standard_jwt import StandardJwt
from quantum_safe.signatures import Sign
from quantum_safe.types import PublicKey, SecretKey
from quantum_safe.types.signatures import SignedMessage

pytestmark = pytest.mark.requires_liboqs

V = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "ts_v2_vectors.json").read_text(encoding="utf-8")
)


def test_vector_counts() -> None:
    assert len(V["envelope_v2"]) == 2
    assert {s["algorithm"] for s in V["signatures_v2"]} == {
        "ML-DSA-44-v2",
        "ML-DSA-65-v2",
        "ML-DSA-87-v2",
        "Ed25519+ML-DSA-44-v2",
        "Ed25519+ML-DSA-65-v2",
        "Ed25519+ML-DSA-87-v2",
        "P-256+ML-DSA-44-v2",
        "P-256+ML-DSA-65-v2",
    }
    assert len(V["signatures_v2"]) == 16 and len(V["standard_jwt"]) == 3


@pytest.mark.parametrize("e", V["envelope_v2"], ids=["no-aad", "with-aad"])
def test_envelope_v2_opens(e) -> None:
    sk = SecretKey(raw=bytes.fromhex(e["secret_key"]), algorithm="ML-KEM-1024")
    sealed = SealedMessage.from_bytes(bytes.fromhex(e["sealed"]))
    assert sealed.version == 2 and sealed.algorithm == "ML-KEM-1024"
    aad = bytes.fromhex(e["aad"])
    assert Envelope.open(sealed, sk, expected_aad=aad).hex() == e["plaintext"]
    with pytest.raises(InvalidTag):
        Envelope.open(sealed, sk, expected_aad=b"another context")


def _verifier(algorithm: str) -> Sign | HybridSign:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if "+" in algorithm:
            classical, pqc = algorithm.split("+", 1)
            return HybridSign(classical, pqc)
        return Sign(algorithm)


@pytest.mark.parametrize(
    "s",
    V["signatures_v2"],
    ids=[f"{i}-{s['algorithm']}" for i, s in enumerate(V["signatures_v2"])],
)
def test_v2_signature_verifies(s) -> None:
    algo = s["algorithm"]
    sm = SignedMessage.from_cbor(bytes.fromhex(s["signed_message"]))
    pub = PublicKey(raw=bytes.fromhex(s["public_key"]), algorithm=algo)
    ctx = bytes.fromhex(s["context"])
    verifier = _verifier(algo)
    verifier.verify(sm, pub, context=ctx)
    assert sm.message == b"ts signed message (v2)"
    with pytest.raises(VerificationError):
        verifier.verify(sm, pub, context=b"other-context")
    tampered = SignedMessage(
        message=sm.message + b"!", signature=sm.signature, algorithm=algo, context=sm.context
    )
    with pytest.raises(VerificationError):
        verifier.verify(tampered, pub, context=ctx)


@pytest.mark.parametrize("t", V["standard_jwt"], ids=[t["algorithm"] for t in V["standard_jwt"]])
def test_standard_jwt_verifies(t) -> None:
    claims = StandardJwt.verify(t["token"], t["public_jwk"], issuer=t["issuer"])
    assert claims["sub"] == "ts-user" and claims["n"] == 7 and "exp" not in claims
    with pytest.raises(VerificationError):
        StandardJwt.verify(t["token"], t["public_jwk"], issuer="someone-else")
    with pytest.raises(VerificationError):
        StandardJwt.verify(t["token"], t["public_jwk"], issuer=t["issuer"], require_exp=True)
