"""
Private AKP COSE keys (the 32-byte seed in label -2), through the optional ``cryptography`` backend.
RFC 9964 Appendix A's all-zero seed must derive the RFC's public key.
"""

from __future__ import annotations

import json
import pathlib

import cbor2
import pytest

pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.mldsa",
    reason="needs cryptography >= 48 (seeded ML-DSA)",
)

RFC = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1]
        / "interop"
        / "vectors"
        / "rfc9964_cose_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]


@pytest.mark.parametrize("v", RFC, ids=[v["algorithm"] for v in RFC])
def test_rfc_all_zero_seed_roundtrips_through_a_private_cose_key(v) -> None:
    from quantum_safe.protocols.cose import (
        encode_cose_private_key,
        keypair_from_cose_key,
        sign1,
        verify_sign1,
    )
    from quantum_safe.signatures.core import Sign

    kp = Sign(v["algorithm"], backend="pyca").keypair_from_seed(bytes.fromhex(v["seed"]))
    assert kp.public.raw_bytes == bytes.fromhex(v["public_key"])
    encoded = encode_cose_private_key(kp, kid=bytes.fromhex(v["kid"]))
    m = cbor2.loads(encoded)
    assert m[1] == 7 and m[3] == v["cose_alg"] and m[-2] == bytes(32)
    assert m[-1] == bytes.fromhex(v["public_key"]) and m[2] == bytes.fromhex(v["kid"])
    back = keypair_from_cose_key(encoded)
    assert back.secret.raw_bytes == bytes(32)
    # the key signs COSE_Sign1 and the RFC public key verifies it
    blob = sign1(b"payload", back.secret, kid=bytes.fromhex(v["kid"]))
    assert verify_sign1(blob, kp.public) == b"payload"


def test_decode_cose_key_still_refuses_private_material() -> None:
    from quantum_safe.protocols.cose import decode_cose_key, encode_cose_private_key
    from quantum_safe.signatures.core import Sign

    kp = Sign("ML-DSA-44", backend="pyca").generate_seed_keypair()
    with pytest.raises(ValueError, match="private"):
        decode_cose_key(encode_cose_private_key(kp))


def test_malformed_private_keys_are_refused() -> None:
    from quantum_safe.protocols.cose import encode_cose_private_key, keypair_from_cose_key
    from quantum_safe.signatures.core import Sign

    kp = Sign("ML-DSA-44", backend="pyca").generate_seed_keypair()
    good = cbor2.loads(encode_cose_private_key(kp))
    for bad in (
        {k: v for k, v in good.items() if k != -2},  # no seed
        good | {-2: b"\x00" * 31},  # wrong length
        good | {-1: bytes(len(good[-1]))},  # public key does not match the seed
        good | {1: 2},  # not AKP
    ):
        with pytest.raises(ValueError):
            keypair_from_cose_key(cbor2.dumps(bad))


def test_expanded_liboqs_keys_are_refused() -> None:
    pytest.importorskip("oqs")
    from quantum_safe.protocols.cose import encode_cose_private_key
    from quantum_safe.signatures.core import Sign

    kp = Sign("ML-DSA-44", backend="liboqs").generate_keypair()
    with pytest.raises(ValueError, match="seed"):
        encode_cose_private_key(kp)
