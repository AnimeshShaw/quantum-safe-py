"""S5: malformed input raises the library's typed error, never a raw Python error.

Before the fix, malformed key, signed-message and sealed-message documents
raised AttributeError / TypeError / KeyError / IndexError (which escape callers
that catch KeyParseError), and some wrong-typed fields were silently coerced:
``bytes(5)`` turned an integer ``msg`` or ``kct`` into five zero bytes.
"""

from __future__ import annotations

import cbor2
import pytest

from quantum_safe.exceptions import KeyParseError
from quantum_safe.protocols.envelope import SealedMessage
from quantum_safe.types import KeyPair, PublicKey, SecretKey
from quantum_safe.types.signatures import SignedMessage

PUB = PublicKey(raw=b"\x01" * 1312, algorithm="ML-DSA-44")
SEC = SecretKey(raw=b"\x02" * 2560, algorithm="ML-DSA-44")
GOOD_KEY = cbor2.loads(PUB.to_cbor())
GOOD_SM = {
    "v": 1,
    "msg": b"m",
    "sig": b"\x00" * 33,
    "algo": "ML-DSA-44",
    "ctx": b"",
    "fp": "",
    "ts": 1.0,
    "hybrid": False,
}
GOOD_SEALED = {
    "v": 1,
    "algo": "X25519+ML-KEM-768",
    "kct": b"k",
    "n": b"\x00" * 12,
    "ct": b"c" * 17,
    "aad": b"",
}


def _k(**kw):
    return cbor2.dumps({**GOOD_KEY, **kw})


def _sm(**kw):
    d = {**GOOD_SM, **kw}
    return cbor2.dumps({k: v for k, v in d.items() if v is not _DROP})


def _sealed(**kw):
    d = {**GOOD_SEALED, **kw}
    return cbor2.dumps({k: v for k, v in d.items() if v is not _DROP})


_DROP = object()

KEY_CASES = {
    "array": cbor2.dumps([1, 2]),
    "int": cbor2.dumps(5),
    "text": cbor2.dumps("pub"),
    "key is text": _k(key="abc"),
    "key is int": _k(key=5),
    "key is list": _k(key=[1, 2]),
    "algo is int": _k(algo=5),
    "algo is bytes": _k(algo=b"ML-DSA-44"),
    "algo is null": _k(algo=None),
    "v is text": _k(v="1"),
}


@pytest.mark.parametrize("data", KEY_CASES.values(), ids=KEY_CASES.keys())
@pytest.mark.parametrize("loader", [PublicKey.from_cbor, SecretKey.from_cbor])
def test_key_cbor_errors_are_typed(loader, data: bytes) -> None:
    with pytest.raises(KeyParseError):
        loader(data)


@pytest.mark.parametrize("pem", ["", "   ", "\n", b"-----BEGIN", 5, None])
@pytest.mark.parametrize("loader", [PublicKey.from_pem, SecretKey.from_pem])
def test_pem_errors_are_typed(loader, pem) -> None:
    with pytest.raises(KeyParseError):
        loader(pem)


JWK_CASES = {
    "list": [1],
    "string": "jwk",
    "alg is int": {**PUB.to_jwk(), "alg": 5},
    "pub is int": {**PUB.to_jwk(), "pub": 5},
    "pub is bytes": {**PUB.to_jwk(), "pub": b"AAAA"},
}


@pytest.mark.parametrize("jwk", JWK_CASES.values(), ids=JWK_CASES.keys())
def test_jwk_errors_are_typed(jwk) -> None:
    with pytest.raises(KeyParseError):
        PublicKey.from_jwk(jwk)


BUNDLE_CASES = {
    "array": cbor2.dumps([1]),
    "no pub": cbor2.dumps({"v": 1, "bundle": "keypair", "sec": cbor2.loads(SEC.to_cbor())}),
    "pub is int": cbor2.dumps({"v": 1, "bundle": "keypair", "pub": 5, "sec": 5}),
}


@pytest.mark.parametrize("data", BUNDLE_CASES.values(), ids=BUNDLE_CASES.keys())
def test_bundle_errors_are_typed(data: bytes) -> None:
    with pytest.raises(KeyParseError):
        KeyPair.from_cbor_bundle(data)


SM_CASES = {
    "array": cbor2.dumps([1]),
    "int": cbor2.dumps(5),
    "no msg": _sm(msg=_DROP),
    "no sig": _sm(sig=_DROP),
    "no algo": _sm(algo=_DROP),
    "msg is int": _sm(msg=5),
    "sig is text": _sm(sig="x"),
    "algo is int": _sm(algo=5),
    "ctx is text": _sm(ctx="c"),
    "fp is bytes": _sm(fp=b"f"),
    "ts is text": _sm(ts="x"),
    "ts is bool": _sm(ts=True),
    "hybrid is int": _sm(hybrid=1),
    "v is true": _sm(v=True),
    "v is text": _sm(v="1"),
}


@pytest.mark.parametrize("data", SM_CASES.values(), ids=SM_CASES.keys())
def test_signed_message_errors_are_typed(data: bytes) -> None:
    with pytest.raises(KeyParseError):
        SignedMessage.from_cbor(data)


SEALED_CASES = {
    "array": cbor2.dumps([1]),
    "int": cbor2.dumps(5),
    "no kct": _sealed(kct=_DROP),
    "kct is int": _sealed(kct=5),
    "n is text": _sealed(n="0" * 12),
    "ct is list": _sealed(ct=[1]),
    "aad is text": _sealed(aad="a"),
    "algo is int": _sealed(algo=5),
    "v is text": _sealed(v="1"),
    "v is true": _sealed(v=True),
}


@pytest.mark.parametrize("data", SEALED_CASES.values(), ids=SEALED_CASES.keys())
def test_sealed_message_errors_are_typed(data: bytes) -> None:
    with pytest.raises(KeyParseError):
        SealedMessage.from_bytes(data)


def test_valid_documents_still_load() -> None:
    assert PublicKey.from_cbor(PUB.to_cbor()) == PUB
    assert SecretKey.from_pem(SEC.to_pem()).raw_bytes == SEC.raw_bytes
    sm = SignedMessage.from_cbor(_sm())
    assert sm.message == b"m" and sm.algorithm == "ML-DSA-44"
    # Integer timestamps (as other writers may produce) are still accepted.
    assert SignedMessage.from_cbor(_sm(ts=5)).signed_at == 5.0
    sealed = SealedMessage.from_bytes(_sealed())
    assert sealed.kem_ct == b"k" and sealed.version == 1
