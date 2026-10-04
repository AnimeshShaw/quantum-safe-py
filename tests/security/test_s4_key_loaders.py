"""S4: key loaders refuse ambiguous input.

Before the fix a key map without ``ktype`` loaded as either type (only an
explicit opposite tag was refused), a JWK with any ``kty`` (or none) loaded,
and ``v: true`` passed the version check because bool is an int subclass.
Every key this library has ever written carries ``ktype``, ``kty: "AKP"`` and
an integer ``v`` (checked against every release tag), so valid data is
unaffected.
"""

from __future__ import annotations

import base64

import cbor2
import pytest

from quantum_safe.exceptions import KeyParseError
from quantum_safe.types import KeyPair, PublicKey, SecretKey

ALGO = "ML-DSA-44"
PUB = PublicKey(raw=b"\x01" * 1312, algorithm=ALGO)
SEC = SecretKey(raw=b"\x02" * 2560, algorithm=ALGO)


def _rewrite_pem(pem: str, edit) -> str:
    """Return the PEM with its CBOR body decoded, edited and re-encoded."""
    lines = pem.strip().splitlines()
    blank = lines.index("")
    body = base64.b64decode("".join(lines[blank + 1 : -1]))
    d = cbor2.loads(body)
    edit(d)
    b64 = base64.b64encode(cbor2.dumps(d)).decode()
    wrapped = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "\n".join([*lines[: blank + 1], *wrapped, lines[-1]])


def _drop(field):
    return lambda d: d.pop(field)


def _set(field, value):
    return lambda d: d.__setitem__(field, value)


# ---------------------------------------------------------------------------
# Honest data still loads
# ---------------------------------------------------------------------------


def test_round_trips_still_work() -> None:
    assert PublicKey.from_cbor(PUB.to_cbor()) == PUB
    assert PublicKey.from_pem(PUB.to_pem()) == PUB
    assert PublicKey.from_jwk(PUB.to_jwk()) == PUB
    assert SecretKey.from_cbor(SEC.to_cbor()).raw_bytes == SEC.raw_bytes
    assert SecretKey.from_pem(SEC.to_pem()).raw_bytes == SEC.raw_bytes
    kp = KeyPair.from_cbor_bundle(KeyPair(PUB, SEC).to_cbor_bundle())
    assert kp.public == PUB and kp.secret.raw_bytes == SEC.raw_bytes


# ---------------------------------------------------------------------------
# ktype is required and must match the loader
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ktype", [None, "sec", "SEC", "public", 1])
def test_public_cbor_requires_ktype_pub(ktype) -> None:
    d = cbor2.loads(PUB.to_cbor())
    if ktype is None:
        d.pop("ktype")
    else:
        d["ktype"] = ktype
    with pytest.raises(KeyParseError):
        PublicKey.from_cbor(cbor2.dumps(d))


@pytest.mark.parametrize("ktype", [None, "pub", "secret", 0])
def test_secret_cbor_requires_ktype_sec(ktype) -> None:
    d = cbor2.loads(SEC.to_cbor())
    if ktype is None:
        d.pop("ktype")
    else:
        d["ktype"] = ktype
    with pytest.raises(KeyParseError):
        SecretKey.from_cbor(cbor2.dumps(d))


def test_public_pem_requires_ktype_pub() -> None:
    with pytest.raises(KeyParseError):
        PublicKey.from_pem(_rewrite_pem(PUB.to_pem(), _drop("ktype")))
    with pytest.raises(KeyParseError):
        PublicKey.from_pem(_rewrite_pem(PUB.to_pem(), _set("ktype", "sec")))


def test_secret_pem_requires_ktype_sec() -> None:
    with pytest.raises(KeyParseError):
        SecretKey.from_pem(_rewrite_pem(SEC.to_pem(), _drop("ktype")))
    with pytest.raises(KeyParseError):
        SecretKey.from_pem(_rewrite_pem(SEC.to_pem(), _set("ktype", "pub")))


def test_bundle_with_untagged_member_is_rejected() -> None:
    bundle = cbor2.loads(KeyPair(PUB, SEC).to_cbor_bundle())
    bundle["pub"].pop("ktype")
    with pytest.raises(KeyParseError):
        KeyPair.from_cbor_bundle(cbor2.dumps(bundle))


# ---------------------------------------------------------------------------
# JWK kty must be "AKP"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kty", [None, "RSA", "EC", "OKP", "akp", ""])
def test_jwk_requires_kty_akp(kty) -> None:
    jwk = dict(PUB.to_jwk())
    if kty is None:
        jwk.pop("kty")
    else:
        jwk["kty"] = kty
    with pytest.raises(KeyParseError):
        PublicKey.from_jwk(jwk)


# ---------------------------------------------------------------------------
# version must be a real int
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", [True, False, 1.0, "1"])
def test_version_must_be_a_real_int(version) -> None:
    d = cbor2.loads(PUB.to_cbor())
    d["v"] = version
    with pytest.raises(KeyParseError):
        PublicKey.from_cbor(cbor2.dumps(d))
