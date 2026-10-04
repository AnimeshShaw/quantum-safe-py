"""S3: a hybrid signature payload must be exactly the four documented entries.

The payload is a CBOR map {classical_sig, pqc_sig, classical_algo, pqc_algo}.
None of it except the two sub-signatures is covered by a signature, so before
the fix extra entries, duplicate keys and trailing bytes were ignored: several
different byte strings verified as the same signature (malleability). The
algorithm names in the payload must also match the verifier's components.
"""

from __future__ import annotations

import dataclasses
import warnings

import cbor2
import pytest

from quantum_safe.exceptions import VerificationError
from quantum_safe.signatures.hybrid import HybridSign
from quantum_safe.types.signatures import HybridSignature

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module")
def signed():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        h = HybridSign("Ed25519", "ML-DSA-44")
    kp = h.generate_keypair()
    sm = h.sign(b"msg", kp.secret)
    return h, kp, sm


def _with_payload(sm, payload: bytes):
    blob = sm.signature
    plen = blob[0]
    return dataclasses.replace(sm, signature=blob[: 1 + plen] + payload)


def _payload(sm) -> bytes:
    plen = sm.signature[0]
    return sm.signature[1 + plen :]


def test_honest_signature_verifies(signed) -> None:
    h, kp, sm = signed
    h.verify(sm, kp.public, context=b"")


def test_extra_entry_is_rejected(signed) -> None:
    h, kp, sm = signed
    d = cbor2.loads(_payload(sm))
    d["extra"] = b"unsigned"
    with pytest.raises(VerificationError):
        h.verify(_with_payload(sm, cbor2.dumps(d)), kp.public, context=b"")


@pytest.mark.parametrize("missing", ["classical_sig", "pqc_sig", "classical_algo", "pqc_algo"])
def test_missing_entry_is_rejected(signed, missing: str) -> None:
    h, kp, sm = signed
    d = cbor2.loads(_payload(sm))
    del d[missing]
    with pytest.raises(VerificationError):
        h.verify(_with_payload(sm, cbor2.dumps(d)), kp.public, context=b"")


@pytest.mark.parametrize(
    ("field", "value"),
    [("pqc_algo", "ML-DSA-65"), ("classical_algo", "P-256"), ("pqc_algo", "ml-dsa-44")],
)
def test_wrong_algorithm_name_is_rejected(signed, field: str, value: str) -> None:
    h, kp, sm = signed
    d = cbor2.loads(_payload(sm))
    d[field] = value
    with pytest.raises(VerificationError):
        h.verify(_with_payload(sm, cbor2.dumps(d)), kp.public, context=b"")


@pytest.mark.parametrize(
    ("field", "value"),
    [("classical_sig", "text"), ("pqc_sig", 5), ("classical_algo", b"Ed25519"), ("pqc_algo", None)],
)
def test_wrong_field_type_is_rejected(signed, field: str, value: object) -> None:
    h, kp, sm = signed
    d = cbor2.loads(_payload(sm))
    d[field] = value
    with pytest.raises(VerificationError):
        h.verify(_with_payload(sm, cbor2.dumps(d)), kp.public, context=b"")


def test_trailing_bytes_are_rejected(signed) -> None:
    h, kp, sm = signed
    with pytest.raises(VerificationError):
        h.verify(_with_payload(sm, _payload(sm) + b"\x00"), kp.public, context=b"")


def test_duplicate_key_is_rejected(signed) -> None:
    """A map header of 5 entries with 'pqc_algo' twice: cbor2 keeps the last."""
    h, kp, sm = signed
    raw = _payload(sm)
    assert raw[0] == 0xA4
    dup = bytes([0xA5]) + raw[1:] + cbor2.dumps("pqc_algo") + cbor2.dumps("ML-DSA-44")
    with pytest.raises(VerificationError):
        h.verify(_with_payload(sm, dup), kp.public, context=b"")


def test_from_bytes_round_trip_and_rejections() -> None:
    hs = HybridSignature(b"c" * 64, b"p" * 10, "Ed25519", "ML-DSA-44")
    assert HybridSignature.from_bytes(hs.to_bytes()) == hs
    for bad in (b"", hs.to_bytes() + b"\x00", cbor2.dumps([1, 2]), cbor2.dumps(5)):
        with pytest.raises(VerificationError):
            HybridSignature.from_bytes(bad)
