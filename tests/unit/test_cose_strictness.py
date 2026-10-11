"""
COSE parsing has exactly one reading of every message (RFC 9052 section 3.1 says labels must be
unique across the protected and unprotected buckets; RFC 8949 allows several spellings of the same
value). Anything another parser could read differently is refused: non-minimal or indefinite-length
encodings, a label present in both header buckets, duplicate map labels, trailing bytes.
"""

from __future__ import annotations

import json
import pathlib

import cbor2
import pytest

pytestmark = pytest.mark.requires_liboqs

RFC = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1]
        / "interop"
        / "vectors"
        / "rfc9964_cose_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]


@pytest.fixture(scope="module")
def kp65():
    from quantum_safe.signatures.core import Sign

    return Sign("ML-DSA-65").generate_keypair()


def _good(kp65) -> bytes:
    from quantum_safe.protocols.cose import sign1

    return sign1(b"m", kp65.secret, kid=b"k")


def test_indefinite_length_outer_array_is_refused(kp65) -> None:
    from quantum_safe.protocols.cose import verify_sign1

    parts = cbor2.loads(_good(kp65)).value
    indefinite = (
        bytes([0xD2, 0x9F])  # tag 18, then an indefinite-length array
        + cbor2.dumps(parts[0])
        + cbor2.dumps({})
        + cbor2.dumps(parts[2])
        + cbor2.dumps(parts[3])
        + bytes([0xFF])
    )
    with pytest.raises(ValueError):
        verify_sign1(indefinite, kp65.public)


def test_non_minimal_length_is_refused(kp65) -> None:
    from quantum_safe.protocols.cose import verify_sign1

    good = _good(kp65)
    assert good[:2] == bytes([0xD2, 0x84])  # tag 18, array of 4
    non_minimal = bytes([0xD2, 0x98, 0x04]) + good[2:]  # the same length spelled with one more byte
    with pytest.raises(ValueError):
        verify_sign1(non_minimal, kp65.public)


def test_a_label_in_both_header_buckets_is_refused(kp65) -> None:
    from quantum_safe.protocols.cose import inspect_sign1, verify_sign1

    parts = cbor2.loads(_good(kp65)).value
    kid_twice = cbor2.dumps(cbor2.CBORTag(18, [parts[0], {4: b"other-kid"}, parts[2], parts[3]]))
    alg_twice = cbor2.dumps(cbor2.CBORTag(18, [parts[0], {1: -48}, parts[2], parts[3]]))
    for bad in (kid_twice, alg_twice):
        with pytest.raises(ValueError):
            verify_sign1(bad, kp65.public)
        with pytest.raises(ValueError):
            inspect_sign1(bad)


def test_cose_key_duplicate_labels_and_trailing_bytes_are_refused() -> None:
    from quantum_safe.protocols.cose import decode_cose_key

    pub = bytes.fromhex(RFC[0]["public_key"])
    other = bytes(len(pub))
    # {1: 7, 3: -48, -1: pub, -1: other}: two different public keys under one label.
    dup = (
        bytes([0xA4, 0x01, 0x07, 0x03, 0x38, 0x2F, 0x20])
        + cbor2.dumps(pub)
        + bytes([0x20])
        + cbor2.dumps(other)
    )
    with pytest.raises(ValueError):
        decode_cose_key(dup)
    good = cbor2.dumps({1: 7, 3: -48, -1: pub})
    assert decode_cose_key(good)[0].raw_bytes == pub
    with pytest.raises(ValueError):
        decode_cose_key(good + bytes([0x00]))
    indefinite_map = (
        bytes([0xBF, 0x01, 0x07, 0x03, 0x38, 0x2F, 0x20]) + cbor2.dumps(pub) + bytes([0xFF])
    )
    with pytest.raises(ValueError):
        decode_cose_key(indefinite_map)
