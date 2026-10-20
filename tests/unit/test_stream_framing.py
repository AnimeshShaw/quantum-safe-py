"""Framing of the stream format is fixed: these values were produced by the implementation that
shipped before the copy-reducing rewrite of ``seal_stream`` / ``open_stream``, so any change in how the
input is chunked, framed or read back shows up here.

The KEM and the randomness are replaced by fixed stand-ins, so the whole stream is deterministic.
"""

from __future__ import annotations

import hashlib
import io

import pytest

pytestmark = pytest.mark.requires_liboqs

CHUNK = 1024
AAD = b"golden"

# plaintext length -> (SHA-256 of the whole stream, length of each piece that seal_stream yields)
GOLDEN = {
    0: (
        "ecd5f9d3d687613f785b840801a43ad10efd5d524e47a04346436d4a096cf3cd",
        [258, 20],
    ),
    1: (
        "a7b91122c0c1a01c24f689d1ed63a371bae66aa2cf652b525d153975a3ab6f02",
        [258, 21],
    ),
    1023: (
        "59ea54af1a2420f49ff1fb535ac84e1be9d86dbd91b726251b78da501d191e31",
        [258, 1043],
    ),
    1024: (
        "12a02e85ccabd3039543220d38c961ce4b319c6f4cd31cd69bdabb72d256027e",
        [258, 1044],
    ),
    1025: (
        "89036df28c48a0ba7cc16c70b249e5719c14881251555faf718a503d802fe79b",
        [258, 1044, 21],
    ),
    2048: (
        "9e6cc3015293db07fd8c2e5604d3dccf9b52f185ec1496ce7f795c447d3c59e1",
        [258, 1044, 1044],
    ),
    3079: (
        "1944dab118e7e9ce8b29d747a6704b01fb55e7441d9a19ab2fafa1c7066f3afe",
        [258, 1044, 1044, 1044, 27],
    ),
}


class _Secret:
    def derive_key(self, length: int, info: bytes, hash_algorithm: str) -> bytes:
        return hashlib.sha256(hash_algorithm.encode() + info).digest()[:length]


@pytest.fixture(scope="module")
def pair():
    from quantum_safe.kem.hybrid import HybridKEM

    return HybridKEM().generate_keypair()


@pytest.fixture(autouse=True)
def _deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    from quantum_safe.protocols import stream

    monkeypatch.setattr(stream, "_encapsulate", lambda pk: (bytes(range(200)), _Secret()))
    monkeypatch.setattr(stream, "_decapsulate", lambda sk, algo, ct: _Secret())
    monkeypatch.setattr(stream.os, "urandom", lambda k: bytes(range(1, 1 + k)))


def _data(n: int) -> bytes:
    return bytes((i * 7 + 3) % 251 for i in range(n))


def _pieces(data: bytes, size: int | None) -> list[bytes]:
    if size is None:
        return [data]
    return [data[i : i + size] for i in range(0, len(data), size)] or [b""]


@pytest.mark.parametrize("piece_size", [None, 1000, 1023, 1025, 1])
@pytest.mark.parametrize("length", sorted(GOLDEN))
def test_sealed_stream_matches_the_recorded_one(pair, length: int, piece_size: int | None) -> None:
    from quantum_safe.protocols.stream import seal_stream

    if piece_size == 1 and length > 1100:
        pytest.skip("one-byte pieces are covered at the smaller sizes")
    frames = list(
        seal_stream(pair.public, _pieces(_data(length), piece_size), aad=AAD, chunk_size=CHUNK)
    )
    digest, lengths = GOLDEN[length]
    assert [len(f) for f in frames] == lengths
    assert hashlib.sha256(b"".join(frames)).hexdigest() == digest


@pytest.mark.parametrize("piece_size", [3, 1000, 1044, 1500, None])
@pytest.mark.parametrize("length", sorted(GOLDEN))
def test_recorded_stream_opens_from_any_piece_size(
    pair, length: int, piece_size: int | None
) -> None:
    from quantum_safe.protocols.stream import open_stream, seal_stream

    stream_bytes = b"".join(seal_stream(pair.public, [_data(length)], aad=AAD, chunk_size=CHUNK))
    assert hashlib.sha256(stream_bytes).hexdigest() == GOLDEN[length][0]
    source = _pieces(stream_bytes, piece_size)
    assert b"".join(open_stream(pair.secret, source, expected_aad=AAD)) == _data(length)


def test_file_objects_work_in_both_directions(pair) -> None:
    from quantum_safe.protocols.stream import open_stream, seal_stream

    data = _data(5000)
    sealed = b"".join(seal_stream(pair.public, io.BytesIO(data), aad=AAD, chunk_size=CHUNK))
    assert b"".join(open_stream(pair.secret, io.BytesIO(sealed), expected_aad=AAD)) == data


@pytest.mark.parametrize("source_type", [bytes, bytearray, memoryview])
def test_pieces_of_any_buffer_type_are_accepted(pair, source_type) -> None:
    from quantum_safe.protocols.stream import seal_stream

    data = _data(3079)
    frames = list(
        seal_stream(
            pair.public,
            [source_type(data[:1500]), source_type(data[1500:])],
            aad=AAD,
            chunk_size=CHUNK,
        )
    )
    assert hashlib.sha256(b"".join(frames)).hexdigest() == GOLDEN[3079][0]


def test_a_reused_input_buffer_does_not_change_what_was_sealed(pair) -> None:
    """A source may refill one buffer between pieces; what was already read must not change."""
    from quantum_safe.protocols.stream import seal_stream

    data = _data(3079)
    buf = bytearray(1000)

    def source():
        for i in range(0, len(data), 1000):
            part = data[i : i + 1000]
            buf[: len(part)] = part
            yield buf[: len(part)] if len(part) < 1000 else buf

    frames = list(seal_stream(pair.public, source(), aad=AAD, chunk_size=CHUNK))
    assert hashlib.sha256(b"".join(frames)).hexdigest() == GOLDEN[3079][0]
