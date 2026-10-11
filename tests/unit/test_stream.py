"""
Streaming envelope, format v3 (audit item PY-X2): authenticated public-key encryption of data that does
not fit in memory or arrives in pieces. One KEM encapsulation per stream, AES-256-GCM per chunk with the
STREAM nonce construction. Byte-compatible with quantum-safe-ts: the vectors in
``tests/interop/vectors/stream_vectors.json`` were written by it and must open here.
"""

from __future__ import annotations

import io
import json
import pathlib
import struct

import pytest
from cryptography.exceptions import InvalidTag

pytestmark = pytest.mark.requires_liboqs

VECTORS = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1] / "interop" / "vectors" / "stream_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]


@pytest.fixture(scope="module")
def pair():
    from quantum_safe.kem.hybrid import HybridKEM

    return HybridKEM().generate_keypair()


def _data(n: int) -> bytes:
    return bytes((i * 31 + n) & 0xFF for i in range(n))


class TestRoundTrip:
    @pytest.mark.parametrize("length", [0, 1, 1023, 1024, 1025, 4096, 5000])
    def test_bytes(self, pair, length: int) -> None:
        from quantum_safe.protocols.stream import open_bytes, seal_bytes

        data = _data(length)
        blob = seal_bytes(pair.public, data, chunk_size=1024)
        assert open_bytes(pair.secret, blob) == data

    def test_streaming_from_a_file_like_object_and_in_odd_pieces(self, pair) -> None:
        from quantum_safe.protocols.stream import open_stream, seal_stream

        data = _data(10_000)
        sealed = b"".join(seal_stream(pair.public, io.BytesIO(data), chunk_size=1024))
        pieces = [
            sealed[i : i + 7] for i in range(0, len(sealed), 7)
        ]  # arbitrary transport framing
        assert b"".join(open_stream(pair.secret, pieces)) == data

    def test_chunks_are_exactly_chunk_size_plus_tag(self, pair) -> None:
        from quantum_safe.protocols.stream import StreamSealer

        s = StreamSealer(pair.public, chunk_size=1024)
        assert len(s.seal_chunk(b"x" * 1024)) == 1024 + 16
        assert len(s.seal_chunk(b"y" * 10, last=True)) == 10 + 16

    def test_pure_ml_kem_1024_and_xwing(self) -> None:
        from quantum_safe import KEM, XWing
        from quantum_safe.protocols.stream import open_bytes, seal_bytes

        for kp in (KEM("ML-KEM-1024").generate_keypair(), XWing().generate_keypair()):
            blob = seal_bytes(kp.public, _data(3000), aad=b"a", chunk_size=1024)
            assert open_bytes(kp.secret, blob, expected_aad=b"a") == _data(3000)


class TestFailsClosed:
    def _blob(self, pair, length: int = 3000, aad: bytes = b"") -> bytes:
        from quantum_safe.protocols.stream import seal_bytes

        return seal_bytes(pair.public, _data(length), aad=aad, chunk_size=1024)

    def _frames(self, blob: bytes) -> tuple[bytes, list[bytes]]:
        hlen = struct.unpack(">I", blob[4:8])[0]
        prelude, pos = blob[: 8 + hlen], 8 + hlen
        frames = []
        while pos < len(blob):
            n = struct.unpack(">I", blob[pos : pos + 4])[0]
            frames.append(blob[pos : pos + 4 + n])
            pos += 4 + n
        return prelude, frames

    def test_truncation_is_detected(self, pair) -> None:
        from quantum_safe.protocols.stream import open_bytes

        prelude, frames = self._frames(self._blob(pair))
        assert len(frames) == 3
        with pytest.raises((InvalidTag, ValueError)):
            open_bytes(pair.secret, prelude + b"".join(frames[:-1]))  # last chunk dropped

    def test_reordering_is_detected(self, pair) -> None:
        from quantum_safe.protocols.stream import open_bytes

        prelude, frames = self._frames(self._blob(pair))
        with pytest.raises(InvalidTag):
            open_bytes(pair.secret, prelude + frames[1] + frames[0] + frames[2])

    def test_dropping_a_middle_chunk_is_detected(self, pair) -> None:
        from quantum_safe.protocols.stream import open_bytes

        prelude, frames = self._frames(self._blob(pair))
        with pytest.raises(InvalidTag):
            open_bytes(pair.secret, prelude + frames[0] + frames[2])

    def test_extension_is_detected(self, pair) -> None:
        from quantum_safe.protocols.stream import open_bytes

        blob = self._blob(pair)
        with pytest.raises((InvalidTag, ValueError)):
            open_bytes(pair.secret, blob + struct.pack(">I", 16) + b"\x00" * 16)

    def test_bit_flip_anywhere_is_detected(self, pair) -> None:
        from quantum_safe.protocols.stream import open_bytes

        blob = bytearray(self._blob(pair, 1500))
        for pos in (0, 10, len(blob) // 2, len(blob) - 1):
            bad = bytearray(blob)
            bad[pos] ^= 1
            with pytest.raises((InvalidTag, ValueError, Exception)):
                open_bytes(pair.secret, bytes(bad))

    def test_wrong_key(self, pair) -> None:
        from quantum_safe.kem.hybrid import HybridKEM
        from quantum_safe.protocols.stream import open_bytes

        other = HybridKEM().generate_keypair()
        with pytest.raises(InvalidTag):
            open_bytes(other.secret, self._blob(pair))

    def test_aad_must_match(self, pair) -> None:
        from quantum_safe.protocols.stream import open_bytes

        blob = self._blob(pair, aad=b"file-7")
        assert open_bytes(pair.secret, blob, expected_aad=b"file-7") == _data(3000)
        with pytest.raises(InvalidTag):
            open_bytes(pair.secret, blob, expected_aad=b"file-8")
        with pytest.raises(InvalidTag):
            open_bytes(pair.secret, blob)  # AAD is not stored in the stream: omitted means empty

    def test_opener_refuses_after_the_last_chunk_and_after_a_failure(self, pair) -> None:
        from quantum_safe.protocols.stream import StreamOpener, StreamSealer

        s = StreamSealer(pair.public, chunk_size=1024)
        c0 = s.seal_chunk(b"a" * 1024)
        c1 = s.seal_chunk(b"b", last=True)
        with pytest.raises(ValueError):
            s.seal_chunk(b"c")  # finished
        o = StreamOpener(pair.secret, s.header)
        assert o.open_chunk(c0) == b"a" * 1024
        assert o.open_chunk(c1, last=True) == b"b"
        with pytest.raises(ValueError):
            o.open_chunk(c1, last=True)
        o2 = StreamOpener(pair.secret, s.header)
        with pytest.raises(InvalidTag):
            o2.open_chunk(c1, last=True)  # wrong position
        with pytest.raises(ValueError):
            o2.open_chunk(c0)  # failed streams stay failed

    def test_chunk_length_rules(self, pair) -> None:
        from quantum_safe.protocols.stream import StreamSealer

        s = StreamSealer(pair.public, chunk_size=1024)
        with pytest.raises(ValueError):
            s.seal_chunk(b"short")  # a non-last chunk must be exactly chunk_size
        with pytest.raises(ValueError):
            s.seal_chunk(b"x" * 1025, last=True)  # nothing exceeds chunk_size

    @pytest.mark.parametrize("bad", [0, 1023, 16 * 1024 * 1024 + 1])
    def test_chunk_size_bounds(self, pair, bad: int) -> None:
        from quantum_safe.protocols.stream import StreamSealer

        with pytest.raises(ValueError):
            StreamSealer(pair.public, chunk_size=bad)

    def test_header_parser_is_strict(self, pair) -> None:
        import cbor2

        from quantum_safe.protocols.stream import StreamOpener, StreamSealer, inspect_stream_header

        header = StreamSealer(pair.public, chunk_size=1024).header
        info = inspect_stream_header(header)
        assert info["algorithm"] == "X25519+ML-KEM-768" and info["chunk_size"] == 1024
        good = cbor2.loads(header)
        for mutate in (
            lambda d: d | {"extra": 1},
            lambda d: {k: v for k, v in d.items() if k != "np"},
            lambda d: d | {"v": 2},
            lambda d: d | {"np": b"\x00" * 6},
            lambda d: d | {"cs": 10},
            lambda d: d | {"algo": "RSA-2048"},
        ):
            with pytest.raises(ValueError):
                inspect_stream_header(cbor2.dumps(mutate(dict(good))))
        with pytest.raises(ValueError):
            inspect_stream_header(header + b"\x00")  # trailing bytes
        with pytest.raises(ValueError):
            StreamOpener(pair.secret, header[:-1])

    def test_unsupported_suite(self) -> None:
        from quantum_safe import KEM
        from quantum_safe.exceptions import UnsupportedAlgorithm
        from quantum_safe.protocols.stream import StreamSealer

        with pytest.raises(UnsupportedAlgorithm):
            StreamSealer(KEM("ML-KEM-768").generate_keypair().public)  # pure ML-KEM-1024 only


class TestInteropWithTypeScript:
    @pytest.mark.parametrize("i", range(len(VECTORS)))
    def test_opens_what_typescript_sealed(self, i: int) -> None:
        from quantum_safe.protocols.stream import open_bytes
        from quantum_safe.types import SecretKey

        v = VECTORS[i]
        sk = SecretKey(bytes.fromhex(v["secret_key"]), v["algorithm"])
        got = open_bytes(sk, bytes.fromhex(v["stream"]), expected_aad=bytes.fromhex(v["aad"]))
        assert got == bytes.fromhex(v["plaintext"])

    def test_vectors_cover_every_suite_and_boundary(self) -> None:
        assert {v["algorithm"] for v in VECTORS} == {
            "X25519+ML-KEM-768",
            "P-256+ML-KEM-512",
            "ML-KEM-1024",
            "X-Wing",
        }
        assert {len(bytes.fromhex(v["plaintext"])) for v in VECTORS} >= {
            0,
            1,
            1024,
            1025,
            2048,
            3000,
        }
