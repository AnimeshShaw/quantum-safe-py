"""
quantum_safe.protocols.stream
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Streaming envelope (format v3): authenticated public-key encryption of data that does not fit in
memory, or arrives in pieces. Byte-compatible with quantum-safe-ts (``sealStream`` and
``openStream``).

One KEM encapsulation per stream. The data is cut into chunks of a fixed size (the last may be
shorter or empty), and each chunk is sealed with AES-256-GCM under a key derived from the KEM shared
secret and the stream header. This is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizar
2015): the 96-bit nonce of chunk ``i`` is ``prefix (7 random bytes) || i (u32 big endian) || last
(1 byte)``, so chunks cannot be reordered, dropped from the middle or duplicated, and truncation
fails because the final chunk present was not sealed with ``last = 1``.

Wire layout
-----------
``"QSS3"`` | ``u32 header length`` | header (CBOR) | then per chunk: ``u32 ciphertext length`` |
ciphertext. All integers big endian.

Header
------
CBOR map with exactly five entries ``{"v": 3, "algo": <suite>, "kct": <KEM ciphertext>,
"np": <7-byte nonce prefix>, "cs": <chunk size>}``. The key is ``HKDF(shared secret, info =
"qs-envelope-stream-v3" || 0x00 || H(header))`` with H and HKDF using SHA-256 for hybrid suites
(including X-Wing) and SHA-384 for pure ML-KEM-1024. Every chunk's AAD is
``u32(len(header)) || header || u32(len(aad)) || aad``; the caller's AAD is not stored in the
stream, so the opener must pass the same value.

Like :class:`~quantum_safe.protocols.envelope.Envelope`, a stream is anonymous: it does not
authenticate the sender. Sign separately when that matters.
"""

from __future__ import annotations

import hashlib
import os
import struct
from collections import deque
from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantum_safe._internal import serialization as _ser
from quantum_safe.exceptions import UnsupportedAlgorithm
from quantum_safe.types import PublicKey, SecretKey

STREAM_VERSION = 3
MAGIC = b"QSS3"
NONCE_PREFIX_LEN = 7
TAG_LEN = 16
MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
DEFAULT_CHUNK_SIZE = 64 * 1024
MAX_HEADER_LEN = 64 * 1024
_KEY_INFO = b"qs-envelope-stream-v3"
_ML_KEM_1024 = "ML-KEM-1024"
_XWING = "X-Wing"


# ---------------------------------------------------------------------------
# Suites
# ---------------------------------------------------------------------------


def _uses_sha384(algorithm: str) -> bool:
    """True for pure ML-KEM-1024; False for hybrids and X-Wing; error for anything else."""
    if algorithm == _ML_KEM_1024:
        return True
    if algorithm == _XWING:
        return False
    if "+" in algorithm:
        from quantum_safe.kem.algorithms import KEM_ALGORITHMS, parse_hybrid_name

        classical, pqc = parse_hybrid_name(algorithm)
        if classical in ("X25519", "P-256", "P-384") and pqc in KEM_ALGORITHMS:
            return False
    raise UnsupportedAlgorithm(
        algorithm,
        available=["a hybrid suite such as X25519+ML-KEM-768", _XWING, _ML_KEM_1024],
    )


def _encapsulate(public_key: PublicKey) -> tuple[bytes, Any]:
    """KEM encapsulation for the key's suite. Returns (ciphertext bytes, SharedSecret)."""
    algorithm = public_key.algorithm
    if algorithm == _ML_KEM_1024:
        from quantum_safe.kem.core import KEM

        ct, ss = KEM(_ML_KEM_1024).encapsulate(public_key)
        return ct.data, ss
    if algorithm == _XWING:
        from quantum_safe.kem.xwing import XWing

        xct, xss = XWing().encapsulate(public_key)
        return bytes(xct), xss
    from quantum_safe.kem.algorithms import parse_hybrid_name
    from quantum_safe.kem.hybrid import HybridKEM

    classical, pqc = parse_hybrid_name(algorithm)
    hct, hss = HybridKEM(classical=classical, pqc=pqc).encapsulate(public_key)
    return hct.to_bytes(), hss


def _decapsulate(secret_key: SecretKey, algorithm: str, kem_ct: bytes) -> Any:  # noqa: ANN401
    """KEM decapsulation for the suite named in the stream header. Returns the SharedSecret."""
    if algorithm == _ML_KEM_1024:
        from quantum_safe.kem.core import KEM
        from quantum_safe.types import CipherText

        return KEM(_ML_KEM_1024).decapsulate(secret_key, CipherText(kem_ct, _ML_KEM_1024))
    if algorithm == _XWING:
        from quantum_safe.kem.xwing import XWing
        from quantum_safe.types.kem import CipherText as XCipherText

        return XWing().decapsulate(secret_key, XCipherText(kem_ct, _XWING))
    from quantum_safe.kem.algorithms import parse_hybrid_name
    from quantum_safe.kem.hybrid import HybridKEM
    from quantum_safe.types import HybridCipherText

    classical, pqc = parse_hybrid_name(algorithm)
    return HybridKEM(classical=classical, pqc=pqc).decapsulate(
        secret_key, HybridCipherText.from_bytes(kem_ct, algorithm=algorithm)
    )


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def _encode_header(algorithm: str, kem_ct: bytes, nonce_prefix: bytes, chunk_size: int) -> bytes:
    """CBOR-encode the five-entry stream header (``v``, ``algo``, ``kct``, ``np``, ``cs``)."""
    return _ser.dumps(
        {
            "v": STREAM_VERSION,
            "algo": algorithm,
            "kct": kem_ct,
            "np": nonce_prefix,
            "cs": chunk_size,
        }
    )


def _parse_header(data: bytes) -> dict[str, Any]:
    """Strict parser: exactly five entries, right types, a supported suite, chunk size in range."""
    if len(data) > MAX_HEADER_LEN:
        raise ValueError("stream header is too large")
    try:
        value = _ser.loads_single(data)
    except Exception as exc:
        raise ValueError("stream header is not well-formed CBOR") from exc
    if not isinstance(value, dict) or set(value) != {"v", "algo", "kct", "np", "cs"}:
        raise ValueError("stream header must be a map with exactly v, algo, kct, np and cs")
    if value["v"] != STREAM_VERSION or isinstance(value["v"], bool):
        raise ValueError("stream header has an unsupported version")
    algo, kct, np, cs = value["algo"], value["kct"], value["np"], value["cs"]
    if not isinstance(algo, str):
        raise ValueError("stream header 'algo' must be text")
    try:
        _uses_sha384(algo)
    except UnsupportedAlgorithm as exc:
        raise ValueError(f"stream suite {algo!r} is not supported") from exc
    if not isinstance(kct, bytes) or not isinstance(np, bytes) or len(np) != NONCE_PREFIX_LEN:
        raise ValueError("stream header 'kct' / 'np' are malformed")
    if (
        isinstance(cs, bool)
        or not isinstance(cs, int)
        or not MIN_CHUNK_SIZE <= cs <= MAX_CHUNK_SIZE
    ):
        raise ValueError(f"chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes")
    return {"algorithm": algo, "kem_ct": kct, "nonce_prefix": np, "chunk_size": cs}


def inspect_stream_header(header: bytes) -> dict[str, Any]:
    """Non-secret fields of a stream header (the CBOR bytes), without any key.

    Returns ``{"algorithm", "kem_ciphertext_length", "chunk_size"}``. Raises ``ValueError`` for a
    malformed header.
    """
    h = _parse_header(bytes(header))
    return {
        "algorithm": h["algorithm"],
        "kem_ciphertext_length": len(h["kem_ct"]),
        "chunk_size": h["chunk_size"],
    }


def _derive_key(shared_secret: Any, header: bytes, sha384: bool) -> bytes:  # noqa: ANN401
    """Derive the 32-byte AES-256-GCM key from the shared secret, bound to the header's hash.

    The HKDF info is ``"qs-envelope-stream-v3" || 0x00 || H(header)``; ``sha384`` selects SHA-384
    for both H and HKDF, otherwise SHA-256 is used for both.
    """
    digest = (hashlib.sha384 if sha384 else hashlib.sha256)(header).digest()
    return bytes(
        shared_secret.derive_key(
            length=32,
            info=_KEY_INFO + b"\x00" + digest,
            hash_algorithm="SHA-384" if sha384 else "SHA-256",
        )
    )


def _build_aad(header: bytes, caller_aad: bytes) -> bytes:
    """Per-chunk AAD: ``u32(len(header)) || header || u32(len(aad)) || aad``, big endian."""
    return struct.pack(">I", len(header)) + header + struct.pack(">I", len(caller_aad)) + caller_aad


class _Cipher:
    """State shared by the sealer and the opener: AES-GCM key, nonce prefix, AAD and counter.

    The chunk counter only moves forward and ``_finished`` is never cleared, so a nonce is used
    for at most one chunk.
    """

    def __init__(self, key: bytes, prefix: bytes, aad: bytes, chunk_size: int) -> None:
        """Store the AES-256-GCM key, the 7-byte nonce prefix, the chunk AAD and the chunk size."""
        self._aes = AESGCM(key)
        self._prefix = prefix
        self._aad = aad
        self.chunk_size = chunk_size
        self._counter = 0
        self._finished = False

    def _nonce(self, last: bool) -> bytes:
        """The 12-byte nonce for the current chunk: prefix, u32 counter, then 1 if ``last``."""
        return self._prefix + struct.pack(">I", self._counter) + (b"\x01" if last else b"\x00")

    def _advance(self, last: bool) -> None:
        """Move to the next chunk, or mark the stream finished after the last one.

        Raises ``ValueError`` (and finishes the stream) if a non-final chunk would need a counter
        beyond ``0xFFFFFFFF``.
        """
        if last:
            self._finished = True
        else:
            if self._counter == 0xFFFFFFFF:
                self._finished = True
                raise ValueError("stream has too many chunks")
            self._counter += 1


class StreamSealer(_Cipher):
    """Seals the chunks of one stream, in order.

    Owns the key and the chunk counter, so a nonce cannot be reused or skipped. Send ``header``
    first, then each ciphertext. Every chunk except the last must be exactly ``chunk_size`` bytes;
    the last may be shorter or empty.
    """

    def __init__(
        self,
        public_key: PublicKey,
        aad: bytes = b"",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        """Encapsulate to ``public_key``, derive the stream key and build the header.

        Args:
            public_key: Recipient's KEM public key: a hybrid suite (``X25519+ML-KEM-768`` and
                similar), X-Wing or ML-KEM-1024.
            aad: Associated data bound to every chunk. It is not stored in the stream; the
                opener must pass the same value.
            chunk_size: Plaintext bytes per chunk, from ``MIN_CHUNK_SIZE`` (1024) to
                ``MAX_CHUNK_SIZE`` (16 MiB). Defaults to ``DEFAULT_CHUNK_SIZE`` (64 KiB).

        Raises:
            ValueError: If ``chunk_size`` is out of range.
            UnsupportedAlgorithm: If the key's algorithm is not a supported stream suite.
        """
        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError(
                f"chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
            )
        sha384 = _uses_sha384(public_key.algorithm)
        kem_ct, shared_secret = _encapsulate(public_key)
        prefix = os.urandom(NONCE_PREFIX_LEN)
        header = _encode_header(public_key.algorithm, kem_ct, prefix, chunk_size)
        super().__init__(
            _derive_key(shared_secret, header, sha384),
            prefix,
            _build_aad(header, bytes(aad)),
            chunk_size,
        )
        self.header = header

    def seal_chunk(self, plaintext: bytes, last: bool = False) -> bytes:
        """Seal the next chunk. Pass ``last=True`` for the final one (exactly once).

        Args:
            plaintext: The chunk. Exactly ``chunk_size`` bytes unless ``last`` is true, when any
                length up to ``chunk_size`` (including empty) is accepted.
            last: True for the final chunk of the stream.

        Returns:
            The ciphertext of the chunk: the plaintext length plus a 16-byte tag. The caller
            frames it for transport.

        Raises:
            ValueError: If the stream is already finished, the chunk has the wrong length, or the
                stream has too many chunks.
        """
        return self._seal(plaintext, last, copy=True)

    def _seal(self, plaintext: Any, last: bool, copy: bool) -> bytes:  # noqa: ANN401
        """Seal one chunk. ``copy=False`` lets ``seal_stream`` pass a view of its own bytes.

        With ``copy=True`` the plaintext is copied with ``bytes()`` first, so a buffer the caller
        may change is never read by AES-GCM directly. With ``copy=False`` the buffer (or
        ``memoryview``) is handed to AES-GCM as it is, with no copy; the caller must own it and
        keep it unchanged during the call. The length checks, the nonce and the counter handling
        are identical for both.
        """
        if self._finished:
            raise ValueError("stream is finished; no further chunks are accepted")
        if len(plaintext) > self.chunk_size or (not last and len(plaintext) != self.chunk_size):
            raise ValueError(
                "plaintext chunk has the wrong length: every chunk except the last must be exactly "
                "the chunk size, and none may exceed it"
            )
        out = self._aes.encrypt(
            self._nonce(last), bytes(plaintext) if copy else plaintext, self._aad
        )
        self._advance(last)
        return out


class StreamOpener(_Cipher):
    """Opens the chunks of one stream, in order. A failure ends the stream (it stays failed)."""

    def __init__(self, secret_key: SecretKey, header: bytes, expected_aad: bytes = b"") -> None:
        """Parse the header, decapsulate the KEM ciphertext in it and derive the stream key.

        Args:
            secret_key: Recipient's KEM secret key; its algorithm must equal the header's.
            header: The CBOR stream header, without the magic and the length prefix.
            expected_aad: The associated data the sealer used. It is not stored in the stream.

        Raises:
            ValueError: If the header is malformed or too large, names an unsupported suite or
                chunk size, or its algorithm differs from ``secret_key.algorithm``.
        """
        header = bytes(header)
        h = _parse_header(header)
        if h["algorithm"] != secret_key.algorithm:
            raise ValueError("stream algorithm does not match the secret key algorithm")
        sha384 = _uses_sha384(h["algorithm"])
        shared_secret = _decapsulate(secret_key, h["algorithm"], h["kem_ct"])
        super().__init__(
            _derive_key(shared_secret, header, sha384),
            h["nonce_prefix"],
            _build_aad(header, bytes(expected_aad)),
            h["chunk_size"],
        )

    def open_chunk(self, ciphertext: bytes, last: bool = False) -> bytes:
        """Open the next chunk. ``last`` says whether the transport ended after this chunk.

        Raises ``cryptography.exceptions.InvalidTag`` if the chunk was modified, reordered, dropped
        or truncated, or the key or AAD is wrong; ``ValueError`` for a wrong length or a finished
        stream.

        Args:
            ciphertext: One chunk's ciphertext with its tag, without the length prefix. Exactly
                ``chunk_size + 16`` bytes, or from 16 up to that for the last chunk.
            last: True when no data follows this chunk in the transport.

        Returns:
            The plaintext of the chunk.
        """
        return self._open(ciphertext, last, copy=True)

    def _open(self, ciphertext: Any, last: bool, copy: bool) -> bytes:  # noqa: ANN401
        """Open one chunk. ``copy=False`` lets ``open_stream`` pass a view of its own bytes.

        With ``copy=True`` the ciphertext is copied with ``bytes()`` first; with ``copy=False`` the
        buffer or ``memoryview`` goes to AES-GCM as it is. Any failure (wrong length or a bad tag)
        marks the stream finished, so every later call raises ``ValueError``.
        """
        if self._finished:
            raise ValueError("stream is finished or has failed; no further chunks are accepted")
        n = len(ciphertext)
        ok = TAG_LEN <= n <= self.chunk_size + TAG_LEN if last else n == self.chunk_size + TAG_LEN
        if not ok:
            self._finished = True
            raise ValueError("encrypted chunk has the wrong length for its position in the stream")
        try:
            plaintext = self._aes.decrypt(
                self._nonce(last), bytes(ciphertext) if copy else ciphertext, self._aad
            )
        except InvalidTag:
            self._finished = True
            raise
        self._advance(last)
        return plaintext


# ---------------------------------------------------------------------------
# Whole-stream helpers
# ---------------------------------------------------------------------------


def _pieces(source: Iterable[bytes] | BinaryIO) -> Iterator[bytes]:
    """Yield the source as immutable ``bytes`` pieces.

    A file-like object (anything with ``read``) is read 64 KiB at a time until it returns nothing;
    any other source is iterated, and each item is converted with ``bytes()``. Because every piece
    is immutable ``bytes``, callers may keep ``memoryview`` slices of it without copying.
    """
    if hasattr(source, "read"):
        while True:
            piece = source.read(64 * 1024)
            if not piece:
                return
            yield bytes(piece)
    else:
        for piece in source:
            yield bytes(piece)


def seal_stream(
    public_key: PublicKey,
    source: Iterable[bytes] | BinaryIO,
    aad: bytes = b"",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Iterator[bytes]:
    """Encrypt a stream of byte pieces (any sizes) to ``public_key``.

    ``source`` is a binary file-like object or any iterable of ``bytes``. Yields the encrypted
    stream as byte pieces: the prelude (magic and header), then one frame per chunk. Concatenate
    the pieces to store or send them. Input of any length, including none, is accepted.

    Chunks are sliced out of the input pieces in place. A full chunk is sealed only when more
    input exists beyond it, so the last chunk is always known and is sealed with ``last = 1``;
    it holds the remainder, which may be shorter than ``chunk_size`` or empty. At most
    ``chunk_size`` bytes are carried over between pieces.

    This is a generator: nothing is validated or encrypted until the first piece is requested.

    Args:
        public_key: Recipient's KEM public key (a hybrid suite, X-Wing or ML-KEM-1024).
        source: A binary file-like object or an iterable of ``bytes`` pieces of any sizes.
        aad: Associated data bound to every chunk. It is not stored in the stream; pass the same
            value to :func:`open_stream`.
        chunk_size: Plaintext bytes per chunk, from 1024 to 16 MiB. Defaults to 64 KiB.

    Yields:
        First the prelude (``"QSS3"``, the u32 header length and the header), then one frame per
        chunk: a u32 ciphertext length followed by the ciphertext.

    Raises:
        ValueError: If ``chunk_size`` is out of range (raised on the first iteration), or if the
            stream would have too many chunks.
        UnsupportedAlgorithm: On the first iteration, if the key's algorithm is not a supported
            stream suite.

    Example::

        with open("backup.tar", "rb") as src, open("backup.tar.qss", "wb") as dst:
            for piece in seal_stream(recipient_public_key, src, aad=b"backup-2026"):
                dst.write(piece)
    """
    sealer = StreamSealer(public_key, aad=aad, chunk_size=chunk_size)
    yield MAGIC + struct.pack(">I", len(sealer.header)) + sealer.header
    cs = sealer.chunk_size
    pending = bytearray()  # the bytes carried over from earlier pieces; never more than ``cs``
    for piece in _pieces(source):
        view = memoryview(piece)
        pos = 0
        # Emit a full chunk only when MORE data exists beyond it, so the final chunk is known last.
        if pending and len(pending) + len(view) > cs:
            pos = cs - len(pending)
            pending += view[:pos]
            ct = sealer._seal(pending, False, copy=False)
            pending.clear()
            yield struct.pack(">I", len(ct)) + ct
        while len(view) - pos > cs:
            ct = sealer._seal(view[pos : pos + cs], False, copy=False)
            pos += cs
            yield struct.pack(">I", len(ct)) + ct
        pending += view[pos:]
    ct = sealer.seal_chunk(bytes(pending), last=True)
    yield struct.pack(">I", len(ct)) + ct


class _Reader:
    """Buffers the pieces a source delivers and hands out exact byte counts, in order.

    The pieces are kept as read-only views (``_pieces`` already gave each one as immutable
    ``bytes``), so a frame that lies inside one piece is returned without being copied.
    """

    def __init__(self, source: Iterable[bytes] | BinaryIO) -> None:
        self._it = _pieces(source)
        self._views: deque[memoryview] = deque()
        self._size = 0
        self._ended = False

    def fill(self, n: int) -> None:
        """Read pieces until at least ``n`` bytes are buffered or the source is exhausted."""
        while not self._ended and self._size < n:
            try:
                piece = next(self._it)
            except StopIteration:
                self._ended = True
            else:
                if piece:
                    self._views.append(memoryview(piece))
                    self._size += len(piece)

    def __len__(self) -> int:
        return self._size

    def take(self, n: int) -> bytes:
        """Remove and return the first ``n`` buffered bytes as a ``bytes`` copy."""
        return bytes(self.take_view(n))

    def take_view(self, n: int) -> memoryview | bytes:
        """Remove and return the first ``n`` bytes (fewer if fewer are buffered).

        When the first buffered piece holds all ``n`` bytes, the result is a ``memoryview`` slice
        of that piece and nothing is copied. When the bytes span pieces, they are joined into a
        new ``bytes`` object.
        """
        views = self._views
        if views and len(views[0]) >= n:
            head = views[0]
            out = head[:n]
            if len(head) == n:
                views.popleft()
            else:
                views[0] = head[n:]
            self._size -= n
            return out
        parts = bytearray()
        while views and len(parts) < n:
            head = views[0]
            need = n - len(parts)
            if len(head) <= need:
                parts += head
                views.popleft()
            else:
                parts += head[:need]
                views[0] = head[need:]
        self._size -= len(parts)
        return bytes(parts)

    def peek_u32(self) -> int:
        """The next four buffered bytes as a big-endian u32, without consuming them.

        The caller must have at least four bytes buffered (see ``fill``).
        """
        head = bytearray()
        for view in self._views:
            head += view[: 4 - len(head)]
            if len(head) >= 4:
                break
        return struct.unpack(">I", bytes(head))[0]  # type: ignore[no-any-return]


def open_stream(
    secret_key: SecretKey,
    source: Iterable[bytes] | BinaryIO,
    expected_aad: bytes = b"",
) -> Iterator[bytes]:
    """Decrypt a stream made by :func:`seal_stream` (or by quantum-safe-ts ``sealStream``).

    The source may deliver the bytes in pieces of any size. Yields the plaintext chunk by chunk and
    raises on the first chunk that fails: a truncated, extended, reordered or modified stream never
    completes silently.

    A frame is the last one when no byte follows it in the source, so each frame is read together
    with one byte of lookahead. Frames inside one input piece are passed to AES-GCM without being
    copied. This is a generator: nothing is read until the first plaintext chunk is requested.

    Args:
        secret_key: Recipient's KEM secret key; its algorithm must equal the stream's.
        source: A binary file-like object or an iterable of ``bytes`` pieces of any sizes.
        expected_aad: The associated data the sealer used. It is not stored in the stream.

    Yields:
        The plaintext of each chunk, in order. The last one may be empty.

    Raises:
        ValueError: If the stream is too short, has the wrong magic, a header length or frame
            length out of range, ends inside the header or a frame, ends without a final chunk,
            or has a malformed header or a key algorithm mismatch.
        cryptography.exceptions.InvalidTag: If a chunk was modified, reordered, dropped or
            truncated, or the key or ``expected_aad`` is wrong.

    Example::

        with open("backup.tar.qss", "rb") as src, open("backup.tar", "wb") as dst:
            for chunk in open_stream(recipient_secret_key, src, expected_aad=b"backup-2026"):
                dst.write(chunk)
    """
    r = _Reader(source)
    r.fill(8)
    if len(r) < 8:
        raise ValueError("stream is too short to contain a header")
    if r.take(4) != MAGIC:
        raise ValueError("not a quantum-safe stream (bad magic)")
    header_len = r.peek_u32()
    r.take(4)
    if header_len == 0 or header_len > MAX_HEADER_LEN:
        raise ValueError("stream header length is out of range")
    r.fill(header_len)
    if len(r) < header_len:
        raise ValueError("stream ended inside the header")
    opener = StreamOpener(secret_key, r.take(header_len), expected_aad=expected_aad)
    max_frame = opener.chunk_size + TAG_LEN
    while True:
        r.fill(4)
        if len(r) == 0:
            raise ValueError("stream ended without a final chunk (truncated)")
        if len(r) < 4:
            raise ValueError("stream ended inside a frame length (truncated)")
        n = r.peek_u32()
        if n < TAG_LEN or n > max_frame:
            raise ValueError("stream frame length is out of range")
        # Need the whole frame AND to know whether any byte follows it (that says if it is last).
        r.fill(4 + n + 1)
        if len(r) < 4 + n:
            raise ValueError("stream ended inside a frame (truncated)")
        r.take(4)
        ciphertext = r.take_view(n)
        last = len(r) == 0
        yield opener._open(ciphertext, last, copy=False)
        if last:
            return


def seal_bytes(
    public_key: PublicKey,
    data: bytes,
    aad: bytes = b"",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Encrypt a whole buffer. Returns the complete encrypted stream.

    Args:
        public_key: Recipient's KEM public key (a hybrid suite, X-Wing or ML-KEM-1024).
        data: The plaintext. Any length, including empty.
        aad: Associated data bound to every chunk; pass the same value to :func:`open_bytes`.
        chunk_size: Plaintext bytes per chunk, from 1024 to 16 MiB. Defaults to 64 KiB.

    Returns:
        The encrypted stream: magic, header and all chunk frames, concatenated.

    Raises:
        ValueError: If ``chunk_size`` is out of range.
        UnsupportedAlgorithm: If the key's algorithm is not a supported stream suite.
    """
    return b"".join(seal_stream(public_key, [bytes(data)], aad=aad, chunk_size=chunk_size))


def open_bytes(secret_key: SecretKey, data: bytes, expected_aad: bytes = b"") -> bytes:
    """Decrypt a whole buffer produced by :func:`seal_bytes` (or quantum-safe-ts ``sealBytes``).

    Args:
        secret_key: Recipient's KEM secret key; its algorithm must equal the stream's.
        data: The complete encrypted stream.
        expected_aad: The associated data used when sealing.

    Returns:
        The plaintext.

    Raises:
        ValueError: If the stream is malformed or truncated (see :func:`open_stream`).
        cryptography.exceptions.InvalidTag: If a chunk fails authentication, or the key or
            ``expected_aad`` is wrong.
    """
    return b"".join(open_stream(secret_key, [bytes(data)], expected_aad=expected_aad))
