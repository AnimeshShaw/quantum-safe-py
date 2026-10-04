"""
quantum_safe._internal.serialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A thin serialization layer over cbor2.

cbor2 is a **required** dependency (see ``dependencies`` in pyproject.toml).
Importing this module without it raises ``ImportError`` with an explanation,
instead of falling back to another format. Earlier versions fell back to a
JSON+base64 envelope in that situation; that format could not be read by any
CBOR reader (including a normal installation of this library and
quantum-safe-ts) and carried no marker that would let a reader tell the two
apart, so a broken installation could silently write keys, signatures and
envelopes that nothing else could open. Failing at import is safer.

Callers should never import cbor2 directly — always go through this module.
The public API mirrors cbor2's: dumps(obj) -> bytes, loads(data) -> obj.
"""

from __future__ import annotations

import io
from typing import Any

try:
    import cbor2 as _cbor2
except ImportError as exc:  # pragma: no cover - exercised by a subprocess test
    raise ImportError(
        "quantum-safe requires the 'cbor2' package (>=5.6) to read and write keys, "
        "signatures and envelopes, and it is not installed. Install it with "
        "'pip install cbor2'. There is no fallback format: one would write data that "
        "no other installation of quantum-safe, and no CBOR reader, could read."
    ) from exc

# Maximum bytes accepted by loads() — guards against memory-exhaustion
# attacks via deeply nested or padded CBOR payloads.
_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

#: Kept for callers that checked which serializer is active; always "cbor2".
BACKEND = "cbor2"


def dumps(obj: Any) -> bytes:  # noqa: ANN401
    """Serialize obj to CBOR."""
    return _cbor2.dumps(obj)


def _check_size(data: bytes) -> None:
    if len(data) > _MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"Payload size {len(data)} exceeds maximum allowed {_MAX_PAYLOAD_BYTES} bytes"
        )


def loads(data: bytes) -> Any:  # noqa: ANN401
    """Deserialize CBOR. Stops after the first item, ignoring trailing bytes."""
    _check_size(data)
    return _cbor2.loads(data)


def loads_single(data: bytes) -> Any:  # noqa: ANN401
    """Decode exactly one CBOR item; reject trailing bytes.

    cbor2.loads() stops after the first item and ignores anything after it,
    which lets two different byte strings decode to the same value. Use this
    for data whose bytes must have a single spelling.
    """
    _check_size(data)
    fp = io.BytesIO(data)
    obj = _cbor2.CBORDecoder(fp).decode()
    if fp.tell() != len(data):
        raise ValueError("trailing bytes after the CBOR item")
    return obj
