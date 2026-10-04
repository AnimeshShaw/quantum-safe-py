"""
quantum_safe._internal.serialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A thin serialization layer over cbor2, with a JSON+base64 fallback that is
used only if cbor2 cannot be imported.

cbor2 is a **required** dependency (see ``dependencies`` in pyproject.toml),
so a correctly installed library always writes CBOR. The fallback is reached
only in a broken or hand-pruned environment, and it is **not
interoperable**: it writes a JSON envelope (``{"_qs_fmt": "json-b64-v1",
...}``) for keys, signed messages and sealed messages that no CBOR reader can
parse, including a normal installation of this library and quantum-safe-ts.
The format carries no marker inside individual key or envelope versions, so
data written while the fallback is active can only be read back by another
installation in the same state. Do not rely on it; if ``BACKEND`` is not
``"cbor2"``, fix the installation.

The fallback format is a JSON object where bytes fields are base64url-encoded
strings with a type tag prefix ("b64:").

Callers should never import cbor2 directly — always go through this module.
The public API mirrors cbor2's: dumps(obj) -> bytes, loads(data) -> obj.
"""

from __future__ import annotations

import base64
import io
import json
from typing import Any

# ---------------------------------------------------------------------------
# Try to use cbor2 first
# ---------------------------------------------------------------------------

# Maximum bytes accepted by loads() — guards against memory-exhaustion
# attacks via deeply nested or padded CBOR / JSON payloads.
_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

try:
    import cbor2 as _cbor2

    def dumps(obj: Any) -> bytes:  # noqa: ANN401
        return _cbor2.dumps(obj)

    def loads(data: bytes) -> Any:  # noqa: ANN401
        if len(data) > _MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload size {len(data)} exceeds maximum allowed {_MAX_PAYLOAD_BYTES} bytes"
            )
        return _cbor2.loads(data)

    def loads_single(data: bytes) -> Any:  # noqa: ANN401
        """Decode exactly one CBOR item; reject trailing bytes.

        cbor2.loads() stops after the first item and ignores anything after
        it, which lets two different byte strings decode to the same value.
        Use this for data whose bytes must have a single spelling.
        """
        if len(data) > _MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload size {len(data)} exceeds maximum allowed {_MAX_PAYLOAD_BYTES} bytes"
            )
        fp = io.BytesIO(data)
        obj = _cbor2.CBORDecoder(fp).decode()
        if fp.tell() != len(data):
            raise ValueError("trailing bytes after the CBOR item")
        return obj

    BACKEND = "cbor2"

except ImportError:
    # ---------------------------------------------------------------------------
    # Fallback: JSON + base64 envelope
    # ---------------------------------------------------------------------------

    _B64_PREFIX = "b64:"

    def _encode(obj: Any) -> Any:  # noqa: ANN401
        """Recursively encode an object for JSON serialization."""
        if isinstance(obj, (bytes, bytearray, memoryview)):
            raw = bytes(obj)
            return _B64_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii")
        if isinstance(obj, dict):
            return {str(k): _encode(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_encode(item) for item in obj]
        # int, float, str, bool, None pass through unchanged
        return obj

    def _decode(obj: Any) -> Any:  # noqa: ANN401
        """Recursively decode a JSON-deserialized object."""
        if isinstance(obj, str) and obj.startswith(_B64_PREFIX):
            b64 = obj[len(_B64_PREFIX) :]
            # Restore padding
            padded = b64 + "=" * (-len(b64) % 4)
            return base64.urlsafe_b64decode(padded)
        if isinstance(obj, dict):
            return {k: _decode(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_decode(item) for item in obj]
        return obj

    def dumps(obj: Any) -> bytes:  # noqa: ANN401
        """Serialize obj to bytes using JSON+base64 envelope."""
        encoded = _encode(obj)
        # We wrap in a thin envelope so loads() can detect this format
        wrapper = {"_qs_fmt": "json-b64-v1", "d": encoded}
        return json.dumps(wrapper, separators=(",", ":")).encode("utf-8")

    def loads(data: bytes) -> Any:  # noqa: ANN401
        """Deserialize bytes produced by dumps()."""
        if len(data) > _MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload size {len(data)} exceeds maximum allowed {_MAX_PAYLOAD_BYTES} bytes"
            )
        wrapper = json.loads(data.decode("utf-8"))
        if isinstance(wrapper, dict) and wrapper.get("_qs_fmt") == "json-b64-v1":
            return _decode(wrapper["d"])
        # Plain JSON (no envelope) — decode as-is, best effort
        return _decode(wrapper)

    def loads_single(data: bytes) -> Any:  # noqa: ANN401
        """Same as loads(); json.loads already rejects trailing data."""
        return loads(data)

    BACKEND = "json-b64"
