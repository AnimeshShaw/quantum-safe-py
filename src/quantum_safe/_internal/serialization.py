"""
quantum_safe._internal.serialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A thin serialization layer that prefers cbor2 when installed but falls back
to a JSON+base64 envelope when it isn't.

Why not just require cbor2?  Because some users (especially those deploying
to constrained environments like AWS Lambda layers or Heroku slugs) want to
keep the dependency tree minimal. cbor2 is listed as an optional dependency
in pyproject.toml; this module handles both cases transparently.

The fallback format is a JSON object where bytes fields are base64url-encoded
strings with a type tag prefix ("b64:").  It is slightly larger than CBOR
but fully self-describing and human-readable, which has its own value for
debugging.

Callers should never import cbor2 directly — always go through this module.
The public API mirrors cbor2's: dumps(obj) -> bytes, loads(data) -> obj.
"""

from __future__ import annotations

import base64
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

    BACKEND = "json-b64"
