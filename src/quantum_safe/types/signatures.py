"""
quantum_safe.types.signatures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Typed wrapper for signature operation outputs.

The key design decision here: Sign() returns a SignedMessage, not raw bytes.
The SignedMessage carries the algorithm name, signing context, and a timestamp
so the verifier doesn't need any out-of-band information to know what it's
verifying.

This solves a real operational problem: when you store a signature alongside
data (in a database, an audit log, an S3 bucket), you need to know which
algorithm produced it years later when you verify it. Raw bytes give you
nothing. A SignedMessage gives you everything.

For hybrid signatures (Ed25519 + ML-DSA), both sub-signatures are stored
and both must verify successfully.

References:
  - FIPS 204 §3 — ML-DSA signature format
  - FIPS 204 §5.2 — context string
  - draft-ietf-jose-pqc-signatures — JWT algorithm identifiers
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from quantum_safe._internal import serialization as _ser

from quantum_safe.exceptions import KeyParseError, VerificationError


# Maximum context length (FIPS 204 §5.2 allows up to 255 bytes)
_MAX_CONTEXT_LEN = 255

# CBOR-serializable version for SignedMessage storage
_SIGNED_MSG_VERSION = 1


@dataclass(frozen=True)
class SignedMessage:
    """A message with its signature(s) and metadata.

    Immutable (frozen dataclass) — once created, the message and signature
    cannot be changed. This prevents accidental mutation of audit records.

    Attributes:
        message:    The original message that was signed.
        signature:  The signature bytes. For hybrid, this contains both
                    sub-signatures in a length-prefixed format.
        algorithm:  The signing algorithm, e.g. 'ML-DSA-65' or
                    'Ed25519+ML-DSA-65'.
        context:    Domain-separation context (up to 255 bytes). Should
                    include your application name and version.
        signer_fingerprint: The fingerprint of the public key used to sign,
                    for quick lookup without re-verifying.
        signed_at:  Unix timestamp (float) of when the signature was created.
                    This is metadata only — it's not part of the signed content
                    and should not be relied upon for security decisions.
        is_hybrid:  Whether this is a hybrid (classical + PQC) signature.
    """

    message: bytes
    signature: bytes
    algorithm: str
    context: bytes = field(default=b"")
    signer_fingerprint: str = field(default="")
    signed_at: float = field(default_factory=time.time)
    is_hybrid: bool = field(default=False)

    def __post_init__(self) -> None:
        if len(self.context) > _MAX_CONTEXT_LEN:
            raise ValueError(
                f"context must be at most {_MAX_CONTEXT_LEN} bytes, "
                f"got {len(self.context)}"
            )
        if not self.message:
            raise ValueError("message cannot be empty")
        if not self.signature:
            raise ValueError("signature cannot be empty")

    def __repr__(self) -> str:
        sig_preview = self.signature[:8].hex()
        return (
            f"SignedMessage("
            f"algo={self.algorithm!r}, "
            f"msg_len={len(self.message)}, "
            f"sig={sig_preview}..., "
            f"context={self.context!r}"
            f")"
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_cbor(self) -> bytes:
        """Serialize to CBOR for storage or transmission."""
        return _ser.dumps({
            "v": _SIGNED_MSG_VERSION,
            "msg": self.message,
            "sig": self.signature,
            "algo": self.algorithm,
            "ctx": self.context,
            "fp": self.signer_fingerprint,
            "ts": self.signed_at,
            "hybrid": self.is_hybrid,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> "SignedMessage":
        """Deserialize from CBOR bytes."""
        try:
            d = _ser.loads(data)
        except Exception as exc:
            raise KeyParseError("cbor", f"SignedMessage decode failed: {exc}") from exc

        if d.get("v", 0) != _SIGNED_MSG_VERSION:
            raise KeyParseError(
                "cbor",
                f"unsupported SignedMessage version {d.get('v')}, "
                f"expected {_SIGNED_MSG_VERSION}",
            )

        return cls(
            message=bytes(d["msg"]),
            signature=bytes(d["sig"]),
            algorithm=d["algo"],
            context=bytes(d.get("ctx", b"")),
            signer_fingerprint=d.get("fp", ""),
            signed_at=float(d.get("ts", 0.0)),
            is_hybrid=bool(d.get("hybrid", False)),
        )

    def to_jwt_payload(self) -> dict[str, Any]:
        """Produce a JWT payload dict for this signed message.

        The JWS (JSON Web Signature) representation follows
        draft-ietf-jose-pqc-signatures for algorithm identifiers.

        Note: this produces the *payload* dict. To get a full JWT string,
        use quantum_safe.protocols.jwt.sign() instead.
        """
        return {
            "msg": base64.urlsafe_b64encode(self.message).rstrip(b"=").decode(),
            "sig": base64.urlsafe_b64encode(self.signature).rstrip(b"=").decode(),
            "alg": self.algorithm,
            "ctx": base64.urlsafe_b64encode(self.context).rstrip(b"=").decode(),
            "fp": self.signer_fingerprint,
            "iat": int(self.signed_at),
        }


@dataclass(frozen=True)
class HybridSignature:
    """Internal representation of a hybrid signature.

    Stores the classical and PQC sub-signatures separately before they're
    combined into a SignedMessage. This is an intermediate type used inside
    HybridSign; callers don't normally deal with it directly.

    Wire format (CBOR-encoded)::

        {
            "classical_sig": bytes,
            "pqc_sig": bytes,
            "classical_algo": str,
            "pqc_algo": str,
        }
    """

    classical_sig: bytes
    pqc_sig: bytes
    classical_algo: str
    pqc_algo: str

    @property
    def combined_algorithm(self) -> str:
        return f"{self.classical_algo}+{self.pqc_algo}"

    def to_bytes(self) -> bytes:
        """Encode as CBOR for embedding in a SignedMessage.signature field."""
        return _ser.dumps({
            "classical_sig": self.classical_sig,
            "pqc_sig": self.pqc_sig,
            "classical_algo": self.classical_algo,
            "pqc_algo": self.pqc_algo,
        })

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridSignature":
        """Decode from CBOR bytes."""
        try:
            d = _ser.loads(data)
        except Exception as exc:
            raise VerificationError() from exc
        
        if not isinstance(d, dict):
            raise VerificationError()

        try:
            return cls(
                classical_sig=bytes(d["classical_sig"]),
                pqc_sig=bytes(d["pqc_sig"]),
                classical_algo=d["classical_algo"],
                pqc_algo=d["pqc_algo"],
            )
        except KeyError as exc:
            raise VerificationError() from exc
