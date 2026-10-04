"""
quantum_safe.signatures._v2
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Signature format v2 (``<suite>-v2``), byte-compatible with quantum-safe-ts
(``crates/quantum-safe-core/src/sig/v2.rs``).

It fixes the structural problems of the original construction, which stays
unchanged under its own identifiers:

* No random prefix and no prefix length in the blob, so there is no
  message/prefix boundary for anyone to move.
* The ML-DSA half is plain FIPS 204 ``ML-DSA.Sign`` with a non-empty *native*
  context (:data:`LABEL`) over ``M2``, so any FIPS 204 library can verify it
  given ``M2`` and :data:`LABEL`.
* The algorithm identifier and the caller's context are inside the signed bytes
  (``M2``), and both halves of a hybrid sign the same ``M2``.
* One fixed-length blob encoding: no CBOR wrapper around the halves, raw
  low-S ECDSA for P-256.
* Keys carry the ``-v2`` tag. The tag is advisory: v1 and v2 keys have
  identical bytes. **Never use the same key material in both formats**: the
  ML-DSA halves are domain-separated by FIPS 204's context (empty in v1,
  :data:`LABEL` here), but the classical halves are not.

``M2 = u8(len(algo)) || algo || u8(len(ctx)) || ctx || message`` where ``algo``
is the full v2 identifier (for example ``ML-DSA-65-v2``). ML-DSA signs ``M2``
with FIPS 204 context :data:`LABEL`; the classical half signs
``LABEL || 0x00 || M2`` (Ed25519, or ECDSA P-256 with SHA-256, raw ``r || s``,
low-S only). A hybrid signature is ``classical signature || ML-DSA signature``.
ML-DSA signing is always hedged (fresh randomness inside ML-DSA, per FIPS 204),
so there is no ``hedged=False`` mode.

This module holds the format. :class:`~quantum_safe.signatures.core.Sign` and
:class:`~quantum_safe.signatures.hybrid.HybridSign` accept v2 identifiers.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from quantum_safe.exceptions import UnsupportedAlgorithm, VerificationError

if TYPE_CHECKING:
    from quantum_safe.backends.base import AbstractSignatureBackend

SUFFIX = "-v2"
LABEL = b"quantum-safe-sig-v2"
CLASSICAL_SIG_LEN = 64

# Same group order as P-256 (NIST FIPS 186-4, curve P-256).
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

#: Hybrid combinations that have a v2 identifier (same as quantum-safe-ts).
V2_HYBRIDS: dict[str, tuple[str, ...]] = {
    "Ed25519": ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"),
    "P-256": ("ML-DSA-44", "ML-DSA-65"),
}
V2_ML_DSA = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


def is_v2(algorithm: str) -> bool:
    """Whether the name carries the ``-v2`` suffix (it may still be unsupported)."""
    return algorithm.endswith(SUFFIX)


def base_of(algorithm: str) -> str | None:
    """The base suite name if ``algorithm`` is a supported v2 identifier, else None."""
    if not algorithm.endswith(SUFFIX):
        return None
    base = algorithm[: -len(SUFFIX)]
    if base in V2_ML_DSA:
        return base
    if "+" in base:
        classical, pqc = base.split("+", 1)
        if pqc in V2_HYBRIDS.get(classical, ()):
            return base
    return None


def require_base(algorithm: str) -> str:
    base = base_of(algorithm)
    if base is None:
        raise UnsupportedAlgorithm(algorithm, available=all_identifiers())
    return base


def all_identifiers() -> list[str]:
    out = [f"{p}{SUFFIX}" for p in V2_ML_DSA]
    out += [f"{c}+{p}{SUFFIX}" for c, ps in V2_HYBRIDS.items() for p in ps]
    return out


def signed_input(algorithm: str, context: bytes, message: bytes) -> bytes:
    """``M2``: the bytes both halves sign (the classical half adds a label in front)."""
    a = algorithm.encode("ascii")
    if len(a) > 255 or len(context) > 255:
        raise ValueError("algorithm and context must each be at most 255 bytes")
    return bytes([len(a)]) + a + bytes([len(context)]) + context + message


def _classical_input(m2: bytes) -> bytes:
    return LABEL + b"\x00" + m2


def pack_components(a: bytes, b: bytes) -> bytes:
    return struct.pack(">H", len(a)) + a + b


def unpack_components(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < 2:
        raise ValueError("hybrid key too short")
    (n,) = struct.unpack(">H", data[:2])
    if len(data) < 2 + n:
        raise ValueError("hybrid key truncated")
    return data[2 : 2 + n], data[2 + n :]


# ---------------------------------------------------------------------------
# Classical halves
# ---------------------------------------------------------------------------


def _classical_sign(classical: str, secret: bytes, data: bytes) -> bytes:
    if classical == "Ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(secret).sign(data)
    if classical == "P-256":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(secret, password=None)
        if not isinstance(key, EllipticCurvePrivateKey):
            raise ValueError("P-256 secret key is not an EC key")
        r, s = decode_dss_signature(key.sign(data, ECDSA(hashes.SHA256())))
        if s > _P256_ORDER // 2:  # low-S only: the high-S twin is a second encoding
            s = _P256_ORDER - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise UnsupportedAlgorithm(classical, available=list(V2_HYBRIDS))


def _classical_verify(classical: str, public: bytes, data: bytes, sig: bytes) -> bool:
    try:
        if classical == "Ed25519":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(public).verify(sig, data)
            return True
        if classical == "P-256":
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.ec import (
                ECDSA,
                SECP256R1,
                EllipticCurvePublicNumbers,
            )
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

            if len(public) != 64 or len(sig) != 64:
                return False
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            if s > _P256_ORDER // 2:
                return False  # the high-S twin is refused
            pub = EllipticCurvePublicNumbers(
                int.from_bytes(public[:32], "big"),
                int.from_bytes(public[32:], "big"),
                SECP256R1(),
            ).public_key()
            pub.verify(encode_dss_signature(r, s), data, ECDSA(hashes.SHA256()))
            return True
    except Exception:  # noqa: BLE001
        return False
    return False


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------


def sign(
    algorithm: str,
    secret: bytes,
    message: bytes,
    context: bytes,
    backend: AbstractSignatureBackend,
) -> bytes:
    """Return the v2 signature blob for ``message`` under ``algorithm``."""
    base = require_base(algorithm)
    m2 = signed_input(algorithm, context, message)
    if "+" not in base:
        return backend.sign_native_context(base, secret, m2, LABEL)
    classical, pqc = base.split("+", 1)
    c_sec, p_sec = unpack_components(secret)
    c_sig = _classical_sign(classical, c_sec, _classical_input(m2))
    return c_sig + backend.sign_native_context(pqc, p_sec, m2, LABEL)


def verify(
    algorithm: str,
    public: bytes,
    message: bytes,
    blob: bytes,
    context: bytes,
    backend: AbstractSignatureBackend,
) -> None:
    """Verify a v2 blob; raises :class:`VerificationError` if it is not valid."""
    base = require_base(algorithm)
    if len(context) > 255 or not message:
        raise VerificationError(algo=algorithm)
    m2 = signed_input(algorithm, context, message)
    if "+" not in base:
        if not backend.verify_native_context(base, public, m2, blob, LABEL):
            raise VerificationError(algo=algorithm)
        return
    classical, pqc = base.split("+", 1)
    try:
        c_pub, p_pub = unpack_components(public)
    except ValueError as exc:
        raise VerificationError(algo=algorithm) from exc
    if len(blob) <= CLASSICAL_SIG_LEN:
        raise VerificationError(algo=algorithm)
    c_sig, p_sig = blob[:CLASSICAL_SIG_LEN], blob[CLASSICAL_SIG_LEN:]
    # Evaluate both halves before combining, so a failure does not reveal which.
    classical_ok = _classical_verify(classical, c_pub, _classical_input(m2), c_sig)
    pqc_ok = backend.verify_native_context(pqc, p_pub, m2, p_sig, LABEL)
    if not (classical_ok and pqc_ok):
        raise VerificationError(algo=algorithm)
