"""
quantum_safe.protocols.cose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

COSE_Sign1 with ML-DSA, and AKP COSE public keys: the COSE half of RFC 9964 (the JOSE half is
:class:`~quantum_safe.protocols.standard_jwt.StandardJwt`). A COSE_Sign1 is the CBOR counterpart of
a compact JWS: it is what CBOR Web Tokens, WebAuthn and many IoT and attestation formats carry.

What is signed
--------------
``Sig_structure = ["Signature1", protected, external_aad, payload]`` (RFC 9052 section 4.4), with
``protected`` the serialized protected header, signed with plain FIPS 204 ``ML-DSA.Sign`` and the
**empty** context (RFC 9964 section 5), i.e. exactly :meth:`Sign.sign_standard`. Any compliant
COSE library verifies the result, and this module verifies theirs.

Algorithm identifiers (RFC 9964 section 8.1.1): ML-DSA-44 = -48, ML-DSA-65 = -49, ML-DSA-87 =
-50.
Key type ``AKP`` = 7 with ``pub`` = -1 and ``priv`` = -2, the 32-byte seed. Public keys work with
any backend; private COSE keys (``encode_cose_private_key`` / ``keypair_from_cose_key``) hold a
seed, so they need the optional ``cryptography`` backend (liboqs secret keys are expanded keys
from which no seed can be recovered).

Verification is strict: the algorithm must be in the protected header and known, ``crit`` is
refused, the protected header must be a minimally encoded map without duplicate labels, and
trailing bytes are rejected.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import cbor2

from quantum_safe.exceptions import VerificationError
from quantum_safe.signatures.core import Sign
from quantum_safe.types import KeyPair, PublicKey, SecretKey

COSE_ALGORITHMS: dict[str, int] = {"ML-DSA-44": -48, "ML-DSA-65": -49, "ML-DSA-87": -50}
_BY_ID = {v: k for k, v in COSE_ALGORITHMS.items()}
KTY_AKP = 7
_TAG_SIGN1 = 18
_TAG_SIGN = 98
_MAX_BYTES = 16 * 1024 * 1024

_PUBLIC_KEY_BYTES = {"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592}


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """The bytes COSE_Sign1 signs: ``["Signature1", protected, external_aad, payload]`` as CBOR."""
    return bytes(cbor2.dumps(["Signature1", bytes(protected), bytes(external_aad), bytes(payload)]))


def _check_algorithm(algorithm: str) -> int:
    if algorithm not in COSE_ALGORITHMS:
        raise ValueError(
            f"COSE ML-DSA supports {', '.join(COSE_ALGORITHMS)} (plain ML-DSA, not '{algorithm}')"
        )
    return COSE_ALGORITHMS[algorithm]


def sign1(
    payload: bytes,
    secret_key: SecretKey,
    *,
    kid: bytes | None = None,
    external_aad: bytes = b"",
    tagged: bool = True,
    detached: bool = False,
) -> bytes:
    """Create a COSE_Sign1 over ``payload`` with an ML-DSA secret key.

    Args:
        payload:       The bytes to sign (carried in the message unless ``detached``).
        secret_key:    A plain ML-DSA-44/65/87 secret key.
        kid:           Optional key identifier, placed in the protected header.
        external_aad:  Application data that is signed but not carried (default empty).
        tagged:        Wrap in CBOR tag 18 (default). Untagged is accepted by most consumers.
        detached:      Leave the payload out of the message (it is still signed); the verifier
                       must supply it.
    """
    cose_alg = _check_algorithm(secret_key.algorithm)
    header: dict[int, Any] = {1: cose_alg}
    if kid is not None:
        header[4] = bytes(kid)
    protected = bytes(cbor2.dumps(header))
    signature = Sign(secret_key.algorithm).sign_standard(
        sig_structure(protected, payload, external_aad), secret_key, context=b""
    )
    body: list[Any] = [protected, {}, None if detached else bytes(payload), signature]
    return bytes(cbor2.dumps(cbor2.CBORTag(_TAG_SIGN1, body) if tagged else body))


def _parse_sign1(data: bytes) -> tuple[list[Any], bool]:
    data = bytes(data)
    if not data or len(data) > _MAX_BYTES:
        raise ValueError("not a COSE_Sign1: empty or too large")
    try:
        import io

        fp = io.BytesIO(data)
        obj = cbor2.CBORDecoder(fp).decode()
        if fp.tell() != len(data):
            raise ValueError("trailing bytes after the COSE_Sign1")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("not well-formed CBOR") from exc
    tagged = False
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag == _TAG_SIGN:
            raise ValueError("this is a COSE_Sign (multiple signatures), not a COSE_Sign1")
        if obj.tag != _TAG_SIGN1:
            raise ValueError(f"unexpected CBOR tag {obj.tag}")
        obj, tagged = obj.value, True
    # cbor2 returns the contents of a tag as an immutable tuple / frozendict.
    if not isinstance(obj, (list, tuple)) or len(obj) != 4:
        raise ValueError("a COSE_Sign1 is an array of four elements")
    protected, unprotected, payload, signature = obj
    if isinstance(unprotected, Mapping):
        unprotected = dict(unprotected)
    if not isinstance(protected, bytes) or not isinstance(unprotected, dict):
        raise ValueError("COSE_Sign1 protected header must be a byte string and unprotected a map")
    if payload is not None and not isinstance(payload, bytes):
        raise ValueError("COSE_Sign1 payload must be a byte string or nil")
    if not isinstance(signature, bytes):
        raise ValueError("COSE_Sign1 signature must be a byte string")
    parts: list[Any] = [protected, unprotected, payload, signature]
    # One reading per message: re-encoding what was decoded must give back exactly the input. That
    # rejects indefinite lengths, non-minimal integers and lengths, and duplicate map labels (which
    # decode to one entry and so re-encode shorter).
    if bytes(cbor2.dumps(cbor2.CBORTag(_TAG_SIGN1, parts) if tagged else parts)) != data:
        raise ValueError("the COSE_Sign1 is not in minimal definite-length CBOR with unique labels")
    return parts, tagged


def _protected_header(protected: bytes) -> dict[Any, Any]:
    if not protected:
        raise ValueError("the protected header is empty: the algorithm must be protected")
    try:
        header = cbor2.loads(protected)
    except Exception as exc:
        raise ValueError("the protected header is not well-formed CBOR") from exc
    if not isinstance(header, dict):
        raise ValueError("the protected header is not a map")
    # More than one spelling of the same header (duplicate labels, non-minimal or indefinite
    # encodings, trailing bytes) is refused: the re-encoding must equal the input exactly.
    if bytes(cbor2.dumps(header)) != protected:
        raise ValueError("the protected header has duplicate labels or a non-minimal encoding")
    return header


def _read(data: bytes) -> tuple[bytes, dict[Any, Any], dict[Any, Any], bytes | None, bytes, bool]:
    (protected, unprotected, payload, signature), tagged = _parse_sign1(data)
    header = _protected_header(protected)
    if set(header) & set(unprotected):
        raise ValueError("a header label appears in both the protected and unprotected headers")
    if 2 in header or 2 in unprotected:
        raise ValueError("a 'crit' header is present and no critical headers are understood")
    return protected, header, unprotected, payload, signature, tagged


def _algorithm_of(header: dict[Any, Any]) -> str:
    if 1 not in header:
        raise ValueError("the protected header carries no algorithm")
    name = _BY_ID.get(header[1])
    if name is None:
        raise ValueError(f"COSE algorithm {header[1]!r} is not an ML-DSA algorithm")
    return name


def inspect_sign1(data: bytes) -> dict[str, Any]:
    """Non-secret facts about a COSE_Sign1, without any key.

    Returns ``{"algorithm", "cose_alg", "kid", "tagged", "payload_length", "detached"}``.
    Raises ``ValueError`` for anything malformed.
    """
    _protected, header, unprotected, payload, _sig, tagged = _read(data)
    algorithm = _algorithm_of(header)
    kid = header.get(4, unprotected.get(4))
    return {
        "algorithm": algorithm,
        "cose_alg": COSE_ALGORITHMS[algorithm],
        "kid": kid,
        "tagged": tagged,
        "payload_length": None if payload is None else len(payload),
        "detached": payload is None,
    }


def verify_sign1(
    data: bytes,
    public_key: PublicKey,
    *,
    external_aad: bytes = b"",
    detached_payload: bytes | None = None,
) -> bytes:
    """Verify a COSE_Sign1 and return its payload.

    Raises:
        ValueError:         the message is malformed, uses an unknown algorithm, or its algorithm
                            differs from the key's.
        VerificationError:  the signature, payload, protected header or ``external_aad`` is wrong
                            (no detail on which, by design).
    """
    protected, header, _unprotected, payload, signature, _tagged = _read(data)
    algorithm = _algorithm_of(header)
    if public_key.algorithm != algorithm:
        raise ValueError(
            f"COSE algorithm {algorithm} does not match the key's algorithm {public_key.algorithm}"
        )
    if payload is None:
        if detached_payload is None:
            raise ValueError("the payload is detached: pass detached_payload")
        payload = bytes(detached_payload)
    elif detached_payload is not None and bytes(detached_payload) != payload:
        raise VerificationError(algo=algorithm)
    Sign(algorithm).verify_standard(
        sig_structure(protected, payload, external_aad), signature, public_key, context=b""
    )
    return payload


# ---------------------------------------------------------------------------
# COSE keys (AKP)
# ---------------------------------------------------------------------------


def encode_cose_key(public_key: PublicKey, kid: bytes | None = None) -> bytes:
    """Encode an ML-DSA public key as an AKP COSE_Key (RFC 9964 section 3)."""
    cose_alg = _check_algorithm(public_key.algorithm)
    key: dict[int, Any] = {1: KTY_AKP, 3: cose_alg, -1: public_key.raw_bytes}
    if kid is not None:
        key[2] = bytes(kid)
    return bytes(cbor2.dumps(key))


def encode_cose_private_key(keypair: KeyPair, kid: bytes | None = None) -> bytes:
    """Encode a seed key pair as a private AKP COSE_Key: ``pub`` and the 32-byte seed in ``priv``.

    The result is a secret. Needs a seed key (see ``Sign.generate_seed_keypair`` and
    ``Sign.keypair_from_seed``); an expanded liboqs key raises ``ValueError``.
    """
    cose_alg = _check_algorithm(keypair.secret.algorithm)
    seed = keypair.secret.raw_bytes
    if len(seed) != 32:
        raise ValueError(
            "this key is an expanded liboqs key; a private COSE_Key needs a 32-byte seed key"
        )
    key: dict[int, Any] = {1: KTY_AKP, 3: cose_alg, -1: keypair.public.raw_bytes, -2: bytes(seed)}
    if kid is not None:
        key[2] = bytes(kid)
    return bytes(cbor2.dumps(key))


def keypair_from_cose_key(data: bytes) -> KeyPair:
    """Rebuild the key pair of a private AKP COSE_Key (needs the ``cryptography`` backend).

    Raises ``ValueError`` if there is no seed, it is not 32 bytes, or ``pub`` does not match it.
    """
    data = bytes(data)
    key = _read_key_map(data)
    seed = key.get(-2)
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("a private COSE_Key carries a 32-byte seed in label -2")
    algorithm = _key_algorithm(key)
    keypair = Sign(algorithm, backend="pyca").keypair_from_seed(seed)
    pub = key.get(-1)
    if pub is not None and pub != keypair.public.raw_bytes:
        raise ValueError("the COSE_Key public key does not match its seed")
    return keypair


def _read_key_map(data: bytes) -> dict[Any, Any]:
    try:
        key = cbor2.loads(data)
    except Exception as exc:
        raise ValueError("not well-formed CBOR") from exc
    if not isinstance(key, dict):
        raise ValueError("a COSE_Key is a map")
    if bytes(cbor2.dumps(key)) != data:
        raise ValueError(
            "the COSE_Key has duplicate labels, trailing bytes or a non-minimal encoding"
        )
    if key.get(1) != KTY_AKP:
        raise ValueError("not an AKP key (kty must be 7)")
    return key


def _key_algorithm(key: dict[Any, Any]) -> str:
    if 3 not in key:
        raise ValueError("an AKP key must carry its algorithm (alg)")
    algorithm = _BY_ID.get(key[3])
    if algorithm is None:
        raise ValueError(f"COSE algorithm {key[3]!r} is not an ML-DSA algorithm")
    return algorithm


def decode_cose_key(data: bytes) -> tuple[PublicKey, bytes | None]:
    """Decode an AKP COSE_Key holding an ML-DSA **public** key. Returns ``(public_key, kid)``.

    Raises ``ValueError`` for another key type, a non-ML-DSA algorithm, a missing algorithm
    (REQUIRED for AKP), a wrong-length key, or a key that carries private material.
    """
    data = bytes(data)
    try:
        key = cbor2.loads(data)
    except Exception as exc:
        raise ValueError("not well-formed CBOR") from exc
    if not isinstance(key, dict):
        raise ValueError("a COSE_Key is a map")
    if bytes(cbor2.dumps(key)) != data:
        raise ValueError(
            "the COSE_Key has duplicate labels, trailing bytes or a non-minimal encoding"
        )
    if key.get(1) != KTY_AKP:
        raise ValueError("not an AKP key (kty must be 7)")
    if -2 in key:
        raise ValueError("this COSE_Key carries private key material; a public key is required")
    if 3 not in key:
        raise ValueError("an AKP key must carry its algorithm (alg)")
    algorithm = _BY_ID.get(key[3])
    if algorithm is None:
        raise ValueError(f"COSE algorithm {key[3]!r} is not an ML-DSA algorithm")
    pub = key.get(-1)
    if not isinstance(pub, bytes) or len(pub) != _PUBLIC_KEY_BYTES[algorithm]:
        raise ValueError(f"the public key must be {_PUBLIC_KEY_BYTES[algorithm]} bytes")
    kid = key.get(2)
    if kid is not None and not isinstance(kid, bytes):
        raise ValueError("kid must be a byte string")
    return PublicKey(pub, algorithm), kid
