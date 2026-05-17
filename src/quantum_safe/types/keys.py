"""
quantum_safe.types.keys
~~~~~~~~~~~~~~~~~~~~~~~

Typed wrappers for cryptographic key material.

The central design goal here is: a raw bytes object should never be used
directly as a key. Every key type in this module:

  1. Zeroizes its memory on deletion (best-effort — Python's GC makes
     guarantees hard, but we do what we can).
  2. Carries its algorithm name so operations can validate compatibility.
  3. Has a stable fingerprint for key pinning and audit logs.
  4. Knows how to serialize/deserialize itself across formats.

We use __slots__ throughout to keep memory layout tight and avoid
accidental attribute bloat on what are essentially byte containers.

References:
  - FIPS 203 (ML-KEM) §3.3 — key encoding
  - FIPS 204 (ML-DSA) §6 — key generation
  - draft-ietf-jose-pqc-kem — JWK representations
  - RFC 7517 — JSON Web Key
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import os
import warnings
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, ClassVar

from quantum_safe._internal import serialization as _ser
from quantum_safe.exceptions import (
    IncompatibleKeyVersion,
    KeyParseError,
    UnsupportedFormatError,
)

if TYPE_CHECKING:
    pass


# Current envelope format version. Bump when the serialization format changes
# in a backward-incompatible way. Old versions remain readable; new versions
# are written.
_CURRENT_KEY_VERSION = 1
_MAX_SUPPORTED_KEY_VERSION = 1

# PEM type strings we emit. We deliberately use "HYBRID" to distinguish our
# combined keys from single-algorithm keys.
_PEM_PUBLIC_LABEL = "QUANTUM SAFE PUBLIC KEY"
_PEM_SECRET_LABEL = "QUANTUM SAFE SECRET KEY"  # never log this label + content  # noqa: S105

# Expected key sizes for known single algorithms (from FIPS 203/204/205).
# Hybrid keys are length-prefixed composites and are NOT listed here.
# Used to reject keys whose byte length doesn't match the claimed algorithm,
# preventing type-confusion attacks where ML-DSA bytes claim to be ML-KEM.
_KNOWN_PUBLIC_KEY_SIZES: dict[str, int] = {
    "ML-KEM-512": 800,
    "ML-KEM-768": 1184,
    "ML-KEM-1024": 1568,
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
    "SLH-DSA-SHAKE-128s": 32,
    "SLH-DSA-SHAKE-128f": 32,
}
_KNOWN_SECRET_KEY_SIZES: dict[str, int] = {
    "ML-KEM-512": 1632,
    "ML-KEM-768": 2400,
    "ML-KEM-1024": 3168,
    "ML-DSA-44": 2528,
    "ML-DSA-65": 4000,
    "ML-DSA-87": 4864,
    "SLH-DSA-SHAKE-128s": 64,
    "SLH-DSA-SHAKE-128f": 64,
}


class KeyType(Enum):
    PUBLIC = auto()
    SECRET = auto()


class MigrationState(Enum):
    """The PQC migration state of a key.

    States progress in one direction (you can't go from PQC_PREFERRED back
    to CLASSICAL_ONLY through normal operations — that requires an explicit
    downgrade call that logs a warning).
    """

    CLASSICAL_ONLY = "classical_only"
    HYBRID_TRANSITION = "hybrid_transition"  # has both classical + PQC components
    PQC_PREFERRED = "pqc_preferred"  # hybrid, but PQC is the trusted component
    PQC_ONLY = "pqc_only"  # no classical component at all


class _ZeroizingBytes:
    """A bytes-like container that attempts to zero its memory on deletion.

    CPython doesn't give us reliable control over when memory is freed, but
    we can at least zero the bytearray we hold and remove our reference.
    This reduces the window during which secret material is visible in a
    heap dump.

    Note: This is NOT a substitute for hardware security modules or OS-level
    secure memory (mlock). For high-security deployments, consider using
    a proper HSM integration — see docs/hsm.md.
    """

    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        # We store as bytearray so we can zero it
        self._data = bytearray(data)

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _ZeroizingBytes):
            # Constant-time comparison — don't short-circuit on mismatch
            return hmac.compare_digest(bytes(self._data), bytes(other._data))
        if isinstance(other, (bytes, bytearray)):
            return hmac.compare_digest(bytes(self._data), bytes(other))
        return NotImplemented

    def __del__(self) -> None:
        # Zero the bytearray using ctypes.memset so the compiler cannot
        # eliminate it as a dead store (unlike a Python-level loop).
        try:
            n = len(self._data)
            if n:
                ctypes.memset((ctypes.c_char * n).from_buffer(self._data), 0, n)
        except Exception:  # noqa: BLE001, S110
            pass  # Don't raise in __del__

    def __repr__(self) -> str:
        return f"_ZeroizingBytes(<{len(self._data)} bytes redacted>)"


class BaseKey(ABC):
    """Abstract base for all key types in this library.

    Subclasses must implement `raw_bytes` and `key_type`. Everything else
    (fingerprinting, PEM export, CBOR, JWK) is implemented here using those
    primitives.
    """

    # Subclasses declare which serialization formats they support.
    # "pem" and "cbor" are supported by all keys; "jwk" requires the key
    # to implement _to_jwk_payload().
    _supported_formats: ClassVar[set[str]] = {"pem", "cbor"}

    @property
    @abstractmethod
    def raw_bytes(self) -> bytes:
        """The raw key bytes as returned by the cryptographic backend."""
        ...

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Algorithm identifier, e.g. 'ML-KEM-768' or 'X25519+ML-KEM-768'."""
        ...

    @property
    @abstractmethod
    def key_type(self) -> KeyType:
        """Whether this is a public or secret key."""
        ...

    @property
    @abstractmethod
    def migration_state(self) -> MigrationState:
        """The PQC migration state of this key."""
        ...

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    def fingerprint(self, hash_algo: str = "sha256") -> str:
        """Return a stable hex fingerprint of this key.

        The fingerprint is computed over (algorithm_name || key_bytes) so
        that two keys with different algorithms but identical bytes get
        different fingerprints. This matters for hybrid keys where the
        classical and PQC sub-key bytes could theoretically collide.

        The result is lowercase hex with no colons. If you want the
        colon-separated SSH-style format, call fingerprint_colon().

        Args:
            hash_algo: Any algorithm accepted by hashlib. Defaults to sha256.
                       For BLAKE3 (faster, still secure), install the blake3
                       package — we'll detect and use it if available.
        """
        if hash_algo == "blake3":
            try:
                import blake3  # type: ignore[import]

                h = blake3.blake3(self.algorithm.encode() + b"\x00" + self.raw_bytes)
                return h.hexdigest()
            except ImportError:
                warnings.warn(
                    "blake3 package not installed, falling back to sha256 for fingerprint",
                    stacklevel=2,
                )
                hash_algo = "sha256"

        h = hashlib.new(hash_algo)
        h.update(self.algorithm.encode("ascii"))
        h.update(b"\x00")  # separator — prevents length extension issues
        h.update(self.raw_bytes)
        return h.hexdigest()

    def fingerprint_colon(self, hash_algo: str = "sha256") -> str:
        """Return fingerprint as colon-separated pairs: aa:bb:cc:..."""
        raw = self.fingerprint(hash_algo)
        return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_pem(self) -> str:
        """Serialize this key to PEM format.

        The PEM header includes qs-version and qs-algo so the deserializer
        doesn't need out-of-band information. Example output:

            -----BEGIN QUANTUM SAFE PUBLIC KEY-----
            qs-version: 1
            qs-algo: X25519+ML-KEM-768
            qs-migration: hybrid_transition

            <base64-encoded CBOR payload>
            -----END QUANTUM SAFE PUBLIC KEY-----

        The blank line between headers and body follows RFC 7468 §2.
        """
        if "pem" not in self._supported_formats:
            raise UnsupportedFormatError("pem", self.algorithm)

        label = _PEM_PUBLIC_LABEL if self.key_type == KeyType.PUBLIC else _PEM_SECRET_LABEL
        cbor_payload = self._to_cbor_payload()
        b64 = base64.b64encode(cbor_payload).decode("ascii")
        # Wrap at 64 chars per line (RFC 7468)
        wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))

        headers = (
            f"qs-version: {_CURRENT_KEY_VERSION}\n"
            f"qs-algo: {self.algorithm}\n"
            f"qs-migration: {self.migration_state.value}"
        )

        return f"-----BEGIN {label}-----\n{headers}\n\n{wrapped}\n-----END {label}-----\n"

    def to_cbor(self) -> bytes:
        """Serialize this key to CBOR bytes.

        CBOR is the preferred binary format. It's more compact than PEM,
        type-safe, and easier to parse than DER. The structure is:

            {
                "v": 1,              # format version
                "algo": "...",       # algorithm string
                "ms": "...",         # migration state
                "ktype": "pub"|"sec",
                "key": <bstr>,       # raw key bytes
            }
        """
        if "cbor" not in self._supported_formats:
            raise UnsupportedFormatError("cbor", self.algorithm)
        return _ser.dumps(self._to_cbor_payload_dict())

    def to_jwk(self) -> dict[str, Any]:
        """Serialize this key as a JSON Web Key (JWK).

        Follows draft-ietf-jose-pqc-kem for ML-KEM keys and
        draft-ietf-jose-pqc-signatures for ML-DSA keys.

        Only public keys can be serialized to JWK by default. Serializing
        a secret key requires passing allow_secret=True and is strongly
        discouraged — use CBOR for secret key storage instead.
        """
        if "jwk" not in self._supported_formats:
            raise UnsupportedFormatError("jwk", self.algorithm)
        return self._to_jwk_payload()

    def _to_cbor_payload(self) -> bytes:
        return _ser.dumps(self._to_cbor_payload_dict())

    def _to_cbor_payload_dict(self) -> dict[str, Any]:
        return {
            "v": _CURRENT_KEY_VERSION,
            "algo": self.algorithm,
            "ms": self.migration_state.value,
            "ktype": "pub" if self.key_type == KeyType.PUBLIC else "sec",
            "key": self.raw_bytes,
        }

    def _to_jwk_payload(self) -> dict[str, Any]:
        # Default: not implemented. Subclasses override for JWK support.
        raise UnsupportedFormatError("jwk", self.algorithm)

    # ------------------------------------------------------------------
    # Deserialization (class methods)
    # ------------------------------------------------------------------

    @classmethod
    def _parse_cbor_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Validate and return a parsed CBOR dict. Raises KeyParseError on bad input."""
        version = data.get("v")
        if not isinstance(version, int):
            raise KeyParseError("cbor", "missing or non-integer 'v' field")
        # Reject both too-new (unsupported features) and too-old (below floor,
        # which would indicate a downgrade attack against future format changes).
        if version < 1:
            raise KeyParseError("cbor", f"invalid key version {version}: minimum is 1")
        if version > _MAX_SUPPORTED_KEY_VERSION:
            raise IncompatibleKeyVersion(version, _MAX_SUPPORTED_KEY_VERSION)
        if "algo" not in data:
            raise KeyParseError("cbor", "missing 'algo' field")
        if "key" not in data:
            raise KeyParseError("cbor", "missing 'key' field")
        return data

    @classmethod
    def _parse_pem_body(cls, pem: str) -> tuple[dict[str, str], bytes]:
        """Parse PEM, returning (headers_dict, raw_cbor_bytes).

        Handles both public and secret key labels.
        """
        lines = pem.strip().splitlines()
        if not lines[0].startswith("-----BEGIN") or not lines[-1].startswith("-----END"):
            raise KeyParseError("pem", "missing BEGIN/END markers")

        # Split headers from body (blank line separator)
        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False

        for line in lines[1:-1]:
            if in_body:
                body_lines.append(line)
            elif line == "":
                in_body = True
            else:
                # Parse header line: "key: value"
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()

        if not body_lines:
            raise KeyParseError("pem", "empty key body")

        try:
            raw = base64.b64decode("".join(body_lines))
        except Exception as exc:
            raise KeyParseError("pem", f"base64 decode failed: {exc}") from exc

        return headers, raw


class PublicKey(BaseKey):
    """A public key for a KEM or signature scheme.

    Public keys are safe to share, log, and store without special handling.
    They support all serialization formats including JWK.
    """

    __slots__ = ("_raw", "_algorithm", "_migration_state", "_backend_tag", "_cached_fp")

    _supported_formats: ClassVar[set[str]] = {"pem", "cbor", "jwk"}

    def __init__(
        self,
        raw: bytes,
        algorithm: str,
        migration_state: MigrationState = MigrationState.HYBRID_TRANSITION,
        backend_tag: str = "unknown",
    ) -> None:
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f"raw must be bytes, got {type(raw).__name__}")
        if not raw:
            raise ValueError("raw key bytes cannot be empty")
        # Reject keys whose size doesn't match the claimed algorithm.
        # Hybrid keys (containing "+") use a length-prefixed composite format
        # and are not validated by this table.
        if "+" not in algorithm:
            expected = _KNOWN_PUBLIC_KEY_SIZES.get(algorithm)
            if expected is not None and len(raw) != expected:
                raise ValueError(
                    f"Public key size {len(raw)} does not match expected "
                    f"{expected} bytes for algorithm '{algorithm}'"
                )
        self._raw = bytes(raw)
        self._algorithm = algorithm
        self._migration_state = migration_state
        self._backend_tag = backend_tag
        self._cached_fp: str | None = None

    @property
    def raw_bytes(self) -> bytes:
        return self._raw

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def key_type(self) -> KeyType:
        return KeyType.PUBLIC

    @property
    def migration_state(self) -> MigrationState:
        return self._migration_state

    @property
    def backend_tag(self) -> str:
        return self._backend_tag

    def __repr__(self) -> str:
        if self._cached_fp is None:
            self._cached_fp = self.fingerprint()
        return (
            f"PublicKey(algo={self._algorithm!r}, "
            f"size={len(self._raw)}B, "
            f"fp={self._cached_fp[:12]}...)"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self._algorithm == other._algorithm and hmac.compare_digest(self._raw, other._raw)

    def __hash__(self) -> int:
        # Safe to hash public keys — they're not secret
        return hash((self._algorithm, self._raw))

    def _to_jwk_payload(self) -> dict[str, Any]:
        # Follows draft-ietf-jose-pqc-kem §3 for KEM keys.
        # The "kty" value "AKP" (Asymmetric Key Pair) is proposed in the draft.
        # For hybrid keys we encode both components.
        return {
            "kty": "AKP",
            "alg": self._algorithm,
            "pub": base64.urlsafe_b64encode(self._raw).rstrip(b"=").decode(),
            "qs-version": _CURRENT_KEY_VERSION,
            "qs-migration": self._migration_state.value,
            "key_ops": ["encapsulate", "verify"],
        }

    @classmethod
    def from_pem(cls, pem: str) -> PublicKey:
        """Parse a public key from PEM format."""
        headers, raw_cbor = cls._parse_pem_body(pem)

        # Sanity-check the label told us it's a public key
        if _PEM_SECRET_LABEL in pem.splitlines()[0]:
            raise KeyParseError(
                "pem",
                "attempted to load a SECRET KEY as a PublicKey — use SecretKey.from_pem() instead",
            )

        try:
            cbor_dict = _ser.loads(raw_cbor)
        except Exception as exc:
            raise KeyParseError("pem", f"CBOR decode failed: {exc}") from exc

        parsed = cls._parse_cbor_dict(cbor_dict)

        try:
            ms = MigrationState(parsed.get("ms", "hybrid_transition"))
        except ValueError:
            ms = MigrationState.HYBRID_TRANSITION

        return cls(
            raw=bytes(parsed["key"]),
            algorithm=parsed["algo"],
            migration_state=ms,
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> PublicKey:
        """Parse a public key from CBOR bytes."""
        try:
            cbor_dict = _ser.loads(data)
        except Exception as exc:
            raise KeyParseError("cbor", f"CBOR decode failed: {exc}") from exc

        parsed = cls._parse_cbor_dict(cbor_dict)
        if parsed.get("ktype") == "sec":
            raise KeyParseError("cbor", "data contains a secret key, not a public key")

        try:
            ms = MigrationState(parsed.get("ms", "hybrid_transition"))
        except ValueError:
            ms = MigrationState.HYBRID_TRANSITION

        return cls(
            raw=bytes(parsed["key"]),
            algorithm=parsed["algo"],
            migration_state=ms,
        )

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any]) -> PublicKey:
        """Parse a public key from a JWK dict."""
        if "pub" not in jwk:
            raise KeyParseError("jwk", "missing 'pub' field")
        if "alg" not in jwk:
            raise KeyParseError("jwk", "missing 'alg' field")

        try:
            # Add padding back before decoding
            b64 = jwk["pub"]
            padded = b64 + "=" * (-len(b64) % 4)
            raw = base64.urlsafe_b64decode(padded)
        except Exception as exc:
            raise KeyParseError("jwk", f"base64url decode failed: {exc}") from exc

        try:
            ms = MigrationState(jwk.get("qs-migration", "hybrid_transition"))
        except ValueError:
            ms = MigrationState.HYBRID_TRANSITION

        return cls(raw=raw, algorithm=jwk["alg"], migration_state=ms)


class SecretKey(BaseKey):
    """A secret key for a KEM or signature scheme.

    Secret keys zeroize their memory on deletion. They should:
    - Never appear in log messages
    - Never be serialized to JWK (which is designed for public sharing)
    - Be stored encrypted at rest (see quantum_safe.protocols.envelope)
    """

    __slots__ = ("_raw", "_algorithm", "_migration_state", "_backend_tag")

    # JWK is intentionally excluded — secret keys should not be JWK-serialized
    _supported_formats: ClassVar[set[str]] = {"pem", "cbor"}

    def __init__(
        self,
        raw: bytes,
        algorithm: str,
        migration_state: MigrationState = MigrationState.HYBRID_TRANSITION,
        backend_tag: str = "unknown",
    ) -> None:
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f"raw must be bytes, got {type(raw).__name__}")
        if not raw:
            raise ValueError("raw key bytes cannot be empty")
        # Note: we intentionally do NOT validate secret key sizes here.
        # Different backends (liboqs, RustCrypto, HSMs) encode secret keys in
        # different ways — e.g. liboqs ML-DSA stores an expanded form with t1
        # appended for faster signing, which differs from the FIPS 204 wire size.
        # Public key sizes are validated in PublicKey.__init__ instead, since
        # public keys must be interoperable across implementations.
        # Use _ZeroizingBytes for secret material
        self._raw = _ZeroizingBytes(raw)
        self._algorithm = algorithm
        self._migration_state = migration_state
        self._backend_tag = backend_tag

    @property
    def raw_bytes(self) -> bytes:
        # Returns an immutable copy. For security-sensitive callers that need
        # to zero the copy after use, call _raw_bytearray() instead and zero
        # with ctypes.memset() in a try/finally block.
        return bytes(self._raw)

    @property
    def _raw_bytearray(self) -> bytearray:
        """Internal: a fresh mutable copy of the key bytes.

        Callers MUST zero this after use:
            buf = sk._raw_bytearray
            try:
                backend.op(buf)
            finally:
                ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
        """
        return bytearray(self._raw._data)

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def key_type(self) -> KeyType:
        return KeyType.SECRET

    @property
    def migration_state(self) -> MigrationState:
        return self._migration_state

    @property
    def backend_tag(self) -> str:
        return self._backend_tag

    def __repr__(self) -> str:
        # Never include key bytes or fingerprint (which leaks info) in repr
        return f"SecretKey(algo={self._algorithm!r}, size={len(self._raw)}B, <REDACTED>)"

    def __str__(self) -> str:
        return f"SecretKey(algo={self._algorithm!r}, <REDACTED>)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretKey):
            return NotImplemented
        # Constant-time comparison
        return self._algorithm == other._algorithm and self._raw == other._raw

    def __hash__(self) -> int:
        # Secret keys should not be hashed (e.g. put in sets) — the hash
        # could leak timing information. We raise instead of silently allowing.
        raise TypeError(
            "SecretKey objects are not hashable. If you need to identify a key, "
            "use its corresponding PublicKey's fingerprint instead."
        )

    @classmethod
    def from_pem(cls, pem: str) -> SecretKey:
        """Parse a secret key from PEM format.

        Warning: the PEM string itself contains secret material — ensure
        it's handled appropriately (not logged, not stored in plaintext).
        """
        if _PEM_PUBLIC_LABEL in pem.splitlines()[0]:
            raise KeyParseError(
                "pem",
                "attempted to load a PUBLIC KEY as a SecretKey — use PublicKey.from_pem() instead",
            )

        _headers, raw_cbor = cls._parse_pem_body(pem)

        try:
            cbor_dict = _ser.loads(raw_cbor)
        except Exception as exc:
            raise KeyParseError("pem", f"CBOR decode failed: {exc}") from exc

        parsed = cls._parse_cbor_dict(cbor_dict)
        if parsed.get("ktype") == "pub":
            raise KeyParseError("pem", "data contains a public key, not a secret key")

        try:
            ms = MigrationState(parsed.get("ms", "hybrid_transition"))
        except ValueError:
            ms = MigrationState.HYBRID_TRANSITION

        return cls(
            raw=bytes(parsed["key"]),
            algorithm=parsed["algo"],
            migration_state=ms,
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> SecretKey:
        """Parse a secret key from CBOR bytes."""
        try:
            cbor_dict = _ser.loads(data)
        except Exception as exc:
            raise KeyParseError("cbor", f"CBOR decode failed: {exc}") from exc

        parsed = cls._parse_cbor_dict(cbor_dict)
        if parsed.get("ktype") == "pub":
            raise KeyParseError("cbor", "data contains a public key, not a secret key")

        try:
            ms = MigrationState(parsed.get("ms", "hybrid_transition"))
        except ValueError:
            ms = MigrationState.HYBRID_TRANSITION

        return cls(
            raw=bytes(parsed["key"]),
            algorithm=parsed["algo"],
            migration_state=ms,
        )


class KeyPair:
    """A matched public/secret key pair.

    This is what keygen functions return. It deliberately does NOT inherit
    from BaseKey — it's a container, not a key.
    """

    __slots__ = ("public", "secret", "_algorithm")

    def __init__(self, public: PublicKey, secret: SecretKey) -> None:
        if public.algorithm != secret.algorithm:
            raise ValueError(
                f"Public key algorithm '{public.algorithm}' does not match "
                f"secret key algorithm '{secret.algorithm}'"
            )
        self.public = public
        self.secret = secret
        self._algorithm = public.algorithm

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def __repr__(self) -> str:
        return f"KeyPair(algo={self._algorithm!r}, pub_fp={self.public.fingerprint()[:12]}...)"

    # Convenience: serialize both keys together as a CBOR map
    def to_cbor_bundle(self) -> bytes:
        """Serialize both keys as a CBOR bundle.

        The bundle contains both public and secret key material. Treat it
        with the same care as the secret key.
        """
        return _ser.dumps(
            {
                "v": _CURRENT_KEY_VERSION,
                "bundle": "keypair",
                "pub": _ser.loads(self.public.to_cbor()),
                "sec": _ser.loads(self.secret.to_cbor()),
            }
        )

    @classmethod
    def from_cbor_bundle(cls, data: bytes) -> KeyPair:
        """Deserialize a key pair from a CBOR bundle."""
        try:
            bundle = _ser.loads(data)
        except Exception as exc:
            raise KeyParseError("cbor", f"bundle decode failed: {exc}") from exc

        if bundle.get("bundle") != "keypair":
            raise KeyParseError("cbor", "not a keypair bundle")

        pub = PublicKey.from_cbor(_ser.dumps(bundle["pub"]))
        sec = SecretKey.from_cbor(_ser.dumps(bundle["sec"]))
        return cls(public=pub, secret=sec)


# ---------------------------------------------------------------------------
# Utility: generate a random nonce / salt of a given length
# ---------------------------------------------------------------------------


def generate_nonce(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes.

    Thin wrapper around os.urandom that documents our intent clearly.
    Don't use random.randbytes() — it's not cryptographically secure.
    """
    if length <= 0:
        raise ValueError(f"nonce length must be positive, got {length}")
    if length < 12:
        warnings.warn(
            f"generate_nonce({length}) is below the 12-byte minimum recommended "
            "for AEAD nonces (e.g. AES-GCM). Most protocols require at least 12 bytes.",
            stacklevel=2,
        )
    return os.urandom(length)
