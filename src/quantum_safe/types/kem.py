"""
quantum_safe.types.kem
~~~~~~~~~~~~~~~~~~~~~~

Typed wrappers for KEM operation outputs.

The two core outputs of a KEM are:
  - CipherText: what the encapsulator sends to the decapsulator
  - SharedSecret: the symmetric key material both parties derive

Both are distinct types (not type aliases for bytes) to prevent the
class of bug where you accidentally pass a shared secret as a ciphertext
or vice versa. This has happened in real implementations.

For hybrid KEMs, we have HybridCipherText which carries both the classical
(X25519) and PQC (ML-KEM) ciphertexts, and derives a combined shared secret.

The combination follows the IETF hybrid KEM construction:
  combined_ss = HKDF-SHA256(
      ikm  = classical_ss || pqc_ss,
      salt = "",
      info = "quantum-safe hybrid KEM v1" || algorithm_string
  )

References:
  - FIPS 203 §6.2 — ML-KEM.Encaps / ML-KEM.Decaps
  - draft-ietf-tls-hybrid-design §3 — combiner construction
  - RFC 5869 — HKDF
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import ClassVar

from quantum_safe.exceptions import DecapsulationError


# We use HKDF-SHA256 for the hybrid combiner. The info string is fixed and
# version-pinned so that old clients can't be tricked into using a different
# construction.
_HYBRID_COMBINER_INFO = b"quantum-safe hybrid KEM v1"
_SHARED_SECRET_LEN = 32  # bytes — 256-bit symmetric key


class SharedSecret:
    """The shared secret output of a KEM operation.

    This is 32 bytes of symmetric key material derived from the KEM.
    Like SecretKey, it zeroizes on deletion.

    You should use this as input to a KDF (e.g. HKDF) to derive actual
    encryption keys — don't use it directly as an AES key without further
    processing.

    The library does this for you in quantum_safe.protocols.envelope.
    """

    __slots__ = ("_data", "_algorithm", "_is_hybrid")

    def __init__(self, data: bytes, algorithm: str, is_hybrid: bool = False) -> None:
        if len(data) != _SHARED_SECRET_LEN:
            raise ValueError(
                f"SharedSecret must be exactly {_SHARED_SECRET_LEN} bytes, "
                f"got {len(data)}"
            )
        # Store in a mutable buffer so we can zero it
        self._data = bytearray(data)
        self._algorithm = algorithm
        self._is_hybrid = is_hybrid

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def is_hybrid(self) -> bool:
        """Whether this secret was derived from a hybrid KEM."""
        return self._is_hybrid

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SharedSecret):
            return hmac.compare_digest(bytes(self._data), bytes(other._data))
        if isinstance(other, (bytes, bytearray)):
            return hmac.compare_digest(bytes(self._data), bytes(other))
        return NotImplemented

    def __repr__(self) -> str:
        return f"SharedSecret(algo={self._algorithm!r}, <{len(self._data)} bytes REDACTED>)"

    def __del__(self) -> None:
        try:
            for i in range(len(self._data)):
                self._data[i] = 0
        except Exception:  # noqa: BLE001
            pass

    def derive_key(
        self,
        length: int = 32,
        salt: bytes | None = None,
        info: bytes = b"",
    ) -> bytes:
        """Derive a key from this shared secret using HKDF-SHA256.

        This is a convenience wrapper. For full control, use
        cryptography.hazmat.primitives.kdf.hkdf directly.

        Args:
            length: Desired output length in bytes (max 255 * 32 = 8160).
            salt:   Optional salt. Defaults to a zero-filled string if None.
            info:   Application-specific context. Include your app name
                    and version to prevent cross-context key reuse.

        Returns:
            Raw key bytes of the requested length.

        Example:
            enc_key = ss.derive_key(32, info=b"myapp-encryption-v1")
            mac_key = ss.derive_key(32, info=b"myapp-mac-v1")
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(bytes(self._data))


class CipherText:
    """The ciphertext output of KEM encapsulation.

    This is what the encapsulator transmits to the decapsulator.
    It's not secret — but it is authenticated (MAC'd or KEM-authenticated
    depending on the scheme), so any modification will cause decapsulation
    to fail.

    Size varies by algorithm:
      ML-KEM-512:   768 bytes
      ML-KEM-768:  1088 bytes
      ML-KEM-1024: 1568 bytes
    """

    __slots__ = ("_data", "_algorithm")

    # Expected ciphertext sizes per algorithm (from FIPS 203 §2.4)
    _EXPECTED_SIZES: ClassVar[dict[str, int]] = {
        "ML-KEM-512": 768,
        "ML-KEM-768": 1088,
        "ML-KEM-1024": 1568,
    }

    def __init__(self, data: bytes, algorithm: str) -> None:
        if not data:
            raise ValueError("ciphertext cannot be empty")
        self._data = data
        self._algorithm = algorithm

        # Warn (not error) on size mismatch — the backend may use a slightly
        # different internal format for hybrid ciphertexts
        expected = self._EXPECTED_SIZES.get(algorithm)
        if expected is not None and len(data) != expected:
            import warnings
            warnings.warn(
                f"CipherText for {algorithm} has unexpected size "
                f"(expected {expected}, got {len(data)}). "
                "This may indicate a backend format difference.",
                stacklevel=2,
            )

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def data(self) -> bytes:
        return self._data

    def __bytes__(self) -> bytes:
        return self._data

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"CipherText(algo={self._algorithm!r}, size={len(self._data)}B)"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CipherText):
            return self._algorithm == other._algorithm and self._data == other._data
        return NotImplemented


class HybridCipherText:
    """Ciphertext from a hybrid KEM: classical ephemeral + PQC encapsulation.

    The wire format is:
        classical_ct_len (2 bytes, big-endian uint16)
        || classical_ct
        || pqc_ct

    This framing allows the receiver to split the two components without
    needing out-of-band length information.
    """

    __slots__ = ("_classical_ct", "_pqc_ct", "_algorithm")

    # The length prefix is a 2-byte big-endian uint16
    _LEN_PREFIX_FORMAT = ">H"
    _LEN_PREFIX_SIZE = 2

    def __init__(
        self,
        classical_ct: bytes,
        pqc_ct: bytes,
        algorithm: str,
    ) -> None:
        if not classical_ct:
            raise ValueError("classical_ct cannot be empty")
        if not pqc_ct:
            raise ValueError("pqc_ct cannot be empty")
        self._classical_ct = classical_ct
        self._pqc_ct = pqc_ct
        self._algorithm = algorithm

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def classical_ct(self) -> bytes:
        return self._classical_ct

    @property
    def pqc_ct(self) -> bytes:
        return self._pqc_ct

    def to_bytes(self) -> bytes:
        """Encode as length-prefixed wire format."""
        prefix = struct.pack(
            self._LEN_PREFIX_FORMAT, len(self._classical_ct)
        )
        return prefix + self._classical_ct + self._pqc_ct

    @classmethod
    def from_bytes(cls, data: bytes, algorithm: str) -> "HybridCipherText":
        """Decode from length-prefixed wire format."""
        if len(data) < cls._LEN_PREFIX_SIZE:
            raise DecapsulationError(algo=algorithm)

        (classical_len,) = struct.unpack_from(cls._LEN_PREFIX_FORMAT, data, 0)
        offset = cls._LEN_PREFIX_SIZE

        if len(data) < offset + classical_len:
            raise DecapsulationError(algo=algorithm)

        classical_ct = data[offset : offset + classical_len]
        pqc_ct = data[offset + classical_len :]

        if not pqc_ct:
            raise DecapsulationError(algo=algorithm)

        return cls(
            classical_ct=classical_ct,
            pqc_ct=pqc_ct,
            algorithm=algorithm,
        )

    def __len__(self) -> int:
        return self._LEN_PREFIX_SIZE + len(self._classical_ct) + len(self._pqc_ct)

    def __repr__(self) -> str:
        return (
            f"HybridCipherText(algo={self._algorithm!r}, "
            f"classical={len(self._classical_ct)}B, "
            f"pqc={len(self._pqc_ct)}B)"
        )


def combine_shared_secrets(
    classical_ss: bytes,
    pqc_ss: bytes,
    algorithm: str,
    classical_ct: bytes,
    pqc_ct: bytes,
) -> SharedSecret:
    """Combine classical and PQC shared secrets using the hybrid KEM combiner.

    Implements the construction from draft-ietf-tls-hybrid-design §3.2:

        combined = HKDF-SHA256(
            ikm  = classical_ss || pqc_ss,
            salt = classical_ct || pqc_ct,
            info = info_string || algo_name
        )

    Using the concatenated ciphertexts as the salt binds the shared secret
    to the specific exchange (prevents KCI attacks where an attacker reuses
    a ciphertext in a different session).

    Args:
        classical_ss: Shared secret from X25519 (32 bytes)
        pqc_ss:       Shared secret from ML-KEM (32 bytes)
        algorithm:    Algorithm string for domain separation
        classical_ct: Classical ciphertext (X25519 public key of encapsulator)
        pqc_ct:       PQC ciphertext

    Returns:
        A 32-byte SharedSecret derived from both components.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    # IKM is the concatenation of both secrets
    ikm = classical_ss + pqc_ss

    # Salt is the concatenation of both ciphertexts — binds to this exchange
    salt = classical_ct + pqc_ct

    # Info provides algorithm-level domain separation
    info = _HYBRID_COMBINER_INFO + b"\x00" + algorithm.encode("ascii")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_SHARED_SECRET_LEN,
        salt=salt,
        info=info,
    )
    combined = hkdf.derive(ikm)

    return SharedSecret(data=combined, algorithm=algorithm, is_hybrid=True)
