"""
quantum_safe.kem.xwing
~~~~~~~~~~~~~~~~~~~~~~~

X-Wing, the general-purpose hybrid KEM of draft-connolly-cfrg-xwing-kem: ML-KEM-768 and X25519
combined with a SHA3-256 combiner that binds the X25519 ciphertext and public key.

This is a different construction from :class:`~quantum_safe.kem.hybrid.HybridKEM` (an
HKDF-SHA-256 combiner over length-prefixed components). It is what other X-Wing implementations
speak, and it is byte-compatible with quantum-safe-ts (``new HybridKEM('X-Wing')``), which is
tested in both directions.

Sizes
-----
secret key   32 bytes (a seed; the ML-KEM and X25519 keys are expanded from it with SHAKE-256)
public key   1216 bytes (ML-KEM-768 public key 1184 || X25519 public key 32)
ciphertext   1120 bytes (ML-KEM-768 ciphertext 1088 || X25519 ephemeral public key 32)
shared secret 32 bytes

Combiner
--------
``ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || label)`` with the six-byte label ``\\.//^\\``.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from quantum_safe.backends import get_kem_backend
from quantum_safe.exceptions import UnsupportedAlgorithm
from quantum_safe.types import KeyPair, MigrationState, PublicKey, SecretKey
from quantum_safe.types.kem import CipherText, SharedSecret

XWING_NAME = "X-Wing"
PUBLIC_KEY_BYTES = 1216
SECRET_KEY_BYTES = 32
CIPHERTEXT_BYTES = 1120
SHARED_SECRET_BYTES = 32

_MLKEM = "ML-KEM-768"
_MLKEM_PK = 1184
_MLKEM_CT = 1088
_LABEL = bytes([0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C])  # \.//^\


def _expand(seed: bytes) -> tuple[bytes, bytes]:
    """Expand the 32-byte secret key: ``(d || z, X25519 secret key)`` from SHAKE-256(seed, 96)."""
    expanded = hashlib.shake_256(seed).digest(96)
    return expanded[:64], expanded[64:96]


def _x25519_public(secret: bytes) -> bytes:
    """Return the 32-byte X25519 public key for a 32-byte secret key."""
    return (
        X25519PrivateKey.from_private_bytes(secret)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def _x25519_exchange(secret: bytes, peer_public: bytes) -> bytes:
    """X25519 as RFC 7748 defines it: a low-order peer point yields the all-zero output.

    pyca/cryptography raises for those points. X-Wing does not reject them (the combiner still
    binds the ciphertext), and other implementations return the all-zero value, so match them.
    """
    try:
        return X25519PrivateKey.from_private_bytes(secret).exchange(
            X25519PublicKey.from_public_bytes(peer_public)
        )
    except ValueError:
        return bytes(32)


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """The X-Wing combiner: SHA3-256 over ``ss_M || ss_X || ct_X || pk_X || label``."""
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _LABEL).digest()


class XWing:
    """X-Wing hybrid KEM (ML-KEM-768 + X25519).

    Example::

        from quantum_safe.kem.xwing import XWing

        kem = XWing()
        kp = kem.generate_keypair()
        ct, ss_sender = kem.encapsulate(kp.public)
        ss_receiver = kem.decapsulate(kp.secret, ct)
        assert ss_sender == ss_receiver

    The secret key is the 32-byte seed; ``keypair_from_seed`` rebuilds a pair from it.
    """

    def __init__(self, backend: str = "auto") -> None:
        """Create an X-Wing KEM on the given backend.

        Args:
            backend: Backend name: "auto", "liboqs", "rustcrypto" or "pyca". The backend must
                support seeded ML-KEM-768 key generation (``keygen_from_seed``) for key
                generation and decapsulation.

        Raises:
            BackendNotAvailable: if the requested backend is not installed.
        """
        self._backend = get_kem_backend(backend)

    @property
    def algorithm(self) -> str:
        """The algorithm name, ``"X-Wing"``."""
        return XWING_NAME

    # ------------------------------------------------------------------

    def keypair_from_seed(self, seed: bytes) -> KeyPair:
        """Derive the key pair for a 32-byte seed (deterministic).

        The public key is 1216 bytes (ML-KEM-768 public key || X25519 public key) and the secret
        key is the seed itself.

        Raises:
            ValueError: if ``seed`` is not exactly 32 bytes.
            UnsupportedAlgorithm: if the backend has no seeded ML-KEM key generation.
        """
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != SECRET_KEY_BYTES:
            raise ValueError(f"an X-Wing seed is exactly {SECRET_KEY_BYTES} bytes")
        d_z, sk_x = _expand(bytes(seed))
        pk_m, _sk_m = self._backend.keygen_from_seed(_MLKEM, d_z)
        pub = PublicKey(
            raw=pk_m + _x25519_public(sk_x),
            algorithm=XWING_NAME,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=self._backend.name,
        )
        sec = SecretKey(
            raw=bytes(seed),
            algorithm=XWING_NAME,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=self._backend.name,
        )
        return KeyPair(public=pub, secret=sec)

    def generate_keypair(self) -> KeyPair:
        """Generate a fresh key pair from 32 random bytes (``os.urandom``)."""
        return self.keypair_from_seed(os.urandom(SECRET_KEY_BYTES))

    def encapsulate(self, public_key: PublicKey) -> tuple[CipherText, SharedSecret]:
        """Produce a ciphertext and the 32-byte shared secret for ``public_key``.

        The ciphertext is 1120 bytes (ML-KEM-768 ciphertext || X25519 ephemeral public key).

        Raises:
            UnsupportedAlgorithm: if the key is not an X-Wing key.
            ValueError: if the public key is not 1216 bytes.
        """
        if public_key.algorithm != XWING_NAME:
            raise UnsupportedAlgorithm(public_key.algorithm, available=[XWING_NAME])
        raw = public_key.raw_bytes
        if len(raw) != PUBLIC_KEY_BYTES:
            raise ValueError(f"an X-Wing public key is {PUBLIC_KEY_BYTES} bytes, got {len(raw)}")
        pk_m, pk_x = raw[:_MLKEM_PK], raw[_MLKEM_PK:]
        ct_m, ss_m = self._backend.encapsulate(_MLKEM, pk_m)
        ephemeral = X25519PrivateKey.generate()
        ct_x = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        try:
            ss_x = ephemeral.exchange(X25519PublicKey.from_public_bytes(pk_x))
        except ValueError:
            ss_x = bytes(32)
        shared = _combine(ss_m, ss_x, ct_x, pk_x)
        return CipherText(ct_m + ct_x, XWING_NAME), SharedSecret(shared, XWING_NAME, is_hybrid=True)

    def decapsulate(self, secret_key: SecretKey, ciphertext: CipherText) -> SharedSecret:
        """Recover the shared secret.

        A modified ciphertext yields a different secret, not an error (implicit rejection).

        Raises:
            UnsupportedAlgorithm: if the key is not an X-Wing key.
            ValueError: if the secret key is not 32 bytes or the ciphertext is not 1120 bytes.
        """
        if secret_key.algorithm != XWING_NAME:
            raise UnsupportedAlgorithm(secret_key.algorithm, available=[XWING_NAME])
        seed = secret_key.raw_bytes
        if len(seed) != SECRET_KEY_BYTES:
            raise ValueError(f"an X-Wing secret key is {SECRET_KEY_BYTES} bytes, got {len(seed)}")
        ct = bytes(ciphertext)
        if len(ct) != CIPHERTEXT_BYTES:
            raise ValueError(f"an X-Wing ciphertext is {CIPHERTEXT_BYTES} bytes, got {len(ct)}")
        ct_m, ct_x = ct[:_MLKEM_CT], ct[_MLKEM_CT:]
        d_z, sk_x = _expand(seed)
        _pk_m, sk_m = self._backend.keygen_from_seed(_MLKEM, d_z)
        ss_m = self._backend.decapsulate(_MLKEM, sk_m, ct_m)
        pk_x = _x25519_public(sk_x)
        ss_x = _x25519_exchange(sk_x, ct_x)
        return SharedSecret(_combine(ss_m, ss_x, ct_x, pk_x), XWING_NAME, is_hybrid=True)
