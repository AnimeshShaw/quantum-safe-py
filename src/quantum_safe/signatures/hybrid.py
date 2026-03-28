"""
quantum_safe.signatures.hybrid
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HybridSign: combined classical + PQC signatures.

Default: Ed25519 + ML-DSA-65.

The construction
----------------
For each signing operation, we produce two independent signatures:
  1. classical_sig = Ed25519.Sign(classical_sk, message, context)
  2. pqc_sig       = ML-DSA.Sign(pqc_sk, message, context)

Both are stored in a HybridSignature structure which is CBOR-encoded and
stored in the SignedMessage.signature field. Verification requires BOTH
sub-signatures to pass.

Why not just sign with the PQC key?
  During the transition period, we treat classical and PQC security as
  independent. If ML-DSA is somehow broken (unlikely but possible for
  a new algorithm), the hybrid signature still has Ed25519 security.
  If Ed25519 is broken by quantum hardware, ML-DSA covers it.

Hedged mode
  Both sub-signatures use the same random prefix (generated once, stored
  in the SignedMessage). This ensures both halves commit to the same
  randomness, preventing differential fault attacks that operate on
  one sub-signature at a time.

Key format
  Hybrid keys use the same length-prefixed packing as HybridKEM keys:
    2 bytes big-endian: classical_component_len
    N bytes:            classical component
    remaining bytes:    pqc component

  Public key: classical_pub || pqc_pub
  Secret key: classical_sec || pqc_sec
"""

from __future__ import annotations

import os
import struct
import time
import warnings
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from quantum_safe.backends import get_signature_backend
from quantum_safe.exceptions import (
    UnsupportedAlgorithm,
    VerificationError,
)
from quantum_safe.signatures.algorithms import (
    DEFAULT_HYBRID_CLASSICAL,
    DEFAULT_HYBRID_PQC,
    HEDGED_RANDOMNESS_BYTES,
    canonical_hybrid_name,
    validate_hybrid_combination,
)
from quantum_safe.signatures.core import Sign
from quantum_safe.types import KeyPair, MigrationState, PublicKey, SecretKey
from quantum_safe.types.signatures import HybridSignature, SignedMessage

if TYPE_CHECKING:
    from quantum_safe.backends.base import AbstractSignatureBackend


# Length prefix format (same as kem/hybrid.py)
_LEN_FMT = ">H"
_LEN_SIZE = 2


def _pack_components(a: bytes, b: bytes) -> bytes:
    return struct.pack(_LEN_FMT, len(a)) + a + b


def _unpack_components(data: bytes, context: str = "") -> tuple[bytes, bytes]:
    if len(data) < _LEN_SIZE:
        raise VerificationError(algo=context)
    (a_len,) = struct.unpack_from(_LEN_FMT, data, 0)
    if len(data) < _LEN_SIZE + a_len:
        raise VerificationError(algo=context)
    a = data[_LEN_SIZE: _LEN_SIZE + a_len]
    b = data[_LEN_SIZE + a_len:]
    return a, b


class HybridSign:
    """Hybrid signature scheme: classical + PQC combined.

    Default: Ed25519 + ML-DSA-65. Both sub-signatures must be valid for
    verification to pass.

    Args:
        classical:  Classical signature algorithm: "Ed25519" or "P-256".
        pqc:        PQC signature algorithm. Default: "ML-DSA-65".
        backend:    PQC backend: "auto", "liboqs", "rustcrypto".
        hedged:     Hedged signing mode (default True). Prepends 32 random
                    bytes before signing to prevent fault injection.
        validate:   Validate that the combination is approved (default True).

    Example::

        from quantum_safe import HybridSign

        signer = HybridSign()
        kp     = signer.generate_keypair()
        sm     = signer.sign(b"document", kp.secret, context=b"myapp-v1")
        signer.verify(sm, kp.public)
    """

    def __init__(
        self,
        classical: str = DEFAULT_HYBRID_CLASSICAL,
        pqc: str = DEFAULT_HYBRID_PQC,
        backend: str = "auto",
        hedged: bool = True,
        validate: bool = True,
    ) -> None:
        if validate:
            validate_hybrid_combination(classical, pqc)

        self._classical = classical
        self._pqc = pqc
        self._algorithm = canonical_hybrid_name(classical, pqc)
        self._hedged = hedged
        self._backend: AbstractSignatureBackend = get_signature_backend(backend)

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def classical_algorithm(self) -> str:
        return self._classical

    @property
    def pqc_algorithm(self) -> str:
        return self._pqc

    @property
    def is_hedged(self) -> bool:
        return self._hedged

    @property
    def backend_name(self) -> str:
        return self._backend.name

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keypair(self) -> KeyPair:
        """Generate a hybrid signing key pair.

        Returns:
            KeyPair where public/secret contain both classical and PQC
            sub-keys, packed with a length prefix.
        """
        classical_pub, classical_sec = self._gen_classical_keypair()
        pqc_pub, pqc_sec = self._backend.keygen(self._pqc)

        combined_pub = _pack_components(classical_pub, pqc_pub)
        combined_sec = _pack_components(classical_sec, pqc_sec)

        pub = PublicKey(
            raw=combined_pub,
            algorithm=self._algorithm,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=self._backend.name,
        )
        sec = SecretKey(
            raw=combined_sec,
            algorithm=self._algorithm,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=self._backend.name,
        )
        return KeyPair(public=pub, secret=sec)

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(
        self,
        message: bytes,
        secret_key: SecretKey,
        context: bytes = b"",
    ) -> SignedMessage:
        """Sign a message with both classical and PQC sub-keys.

        Args:
            message:    Bytes to sign.
            secret_key: Hybrid secret key from generate_keypair().
            context:    Domain-separation context (up to 255 bytes).

        Returns:
            SignedMessage. The .signature field contains a CBOR-encoded
            HybridSignature with both sub-signatures. Both must be valid
            for verify() to succeed.
        """
        if secret_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                secret_key.algorithm, available=[self._algorithm]
            )
        if len(context) > 255:
            raise ValueError(f"context must be ≤255 bytes, got {len(context)}")

        classical_sec_bytes, pqc_sec_bytes = _unpack_components(
            secret_key.raw_bytes, context=self._algorithm
        )

        # Generate one rand_prefix shared by both sub-signatures.
        # They both commit to the same randomness — prevents split signing
        # attacks.
        if self._hedged:
            rand_prefix = os.urandom(HEDGED_RANDOMNESS_BYTES)
        else:
            rand_prefix = b""

        msg_to_sign = rand_prefix + message

        # Classical sub-signature
        classical_sig = self._sign_classical(
            classical_sec_bytes, msg_to_sign, context
        )

        # PQC sub-signature
        pqc_sig = self._backend.sign(
            self._pqc, pqc_sec_bytes, msg_to_sign, context
        )

        # Pack both into a HybridSignature, then wrap in our blob format
        hs = HybridSignature(
            classical_sig=classical_sig,
            pqc_sig=pqc_sig,
            classical_algo=self._classical,
            pqc_algo=self._pqc,
        )

        # Same blob format as Sign: prefix_len (1B) || prefix || payload
        sig_blob = Sign._pack_sig_blob(rand_prefix, hs.to_bytes())

        return SignedMessage(
            message=message,
            signature=sig_blob,
            algorithm=self._algorithm,
            context=context,
            signer_fingerprint="",
            signed_at=time.time(),
            is_hybrid=True,
        )

    def sign_with_fingerprint(
        self,
        message: bytes,
        keypair: KeyPair,
        context: bytes = b"",
    ) -> SignedMessage:
        """Like sign(), but stores the signer's public key fingerprint."""
        sm = self.sign(message, keypair.secret, context)
        return SignedMessage(
            message=sm.message,
            signature=sm.signature,
            algorithm=sm.algorithm,
            context=sm.context,
            signer_fingerprint=keypair.public.fingerprint(),
            signed_at=sm.signed_at,
            is_hybrid=sm.is_hybrid,
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, signed_message: SignedMessage, public_key: PublicKey) -> None:
        """Verify a hybrid signed message. Both sub-signatures must be valid.

        Args:
            signed_message: A SignedMessage from sign().
            public_key:     The signer's hybrid public key.

        Raises:
            VerificationError: if either sub-signature is invalid.
            UnsupportedAlgorithm: if algorithm doesn't match.
        """
        if signed_message.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                signed_message.algorithm, available=[self._algorithm]
            )
        if public_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                public_key.algorithm, available=[self._algorithm]
            )

        classical_pub_bytes, pqc_pub_bytes = _unpack_components(
            public_key.raw_bytes, context=self._algorithm
        )

        # Unpack the blob to get rand_prefix and the HybridSignature payload
        rand_prefix, hs_bytes = Sign._unpack_sig_blob(signed_message.signature)
        msg_to_verify = rand_prefix + signed_message.message

        # Decode the HybridSignature
        try:
            hs = HybridSignature.from_bytes(hs_bytes)
        except Exception as exc:
            raise VerificationError(algo=self._algorithm) from exc

        # Verify classical sub-signature
        classical_ok = self._verify_classical(
            classical_pub_bytes,
            msg_to_verify,
            hs.classical_sig,
            signed_message.context,
        )
        if not classical_ok:
            raise VerificationError(
                algo=self._algorithm,
                # Don't say which sub-signature failed — an attacker could
                # use that to probe which component is weak.
            )

        # Verify PQC sub-signature
        pqc_ok = self._backend.verify(
            self._pqc,
            pqc_pub_bytes,
            msg_to_verify,
            hs.pqc_sig,
            signed_message.context,
        )
        if not pqc_ok:
            raise VerificationError(algo=self._algorithm)

    # ------------------------------------------------------------------
    # Classical signing internals
    # ------------------------------------------------------------------

    def _gen_classical_keypair(self) -> tuple[bytes, bytes]:
        """Generate a classical signing keypair.

        Returns (public_key_bytes, secret_key_bytes).
        """
        if self._classical == "Ed25519":
            priv = Ed25519PrivateKey.generate()
            pub = priv.public_key()
            priv_bytes = priv.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
            pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            return pub_bytes, priv_bytes

        elif self._classical == "P-256":
            from cryptography.hazmat.primitives.asymmetric.ec import (
                SECP256R1, generate_private_key, ECDSA
            )
            from cryptography.hazmat.backends import default_backend
            priv = generate_private_key(SECP256R1(), default_backend())
            pub = priv.public_key()
            priv_bytes = priv.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            # Store public key as raw 64-byte (x, y)
            pub_nums = pub.public_key().public_numbers() if hasattr(pub, 'public_key') else pub.public_numbers()
            x_bytes = pub_nums.x.to_bytes(32, "big")
            y_bytes = pub_nums.y.to_bytes(32, "big")
            return x_bytes + y_bytes, priv_bytes

        else:
            raise UnsupportedAlgorithm(
                self._classical, available=["Ed25519", "P-256"]
            )

    def _sign_classical(
        self,
        secret_key_bytes: bytes,
        message: bytes,
        context: bytes,
    ) -> bytes:
        """Sign with the classical sub-key."""
        if self._classical == "Ed25519":
            # Ed25519 doesn't support context natively, so we prepend it
            # using a length-prefixed format (same as liboqs backend does for PQC).
            msg_with_ctx = bytes([len(context)]) + context + message
            priv = Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
            return priv.sign(msg_with_ctx)

        elif self._classical == "P-256":
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            msg_with_ctx = bytes([len(context)]) + context + message
            priv = load_pem_private_key(
                secret_key_bytes, password=None, backend=default_backend()
            )
            return priv.sign(msg_with_ctx, ECDSA(hashes.SHA256()))

        else:
            raise UnsupportedAlgorithm(self._classical, available=["Ed25519", "P-256"])

    def _verify_classical(
        self,
        public_key_bytes: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        """Verify with the classical sub-key. Returns bool."""
        msg_with_ctx = bytes([len(context)]) + context + message

        if self._classical == "Ed25519":
            try:
                pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                pub.verify(signature, msg_with_ctx)
                return True
            except Exception:  # noqa: BLE001
                return False

        elif self._classical == "P-256":
            from cryptography.hazmat.primitives.asymmetric.ec import (
                ECDSA, SECP256R1, EllipticCurvePublicNumbers
            )
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            try:
                if len(public_key_bytes) != 64:
                    return False
                x = int.from_bytes(public_key_bytes[:32], "big")
                y = int.from_bytes(public_key_bytes[32:], "big")
                pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(
                    default_backend()
                )
                pub.verify(signature, msg_with_ctx, ECDSA(hashes.SHA256()))
                return True
            except Exception:  # noqa: BLE001
                return False

        else:
            return False

    def __repr__(self) -> str:
        return (
            f"HybridSign("
            f"classical={self._classical!r}, "
            f"pqc={self._pqc!r}, "
            f"hedged={self._hedged}, "
            f"backend={self._backend.name!r})"
        )
