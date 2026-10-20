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
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256, SHA384
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
from quantum_safe.signatures import _v2
from quantum_safe.signatures.algorithms import (
    DEFAULT_HYBRID_CLASSICAL,
    DEFAULT_HYBRID_PQC,
    HEDGED_RANDOMNESS_BYTES,
    canonical_hybrid_name,
    validate_hybrid_combination,
)
from quantum_safe.signatures.core import Sign, check_expected_context
from quantum_safe.types import KeyPair, MigrationState, PublicKey, SecretKey
from quantum_safe.types.signatures import HybridSignature, SignedMessage

if TYPE_CHECKING:
    from quantum_safe.backends.base import AbstractSignatureBackend


# Length prefix format (same as kem/hybrid.py)
_LEN_FMT = ">H"
_LEN_SIZE = 2


def _pack_components(a: bytes, b: bytes) -> bytes:
    """Return ``len(a)`` (2 bytes, big-endian) || ``a`` || ``b``."""
    return struct.pack(_LEN_FMT, len(a)) + a + b


def _unpack_components(data: bytes, context: str = "") -> tuple[bytes, bytes]:
    """Split data packed by ``_pack_components``; raise VerificationError if it is truncated."""
    if len(data) < _LEN_SIZE:
        raise VerificationError(algo=context)
    (a_len,) = struct.unpack_from(_LEN_FMT, data, 0)
    if len(data) < _LEN_SIZE + a_len:
        raise VerificationError(algo=context)
    a = data[_LEN_SIZE : _LEN_SIZE + a_len]
    b = data[_LEN_SIZE + a_len :]
    return a, b


# classical name -> (curve class, coordinate length in bytes, ECDSA digest class)
_EC_SIGNING: dict[str, tuple[type, int, type]] = {
    "P-256": (SECP256R1, 32, SHA256),
    "P-384": (SECP384R1, 48, SHA384),
}


class HybridSign:
    """Hybrid signature scheme: classical + PQC combined.

    Default: Ed25519 + ML-DSA-65 in the ``-v2`` format (``Ed25519+ML-DSA-65-v2``).
    Both sub-signatures must be valid for verification to pass.

    Args:
        classical:  Classical signature algorithm: "Ed25519", "P-256" or "P-384".
        pqc:        PQC signature algorithm. Default: "ML-DSA-65-v2" (the original
                    prefix format is "ML-DSA-65"; name it to keep using it). With
                    ``hedged=False`` and no ``pqc``, the original format is used,
                    because ``-v2`` is always hedged.
        backend:    PQC backend: "auto", "liboqs", "rustcrypto".
        hedged:     Hedged signing mode (default True). Prepends 32 random
                    bytes before signing to prevent fault injection. A
                    verifier accepts only signatures made in its own mode;
                    use the signer's ``hedged`` value and one mode per key.
        validate:   Validate that the combination is approved (default True).

    Example::

        from quantum_safe import HybridSign

        signer = HybridSign()
        kp     = signer.generate_keypair()
        sm     = signer.sign(b"document", kp.secret, context=b"myapp-v1")
        signer.verify(sm, kp.public, context=b"myapp-v1")
    """

    def __init__(
        self,
        classical: str = DEFAULT_HYBRID_CLASSICAL,
        pqc: str | None = None,
        backend: str = "auto",
        hedged: bool = True,
        validate: bool = True,
    ) -> None:
        """Create a hybrid signer/verifier for a classical and a PQC algorithm.

        The arguments are described in the class docstring. A ``-v2`` suffix on ``pqc`` selects
        the v2 signature format.

        Raises:
            UnsupportedAlgorithm: if a ``-v2`` pairing has no v2 identifier.
            ValueError: if a ``-v2`` suite is combined with ``hedged=False``, or ``validate`` is
                True and the combination is not an approved hybrid.
            BackendNotAvailable: if the requested backend is not installed.
        """
        if pqc is None:
            # The default suite is the -v2 format. It is always hedged inside ML-DSA, so a caller
            # that asks for ``hedged=False`` without naming a suite gets the original format, the
            # only one with an unhedged mode (this keeps verifiers built that way working).
            pqc = DEFAULT_HYBRID_PQC if hedged else DEFAULT_HYBRID_PQC.removesuffix(_v2.SUFFIX)
        # A ``-v2`` suffix on the PQC half selects the v2 signature format.
        self._v2 = _v2.is_v2(pqc)
        if self._v2:
            if _v2.base_of(f"{classical}+{pqc}") is None:
                raise UnsupportedAlgorithm(f"{classical}+{pqc}", available=_v2.all_identifiers())
            if not hedged:
                raise ValueError(
                    "v2 signatures are always hedged inside ML-DSA (FIPS 204); "
                    "hedged=False does not exist for them"
                )
            pqc_base = pqc[: -len(_v2.SUFFIX)]
        else:
            pqc_base = pqc
        if validate:
            validate_hybrid_combination(classical, pqc_base)

        self._classical = classical
        self._pqc = pqc
        self._pqc_base = pqc_base  # the registry / backend name of the ML-DSA half
        self._algorithm = canonical_hybrid_name(classical, pqc)
        self._hedged = hedged
        self._backend: AbstractSignatureBackend = get_signature_backend(backend)

    @property
    def algorithm(self) -> str:
        """Full hybrid algorithm string, e.g. 'Ed25519+ML-DSA-65-v2'."""
        return self._algorithm

    @property
    def classical_algorithm(self) -> str:
        """The classical component algorithm name, e.g. 'Ed25519'."""
        return self._classical

    @property
    def pqc_algorithm(self) -> str:
        """The PQC component algorithm name, including any ``-v2`` suffix."""
        return self._pqc

    @property
    def is_hedged(self) -> bool:
        """True if signing prepends 32 random bytes to the message."""
        return self._hedged

    @property
    def backend_name(self) -> str:
        """Name of the backend used for the PQC component."""
        return self._backend.name

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keypair(self) -> KeyPair:
        """Generate a hybrid signing key pair.

        Returns:
            KeyPair where public/secret contain both classical and PQC
            sub-keys, packed with a length prefix.

        Raises:
            UnsupportedAlgorithm: if the classical algorithm is not Ed25519, P-256 or P-384.
            KeyGenerationError: if the backend fails to generate the PQC key pair.
        """
        classical_pub, classical_sec = self._gen_classical_keypair()
        pqc_pub, pqc_sec = self._backend.keygen(self._pqc_base)

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

        Raises:
            UnsupportedAlgorithm: if the key's algorithm doesn't match.
            ValueError: if ``context`` is longer than 255 bytes.
            VerificationError: if the packed secret key is truncated.
        """
        if secret_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(secret_key.algorithm, available=[self._algorithm])
        if len(context) > 255:
            raise ValueError(f"context must be <=255 bytes, got {len(context)}")

        if self._v2:
            blob = _v2.sign(self._algorithm, secret_key.raw_bytes, message, context, self._backend)
            return SignedMessage(
                message=message,
                signature=blob,
                algorithm=self._algorithm,
                context=context,
                signer_fingerprint="",
                signed_at=time.time(),
                is_hybrid=True,
            )

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
        classical_sig = self._sign_classical(classical_sec_bytes, msg_to_sign, context)

        # PQC sub-signature
        pqc_sig = self._backend.sign(self._pqc, pqc_sec_bytes, msg_to_sign, context)

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
        """Like sign(), but stores the signer's public key fingerprint.

        Args:
            message: Bytes to sign.
            keypair: The hybrid key pair. The secret key signs; the public key's fingerprint
                is stored in the result.
            context: Domain-separation context (up to 255 bytes).

        Returns:
            SignedMessage with ``signer_fingerprint`` set.

        Raises:
            UnsupportedAlgorithm: if the key's algorithm doesn't match.
            ValueError: if ``context`` is longer than 255 bytes.
        """
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

    def verify(
        self,
        signed_message: SignedMessage,
        public_key: PublicKey,
        context: bytes | None = None,
    ) -> None:
        """Verify a hybrid signed message. Both sub-signatures must be valid.

        Args:
            signed_message: A SignedMessage from sign().
            public_key:     The signer's hybrid public key.
            context:        The context this verifier expects; the message's
                            own context must equal it. Omitting it is
                            deprecated (see Sign.verify).

        Raises:
            VerificationError: if either sub-signature is invalid, or the
                message's context differs from ``context``.
            UnsupportedAlgorithm: if algorithm doesn't match.
        """
        check_expected_context(signed_message, context, self._algorithm)
        if signed_message.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(signed_message.algorithm, available=[self._algorithm])
        if public_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(public_key.algorithm, available=[self._algorithm])

        if self._v2:
            _v2.verify(
                self._algorithm,
                public_key.raw_bytes,
                signed_message.message,
                signed_message.signature,
                signed_message.context,
                self._backend,
            )
            return

        classical_pub_bytes, pqc_pub_bytes = _unpack_components(
            public_key.raw_bytes, context=self._algorithm
        )

        # Unpack the blob to get rand_prefix and the HybridSignature payload.
        # The prefix length must match this verifier's hedging mode; see
        # Sign._unpack_sig_blob for why it cannot be read from the blob.
        expected_prefix_len = HEDGED_RANDOMNESS_BYTES if self._hedged else 0
        rand_prefix, hs_bytes = Sign._unpack_sig_blob(signed_message.signature, expected_prefix_len)
        msg_to_verify = rand_prefix + signed_message.message

        # Decode the HybridSignature
        try:
            hs = HybridSignature.from_bytes(hs_bytes)
        except Exception as exc:
            raise VerificationError(algo=self._algorithm) from exc

        # The algorithm names in the payload are not signed; they must name
        # this verifier's own components. (Public data, so an early exit here
        # reveals nothing.)
        if hs.classical_algo != self._classical or hs.pqc_algo != self._pqc:
            raise VerificationError(algo=self._algorithm)

        # Verify BOTH sub-signatures unconditionally before checking results.
        # Early return on classical failure would leak timing information that
        # reveals which sub-key is compromised (an oracle for a quantum attacker
        # who has broken the classical component).
        classical_ok = self._verify_classical(
            classical_pub_bytes,
            msg_to_verify,
            hs.classical_sig,
            signed_message.context,
        )

        pqc_ok = self._backend.verify(
            self._pqc,
            pqc_pub_bytes,
            msg_to_verify,
            hs.pqc_sig,
            signed_message.context,
        )

        if not (classical_ok and pqc_ok):
            raise VerificationError(algo=self._algorithm)

    # ------------------------------------------------------------------
    # Classical signing internals
    # ------------------------------------------------------------------

    def _gen_classical_keypair(self) -> tuple[bytes, bytes]:
        """Generate a classical signing keypair.

        Returns (public_key_bytes, secret_key_bytes): raw 32-byte keys for Ed25519, raw (x, y)
        coordinates and a PKCS8 PEM private key for P-256 and P-384.
        """
        if self._classical == "Ed25519":
            priv = Ed25519PrivateKey.generate()
            pub = priv.public_key()
            priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            return pub_bytes, priv_bytes

        elif self._classical in _EC_SIGNING:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key

            curve_cls, coord, _ = _EC_SIGNING[self._classical]
            ec_priv = generate_private_key(curve_cls(), default_backend())
            ec_pub = ec_priv.public_key()
            priv_bytes = ec_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            # Store public key as raw (x, y): 64 bytes for P-256, 96 for P-384
            pub_nums = ec_pub.public_numbers()
            x_bytes = pub_nums.x.to_bytes(coord, "big")
            y_bytes = pub_nums.y.to_bytes(coord, "big")
            return x_bytes + y_bytes, priv_bytes

        else:
            raise UnsupportedAlgorithm(self._classical, available=["Ed25519", "P-256", "P-384"])

    def _sign_classical(
        self,
        secret_key_bytes: bytes,
        message: bytes,
        context: bytes,
    ) -> bytes:
        """Sign ``len(context) || context || message`` with the classical sub-key."""
        if self._classical == "Ed25519":
            # Ed25519 doesn't support context natively, so we prepend it
            # using a length-prefixed format (same as liboqs backend does for PQC).
            msg_with_ctx = bytes([len(context)]) + context + message
            priv = Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
            return priv.sign(msg_with_ctx)

        elif self._classical in _EC_SIGNING:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric.ec import (
                ECDSA,
                EllipticCurvePrivateKey,
            )
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            _, _, digest_cls = _EC_SIGNING[self._classical]
            msg_with_ctx = bytes([len(context)]) + context + message
            ec_priv = cast(
                EllipticCurvePrivateKey,
                load_pem_private_key(secret_key_bytes, password=None, backend=default_backend()),
            )
            return ec_priv.sign(msg_with_ctx, ECDSA(digest_cls()))

        else:
            raise UnsupportedAlgorithm(self._classical, available=["Ed25519", "P-256", "P-384"])

    def _verify_classical(
        self,
        public_key_bytes: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        """Verify with the classical sub-key over ``len(context) || context || message``.

        Returns False for an invalid signature or a malformed key or signature.
        """
        msg_with_ctx = bytes([len(context)]) + context + message

        if self._classical == "Ed25519":
            try:
                pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                pub.verify(signature, msg_with_ctx)
                return True
            except Exception:  # noqa: BLE001
                return False

        elif self._classical in _EC_SIGNING:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric.ec import (
                ECDSA,
                EllipticCurvePublicNumbers,
            )

            curve_cls, coord, digest_cls = _EC_SIGNING[self._classical]
            try:
                if len(public_key_bytes) != 2 * coord:
                    return False
                x = int.from_bytes(public_key_bytes[:coord], "big")
                y = int.from_bytes(public_key_bytes[coord:], "big")
                ec_pub = EllipticCurvePublicNumbers(x, y, curve_cls()).public_key(default_backend())
                ec_pub.verify(signature, msg_with_ctx, ECDSA(digest_cls()))
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
