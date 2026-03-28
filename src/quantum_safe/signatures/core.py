"""
quantum_safe.signatures.core
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Sign class: single-algorithm PQC digital signatures.

Like KEM vs HybridKEM, most production callers should use HybridSign.
Sign is for benchmarking, protocol conformance testing, and cases where
you specifically need a single PQC algorithm.

Hedged signing
--------------
By default, Sign operates in hedged mode: before hashing the message, we
prepend 32 random bytes:

    actual_message = rand_32 || message

The signature is over this extended message. The rand_32 is stored in the
SignedMessage so the verifier knows to prepend them before verifying.

Why? Deterministic signing (sign the message directly) is vulnerable to
fault injection attacks where an adversary induces a hardware error during
the signing computation and recovers the secret key from the faulty output.
Hedged signing prevents this because the attacker can't control the random
prefix. It also provides an additional layer against nonce reuse (though
ML-DSA doesn't use a nonce the way ECDSA does, the principle applies).

The cost: 32 extra bytes in the SignedMessage. The benefit: resistance
against a whole class of side-channel and fault attacks that have been
demonstrated on lattice signatures in lab conditions.

Context strings
---------------
FIPS 204 §5.2 defines a context parameter (up to 255 bytes) that is
mixed into the signing hash. We use it for domain separation:

    signature = ML-DSA.Sign(sk, message, context)

This prevents cross-protocol attacks where a signature from one application
is replayed as valid in another. Always pass a context that uniquely
identifies your application and protocol version:

    sign(message, secret_key, context=b"myapp-v1-document-signing")
"""

from __future__ import annotations

import os
import time
import warnings
from typing import TYPE_CHECKING

from quantum_safe.backends import get_signature_backend
from quantum_safe.exceptions import InsecureOperationError, UnsupportedAlgorithm, VerificationError
from quantum_safe.signatures.algorithms import (
    HEDGED_RANDOMNESS_BYTES,
    get_algorithm_spec,
)
from quantum_safe.types import KeyPair, MigrationState, PublicKey, SecretKey
from quantum_safe.types.signatures import SignedMessage

if TYPE_CHECKING:
    from quantum_safe.backends.base import AbstractSignatureBackend


class Sign:
    """Single-algorithm PQC signature scheme.

    Args:
        algorithm:  PQC signature algorithm. Defaults to ML-DSA-65.
        backend:    Backend name: "auto", "liboqs", "rustcrypto".
        hedged:     If True (default), prepend 32 random bytes before signing
                    to prevent fault injection attacks.
        strict:     If True, raise instead of warn for non-standard configs.

    Example::

        from quantum_safe.signatures import Sign

        signer = Sign()                    # ML-DSA-65, hedged
        kp     = signer.generate_keypair()
        sm     = signer.sign(b"hello", kp.secret, context=b"myapp-v1")
        signer.verify(sm, kp.public)       # raises VerificationError if invalid
    """

    def __init__(
        self,
        algorithm: str = "ML-DSA-65",
        backend: str = "auto",
        hedged: bool = True,
        strict: bool = False,
    ) -> None:
        self._algorithm = algorithm
        self._hedged = hedged
        self._strict = strict
        self._spec = get_algorithm_spec(algorithm)
        self._backend: AbstractSignatureBackend = get_signature_backend(backend)

        if not self._spec.is_nist_standard:
            msg = (
                f"Algorithm '{algorithm}' is not NIST-standardized. "
                "It may not be suitable for production."
            )
            if strict:
                raise InsecureOperationError(msg, algorithm=algorithm)
            warnings.warn(msg, stacklevel=2)

    @property
    def algorithm(self) -> str:
        return self._algorithm

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
        """Generate a signing key pair.

        Returns:
            KeyPair with .public and .secret. The secret key is needed to
            sign; the public key is needed to verify.
        """
        pub_bytes, sec_bytes = self._backend.keygen(self._algorithm)
        pub = PublicKey(
            raw=pub_bytes,
            algorithm=self._algorithm,
            migration_state=MigrationState.PQC_ONLY,
            backend_tag=self._backend.name,
        )
        sec = SecretKey(
            raw=sec_bytes,
            algorithm=self._algorithm,
            migration_state=MigrationState.PQC_ONLY,
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
        """Sign a message.

        Args:
            message:    Arbitrary bytes to sign. There is no length limit,
                        but for very large messages (> a few MB) consider
                        signing a hash of the message instead.
            secret_key: The signer's secret key, matching this algorithm.
            context:    Domain-separation context. Up to 255 bytes.
                        Should include your app name and protocol version.
                        Example: b"myapp-v2-user-attestation"

        Returns:
            SignedMessage containing the message, signature, algorithm,
            context, signer fingerprint, and timestamp. The SignedMessage
            is self-contained — pass it to verify() directly.

        Raises:
            UnsupportedAlgorithm: if the key's algorithm doesn't match.
        """
        if secret_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                secret_key.algorithm,
                available=[self._algorithm],
            )
        if len(context) > 255:
            raise ValueError(f"context must be ≤255 bytes, got {len(context)}")

        # Hedged mode: prepend random bytes so two signings of the same message
        # with the same key produce different signatures AND resist fault attacks.
        if self._hedged:
            rand_prefix = os.urandom(HEDGED_RANDOMNESS_BYTES)
            msg_to_sign = rand_prefix + message
        else:
            rand_prefix = b""
            msg_to_sign = message

        raw_sig = self._backend.sign(
            self._algorithm,
            secret_key.raw_bytes,
            msg_to_sign,
            context,
        )

        # The stored signature blob: rand_prefix_len (1B) || rand_prefix || raw_sig
        # This lets verify() reconstruct msg_to_sign without out-of-band info.
        sig_blob = self._pack_sig_blob(rand_prefix, raw_sig)

        # We compute the signer fingerprint from the *public* key side, but we
        # only have the secret key here. We store an empty fingerprint and let
        # the caller fill it in if they want. HybridSign overrides this.
        return SignedMessage(
            message=message,
            signature=sig_blob,
            algorithm=self._algorithm,
            context=context,
            signer_fingerprint="",
            signed_at=time.time(),
            is_hybrid=False,
        )

    def sign_with_fingerprint(
        self,
        message: bytes,
        keypair: KeyPair,
        context: bytes = b"",
    ) -> SignedMessage:
        """Like sign(), but also stores the signer's public key fingerprint.

        Use this when the verifier won't have the public key in advance and
        needs to look it up from a key store by fingerprint.
        """
        sm = self.sign(message, keypair.secret, context)
        # We can't use dataclass._replace directly on a frozen dataclass field
        # assignment, so reconstruct with the fingerprint filled in.
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
        """Verify a signed message.

        Args:
            signed_message: A SignedMessage returned by sign().
            public_key:     The signer's public key.

        Returns:
            None on success.

        Raises:
            VerificationError: if the signature is invalid, the algorithm
                doesn't match, or the context doesn't match.
            UnsupportedAlgorithm: if the SignedMessage's algorithm differs
                from this Sign instance's algorithm.
        """
        if signed_message.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                signed_message.algorithm,
                available=[self._algorithm],
            )
        if public_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                public_key.algorithm,
                available=[self._algorithm],
            )

        rand_prefix, raw_sig = self._unpack_sig_blob(signed_message.signature)
        msg_to_verify = rand_prefix + signed_message.message

        ok = self._backend.verify(
            self._algorithm,
            public_key.raw_bytes,
            msg_to_verify,
            raw_sig,
            signed_message.context,
        )

        if not ok:
            raise VerificationError(algo=self._algorithm)

    def verify_bytes(
        self,
        message: bytes,
        signature_blob: bytes,
        public_key: PublicKey,
        context: bytes = b"",
    ) -> None:
        """Verify a raw signature blob (for interop with external signers).

        Use this when the signature was produced outside this library and
        you have raw bytes rather than a SignedMessage. The blob must
        be in our packed format (rand_prefix_len || rand_prefix || raw_sig).

        For fully external signatures (produced by liboqs directly or another
        tool), use verify_raw() instead.
        """
        rand_prefix, raw_sig = self._unpack_sig_blob(signature_blob)
        msg_to_verify = rand_prefix + message
        ok = self._backend.verify(
            self._algorithm,
            public_key.raw_bytes,
            msg_to_verify,
            raw_sig,
            context,
        )
        if not ok:
            raise VerificationError(algo=self._algorithm)

    def verify_raw(
        self,
        message: bytes,
        raw_signature: bytes,
        public_key: PublicKey,
        context: bytes = b"",
    ) -> None:
        """Verify a raw signature produced outside this library.

        Use this for interoperability with other ML-DSA implementations.
        Note: hedged mode doesn't apply here — you're verifying a raw
        (non-hedged) signature.
        """
        ok = self._backend.verify(
            self._algorithm,
            public_key.raw_bytes,
            message,
            raw_signature,
            context,
        )
        if not ok:
            raise VerificationError(algo=self._algorithm)

    # ------------------------------------------------------------------
    # Internal: signature blob packing
    # ------------------------------------------------------------------

    @staticmethod
    def _pack_sig_blob(rand_prefix: bytes, raw_sig: bytes) -> bytes:
        """Pack rand_prefix + raw_sig into a single blob.

        Format: prefix_len (1 byte) || rand_prefix || raw_sig

        prefix_len is 0 for non-hedged signatures, 32 for hedged.
        """
        if len(rand_prefix) > 255:
            raise ValueError("rand_prefix too long")
        return bytes([len(rand_prefix)]) + rand_prefix + raw_sig

    @staticmethod
    def _unpack_sig_blob(blob: bytes) -> tuple[bytes, bytes]:
        """Unpack a signature blob into (rand_prefix, raw_sig)."""
        if len(blob) < 1:
            raise VerificationError()
        prefix_len = blob[0]
        if len(blob) < 1 + prefix_len:
            raise VerificationError()
        rand_prefix = blob[1: 1 + prefix_len]
        raw_sig = blob[1 + prefix_len:]
        return rand_prefix, raw_sig

    def __repr__(self) -> str:
        return (
            f"Sign(algo={self._algorithm!r}, "
            f"hedged={self._hedged}, "
            f"backend={self._backend.name!r})"
        )
