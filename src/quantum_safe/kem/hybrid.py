"""
quantum_safe.kem.hybrid
~~~~~~~~~~~~~~~~~~~~~~~~

HybridKEM: combines a classical Diffie-Hellman KEM (X25519 or P-256) with
a PQC KEM (ML-KEM) into a single hybrid operation.

The construction is based on draft-ietf-tls-hybrid-design and is exactly
what TLS 1.3 hybrid key exchange uses (the X25519MLKEM768 group in RFC 9001
and the IANA TLS group registry).

Why hybrid?
-----------
During the transition period, we can't be certain that ML-KEM is unbroken.
NIST standardized it, but it's young — a decade-old algorithm with a massive
cryptanalysis community behind it is worth more assurance than mathematical
proofs alone. Hybrid mode means:

  - If ML-KEM is broken but X25519 isn't: the hybrid is still X25519-secure.
  - If X25519 is broken by a quantum computer but ML-KEM isn't: the hybrid
    is still ML-KEM-secure.
  - Both would have to be broken simultaneously for the hybrid to fail.

This is the position taken by NIST, CISA, BSI, NCSC, and every major TLS
library that has added PQC support.

The combiner
------------
Given:
  - X25519 ephemeral keypair: (epk_x, esk_x)
  - ML-KEM keypair: (pk_m, sk_m)

Encapsulate:
  1. Generate ephemeral X25519 keypair (epk_x, esk_x).
  2. Compute X25519 DH: ss_x = X25519(esk_x, pk_x_recipient)
  3. Run ML-KEM encapsulate: (ct_m, ss_m) = MLKEMEncap(pk_m)
  4. Combined ciphertext: ct = len(epk_x) || epk_x || ct_m
     (ephemeral public key replaces a traditional ciphertext for X25519)
  5. Combined secret: ss = HKDF(ikm=ss_x||ss_m, salt=ct_x||ct_m, info=...)

Decapsulate:
  1. Split ct into epk_x and ct_m.
  2. Compute X25519 DH: ss_x = X25519(sk_x, epk_x)
  3. Run ML-KEM decapsulate: ss_m = MLKEMDecap(sk_m, ct_m)
  4. Derive combined secret with same HKDF call.

The public key for a hybrid KEM is (pk_x || pk_m) — both components.
The secret key is (sk_x || sk_m) — both components.

Key format
----------
We store hybrid keys in a length-prefixed format so we can split them
without out-of-band length information:

    2 bytes big-endian: classical_component_len
    N bytes:            classical component (public or secret key)
    remaining bytes:    pqc component

This is the same framing as HybridCipherText.
"""

from __future__ import annotations

import os
import struct
import warnings
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from quantum_safe.backends import get_kem_backend
from quantum_safe.exceptions import (
    DecapsulationError,
    InsecureOperationError,
    UnsupportedAlgorithm,
)
from quantum_safe.kem.algorithms import (
    DEFAULT_HYBRID_CLASSICAL,
    DEFAULT_HYBRID_PQC,
    canonical_hybrid_name,
    validate_hybrid_combination,
)
from quantum_safe.types import (
    HybridCipherText,
    KeyPair,
    MigrationState,
    PublicKey,
    SecretKey,
    SharedSecret,
    combine_shared_secrets,
)

if TYPE_CHECKING:
    from quantum_safe.backends.base import AbstractKEMBackend


# Length prefix format: 2-byte big-endian uint16
_LEN_FMT = ">H"
_LEN_SIZE = 2


def _pack_components(a: bytes, b: bytes) -> bytes:
    """Pack two byte strings with a length prefix on the first."""
    return struct.pack(_LEN_FMT, len(a)) + a + b


def _unpack_components(data: bytes, context: str = "") -> tuple[bytes, bytes]:
    """Unpack two byte strings packed by _pack_components."""
    if len(data) < _LEN_SIZE:
        raise DecapsulationError(algo=context)
    (a_len,) = struct.unpack_from(_LEN_FMT, data, 0)
    if len(data) < _LEN_SIZE + a_len:
        raise DecapsulationError(algo=context)
    a = data[_LEN_SIZE: _LEN_SIZE + a_len]
    b = data[_LEN_SIZE + a_len:]
    return a, b


class HybridKEM:
    """Hybrid KEM: classical Diffie-Hellman + post-quantum KEM.

    Default configuration: X25519 + ML-KEM-768. This matches the TLS 1.3
    hybrid group X25519MLKEM768 and is recommended by all major standards
    bodies for the current transition period.

    Args:
        classical:      Classical KEM algorithm. Currently "X25519" or "P-256".
                        Default: "X25519".
        pqc:            PQC KEM algorithm. Default: "ML-KEM-768".
        backend:        Backend for PQC operations: "auto", "liboqs",
                        "rustcrypto". Default: "auto".
        validate:       If True (default), validate that the classical+pqc
                        combination is an approved hybrid. Set False only
                        if you're testing a non-standard combination.

    Example::

        from quantum_safe import HybridKEM

        kem = HybridKEM()                      # X25519 + ML-KEM-768
        kp  = kem.generate_keypair()
        ct, ss = kem.encapsulate(kp.public)
        ss2    = kem.decapsulate(kp.secret, ct)
        assert ss == ss2
    """

    def __init__(
        self,
        classical: str = DEFAULT_HYBRID_CLASSICAL,
        pqc: str = DEFAULT_HYBRID_PQC,
        backend: str = "auto",
        validate: bool = True,
    ) -> None:
        if validate:
            validate_hybrid_combination(classical, pqc)

        self._classical = classical
        self._pqc = pqc
        self._algorithm = canonical_hybrid_name(classical, pqc)
        self._backend: AbstractKEMBackend = get_kem_backend(backend)

        # Pre-validate that the backend supports the PQC algorithm
        supported = {a.name for a in self._backend.supported_algorithms()}
        if pqc not in supported and self._backend.is_available():
            raise UnsupportedAlgorithm(pqc, available=list(supported))

    @property
    def algorithm(self) -> str:
        """Full hybrid algorithm string, e.g. 'X25519+ML-KEM-768'."""
        return self._algorithm

    @property
    def classical_algorithm(self) -> str:
        return self._classical

    @property
    def pqc_algorithm(self) -> str:
        return self._pqc

    @property
    def backend_name(self) -> str:
        return self._backend.name

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keypair(self) -> KeyPair:
        """Generate a hybrid key pair.

        The public key contains both the X25519 public key and the ML-KEM
        public key, packed with a length prefix. The secret key is similarly
        structured.

        The migration_state is set to HYBRID_TRANSITION by default — this
        key participates in the current hybrid deployment.

        Returns:
            KeyPair where both .public and .secret contain hybrid key material.
        """
        # Generate classical component
        classical_priv, classical_pub = self._gen_classical_keypair()

        # Generate PQC component via backend
        pqc_pub_bytes, pqc_sec_bytes = self._backend.keygen(self._pqc)

        # Pack: length-prefix classical, append PQC
        combined_pub = _pack_components(classical_pub, pqc_pub_bytes)
        combined_sec = _pack_components(classical_priv, pqc_sec_bytes)

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
    # Encapsulate
    # ------------------------------------------------------------------

    def encapsulate(self, public_key: PublicKey) -> tuple[HybridCipherText, SharedSecret]:
        """Encapsulate a shared secret under the recipient's hybrid public key.

        Args:
            public_key: The recipient's HybridKEM public key.

        Returns:
            (ct, ss): HybridCipherText to send to the recipient, SharedSecret
                      for the sender's use.

        Note:
            The HybridCipherText.to_bytes() gives you the wire-format bytes
            to transmit. The SharedSecret is 32 bytes of combined key material
            derived from both the classical and PQC exchanges.
        """
        if public_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                public_key.algorithm,
                available=[self._algorithm],
            )

        # Split the recipient's combined public key
        classical_pub_bytes, pqc_pub_bytes = _unpack_components(
            public_key.raw_bytes, context=self._algorithm
        )

        # --- Classical half ---
        classical_ct, classical_ss = self._encapsulate_classical(classical_pub_bytes)

        # --- PQC half ---
        pqc_ct_bytes, pqc_ss_bytes = self._backend.encapsulate(
            self._pqc, pqc_pub_bytes
        )

        # --- Combine ---
        hct = HybridCipherText(
            classical_ct=classical_ct,
            pqc_ct=pqc_ct_bytes,
            algorithm=self._algorithm,
        )

        combined_ss = combine_shared_secrets(
            classical_ss=classical_ss,
            pqc_ss=pqc_ss_bytes[:32],
            algorithm=self._algorithm,
            classical_ct=classical_ct,
            pqc_ct=pqc_ct_bytes,
        )

        return hct, combined_ss

    # ------------------------------------------------------------------
    # Decapsulate
    # ------------------------------------------------------------------

    def decapsulate(
        self, secret_key: SecretKey, ciphertext: HybridCipherText
    ) -> SharedSecret:
        """Decapsulate: recover the shared secret from a hybrid ciphertext.

        Args:
            secret_key: The recipient's HybridKEM secret key.
            ciphertext: HybridCipherText from the sender.

        Returns:
            SharedSecret matching the sender's.

        Raises:
            DecapsulationError: on structural failures. Note that ML-KEM
                uses implicit rejection, so a bad ML-KEM ciphertext returns
                a pseudorandom value rather than failing — this is by design.
        """
        if secret_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                secret_key.algorithm,
                available=[self._algorithm],
            )

        # Split secret key into classical + PQC components
        classical_sec_bytes, pqc_sec_bytes = _unpack_components(
            secret_key.raw_bytes, context=self._algorithm
        )

        # --- Classical half ---
        classical_ss = self._decapsulate_classical(
            classical_sec_bytes, ciphertext.classical_ct
        )

        # --- PQC half ---
        pqc_ss_bytes = self._backend.decapsulate(
            self._pqc, pqc_sec_bytes, ciphertext.pqc_ct
        )

        # --- Combine (same construction as encapsulate) ---
        return combine_shared_secrets(
            classical_ss=classical_ss,
            pqc_ss=pqc_ss_bytes[:32],
            algorithm=self._algorithm,
            classical_ct=ciphertext.classical_ct,
            pqc_ct=ciphertext.pqc_ct,
        )

    # ------------------------------------------------------------------
    # Classical KEM internals
    # ------------------------------------------------------------------

    def _gen_classical_keypair(self) -> tuple[bytes, bytes]:
        """Generate classical ephemeral key material.

        Returns (private_bytes, public_bytes).

        We generate a fresh ephemeral key for every key pair. In the context
        of hybrid KEM, the classical component functions as a long-term key
        (unlike in DH-based protocols where it would be ephemeral per session).
        The caller decides the key lifecycle.
        """
        if self._classical == "X25519":
            priv = X25519PrivateKey.generate()
            pub = priv.public_key()
            priv_bytes = priv.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
            pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            return priv_bytes, pub_bytes
        elif self._classical == "P-256":
            from cryptography.hazmat.primitives.asymmetric.ec import (
                SECP256R1,
                generate_private_key,
                ECDH,
            )
            from cryptography.hazmat.backends import default_backend
            priv = generate_private_key(SECP256R1(), default_backend())
            pub = priv.public_key()
            priv_bytes = priv.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            pub_bytes = pub.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            return priv_bytes, pub_bytes
        else:
            raise UnsupportedAlgorithm(
                self._classical,
                available=["X25519", "P-256"],
            )

    def _encapsulate_classical(
        self, recipient_pub_bytes: bytes
    ) -> tuple[bytes, bytes]:
        """Perform classical key encapsulation.

        For X25519, encapsulation = generate ephemeral keypair, compute DH.
        The 'ciphertext' is the ephemeral public key.

        Returns (classical_ct_bytes, shared_secret_bytes).
        """
        if self._classical == "X25519":
            # Generate an ephemeral X25519 keypair
            ephem_priv = X25519PrivateKey.generate()
            ephem_pub = ephem_priv.public_key()

            # Load recipient's X25519 public key
            recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_bytes)

            # DH exchange
            shared = ephem_priv.exchange(recipient_pub)

            # The "ciphertext" is the ephemeral public key
            ct = ephem_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            return ct, shared

        elif self._classical == "P-256":
            from cryptography.hazmat.primitives.asymmetric.ec import (
                SECP256R1,
                generate_private_key,
                EllipticCurvePublicKey,
                ECDH,
            )
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers,
            )
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.primitives.asymmetric.ec import (
                from_encoded_point, EllipticCurvePublicKey
            )

            ephem_priv = generate_private_key(SECP256R1(), default_backend())
            ephem_pub = ephem_priv.public_key()

            # Load recipient's public key from uncompressed point
            # cryptography doesn't have a direct from_encoded_point in all versions
            # so we use the longer form
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers,
            )
            if len(recipient_pub_bytes) != 65 or recipient_pub_bytes[0] != 0x04:
                raise DecapsulationError(algo=self._classical)
            x = int.from_bytes(recipient_pub_bytes[1:33], "big")
            y = int.from_bytes(recipient_pub_bytes[33:65], "big")
            recipient_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(
                default_backend()
            )

            shared_key = ephem_priv.exchange(ECDH(), recipient_pub)
            ct = ephem_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            return ct, shared_key[:32]
        else:
            raise UnsupportedAlgorithm(self._classical, available=["X25519", "P-256"])

    def _decapsulate_classical(
        self, secret_key_bytes: bytes, ciphertext_bytes: bytes
    ) -> bytes:
        """Recover the classical shared secret.

        For X25519, the ciphertext is the sender's ephemeral public key.
        We compute DH(our_secret_key, sender_ephemeral_pub).

        Returns shared_secret_bytes.
        """
        if self._classical == "X25519":
            try:
                # Load our static secret key
                our_priv = X25519PrivateKey.from_private_bytes(secret_key_bytes)
                # Load sender's ephemeral public key (the "ciphertext")
                sender_ephem_pub = X25519PublicKey.from_public_bytes(ciphertext_bytes)
                return our_priv.exchange(sender_ephem_pub)
            except Exception as exc:
                raise DecapsulationError(algo=self._algorithm) from exc

        elif self._classical == "P-256":
            try:
                from cryptography.hazmat.primitives.asymmetric.ec import (
                    SECP256R1,
                    EllipticCurvePublicNumbers,
                    ECDH,
                )
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.serialization import load_pem_private_key

                our_priv = load_pem_private_key(secret_key_bytes, password=None,
                                                backend=default_backend())
                if len(ciphertext_bytes) != 65 or ciphertext_bytes[0] != 0x04:
                    raise DecapsulationError(algo=self._algorithm)
                x = int.from_bytes(ciphertext_bytes[1:33], "big")
                y = int.from_bytes(ciphertext_bytes[33:65], "big")
                sender_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(
                    default_backend()
                )
                shared = our_priv.exchange(ECDH(), sender_pub)
                return shared[:32]
            except DecapsulationError:
                raise
            except Exception as exc:
                raise DecapsulationError(algo=self._algorithm) from exc
        else:
            raise UnsupportedAlgorithm(self._classical, available=["X25519", "P-256"])

    def __repr__(self) -> str:
        return (
            f"HybridKEM("
            f"classical={self._classical!r}, "
            f"pqc={self._pqc!r}, "
            f"backend={self._backend.name!r})"
        )
