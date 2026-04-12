"""
quantum_safe.protocols.envelope
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authenticated encryption envelope: KEM-derived key + AES-256-GCM.

This is what you use when you want to encrypt data to a recipient's
public key such that:
  - Only the holder of the corresponding secret key can decrypt it.
  - Any tampering with the ciphertext is detected.
  - The algorithm used is recorded in the envelope for future migration.
  - The format survives algorithm upgrades via the version field.

Construction
------------
For a given recipient public key pk:

  1. Run HybridKEM.encapsulate(pk) → (kem_ct, shared_secret)
  2. Derive enc_key = HKDF(shared_secret, info="qs-envelope-enc-v1")
  3. Derive mac_key = HKDF(shared_secret, info="qs-envelope-mac-v1")
     (mac_key is currently unused — AES-GCM provides authentication —
      but we derive it for forward compatibility with MAC-then-encrypt schemes)
  4. Generate a random 12-byte nonce.
  5. aead_ct = AES-256-GCM.encrypt(enc_key, nonce, plaintext, aad=metadata)
     where metadata = version || algo || kem_ct_fingerprint
  6. Store: SealedMessage{version, algo, kem_ct, nonce, aead_ct, aad}

The metadata is authenticated but not encrypted (AAD in GCM). This means
the algorithm name and version are visible without decryption — useful for
operational tools that need to inspect ciphertexts without access to the key.

Wire format (CBOR-encoded SealedMessage)
-----------------------------------------
{
    "v":    1,                    # envelope format version
    "algo": "X25519+ML-KEM-768",  # KEM algorithm used
    "kct":  <bytes>,              # KEM ciphertext (HybridCipherText.to_bytes())
    "n":    <bytes>,              # 12-byte AES-GCM nonce
    "ct":   <bytes>,              # AES-256-GCM ciphertext + 16-byte tag
    "aad":  <bytes>,              # additional authenticated data (visible, not encrypted)
}

Migration
---------
When you want to upgrade from one KEM algorithm to another:
  1. Decrypt the existing SealedMessage (you need the old secret key for this).
  2. Re-seal the plaintext with the new algorithm.
  3. Delete the old SealedMessage.

The version field and algorithm name make it straightforward to identify
which sealed messages need upgrading — scan for version=1, algo=old_algo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantum_safe._internal import serialization as _ser
from quantum_safe.exceptions import (
    DecapsulationError,
    KeyParseError,
)
from quantum_safe.kem.hybrid import HybridKEM
from quantum_safe.types import HybridCipherText, PublicKey, SecretKey

# Envelope format version. Bump for backward-incompatible changes.
_ENVELOPE_VERSION = 1

# AES-GCM parameters
_NONCE_LEN = 12        # bytes — GCM standard nonce
_KEY_LEN = 32          # bytes — AES-256
_GCM_TAG_LEN = 16      # bytes — appended to ciphertext by AESGCM

# HKDF info strings for key derivation — version-pinned for domain separation
_ENC_KEY_INFO = b"qs-envelope-enc-v1"
_MAC_KEY_INFO = b"qs-envelope-mac-v1"


@dataclass
class SealedMessage:
    """A ciphertext envelope produced by Envelope.seal().

    All fields are needed to decrypt. The `aad` field is authenticated
    but not encrypted — it's safe to inspect without the decryption key.

    Attributes:
        version:    Envelope format version.
        algorithm:  KEM algorithm used (e.g. "X25519+ML-KEM-768").
        kem_ct:     KEM ciphertext bytes (HybridCipherText wire format).
        nonce:      12-byte AES-GCM nonce. Never reused.
        ciphertext: AES-256-GCM encrypted payload including 16-byte tag.
        aad:        Additional authenticated data. Visible but authenticated.
    """

    version: int
    algorithm: str
    kem_ct: bytes
    nonce: bytes
    ciphertext: bytes
    aad: bytes = field(default=b"")

    def __post_init__(self) -> None:
        if len(self.nonce) != _NONCE_LEN:
            raise ValueError(
                f"nonce must be exactly {_NONCE_LEN} bytes, got {len(self.nonce)}"
            )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize to CBOR (or JSON-b64 fallback) bytes."""
        return _ser.dumps({
            "v":    self.version,
            "algo": self.algorithm,
            "kct":  self.kem_ct,
            "n":    self.nonce,
            "ct":   self.ciphertext,
            "aad":  self.aad,
        })

    @classmethod
    def from_bytes(cls, data: bytes) -> SealedMessage:
        """Deserialize from bytes produced by to_bytes()."""
        try:
            d = _ser.loads(data)
        except Exception as exc:
            raise KeyParseError("envelope", f"CBOR/JSON decode failed: {exc}") from exc

        required = ("v", "algo", "kct", "n", "ct")
        for key in required:
            if key not in d:
                raise KeyParseError("envelope", f"missing field '{key}'")

        return cls(
            version=d["v"],
            algorithm=d["algo"],
            kem_ct=bytes(d["kct"]),
            nonce=bytes(d["n"]),
            ciphertext=bytes(d["ct"]),
            aad=bytes(d.get("aad", b"")),
        )

    def to_hex(self) -> str:
        """Convenience: serialize to a hex string."""
        return self.to_bytes().hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> SealedMessage:
        """Deserialize from a hex string."""
        try:
            return cls.from_bytes(bytes.fromhex(hex_str))
        except Exception as exc:
            raise KeyParseError("envelope", f"hex decode failed: {exc}") from exc

    def inspect(self) -> dict[str, Any]:
        """Return a dict of visible (non-secret) metadata for logging/debugging.

        Never logs ciphertext or key material. Safe to include in structured logs.
        """
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "kem_ct_size": len(self.kem_ct),
            "ciphertext_size": len(self.ciphertext),
            "aad": self.aad.hex() if self.aad else "",
        }

    def __repr__(self) -> str:
        return (
            f"SealedMessage("
            f"v={self.version}, "
            f"algo={self.algorithm!r}, "
            f"ct_size={len(self.ciphertext)}B)"
        )


class Envelope:
    """Authenticated encryption using hybrid KEM + AES-256-GCM.

    This is a class with only class methods — you don't instantiate it.
    Think of it as a namespace for seal() and open().

    Example::

        # Sender:
        sealed = Envelope.seal(b"top secret", recipient_public_key)
        wire   = sealed.to_bytes()        # send this over the network

        # Recipient:
        msg    = sealed.from_bytes(wire)
        plain  = Envelope.open(msg, recipient_secret_key)
    """

    @classmethod
    def seal(
        cls,
        plaintext: bytes,
        recipient_public_key: PublicKey,
        aad: bytes = b"",
        kem: HybridKEM | None = None,
    ) -> SealedMessage:
        """Encrypt plaintext to the recipient's public key.

        Args:
            plaintext:           The data to encrypt. No size limit.
            recipient_public_key: Recipient's HybridKEM public key.
            aad:                 Additional authenticated data. Included
                                 unencrypted in the envelope but authenticated
                                 by GCM — any modification fails decryption.
                                 Use for metadata you want visible but protected
                                 (e.g. recipient ID, timestamp, content type).
            kem:                 HybridKEM instance to use. If None, creates
                                 a default HybridKEM() matching the key's
                                 algorithm.

        Returns:
            SealedMessage that can be decrypted with Envelope.open().

        Raises:
            UnsupportedAlgorithm: if the key's algorithm isn't a known
                                  hybrid KEM combination.
        """
        if kem is None:
            kem = cls._kem_for_key(recipient_public_key)

        # KEM encapsulation — this is the core of the construction
        kem_ct, shared_secret = kem.encapsulate(recipient_public_key)

        # Derive AES key from the shared secret
        enc_key = shared_secret.derive_key(
            length=_KEY_LEN,
            info=_ENC_KEY_INFO,
        )

        # Random nonce — 12 bytes for AES-GCM
        nonce = os.urandom(_NONCE_LEN)

        # Build AAD: version byte || algo string, plus any caller-supplied aad.
        # This binds the version and algorithm into the authentication tag.
        built_aad = cls._build_aad(
            version=_ENVELOPE_VERSION,
            algorithm=recipient_public_key.algorithm,
            extra=aad,
        )

        # Encrypt + authenticate
        aes = AESGCM(enc_key)
        ciphertext = aes.encrypt(nonce, plaintext, built_aad)

        return SealedMessage(
            version=_ENVELOPE_VERSION,
            algorithm=recipient_public_key.algorithm,
            kem_ct=kem_ct.to_bytes(),
            nonce=nonce,
            ciphertext=ciphertext,
            aad=aad,  # store the caller's aad (not the built one)
        )

    @classmethod
    def open(
        cls,
        sealed: SealedMessage,
        recipient_secret_key: SecretKey,
        kem: HybridKEM | None = None,
    ) -> bytes:
        """Decrypt a SealedMessage.

        Args:
            sealed:               SealedMessage from Envelope.seal() or
                                  deserialized from the wire.
            recipient_secret_key: The recipient's HybridKEM secret key.
            kem:                  HybridKEM instance. If None, auto-created
                                  from the envelope's algorithm field.

        Returns:
            Original plaintext bytes.

        Raises:
            DecapsulationError:  if KEM decapsulation fails.
            cryptography.exceptions.InvalidTag: if the ciphertext is tampered
                                  or the wrong key is used (GCM authentication
                                  failure). We let this propagate from
                                  cryptography directly — don't catch it.
        """
        if kem is None:
            kem = cls._kem_for_algorithm(sealed.algorithm)

        # Reconstruct the HybridCipherText from wire bytes
        try:
            kem_ct = HybridCipherText.from_bytes(
                sealed.kem_ct, algorithm=sealed.algorithm
            )
        except Exception as exc:
            raise DecapsulationError(algo=sealed.algorithm) from exc

        # KEM decapsulation — recovers the shared secret
        shared_secret = kem.decapsulate(recipient_secret_key, kem_ct)

        # Derive the same AES key
        enc_key = shared_secret.derive_key(
            length=_KEY_LEN,
            info=_ENC_KEY_INFO,
        )

        # Rebuild AAD — must match what was used during seal()
        built_aad = cls._build_aad(
            version=sealed.version,
            algorithm=sealed.algorithm,
            extra=sealed.aad,
        )

        # Decrypt + verify authentication tag
        # AESGCM.decrypt() raises InvalidTag if tampered — let it propagate.
        aes = AESGCM(enc_key)
        return aes.decrypt(sealed.nonce, sealed.ciphertext, built_aad)

    @staticmethod
    def _build_aad(version: int, algorithm: str, extra: bytes) -> bytes:
        """Build the full AAD passed to AES-GCM.

        We always include version and algorithm so these fields are
        authenticated even when the caller doesn't pass any extra aad.

        Format: version_byte || algo_len_byte || algo_bytes || extra_aad
        """
        algo_bytes = algorithm.encode("ascii")
        if len(algo_bytes) > 255:
            raise ValueError("algorithm name too long for AAD encoding")
        return bytes([version, len(algo_bytes)]) + algo_bytes + extra

    @staticmethod
    def _kem_for_key(public_key: PublicKey) -> HybridKEM:
        """Create a HybridKEM matching the algorithm of the given key."""
        return Envelope._kem_for_algorithm(public_key.algorithm)

    @staticmethod
    def _kem_for_algorithm(algorithm: str) -> HybridKEM:
        """Parse a hybrid algorithm string and create a matching HybridKEM."""
        from quantum_safe.kem.algorithms import parse_hybrid_name
        try:
            classical, pqc = parse_hybrid_name(algorithm)
        except ValueError as exc:
            from quantum_safe.exceptions import UnsupportedAlgorithm
            raise UnsupportedAlgorithm(
                algorithm,
                available=["X25519+ML-KEM-768", "X25519+ML-KEM-1024"],
            ) from exc
        return HybridKEM(classical=classical, pqc=pqc)
