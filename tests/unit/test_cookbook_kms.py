"""The cookbook's "secret keys wrapped by a KMS" recipe, run as written (with its in-memory stand-in)."""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantum_safe import HybridKEM
from quantum_safe.protocols.envelope import Envelope
from quantum_safe.types import SecretKey

pytestmark = pytest.mark.requires_liboqs


class Kms:
    """Stands in for your KMS client. AWS KMS, GCP KMS and Vault transit all offer these two calls."""

    def __init__(self) -> None:
        self._master = AESGCM.generate_key(bit_length=256)

    def generate_data_key(self, context: bytes) -> tuple[bytes, bytes]:
        plain, nonce = os.urandom(32), os.urandom(12)
        return plain, nonce + AESGCM(self._master).encrypt(nonce, plain, context)

    def decrypt(self, wrapped: bytes, context: bytes) -> bytes:
        return AESGCM(self._master).decrypt(wrapped[:12], wrapped[12:], context)


def wrap_secret_key(kms: Kms, secret: SecretKey, name: str) -> bytes:
    context = name.encode()
    data_key, wrapped_key = kms.generate_data_key(context)
    nonce = os.urandom(12)
    sealed = AESGCM(data_key).encrypt(nonce, secret.to_cbor(), context)
    return len(wrapped_key).to_bytes(2, "big") + wrapped_key + nonce + sealed


def unwrap_secret_key(kms: Kms, stored: bytes, name: str) -> SecretKey:
    context = name.encode()
    n = int.from_bytes(stored[:2], "big")
    wrapped_key, nonce, sealed = stored[2 : 2 + n], stored[2 + n : 14 + n], stored[14 + n :]
    data_key = kms.decrypt(wrapped_key, context)
    return SecretKey.from_cbor(AESGCM(data_key).decrypt(nonce, sealed, context))


def test_a_wrapped_key_round_trips_and_is_bound_to_its_name() -> None:
    kms = Kms()
    pair = HybridKEM().generate_keypair()
    stored = wrap_secret_key(kms, pair.secret, "orders-service/recipient-key")
    secret = unwrap_secret_key(kms, stored, "orders-service/recipient-key")
    sealed = Envelope.seal(b"order 1001", pair.public, aad=b"orders")
    assert Envelope.open(sealed, secret, expected_aad=b"orders") == b"order 1001"
    with pytest.raises(InvalidTag):
        unwrap_secret_key(kms, stored, "billing-service/recipient-key")
    assert pair.secret.to_cbor() not in stored
