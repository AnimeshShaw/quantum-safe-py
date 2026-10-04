"""Envelope v2: the CNSA 2.0 profile (pure ML-KEM-1024, HKDF-SHA-384, AES-256-GCM).

Same bytes as quantum-safe-ts's envelope v2 (crates/quantum-safe-core
envelope.rs): version 2, algorithm "ML-KEM-1024", the key derived with
HKDF-SHA-384 (no salt) and info ``qs-envelope-enc-v2-cnsa2``, AAD
``2 || len(algo) || algo || extra``. v1 (hybrid KEM, HKDF-SHA-256) is unchanged.
"""

from __future__ import annotations

import dataclasses
import warnings

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from quantum_safe import KEM, HybridKEM
from quantum_safe.exceptions import UnsupportedAlgorithm
from quantum_safe.protocols.envelope import Envelope, SealedMessage
from quantum_safe.types import CipherText, SharedSecret

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module")
def kp():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return KEM("ML-KEM-1024").generate_keypair()


def test_seal_produces_a_v2_envelope(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public, aad=b"ctx")
    assert sealed.version == 2
    assert sealed.algorithm == "ML-KEM-1024"
    assert len(sealed.kem_ct) == 1568  # a raw ML-KEM-1024 ciphertext, no framing
    assert Envelope.open(sealed, kp.secret, expected_aad=b"ctx") == b"payload"


def test_key_derivation_is_hkdf_sha384_with_the_v2_info(kp) -> None:
    """Recompute the AES key from the spec and decrypt by hand."""
    sealed = Envelope.seal(b"payload", kp.public, aad=b"ctx")
    ss = KEM("ML-KEM-1024").decapsulate(kp.secret, CipherText(sealed.kem_ct, "ML-KEM-1024"))
    key = HKDF(
        algorithm=hashes.SHA384(), length=32, salt=None, info=b"qs-envelope-enc-v2-cnsa2"
    ).derive(bytes(ss))
    algo = b"ML-KEM-1024"
    aad = bytes([2, len(algo)]) + algo + b"ctx"
    assert AESGCM(key).decrypt(sealed.nonce, sealed.ciphertext, aad) == b"payload"
    # And it is not the v1 derivation.
    v1_key = ss.derive_key(32, info=b"qs-envelope-enc-v1")
    with pytest.raises(InvalidTag):
        AESGCM(v1_key).decrypt(sealed.nonce, sealed.ciphertext, aad)


def test_derive_key_supports_sha384_and_sha512() -> None:
    ss = SharedSecret(b"\x07" * 32, "ML-KEM-1024")
    for name, algo in (("SHA-384", hashes.SHA384()), ("SHA-512", hashes.SHA512())):
        want = HKDF(algorithm=algo, length=48, salt=None, info=b"i").derive(bytes(ss))
        assert ss.derive_key(48, info=b"i", hash_algorithm=name) == want
    assert ss.derive_key(32, info=b"i") == HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"i"
    ).derive(bytes(ss))
    with pytest.raises(ValueError):
        ss.derive_key(32, hash_algorithm="MD5")


def test_wire_round_trip(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public)
    again = SealedMessage.from_bytes(sealed.to_bytes())
    assert again.version == 2
    assert Envelope.open(again, kp.secret) == b"payload"


def test_v1_hybrid_envelopes_are_unchanged() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        hk = HybridKEM().generate_keypair()
    sealed = Envelope.seal(b"payload", hk.public)
    assert sealed.version == 1
    assert Envelope.open(sealed, hk.secret) == b"payload"


@pytest.mark.parametrize("algo", ["ML-KEM-512", "ML-KEM-768"])
def test_other_pure_kems_are_not_sealable(algo: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        other = KEM(algo).generate_keypair()
    with pytest.raises(UnsupportedAlgorithm):
        Envelope.seal(b"payload", other.public)


def test_a_version_relabelled_envelope_is_refused(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public)
    with pytest.raises(UnsupportedAlgorithm):
        Envelope.open(dataclasses.replace(sealed, version=1), kp.secret)
    with pytest.raises(UnsupportedAlgorithm):
        Envelope.open(dataclasses.replace(sealed, version=3), kp.secret)


def test_a_hybrid_envelope_relabelled_v2_is_refused() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        hk = HybridKEM().generate_keypair()
    sealed = Envelope.seal(b"payload", hk.public)
    with pytest.raises(UnsupportedAlgorithm):
        Envelope.open(dataclasses.replace(sealed, version=2), hk.secret)


def test_tampering_is_detected(kp) -> None:
    sealed = Envelope.seal(b"payload", kp.public, aad=b"a")
    flipped = bytes([sealed.ciphertext[0] ^ 1]) + sealed.ciphertext[1:]
    with pytest.raises(InvalidTag):
        Envelope.open(dataclasses.replace(sealed, ciphertext=flipped), kp.secret, expected_aad=b"a")
    with pytest.raises(InvalidTag):
        Envelope.open(sealed, kp.secret, expected_aad=b"b")


def test_a_key_for_another_algorithm_is_refused(kp) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        hk = HybridKEM().generate_keypair()
    sealed = Envelope.seal(b"payload", kp.public)
    with pytest.raises(UnsupportedAlgorithm):
        Envelope.open(sealed, hk.secret)
