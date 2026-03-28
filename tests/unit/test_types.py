"""
Unit tests for quantum_safe.types

These tests don't require any PQC backend to be installed — they only
test the type system, serialization, and memory safety behaviors.
"""

import gc
import time

import cbor2
import pytest

from quantum_safe.exceptions import (
    IncompatibleKeyVersion,
    KeyParseError,
    UnsupportedFormatError,
    VerificationError,
)
from quantum_safe.types import (
    CipherText,
    HybridCipherText,
    KeyPair,
    KeyType,
    MigrationState,
    PublicKey,
    SecretKey,
    SharedSecret,
    SignedMessage,
    combine_shared_secrets,
    generate_nonce,
)
from quantum_safe.types.keys import _ZeroizingBytes


# ---------------------------------------------------------------------------
# _ZeroizingBytes
# ---------------------------------------------------------------------------


class TestZeroizingBytes:
    def test_round_trip(self):
        b = _ZeroizingBytes(b"hello")
        assert bytes(b) == b"hello"

    def test_length(self):
        b = _ZeroizingBytes(b"hello")
        assert len(b) == 5

    def test_constant_time_eq(self):
        a = _ZeroizingBytes(b"abc")
        b = _ZeroizingBytes(b"abc")
        c = _ZeroizingBytes(b"xyz")
        assert a == b
        assert a != c

    def test_eq_with_plain_bytes(self):
        b = _ZeroizingBytes(b"test")
        assert b == b"test"
        assert b != b"other"

    def test_zeroize_on_del(self):
        raw = bytearray(b"secret key material")
        z = _ZeroizingBytes(bytes(raw))
        # Access the internal buffer before deletion
        internal = z._data
        del z
        gc.collect()
        # After deletion, the buffer should be zeroed
        assert all(x == 0 for x in internal)

    def test_repr_does_not_leak(self):
        z = _ZeroizingBytes(b"secret")
        r = repr(z)
        assert "secret" not in r
        assert "REDACTED" in r or "bytes" in r


# ---------------------------------------------------------------------------
# PublicKey
# ---------------------------------------------------------------------------


class TestPublicKey:
    def _make_key(self, algo="ML-KEM-768", size=1184):
        raw = bytes(range(256)) * (size // 256 + 1)
        raw = raw[:size]
        return PublicKey(raw=raw, algorithm=algo)

    def test_basic_construction(self):
        pk = self._make_key()
        assert pk.algorithm == "ML-KEM-768"
        assert pk.key_type == KeyType.PUBLIC
        assert len(pk.raw_bytes) == 1184

    def test_empty_raw_raises(self):
        with pytest.raises(ValueError, match="empty"):
            PublicKey(raw=b"", algorithm="ML-KEM-768")

    def test_wrong_type_raises(self):
        with pytest.raises(TypeError):
            PublicKey(raw="not bytes", algorithm="ML-KEM-768")  # type: ignore

    def test_fingerprint_deterministic(self):
        pk = self._make_key()
        assert pk.fingerprint() == pk.fingerprint()

    def test_fingerprint_differs_by_algo(self):
        raw = b"\x01" * 800
        pk1 = PublicKey(raw=raw, algorithm="ML-KEM-768")
        pk2 = PublicKey(raw=raw, algorithm="ML-KEM-512")
        # Same bytes, different algorithm — fingerprints must differ
        assert pk1.fingerprint() != pk2.fingerprint()

    def test_fingerprint_colon_format(self):
        pk = self._make_key()
        colon = pk.fingerprint_colon()
        no_colon = pk.fingerprint()
        assert ":" in colon
        assert colon.replace(":", "") == no_colon

    def test_equality(self):
        raw = b"\xab" * 1184
        pk1 = PublicKey(raw=raw, algorithm="ML-KEM-768")
        pk2 = PublicKey(raw=raw, algorithm="ML-KEM-768")
        assert pk1 == pk2

    def test_inequality_different_raw(self):
        pk1 = PublicKey(raw=b"\x00" * 1184, algorithm="ML-KEM-768")
        pk2 = PublicKey(raw=b"\x01" * 1184, algorithm="ML-KEM-768")
        assert pk1 != pk2

    def test_hashable(self):
        pk = self._make_key()
        # Should be usable in a set or as a dict key
        s = {pk}
        assert pk in s

    def test_pem_round_trip(self):
        pk = self._make_key()
        pem = pk.to_pem()
        assert "-----BEGIN QUANTUM SAFE PUBLIC KEY-----" in pem
        assert "qs-version: 1" in pem
        assert "qs-algo: ML-KEM-768" in pem

        pk2 = PublicKey.from_pem(pem)
        assert pk2.algorithm == pk.algorithm
        assert pk2.raw_bytes == pk.raw_bytes

    def test_cbor_round_trip(self):
        pk = self._make_key()
        cbor_data = pk.to_cbor()
        pk2 = PublicKey.from_cbor(cbor_data)
        assert pk2.algorithm == pk.algorithm
        assert pk2.raw_bytes == pk.raw_bytes

    def test_jwk_round_trip(self):
        pk = self._make_key()
        jwk = pk.to_jwk()
        assert jwk["kty"] == "AKP"
        assert jwk["alg"] == "ML-KEM-768"
        assert "pub" in jwk

        pk2 = PublicKey.from_jwk(jwk)
        assert pk2.raw_bytes == pk.raw_bytes

    def test_pem_wrong_label_raises(self):
        # Try loading a secret key PEM as a public key
        sk = SecretKey(raw=b"\x42" * 2400, algorithm="ML-KEM-768")
        sk_pem = sk.to_pem()
        with pytest.raises(KeyParseError):
            PublicKey.from_pem(sk_pem)

    def test_from_pem_bad_base64_raises(self):
        bad_pem = (
            "-----BEGIN QUANTUM SAFE PUBLIC KEY-----\n"
            "qs-version: 1\n"
            "qs-algo: ML-KEM-768\n"
            "\n"
            "!!! not valid base64 !!!\n"
            "-----END QUANTUM SAFE PUBLIC KEY-----\n"
        )
        with pytest.raises(KeyParseError):
            PublicKey.from_pem(bad_pem)

    def test_migration_state_preserved_in_pem(self):
        pk = PublicKey(
            raw=b"\x01" * 1184,
            algorithm="ML-KEM-768",
            migration_state=MigrationState.PQC_ONLY,
        )
        pem = pk.to_pem()
        assert "pqc_only" in pem
        pk2 = PublicKey.from_pem(pem)
        assert pk2.migration_state == MigrationState.PQC_ONLY


# ---------------------------------------------------------------------------
# SecretKey
# ---------------------------------------------------------------------------


class TestSecretKey:
    def test_repr_does_not_leak(self):
        sk = SecretKey(raw=b"\xff" * 2400, algorithm="ML-KEM-768")
        r = repr(sk)
        assert "\xff" not in r
        assert "REDACTED" in r

    def test_not_hashable(self):
        sk = SecretKey(raw=b"\x00" * 2400, algorithm="ML-KEM-768")
        with pytest.raises(TypeError, match="not hashable"):
            hash(sk)

    def test_secret_key_pem_not_loadable_as_public(self):
        sk = SecretKey(raw=b"\x42" * 2400, algorithm="ML-KEM-768")
        pem = sk.to_pem()
        assert "QUANTUM SAFE SECRET KEY" in pem

    def test_jwk_not_supported_for_secret_key(self):
        sk = SecretKey(raw=b"\x00" * 2400, algorithm="ML-KEM-768")
        with pytest.raises(UnsupportedFormatError):
            sk.to_jwk()

    def test_cbor_round_trip(self):
        raw = b"\xde\xad\xbe\xef" * 600
        sk = SecretKey(raw=raw, algorithm="ML-KEM-768")
        cbor_data = sk.to_cbor()
        sk2 = SecretKey.from_cbor(cbor_data)
        assert sk2.algorithm == sk.algorithm
        assert sk2.raw_bytes == sk.raw_bytes

    def test_equality_constant_time(self):
        sk1 = SecretKey(raw=b"\x01" * 2400, algorithm="ML-KEM-768")
        sk2 = SecretKey(raw=b"\x01" * 2400, algorithm="ML-KEM-768")
        sk3 = SecretKey(raw=b"\x02" * 2400, algorithm="ML-KEM-768")
        assert sk1 == sk2
        assert sk1 != sk3


# ---------------------------------------------------------------------------
# KeyPair
# ---------------------------------------------------------------------------


class TestKeyPair:
    def test_algo_mismatch_raises(self):
        pk = PublicKey(raw=b"\x01" * 1184, algorithm="ML-KEM-768")
        sk = SecretKey(raw=b"\x01" * 2400, algorithm="ML-KEM-512")
        with pytest.raises(ValueError, match="does not match"):
            KeyPair(public=pk, secret=sk)

    def test_cbor_bundle_round_trip(self):
        pk = PublicKey(raw=b"\xaa" * 1184, algorithm="ML-KEM-768")
        sk = SecretKey(raw=b"\xbb" * 2400, algorithm="ML-KEM-768")
        kp = KeyPair(public=pk, secret=sk)
        bundle = kp.to_cbor_bundle()
        kp2 = KeyPair.from_cbor_bundle(bundle)
        assert kp2.public.raw_bytes == pk.raw_bytes
        assert kp2.secret.raw_bytes == sk.raw_bytes

    def test_repr_safe(self):
        pk = PublicKey(raw=b"\xaa" * 1184, algorithm="ML-KEM-768")
        sk = SecretKey(raw=b"\xbb" * 2400, algorithm="ML-KEM-768")
        kp = KeyPair(public=pk, secret=sk)
        r = repr(kp)
        assert "ML-KEM-768" in r
        assert "\xbb" not in r


# ---------------------------------------------------------------------------
# CipherText
# ---------------------------------------------------------------------------


class TestCipherText:
    def test_basic(self):
        ct = CipherText(data=b"\x00" * 1088, algorithm="ML-KEM-768")
        assert len(ct) == 1088
        assert bytes(ct) == b"\x00" * 1088

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            CipherText(data=b"", algorithm="ML-KEM-768")

    def test_size_warning_on_mismatch(self):
        # Wrong size for ML-KEM-768 should warn, not raise
        with pytest.warns(UserWarning, match="unexpected size"):
            CipherText(data=b"\x00" * 999, algorithm="ML-KEM-768")


# ---------------------------------------------------------------------------
# HybridCipherText
# ---------------------------------------------------------------------------


class TestHybridCipherText:
    def test_round_trip(self):
        classical = b"\xaa" * 32
        pqc = b"\xbb" * 1088
        hct = HybridCipherText(
            classical_ct=classical,
            pqc_ct=pqc,
            algorithm="X25519+ML-KEM-768",
        )
        wire = hct.to_bytes()
        hct2 = HybridCipherText.from_bytes(wire, algorithm="X25519+ML-KEM-768")
        assert hct2.classical_ct == classical
        assert hct2.pqc_ct == pqc

    def test_truncated_wire_raises(self):
        from quantum_safe.exceptions import DecapsulationError
        with pytest.raises(DecapsulationError):
            HybridCipherText.from_bytes(b"\x00", algorithm="X25519+ML-KEM-768")

    def test_len(self):
        hct = HybridCipherText(b"\x01" * 32, b"\x02" * 1088, "X25519+ML-KEM-768")
        # 2 (prefix) + 32 + 1088
        assert len(hct) == 1122


# ---------------------------------------------------------------------------
# SharedSecret
# ---------------------------------------------------------------------------


class TestSharedSecret:
    def test_must_be_32_bytes(self):
        with pytest.raises(ValueError):
            SharedSecret(data=b"\x00" * 31, algorithm="ML-KEM-768")
        with pytest.raises(ValueError):
            SharedSecret(data=b"\x00" * 33, algorithm="ML-KEM-768")
        # 32 bytes is fine
        SharedSecret(data=b"\x00" * 32, algorithm="ML-KEM-768")

    def test_zeroize_on_del(self):
        ss = SharedSecret(data=b"\xff" * 32, algorithm="ML-KEM-768")
        internal = ss._data
        del ss
        gc.collect()
        assert all(x == 0 for x in internal)

    def test_constant_time_eq(self):
        data = b"\x42" * 32
        ss1 = SharedSecret(data=data, algorithm="ML-KEM-768")
        ss2 = SharedSecret(data=data, algorithm="ML-KEM-768")
        ss3 = SharedSecret(data=b"\x43" * 32, algorithm="ML-KEM-768")
        assert ss1 == ss2
        assert ss1 != ss3

    def test_derive_key(self):
        ss = SharedSecret(data=b"\x01" * 32, algorithm="ML-KEM-768")
        k1 = ss.derive_key(32, info=b"enc")
        k2 = ss.derive_key(32, info=b"mac")
        # Different info → different keys
        assert k1 != k2
        assert len(k1) == 32

    def test_repr_does_not_leak(self):
        ss = SharedSecret(data=b"\xde" * 32, algorithm="ML-KEM-768")
        r = repr(ss)
        assert "\xde" not in r
        assert "REDACTED" in r


# ---------------------------------------------------------------------------
# combine_shared_secrets
# ---------------------------------------------------------------------------


class TestCombineSharedSecrets:
    def test_produces_32_bytes(self):
        combined = combine_shared_secrets(
            classical_ss=b"\x01" * 32,
            pqc_ss=b"\x02" * 32,
            algorithm="X25519+ML-KEM-768",
            classical_ct=b"\x03" * 32,
            pqc_ct=b"\x04" * 1088,
        )
        assert len(combined) == 32
        assert isinstance(combined, SharedSecret)
        assert combined.is_hybrid

    def test_different_inputs_different_outputs(self):
        kwargs = dict(
            pqc_ss=b"\x02" * 32,
            algorithm="X25519+ML-KEM-768",
            classical_ct=b"\x03" * 32,
            pqc_ct=b"\x04" * 1088,
        )
        ss1 = combine_shared_secrets(classical_ss=b"\x01" * 32, **kwargs)
        ss2 = combine_shared_secrets(classical_ss=b"\xFF" * 32, **kwargs)
        assert ss1 != ss2

    def test_deterministic(self):
        kwargs = dict(
            classical_ss=b"\x01" * 32,
            pqc_ss=b"\x02" * 32,
            algorithm="X25519+ML-KEM-768",
            classical_ct=b"\x03" * 32,
            pqc_ct=b"\x04" * 1088,
        )
        ss1 = combine_shared_secrets(**kwargs)
        ss2 = combine_shared_secrets(**kwargs)
        assert ss1 == ss2


# ---------------------------------------------------------------------------
# SignedMessage
# ---------------------------------------------------------------------------


class TestSignedMessage:
    def test_basic(self):
        sm = SignedMessage(
            message=b"hello",
            signature=b"\xab" * 64,
            algorithm="ML-DSA-65",
            context=b"myapp-v1",
        )
        assert sm.message == b"hello"
        assert sm.algorithm == "ML-DSA-65"

    def test_context_too_long_raises(self):
        with pytest.raises(ValueError, match="255"):
            SignedMessage(
                message=b"hello",
                signature=b"\x00" * 64,
                algorithm="ML-DSA-65",
                context=b"x" * 256,
            )

    def test_empty_message_raises(self):
        with pytest.raises(ValueError, match="empty"):
            SignedMessage(
                message=b"",
                signature=b"\x00" * 64,
                algorithm="ML-DSA-65",
            )

    def test_cbor_round_trip(self):
        sm = SignedMessage(
            message=b"test message",
            signature=b"\xcc" * 3293,
            algorithm="ML-DSA-65",
            context=b"unit-test",
            signer_fingerprint="abcdef1234",
        )
        cbor_data = sm.to_cbor()
        sm2 = SignedMessage.from_cbor(cbor_data)
        assert sm2.message == sm.message
        assert sm2.signature == sm.signature
        assert sm2.algorithm == sm.algorithm
        assert sm2.context == sm.context
        assert sm2.signer_fingerprint == sm.signer_fingerprint

    def test_frozen(self):
        sm = SignedMessage(
            message=b"hello",
            signature=b"\x00" * 64,
            algorithm="ML-DSA-65",
        )
        with pytest.raises(Exception):  # frozen dataclass raises FrozenInstanceError
            sm.message = b"tampered"  # type: ignore

    def test_jwt_payload_keys(self):
        sm = SignedMessage(
            message=b"payload",
            signature=b"\x01" * 64,
            algorithm="ML-DSA-65",
            context=b"ctx",
        )
        jwt = sm.to_jwt_payload()
        assert "msg" in jwt
        assert "sig" in jwt
        assert "alg" in jwt
        assert jwt["alg"] == "ML-DSA-65"


# ---------------------------------------------------------------------------
# generate_nonce
# ---------------------------------------------------------------------------


class TestGenerateNonce:
    def test_length(self):
        n = generate_nonce(32)
        assert len(n) == 32

    def test_randomness(self):
        # Two nonces should almost certainly differ
        n1 = generate_nonce(32)
        n2 = generate_nonce(32)
        assert n1 != n2

    def test_zero_length_raises(self):
        with pytest.raises(ValueError):
            generate_nonce(0)

    def test_negative_length_raises(self):
        with pytest.raises(ValueError):
            generate_nonce(-1)
