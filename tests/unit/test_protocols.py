"""
Unit tests for quantum_safe.protocols

All tests use mock backends or real classical crypto. PQC-dependent paths
are marked requires_liboqs.

The Envelope tests use a full mock HybridKEM so we can exercise the full
seal/open cycle without a PQC backend. The JWT tests use Ed25519 signing
(which is classical but exercises the full signer/verifier code path).
"""

from __future__ import annotations

import json
import os
import ssl
import time

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

from quantum_safe.exceptions import (
    DecapsulationError,
    KeyParseError,
    UnsupportedAlgorithm,
    VerificationError,
)
from quantum_safe.protocols.envelope import (
    Envelope,
    SealedMessage,
    _ENVELOPE_VERSION,
    _NONCE_LEN,
)
from quantum_safe.protocols.jwt import (
    JWTSigner,
    JWTVerifier,
    _b64url_encode,
    _b64url_decode,
    _json_b64,
)
from quantum_safe.protocols.tls import (
    HybridTLSConfig,
    check_hybrid_support,
    configure_hybrid_context,
    get_hybrid_group_name,
)
from quantum_safe.protocols.x509 import (
    HybridCertificateBuilder,
    generate_classical_keypair_for_cert,
)
from quantum_safe.backends.base import AbstractKEMBackend, AbstractSignatureBackend
from quantum_safe.signatures.hybrid import HybridSign
from quantum_safe.signatures.core import Sign
from quantum_safe.types import (
    HybridCipherText,
    KeyPair,
    MigrationState,
    PublicKey,
    SecretKey,
    SharedSecret,
)
from quantum_safe.kem.hybrid import HybridKEM


# ---------------------------------------------------------------------------
# Minimal mock HybridKEM for envelope testing — real X25519, mock ML-KEM
# ---------------------------------------------------------------------------


class MockPQCBackend(AbstractKEMBackend):
    """Fake PQC KEM for envelope/JWT tests."""
    name = "mock"
    def keygen(self, a):    return b"\xAA" * 1184, b"\xBB" * 2400
    def encapsulate(self, a, pub): return b"\xCC" * 1088, b"\xDD" * 32
    def decapsulate(self, a, sec, ct): return b"\xDD" * 32
    def is_available(self): return True
    def supported_algorithms(self): return []


class MockSigBackend(AbstractSignatureBackend):
    """Fake PQC signature backend for JWT/x509 tests."""
    name = "mock"
    def keygen(self, a):    return b"\xAA" * 1952, b"\xBB" * 4000
    def sign(self, a, sk, msg, ctx=b""):   return b"\xCC" * 3293
    def verify(self, a, pk, msg, sig, ctx=b""): return len(sig) == 3293
    def is_available(self): return True
    def supported_algorithms(self): return []


def make_hybrid_kem() -> HybridKEM:
    kem = HybridKEM.__new__(HybridKEM)
    kem._classical = "X25519"
    kem._pqc = "ML-KEM-768"
    kem._algorithm = "X25519+ML-KEM-768"
    kem._backend = MockPQCBackend()
    return kem


def make_hybrid_sign() -> HybridSign:
    hs = HybridSign.__new__(HybridSign)
    hs._classical = "Ed25519"
    hs._pqc = "ML-DSA-65"
    hs._algorithm = "Ed25519+ML-DSA-65"
    hs._hedged = True
    hs._backend = MockSigBackend()
    return hs


# ---------------------------------------------------------------------------
# SealedMessage serialization
# ---------------------------------------------------------------------------


class TestSealedMessageSerialization:
    def _make_sealed(self, algo="X25519+ML-KEM-768") -> SealedMessage:
        return SealedMessage(
            version=1,
            algorithm=algo,
            kem_ct=b"\xAA" * 64,
            nonce=os.urandom(_NONCE_LEN),
            ciphertext=b"\xBB" * 48,
            aad=b"metadata",
        )

    def test_round_trip_bytes(self):
        sm = self._make_sealed()
        data = sm.to_bytes()
        sm2 = SealedMessage.from_bytes(data)
        assert sm2.version == sm.version
        assert sm2.algorithm == sm.algorithm
        assert sm2.kem_ct == sm.kem_ct
        assert sm2.nonce == sm.nonce
        assert sm2.ciphertext == sm.ciphertext
        assert sm2.aad == sm.aad

    def test_round_trip_hex(self):
        sm = self._make_sealed()
        hex_str = sm.to_hex()
        assert isinstance(hex_str, str)
        sm2 = SealedMessage.from_hex(hex_str)
        assert sm2.algorithm == sm.algorithm
        assert sm2.ciphertext == sm.ciphertext

    def test_from_bytes_missing_field_raises(self):
        import json
        # Manually craft a broken envelope
        broken = {"v": 1, "algo": "X25519+ML-KEM-768"}
        # Encode without required fields
        from quantum_safe._internal import serialization as _ser
        data = _ser.dumps(broken)
        with pytest.raises(KeyParseError, match="missing field"):
            SealedMessage.from_bytes(data)

    def test_nonce_wrong_length_raises(self):
        with pytest.raises(ValueError, match="nonce"):
            SealedMessage(
                version=1, algorithm="X25519+ML-KEM-768",
                kem_ct=b"\x00" * 64,
                nonce=b"\x00" * 11,  # wrong: should be 12
                ciphertext=b"\x00" * 48,
            )

    def test_inspect_contains_no_secrets(self):
        sm = self._make_sealed()
        info = sm.inspect()
        # Should have metadata but not raw ciphertext
        assert "algorithm" in info
        assert info["kem_ct_size"] == 64
        assert "ciphertext" not in info
        assert isinstance(info["ciphertext_size"], int)

    def test_repr_safe(self):
        sm = self._make_sealed()
        r = repr(sm)
        assert "X25519+ML-KEM-768" in r
        assert "\xBB" not in r


# ---------------------------------------------------------------------------
# Envelope AAD builder
# ---------------------------------------------------------------------------


class TestEnvelopeAAD:
    def test_aad_includes_version_and_algo(self):
        aad = Envelope._build_aad(1, "X25519+ML-KEM-768", b"")
        assert aad[0] == 1  # version byte
        algo_len = aad[1]
        algo_bytes = aad[2: 2 + algo_len]
        assert algo_bytes == b"X25519+ML-KEM-768"

    def test_aad_includes_extra(self):
        extra = b"recipient-id-abc"
        aad = Envelope._build_aad(1, "X25519+ML-KEM-768", extra)
        assert aad.endswith(extra)

    def test_different_versions_different_aad(self):
        aad1 = Envelope._build_aad(1, "X25519+ML-KEM-768", b"")
        aad2 = Envelope._build_aad(2, "X25519+ML-KEM-768", b"")
        assert aad1 != aad2

    def test_different_algos_different_aad(self):
        aad1 = Envelope._build_aad(1, "X25519+ML-KEM-768", b"")
        aad2 = Envelope._build_aad(1, "X25519+ML-KEM-1024", b"")
        assert aad1 != aad2


# ---------------------------------------------------------------------------
# Envelope seal/open — using mock KEM (no liboqs needed)
# ---------------------------------------------------------------------------


class TestEnvelopeSealOpen:
    def test_full_round_trip(self):
        kem = make_hybrid_kem()
        kp = kem.generate_keypair()

        plaintext = b"top secret payload"
        sealed = Envelope.seal(plaintext, kp.public, kem=kem)
        recovered = Envelope.open(sealed, kp.secret, kem=kem)
        assert recovered == plaintext

    def test_different_plaintexts(self):
        kem = make_hybrid_kem()
        kp = kem.generate_keypair()
        for msg in [b"", b"x", b"\x00" * 1000, b"unicode \xf0\x9f\x94\x90"]:
            sealed = Envelope.seal(msg, kp.public, kem=kem)
            assert Envelope.open(sealed, kp.secret, kem=kem) == msg

    def test_aad_authenticated(self):
        """Modifying aad should cause decryption to fail."""
        from cryptography.exceptions import InvalidTag
        kem = make_hybrid_kem()
        kp = kem.generate_keypair()

        sealed = Envelope.seal(b"secret", kp.public, aad=b"legit", kem=kem)
        # Tamper with aad
        tampered = SealedMessage(
            version=sealed.version,
            algorithm=sealed.algorithm,
            kem_ct=sealed.kem_ct,
            nonce=sealed.nonce,
            ciphertext=sealed.ciphertext,
            aad=b"tampered",   # different aad
        )
        with pytest.raises(InvalidTag):
            Envelope.open(tampered, kp.secret, kem=kem)

    def test_tampered_ciphertext_fails(self):
        from cryptography.exceptions import InvalidTag
        kem = make_hybrid_kem()
        kp = kem.generate_keypair()

        sealed = Envelope.seal(b"secret data", kp.public, kem=kem)
        # Flip a byte in the ciphertext
        ct_list = bytearray(sealed.ciphertext)
        ct_list[0] ^= 0xFF
        tampered = SealedMessage(
            version=sealed.version,
            algorithm=sealed.algorithm,
            kem_ct=sealed.kem_ct,
            nonce=sealed.nonce,
            ciphertext=bytes(ct_list),
            aad=sealed.aad,
        )
        with pytest.raises(InvalidTag):
            Envelope.open(tampered, kp.secret, kem=kem)

    def test_nonces_are_random(self):
        kem = make_hybrid_kem()
        kp = kem.generate_keypair()
        sealed1 = Envelope.seal(b"msg", kp.public, kem=kem)
        sealed2 = Envelope.seal(b"msg", kp.public, kem=kem)
        # Different nonces each time
        assert sealed1.nonce != sealed2.nonce

    def test_envelope_serialization_survives_wire(self):
        kem = make_hybrid_kem()
        kp = kem.generate_keypair()

        plaintext = b"serialize me across a wire"
        sealed = Envelope.seal(plaintext, kp.public, kem=kem)
        wire = sealed.to_bytes()
        sealed2 = SealedMessage.from_bytes(wire)
        recovered = Envelope.open(sealed2, kp.secret, kem=kem)
        assert recovered == plaintext

    def test_wrong_key_fails(self):
        from cryptography.exceptions import InvalidTag
        kem = make_hybrid_kem()
        kp1 = kem.generate_keypair()
        kp2 = kem.generate_keypair()

        sealed = Envelope.seal(b"for kp1", kp1.public, kem=kem)
        # kp2's secret key will decapsulate to a different shared secret
        # → different AES key → InvalidTag
        with pytest.raises((InvalidTag, DecapsulationError)):
            Envelope.open(sealed, kp2.secret, kem=kem)


# ---------------------------------------------------------------------------
# JWT utilities
# ---------------------------------------------------------------------------


class TestJWTUtils:
    def test_b64url_round_trip(self):
        data = os.urandom(64)
        encoded = _b64url_encode(data)
        assert "=" not in encoded   # no padding
        decoded = _b64url_decode(encoded)
        assert decoded == data

    def test_b64url_decode_handles_missing_padding(self):
        # Padding stripped at encode, restored at decode
        original = b"test data !"
        enc = _b64url_encode(original)
        assert _b64url_decode(enc) == original

    def test_json_b64_is_compact(self):
        b64 = _json_b64({"alg": "ML-DSA-65", "typ": "JWT"})
        decoded = json.loads(_b64url_decode(b64))
        assert decoded["alg"] == "ML-DSA-65"
        assert " " not in b64  # compact JSON


# ---------------------------------------------------------------------------
# JWT signer/verifier — Ed25519 classical path with mock PQC
# ---------------------------------------------------------------------------


class TestJWTSignerVerifier:
    def _make_jwt_pair(self):
        """Create a JWTSigner/JWTVerifier pair using hybrid Ed25519+mock."""
        hs = make_hybrid_sign()
        kp = hs.generate_keypair()

        signer = JWTSigner.__new__(JWTSigner)
        signer._keypair = kp
        signer._hedged = True
        signer._issuer = "test-issuer"
        signer._algorithm = "Ed25519+ML-DSA-65"
        signer._signer = hs

        verifier = JWTVerifier.__new__(JWTVerifier)
        verifier._public_key = kp.public
        verifier._issuer = "test-issuer"
        verifier._audience = None
        verifier._algorithm = "Ed25519+ML-DSA-65"
        verifier._verifier = hs

        return signer, verifier, kp

    def test_sign_returns_three_parts(self):
        signer, _, _ = self._make_jwt_pair()
        token = signer.sign({"sub": "user123"})
        assert token.count(".") == 2

    def test_header_contains_alg(self):
        signer, _, _ = self._make_jwt_pair()
        token = signer.sign({"sub": "user123"})
        header_b64 = token.split(".")[0]
        header = json.loads(_b64url_decode(header_b64))
        assert header["alg"] == "Ed25519+ML-DSA-65"
        assert header["typ"] == "JWT"
        assert header["qs-version"] == 1

    def test_payload_contains_iat_and_exp(self):
        signer, _, _ = self._make_jwt_pair()
        token = signer.sign({"sub": "user123"}, expires_in=3600)
        payload_b64 = token.split(".")[1]
        claims = json.loads(_b64url_decode(payload_b64))
        assert "iat" in claims
        assert "exp" in claims
        assert claims["exp"] > claims["iat"]

    def test_payload_contains_issuer(self):
        signer, _, _ = self._make_jwt_pair()
        token = signer.sign({"sub": "user123"})
        payload_b64 = token.split(".")[1]
        claims = json.loads(_b64url_decode(payload_b64))
        assert claims["iss"] == "test-issuer"

    def test_caller_claims_are_present(self):
        signer, _, _ = self._make_jwt_pair()
        token = signer.sign({"sub": "user456", "role": "admin"})
        payload_b64 = token.split(".")[1]
        claims = json.loads(_b64url_decode(payload_b64))
        assert claims["sub"] == "user456"
        assert claims["role"] == "admin"

    def test_verify_valid_token(self):
        signer, verifier, _ = self._make_jwt_pair()
        token = signer.sign({"sub": "userABC"})
        # Ed25519 is real — verify will check the real signature
        claims = verifier.verify(token)
        assert claims["sub"] == "userABC"
        assert claims["iss"] == "test-issuer"

    def test_verify_expired_token_raises(self):
        signer, verifier, _ = self._make_jwt_pair()
        # expires_in=0 leaves out exp, so we need to manually set exp in past
        token = signer.sign({"sub": "user", "exp": int(time.time()) - 100})
        with pytest.raises(VerificationError):
            verifier.verify(token)

    def test_verify_tampered_payload_raises(self):
        signer, verifier, _ = self._make_jwt_pair()
        token = signer.sign({"sub": "user1"})
        header, payload, sig = token.split(".")
        # Encode a tampered payload
        tampered_payload = _b64url_encode(
            json.dumps({"sub": "admin", "iss": "test-issuer", "iat": int(time.time())},
                       separators=(",", ":")).encode()
        )
        tampered_token = f"{header}.{tampered_payload}.{sig}"
        with pytest.raises(VerificationError):
            verifier.verify(tampered_token)

    def test_verify_wrong_algorithm_raises(self):
        signer, _, kp = self._make_jwt_pair()
        token = signer.sign({"sub": "user"})
        # Verifier configured for wrong algorithm
        wrong_verifier = JWTVerifier.__new__(JWTVerifier)
        wrong_verifier._public_key = kp.public
        wrong_verifier._issuer = None
        wrong_verifier._audience = None
        wrong_verifier._algorithm = "ML-DSA-65"
        wrong_verifier._verifier = Sign.__new__(Sign)
        with pytest.raises(UnsupportedAlgorithm):
            wrong_verifier.verify(token)

    def test_malformed_token_raises(self):
        _, verifier, _ = self._make_jwt_pair()
        with pytest.raises(ValueError, match="3 parts"):
            verifier.verify("not.a.valid.jwt.with.too.many.dots")

    def test_verify_issuer_mismatch_raises(self):
        signer, _, kp = self._make_jwt_pair()
        token = signer.sign({"sub": "user"})
        # Verifier with different expected issuer
        hs = make_hybrid_sign()
        strict_verifier = JWTVerifier.__new__(JWTVerifier)
        strict_verifier._public_key = kp.public
        strict_verifier._issuer = "different-issuer"
        strict_verifier._audience = None
        strict_verifier._algorithm = "Ed25519+ML-DSA-65"
        strict_verifier._verifier = hs
        with pytest.raises(VerificationError):
            strict_verifier.verify(token)


# ---------------------------------------------------------------------------
# TLS configuration
# ---------------------------------------------------------------------------


class TestHybridTLSConfig:
    def test_default_config(self):
        cfg = HybridTLSConfig()
        assert cfg.kem_algorithm == "X25519+ML-KEM-768"
        assert cfg.fallback_classical is True
        assert cfg.require_hybrid is False

    def test_group_preference_includes_hybrid(self):
        cfg = HybridTLSConfig()
        groups = cfg.group_preference
        # Should have at least one hybrid group
        assert any("mlkem" in g.lower() or "MLKEM" in g for g in groups)

    def test_group_preference_includes_fallback_when_enabled(self):
        cfg = HybridTLSConfig(fallback_classical=True)
        groups = cfg.group_preference
        assert "X25519" in groups

    def test_group_preference_no_fallback(self):
        cfg = HybridTLSConfig(fallback_classical=False)
        groups = cfg.group_preference
        assert "X25519" not in groups or all(
            "mlkem" in g.lower() or "MLKEM" in g for g in groups if g == "X25519"
        )

    def test_unknown_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unknown KEM algorithm"):
            HybridTLSConfig(kem_algorithm="FAKE+ALGO")

    def test_get_hybrid_group_name(self):
        assert get_hybrid_group_name("X25519+ML-KEM-768") == "X25519MLKEM768"
        assert get_hybrid_group_name("X25519") == "X25519"

    def test_get_hybrid_group_name_unknown_raises(self):
        with pytest.raises(ValueError):
            get_hybrid_group_name("FAKE+ALGO")


class TestCheckHybridSupport:
    def test_returns_dict(self):
        info = check_hybrid_support()
        assert isinstance(info, dict)
        assert "openssl_version" in info
        assert "oqs_provider" in info
        assert "recommendation" in info

    def test_openssl_version_is_string(self):
        info = check_hybrid_support()
        assert isinstance(info["openssl_version"], str)
        assert "OpenSSL" in info["openssl_version"]


class TestConfigureHybridContext:
    def test_returns_ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with pytest.warns(UserWarning, match="OQS provider not available"):
            result = configure_hybrid_context(ctx)
        assert result is ctx  # returns the same object

    def test_minimum_version_set(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with pytest.warns(UserWarning, match="OQS provider not available"):
            configure_hybrid_context(ctx, HybridTLSConfig())
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3

    def test_warns_when_oqs_unavailable(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Standard ssl doesn't have set_groups — should warn
        with pytest.warns(UserWarning, match="OQS provider"):
            configure_hybrid_context(ctx)

    def test_require_hybrid_raises_when_unavailable(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cfg = HybridTLSConfig(require_hybrid=True)
        with pytest.raises(ssl.SSLError, match="Hybrid TLS is required"):
            configure_hybrid_context(ctx, cfg)


# ---------------------------------------------------------------------------
# X.509 certificate builder — classical-only path (no PQC backend)
# ---------------------------------------------------------------------------

@pytest.mark.requires_liboqs
class TestHybridCertificateBuilder:
    def _make_hybrid_kp(self) -> KeyPair:
        hs = make_hybrid_sign()
        return hs.generate_keypair()

    def test_generate_classical_keypair_ed25519(self):
        priv = generate_classical_keypair_for_cert("Ed25519")
        assert isinstance(priv, Ed25519PrivateKey)

    def test_generate_classical_keypair_p256(self):
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
        priv = generate_classical_keypair_for_cert("P-256")
        assert isinstance(priv, EllipticCurvePrivateKey)

    def test_generate_classical_keypair_unknown_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            generate_classical_keypair_for_cert("RSA-4096")

    def test_build_returns_pem_and_cosig(self):
        classical_priv = generate_classical_keypair_for_cert("Ed25519")
        hybrid_kp = self._make_hybrid_kp()

        builder = HybridCertificateBuilder(
            subject_cn="test.service.internal",
            classical_private_key=classical_priv,
            pqc_keypair=hybrid_kp,
            validity_days=365,
        )
        cert_pem, cosig_bundle = builder.build()

        assert b"-----BEGIN CERTIFICATE-----" in cert_pem
        assert b"-----END CERTIFICATE-----" in cert_pem
        assert isinstance(cosig_bundle, bytes)
        assert len(cosig_bundle) > 0

    def test_cert_contains_subject_cn(self):
        from cryptography import x509 as cx509
        from cryptography.hazmat.backends import default_backend

        classical_priv = generate_classical_keypair_for_cert("Ed25519")
        hybrid_kp = self._make_hybrid_kp()

        builder = HybridCertificateBuilder(
            subject_cn="myservice.example.com",
            classical_private_key=classical_priv,
            pqc_keypair=hybrid_kp,
        )
        cert_pem, _ = builder.build()

        cert = cx509.load_pem_x509_certificate(cert_pem, default_backend())
        cn = cert.subject.get_attributes_for_oid(
            cx509.NameOID.COMMON_NAME
        )[0].value
        assert cn == "myservice.example.com"

    def test_cert_has_pqc_pubkey_extension(self):
        from cryptography import x509 as cx509
        from cryptography.hazmat.backends import default_backend
        from quantum_safe.protocols.x509 import _PQC_PUBKEY_OID

        classical_priv = generate_classical_keypair_for_cert("Ed25519")
        hybrid_kp = self._make_hybrid_kp()

        builder = HybridCertificateBuilder(
            subject_cn="ext-test.example.com",
            classical_private_key=classical_priv,
            pqc_keypair=hybrid_kp,
        )
        cert_pem, _ = builder.build()

        cert = cx509.load_pem_x509_certificate(cert_pem, default_backend())
        ext = cert.extensions.get_extension_for_oid(_PQC_PUBKEY_OID)
        assert ext is not None
        # Extension should not be critical
        assert ext.critical is False

    def test_cert_with_san(self):
        from cryptography import x509 as cx509
        from cryptography.hazmat.backends import default_backend

        classical_priv = generate_classical_keypair_for_cert("Ed25519")
        hybrid_kp = self._make_hybrid_kp()

        builder = HybridCertificateBuilder(
            subject_cn="multi-san.example.com",
            classical_private_key=classical_priv,
            pqc_keypair=hybrid_kp,
            dns_names=["api.example.com", "www.example.com"],
            ip_addresses=["10.0.0.1"],
        )
        cert_pem, _ = builder.build()

        cert = cx509.load_pem_x509_certificate(cert_pem, default_backend())
        san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
        # get_values_for_type(DNSName) returns plain strings in cryptography >= 42
        dns_values = list(san_ext.value.get_values_for_type(cx509.DNSName))
        assert "api.example.com" in dns_values
        assert "www.example.com" in dns_values

    def test_cert_validity_period(self):
        from cryptography import x509 as cx509
        from cryptography.hazmat.backends import default_backend
        import datetime

        classical_priv = generate_classical_keypair_for_cert("Ed25519")
        hybrid_kp = self._make_hybrid_kp()

        builder = HybridCertificateBuilder(
            subject_cn="validity.example.com",
            classical_private_key=classical_priv,
            pqc_keypair=hybrid_kp,
            validity_days=90,
        )
        cert_pem, _ = builder.build()

        cert = cx509.load_pem_x509_certificate(cert_pem, default_backend())
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        # Should be approximately 90 days
        assert 89 <= delta.days <= 91


@pytest.mark.requires_liboqs
class TestProtocolsWithRealBackend:
    def test_envelope_full_with_real_kem(self):
        kem = HybridKEM()
        kp = kem.generate_keypair()
        sealed = Envelope.seal(b"real secret", kp.public)
        recovered = Envelope.open(sealed, kp.secret)
        assert recovered == b"real secret"

    def test_jwt_full_with_real_pqc(self):
        from quantum_safe.signatures import HybridSign
        signer = HybridSign()
        kp = signer.generate_keypair()
        jwt_signer = JWTSigner(kp, issuer="real-test")
        token = jwt_signer.sign({"sub": "user999"})
        verifier = JWTVerifier(kp.public, issuer="real-test")
        claims = verifier.verify(token)
        assert claims["sub"] == "user999"
