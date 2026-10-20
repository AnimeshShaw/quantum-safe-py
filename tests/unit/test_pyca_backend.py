"""
The optional ``cryptography`` (pyca) backend (audit items PY-X4 / PY-A1): ML-KEM-768/1024 and
ML-DSA-44/65/87 with **seeded** key generation.

What it adds over liboqs: a key is its 32-byte (ML-DSA) or 64-byte (ML-KEM) seed, FIPS's native secret
key form, so keys can be exported as seeds, rebuilt from them, shared with quantum-safe-ts, and used
in RFC 9964 private JWKs and COSE keys. liboqs cannot derive a key from a seed for ML-DSA.

Independent known answer: RFC 9964 Appendix A's all-zero seed must derive the RFC's public key.
"""

from __future__ import annotations

import json
import pathlib

import pytest

pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.mldsa",
    reason="needs cryptography >= 48 (seeded ML-DSA / ML-KEM)",
)

RFC = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1]
        / "interop"
        / "vectors"
        / "rfc9964_cose_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]
LEVELS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
PK_LEN = {"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592}


@pytest.fixture(scope="module")
def sig_backend():
    from quantum_safe.backends import get_signature_backend

    return get_signature_backend("pyca")


@pytest.fixture(scope="module")
def kem_backend():
    from quantum_safe.backends import get_kem_backend

    return get_kem_backend("pyca")


class TestRegistry:
    def test_is_a_known_backend_and_listed(self) -> None:
        from quantum_safe.backends import list_available_backends

        assert list_available_backends()["pyca"] is True

    def test_supported_algorithms(self, sig_backend, kem_backend) -> None:
        assert {a.name for a in sig_backend.supported_algorithms()} == set(LEVELS)
        assert {a.name for a in kem_backend.supported_algorithms()} == {"ML-KEM-768", "ML-KEM-1024"}

    def test_unsupported_algorithms_are_named_errors(self, sig_backend, kem_backend) -> None:
        from quantum_safe.exceptions import UnsupportedAlgorithm

        with pytest.raises(UnsupportedAlgorithm):
            kem_backend.keygen("ML-KEM-512")
        with pytest.raises(UnsupportedAlgorithm):
            sig_backend.keygen("SLH-DSA-SHAKE-128f")


class TestSeededSignatures:
    @pytest.mark.parametrize("v", RFC, ids=[v["algorithm"] for v in RFC])
    def test_rfc9964_all_zero_seed_derives_the_rfc_public_key(self, sig_backend, v) -> None:
        pub, sec = sig_backend.keygen_from_seed(v["algorithm"], bytes(32))
        assert pub == bytes.fromhex(v["public_key"])
        assert sec == bytes(32)

    @pytest.mark.parametrize("level", LEVELS)
    def test_keygen_returns_a_seed_that_rebuilds_the_key(self, sig_backend, level: str) -> None:
        pub, seed = sig_backend.keygen(level)
        assert len(pub) == PK_LEN[level] and len(seed) == 32
        again, _ = sig_backend.keygen_from_seed(level, seed)
        assert again == pub

    @pytest.mark.parametrize("level", LEVELS)
    def test_standard_signature_roundtrip_and_context(self, sig_backend, level: str) -> None:
        pub, seed = sig_backend.keygen(level)
        sig = sig_backend.sign_native_context(level, seed, b"message", b"ctx")
        assert sig_backend.verify_native_context(level, pub, b"message", sig, b"ctx") is True
        assert sig_backend.verify_native_context(level, pub, b"message", sig, b"other") is False
        assert sig_backend.verify_native_context(level, pub, b"messagE", sig, b"ctx") is False

    def test_library_format_roundtrip_through_sign(self) -> None:
        from quantum_safe.signatures.core import Sign

        s = Sign("ML-DSA-65", backend="pyca")
        kp = s.generate_keypair()
        assert len(kp.secret.raw_bytes) == 32  # the seed
        sm = s.sign(b"hello", kp.secret, context=b"c")
        s.verify(sm, kp.public, context=b"c")

    def test_v2_format_roundtrip(self) -> None:
        from quantum_safe.signatures.hybrid import HybridSign

        h = HybridSign("Ed25519", "ML-DSA-65-v2", backend="pyca")
        kp = h.generate_keypair()
        h.verify(h.sign(b"m", kp.secret, context=b"c"), kp.public, context=b"c")


class TestSeedKeyConveniences:
    def test_generate_export_import_seed(self) -> None:
        from quantum_safe.signatures.core import Sign

        s = Sign("ML-DSA-44", backend="pyca")
        kp = s.generate_seed_keypair()
        seed = s.export_seed(kp.secret)
        assert len(seed) == 32
        again = s.keypair_from_seed(seed)
        assert again.public.raw_bytes == kp.public.raw_bytes
        sig = s.sign_standard(b"m", again.secret, context=b"c")
        s.verify_standard(b"m", sig, kp.public, context=b"c")

    def test_rfc9964_seed_through_the_public_api(self) -> None:
        from quantum_safe.signatures.core import Sign

        v = RFC[1]
        kp = Sign(v["algorithm"], backend="pyca").keypair_from_seed(bytes.fromhex(v["seed"]))
        assert kp.public.raw_bytes == bytes.fromhex(v["public_key"])

    @pytest.mark.requires_liboqs
    def test_export_seed_refuses_an_expanded_key(self) -> None:
        from quantum_safe.signatures.core import Sign

        kp = Sign("ML-DSA-44", backend="liboqs").generate_keypair()
        with pytest.raises(ValueError, match="seed"):
            Sign("ML-DSA-44", backend="pyca").export_seed(kp.secret)

    def test_bad_seed_length(self) -> None:
        from quantum_safe.signatures.core import Sign

        with pytest.raises(ValueError, match="32"):
            Sign("ML-DSA-44", backend="pyca").keypair_from_seed(b"\x00" * 31)


class TestKem:
    @pytest.mark.parametrize("alg", ["ML-KEM-768", "ML-KEM-1024"])
    def test_roundtrip_and_seed(self, kem_backend, alg: str) -> None:
        pub, seed = kem_backend.keygen(alg)
        assert len(seed) == 64
        ct, ss = kem_backend.encapsulate(alg, pub)
        assert kem_backend.decapsulate(alg, seed, ct) == ss
        again, _ = kem_backend.keygen_from_seed(alg, seed)
        assert again == pub

    def test_seed_length_is_checked(self, kem_backend) -> None:
        with pytest.raises(ValueError):
            kem_backend.keygen_from_seed("ML-KEM-768", b"\x00" * 32)

    def test_implicit_rejection_does_not_raise(self, kem_backend) -> None:
        pub, seed = kem_backend.keygen("ML-KEM-768")
        ct, ss = kem_backend.encapsulate("ML-KEM-768", pub)
        bad = bytearray(ct)
        bad[0] ^= 1
        assert kem_backend.decapsulate("ML-KEM-768", seed, bytes(bad)) != ss

    def test_hybrid_kem_runs_on_pyca_alone(self) -> None:
        from quantum_safe.kem.hybrid import HybridKEM

        kem = HybridKEM("X25519", "ML-KEM-768", backend="pyca")
        kp = kem.generate_keypair()
        ct, ss = kem.encapsulate(kp.public)
        assert kem.decapsulate(kp.secret, ct) == ss

    def test_xwing_runs_on_pyca_alone(self) -> None:
        from quantum_safe.kem.xwing import XWing

        x = XWing(backend="pyca")
        kp = x.generate_keypair()
        ct, ss = x.encapsulate(kp.public)
        assert x.decapsulate(kp.secret, ct) == ss


@pytest.mark.requires_liboqs
class TestAgainstLiboqs:
    """Two independent implementations must agree."""

    @pytest.mark.parametrize("level", LEVELS)
    def test_standard_signatures_cross_verify(self, level: str) -> None:
        from quantum_safe.backends import get_signature_backend

        pyca, oqs = get_signature_backend("pyca"), get_signature_backend("liboqs")
        pub, seed = pyca.keygen(level)
        sig = pyca.sign_native_context(level, seed, b"cross", b"ctx")
        assert oqs.verify_native_context(level, pub, b"cross", sig, b"ctx") is True
        opub, osec = oqs.keygen(level)
        osig = oqs.sign_native_context(level, osec, b"cross", b"ctx")
        assert pyca.verify_native_context(level, opub, b"cross", osig, b"ctx") is True

    @pytest.mark.parametrize("alg", ["ML-KEM-768", "ML-KEM-1024"])
    def test_kem_cross_decapsulate_and_seeded_keygen_agree(self, alg: str) -> None:
        from quantum_safe.backends import get_kem_backend

        pyca, oqs = get_kem_backend("pyca"), get_kem_backend("liboqs")
        seed = bytes(range(64))
        pub_p, _ = pyca.keygen_from_seed(alg, seed)
        pub_o, sec_o = oqs.keygen_from_seed(alg, seed)
        assert pub_p == pub_o  # FIPS 203 key expansion: both implementations agree
        ct, ss = oqs.encapsulate(alg, pub_p)
        assert pyca.decapsulate(alg, seed, ct) == ss
        assert oqs.decapsulate(alg, sec_o, ct) == ss

    def test_seed_keys_work_with_the_default_backend(self) -> None:
        """A seed key made by the pyca backend signs and verifies through the default (liboqs) route."""
        from quantum_safe.signatures.core import Sign

        kp = Sign("ML-DSA-65", backend="pyca").generate_keypair()
        default = Sign("ML-DSA-65", backend="liboqs")
        sm = default.sign(b"routed", kp.secret, context=b"c")
        default.verify(sm, kp.public, context=b"c")

    def test_expanded_keys_work_through_the_pyca_route(self) -> None:
        from quantum_safe.signatures.core import Sign

        kp = Sign("ML-DSA-65", backend="liboqs").generate_keypair()
        s = Sign("ML-DSA-65", backend="pyca")
        sm = s.sign(b"routed", kp.secret, context=b"c")
        s.verify(sm, kp.public, context=b"c")
