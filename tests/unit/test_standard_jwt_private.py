"""
Private AKP JWKs for StandardJwt (audit item PY-X4): RFC 9964's ``priv`` is the 32-byte ML-DSA seed.

Needs the optional ``cryptography`` backend (>= 48), which is the one that can derive a key from a
seed. Independent known answers: RFC 9964 Appendix A.1 (all-zero seed; public JWK; a compact JWS).
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.mldsa",
    reason="needs cryptography >= 48 (seeded ML-DSA)",
)

from quantum_safe.exceptions import KeyParseError, VerificationError  # noqa: E402
from quantum_safe.protocols.standard_jwt import StandardJwt  # noqa: E402

JOSE = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1]
        / "interop"
        / "vectors"
        / "rfc9964_jose_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.mark.parametrize("v", JOSE, ids=[v["algorithm"] for v in JOSE])
class TestRfc9964AppendixA1:
    def test_all_zero_seed_derives_the_rfc_public_jwk(self, v) -> None:
        private = {"kty": "AKP", "alg": v["algorithm"], "priv": v["priv_b64u"], "kid": v["kid"]}
        public = StandardJwt.public_jwk(private)
        assert public["pub"] == v["pub_b64u"] and public["alg"] == v["algorithm"]
        assert "priv" not in public and public["kid"] == v["kid"]

    def test_keypair_from_the_rfc_private_jwk(self, v) -> None:
        kp = StandardJwt.keypair_from_private_jwk(
            {"kty": "AKP", "alg": v["algorithm"], "pub": v["pub_b64u"], "priv": v["priv_b64u"]}
        )
        assert kp.public.raw_bytes == _b64u(v["pub_b64u"])
        assert kp.secret.raw_bytes == bytes(32)

    def test_the_rfc_signature_verifies_over_its_signing_input(self, v) -> None:
        from quantum_safe.backends import get_signature_backend

        h, p, s = v["jws"].split(".")
        assert f"{h}.{p}".encode("ascii") == bytes.fromhex(v["to_be_signed_hex"])
        ok = get_signature_backend("auto").verify_native_context(
            v["algorithm"], _b64u(v["pub_b64u"]), f"{h}.{p}".encode("ascii"), _b64u(s), b""
        )
        assert ok is True


class TestPrivateJwk:
    def test_generate_sign_verify(self) -> None:
        private = StandardJwt.generate_private_jwk("ML-DSA-65", kid="k1")
        assert private["kty"] == "AKP" and private["alg"] == "ML-DSA-65" and private["kid"] == "k1"
        assert len(_b64u(private["priv"])) == 32 and len(_b64u(private["pub"])) == 1952
        token = StandardJwt.sign({"sub": "alice"}, private, issuer="https://issuer.example")
        public = StandardJwt.public_jwk(private)
        claims = StandardJwt.verify(token, public, issuer="https://issuer.example")
        assert claims["sub"] == "alice"
        assert json.loads(_b64u(token.split(".")[0]))["kid"] == "k1"

    def test_the_public_jwk_never_contains_priv(self) -> None:
        private = StandardJwt.generate_private_jwk()
        assert "priv" not in StandardJwt.public_jwk(private)

    def test_private_jwk_from_a_keypair_roundtrips(self) -> None:
        from quantum_safe.signatures.core import Sign

        kp = Sign("ML-DSA-44", backend="pyca").generate_seed_keypair()
        jwk = StandardJwt.private_jwk(kp, kid="x")
        again = StandardJwt.keypair_from_private_jwk(jwk)
        assert again.public.raw_bytes == kp.public.raw_bytes
        assert again.secret.raw_bytes == kp.secret.raw_bytes

    def test_a_wrong_key_does_not_verify(self) -> None:
        a = StandardJwt.generate_private_jwk()
        b = StandardJwt.generate_private_jwk()
        token = StandardJwt.sign({"sub": "u"}, a)
        with pytest.raises(VerificationError):
            StandardJwt.verify(token, StandardJwt.public_jwk(b))

    def test_malformed_private_jwks_are_refused(self) -> None:
        good = StandardJwt.generate_private_jwk()
        for bad in (
            {k: v for k, v in good.items() if k != "priv"},  # no seed: not a private key
            good | {"priv": "AAAA"},  # not 32 bytes
            good | {"kty": "OKP"},
            good | {"alg": "ML-DSA-99"},
            good | {"pub": "AAAA"},  # public part does not match the seed
        ):
            with pytest.raises((KeyParseError, ValueError, Exception)) as err:
                StandardJwt.keypair_from_private_jwk(bad)
            assert err.value is not None

    def test_signing_with_an_expanded_liboqs_key_still_works(self) -> None:
        """Existing behaviour is unchanged: ``sign`` still takes a plain SecretKey."""
        pytest.importorskip("oqs")
        kp = StandardJwt.generate_keypair("ML-DSA-65")
        token = StandardJwt.sign({"sub": "legacy"}, kp.secret)
        assert StandardJwt.verify(token, kp.public)["sub"] == "legacy"
