"""StandardJwt: RFC 9964 ML-DSA JWTs, verifiable by any JOSE implementation.

A standard token is ``b64url(header).b64url(payload).b64url(signature)`` where
the header is ``{"alg": "ML-DSA-65", "typ": "JWT"}`` and the signature is a
raw FIPS 204 ML-DSA signature over ``header.payload`` with an *empty* context.
Mirrors quantum-safe-ts's ``StandardJwt`` (see its ``jwt.ts``).
"""

from __future__ import annotations

import base64
import json
import time
import warnings

import pytest

from quantum_safe.exceptions import UnsupportedAlgorithm, VerificationError
from quantum_safe.protocols.standard_jwt import StandardJwt

pytestmark = pytest.mark.requires_liboqs

SIG_LEN = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def forge(header: dict, claims: dict, sig: bytes = b"\x00") -> str:
    return ".".join([b64(json.dumps(header).encode()), b64(json.dumps(claims).encode()), b64(sig)])


@pytest.fixture(scope="module", params=list(SIG_LEN))
def pair(request):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        kp = StandardJwt.generate_keypair(request.param)
    return request.param, kp


def test_public_jwk_is_a_clean_akp_key(pair) -> None:
    alg, kp = pair
    jwk = StandardJwt.public_jwk(kp.public, kid="k1")
    assert jwk == {"kty": "AKP", "alg": alg, "pub": b64(kp.public.raw_bytes), "kid": "k1"}
    assert "priv" not in jwk
    assert set(StandardJwt.public_jwk(kp.public)) == {"kty", "alg", "pub"}


def test_round_trip(pair) -> None:
    alg, kp = pair
    token = StandardJwt.sign({"sub": "u1"}, kp.secret, issuer="me")
    claims = StandardJwt.verify(token, StandardJwt.public_jwk(kp.public), issuer="me")
    assert claims["sub"] == "u1" and claims["iss"] == "me" and "iat" in claims and "exp" in claims
    # a PublicKey works as the verification key too
    assert StandardJwt.verify(token, kp.public)["sub"] == "u1"
    header = json.loads(unb64(token.split(".")[0]))
    assert header == {"alg": alg, "typ": "JWT"}


def test_the_signature_is_a_raw_fips_204_signature_over_header_dot_payload(pair) -> None:
    """Verify with liboqs directly, empty context: what any JOSE library does."""
    import oqs

    alg, kp = pair
    token = StandardJwt.sign({"sub": "u1"}, kp.secret)
    h, p, s = token.split(".")
    sig = unb64(s)
    assert len(sig) == SIG_LEN[alg]
    v = oqs.Signature(alg)
    assert v.verify(f"{h}.{p}".encode(), sig, kp.public.raw_bytes)
    assert v.verify_with_ctx_str(f"{h}.{p}".encode(), sig, b"", kp.public.raw_bytes)


def test_kid_is_carried_in_the_header(pair) -> None:
    _, kp = pair
    token = StandardJwt.sign({}, kp.secret, kid="key-7")
    assert json.loads(unb64(token.split(".")[0]))["kid"] == "key-7"


def test_expiry_and_claim_checks() -> None:
    kp = StandardJwt.generate_keypair("ML-DSA-44")
    jwk = StandardJwt.public_jwk(kp.public)
    now = int(time.time())
    expired = StandardJwt.sign({"exp": now - 3600}, kp.secret)
    with pytest.raises(VerificationError):
        StandardJwt.verify(expired, jwk)
    assert StandardJwt.verify(expired, jwk, validate_exp=False)["exp"] == now - 3600
    future = StandardJwt.sign({"nbf": now + 3600}, kp.secret)
    with pytest.raises(VerificationError):
        StandardJwt.verify(future, jwk)
    tok = StandardJwt.sign({"aud": ["a", "b"]}, kp.secret, issuer="iss1")
    assert StandardJwt.verify(tok, jwk, audience="b", issuer="iss1")
    for kwargs in ({"audience": "c"}, {"issuer": "other"}):
        with pytest.raises(VerificationError):
            StandardJwt.verify(tok, jwk, **kwargs)
    no_exp = StandardJwt.sign({"sub": "x"}, kp.secret, expires_in=0)
    assert "exp" not in StandardJwt.verify(no_exp, jwk)
    with pytest.raises(VerificationError):
        StandardJwt.verify(no_exp, jwk, require_exp=True)
    with pytest.raises(VerificationError):
        StandardJwt.verify(StandardJwt.sign({"exp": "soon"}, kp.secret), jwk)  # non-numeric exp
    assert StandardJwt.verify(expired, jwk, now=now - 7200)["exp"] == now - 3600  # injected clock


def test_negative_expires_in_is_refused() -> None:
    kp = StandardJwt.generate_keypair("ML-DSA-44")
    with pytest.raises(ValueError, match="expires_in"):
        StandardJwt.sign({}, kp.secret, expires_in=-1)


def test_tampering_is_detected() -> None:
    kp = StandardJwt.generate_keypair("ML-DSA-65")
    jwk = StandardJwt.public_jwk(kp.public)
    h, p, s = StandardJwt.sign({"sub": "alice"}, kp.secret).split(".")
    forged_payload = b64(json.dumps({"sub": "admin"}).encode())
    for bad in (
        f"{h}.{forged_payload}.{s}",
        f"{h}.{p}.{b64(unb64(s)[:-1])}",
        f"{h}.{p}.{b64(unb64(s) + b'x')}",
    ):
        with pytest.raises(VerificationError):
            StandardJwt.verify(bad, jwk)


def test_algorithm_must_match_the_key_and_crit_is_refused() -> None:
    kp44 = StandardJwt.generate_keypair("ML-DSA-44")
    kp65 = StandardJwt.generate_keypair("ML-DSA-65")
    token = StandardJwt.sign({"sub": "u"}, kp44.secret)
    with pytest.raises(UnsupportedAlgorithm):
        StandardJwt.verify(token, StandardJwt.public_jwk(kp65.public))
    with pytest.raises(UnsupportedAlgorithm):
        StandardJwt.verify(
            forge({"alg": "ML-DSA-44", "typ": "JWT", "crit": ["x"], "x": 1}, {}),
            StandardJwt.public_jwk(kp44.public),
        )
    with pytest.raises(UnsupportedAlgorithm):
        StandardJwt.verify(forge({"alg": "none"}, {}), StandardJwt.public_jwk(kp44.public))


def test_one_spelling_per_signature() -> None:
    """Padding and non-canonical trailing bits are second encodings: refused."""
    kp = StandardJwt.generate_keypair("ML-DSA-44")
    jwk = StandardJwt.public_jwk(kp.public)
    h, p, s = StandardJwt.sign({"sub": "u"}, kp.secret).split(".")
    padded = s + "=" * (-len(s) % 4)
    if padded != s:
        with pytest.raises(VerificationError):
            StandardJwt.verify(f"{h}.{p}.{padded}", jwk)
    assert len(s) % 4 in (2, 3)  # an unpadded length with spare bits
    last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".index(s[-1])
    twin = s[:-1] + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last ^ 1]
    with pytest.raises(VerificationError):
        StandardJwt.verify(f"{h}.{p}.{twin}", jwk)


@pytest.mark.parametrize("bad", ["", "a.b", "a.b.c.d", "a..c", "...", ".b.c"])
def test_malformed_tokens(bad: str) -> None:
    kp = StandardJwt.generate_keypair("ML-DSA-44")
    with pytest.raises(ValueError):
        StandardJwt.verify(bad, StandardJwt.public_jwk(kp.public))


def test_invalid_keys_and_jwks() -> None:
    from quantum_safe.exceptions import KeyParseError

    kp = StandardJwt.generate_keypair("ML-DSA-44")
    good = StandardJwt.public_jwk(kp.public)
    token = StandardJwt.sign({}, kp.secret)
    for bad in (
        {**good, "kty": "RSA"},
        {k: v for k, v in good.items() if k != "pub"},
        {**good, "alg": "ML-DSA-99"},
        {**good, "pub": 5},
        "jwk",
        None,
    ):
        with pytest.raises((KeyParseError, UnsupportedAlgorithm)):
            StandardJwt.verify(token, bad)
    with pytest.raises(UnsupportedAlgorithm):
        StandardJwt.generate_keypair("ML-KEM-768")
    with pytest.raises(UnsupportedAlgorithm):
        StandardJwt.generate_keypair("Ed25519+ML-DSA-65")  # hybrids are not RFC 9964


def test_a_v2_or_quantum_safe_jwt_is_not_a_standard_token() -> None:
    from quantum_safe.protocols.jwt import JWTSigner

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        kp = StandardJwt.generate_keypair("ML-DSA-65")
    legacy = JWTSigner(kp).sign({"sub": "u"})
    with pytest.raises(VerificationError):
        StandardJwt.verify(legacy, StandardJwt.public_jwk(kp.public))
    standard = StandardJwt.sign({"sub": "u"}, kp.secret)
    from quantum_safe.protocols.jwt import JWTVerifier

    with pytest.raises(VerificationError):
        JWTVerifier(kp.public).verify(standard)
