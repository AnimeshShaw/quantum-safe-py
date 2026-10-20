"""
quantum_safe.protocols.standard_jwt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RFC 9964 ML-DSA JSON Web Tokens: tokens any compliant JOSE implementation can
verify. Mirrors ``StandardJwt`` in quantum-safe-ts.

How this differs from :mod:`quantum_safe.protocols.jwt`
-------------------------------------------------------
``JWTSigner`` tokens verify only with quantum-safe: their signature field is
this library's signature blob and they sign a context-prefixed message. A
standard token is::

    base64url(header) . base64url(payload) . base64url(signature)

with header ``{"alg": "ML-DSA-65", "typ": "JWT"}`` and a **raw FIPS 204 ML-DSA
signature over** ``header.payload`` **with an empty context**. The public key
is an ``AKP`` JWK (``{"kty": "AKP", "alg": ..., "pub": base64url(public key)}``).
Only the pure ML-DSA algorithms (44, 65, 87) are defined by the RFC; hybrids
are not.

Private JWKs
------------
RFC 9964 defines the private JWK member ``priv`` as the 32-byte ML-DSA *seed*.
liboqs cannot derive a key pair from a seed (it has no seeded ML-DSA key
generation), so private JWKs go through the optional ``cryptography`` backend
(``cryptography >= 48``, ``pip install quantum-safe-py[pyca]``):
:meth:`StandardJwt.generate_private_jwk`, :meth:`StandardJwt.private_jwk`,
:meth:`StandardJwt.keypair_from_private_jwk`, and :meth:`StandardJwt.sign` with
a private JWK. A private JWK made by quantum-safe-ts signs here and the
reverse. Without that backend, plain ``KeyPair`` objects (expanded liboqs keys)
sign as before, and a private JWK from elsewhere cannot be used.

Verification is strict: the key's algorithm must equal the header ``alg``,
``crit`` headers are rejected, and the signature must be canonical unpadded
base64url (one spelling per signature).
"""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Any

from quantum_safe.exceptions import KeyParseError, UnsupportedAlgorithm, VerificationError
from quantum_safe.types import KeyPair, PublicKey, SecretKey

#: JOSE ``alg`` values for ML-DSA (RFC 9964).
ML_DSA_JOSE_ALGS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

_CLOCK_SKEW_SECONDS = 30
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode, restoring the padding. Does not require the canonical spelling."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_decode_strict(s: str) -> bytes:
    """Decode canonical unpadded base64url; anything else has a second spelling."""
    if not _B64URL.fullmatch(s):
        raise ValueError("not canonical base64url")
    raw = _b64url_decode(s)
    if _b64url_encode(raw) != s:
        raise ValueError("non-canonical base64url")
    return raw


def _json_b64(obj: Any) -> str:  # noqa: ANN401
    """Encode an object as compact JSON, then as unpadded base64url."""
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _decode_json(part: str, what: str) -> dict[str, Any]:
    """Decode a base64url JWT part to a JSON object; ``ValueError`` if it is not one."""
    try:
        value = json.loads(_b64url_decode(part).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Malformed JWT: could not decode the {what}.") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Malformed JWT: the {what} is not a JSON object.")
    return value


def _check_alg(alg: object) -> str:
    """Return ``alg`` if it is in ``ML_DSA_JOSE_ALGS``; otherwise raise ``UnsupportedAlgorithm``."""
    if not isinstance(alg, str) or alg not in ML_DSA_JOSE_ALGS:
        raise UnsupportedAlgorithm(str(alg), available=list(ML_DSA_JOSE_ALGS))
    return alg


def _backend() -> Any:  # noqa: ANN401
    """The signature backend (``"auto"``) used for the raw FIPS 204 sign and verify calls."""
    from quantum_safe.backends import get_signature_backend

    return get_signature_backend("auto")


def _public_parts(key: PublicKey | dict[str, Any]) -> tuple[str, bytes]:
    """(alg, raw public key bytes) from a PublicKey or an AKP JWK."""
    if isinstance(key, PublicKey):
        return _check_alg(key.algorithm), key.raw_bytes
    if not isinstance(key, dict):
        raise KeyParseError("jwk", f"expected a PublicKey or a JWK dict, got {type(key).__name__}")
    if key.get("kty") != "AKP":
        raise KeyParseError("jwk", f"'kty' must be 'AKP', got {key.get('kty')!r}")
    alg = _check_alg(key.get("alg"))
    pub = key.get("pub")
    if not isinstance(pub, str):
        raise KeyParseError("jwk", "missing or non-string 'pub'")
    try:
        return alg, _b64url_decode(pub)
    except Exception as exc:
        raise KeyParseError("jwk", f"base64url decode of 'pub' failed: {exc}") from exc


class StandardJwt:
    """RFC 9964 ML-DSA JWTs, verifiable by any compliant JOSE implementation."""

    @staticmethod
    def generate_keypair(alg: str = "ML-DSA-65") -> KeyPair:
        """Generate an ML-DSA signing key pair (``ML-DSA-44``, ``-65`` or ``-87``)."""
        from quantum_safe.signatures.core import Sign

        return Sign(_check_alg(alg)).generate_keypair()

    @staticmethod
    def public_jwk(
        public_key: PublicKey | dict[str, Any], kid: str | None = None
    ) -> dict[str, Any]:
        """The public key as an ``AKP`` JWK: ``{"kty": "AKP", "alg": ..., "pub": ...}``.

        ``public_key`` is a :class:`PublicKey`, or a private AKP JWK (a dict with ``priv``), from
        which the public JWK is derived and ``priv`` is dropped. ``kid`` defaults to the private
        JWK's own.
        """
        if isinstance(public_key, dict):
            keypair = StandardJwt.keypair_from_private_jwk(public_key)
            return StandardJwt.public_jwk(keypair.public, kid or public_key.get("kid"))
        alg = _check_alg(public_key.algorithm)
        jwk: dict[str, Any] = {
            "kty": "AKP",
            "alg": alg,
            "pub": _b64url_encode(public_key.raw_bytes),
        }
        if kid:
            jwk["kid"] = kid
        return jwk

    # -- private JWKs (the 32-byte seed): need the optional cryptography backend ----------------

    @staticmethod
    def generate_private_jwk(alg: str = "ML-DSA-65", kid: str | None = None) -> dict[str, Any]:
        """Generate an ML-DSA key and return it as a private ``AKP`` JWK (``priv`` is the seed).

        The result is a secret: store it as carefully as any private key. Needs the optional
        ``cryptography >= 48`` backend.
        """
        from quantum_safe.signatures.core import Sign

        keypair = Sign(_check_alg(alg), backend="pyca").generate_seed_keypair()
        return StandardJwt.private_jwk(keypair, kid=kid)

    @staticmethod
    def private_jwk(keypair: KeyPair, kid: str | None = None) -> dict[str, Any]:
        """The private ``AKP`` JWK of a seed key pair (see ``Sign.generate_seed_keypair``)."""
        _check_alg(keypair.secret.algorithm)
        seed = keypair.secret.raw_bytes
        if len(seed) != 32:
            raise ValueError(
                "this key is an expanded liboqs key; a private JWK needs a 32-byte seed key "
                "(Sign.generate_seed_keypair)"
            )
        jwk = StandardJwt.public_jwk(keypair.public, kid)
        jwk["priv"] = _b64url_encode(seed)
        return jwk

    @staticmethod
    def keypair_from_private_jwk(jwk: dict[str, Any]) -> KeyPair:
        """Rebuild the key pair of a private ``AKP`` JWK.

        Raises ``KeyParseError`` if the JWK is not an AKP private key, its ``priv`` is not a
        canonical 32-byte seed, or its ``pub`` does not match the seed.
        """
        from quantum_safe.signatures.core import Sign

        if not isinstance(jwk, dict):
            raise KeyParseError("jwk", f"expected a JWK dict, got {type(jwk).__name__}")
        if jwk.get("kty") != "AKP":
            raise KeyParseError("jwk", f"'kty' must be 'AKP', got {jwk.get('kty')!r}")
        alg = _check_alg(jwk.get("alg"))
        priv = jwk.get("priv")
        if not isinstance(priv, str):
            raise KeyParseError("jwk", "a private JWK needs a string 'priv' (the 32-byte seed)")
        try:
            seed = _b64url_decode_strict(priv)
        except ValueError as exc:
            raise KeyParseError("jwk", f"'priv' is not canonical base64url: {exc}") from exc
        if len(seed) != 32:
            raise KeyParseError("jwk", f"'priv' must be a 32-byte seed, got {len(seed)} bytes")
        keypair = Sign(alg, backend="pyca").keypair_from_seed(seed)
        pub = jwk.get("pub")
        if pub is not None:
            try:
                same = _b64url_decode(pub) == keypair.public.raw_bytes
            except Exception:  # noqa: BLE001
                same = False
            if not same:
                raise KeyParseError("jwk", "'pub' does not match the key derived from 'priv'")
        return keypair

    @staticmethod
    def sign(
        claims: dict[str, Any],
        secret_key: SecretKey | dict[str, Any],
        issuer: str | None = None,
        expires_in: int = 3600,
        kid: str | None = None,
    ) -> str:
        """Sign claims as a compact JWS whose ``alg`` is the key's ML-DSA level.

        Args:
            claims:     The claims. ``iss`` (if ``issuer``), ``iat`` and ``exp``
                        are added first and ``claims`` may override them.
            secret_key: An ML-DSA secret key (a plain ``Sign`` key, not hybrid), or a
                        private ``AKP`` JWK dict (needs the ``cryptography`` backend).
            issuer:     Added as the ``iss`` claim.
            expires_in: Lifetime in seconds (default 3600); ``0`` omits ``exp``.
            kid:        Added to the header when given. For a private JWK it defaults to the
                        JWK's own ``kid``.

        Returns:
            The compact JWS ``header.payload.signature``. The header is ``{"alg": <level>,
            "typ": "JWT"}`` (plus ``kid``) and the signature is a raw ML-DSA signature over
            ``header.payload`` with an empty context.

        Raises:
            UnsupportedAlgorithm: If the key is not an ML-DSA-44, -65 or -87 key.
            KeyParseError: If a private JWK is malformed.
            ValueError: If ``expires_in`` is negative or a bool.
        """
        if isinstance(secret_key, dict):
            if kid is None:
                kid = secret_key.get("kid")
            secret_key = StandardJwt.keypair_from_private_jwk(secret_key).secret
        alg = _check_alg(secret_key.algorithm)
        if isinstance(expires_in, bool) or expires_in < 0:
            raise ValueError(
                "expires_in must be a non-negative number of seconds (0 omits exp); "
                "a negative value would silently produce a token without exp"
            )
        now = int(time.time())
        full: dict[str, Any] = {}
        if issuer:
            full["iss"] = issuer
        full["iat"] = now
        if expires_in > 0:
            full["exp"] = now + int(expires_in)
        full.update(claims)

        header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
        if kid:
            header["kid"] = kid
        signing_input = f"{_json_b64(header)}.{_json_b64(full)}"
        sig = _backend().sign_native_context(
            alg, secret_key.raw_bytes, signing_input.encode("ascii"), b""
        )
        return f"{signing_input}.{_b64url_encode(sig)}"

    @staticmethod
    def verify(
        token: str,
        key: PublicKey | dict[str, Any],
        issuer: str | None = None,
        audience: str | None = None,
        validate_exp: bool = True,
        validate_nbf: bool = True,
        require_exp: bool = False,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Verify a compact JWS against ``key`` and return its claims.

        Args:
            token:        The JWT.
            key:          A ``PublicKey`` or an ``AKP`` JWK dict. Its algorithm
                          must equal the header ``alg``.
            issuer:       If set, ``iss`` must equal it.
            audience:     If set, ``aud`` (string or list) must contain it.
            validate_exp: Check ``exp`` when present (default True).
            validate_nbf: Check ``nbf`` when present (default True).
            require_exp:  Reject tokens without ``exp`` (default False;
                          recommended for anything that should expire).
            now:          Unix time to check against (default: the clock).

        Returns:
            The verified claims dict. ``exp`` and ``nbf`` are checked with a tolerance of 30
            seconds.

        Raises:
            ValueError:           the token is structurally malformed.
            UnsupportedAlgorithm: ``alg`` differs from the key's, or a ``crit``
                                  header is present.
            VerificationError:    the signature or a claim check fails.
        """
        alg, pub = _public_parts(key)
        if not isinstance(token, str):
            raise ValueError("token must be a string")
        parts = token.split(".")
        if len(parts) != 3 or any(not p for p in parts):
            raise ValueError(f"Malformed JWT: expected 3 non-empty parts, got {len(parts)}.")
        h, p, s = parts

        header = _decode_json(h, "header")
        if header.get("alg") != alg:
            raise UnsupportedAlgorithm(str(header.get("alg")), available=[alg])
        if "crit" in header:
            raise UnsupportedAlgorithm('JWS "crit" headers', available=[])
        claims = _decode_json(p, "payload")

        try:
            sig = _b64url_decode_strict(s)  # one spelling per signature
        except ValueError as exc:
            raise VerificationError(algo=alg) from exc
        ok = _backend().verify_native_context(alg, pub, f"{h}.{p}".encode("ascii"), sig, b"")
        if not ok:
            raise VerificationError(algo=alg)

        StandardJwt._check_claims(
            claims, issuer, audience, validate_exp, validate_nbf, require_exp, now, alg
        )
        return claims

    @staticmethod
    def _check_claims(
        claims: dict[str, Any],
        issuer: str | None,
        audience: str | None,
        validate_exp: bool,
        validate_nbf: bool,
        require_exp: bool,
        now: float | None,
        alg: str,
    ) -> None:
        """Check ``exp``, ``nbf``, ``iss`` and ``aud``; raise ``VerificationError`` on a failure.

        ``exp`` and ``nbf`` must be numbers (not bools) and are compared with a 30 second
        tolerance. The error does not say which check failed.
        """
        current = time.time() if now is None else now

        def number(value: object) -> bool:
            """True for an int or float that is not a bool."""
            return isinstance(value, (int, float)) and not isinstance(value, bool)

        # No detail on which check failed: callers can read the claims themselves.
        if require_exp and "exp" not in claims:
            raise VerificationError(algo=alg)
        if validate_exp and "exp" in claims:
            exp = claims["exp"]
            if not number(exp) or current > exp + _CLOCK_SKEW_SECONDS:
                raise VerificationError(algo=alg)
        if validate_nbf and "nbf" in claims:
            nbf = claims["nbf"]
            if not number(nbf) or current < nbf - _CLOCK_SKEW_SECONDS:
                raise VerificationError(algo=alg)
        if issuer is not None and claims.get("iss") != issuer:
            raise VerificationError(algo=alg)
        if audience is not None:
            aud = claims.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            if not isinstance(aud, list) or audience not in aud:
                raise VerificationError(algo=alg)
