"""
quantum_safe.protocols.jwt
~~~~~~~~~~~~~~~~~~~~~~~~~~~

PQC-aware JSON Web Token (JWT) support.

Algorithm identifiers follow draft-ietf-jose-pqc-signatures, which defines
algorithm strings for use in the JWT `alg` header:

  ML-DSA-44       → "ML-DSA-44"  (FIPS 204, level 2)
  ML-DSA-65       → "ML-DSA-65"  (FIPS 204, level 3)
  ML-DSA-87       → "ML-DSA-87"  (FIPS 204, level 5)
  Ed25519+ML-DSA-65 → "Ed25519+ML-DSA-65"  (hybrid)

We deliberately do NOT support:
  - Symmetric algorithms (HS256, HS512) — no key exchange semantics
  - RSA algorithms (RS256, PS384) — being phased out
  - ECDSA (ES256, ES384) — our hybrid covers this via Ed25519 component

This module is intentionally minimal: it covers the most common JWT use case
(stateless bearer tokens) without trying to implement the full JOSE suite.
For encrypted JWTs (JWE), use quantum_safe.protocols.envelope instead.

Token format
------------
Standard JWT: base64url(header) || "." || base64url(payload) || "." || base64url(signature)

Header: {"alg": "ML-DSA-65", "typ": "JWT", "qs-version": 1}

The `qs-version` header field lets verifiers detect our tokens and validate
them with the right logic, even if the token is processed by a generic JWT
library that doesn't know about PQC algorithms.

Hedged signing
--------------
By default, JWTs are signed in hedged mode (random prefix prepended to the
signing input). This is different from standard JWT signing, where the input
is deterministic. The hedged prefix is NOT stored in the JWT — it's embedded
in the signature blob using Sign._pack_sig_blob format.

The tradeoff: hedged JWTs cannot be verified by standard JWT libraries.
They can only be verified by quantum-safe. If you need interoperability
with standard JWT verifiers, pass hedged=False, but understand that this
removes fault-injection protection.

Expiration and claims
---------------------
We validate standard claims: exp (expiration), nbf (not before), iss (issuer).
Additional claim validation is the caller's responsibility.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, cast

from quantum_safe.exceptions import UnsupportedAlgorithm, VerificationError
from quantum_safe.signatures.core import Sign
from quantum_safe.signatures.hybrid import HybridSign
from quantum_safe.types import KeyPair, PublicKey
from quantum_safe.types.signatures import SignedMessage

# JWT version tag embedded in the header
_QS_JWT_VERSION = 1

# The separator used in JWT encoding
_JWT_SEP = "."

# Maximum clock skew tolerance in seconds for nbf/exp validation
_CLOCK_SKEW_SECONDS = 30


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _json_b64(obj: Any) -> str:  # noqa: ANN401
    """Encode a dict as compact JSON then base64url."""
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


class JWTSigner:
    """Signs JWTs using PQC or hybrid signature algorithms.

    Args:
        keypair:    The signing keypair. Algorithm is inferred from the key.
        hedged:     Use hedged signing mode (default True). See module docstring.
        issuer:     Optional issuer string to embed in tokens as the `iss` claim.
        backend:    Signature backend: "auto", "liboqs", "rustcrypto".

    Example::

        signer = JWTSigner(keypair, issuer="auth.myapp.com")
        token  = signer.sign({"sub": "user123", "role": "admin"})
        # → "eyJhbGci..."

        verifier = JWTVerifier(public_key)
        claims   = verifier.verify(token)
        # → {"sub": "user123", "role": "admin", "iss": "auth.myapp.com", ...}
    """

    def __init__(
        self,
        keypair: KeyPair,
        hedged: bool = True,
        issuer: str | None = None,
        backend: str = "auto",
    ) -> None:
        self._keypair = keypair
        self._hedged = hedged
        self._issuer = issuer
        self._algorithm = keypair.algorithm
        self._signer = self._build_signer(keypair.algorithm, hedged, backend)

    def _build_signer(self, algorithm: str, hedged: bool, backend: str) -> Sign | HybridSign:
        """Create the right signer for the given algorithm."""
        if "+" in algorithm:
            # Hybrid algorithm — use the normal constructor so that
            # validate_hybrid_combination() is called and unapproved
            # classical+PQC combinations are rejected.
            from quantum_safe.signatures.algorithms import parse_hybrid_name

            classical, pqc = parse_hybrid_name(algorithm)
            return HybridSign(classical=classical, pqc=pqc, hedged=hedged, backend=backend)
        else:
            # Single PQC algorithm
            return Sign(algorithm=algorithm, hedged=hedged, backend=backend)

    def sign(
        self,
        claims: dict[str, Any],
        expires_in: int = 3600,
        context: bytes = b"jwt",
    ) -> str:
        """Sign a claims dict and return a JWT string.

        Args:
            claims:      Dict of JWT claims. Standard claims (iss, iat, exp)
                         are added automatically.
            expires_in:  Token lifetime in seconds. Default 1 hour.
                         Pass 0 to omit exp (not recommended).
            context:     Signing context for domain separation.
                         Default b"jwt" — override to prevent cross-purpose reuse.

        Returns:
            JWT string in the form "header.payload.signature".
        """
        now = int(time.time())

        # Merge standard claims with caller-supplied claims.
        # Caller claims take precedence except for iat.
        full_claims: dict[str, Any] = {}
        if self._issuer:
            full_claims["iss"] = self._issuer
        full_claims["iat"] = now
        if expires_in > 0:
            full_claims["exp"] = now + expires_in
        full_claims.update(claims)  # caller claims override

        header = {
            "alg": self._algorithm,
            "typ": "JWT",
            "qs-version": _QS_JWT_VERSION,
        }

        header_b64 = _json_b64(header)
        payload_b64 = _json_b64(full_claims)
        signing_input = f"{header_b64}{_JWT_SEP}{payload_b64}".encode("ascii")

        # Sign the header.payload bytes
        sm = self._signer.sign(signing_input, self._keypair.secret, context=context)

        # The JWT signature part is the raw sig_blob, base64url-encoded
        sig_b64 = _b64url_encode(sm.signature)

        return f"{header_b64}{_JWT_SEP}{payload_b64}{_JWT_SEP}{sig_b64}"

    @property
    def algorithm(self) -> str:
        return self._algorithm


class JWTVerifier:
    """Verifies PQC/hybrid JWTs.

    Args:
        public_key:   The signer's public key. Algorithm is inferred from it.
        issuer:       If set, the `iss` claim must match this value.
        audience:     If set, the `aud` claim must include this value.
        backend:      Signature backend.

    Example::

        verifier = JWTVerifier(public_key, issuer="auth.myapp.com")
        claims   = verifier.verify(token)
        user_id  = claims["sub"]
    """

    def __init__(
        self,
        public_key: PublicKey,
        issuer: str | None = None,
        audience: str | None = None,
        backend: str = "auto",
    ) -> None:
        self._public_key = public_key
        self._issuer = issuer
        self._audience = audience
        self._algorithm = public_key.algorithm
        self._verifier = self._build_verifier(public_key.algorithm, backend)

    def _build_verifier(self, algorithm: str, backend: str) -> Sign | HybridSign:
        if "+" in algorithm:
            # Use the normal constructor to ensure validate_hybrid_combination()
            # runs and unapproved algorithm pairs are rejected.
            from quantum_safe.signatures.algorithms import parse_hybrid_name

            classical, pqc = parse_hybrid_name(algorithm)
            return HybridSign(classical=classical, pqc=pqc, backend=backend)
        else:
            return Sign(algorithm=algorithm, backend=backend)

    def verify(
        self,
        token: str,
        context: bytes = b"jwt",
        validate_exp: bool = True,
        validate_nbf: bool = True,
    ) -> dict[str, Any]:
        """Verify a JWT and return its claims.

        Args:
            token:        JWT string from JWTSigner.sign().
            context:      Signing context. Must match what was used to sign.
            validate_exp: Check expiration (default True).
            validate_nbf: Check not-before (default True).

        Returns:
            Verified claims dict.

        Raises:
            VerificationError:    If the signature is invalid or claims fail.
            ValueError:           If the token is structurally malformed.
        """
        parts = token.split(_JWT_SEP)
        if len(parts) != 3:
            raise ValueError(f"Malformed JWT: expected 3 parts, got {len(parts)}")

        header_b64, payload_b64, sig_b64 = parts

        # Decode header
        try:
            header = json.loads(_b64url_decode(header_b64))
        except Exception as exc:
            raise ValueError(f"Failed to decode JWT header: {exc}") from exc

        # Check algorithm matches
        token_algo = header.get("alg")
        if token_algo != self._algorithm:
            raise UnsupportedAlgorithm(
                str(token_algo),
                available=[self._algorithm],
            )

        # Decode payload (claims)
        try:
            claims = json.loads(_b64url_decode(payload_b64))
        except Exception as exc:
            raise ValueError(f"Failed to decode JWT payload: {exc}") from exc

        # Rebuild the signing input
        signing_input = f"{header_b64}{_JWT_SEP}{payload_b64}".encode("ascii")

        # Decode signature blob
        try:
            sig_blob = _b64url_decode(sig_b64)
        except Exception as exc:
            raise VerificationError(algo=self._algorithm) from exc

        # Reconstruct a SignedMessage and verify
        sm = SignedMessage(
            message=signing_input,
            signature=sig_blob,
            algorithm=self._algorithm,
            context=context,
        )

        # This raises VerificationError if invalid
        self._verifier.verify(sm, self._public_key)

        # Validate standard claims
        now = time.time()

        if validate_exp and "exp" in claims:
            if now > claims["exp"] + _CLOCK_SKEW_SECONDS:
                raise VerificationError(
                    algo=self._algorithm,
                    # Don't embed "token expired" — a timing oracle could
                    # use this. Callers can check claims["exp"] themselves.
                )

        if validate_nbf and "nbf" in claims:
            if now < claims["nbf"] - _CLOCK_SKEW_SECONDS:
                raise VerificationError(algo=self._algorithm)

        if self._issuer is not None:
            if claims.get("iss") != self._issuer:
                raise VerificationError(algo=self._algorithm)

        if self._audience is not None:
            aud = claims.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            if self._audience not in aud:
                raise VerificationError(algo=self._algorithm)

        return cast(dict[str, Any], claims)

    @property
    def algorithm(self) -> str:
        return self._algorithm
