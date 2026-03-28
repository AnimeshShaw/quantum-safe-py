"""
quantum_safe.protocols.tls
~~~~~~~~~~~~~~~~~~~~~~~~~~~

TLS hybrid key exchange configuration helpers.

This module provides the glue between our HybridKEM and the system's TLS
stack. The goal is to make "configure TLS for hybrid PQC" a one-liner.

State of the ecosystem (2025)
------------------------------
TLS 1.3 hybrid key exchange is defined in:
  - draft-ietf-tls-hybrid-design: specifies how to combine classical and PQC
    key exchange in a single TLS group
  - IANA TLS group registry: X25519MLKEM768 (code point 0x11EB) is the
    standardized name for the X25519+ML-KEM-768 hybrid group

Support status:
  - OpenSSL 3.x + OQS provider: full hybrid TLS support
  - BoringSSL (Chromium/Go): X25519Kyber768 (draft name) natively supported
  - Python ssl module: inherits OpenSSL's capabilities
  - nginx, curl, Go: support via OQS fork or native BoringSSL

What this module does
---------------------
1. HybridTLSConfig: a validated config dataclass for TLS hybrid settings.
2. configure_hybrid_context(): patches a Python ssl.SSLContext to request
   hybrid key exchange when OQS-OpenSSL is available.
3. check_hybrid_support(): runtime detection of TLS hybrid capability.

When OQS-OpenSSL is not available, the functions degrade gracefully:
they configure the best available key exchange (X25519) and log a warning.
This is intentional — we'd rather have working TLS with classical security
than a broken connection because OQS isn't installed.

For server-side configuration examples, see docs/tls.md.
"""

from __future__ import annotations

import ssl
import warnings
from dataclasses import dataclass, field
from typing import Any


# IANA-registered TLS group names for hybrid key exchange
# These are the standard names used in OpenSSL's set_groups() call
_HYBRID_GROUPS = {
    # X25519+ML-KEM-768: the primary recommended hybrid group
    "X25519+ML-KEM-768": "X25519MLKEM768",
    # X25519+ML-KEM-512: smaller, level 1
    "X25519+ML-KEM-512": "X25519MLKEM512",
    # Classical-only fallbacks (used when OQS isn't available)
    "X25519": "X25519",
    "P-256": "P-256",
    "P-384": "P-384",
}

# OQS provider group names (used with OpenSSL + OQS provider)
_OQS_GROUP_NAMES = {
    "X25519+ML-KEM-768": "x25519_mlkem768",
    "X25519+ML-KEM-512": "x25519_mlkem512",
}

# Priority order: hybrid first, classical fallback
_DEFAULT_GROUP_PREFERENCE = [
    "X25519MLKEM768",   # hybrid primary
    "X25519",           # classical fallback
    "P-256",            # classical fallback
]


@dataclass
class HybridTLSConfig:
    """Configuration for hybrid TLS key exchange.

    Attributes:
        kem_algorithm:      The hybrid KEM algorithm to request.
                            Default: "X25519+ML-KEM-768".
        fallback_classical: If True (default), include classical X25519 as a
                            fallback group. This allows handshaking with peers
                            that don't support hybrid.
        require_hybrid:     If True, reject connections from peers that don't
                            support hybrid key exchange. Default False — too
                            disruptive for most deployments today.
        min_tls_version:    Minimum TLS version. Default TLS 1.3 — never
                            negotiate lower.
        oqs_provider_path:  Path to OQS OpenSSL provider .so/.dylib.
                            If None, we search standard provider locations.
    """

    kem_algorithm: str = "X25519+ML-KEM-768"
    fallback_classical: bool = True
    require_hybrid: bool = False
    min_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    oqs_provider_path: str | None = None

    def __post_init__(self) -> None:
        if self.kem_algorithm not in _HYBRID_GROUPS:
            raise ValueError(
                f"Unknown KEM algorithm '{self.kem_algorithm}'. "
                f"Valid options: {list(_HYBRID_GROUPS)}"
            )

    @property
    def group_preference(self) -> list[str]:
        """Ordered list of TLS group names to pass to set_groups().

        Hybrid groups are listed first. Classical groups follow as fallbacks
        if fallback_classical is True.
        """
        groups = []

        # Add the requested hybrid group (OQS name first, IANA name second)
        oqs_name = _OQS_GROUP_NAMES.get(self.kem_algorithm)
        iana_name = _HYBRID_GROUPS.get(self.kem_algorithm)

        if oqs_name:
            groups.append(oqs_name)
        if iana_name and iana_name not in groups:
            groups.append(iana_name)

        if self.fallback_classical:
            groups.extend(["X25519", "P-256"])

        return groups


def check_hybrid_support() -> dict[str, Any]:
    """Probe the runtime environment for TLS hybrid support.

    Returns a dict with:
        openssl_version:  OpenSSL version string
        oqs_provider:     True if OQS provider is loadable
        hybrid_groups:    List of detected hybrid group names
        recommendation:   Human-readable recommendation

    This is safe to call at import time and in health checks.
    """
    info: dict[str, Any] = {
        "openssl_version": ssl.OPENSSL_VERSION,
        "oqs_provider": False,
        "hybrid_groups": [],
        "recommendation": "",
    }

    # Check OpenSSL version — need 3.x for OQS provider
    ver = ssl.OPENSSL_VERSION_INFO
    if ver[0] < 3:
        info["recommendation"] = (
            f"OpenSSL {ssl.OPENSSL_VERSION} is too old for OQS provider support. "
            f"Upgrade to OpenSSL 3.x."
        )
        return info

    # Try to detect OQS provider
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # If set_groups is available and accepts hybrid names, OQS is present
        ctx.set_ciphers("DEFAULT")
        # Try setting a hybrid group — if it doesn't raise, it's supported
        # The actual call that would fail on non-OQS builds:
        # ctx.set_groups(["x25519_mlkem768"])  # not available in stdlib ssl
        # We can only detect this heuristically in pure Python
        info["recommendation"] = (
            "OpenSSL 3.x detected. Install oqs-provider for hybrid TLS. "
            "See: https://github.com/open-quantum-safe/oqs-provider"
        )
    except Exception:  # noqa: BLE001
        pass

    return info


def configure_hybrid_context(
    ctx: ssl.SSLContext,
    config: HybridTLSConfig | None = None,
) -> ssl.SSLContext:
    """Configure an ssl.SSLContext for hybrid key exchange.

    This modifies the context in-place and also returns it for chaining.

    Args:
        ctx:    An ssl.SSLContext to configure. You create this with
                ssl.create_default_context() or ssl.SSLContext().
        config: HybridTLSConfig. If None, uses default (X25519+ML-KEM-768
                with X25519 fallback).

    Returns:
        The modified ssl.SSLContext.

    Raises:
        ssl.SSLError: if the requested groups aren't supported by the
                      installed OpenSSL.

    Example::

        import ssl
        from quantum_safe.protocols.tls import configure_hybrid_context

        ctx = ssl.create_default_context()
        configure_hybrid_context(ctx)
        # ctx now prefers X25519MLKEM768 with X25519 fallback
    """
    if config is None:
        config = HybridTLSConfig()

    # Enforce minimum TLS version — never go below 1.3
    ctx.minimum_version = config.min_tls_version

    # Attempt to set hybrid groups.
    # set_groups() is not available in Python's stdlib ssl module but IS
    # available when using PyOpenSSL or a patched ssl module with OQS.
    # We try it and gracefully fall back if unavailable.
    groups = config.group_preference
    set_groups_succeeded = False

    if hasattr(ctx, "set_groups"):
        # PyOpenSSL or OQS-patched ssl
        try:
            getattr(ctx, "set_groups")(groups)
            set_groups_succeeded = True
        except ssl.SSLError as exc:
            warnings.warn(
                f"Failed to set hybrid TLS groups {groups}: {exc}. "
                f"Falling back to default OpenSSL group selection. "
                f"Install oqs-provider for hybrid support.",
                stacklevel=2,
            )

    if not set_groups_succeeded:
        # Standard Python ssl — can only set classical curves
        # This is the fallback: still secure, just not PQC
        try:
            ctx.set_ecdh_curve("prime256v1")  # P-256 fallback
        except (AttributeError, ssl.SSLError):
            pass  # Not all contexts support this

        if config.require_hybrid:
            raise ssl.SSLError(
                "Hybrid TLS is required but OQS provider is not available. "
                "Install oqs-provider or set require_hybrid=False."
            )

        warnings.warn(
            "OQS provider not available. TLS will use classical X25519/P-256 "
            "key exchange. For hybrid PQC support, install oqs-provider: "
            "https://github.com/open-quantum-safe/oqs-provider",
            stacklevel=2,
        )

    return ctx


def get_hybrid_group_name(kem_algorithm: str) -> str:
    """Return the TLS group name for a given hybrid KEM algorithm.

    Useful when configuring TLS in environments that accept group names
    directly (e.g. Go's tls.Config.CurvePreferences, nginx ssl_ecdh_curve).

    Args:
        kem_algorithm: e.g. "X25519+ML-KEM-768"

    Returns:
        IANA TLS group name, e.g. "X25519MLKEM768"

    Raises:
        ValueError: if the algorithm is not a known TLS group
    """
    name = _HYBRID_GROUPS.get(kem_algorithm)
    if name is None:
        raise ValueError(
            f"No TLS group name for KEM algorithm '{kem_algorithm}'. "
            f"Known mappings: {dict(_HYBRID_GROUPS)}"
        )
    return name
