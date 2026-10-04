"""Pin what the ML-DSA half of a signature actually signs (finding D1).

The context is bound by a message prefix, not by FIPS 204's native context:
the signature is plain ML-DSA with an empty FIPS 204 context over
``len(ctx) || ctx || prefix || message``. This is the wire format; if it ever
changes, previously issued signatures stop verifying, so this test must fail
loudly rather than the docstrings drifting out of date.
"""

from __future__ import annotations

import warnings

import pytest

from quantum_safe.signatures.core import Sign

pytestmark = pytest.mark.requires_liboqs


@pytest.mark.parametrize("hedged", [True, False])
@pytest.mark.parametrize("ctx", [b"", b"app-v1"])
def test_ml_dsa_signs_prefixed_bytes_with_empty_native_context(hedged: bool, ctx: bytes) -> None:
    import oqs

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        signer = Sign("ML-DSA-44", hedged=hedged)
    kp = signer.generate_keypair()
    sm = signer.sign(b"hello", kp.secret, context=ctx)
    plen = sm.signature[0]
    prefix = sm.signature[1 : 1 + plen]
    raw = sm.signature[1 + plen :]
    signed_bytes = bytes([len(ctx)]) + ctx + prefix + b"hello"

    v = oqs.Signature("ML-DSA-44")
    assert v.verify(signed_bytes, raw, kp.public.raw_bytes)
    if ctx and hasattr(v, "verify_with_ctx_str"):
        # Not FIPS 204's native context.
        assert not v.verify_with_ctx_str(prefix + b"hello", raw, ctx, kp.public.raw_bytes)
