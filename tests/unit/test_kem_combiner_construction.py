"""Pin the hybrid KEM combiner (finding D2).

The combiner is a library-specific HKDF construction, not the TLS 1.3 hybrid
groups' plain concatenation (RFC 10024) and not X-Wing. Recomputing it from
the documented formula guards both the wire format and the docstrings.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from quantum_safe.types import combine_shared_secrets


def _documented(ss_c: bytes, ss_p: bytes, algo: str, ct_c: bytes, ct_p: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ct_c + ct_p,
        info=b"quantum-safe hybrid KEM v1" + b"\x00" + algo.encode("ascii"),
    ).derive(ss_c + ss_p)


def test_combiner_matches_documented_formula() -> None:
    ss_c, ss_p = b"\x11" * 32, b"\x22" * 32
    ct_c, ct_p = b"\x33" * 32, b"\x44" * 1088
    algo = "X25519+ML-KEM-768"
    got = combine_shared_secrets(ss_c, ss_p, algo, ct_c, ct_p)
    assert bytes(got) == _documented(ss_c, ss_p, algo, ct_c, ct_p)


def test_combiner_is_not_plain_concatenation() -> None:
    ss_c, ss_p = b"\x11" * 32, b"\x22" * 32
    got = bytes(combine_shared_secrets(ss_c, ss_p, "X25519+ML-KEM-768", b"a", b"b"))
    assert got not in (ss_c + ss_p, ss_p + ss_c)
    assert len(got) == 32
