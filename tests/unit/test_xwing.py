"""
X-Wing (draft-connolly-cfrg-xwing-kem): ML-KEM-768 + X25519 with a SHA3-256 combiner (audit item PY-X1).

Interoperability is pinned against quantum-safe-ts, whose X-Wing comes from the ``x-wing`` crate: the
vectors in ``tests/interop/vectors/xwing_vectors.json`` were written by it, and every one must
decapsulate here to the same shared secret and re-derive the same public key from its seed.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

pytestmark = pytest.mark.requires_liboqs

_FILE = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1] / "interop" / "vectors" / "xwing_vectors.json"
    ).read_text(encoding="utf-8")
)
VECTORS = _FILE["vectors"]
LOW_ORDER = _FILE["low_order"]


@pytest.fixture(scope="module")
def xwing():
    from quantum_safe.kem.xwing import XWing

    return XWing()


def test_sizes_and_name(xwing) -> None:
    kp = xwing.generate_keypair()
    assert kp.public.algorithm == kp.secret.algorithm == "X-Wing"
    assert len(kp.public.raw_bytes) == 1216
    assert len(kp.secret.raw_bytes) == 32
    ct, ss = xwing.encapsulate(kp.public)
    assert len(bytes(ct)) == 1120
    assert len(bytes(ss)) == 32


def test_roundtrip(xwing) -> None:
    kp = xwing.generate_keypair()
    ct, ss = xwing.encapsulate(kp.public)
    assert xwing.decapsulate(kp.secret, ct) == ss


def test_keypair_is_deterministic_from_the_seed(xwing) -> None:
    seed = bytes(range(32))
    a, b = xwing.keypair_from_seed(seed), xwing.keypair_from_seed(seed)
    assert a.public.raw_bytes == b.public.raw_bytes
    assert a.secret.raw_bytes == seed


def test_seed_must_be_32_bytes(xwing) -> None:
    for bad in (b"", b"\x00" * 31, b"\x00" * 33):
        with pytest.raises(ValueError, match="32"):
            xwing.keypair_from_seed(bad)


def test_modified_ciphertext_decapsulates_to_a_different_secret(xwing) -> None:
    """ML-KEM's implicit rejection: no error, and not the encapsulated secret."""
    kp = xwing.generate_keypair()
    ct, ss = xwing.encapsulate(kp.public)
    for pos in (0, 500, 1087, 1088, 1119):
        raw = bytearray(bytes(ct))
        raw[pos] ^= 1
        from quantum_safe.types.kem import CipherText

        got = xwing.decapsulate(kp.secret, CipherText(bytes(raw), "X-Wing"))
        assert got != ss


def test_wrong_lengths_are_rejected(xwing) -> None:
    from quantum_safe.types import PublicKey, SecretKey
    from quantum_safe.types.kem import CipherText

    kp = xwing.generate_keypair()
    ct, _ = xwing.encapsulate(kp.public)
    with pytest.raises(ValueError):
        xwing.decapsulate(kp.secret, CipherText(bytes(ct)[:-1], "X-Wing"))
    with pytest.raises(ValueError):
        xwing.decapsulate(SecretKey(b"\x01" * 31, "X-Wing"), ct)
    with pytest.raises(ValueError):
        PublicKey(b"\x01" * 1215, "X-Wing")


def test_a_key_of_another_algorithm_is_refused(xwing) -> None:
    from quantum_safe.exceptions import UnsupportedAlgorithm
    from quantum_safe.kem.hybrid import HybridKEM

    other = HybridKEM().generate_keypair()
    with pytest.raises(UnsupportedAlgorithm):
        xwing.encapsulate(other.public)


def test_key_serialization_roundtrip(xwing) -> None:
    from quantum_safe.types import PublicKey, SecretKey

    kp = xwing.generate_keypair()
    pub = PublicKey.from_pem(kp.public.to_pem())
    sec = SecretKey.from_pem(kp.secret.to_pem())
    assert pub.algorithm == sec.algorithm == "X-Wing"
    ct, ss = xwing.encapsulate(pub)
    assert xwing.decapsulate(sec, ct) == ss


def test_combiner_matches_the_specification_form(xwing) -> None:
    """ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || label), the label being the six bytes \\.//^\\ ."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from quantum_safe.kem.xwing import _LABEL, _expand

    assert _LABEL == bytes([0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C])
    kp = xwing.generate_keypair()
    ct, ss = xwing.encapsulate(kp.public)
    raw_ct = bytes(ct)
    ct_m, ct_x = raw_ct[:1088], raw_ct[1088:]
    d_z, sk_x = _expand(kp.secret.raw_bytes)
    from quantum_safe.backends import get_kem_backend

    ss_m = get_kem_backend("auto").decapsulate("ML-KEM-768", _mlkem_sk(d_z), ct_m)
    pk_x = kp.public.raw_bytes[1184:]
    ss_x = X25519PrivateKey.from_private_bytes(sk_x).exchange(
        __import__(
            "cryptography.hazmat.primitives.asymmetric.x25519", fromlist=["X25519PublicKey"]
        ).X25519PublicKey.from_public_bytes(ct_x)
    )
    assert hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _LABEL).digest() == bytes(ss)


def _mlkem_sk(d_z: bytes) -> bytes:
    import oqs

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem.generate_keypair_seed(d_z)
        return bytes(kem.export_secret_key())


class TestInteropWithTypeScript:
    @pytest.mark.parametrize("i", range(len(VECTORS)))
    def test_decapsulates_what_typescript_encapsulated(self, xwing, i: int) -> None:
        from quantum_safe.types import SecretKey
        from quantum_safe.types.kem import CipherText

        v = VECTORS[i]
        sk = SecretKey(bytes.fromhex(v["secret_key"]), "X-Wing")
        got = xwing.decapsulate(sk, CipherText(bytes.fromhex(v["ciphertext"]), "X-Wing"))
        assert bytes(got) == bytes.fromhex(v["shared_secret"])

    @pytest.mark.parametrize("i", range(len(VECTORS)))
    def test_derives_the_same_public_key_from_the_seed(self, xwing, i: int) -> None:
        v = VECTORS[i]
        kp = xwing.keypair_from_seed(bytes.fromhex(v["secret_key"]))
        assert kp.public.raw_bytes == bytes.fromhex(v["public_key"])

    @pytest.mark.parametrize("i", range(len(LOW_ORDER)))
    def test_low_order_x25519_point_gives_the_same_secret_as_typescript(
        self, xwing, i: int
    ) -> None:
        """X25519 maps a low-order point to all zeros; X-Wing neither rejects it nor errors."""
        from quantum_safe.types import SecretKey
        from quantum_safe.types.kem import CipherText

        v = LOW_ORDER[i]
        assert bytes.fromhex(v["ciphertext"])[1088:] == bytes(32)
        sk = SecretKey(bytes.fromhex(v["secret_key"]), "X-Wing")
        got = xwing.decapsulate(sk, CipherText(bytes.fromhex(v["ciphertext"]), "X-Wing"))
        assert bytes(got) == bytes.fromhex(v["shared_secret"])

    def test_vector_file_is_not_vacuous(self) -> None:
        assert len(LOW_ORDER) >= 3
        assert len(VECTORS) >= 12
        assert len({v["public_key"] for v in VECTORS}) >= 6
