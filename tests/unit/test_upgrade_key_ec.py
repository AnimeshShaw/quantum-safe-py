"""``qs-migrate upgrade-key`` for P-256 and P-384 PKCS#8 keys (a CNSA 1.0 estate holds P-384)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from quantum_safe import HybridKEM, HybridSign
from quantum_safe.migrate.keyfile import KeyUpgradeError, upgrade_key_file
from quantum_safe.types import PublicKey, SecretKey

pytestmark = pytest.mark.requires_liboqs


def _pem(tmp_path, curve):
    path = tmp_path / "ec.pem"
    key = generate_private_key(curve())
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return path


@pytest.mark.parametrize(
    ("curve", "kem_target", "sign_target"),
    [
        (SECP384R1, "P-384+ML-KEM-1024", "P-384+ML-DSA-87-v2"),
        (SECP256R1, "P-256+ML-KEM-768", "P-256+ML-DSA-65-v2"),
    ],
)
def test_an_ec_key_upgrades_to_a_working_kem_or_signing_key(
    tmp_path, curve, kem_target, sign_target
) -> None:
    src = _pem(tmp_path, curve)

    done = upgrade_key_file(src, tmp_path / "kem.pem", key_type="kem")
    assert done.new_algorithm == kem_target and done.key_type == "kem"
    pub = PublicKey.from_pem((tmp_path / "kem.pem.pub").read_text(encoding="ascii"))
    sec = SecretKey.from_pem((tmp_path / "kem.pem").read_text(encoding="ascii"))
    classical, pqc = kem_target.split("+")
    kem = HybridKEM(classical, pqc)
    ct, secret = kem.encapsulate(pub)
    assert kem.decapsulate(sec, ct) == secret

    done = upgrade_key_file(src, tmp_path / "sign.pem", key_type="sign")
    assert done.new_algorithm == sign_target and done.key_type == "sign"
    pub = PublicKey.from_pem((tmp_path / "sign.pem.pub").read_text(encoding="ascii"))
    sec = SecretKey.from_pem((tmp_path / "sign.pem").read_text(encoding="ascii"))
    classical, pqc = sign_target.split("+")
    signer = HybridSign(classical, pqc)
    signer.verify(signer.sign(b"migrated", sec), pub)


def test_an_ec_key_needs_to_be_told_what_it_is_for(tmp_path) -> None:
    src = _pem(tmp_path, SECP384R1)
    with pytest.raises(KeyUpgradeError, match="--key-type"):
        upgrade_key_file(src, tmp_path / "out.pem")
    assert not (tmp_path / "out.pem").exists()


def test_the_original_key_is_untouched(tmp_path) -> None:
    src = _pem(tmp_path, SECP384R1)
    before = src.read_bytes()
    upgrade_key_file(src, tmp_path / "out.pem", key_type="kem")
    assert src.read_bytes() == before


def test_a_target_that_changes_the_curve_is_refused(tmp_path) -> None:
    src = _pem(tmp_path, SECP384R1)
    with pytest.raises(KeyUpgradeError):
        upgrade_key_file(src, tmp_path / "out.pem", key_type="kem", target="P-256+ML-KEM-768")
