"""All twelve FIPS 205 SLH-DSA parameter sets are available (audit item PY-S1).

FIPS 205 defines 12 sets: 2 hash families (SHA2, SHAKE) x 3 security levels (128, 192, 256) x 2
variants ("s" small signature / slow signing, "f" fast signing / larger signature). The registry
used to list three of them although the backend mapped all twelve. Sizes below are what liboqs
0.16.0 reports for each ``SLH_DSA_PURE_*`` mechanism, which equal FIPS 205 Table 2.
"""

from __future__ import annotations

import pytest

from quantum_safe.signatures.algorithms import SIGNATURE_ALGORITHMS, NISTLevel

# name: (public key, secret key, signature, NIST level)
FIPS_205 = {
    "128s": (32, 64, 7856, 1),
    "128f": (32, 64, 17088, 1),
    "192s": (48, 96, 16224, 3),
    "192f": (48, 96, 35664, 3),
    "256s": (64, 128, 29792, 5),
    "256f": (64, 128, 49856, 5),
}
NAMES = {f"SLH-DSA-{fam}-{v}": FIPS_205[v] for fam in ("SHAKE", "SHA2") for v in FIPS_205}


def test_twelve_sets_in_the_registry() -> None:
    present = {n for n in SIGNATURE_ALGORITHMS if n.startswith("SLH-DSA-")}
    assert present == set(NAMES)
    assert len(present) == 12


@pytest.mark.parametrize("name", sorted(NAMES))
def test_registry_sizes_and_level(name: str) -> None:
    pk, sk, sig, level = NAMES[name]
    spec = SIGNATURE_ALGORITHMS[name]
    assert (spec.public_key_bytes, spec.secret_key_bytes, spec.signature_bytes) == (pk, sk, sig)
    assert spec.nist_level == NISTLevel(level)
    assert spec.is_nist_standard is True and spec.is_lattice_based is False
    assert spec.supports_context is True
    assert spec.sign_speed == ("slow" if name.endswith("s") else "medium")


@pytest.mark.parametrize("name", sorted(NAMES))
def test_backend_info_and_liboqs_name(name: str) -> None:
    from quantum_safe.backends.liboqs import _SIG_LIBOQS_NAMES, _SIGNATURE_ALGORITHM_INFO

    fam, variant = name.split("-")[2], name.split("-")[3]
    assert _SIG_LIBOQS_NAMES[name] == f"SLH_DSA_PURE_{fam}_{variant.upper()}"
    info = _SIGNATURE_ALGORITHM_INFO[name]
    pk, sk, sig, level = NAMES[name]
    assert (info.public_key_size, info.secret_key_size, info.ciphertext_size) == (pk, sk, sig)
    assert info.nist_level == level and info.is_nist_standard is True


@pytest.mark.parametrize("name", sorted(NAMES))
def test_key_size_tables_know_every_set(name: str) -> None:
    from quantum_safe.types.keys import _KNOWN_PUBLIC_KEY_SIZES, _KNOWN_SECRET_KEY_SIZES

    pk, sk, *_ = NAMES[name]
    assert _KNOWN_PUBLIC_KEY_SIZES[name] == pk
    assert _KNOWN_SECRET_KEY_SIZES[name] == sk


@pytest.mark.requires_liboqs
@pytest.mark.parametrize("name", sorted(n for n in NAMES if n.endswith("f")))
def test_fast_sets_sign_and_verify_with_the_standard_pair(name: str) -> None:
    from quantum_safe.exceptions import VerificationError
    from quantum_safe.signatures.core import Sign

    s = Sign(name)
    kp = s.generate_keypair()
    sig = s.sign_standard(b"message", kp.secret, context=b"ctx")
    assert len(sig) == NAMES[name][2]
    s.verify_standard(b"message", sig, kp.public, context=b"ctx")
    with pytest.raises(VerificationError):
        s.verify_standard(b"message!", sig, kp.public, context=b"ctx")


@pytest.mark.requires_liboqs
@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(n for n in NAMES if n.endswith("s")))
def test_small_sets_sign_and_verify_with_the_standard_pair(name: str) -> None:
    from quantum_safe.signatures.core import Sign

    s = Sign(name)
    kp = s.generate_keypair()
    sig = s.sign_standard(b"message", kp.secret, context=b"ctx")
    assert len(sig) == NAMES[name][2]
    s.verify_standard(b"message", sig, kp.public, context=b"ctx")
