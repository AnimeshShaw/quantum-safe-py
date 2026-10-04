"""Registry sizes must equal what the backend actually produces (finding D3).

All three ML-DSA parameter sets listed round-3 Dilithium sizes instead of
FIPS 204's (secret keys 2528/4000/4864 instead of 2560/4032/4896; signatures
3293/4595 instead of 3309/4627 for ML-DSA-65/87), in the signature registry,
both backends' AlgorithmInfo and the secret-key size table. Keys were still
correct because they come from liboqs; only the reported numbers were wrong.
These tests compare every table against liboqs.
"""

from __future__ import annotations

import pytest

from quantum_safe.backends.liboqs import _KEM_LIBOQS_NAMES, _SIG_LIBOQS_NAMES
from quantum_safe.kem.algorithms import KEM_ALGORITHMS
from quantum_safe.signatures.algorithms import SIGNATURE_ALGORITHMS

pytestmark = pytest.mark.requires_liboqs


def _enabled_sigs() -> set[str]:
    import oqs

    return set(oqs.get_enabled_sig_mechanisms())


def _enabled_kems() -> set[str]:
    import oqs

    return set(oqs.get_enabled_kem_mechanisms())


@pytest.mark.parametrize("name", sorted(SIGNATURE_ALGORITHMS))
def test_signature_registry_sizes_match_liboqs(name: str) -> None:
    import oqs

    liboqs_name = _SIG_LIBOQS_NAMES.get(name, name)
    if liboqs_name not in _enabled_sigs():
        pytest.skip(f"{liboqs_name} not enabled in this liboqs build")
    spec = SIGNATURE_ALGORITHMS[name]
    d = oqs.Signature(liboqs_name).details
    assert (spec.public_key_bytes, spec.secret_key_bytes, spec.signature_bytes) == (
        d["length_public_key"],
        d["length_secret_key"],
        d["length_signature"],
    )


FIPS_204_SIZES = {
    "ML-DSA-44": (1312, 2560, 2420),
    "ML-DSA-65": (1952, 4032, 3309),
    "ML-DSA-87": (2592, 4896, 4627),
}


@pytest.mark.parametrize("name", sorted(FIPS_204_SIZES))
def test_ml_dsa_registry_uses_fips_204_sizes(name: str) -> None:
    spec = SIGNATURE_ALGORITHMS[name]
    assert (spec.public_key_bytes, spec.secret_key_bytes, spec.signature_bytes) == (
        FIPS_204_SIZES[name]
    )


@pytest.mark.parametrize("name", sorted(FIPS_204_SIZES))
def test_backend_algorithm_info_uses_fips_204_sizes(name: str) -> None:
    from quantum_safe.backends.liboqs import _SIGNATURE_ALGORITHM_INFO
    from quantum_safe.backends.rustcrypto import RustCryptoSignatureBackend

    # supported_algorithms() is static data; it does not need the extension.
    rust = {i.name: i for i in RustCryptoSignatureBackend.supported_algorithms(None)}  # type: ignore[arg-type]
    for info in (_SIGNATURE_ALGORITHM_INFO[name], rust[name]):
        assert (info.public_key_size, info.secret_key_size, info.ciphertext_size) == (
            FIPS_204_SIZES[name]
        )


@pytest.mark.parametrize("name", sorted(FIPS_204_SIZES))
def test_known_secret_key_size_table_uses_fips_204_sizes(name: str) -> None:
    from quantum_safe.types.keys import _KNOWN_PUBLIC_KEY_SIZES, _KNOWN_SECRET_KEY_SIZES

    pk, sk, _ = FIPS_204_SIZES[name]
    assert (_KNOWN_PUBLIC_KEY_SIZES[name], _KNOWN_SECRET_KEY_SIZES[name]) == (pk, sk)


@pytest.mark.parametrize("name", sorted(KEM_ALGORITHMS))
def test_kem_registry_sizes_match_liboqs(name: str) -> None:
    import oqs

    liboqs_name = _KEM_LIBOQS_NAMES.get(name, name)
    if liboqs_name not in _enabled_kems():
        pytest.skip(f"{liboqs_name} not enabled in this liboqs build")
    spec = KEM_ALGORITHMS[name]
    d = oqs.KeyEncapsulation(liboqs_name).details
    assert spec.public_key_bytes == d["length_public_key"]
    assert spec.ciphertext_bytes == d["length_ciphertext"]
    if hasattr(spec, "secret_key_bytes"):
        assert spec.secret_key_bytes == d["length_secret_key"]
