"""Upgraded signing keys follow the default suite (1.0.0).

``HybridSign()`` is ``Ed25519+ML-DSA-65-v2`` and a signer refuses a key tagged with another
format, so ``Upgrader`` and ``qs-migrate upgrade-key`` must produce ``-v2``-tagged signing keys by
default, and still produce the original format when it is named.
"""

from __future__ import annotations

import pytest

from quantum_safe.exceptions import UnsupportedAlgorithm

pytestmark = pytest.mark.requires_liboqs


def _ed25519() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    k = Ed25519PrivateKey.generate()
    return (
        k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


def test_default_target_is_the_v2_suite_and_works_with_the_default_signer() -> None:
    from quantum_safe.migrate.upgrader import Upgrader
    from quantum_safe.signatures.hybrid import HybridSign

    sec, pub = _ed25519()
    result = Upgrader.upgrade_signing_key(sec, pub)
    assert result.new_algorithm == "Ed25519+ML-DSA-65-v2"
    signer = HybridSign()
    sm = signer.sign(b"m", result.new_keypair.secret, context=b"c")
    signer.verify(sm, result.new_keypair.public, context=b"c")


def test_original_format_is_still_available_by_name() -> None:
    from quantum_safe.migrate.upgrader import Upgrader
    from quantum_safe.signatures.hybrid import HybridSign

    sec, pub = _ed25519()
    result = Upgrader.upgrade_signing_key(sec, pub, target_pqc="ML-DSA-65")
    assert result.new_algorithm == "Ed25519+ML-DSA-65"
    signer = HybridSign("Ed25519", "ML-DSA-65")
    sm = signer.sign(b"m", result.new_keypair.secret, context=b"c")
    signer.verify(sm, result.new_keypair.public, context=b"c")


def test_explicit_v2_for_each_ml_dsa_level() -> None:
    from quantum_safe.migrate.upgrader import Upgrader

    sec, pub = _ed25519()
    for level in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        r = Upgrader.upgrade_signing_key(sec, pub, target_pqc=f"{level}-v2")
        assert r.new_algorithm == f"Ed25519+{level}-v2"


def test_unknown_v2_combination_is_refused() -> None:
    from quantum_safe.migrate.upgrader import Upgrader

    sec, pub = _ed25519()
    with pytest.raises((ValueError, UnsupportedAlgorithm)):
        Upgrader.upgrade_signing_key(sec, pub, target_pqc="ML-DSA-99-v2")
