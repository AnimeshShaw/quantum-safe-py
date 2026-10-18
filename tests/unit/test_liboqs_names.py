"""
liboqs renames mechanisms between releases; the registry keeps one stable public name (audit item PY-H1).

HQC is the example: liboqs 0.15 calls the 128-bit set ``HQC-128`` and implements the 2023 submission;
liboqs 0.16 calls it ``HQC-1`` and implements the 2025-08-22 specification (new sizes). These tests use a
fake ``oqs`` module so they run without liboqs and pin that:

* a registry name resolves to whichever candidate the loaded build enables;
* an algorithm the build does not provide fails with a clear, typed error that lists what is available;
* the registry sizes for BIKE and HQC are the ones a real liboqs 0.16.0 build reports.
"""

from __future__ import annotations

import pytest

from quantum_safe.backends import liboqs as backend
from quantum_safe.exceptions import UnsupportedAlgorithm
from quantum_safe.kem.algorithms import KEM_ALGORITHMS


class FakeKEM:
    def __init__(self, name: str) -> None:
        self.name = name

    def generate_keypair(self) -> bytes:
        return b"\x01" * 8

    def export_secret_key(self) -> bytes:
        return b"\x02" * 8


class FakeOqs:
    def __init__(self, enabled: set[str]) -> None:
        self._enabled = enabled
        self.created: list[str] = []

    def get_enabled_kem_mechanisms(self) -> list[str]:
        return sorted(self._enabled)

    def KeyEncapsulation(self, name: str) -> FakeKEM:  # noqa: N802 (mirrors the oqs API)
        if name not in self._enabled:
            raise RuntimeError(f"{name} is not supported")
        self.created.append(name)
        return FakeKEM(name)


@pytest.fixture
def use_fake(monkeypatch: pytest.MonkeyPatch):
    def _install(enabled: set[str]) -> FakeOqs:
        fake = FakeOqs(enabled)
        monkeypatch.setattr(backend, "_import_oqs", lambda: fake)
        return fake

    return _install


class TestNameResolution:
    @pytest.mark.parametrize(
        ("registry_name", "liboqs_names"),
        [
            ("HQC-128", ("HQC-1", "HQC-128")),
            ("HQC-192", ("HQC-3", "HQC-192")),
            ("HQC-256", ("HQC-5", "HQC-256")),
        ],
    )
    def test_hqc_resolves_to_the_names_of_both_liboqs_generations(
        self, use_fake, registry_name: str, liboqs_names: tuple[str, str]
    ) -> None:
        new, old = liboqs_names
        for enabled_name in (new, old):
            fake = use_fake({enabled_name, "ML-KEM-768"})
            names = {a.name for a in backend.LiboqsKEMBackend().supported_algorithms()}
            assert registry_name in names
            backend.LiboqsKEMBackend().keygen(registry_name)
            assert fake.created == [enabled_name]

    def test_unchanged_names_resolve_to_themselves(self, use_fake) -> None:
        fake = use_fake({"ML-KEM-768"})
        backend.LiboqsKEMBackend().keygen("ML-KEM-768")
        assert fake.created == ["ML-KEM-768"]

    def test_algorithm_missing_from_the_build_is_a_clear_error(self, use_fake) -> None:
        use_fake({"ML-KEM-768", "ML-KEM-1024"})
        with pytest.raises(UnsupportedAlgorithm) as err:
            backend.LiboqsKEMBackend().keygen("HQC-128")
        text = str(err.value)
        assert "HQC-128" in text
        assert "ML-KEM-768" in text  # what this build does provide

    def test_unknown_algorithm_is_still_unsupported(self, use_fake) -> None:
        use_fake({"ML-KEM-768"})
        with pytest.raises(UnsupportedAlgorithm):
            backend.LiboqsKEMBackend().keygen("ML-KEM-9999")


class TestRegistrySizesFromARealBuild:
    """Values read from liboqs 0.16.0 (commit 5a1a854) built with HQC and BIKE enabled."""

    EXPECTED = {
        # name: (public key, secret key, ciphertext, shared secret, NIST level)
        "BIKE-L1": (1541, 5223, 1573, 32, 1),
        "BIKE-L3": (3083, 10105, 3115, 32, 3),
        "BIKE-L5": (5122, 16494, 5154, 32, 5),
        "HQC-128": (2241, 2321, 4433, 32, 1),
        "HQC-192": (4514, 4602, 8978, 32, 3),
        "HQC-256": (7237, 7333, 14421, 32, 5),
    }

    @pytest.mark.parametrize("name", sorted(EXPECTED))
    def test_kem_registry(self, name: str) -> None:
        spec = KEM_ALGORITHMS[name]
        pk, sk, ct, ss, level = self.EXPECTED[name]
        assert (
            spec.public_key_bytes,
            spec.secret_key_bytes,
            spec.ciphertext_bytes,
            spec.shared_secret_bytes,
            int(spec.nist_level),
        ) == (pk, sk, ct, ss, level)
        assert spec.is_nist_standard is False

    @pytest.mark.parametrize("name", sorted(EXPECTED))
    def test_backend_info_agrees_with_registry(self, name: str) -> None:
        info = backend._KEM_ALGORITHM_INFO[name]
        spec = KEM_ALGORITHMS[name]
        assert (info.public_key_size, info.secret_key_size, info.ciphertext_size) == (
            spec.public_key_bytes,
            spec.secret_key_bytes,
            spec.ciphertext_bytes,
        )

    @pytest.mark.parametrize("name", sorted(EXPECTED))
    def test_key_size_tables_agree(self, name: str) -> None:
        from quantum_safe.types.keys import _KNOWN_PUBLIC_KEY_SIZES, _KNOWN_SECRET_KEY_SIZES

        pk, sk, *_ = self.EXPECTED[name]
        if name in _KNOWN_PUBLIC_KEY_SIZES:
            assert _KNOWN_PUBLIC_KEY_SIZES[name] == pk
        if name in _KNOWN_SECRET_KEY_SIZES:
            assert _KNOWN_SECRET_KEY_SIZES[name] == sk


class TestVendoredDirLookupIsCached:
    """The bundled-liboqs lookup runs on every KEM and signature call; it must not touch the disk each time."""

    def test_filesystem_is_consulted_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import importlib.resources

        from quantum_safe.backends import liboqs as backend

        calls: list[str] = []
        real_files = importlib.resources.files

        def counting_files(package: str):  # type: ignore[no-untyped-def]
            calls.append(package)
            return real_files(package)

        backend._vendored_liboqs_dir.cache_clear()
        monkeypatch.setattr(importlib.resources, "files", counting_files)
        try:
            first = backend._vendored_liboqs_dir()
            for _ in range(50):
                assert backend._vendored_liboqs_dir() == first
            assert len(calls) == 1
        finally:
            backend._vendored_liboqs_dir.cache_clear()
