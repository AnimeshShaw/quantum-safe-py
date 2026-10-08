"""
``qs-migrate upgrade-key`` performs the upgrade it is named for (GitHub issue #9).

It used to parse the key, print "Upgrading to ...", and exit 0 without writing anything.
These tests pin the real behaviour: a valid classical secret key becomes a hybrid key
pair on disk; anything that cannot be upgraded fails with a non-zero exit and leaves no
output behind; the input is never touched; secret material is never printed.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

click = pytest.importorskip("click")
from click.testing import CliRunner  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from quantum_safe.migrate.cli import _cli as migrate_cli  # type: ignore[attr-defined]  # noqa: E402
from quantum_safe.types import MigrationState, PublicKey, SecretKey  # noqa: E402

liboqs = pytest.mark.requires_liboqs


def pkcs8(key) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def raw_secret(key) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def x25519_pem(tmp_path: Path) -> Path:
    p = tmp_path / "x25519.pem"
    p.write_bytes(pkcs8(x25519.X25519PrivateKey.generate()))
    return p


@pytest.fixture
def ed25519_pem(tmp_path: Path) -> Path:
    p = tmp_path / "ed25519.pem"
    p.write_bytes(pkcs8(ed25519.Ed25519PrivateKey.generate()))
    return p


def upgrade(runner: CliRunner, src: Path, out: Path, *extra: str):
    return runner.invoke(migrate_cli, ["upgrade-key", "-i", str(src), "-o", str(out), *extra])


def assert_nothing_written(tmp_path: Path, *keep: Path) -> None:
    leftovers = sorted(p.name for p in tmp_path.iterdir() if p not in keep)
    assert leftovers == [], leftovers


class TestUpgradeSucceeds:
    @liboqs
    def test_x25519_becomes_a_hybrid_kem_key_pair(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        before = x25519_pem.read_bytes()
        out = tmp_path / "hybrid.pem"
        result = upgrade(runner, x25519_pem, out)
        assert result.exit_code == 0, result.output

        sec = SecretKey.from_pem(out.read_text())
        pub = PublicKey.from_pem((tmp_path / "hybrid.pem.pub").read_text())
        assert sec.algorithm == pub.algorithm == "X25519+ML-KEM-768"
        assert sec.migration_state is MigrationState.HYBRID_TRANSITION

        # The original secret is retained unchanged inside the hybrid secret.
        original = serialization_raw(before)
        assert original in sec.raw_bytes

        # And the pair works.
        from quantum_safe.kem.hybrid import HybridKEM

        kem = HybridKEM("X25519", "ML-KEM-768")
        ct, shared = kem.encapsulate(pub)
        assert kem.decapsulate(sec, ct) == shared

        assert x25519_pem.read_bytes() == before  # the input is not modified

    @liboqs
    def test_ed25519_becomes_a_hybrid_signing_key_pair(
        self, runner: CliRunner, tmp_path: Path, ed25519_pem: Path
    ) -> None:
        out = tmp_path / "sign.pem"
        pub_out = tmp_path / "sign.pub.pem"
        result = upgrade(runner, ed25519_pem, out, "--public-output", str(pub_out))
        assert result.exit_code == 0, result.output

        sec = SecretKey.from_pem(out.read_text())
        pub = PublicKey.from_pem(pub_out.read_text())
        assert sec.algorithm == pub.algorithm == "Ed25519+ML-DSA-65"

        from quantum_safe.signatures.hybrid import HybridSign

        signer = HybridSign("Ed25519", "ML-DSA-65")
        signer.verify(signer.sign(b"hello", sec), pub, context=b"")

    @liboqs
    def test_the_classical_half_is_the_input_key(
        self, runner: CliRunner, tmp_path: Path, ed25519_pem: Path
    ) -> None:
        """Signatures from the upgraded key verify against the ORIGINAL public key's half."""
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_secret_of(ed25519_pem))
        original_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        out = tmp_path / "h.pem"
        assert upgrade(runner, ed25519_pem, out).exit_code == 0
        pub = PublicKey.from_pem((tmp_path / "h.pem.pub").read_text())
        assert original_pub in pub.raw_bytes

    @liboqs
    def test_library_secret_key_pem_is_accepted(self, runner: CliRunner, tmp_path: Path) -> None:
        key = x25519.X25519PrivateKey.generate()
        lib_pem = tmp_path / "lib.pem"
        lib_pem.write_text(SecretKey(raw_secret(key), "X25519").to_pem())
        out = tmp_path / "out.pem"
        assert upgrade(runner, lib_pem, out).exit_code == 0
        assert SecretKey.from_pem(out.read_text()).algorithm == "X25519+ML-KEM-768"

    @liboqs
    @pytest.mark.parametrize(
        ("fixture", "target"),
        [("x25519_pem", "X25519+ML-KEM-1024"), ("ed25519_pem", "Ed25519+ML-DSA-87")],
    )
    def test_requested_target_is_honoured(
        self, runner: CliRunner, tmp_path: Path, request, fixture: str, target: str
    ) -> None:
        src = request.getfixturevalue(fixture)
        out = tmp_path / "o.pem"
        result = upgrade(runner, src, out, "--target", target)
        assert result.exit_code == 0, result.output
        assert SecretKey.from_pem(out.read_text()).algorithm == target

    @liboqs
    def test_matching_key_type_is_accepted(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        assert upgrade(runner, x25519_pem, tmp_path / "o.pem", "--key-type", "kem").exit_code == 0

    @liboqs
    def test_no_secret_material_is_printed(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        result = upgrade(runner, x25519_pem, tmp_path / "o.pem")
        assert result.exit_code == 0
        secret_b64 = base64.b64encode(serialization_raw(x25519_pem.read_bytes())).decode()
        body = (tmp_path / "o.pem").read_text().split("\n\n", 1)[1].split("-----END")[0]
        assert secret_b64 not in result.output
        assert body.replace("\n", "")[:40] not in result.output
        assert "was not changed" in result.output

    @liboqs
    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
    def test_secret_key_file_is_private(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        out = tmp_path / "o.pem"
        assert upgrade(runner, x25519_pem, out).exit_code == 0
        assert (os.stat(out).st_mode & 0o777) == 0o600
        assert not any(p.name.endswith(".tmp") for p in tmp_path.iterdir())


class TestRefusals:
    """Every case exits non-zero, says why, and leaves no output file behind."""

    def fails(self, runner, tmp_path, src, *extra, match: str):
        out = tmp_path / "out.pem"
        result = upgrade(runner, src, out, *extra)
        assert result.exit_code == 1, result.output
        assert match.lower() in result.output.lower(), result.output
        assert not out.exists() and not (tmp_path / "out.pem.pub").exists()
        assert not any(p.name.endswith(".tmp") for p in tmp_path.iterdir())

    def test_malformed_input(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("hello")
        self.fails(runner, tmp_path, bad, match="not a recognised key file")

    def test_corrupt_pkcs8(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
        self.fails(runner, tmp_path, bad, match="could not parse")

    def test_binary_input(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = tmp_path / "bad.bin"
        bad.write_bytes(b"\xff\xfe\x00\x01")
        self.fails(runner, tmp_path, bad, match="not a PEM text file")

    def test_public_key_only_is_a_clear_failure(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        pub = x25519.X25519PrivateKey.from_private_bytes(raw_secret_of(x25519_pem)).public_key()
        for name, text in (
            ("std.pem", pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()),
            (
                "lib.pem",
                PublicKey(pub.public_bytes(Encoding.Raw, PublicFormat.Raw), "X25519").to_pem(),
            ),
        ):
            f = tmp_path / name
            f.write_text(text)
            self.fails(runner, tmp_path, f, match="public key")

    def test_unsupported_classical_algorithms(self, runner: CliRunner, tmp_path: Path) -> None:
        for name, key in (
            ("p256.pem", ec.generate_private_key(ec.SECP256R1())),
            ("rsa.pem", rsa.generate_private_key(65537, 2048)),
        ):
            f = tmp_path / name
            f.write_bytes(pkcs8(key))
            self.fails(runner, tmp_path, f, match="not upgraded by this command")

    def test_encrypted_key(self, runner: CliRunner, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

        f = tmp_path / "enc.pem"
        f.write_bytes(
            x25519.X25519PrivateKey.generate().private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"pw")
            )
        )
        self.fails(runner, tmp_path, f, match="encrypted")

    def test_already_post_quantum_key(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "pq.pem"
        f.write_text(SecretKey(b"\x01" * 64, "X25519+ML-KEM-768").to_pem())
        self.fails(runner, tmp_path, f, match="already post-quantum")

    def test_wrong_length_library_key(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "short.pem"
        f.write_text(SecretKey(b"\x01" * 31, "X25519").to_pem())
        self.fails(runner, tmp_path, f, match="32 bytes")

    @pytest.mark.parametrize(
        ("target", "match"),
        [
            (
                "X25519+ML-DSA-65",
                "not in the algorithm registry",
            ),  # a signature algorithm for a KEM key
            ("X25519+ML-KEM-9999", "not in the algorithm registry"),
            ("X25519+BIKE-L1", "not an approved hybrid"),
            ("Ed25519+ML-DSA-65", "keeps a Ed25519 component"),
            ("ML-KEM-768", "must look like"),
            ("X25519+", "must look like"),
            ("X25519+ML-KEM-768+x", "must look like"),
        ],
    )
    def test_bad_targets(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path, target: str, match: str
    ) -> None:
        self.fails(runner, tmp_path, x25519_pem, "--target", target, match=match)

    def test_key_type_must_match_the_input(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        self.fails(runner, tmp_path, x25519_pem, "--key-type", "sign", match="does not match")

    def test_signing_target_for_a_kem_key(
        self, runner: CliRunner, tmp_path: Path, ed25519_pem: Path
    ) -> None:
        # Mismatch between the old default (a KEM target) and an Ed25519 input.
        self.fails(
            runner, tmp_path, ed25519_pem, "--target", "X25519+ML-KEM-768", match="keeps a X25519"
        )

    def test_missing_options_are_usage_errors(self, runner: CliRunner) -> None:
        assert runner.invoke(migrate_cli, ["upgrade-key"]).exit_code == 2
        assert (
            runner.invoke(migrate_cli, ["upgrade-key", "-i", "nope.pem", "-o", "x"]).exit_code == 2
        )


class TestOverwriteProtection:
    @liboqs
    def test_existing_output_is_not_replaced_without_force(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        out = tmp_path / "out.pem"
        out.write_text("precious")
        result = upgrade(runner, x25519_pem, out)
        assert result.exit_code == 1 and "already exists" in result.output
        assert out.read_text() == "precious"
        assert not (tmp_path / "out.pem.pub").exists()

    @liboqs
    def test_existing_public_output_is_not_replaced_without_force(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        pub = tmp_path / "out.pem.pub"
        pub.write_text("precious")
        result = upgrade(runner, x25519_pem, tmp_path / "out.pem")
        assert result.exit_code == 1
        assert pub.read_text() == "precious" and not (tmp_path / "out.pem").exists()

    @liboqs
    def test_force_replaces(self, runner: CliRunner, tmp_path: Path, x25519_pem: Path) -> None:
        out = tmp_path / "out.pem"
        out.write_text("old")
        assert upgrade(runner, x25519_pem, out, "--force").exit_code == 0
        assert SecretKey.from_pem(out.read_text()).algorithm == "X25519+ML-KEM-768"

    def test_the_input_can_never_be_the_output(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        before = x25519_pem.read_bytes()
        for extra in ((), ("--force",)):
            result = upgrade(runner, x25519_pem, x25519_pem, *extra)
            assert result.exit_code == 1 and "three different files" in result.output
        result = upgrade(
            runner, x25519_pem, tmp_path / "o.pem", "--public-output", str(x25519_pem), "--force"
        )
        assert result.exit_code == 1
        assert x25519_pem.read_bytes() == before

    def test_missing_output_directory(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path
    ) -> None:
        result = upgrade(runner, x25519_pem, tmp_path / "nope" / "o.pem")
        assert result.exit_code == 1 and "does not exist" in result.output


class TestNoPartialOutput:
    @liboqs
    def test_failure_while_placing_the_public_key_removes_the_secret_key(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path, monkeypatch
    ) -> None:
        real_replace = os.replace
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(28, "No space left on device")
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", flaky)
        result = upgrade(runner, x25519_pem, tmp_path / "o.pem")
        assert result.exit_code == 1 and "could not write" in result.output
        assert_nothing_written(tmp_path, x25519_pem)

    @liboqs
    def test_failure_while_writing_leaves_nothing(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path, monkeypatch
    ) -> None:
        def boom(*a, **k):
            raise OSError(13, "Permission denied")

        monkeypatch.setattr(os, "fsync", boom)
        result = upgrade(runner, x25519_pem, tmp_path / "o.pem")
        assert result.exit_code == 1
        assert_nothing_written(tmp_path, x25519_pem)

    def test_backend_failure_writes_nothing(
        self, runner: CliRunner, tmp_path: Path, x25519_pem: Path, monkeypatch
    ) -> None:
        from quantum_safe.migrate.upgrader import Upgrader

        def boom(*a, **k):
            raise RuntimeError("no backend")

        monkeypatch.setattr(Upgrader, "upgrade_kem_key", classmethod(lambda cls, *a, **k: boom()))
        result = upgrade(runner, x25519_pem, tmp_path / "o.pem")
        assert result.exit_code == 1 and "the upgrade failed: no backend" in result.output
        assert_nothing_written(tmp_path, x25519_pem)


def serialization_raw(pkcs8_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return raw_secret(load_pem_private_key(pkcs8_pem, password=None))


def raw_secret_of(path: Path) -> bytes:
    return serialization_raw(path.read_bytes())
