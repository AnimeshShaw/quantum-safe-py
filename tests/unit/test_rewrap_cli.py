"""``qs-migrate rewrap``: the command line over :func:`quantum_safe.migrate.rewrap.rewrap_directory`."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("click")
pytestmark = pytest.mark.requires_liboqs

from click.testing import CliRunner  # noqa: E402

from quantum_safe import HybridKEM  # noqa: E402
from quantum_safe.migrate.cli import _cli  # noqa: E402
from quantum_safe.protocols.envelope import Envelope, SealedMessage  # noqa: E402


@pytest.fixture()
def setup(tmp_path):
    old = HybridKEM("X25519", "ML-KEM-768").generate_keypair()
    new = HybridKEM("X25519", "ML-KEM-1024").generate_keypair()
    src = tmp_path / "src"
    src.mkdir()
    (src / "one.sealed").write_bytes(
        Envelope.seal(b"one", old.public, aad=b"one.sealed").to_bytes()
    )
    (src / "two.sealed").write_bytes(
        Envelope.seal(b"two", old.public, aad=b"two.sealed").to_bytes()
    )
    files = {
        "old_secret": old.secret.to_pem(),
        "new_public": new.public.to_pem(),
        "new_secret": new.secret.to_pem(),
    }
    for name, pem in files.items():
        (tmp_path / f"{name}.pem").write_text(pem, encoding="utf-8")
    return tmp_path, src, new


def _args(tmp_path, src, *extra):
    return [
        "rewrap",
        str(src),
        *extra,
        "--old-secret",
        str(tmp_path / "old_secret.pem"),
        "--new-public",
        str(tmp_path / "new_public.pem"),
    ]


def test_rewrap_writes_a_verified_copy_a_report_and_a_cbom(setup) -> None:
    tmp_path, src, new = setup
    dst = tmp_path / "dst"
    result = CliRunner().invoke(
        _cli,
        [
            *_args(tmp_path, src, str(dst)),
            "--new-secret",
            str(tmp_path / "new_secret.pem"),
            "--aad-from-path",
            "--report",
            str(tmp_path / "report.json"),
            "--cbom",
            str(tmp_path / "cbom.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    sealed = SealedMessage.from_bytes((dst / "one.sealed").read_bytes())
    assert sealed.algorithm == "X25519+ML-KEM-1024"
    assert Envelope.open(sealed, new.secret, expected_aad=b"one.sealed") == b"one"
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["counts"]["rewrapped"] == 2 and report["aad_checked"] is True
    cbom = json.loads((tmp_path / "cbom.json").read_text(encoding="utf-8"))
    assert cbom["specVersion"] == "1.6"


def test_failures_exit_one_and_name_the_file(setup) -> None:
    tmp_path, src, _ = setup
    result = CliRunner().invoke(
        _cli, [*_args(tmp_path, src, str(tmp_path / "dst")), "--aad", "wrong"]
    )
    assert result.exit_code == 1
    assert "FAILED one.sealed" in result.output


def test_in_place_and_destination_rules(setup) -> None:
    tmp_path, src, _ = setup
    runner = CliRunner()
    missing = runner.invoke(_cli, _args(tmp_path, src))
    assert missing.exit_code == 2 and "destination" in missing.output
    done = runner.invoke(_cli, [*_args(tmp_path, src), "--in-place", "--aad-from-path"])
    assert done.exit_code == 0, done.output
    assert (
        SealedMessage.from_bytes((src / "one.sealed").read_bytes()).algorithm
        == "X25519+ML-KEM-1024"
    )


def test_aad_options_are_exclusive(setup) -> None:
    tmp_path, src, _ = setup
    result = CliRunner().invoke(
        _cli, [*_args(tmp_path, src, str(tmp_path / "d")), "--aad", "x", "--aad-from-path"]
    )
    assert result.exit_code == 2
