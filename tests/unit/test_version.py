"""The two forms of the package version agree with each other and with pyproject.toml."""

from __future__ import annotations

import pathlib
import re

from quantum_safe import __version__, __version_info__


def test_version_info_matches_version_string() -> None:
    assert ".".join(str(part) for part in __version_info__) == __version__


def test_version_matches_pyproject() -> None:
    text = (pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match is not None
    assert match.group(1) == __version__
