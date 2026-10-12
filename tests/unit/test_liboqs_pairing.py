"""
liboqs and liboqs-python are used as a matching pair (audit item X-V1).

A fresh ``pip install quantum-safe-py[liboqs]`` used to resolve ``liboqs-python`` 0.16.0.1 against a
vendored liboqs 0.15.0, and every import printed "liboqs version (major, minor) 0.15.0 differs from
liboqs-python version 0.16.0.1". These tests keep the version in ONE place and make every place that
names a liboqs version agree with it, so the two cannot drift apart again:

* ``quantum_safe/_liboqs_version.py``: the single source of truth
* the ``liboqs`` extra in ``pyproject.toml``
* the build hook (``hatch_build.py``), which compiles the vendored copy
* the benchmark ``Dockerfile``
* the wheel and CI workflows, which assert the pair after installing

The runtime tests need liboqs and are skipped without it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    tomllib = None  # type: ignore[assignment]

from quantum_safe._liboqs_version import LIBOQS_PYTHON_SPEC, LIBOQS_VERSION

ROOT = Path(__file__).resolve().parents[2]


def _major_minor(version: str) -> tuple[int, int]:
    m = re.match(r"(\d+)\.(\d+)", version)
    assert m, version
    return int(m.group(1)), int(m.group(2))


class TestOneSourceOfTruth:
    def test_version_and_spec_are_consistent(self) -> None:
        major, minor = _major_minor(LIBOQS_VERSION)
        assert LIBOQS_PYTHON_SPEC == f">={LIBOQS_VERSION},<{major}.{minor + 1}"

    def test_extra_in_pyproject_uses_the_spec(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        if tomllib is not None:
            extra = tomllib.loads(text)["project"]["optional-dependencies"]["liboqs"]
        else:  # Python 3.10: the extra is a one-line list in a known table
            m = re.search(r"^liboqs = \[\s*\"([^\"]+)\",?\s*\]", text, re.MULTILINE)
            assert m, "liboqs extra not found in pyproject.toml"
            extra = [m.group(1)]
        assert extra == [f"liboqs-python{LIBOQS_PYTHON_SPEC}"]

    def test_dockerfile_builds_the_same_liboqs(self) -> None:
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        m = re.search(r"^ARG LIBOQS_TAG=(\S+)", text, re.MULTILINE)
        assert m, "Dockerfile has no ARG LIBOQS_TAG default"
        assert m.group(1) == LIBOQS_VERSION

    def test_build_hook_reads_the_single_source(self) -> None:
        text = (ROOT / "hatch_build.py").read_text(encoding="utf-8")
        assert "_liboqs_version.py" in text
        assert "liboqs-python>=0.10.0" not in text
        assert "PYOQS_VERSION" in text  # the installer must be told the exact liboqs tag

    def test_ci_tells_liboqs_python_which_liboqs_to_build(self) -> None:
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        m = re.search(r'^\s*PYOQS_VERSION:\s*"?([0-9.]+)"?', text, re.MULTILINE)
        assert m, "ci.yml does not set PYOQS_VERSION"
        assert m.group(1) == LIBOQS_VERSION

    def test_no_other_file_pins_a_different_liboqs_python(self) -> None:
        # The workflows install the wheel and the extra; none may carry its own old pin.
        for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
            for line in wf.read_text(encoding="utf-8").splitlines():
                m = re.search(r"liboqs-python\s*[=<>~!]=?\s*([0-9][^\s'\"]*)", line)
                if m and "pip" in line:
                    assert m.group(1).startswith(("0.16", LIBOQS_VERSION)), (wf.name, line)


@pytest.mark.requires_liboqs
class TestRuntimePair:
    def test_liboqs_matches_the_release_version(self) -> None:
        from quantum_safe.backends.liboqs import liboqs_versions

        v = liboqs_versions()
        assert _major_minor(v["liboqs"]) == _major_minor(LIBOQS_VERSION), v
        assert v["paired"] is True, v

    def test_liboqs_python_is_inside_the_supported_range(self) -> None:
        from quantum_safe.backends.liboqs import liboqs_versions

        assert _major_minor(liboqs_versions()["liboqs_python"]) == _major_minor(LIBOQS_VERSION)

    def test_import_emits_no_pairing_warning(self) -> None:
        # A fresh interpreter, warnings as errors: any "differs from liboqs-python" warning fails.
        code = (
            "import warnings; warnings.simplefilter('error');"
            "from quantum_safe.backends.liboqs import LiboqsKEMBackend;"
            "LiboqsKEMBackend().supported_algorithms(); print('ok')"
        )
        r = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, check=False
        )
        assert r.returncode == 0 and "ok" in r.stdout, r.stderr[-800:]

    def test_pairing_check_reports_a_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import quantum_safe.backends.liboqs as backend

        class Fake:
            @staticmethod
            def oqs_version() -> str:
                return "0.15.0"

            @staticmethod
            def oqs_python_version() -> str:
                return "0.16.0.1"

        monkeypatch.setattr(backend, "_import_oqs", lambda: Fake)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            v = backend.liboqs_versions()
        assert v["paired"] is False
        assert v["liboqs"] == "0.15.0" and v["liboqs_python"] == "0.16.0.1"
