"""scripts/artifact_record.py: the per-release record of what was built and from what."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "artifact_record", ROOT / "scripts" / "artifact_record.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["artifact_record"] = module
    spec.loader.exec_module(module)
    return module


def test_record_lists_every_file_with_its_sha256_and_the_pins(tmp_path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "quantum_safe_py-0.4.0-py3-none-any.whl").write_bytes(b"wheel bytes")
    (dist / "quantum_safe_py-0.4.0.tar.gz").write_bytes(b"sdist bytes")
    (dist / "README.txt").write_bytes(b"ignored: not an artifact")

    record = _load().build_record(dist, ROOT)

    names = {a["file"] for a in record["artifacts"]}
    assert names == {"quantum_safe_py-0.4.0-py3-none-any.whl", "quantum_safe_py-0.4.0.tar.gz"}
    wheel = next(a for a in record["artifacts"] if a["file"].endswith(".whl"))
    assert wheel["sha256"] == hashlib.sha256(b"wheel bytes").hexdigest()
    assert wheel["bytes"] == len(b"wheel bytes")
    assert record["package"] == "quantum-safe-py"
    assert record["liboqs"]["version"] == "0.16.0"
    assert record["liboqs"]["python_spec"] == ">=0.16.0,<0.17"
    assert record["schema"] == 1
    assert "created" in record and "git_commit" in record


def test_the_record_is_deterministic_for_the_same_inputs(tmp_path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "a-1.whl").write_bytes(b"x")
    module = _load()
    first = module.build_record(dist, ROOT, created="2026-10-15T00:00:00+00:00")
    second = module.build_record(dist, ROOT, created="2026-10-15T00:00:00+00:00")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
