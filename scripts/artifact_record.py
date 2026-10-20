#!/usr/bin/env python3
"""Write the artifact record of a release: what was built, from which commit and pins.

    python scripts/artifact_record.py dist/ --out artifact-record-1.0.0.json

For every wheel and source distribution in the directory it records the SHA-256 and size, plus
the package version, the git commit, and the pins that decide what is inside a wheel (the liboqs
release and the liboqs-python spec). Attach the file to the GitHub release; Zenodo archives the
release and gives it a DOI, and the record lets anyone check a downloaded file against what the
release says it contains. Nothing here is secret and nothing is signed: it is a plain,
reproducible statement of facts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ARTIFACT_SUFFIXES = (".whl", ".tar.gz")


def _pins(root: pathlib.Path) -> dict[str, Any]:
    namespace: dict[str, Any] = {}
    source = (root / "src" / "quantum_safe" / "_liboqs_version.py").read_text(encoding="utf-8")
    exec(compile(source, "_liboqs_version.py", "exec"), namespace)  # noqa: S102 - our own file
    return {
        "version": namespace["LIBOQS_VERSION"],
        "python_spec": namespace["LIBOQS_PYTHON_SPEC"],
    }


def _package_version(root: pathlib.Path) -> str:
    namespace: dict[str, Any] = {}
    source = (root / "src" / "quantum_safe" / "_version.py").read_text(encoding="utf-8")
    exec(compile(source, "_version.py", "exec"), namespace)  # noqa: S102
    return str(namespace["__version__"])


def _git(root: pathlib.Path, *args: str) -> str:
    try:
        out = subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def build_record(
    dist: pathlib.Path, root: pathlib.Path, *, created: str | None = None
) -> dict[str, Any]:
    """The record for the files in ``dist`` (wheels and sdists only)."""
    artifacts = []
    for path in sorted(dist.iterdir()):
        if not path.is_file() or not path.name.endswith(ARTIFACT_SUFFIXES):
            continue
        data = path.read_bytes()
        artifacts.append(
            {"file": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        )
    return {
        "schema": 1,
        "package": "quantum-safe-py",
        "version": _package_version(root),
        "git_commit": _git(root, "rev-parse", "HEAD"),
        "git_tag": _git(root, "describe", "--tags", "--exact-match"),
        "created": created or datetime.now(timezone.utc).isoformat(),
        "liboqs": _pins(root),
        "artifacts": artifacts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dist", type=pathlib.Path, help="directory with the built wheels and sdist")
    parser.add_argument(
        "--out", type=pathlib.Path, default=None, help="write here (default stdout)"
    )
    args = parser.parse_args(argv)
    root = pathlib.Path(__file__).resolve().parents[1]
    if not args.dist.is_dir():
        print(f"not a directory: {args.dist}", file=sys.stderr)
        return 2
    record = build_record(args.dist, root)
    if not record["artifacts"]:
        print("no wheels or source distributions found", file=sys.stderr)
        return 1
    text = json.dumps(record, indent=2) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}: {len(record['artifacts'])} artifacts")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
