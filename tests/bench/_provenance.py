"""Where and how a benchmark run happened, recorded next to its numbers.

A published figure is only checkable if the file holding it says which machine, kernel,
liboqs and code produced it. ``environment()`` collects that; the benchmark harnesses write
it under ``"metadata"`` in every saved file.
"""

from __future__ import annotations

import datetime
import os
import platform
import subprocess
import sys
from typing import Any


def _git_commit() -> str:
    env = os.environ.get("QS_GIT_COMMIT")  # set when the image is built (no .git inside it)
    if env:
        return env
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False
        )
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _liboqs_version() -> str:
    try:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import oqs

            return str(oqs.oqs_version())
    except Exception:  # noqa: BLE001
        return "not installed"


def environment() -> dict[str, Any]:
    """Facts about this run. Nothing here is a secret."""
    try:
        affinity = sorted(os.sched_getaffinity(0))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        affinity = None
    return {
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": _cpu_model(),
        "logical_cpus": os.cpu_count(),
        "cpu_affinity": affinity,
        "liboqs": _liboqs_version(),
        "git_commit": _git_commit(),
        "in_container": os.path.exists("/.dockerenv"),
    }
