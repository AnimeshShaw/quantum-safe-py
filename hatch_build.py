"""
Custom hatchling build hook: vendors a compiled liboqs binary into the wheel.

liboqs-python (the dependency behind our `[liboqs]` extra) does not ship a
prebuilt liboqs binary — it compiles liboqs from source the first time
`import oqs` runs, using whatever OQS_INSTALL_PATH points at (default
`~/_oqs`). That's fine for a dev machine with git/CMake/a C compiler, but
wrong for an end user installing a released wheel.

This hook runs liboqs-python's own installer once, at build time, pointed at
a local staging directory, then copies the resulting compiled library into
the wheel under `quantum_safe/_vendor/liboqs/`. At runtime,
`quantum_safe.backends.liboqs._import_oqs()` points OQS_INSTALL_PATH at that
bundled directory before importing `oqs`, so liboqs-python finds the binary
immediately and never falls into its own auto-build path.

Only active when QUANTUM_SAFE_VENDOR_LIBOQS=1 is set (set by the cibuildwheel
config in pyproject.toml). A plain `pip install -e .` or sdist build skips
this entirely and behaves exactly as before.

Hatchling invokes this hook's initialize() both for metadata-only prep
(prepare_metadata_for_build_wheel) and the real wheel build, and cibuildwheel
builds cp310/cp311/cp312 as separate wheels in the same container — that's
up to 6 invocations per platform. The staging directory lives under the
project root (not an ephemeral build venv), so it survives across all of
those; we treat a populated staging dir as a cache hit and skip recompiling.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_VENDOR_ENV_FLAG = "QUANTUM_SAFE_VENDOR_LIBOQS"


class LiboqsVendorBuildHook(BuildHookInterface):
    """Compiles liboqs via liboqs-python's installer and bundles it into the wheel."""

    PLUGIN_NAME = "liboqs-vendor"

    def initialize(self, version: str, build_data: dict) -> None:  # noqa: ANN401
        if os.environ.get(_VENDOR_ENV_FLAG) != "1":
            return

        root = Path(self.root)
        staging = root / "build" / "liboqs-vendor-staging"

        src_dir = self._expected_src_dir(staging)
        if src_dir.is_dir() and any(src_dir.iterdir()):
            self.app.display_info(f"[liboqs-vendor] reusing cached build at {src_dir}")
        else:
            self._build_liboqs(staging)
            src_dir = self._expected_src_dir(staging)
            if not src_dir.is_dir() or not any(src_dir.iterdir()):
                raise RuntimeError(
                    f"[liboqs-vendor] expected liboqs build output at {src_dir}, "
                    "but it's missing or empty. liboqs-python's installer layout "
                    "may have changed."
                )

        self.app.display_info(f"[liboqs-vendor] vendoring {src_dir} into wheel")

        build_data.setdefault("force_include", {})[str(src_dir)] = (
            f"quantum_safe/_vendor/liboqs/{src_dir.name}"
        )
        build_data["pure_python"] = False
        build_data["infer_tag"] = True

    @staticmethod
    def _expected_src_dir(staging: Path) -> Path:
        if sys.platform == "win32":
            return staging / "bin"
        lib64 = staging / "lib64"
        return lib64 if lib64.is_dir() else staging / "lib"

    def _build_liboqs(self, staging: Path) -> None:
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)

        self.app.display_info(f"[liboqs-vendor] building liboqs into {staging} ...")

        # The interpreter hatchling runs us under (pip's isolated build
        # environment for [build-system] requires) does not necessarily have
        # pip importable as a module — bootstrap it defensively before use.
        subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], check=False)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "liboqs-python>=0.10.0"],
            check=True,
        )

        env = os.environ.copy()
        env["OQS_INSTALL_PATH"] = str(staging)
        subprocess.run(
            [sys.executable, "-c", "import oqs"],
            check=True,
            env=env,
            cwd=str(Path(self.root)),
        )
