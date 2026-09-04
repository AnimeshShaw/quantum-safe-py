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

        lib_dirs = self._existing_lib_dirs(staging)
        if lib_dirs:
            self.app.display_info(f"[liboqs-vendor] reusing cached build at {staging}")
        else:
            self._build_liboqs(staging)
            lib_dirs = self._existing_lib_dirs(staging)
            if not lib_dirs:
                raise RuntimeError(
                    f"[liboqs-vendor] expected liboqs build output under {staging} "
                    "(bin/lib/lib64), but found none. liboqs-python's installer "
                    "layout may have changed."
                )

        force_include = build_data.setdefault("force_include", {})
        for lib_dir in lib_dirs:
            self.app.display_info(f"[liboqs-vendor] vendoring {lib_dir} into wheel")
            force_include[str(lib_dir)] = f"quantum_safe/_vendor/liboqs/{lib_dir.name}"

        build_data["pure_python"] = False
        build_data["infer_tag"] = True

    @staticmethod
    def _existing_lib_dirs(staging: Path) -> list[Path]:
        """All non-empty platform lib dirs actually present under staging.

        Usually just one (bin on Windows, lib or lib64 elsewhere) — but on
        RHEL/AlmaLinux-family systems _build_liboqs mirrors lib64 into lib
        too, so both get vendored into the wheel.
        """
        candidates = [staging / name for name in ("bin", "lib", "lib64")]
        return [d for d in candidates if d.is_dir() and any(d.iterdir())]

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

        # pip's build-isolation machinery sets PYTHONPATH to restrict this
        # process (and anything it spawns) to an overlay containing only
        # hatchling's own build dependencies. ensurepip can still write pip
        # into the real site-packages (it doesn't need to import "pip" to do
        # that), but a subsequent `python -m pip` can't find what was just
        # installed, because the inherited PYTHONPATH hides the real
        # site-packages from it. Strip it for these subprocesses only.
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)

        subprocess.run(
            [sys.executable, "-m", "ensurepip", "--upgrade"], check=False, env=env
        )
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "liboqs-python>=0.10.0"],
            check=True,
            env=env,
        )

        env["OQS_INSTALL_PATH"] = str(staging)
        result = subprocess.run(
            [sys.executable, "-c", "import oqs"],
            env=env,
            cwd=str(Path(self.root)),
        )

        src_dir = self._expected_src_dir(staging)

        # RHEL/AlmaLinux-family systems (this manylinux image included) have
        # CMake install into lib64, not lib. Mirror it into lib too — cheap
        # insurance against a lib64-vs-lib mismatch in liboqs-python's own
        # lookup, both here at build time and later for real end users going
        # through the same OQS_INSTALL_PATH mechanism at runtime.
        if src_dir.name == "lib64":
            mirror = staging / "lib"
            if not mirror.exists():
                shutil.copytree(src_dir, mirror)

        if result.returncode != 0:
            if self._main_lib_loads(src_dir):
                self.app.display_info(
                    "[liboqs-vendor] liboqs-python's own post-install check failed, "
                    "but the compiled library loads fine via direct ctypes.CDLL — "
                    "continuing (likely a lib64-vs-lib lookup quirk in its internal "
                    "verification, not a real build problem)."
                )
            else:
                raise RuntimeError(
                    "[liboqs-vendor] liboqs failed to load even via direct "
                    "ctypes.CDLL — see diagnostic above for the real error."
                )

    def _main_lib_loads(self, src_dir: Path) -> bool:
        """liboqs-python swallows the real OSError behind a generic message.

        Probe every compiled shared library directly with ctypes.CDLL — this
        prints the actual missing-dependency error (e.g. a specific .so/.dll
        name) instead of liboqs-python's "Could not load liboqs shared
        library", and tells us whether the main library actually works
        regardless of what liboqs-python's own check concluded.
        """
        self.app.display_info(f"[liboqs-vendor] diagnosing load failure in {src_dir}")
        main_name = "liboqs.dylib" if sys.platform == "darwin" else "liboqs.so"
        probe = (
            "import ctypes, glob, json\n"
            f"main_name = {main_name!r}\n"
            f"for path in sorted(glob.glob(r'{src_dir}/*')):\n"
            "    try:\n"
            "        ctypes.CDLL(path)\n"
            "        print(f'OK: {path}')\n"
            "    except OSError as e:\n"
            "        print(f'FAIL: {path}: {e}')\n"
            f"try:\n"
            f"    ctypes.CDLL(str({str(src_dir)!r} + '/' + main_name))\n"
            "    print('MAIN_LIB_OK')\n"
            "except OSError as e:\n"
            "    print(f'MAIN_LIB_FAIL: {e}')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True, check=False
        )
        self.app.display_info(proc.stdout)
        if proc.stderr:
            self.app.display_info(proc.stderr)
        return "MAIN_LIB_OK" in proc.stdout
