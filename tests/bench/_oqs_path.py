"""
Windows DLL path registration for liboqs.

On Windows, Python 3.8+ requires explicit DLL directory registration
(os.add_dll_directory) for security — adding to PATH alone is not enough.

Priority order:
  1. OQS_DLL_DIR environment variable — set this to override everything
  2. C:\\Users\\<current user>\\_oqs\\bin — convention used in this project
  3. Nothing extra — if oqs.dll is already on PATH or in site-packages,
     it will be found automatically

Import this module before any `import oqs` call:

    import _oqs_path  # noqa: F401
    import oqs
"""

from __future__ import annotations

import os
import sys

if sys.platform == "win32":
    _candidates = [
        os.environ.get("OQS_DLL_DIR", ""),
        os.path.join(os.path.expanduser("~"), "_oqs", "bin"),
    ]
    for _path in _candidates:
        if _path and os.path.isdir(_path):
            os.add_dll_directory(_path)
            break
