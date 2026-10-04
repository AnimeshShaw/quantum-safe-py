"""D5: a missing cbor2 must fail loudly, never fall back to another format."""

from __future__ import annotations

import subprocess
import sys
import textwrap


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-W", "ignore", "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_import_fails_loudly_without_cbor2() -> None:
    result = _run(
        """
        import sys
        sys.modules["cbor2"] = None   # makes "import cbor2" raise ImportError
        try:
            import quantum_safe._internal.serialization
        except ImportError as exc:
            print("IMPORT_ERROR:", exc)
            raise SystemExit(0)
        raise SystemExit("imported without cbor2")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "IMPORT_ERROR:" in result.stdout
    assert "requires the 'cbor2' package" in result.stdout
    assert "no fallback format" in result.stdout


def test_no_json_fallback_remains() -> None:
    import quantum_safe._internal.serialization as ser

    assert ser.BACKEND == "cbor2"
    assert ser.dumps({"a": 1})[:1] == b"\xa1"  # a CBOR map, not JSON
    assert not hasattr(ser, "_B64_PREFIX")
