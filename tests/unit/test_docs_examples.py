"""Every Python example in the practical guides must run exactly as written.

Documentation that drifts from the code is a bug in the library. The guides listed below are
executable: each ``.. code-block:: python`` block is run in order, in one namespace per file,
with the library's own deprecations turned into errors so an example that omits ``context=``
or ``expected_aad=`` fails here.
"""

from __future__ import annotations

import pathlib
import re
import warnings

import pytest

pytestmark = pytest.mark.requires_liboqs

GUIDES = pathlib.Path(__file__).resolve().parents[2] / "docs" / "guides"
EXECUTABLE = [
    "upgrading.rst",
    "choosing.rst",
    "cookbook.rst",
    "interop.rst",
    "compliance.rst",
    "security.rst",
]

_BLOCK = re.compile(
    r"^(?P<indent> *)\.\. code-block:: python\n(?:[ ]*:[^\n]*\n)*\n(?P<body>(?:(?P=indent) +[^\n]*\n|\n)+)",
    re.M,
)


def _blocks(text: str) -> list[tuple[int, str]]:
    out = []
    for m in _BLOCK.finditer(text):
        lines = m.group("body").split("\n")
        width = min((len(x) - len(x.lstrip()) for x in lines if x.strip()), default=0)
        out.append((text[: m.start()].count("\n") + 1, "\n".join(x[width:] for x in lines)))
    return out


@pytest.mark.parametrize("name", EXECUTABLE)
def test_guide_examples_run(name: str) -> None:
    path = GUIDES / name
    blocks = _blocks(path.read_text(encoding="utf-8"))
    namespace: dict[str, object] = {"__name__": "__doc_example__"}
    for line, code in blocks:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            warnings.filterwarnings("error", message=r"verify\(\) without context=")
            warnings.filterwarnings("error", message=r"Envelope.open\(\) without expected_aad=")
            try:
                exec(compile(code, f"{name}:{line}", "exec"), namespace)  # noqa: S102
            except Exception as exc:
                raise AssertionError(
                    f"{name}, block at line {line}: {type(exc).__name__}: {exc}"
                ) from exc


def test_every_executable_guide_has_examples() -> None:
    for name in EXECUTABLE:
        assert _blocks((GUIDES / name).read_text(encoding="utf-8")), name
