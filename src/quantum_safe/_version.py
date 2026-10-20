"""Package version: ``__version__`` as a string and ``__version_info__`` as a tuple."""

# This file is the single source of truth for the package version.
# pyproject.toml reads from here via hatch-vcs in release builds;
# during development we just hardcode it.
__version__ = "1.0.0"
__version_info__ = (1, 0, 0)
