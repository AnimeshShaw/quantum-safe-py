"""Sphinx configuration for quantum-safe documentation."""

import sys
import os

# Make the source package importable without installing
sys.path.insert(0, os.path.abspath("../src"))

# ---------------------------------------------------------------------------
# Project metadata
# ---------------------------------------------------------------------------
project = "quantum-safe"
author = "Animesh"
copyright = "2024, Animesh"
release = "0.1.0"
version = "0.1"

# ---------------------------------------------------------------------------
# General config
# ---------------------------------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",          # Google / NumPy docstrings
    "sphinx.ext.viewcode",          # [source] links on every class/function
    "sphinx.ext.intersphinx",       # links to Python / cryptography docs
    "sphinx.ext.todo",
    "sphinx_autodoc_typehints",     # renders type annotations as prose
]

autosummary_generate = True
autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"
always_document_param_types = True
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_rtype = False          # rtype merged into Returns section
napoleon_attr_annotations = True
todo_include_todos = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    # "cryptography": ("https://cryptography.io/en/latest", None),
}

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# ---------------------------------------------------------------------------
# HTML output — Furo theme
# ---------------------------------------------------------------------------
html_theme = "furo"
html_title = "quantum-safe"
html_static_path = ["_static"]
html_show_sourcelink = True

html_theme_options = {
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
    "light_css_variables": {
        "color-brand-primary": "#7C3AED",
        "color-brand-content": "#7C3AED",
    },
    "dark_css_variables": {
        "color-brand-primary": "#A78BFA",
        "color-brand-content": "#A78BFA",
    },
    "footer_icons": [],
}

# ---------------------------------------------------------------------------
# Autodoc tweaks — skip private internals
# ---------------------------------------------------------------------------
def skip_member(app, what, name, obj, skip, options):
    """Skip dunder methods and private helpers from API docs."""
    if name.startswith("_") and name not in (
        "__init__",
        "__eq__",
        "__hash__",
        "__repr__",
        "__bytes__",
        "__len__",
    ):
        return True
    return skip


def setup(app):
    app.connect("autodoc-skip-member", skip_member)
