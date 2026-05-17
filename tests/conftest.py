import pytest


def pytest_collection_modifyitems(config, items):
    try:
        import oqs  # noqa: F401

        _has_liboqs = True
    except ImportError:
        _has_liboqs = False

    skip_liboqs = pytest.mark.skip(reason="liboqs-python not installed")

    for item in items:
        if not _has_liboqs and (
            item.get_closest_marker("requires_liboqs") or item.get_closest_marker("requires_oqs")
        ):
            item.add_marker(skip_liboqs)
