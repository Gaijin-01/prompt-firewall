"""Path-based loader for the plugin package under test.

Mirrors the loader used by ``test_firewall.py``: every suite in this directory
exercises the same tree, with no installed plugin and no live plugin involved.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent
PACKAGE = "pfplugin_under_test"


def load_package() -> types.ModuleType:
    """Import the plugin directory as a package, by path."""
    if PACKAGE in sys.modules:
        return sys.modules[PACKAGE]
    spec = importlib.util.spec_from_file_location(
        PACKAGE,
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = PACKAGE
    module.__path__ = [str(PLUGIN_DIR)]
    sys.modules[PACKAGE] = module
    spec.loader.exec_module(module)
    return module


def load_module(name: str) -> types.ModuleType:
    """Import a submodule of the plugin package under test."""
    load_package()
    return importlib.import_module(PACKAGE + "." + name)
