#!/usr/bin/env python3
"""Run BOTH suites of the prompt-firewall package.

* ``tests/test_firewall.py`` - plain ``test_*`` functions.
* ``tests/test_native_integration.py`` - ``unittest.TestCase`` classes.

Loading is package-relative (importlib.util.spec_from_file_location) so the
suites run without the plugin being installed.
"""

from __future__ import annotations

import importlib.util
import sys
import time
import traceback
import unittest
from pathlib import Path

import os
PKG = Path(os.environ.get("PF_PKG_DIR") or Path(__file__).resolve().parent.parent)
TESTS = PKG / "tests"


def load_pkg():
    spec = importlib.util.spec_from_file_location(
        "pfpkg_run", PKG / "__init__.py", submodule_search_locations=[str(PKG)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pfpkg_run"] = mod
    spec.loader.exec_module(mod)
    return mod


load_pkg()
sys.path.insert(0, str(TESTS))


def run_functions():
    spec = importlib.util.spec_from_file_location(
        "pf_primary", TESTS / "test_firewall.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pf_primary"] = mod
    spec.loader.exec_module(mod)
    names = sorted(n for n in dir(mod) if n.startswith("test_"))
    passed = failed = 0
    for name in names:
        fn = getattr(mod, name)
        if not callable(fn):
            continue
        try:
            fn()
            passed += 1
            print(f"PASS primary::{name}")
        except Exception:
            failed += 1
            print(f"FAIL primary::{name}")
            traceback.print_exc()
    return passed, failed


def run_native():
    spec = importlib.util.spec_from_file_location(
        "pf_native", TESTS / "test_native_integration.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pf_native"] = mod
    spec.loader.exec_module(mod)
    suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    return result.testsRun - len(result.failures) - len(result.errors), (
        len(result.failures) + len(result.errors)
    )


t0 = time.time()
p1, f1 = run_functions()
print("\n--- native ---")
p2, f2 = run_native()
print(f"\nPRIMARY passed={p1} failed={f1}")
print(f"NATIVE  passed={p2} failed={f2}")
print(f"TOTAL   passed={p1 + p2} failed={f1 + f2} time={time.time() - t0:.2f}s")
sys.exit(1 if (f1 or f2) else 0)
