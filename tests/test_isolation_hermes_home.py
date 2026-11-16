"""The plugin must never fall back to the operator's live ~/.hermes.

Regression guard for the isolation defect found during the 1.1.6 acceptance
run: an isolated profile without hermes_cli.config.get_hermes_home made the
plugin fall back to ~/.hermes and write its audit trail into the live
profile.  An explicit HERMES_HOME must always win.
"""
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pf_iso_tests", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
)
assert spec and spec.loader
pf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pf
spec.loader.exec_module(pf)


def test_hermes_home_env_var_wins(monkeypatch, tmp_path):
    isolated = tmp_path / "isolated-home"
    monkeypatch.setenv("HERMES_HOME", str(isolated))
    resolved = Path(pf._hermes_home()).resolve()
    assert resolved == isolated.resolve(), resolved


def test_hermes_home_env_var_is_absolute(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", "relative-home")
    resolved = Path(pf._hermes_home())
    assert resolved.is_absolute(), resolved


def test_audit_path_follows_the_isolated_home(monkeypatch, tmp_path):
    isolated = tmp_path / "isolated-home"
    monkeypatch.setenv("HERMES_HOME", str(isolated))
    assert Path(pf._audit_path()).resolve().is_relative_to(isolated.resolve()), pf._audit_path()
