"""Regressions for the P0-2 shell parser and audit writer fixes."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pf_loader import load_package, load_module  # noqa: E402


def _neutral_root():
    """A disposable root outside any .hermes tree, independent of TMPDIR."""
    return Path(tempfile.mkdtemp(prefix="pf118-neutral-", dir="/tmp"))


def test_newline_is_a_command_separator():
    """Multi-line scripts must not collapse into one shlex segment."""
    policy = load_module("policy")
    cmd = "echo first\ncd /tmp\nrm -rf ./build"
    segments = policy._shell_segments(cmd)
    assert len(segments) == 3, segments
    assert segments[1][0] == "cd"


def test_relative_destination_uses_execution_cwd(tmp_path, monkeypatch):
    """A relative write resolves against the passed cwd, not the process cwd."""
    policy = load_module("policy")
    monkeypatch.chdir("/")  # hostile ambient cwd
    dests = policy.extract_shell_write_targets("rm -rf logs/old.txt")
    # With no known cwd the path stays relative and is not rooted at "/".
    assert all(not d.startswith("/") for d in dests), dests
    cwd = str(tmp_path)
    dests = policy._shell_write_destinations("rm -rf logs/old.txt", cwd=cwd)
    assert os.path.join(cwd, "logs/old.txt") in dests, dests


def test_variable_assignment_and_cd_chain(tmp_path):
    """BASE=/x; cd $BASE; rm -rf $BASE must resolve to an absolute path."""
    policy = load_module("policy")
    base = str(tmp_path / "worktree")
    cmd = f'BASE={base}\ncd "$BASE"\nrm -rf "$BASE"\n'
    dests = policy._shell_write_destinations(cmd)
    assert base in dests, dests


def test_multiline_command_not_false_positive(tmp_path):
    """The reproduced live false positive must now be allowed."""
    policy = load_module("policy")
    base = str(tmp_path / "baseline")
    cmd = (
        "set -e\n"
        f'BASE={base}\n'
        'rm -rf "$BASE"\n'
        'mkdir -p "$BASE"\n'
        'cd /tmp\n'
        f'echo head > "$BASE/head.txt"\n'
    )
    verdict = policy.evaluate_tool_call("terminal", {"command": cmd})
    assert verdict.action == "allow", (verdict.action, verdict.reason)
    assert verdict.reason == "no_violation"


def test_scratch_exclusion_follows_path_not_active_home(monkeypatch):
    """A real <home>/.hermes/cache path stays scratch with another active home."""
    policy = load_module("policy")
    root = _neutral_root()
    try:
        scratch = root / "fixtures" / ".hermes" / "cache" / "work" / "file.txt"
        scratch.parent.mkdir(parents=True)
        scratch.write_text("scratch", encoding="utf-8")
        active_home = root / "different_home" / "active"
        active_home.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(root / "fixtures"))
        monkeypatch.setenv("HERMES_HOME", str(active_home))
        monkeypatch.setenv("TMPDIR", str(root))
        assert ".hermes/cache" in str(scratch)
        assert not policy.is_protected_path(str(scratch)), scratch
        assert not policy.is_control_plane_path(str(scratch)), scratch
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_protected_aliases_remain_protected_with_relocated_home(monkeypatch):
    """Relocating HERMES_HOME must not deprotect plugin/config/instruction files."""
    policy = load_module("policy")
    root = _neutral_root()
    try:
        active_home = root / "different_home" / "active"
        active_home.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(root / "fixtures"))
        monkeypatch.setenv("HERMES_HOME", str(active_home))
        monkeypatch.setenv("TMPDIR", str(root))
        home = root / "fixtures" / ".hermes"
        protected = [
            home / "plugins" / "prompt-firewall" / "policy.py",
            home / "config.yaml",
            home / "AGENTS.md",
            home / "SOUL.md",
        ]
        for path in protected:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x", encoding="utf-8")
            assert policy.is_protected_path(str(path)), path
            assert policy.is_control_plane_path(str(path)), path
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_nested_home_and_alias_traversal_are_not_downgraded(monkeypatch):
    """Nested .hermes roots and symlink aliases cannot become scratch."""
    policy = load_module("policy")
    root = _neutral_root()
    try:
        active_home = root / "different_home" / "active"
        active_home.mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(active_home))
        monkeypatch.setenv("TMPDIR", str(root))
        fixture_home = root / "fixtures"
        nested_parent = fixture_home / ".hermes" / "cache" / "fixture"
        nested = nested_parent / ".hermes" / "AGENTS.md"
        nested.parent.mkdir(parents=True)
        nested.write_text("x", encoding="utf-8")
        monkeypatch.setenv("HOME", str(nested_parent))
        assert policy.is_protected_path(str(nested)), nested

        monkeypatch.setenv("HOME", str(fixture_home))
        plugin_dir = fixture_home / ".hermes" / "plugins" / "prompt-firewall"
        plugin_dir.mkdir(parents=True)
        alias = root / "fixtures" / ".hermes" / "cache" / "plugin_alias"
        alias.parent.mkdir(parents=True, exist_ok=True)
        try:
            alias.symlink_to(plugin_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
        alias_file = alias / "policy.py"
        assert policy.is_protected_path(str(alias_file)), alias_file

        traversal = root / "fixtures" / ".hermes" / "cache" / ".." / "plugins" / "prompt-firewall" / "policy.py"
        assert policy.is_protected_path(str(traversal)), traversal
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_heredoc_body_is_not_executed_as_commands(tmp_path):
    """A heredoc body containing write-looking lines is data, not commands."""
    policy = load_module("policy")
    out = str(tmp_path / "out.txt")
    cmd = f"cat > {out} <<'EOF'\nrm -rf /etc\nEOF\n"
    segments = policy._shell_segments(cmd)
    assert all(s[0] != "rm" for s in segments if s), segments


def test_audit_writer_fields_and_routing(tmp_path, monkeypatch):
    """Audit records carry attribution/timing and honor the explicit sink."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    monkeypatch.setenv("PROMPT_FIREWALL_MODE", "test")
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("PROMPT_FIREWALL_AUDIT_LOG", str(log))
    pf = load_package()
    pf.audit_event(
        event="block", reason="unit", source="unit:test",
        session_id="sess-1", tool_call_id="call-1",
        scan_ms=1.23456, policy_ms=2.34567, audit_ms=3.45678,
    )
    rec = json.loads(log.read_text(encoding="utf-8").strip())
    assert rec["event_id"]
    assert rec["mode"] == "test"
    assert rec["session_id"] == "sess-1"
    assert rec["tool_call_id"] == "call-1"
    assert rec["scan_ms"] == 1.235
    assert rec["policy_ms"] == 2.346
    assert rec["audit_ms"] == 3.457
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_mode_routing_without_explicit_sink(tmp_path, monkeypatch):
    """Without an explicit sink, test mode uses a suffixed log file."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    monkeypatch.delenv("PROMPT_FIREWALL_AUDIT_LOG", raising=False)
    monkeypatch.setenv("PROMPT_FIREWALL_MODE", "probe")
    pf = load_package()
    expected = tmp_path / "hermes" / "logs" / "prompt-firewall.probe.jsonl"
    assert pf._audit_path() == str(expected)
