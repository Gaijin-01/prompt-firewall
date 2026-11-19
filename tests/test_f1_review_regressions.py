"""Regression: the three findings of the independent F1 review.

The review of the first F1 candidate (commit ``a89f4778``) raised three
targeted concerns. Each is pinned here, together with the false positives
that a naive fix would introduce.

1. ``_git_destinations`` returned the sub-command word ``"add"`` instead of
   the worktree path, so ``git worktree add <protected>`` was resolved to a
   non-existent destination. The verdict then depended on the *process*
   working directory: the bogus ``"add"`` was normalized against the CWD, so
   the command was escalated only when the firewall happened to run inside
   the protected Hermes home. That is why the pre-existing suite reported a
   pass: it ran with a CWD under ``~/.hermes``.

2. ``_ambiguous_protected_write`` only ran when the whole command had no
   resolved write target. A benign resolved write in one segment therefore
   masked an unverifiable protected write in another segment.

3. ``_READ_ONLY_SUBCOMMANDS`` listed ``pip config`` as read-only, so the
   mutating ``pip config set``/``unset`` were classified as reads.

Every command is passed to the policy as a string. Nothing is executed.
"""
import importlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pf_f1_review_tests", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
)
assert spec and spec.loader
pf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pf
spec.loader.exec_module(pf)

policy = importlib.import_module(f"{spec.name}.policy")

H = str(policy.normalize_path(str(Path.home() / ".hermes")))
PLUGINS = f"{H}/plugins/prompt-firewall"
CONFIG = f"{H}/config.yaml"
WORKTREE = f"{PLUGINS}/wt"


def _verdict(command: str):
    return policy.evaluate_tool_call("terminal", {"command": command})


def _hook(command: str):
    return pf._on_pre_tool_call(
        tool_name="terminal", args={"command": command}, session_key="test"
    )


def _assert_both_escalate(command: str, label: str) -> None:
    """The command must reach the operator gate on both decision paths."""
    verdict = _verdict(command)
    assert verdict.action == "approve", (
        f"{label}: expected an approval gate, got {verdict.action}/{verdict.reason}"
    )
    hook = _hook(command)
    assert hook is not None and hook.get("action") == "approve", (
        f"{label}: native hook did not escalate ({hook})"
    )


def _assert_both_allow(command: str, label: str) -> None:
    verdict = _verdict(command)
    assert verdict.action == "allow", (
        f"{label}: legitimate operation was escalated "
        f"({verdict.action}/{verdict.reason})"
    )
    hook = _hook(command)
    assert hook is None or hook.get("action") != "approve", (
        f"{label}: native hook escalated a legitimate operation ({hook})"
    )


# --------------------------------------------------------------------------- #
# Finding 1 - ``git worktree add`` must resolve its PATH, not the word "add".
# --------------------------------------------------------------------------- #

def test_git_worktree_destinations_are_the_worktree_path():
    assert policy._git_destinations(["worktree", "add", WORKTREE, "branch"]) == [
        WORKTREE
    ]
    assert policy._git_destinations(["worktree", "add", WORKTREE]) == [WORKTREE]
    assert policy._git_destinations(["worktree", "add", "-b", "topic", WORKTREE]) == [
        WORKTREE
    ]
    assert policy._git_destinations(["worktree", "remove", WORKTREE]) == [WORKTREE]
    assert policy._git_destinations(["worktree", "list"]) == []
    assert policy._git_destinations(["clone", "repo.invalid/x", "/tmp/clone"]) == [
        "/tmp/clone"
    ]


def test_git_worktree_into_protected_surface_is_escalated():
    _assert_both_escalate(
        f"git worktree add {WORKTREE} branch", "git worktree add into plugins"
    )
    _assert_both_escalate(
        f"git worktree add {WORKTREE}", "git worktree add without branch"
    )
    _assert_both_escalate(
        f"git worktree remove {WORKTREE}", "git worktree remove protected"
    )


def test_git_worktree_verdict_is_independent_of_the_working_directory(monkeypatch, tmp_path):
    """The verdict must not depend on where the firewall process runs.

    The pre-existing suite passed the ``git worktree`` case only because it
    ran with a CWD inside the protected Hermes home, where the bogus
    destination ``"add"`` normalized to a protected path.
    """
    command = f"git worktree add {WORKTREE} branch"
    for where in (tmp_path, Path.home(), Path("/tmp")):
        monkeypatch.chdir(where)
        _assert_both_escalate(command, f"git worktree add from cwd {where}")


def test_git_worktree_read_only_and_benign_stay_allowed():
    _assert_both_allow("git worktree list", "git worktree list")
    _assert_both_allow("git worktree add /tmp/wt branch", "git worktree add to /tmp")
    _assert_both_allow("git status", "git status")
    _assert_both_allow("git log --oneline -5", "git log")
    _assert_both_allow("git clone repo.invalid/x /tmp/clone", "git clone to /tmp")


# --------------------------------------------------------------------------- #
# Finding 2 - a benign resolved write must not mask an unverifiable
#              protected write in another segment of the same command.
# --------------------------------------------------------------------------- #

def test_mixed_command_does_not_mask_an_unverifiable_protected_write():
    _assert_both_escalate(
        f"cp /tmp/a.txt /tmp/b.txt ; pip config set --editor {CONFIG}",
        "benign write plus unresolved protected write",
    )
    _assert_both_escalate(
        f"cp /tmp/a.txt /tmp/b.txt ; git worktree add {WORKTREE} branch",
        "benign write plus protected worktree",
    )
    _assert_both_escalate(
        f"echo x > /tmp/out.txt ; tar xzf /tmp/evil.tgz -C {PLUGINS}",
        "benign redirect plus protected extract",
    )


def test_benign_mixed_commands_stay_allowed():
    _assert_both_allow("cp /tmp/a.txt /tmp/b.txt", "single benign write")
    _assert_both_allow(
        "cp /tmp/a.txt /tmp/b.txt ; cp /tmp/c.txt /tmp/d.txt", "two benign writes"
    )
    _assert_both_allow(
        f"cp /tmp/a.txt /tmp/b.txt ; cp {CONFIG} /tmp/c.yaml",
        "benign write plus protected source",
    )


# --------------------------------------------------------------------------- #
# Finding 3 - ``pip config set``/``unset`` mutate; ``list``/``get`` read.
# --------------------------------------------------------------------------- #

def test_pip_config_read_only_classification():
    assert policy._is_read_only_invocation("pip", ["config", "list"]) is True
    assert policy._is_read_only_invocation("pip", ["config", "get", "global.x"]) is True
    assert policy._is_read_only_invocation("pip", ["config"]) is True
    assert policy._is_read_only_invocation("pip", ["config", "set", "k", "v"]) is False
    assert policy._is_read_only_invocation("pip", ["config", "unset", "k"]) is False
    assert policy._is_read_only_invocation("pip", ["list"]) is True
    assert policy._is_read_only_invocation("pip", ["install", "pkg"]) is False


def test_pip_config_read_only_operations_stay_allowed():
    _assert_both_allow("pip config list", "pip config list")
    _assert_both_allow("pip config get global.index-url", "pip config get")
    _assert_both_allow("pip config", "pip config without sub-command")


def test_pip_config_mutation_naming_a_protected_path_is_escalated():
    _assert_both_escalate(
        f"pip config set --editor {CONFIG}", "pip config set with protected path"
    )
    _assert_both_escalate(
        f"pip config set global.index-url {CONFIG}",
        "pip config set with protected value",
    )


def test_pip_config_mutation_without_a_protected_path_is_not_escalated():
    """A value that is not a local path must not be mistaken for one."""
    verdict = _verdict("pip config set global.index-url repo.invalid/x")
    assert verdict.action != "approve", (
        f"a non-path value was treated as a protected write "
        f"({verdict.action}/{verdict.reason})"
    )
    verdict = _verdict("pip config unset global.index-url")
    assert verdict.action != "approve", (
        f"a benign pip config mutation was treated as a protected write "
        f"({verdict.action}/{verdict.reason})"
    )


def test_pip_config_set_to_an_unrelated_file_is_not_a_protected_write():
    verdict = _verdict("pip config set global.index-url /tmp/index-url")
    assert verdict.action == "allow", (
        f"a benign pip config value was escalated ({verdict.action}/{verdict.reason})"
    )


# --------------------------------------------------------------------------- #
# The hook contract itself must not have moved.
# --------------------------------------------------------------------------- #

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


# ---------------------------------------------------------------------------
# Fourth finding (found while adjudicating the three review findings):
# a leading environment assignment hid the write verb from the resolver.
# ---------------------------------------------------------------------------


def test_env_assignment_prefix_does_not_hide_the_write_verb():
    """``FOO=1 rm <protected>`` must not be allowed silently.

    The assignment only sets a variable for the command; the command still
    runs ``rm``. Resolving the command word to ``FOO=1`` hid the write verb
    and let the protected write through.
    """
    cases = [
        f"FOO=1 rm {CONFIG}",
        f"FOO=1 cp /tmp/a.txt {CONFIG}",
        f"FOO=1 tar xzf /tmp/evil.tgz -C {PLUGINS}",
        f"FOO=1 pip config set --editor {CONFIG}",
        f"env FOO=1 rm {CONFIG}",
        f"LC_ALL=C rm {CONFIG}",
    ]
    for command in cases:
        verdict = _verdict(command)
        assert verdict.action == "approve", (command, verdict.action, verdict.reason)


def test_env_assignment_prefix_keeps_benign_commands_allowed():
    cases = [
        "FOO=1 rm /tmp/plain.txt",
        f"FOO=1 ls {PLUGINS}",
        "FOO=1 git status",
        "FOO=1 echo hi > /tmp/out.txt",
    ]
    for command in cases:
        verdict = _verdict(command)
        assert verdict.action == "allow", (command, verdict.action, verdict.reason)


def test_env_assignment_prefix_is_not_mistaken_for_a_path():
    """The assignment token must never be read as the command word."""
    assert policy._shell_verb(["FOO=1", "rm", "/tmp/x"]) == ("rm", ["/tmp/x"])
    assert policy._shell_verb(["env", "FOO=1", "rm", "/tmp/x"]) == ("rm", ["/tmp/x"])
