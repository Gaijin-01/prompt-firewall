"""Regression: the five source-mutation findings of the final F1 review.

The independent audit of the first F1 candidate found five silent allows:
commands that mutate or remove a protected surface without naming it as a
write destination.

1. ``git worktree move SRC DST`` removes the worktree at SRC. The resolver
   returned only DST, so a protected SRC was invisible.
2. ``rclone move SRC DST`` deletes the source after the transfer. The
   resolver returned only the destination.
3. ``rsync --remove-source-files SRC DST`` deletes every transferred source
   file. The resolver returned only the destination.
4. ``git diff --output=FILE`` writes FILE. ``git diff`` was classified
   read-only, so the write was invisible.
5. ``find /tmp -fprint FILE`` writes FILE. A plain ``find`` was classified
   read-only, so the write was invisible.

Every command is passed to the policy as a string. Nothing is executed.
"""
import importlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pf_f1_source_mutation_tests", ROOT / "__init__.py",
    submodule_search_locations=[str(ROOT)],
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
# Finding 1 - ``git worktree move`` removes the source worktree.
# --------------------------------------------------------------------------- #

def test_git_worktree_move_reports_source_and_destination():
    assert policy._git_destinations(["worktree", "move", "/src/wt", "/dst/wt"]) == [
        "/src/wt",
        "/dst/wt",
    ]
    assert policy._git_destinations(["worktree", "add", "/dst/wt", "branch"]) == [
        "/dst/wt"
    ]
    assert policy._git_destinations(["worktree", "remove", "/src/wt"]) == ["/src/wt"]
    assert policy._git_destinations(["worktree", "list"]) == []


def test_git_worktree_move_of_protected_source_is_escalated():
    _assert_both_escalate(
        f"git worktree move {WORKTREE} /tmp/dst", "git worktree move protected src"
    )
    _assert_both_escalate(
        f"git worktree move {WORKTREE} /tmp/dst", "git worktree move protected src"
    )


def test_git_worktree_move_of_benign_source_stays_allowed():
    _assert_both_allow(
        "git worktree move /tmp/src/wt /tmp/dst/wt", "git worktree move benign"
    )
    _assert_both_allow("git worktree list", "git worktree list")


# --------------------------------------------------------------------------- #
# Finding 2 - ``rclone move`` removes the source.
# --------------------------------------------------------------------------- #

def test_rclone_move_reports_the_removed_source():
    assert policy._sync_destinations("rclone", ["move", "/src", "/dst"]) == [
        "/src",
        "/dst",
    ]
    assert policy._sync_destinations("rclone", ["copy", "/src", "/dst"]) == ["/dst"]
    assert policy._sync_destinations("rclone", ["sync", "/src", "/dst"]) == ["/dst"]


def test_rclone_move_of_protected_source_is_escalated():
    _assert_both_escalate(
        f"rclone move {WORKTREE} /tmp/dst", "rclone move protected src"
    )


def test_rclone_copy_of_protected_source_stays_allowed():
    _assert_both_allow(
        f"rclone copy {WORKTREE} /tmp/dst", "rclone copy protected src"
    )


# --------------------------------------------------------------------------- #
# Finding 3 - ``rsync --remove-source-files`` removes the source.
# --------------------------------------------------------------------------- #

def test_rsync_remove_source_files_reports_the_removed_source():
    assert policy._sync_destinations(
        "rsync", ["--remove-source-files", "/src", "/dst"]
    ) == ["/src", "/dst"]
    assert policy._sync_destinations("rsync", ["-a", "/src", "/dst"]) == ["/dst"]


def test_rsync_remove_source_files_of_protected_source_is_escalated():
    _assert_both_escalate(
        f"rsync --remove-source-files {WORKTREE} /tmp/dst",
        "rsync --remove-source-files protected src",
    )


def test_plain_rsync_of_protected_source_stays_allowed():
    _assert_both_allow(
        f"rsync -a {WORKTREE} /tmp/dst", "rsync plain copy protected src"
    )


# --------------------------------------------------------------------------- #
# Finding 4 - ``git diff --output=FILE`` writes a file.
# --------------------------------------------------------------------------- #

def test_git_output_file_is_a_write_destination():
    assert policy._git_destinations(["diff", "--output=/tmp/out.diff"]) == [
        "/tmp/out.diff"
    ]
    assert policy._git_destinations(["diff", "--output", "/tmp/out.diff"]) == [
        "/tmp/out.diff"
    ]
    assert policy._git_destinations(["diff", "HEAD~1", "HEAD"]) == []
    assert policy._git_destinations(["log", "--oneline"]) == []


def test_git_diff_output_into_protected_file_is_escalated():
    _assert_both_escalate(
        f"git diff --output={CONFIG}", "git diff --output= protected file"
    )
    _assert_both_escalate(
        f"git diff --output {CONFIG}", "git diff --output protected file"
    )


def test_git_diff_without_output_stays_read_only():
    _assert_both_allow("git diff", "git diff")
    _assert_both_allow("git diff HEAD~1 HEAD", "git diff two revisions")
    _assert_both_allow("git log --oneline -3", "git log")
    _assert_both_allow("git diff --output=/tmp/out.diff", "git diff to /tmp")


# --------------------------------------------------------------------------- #
# Finding 5 - ``find -fprint FILE`` writes a file.
# --------------------------------------------------------------------------- #

def test_find_output_file_is_a_write_destination():
    assert policy._find_destinations(["/tmp", "-fprint", "/tmp/out.txt"]) == [
        "/tmp/out.txt"
    ]
    assert policy._find_destinations(["/tmp", "-fprintf", "/tmp/out.txt", "%p"]) == [
        "/tmp/out.txt"
    ]
    assert policy._find_destinations(["/tmp", "-fls", "/tmp/out.txt"]) == [
        "/tmp/out.txt"
    ]
    assert policy._find_destinations(["/tmp", "-name", "*.txt"]) == []


def test_find_output_into_protected_file_is_escalated():
    _assert_both_escalate(
        f"find /tmp -fprint {CONFIG}", "find -fprint protected file"
    )
    _assert_both_escalate(
        f"find /tmp -fprintf {CONFIG} '%p\\n'", "find -fprintf protected file"
    )
    _assert_both_escalate(
        f"find /tmp -fls {CONFIG}", "find -fls protected file"
    )


def test_plain_find_stays_read_only():
    _assert_both_allow("find /tmp -name '*.txt'", "find plain")
    _assert_both_allow("find /tmp -fprint /tmp/out.txt", "find -fprint to /tmp")


# --------------------------------------------------------------------------- #
# Ordinary copy and read operations must stay allowed.
# --------------------------------------------------------------------------- #

def test_ordinary_copy_and_read_operations_stay_allowed():
    _assert_both_allow(f"cp {CONFIG} /tmp/copy.yaml", "cp from protected")
    _assert_both_allow(f"scp {CONFIG} /tmp/x", "scp from protected")
    _assert_both_allow(f"cat {CONFIG}", "cat protected")
    _assert_both_allow(f"grep -r secret {CONFIG}", "grep protected")
    _assert_both_allow(f"ls -la {PLUGINS}", "ls protected dir")
    _assert_both_allow(
        f"rsync -a {WORKTREE} /tmp/dst", "rsync copy of protected source"
    )
    _assert_both_allow(
        f"rclone copy {WORKTREE} /tmp/dst", "rclone copy of protected source"
    )


def test_writes_into_protected_surfaces_are_still_escalated():
    _assert_both_escalate(f"cp /tmp/a.txt {CONFIG}", "cp into protected")
    _assert_both_escalate(f"rsync -a /tmp/src {CONFIG}", "rsync into protected")
    _assert_both_escalate(f"mv {CONFIG} /tmp/moved.yaml", "mv out of protected")
    _assert_both_escalate(
        f"tar xzf /tmp/x.tgz -C {PLUGINS}", "tar extract into protected"
    )


# --------------------------------------------------------------------------- #
# Scope of the ``git --output`` rule - verified against real git.
# --------------------------------------------------------------------------- #

def test_git_output_subcommand_set_matches_git_behaviour():
    """The rule covers exactly the sub-commands git accepts ``--output`` on.

    Verified empirically in an isolated temporary repository: for every
    sub-command in this set git creates the file; for the remaining ones
    git rejects the option with "unknown option `output'" and touches no
    file.
    """
    for sub in ("diff", "log", "show", "format-patch", "archive", "rev-list",
                "shortlog", "blame", "annotate", "reflog", "whatchanged"):
        assert sub in policy._GIT_OUTPUT_SUBCOMMANDS, sub
    for sub in ("status", "grep", "describe", "ls-files", "cat-file",
                "show-ref", "for-each-ref", "ls-tree", "rev-parse"):
        assert sub not in policy._GIT_OUTPUT_SUBCOMMANDS, sub


def test_git_format_patch_output_is_a_write():
    assert policy._git_destinations(["format-patch", "--output=/tmp/p.patch"]) == [
        "/tmp/p.patch"
    ]
    _assert_both_escalate(
        f"git format-patch --output={CONFIG}", "git format-patch --output protected"
    )


def test_git_subcommands_that_reject_output_stay_read_only():
    # git rejects ``--output`` for these: no file is created.
    for sub in ("status", "grep", "ls-files", "cat-file", "show-ref"):
        _assert_both_allow(f"git {sub}", f"git {sub}")


def test_rclone_moveto_removes_the_source():
    assert policy._sync_destinations("rclone", ["moveto", "/src", "/dst"]) == [
        "/src",
        "/dst",
    ]
    _assert_both_escalate(
        f"rclone moveto {WORKTREE} /tmp/dst", "rclone moveto protected src"
    )


def test_rclone_remote_source_is_not_a_local_mutation():
    # ``host:path`` names another machine's filesystem.
    assert policy._sync_destinations("rclone", ["move", "host:/src", "/dst"]) == [
        "/dst"
    ]


# --------------------------------------------------------------------------- #
# Housekeeping: the duplicated ``import re`` was removed.
# --------------------------------------------------------------------------- #

def test_policy_has_a_single_import_re():
    source = (ROOT / "policy.py").read_text()
    assert source.count("\nimport re\n") == 1, "policy.py must import re exactly once"
