"""Regression controls for evaluation-local action-path caches.

The 1.1.9 action-path optimization memoized path resolution, argument walking,
shell destinations and executable views.  These controls pin the contract that
fixed the two pre-release regressions:

* an environment change between evaluations must never reuse a stale path
  resolution or shell destination;
* overlapping evaluations (including nested ones) must never share cache
  state, and an exception must restore the caller's state;
* no cache may live in a process-global mutable module attribute.

Shell commands in these tests are only PARSED by the policy; no file is
written.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from pf_loader import load_module  # noqa: E402

policy = load_module("policy")
eval_context = load_module("_eval_context")


def _home_case(monkeypatch, tmp_path: Path, tag: str) -> None:
    home = tmp_path / tag
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))


def test_environment_change_does_not_reuse_stale_shell_destinations(
        monkeypatch, tmp_path: Path) -> None:
    """A HOME change between evaluations must change the verdict again.

    On the unfixed candidate the process-global shell memo kept the first
    evaluation's expansion and returned ALLOW for the second environment even
    though a fresh evaluation correctly returned APPROVE.
    """
    command = "cd ~ && echo hi > .hermes/MEMORY.md"
    args = {"command": command, "cwd": "/tmp"}
    _home_case(monkeypatch, tmp_path, "A")
    first = policy.evaluate_tool_call("terminal", args)
    _home_case(monkeypatch, tmp_path, "B")
    second = policy.evaluate_tool_call("terminal", args)
    assert first.action == "approve", (first.action, first.reason)
    assert second.action == "approve", (second.action, second.reason)
    assert first.reason == second.reason


def test_helper_outside_evaluation_never_retains_environment(
        monkeypatch, tmp_path: Path) -> None:
    """Calling a helper directly must re-read the environment every time."""
    _home_case(monkeypatch, tmp_path, "A")
    first = policy.normalize_path("~/.hermes/MEMORY.md")
    _home_case(monkeypatch, tmp_path, "B")
    second = policy.normalize_path("~/.hermes/MEMORY.md")
    assert first != second
    assert first.startswith(str(tmp_path / "A"))
    assert second.startswith(str(tmp_path / "B"))


def test_overlapping_evaluations_have_independent_cache_states() -> None:
    """Two threads must not observe each other's evaluation caches."""
    observed: dict[str, object] = {}
    barrier = threading.Barrier(2)

    def worker(tag: str) -> None:
        token = eval_context.bind_eval_state()
        try:
            state = eval_context.eval_state()
            state["marker"] = tag
            state["memo"] = {tag: tag}
            barrier.wait(timeout=5)
            seen = eval_context.eval_state()
            observed[tag] = (seen.get("marker"), dict(seen.get("memo", {})))
        finally:
            eval_context.reset_eval_state(token)

    threads = [threading.Thread(target=worker, args=(t,)) for t in ("left", "right")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert observed == {
        "left": ("left", {"left": "left"}),
        "right": ("right", {"right": "right"}),
    }


def test_nested_evaluation_gets_fresh_state_and_restores_outer() -> None:
    """A nested evaluation must not see or destroy the outer evaluation's cache."""
    outer_token = eval_context.bind_eval_state()
    try:
        eval_context.eval_state()["marker"] = "outer"
        before = eval_context.eval_state().get("marker")
        verdict = policy.evaluate_tool_call("terminal", {"command": "ls -la"})
        assert verdict is not None
        assert eval_context.eval_state().get("marker") == before == "outer"
    finally:
        eval_context.reset_eval_state(outer_token)

    token = eval_context.bind_eval_state()
    try:
        eval_context.eval_state()["marker"] = "outer-2"
        eval_context.eval_state()["shell_write"] = {"sentinel": "outer"}
        nested = eval_context.bind_eval_state()
        try:
            assert eval_context.eval_state().get("marker") is None
            assert eval_context.eval_state().get("shell_write", {}) == {}
            eval_context.eval_state()["marker"] = "inner"
        finally:
            eval_context.reset_eval_state(nested)
        assert eval_context.eval_state().get("marker") == "outer-2"
        assert eval_context.eval_state().get("shell_write") == {"sentinel": "outer"}
    finally:
        eval_context.reset_eval_state(token)


def test_exception_cleanup_restores_previous_cache_state(monkeypatch) -> None:
    """An exception during evaluation must not leave a cache bound."""
    token = eval_context.bind_eval_state()
    try:
        eval_context.eval_state()["marker"] = "kept"

        def explode(*args, **kwargs):
            raise RuntimeError("simulated policy failure")

        monkeypatch.setattr(policy, "_evaluate_tool_call", explode)
        with pytest.raises(RuntimeError):
            policy.evaluate_tool_call("terminal", {"command": "ls"})
        assert eval_context.eval_state().get("marker") == "kept"
    finally:
        eval_context.reset_eval_state(token)
    assert eval_context.eval_state().get("marker") is None


@pytest.mark.parametrize("module, names", [
    (policy, ["_SHELL_WRITE_MEMO", "_NORMALIZE_PATH_MEMO",
              "_ARG_STRINGS_MEMO", "_ACTIVE_HERMES_HOME_MEMO"]),
    (load_module("executable_view"), ["_EXECUTABLE_VIEW_MEMO"]),
])
def test_no_process_global_memo_attributes(module, names) -> None:
    """Every 1.1.9 cache must be evaluation-local, not a module global."""
    for name in names:
        assert not hasattr(module, name), f"process-global cache remains: {name}"
