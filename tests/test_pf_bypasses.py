#!/usr/bin/env python3
"""P0-A/P0-B bypass regressions, portably expressed.

Every fixture below is a synthetic path under a temporary root. The strings are
passed to the policy classifier only; no command or code payload is executed.
"""
from __future__ import annotations

import pytest

from pf_loader import load_module

POLICY = load_module('policy')

_SEG = ["hermes-research-shell", "skills", "research-shell-orchestrate", "SKILL.md"]
REL_SKILL = "/".join(_SEG)


@pytest.fixture
def candidate_skill(tmp_path):
    root = tmp_path / "candidate"
    skill = root.joinpath(*_SEG)
    skill.parent.mkdir(parents=True)
    skill.write_text("# synthetic skill fixture\n", encoding="utf-8")
    return str(skill), str(root)


def test_defect_a_exec_branch_must_gate_on_durable_instruction_surface(candidate_skill):
    skill, _ = candidate_skill
    v = POLICY.evaluate_tool_call("terminal", {"command": "printf x > " + skill})
    assert v.blocked, f"exec durable write ALLOWED ({v.action}/{v.reason})"


def test_defect_a_exec_branch_relative_destination_must_be_refused(candidate_skill):
    skill, root = candidate_skill
    v = POLICY.evaluate_tool_call(
        "terminal", {"command": "cd " + root + " && printf x > " + REL_SKILL})
    assert v.blocked, f"relative exec durable write ALLOWED ({v.action}/{v.reason})"


def test_defect_a_python_exec_branch_must_gate_on_durable_instruction_surface(candidate_skill):
    skill, _ = candidate_skill
    v = POLICY.evaluate_tool_call(
        "execute_code", {"code": "open(" + repr(skill) + ",'wb').write(b'x')"})
    assert v.blocked, f"python exec durable write ALLOWED ({v.action}/{v.reason})"


def test_defect_a_file_tool_branch_does_refuse_the_same_destination(candidate_skill):
    skill, _ = candidate_skill
    v = POLICY.evaluate_tool_call("write_file", {"path": skill, "content": "x"})
    assert v.blocked, "file-tool branch stopped refusing the destination"


def _copy_payload(skill, source):
    return ("import shutil, os\n"
            "src = " + repr(str(source)) + "\n"
            "dst = " + repr(skill) + "\n"
            "tmp = dst + '.tmp'\n"
            "shutil.copy(src, tmp)\n"
            "os.replace(tmp, dst)\n")


def test_defect_b_exact_recorded_payload_must_be_refused(candidate_skill, tmp_path):
    skill, _ = candidate_skill
    source = tmp_path / "synthetic_skill_body.md"
    source.write_text("# synthetic source\n", encoding="utf-8")
    v = POLICY.evaluate_tool_call("execute_code", {"code": _copy_payload(skill, source)})
    assert v.blocked, f"recorded payload ALLOWED ({v.action}/{v.reason})"


def test_defect_b_inner_terminal_inside_execute_code_must_be_refused(candidate_skill, tmp_path):
    _, root = candidate_skill
    source = tmp_path / "synthetic_skill_body.md"
    source.write_text("# synthetic source\n", encoding="utf-8")
    inner = ("import shutil, os\n"
             "src = " + repr(str(source)) + "\n"
             "dst = " + repr(REL_SKILL) + "\n"
             "tmp = dst + '.tmp'\n"
             "shutil.copy(src, tmp)\n"
             "os.replace(tmp, dst)\n")
    payload = ("from hermes_tools import terminal\n"
               "terminal(command=\"\"\"cd " + root + " && python3 - <<'PY'\n"
               + inner + "PY\"\"\")\n")
    v = POLICY.evaluate_tool_call("execute_code", {"code": payload})
    assert v.blocked, f"nested shell write ALLOWED ({v.action}/{v.reason})"


def test_defect_b_variable_destination_copy_and_replace_must_be_refused(candidate_skill, tmp_path):
    skill, _ = candidate_skill
    source = tmp_path / "synthetic_skill_body.md"
    source.write_text("# synthetic source\n", encoding="utf-8")
    v = POLICY.evaluate_tool_call("execute_code", {"code": _copy_payload(skill, source)})
    assert v.blocked, f"variable destination ALLOWED ({v.action}/{v.reason})"


def test_defect_b_unresolvable_write_to_durable_surface_must_fail_closed(tmp_path):
    source = tmp_path / "synthetic_skill_body.md"
    source.write_text("# synthetic source\n", encoding="utf-8")
    code = ("import shutil, os\n"
            "dst = os.environ['TARGET']\n"
            "shutil.copy(" + repr(str(source)) + ", dst)\n")
    v = POLICY.evaluate_tool_call("execute_code", {"code": code})
    assert v.action != "allow", f"unresolvable destination ALLOWED ({v.action}/{v.reason})"


def test_defects_are_closed_on_all_three_paths(candidate_skill, tmp_path):
    skill, _ = candidate_skill
    source = tmp_path / "synthetic_skill_body.md"
    source.write_text("# synthetic source\n", encoding="utf-8")
    a = POLICY.evaluate_tool_call("terminal", {"command": "printf x > " + skill})
    b = POLICY.evaluate_tool_call(
        "execute_code", {"code": "open(" + repr(skill) + ",'wb').write(b'x')"})
    c = POLICY.evaluate_tool_call(
        "execute_code", {"code": "import shutil\ndst=os.environ['T']\nshutil.copy('src',dst)"})
    assert a.blocked and b.blocked and c.action != "allow"


def test_the_durable_surface_predicate_itself_is_correct(candidate_skill):
    skill, _ = candidate_skill
    assert POLICY.is_durable_instruction_surface(skill) is True
    assert POLICY.is_protected_path(skill) is False
    assert POLICY.is_control_plane_path(skill) is False
