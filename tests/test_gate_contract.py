"""Contract: the expensive rules carry conservative literal gates.

Permanent release-candidate test.  Portable: it needs no corpus file, no
absolute path and no external harness.  A deterministic filler is generated
in-process.

RED (published 1.1.8): the four expensive rules have no ``_GATES`` entry at
all, so ``detectors._GATES.get(pid) is None`` for each of them.

GREEN (candidate): every expensive rule has a literal gate, and a large
benign document provably satisfies none of the gate literals.
"""

from __future__ import annotations

import importlib.util
import random
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent

#: Rules whose regexes dominate the scan cost on large benign documents.
EXPENSIVE = (
    "mixed_language_override",
    "ignore_previous_instructions_ru",
    "role_spoof_system_turn",
    "api_relay_advertisement",
)

LOREM = (
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod "
    "tempor incididunt ut labore et dolore magna aliqua ut enim ad minim "
    "veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
    "commodo consequat duis aute irure in reprehenderit voluptate velit esse"
)


def _load_plugin_package() -> types.ModuleType:
    pkg_name = "prompt_firewall_gate_test"
    if pkg_name in sys.modules:
        return sys.modules[pkg_name]
    spec = importlib.util.spec_from_file_location(
        pkg_name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)]
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = pkg_name
    module.__path__ = [str(PLUGIN_DIR)]
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)
    return module


pf = _load_plugin_package()
detectors = pf.detectors
prefilter = pf._prefilter


def _filler(n_chars: int, seed: int) -> str:
    """Deterministic filler text of ~n_chars characters (same shape as the
    archived B2 corpus, self-contained so no external file is needed)."""
    rng = random.Random(seed)
    words = LOREM.split()
    out = []
    size = 0
    while size < n_chars:
        chunk = " ".join(rng.choice(words) for _ in range(12))
        out.append(chunk)
        size += len(chunk) + 1
    return " ".join(out)[:n_chars]


def test_expensive_rules_have_literal_gates():
    missing = [pid for pid in EXPENSIVE if detectors._GATES.get(pid) is None]
    assert not missing, f"ungated rules: {missing}"


def test_gates_reject_benign_lorem():
    text = prefilter.normalize_ci(_filler(200_000, 4242))
    for pid in EXPENSIVE:
        kind, lits = detectors._GATES[pid]
        hay = text if kind == "cs" else text
        assert not any(lit in hay for lit in lits), pid


def test_gate_literals_are_a_necessary_condition_for_a_match():
    """A gate must never reject a document the rule actually matches.

    The soundness contract of the gate is

        rule matches T   =>   T contains at least one gate literal

    (not the converse).  This test verifies that direction empirically: it
    builds documents from every gate literal of every gated rule, runs the
    rule's own regex over them, and asserts that whenever the rule matched,
    the gate admitted the document too.  A gate that rejected a matching
    document would suppress a real finding.

    The check is done through the scanner's own gate helper, so it exercises
    the code path used in production.
    """
    for pid, (kind, lits) in detectors._GATES.items():
        pattern = next(r for p, _c, r, _s in detectors._RULES if p == pid)
        for lit in lits:
            for probe in (
                lit,
                lit + " previous instructions",
                "previous " + lit,
                "the system prompt " + lit + " now",
                lit.upper(),
                lit.lower(),
            ):
                matched = bool(pattern.search(probe))
                allowed = detectors._gate_allows(pid, probe, [None])
                if matched:
                    assert allowed, (
                        f"gate rejected a matching document: rule={pid} "
                        f"literal={lit!r}"
                    )
                # A gate literal must be present in the haystack the gate
                # actually searches.  For the "cs" kind that is the raw
                # document; for the "ci" kind it is the case-folded
                # projection -- except for the two rules whose literals are
                # Cyrillic, where the projection only folds ASCII and the
                # scanner therefore admits any non-ASCII document
                # conservatively (``_NONASCII_FALLBACK_GATES``).
                if pid in detectors._NONASCII_FALLBACK_GATES and not probe.isascii():
                    assert allowed, (pid, lit)
                    continue
                hay = probe if kind == "cs" else prefilter.normalize_ci(probe)
                assert any(lit in hay for lit in lits), (pid, lit)


def test_every_gated_rule_id_exists_in_the_rule_table():
    rule_ids = {pid for pid, _c, _r, _s in detectors._RULES}
    unknown = sorted(set(detectors._GATES) - rule_ids)
    assert not unknown, f"gates for unknown rules: {unknown}"
