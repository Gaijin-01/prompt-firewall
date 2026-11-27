"""Contract: lazy invisible normalisation never materialises an index map.

Permanent release-candidate test.  The plugin package is imported by path,
so no installed plugin and no live Hermes are involved.

RED (published 1.1.8): ``_strip_invisible_map`` always walks the whole
string and always returns a full index map, so ``len(index_map) == 0`` fails
for benign input.

GREEN (candidate): the scanner takes an identity fast path when no invisible
character is present.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent

_ZWSP = chr(0x200B)
_RLO = chr(0x202E)


def _load_plugin_package() -> types.ModuleType:
    pkg_name = "prompt_firewall_invisible_test"
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


def test_benign_text_returns_lazy_identity_map():
    text = "hello world\n" * 10
    cleaned, index_map = detectors._strip_invisible_map(text)
    assert cleaned == text
    assert len(index_map) == 0, "benign input must not materialise an index map"


def test_zero_width_and_bidi_coordinates_are_exact():
    original = "ab" + _ZWSP + "cd" + _RLO + "ef"
    cleaned, index_map = detectors._strip_invisible_map(original)
    assert cleaned == "abcdef"
    assert list(index_map) == [0, 1, 3, 4, 6, 7]


def test_multilingual_text_is_unchanged():
    text = "Привет שלום 世界 مرحبا\n" * 4
    cleaned, index_map = detectors._strip_invisible_map(text)
    assert cleaned == text
    assert len(index_map) == 0


def test_invisible_codepoint_set_has_exactly_thirty_six_members():
    assert len(detectors._INVISIBLE_CODEPOINTS) == 36


def test_parser_independent_fallback_matches_the_fast_path():
    """The fallback derivation must equal the ``re._parser`` derivation.

    If the two diverged, an invisible character could survive normalisation
    on an unsupported interpreter and a finding would be reported at the
    wrong offset.
    """
    assert detectors._invisible_codepoints_fallback() == detectors._INVISIBLE_CODEPOINTS


def test_every_invisible_codepoint_is_actually_matched_by_the_regex():
    for cp in detectors._INVISIBLE_CODEPOINTS:
        assert detectors._INVISIBLE_RE.fullmatch(chr(cp)), hex(cp)
