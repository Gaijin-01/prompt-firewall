"""The surrogate scan is exactly equivalent to the per-character test.

``_has_surrogate`` replaces ``any(0xD800 <= ord(ch) <= 0xDFFF for ch in
text)`` in the path normalizer.  The replacement is only legitimate if it
detects EXACTLY the same set of strings, so this test pins the
equivalence:

* exhaustively over every single Unicode code point, and
* over randomly generated multi-character strings that mix surrogate,
  non-surrogate and astral code points.

The random cases use a fixed seed, so a failure is reproducible.
"""

from __future__ import annotations

import random

import pytest

import pf_loader

policy = pf_loader.load_module("policy")


def _reference(text: str) -> bool:
    """The original per-character surrogate test."""
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def test_exhaustive_over_every_code_point():
    """Every code point, alone and embedded in a path, classifies the same."""
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            sample = "a" + chr(cp) + "/b"
        else:
            sample = chr(cp)
        assert policy._has_surrogate(sample) == _reference(sample), (
            f"mismatch at U+{cp:04X}")


def test_random_multi_character_strings():
    """Mixed strings, including astral code points, classify the same."""
    rng = random.Random(20261127)
    for _ in range(20000):
        size = rng.randint(0, 16)
        chars = []
        for _ in range(size):
            pick = rng.random()
            if pick < 0.2:
                cp = rng.randint(0xD800, 0xDFFF)
            elif pick < 0.4:
                cp = rng.randint(0x10000, 0x10FFFF)
            else:
                cp = rng.randint(0, 0xD7FF)
            chars.append(chr(cp))
        sample = "".join(chars)
        assert policy._has_surrogate(sample) == _reference(sample), (
            f"mismatch on {sample!r}")


@pytest.mark.parametrize("text,expected", [
    ("", False),
    ("/home/sefi/.hermes/config.yaml", False),
    ("/tmp/naïve/café.txt", False),
    ("/tmp/\U0001F600/emoji.txt", False),
    ("/tmp/\ud800", True),
    ("/tmp/a\udfffb", True),
    ("\ud800", True),
    ("\udfff", True),
])
def test_known_cases(text, expected):
    assert policy._has_surrogate(text) is expected
    assert policy._has_surrogate(text) == _reference(text)


def test_normalize_path_still_rejects_surrogate_paths():
    """The path normalizer still refuses a surrogate-bearing path."""
    assert policy.normalize_path("/tmp/\ud800/x") == ""
    assert policy.normalize_path("/tmp/a\udfffb") == ""
    assert policy.normalize_path("/tmp/ok.txt") != ""
