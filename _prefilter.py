"""Literal prefilter derivation for the PF 1.1.8 rule table (candidate only).

This module is copied into the candidate package ``vendor/pf118_opt`` by
``build_candidate.py``.  The pinned upstream source is untouched.

Soundness contract
------------------
For every rule regex R the derivation below produces a set L of literal
strings with the property

    R matches somewhere in T   =>   T contains some element of L

(under the regex' own flags).  Therefore, if a text contains *none* of L, R
cannot match it and the rule may be skipped without changing any finding.
When no such set can be proven, the rule is never skipped.

Derivation rules (all conservative):

* Only *mandatory* elements of a concatenation may contribute.  Optional
  elements (``MAX_REPEAT`` with ``minimum < 1``) are skipped; a mandatory
  element that yields no provable literal is skipped as well and the search
  continues with the next element of the same concatenation, which is itself
  mandatory, so its literal is guaranteed by any match.
* A ``BRANCH`` contributes the union of its branches' literal sets only when
  *every* branch contributes one and no branch can match the empty string.
* Local flag changes (``(?i:...)``) make the case semantics unknown, so the
  element contributes nothing.
* ``ASSERT``/``ASSERT_NOT``/``AT`` are zero-width: they constrain positions,
  not consumed text, so they contribute no literal.

Case semantics
--------------
``re.IGNORECASE`` does not coincide with ``str.casefold()`` (``U+0131``
matches ASCII ``i`` under ``re.I`` but does not fold to ``i``) and
``str.lower()`` may *lengthen* a string (``U+0130`` -> ``i`` + combining
dot), which would break a contiguous multi-character containment test.

The candidate therefore uses an explicit per-character equivalence-class
projection: for every ASCII letter L the set

    S_L = { t : re matches L against t under re.IGNORECASE }

is computed by an exhaustive scan of the entire Unicode range at build time.
Normalization maps every code point of every S_L to the lowercase ASCII
letter and leaves everything else unchanged.  The projection is 1:1 and
position preserving, so

    T matches literal L (case-insensitively)  =>  normalize(T) contains L

which is exactly the containment test the gate needs.
"""
from __future__ import annotations

import re

try:  # pragma: no cover - exercised via the fallback test
    import re._parser as _sre_parse
except Exception:  # pragma: no cover - private module removed upstream
    _sre_parse = None

#: Translation table (code point -> lowercase ASCII letter) covering every
#: code point that ``re.IGNORECASE`` treats as an ASCII letter.
CASE_TABLE = {'A': 'a', 'B': 'b', 'C': 'c', 'D': 'd', 'E': 'e', 'F': 'f', 'G': 'g', 'H': 'h', 'I': 'i', 'J': 'j', 'K': 'k', 'L': 'l', 'M': 'm', 'N': 'n', 'O': 'o', 'P': 'p', 'Q': 'q', 'R': 'r', 'S': 's', 'T': 't', 'U': 'u', 'V': 'v', 'W': 'w', 'X': 'x', 'Y': 'y', 'Z': 'z', 'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd', 'e': 'e', 'f': 'f', 'g': 'g', 'h': 'h', 'i': 'i', 'j': 'j', 'k': 'k', 'l': 'l', 'm': 'm', 'n': 'n', 'o': 'o', 'p': 'p', 'q': 'q', 'r': 'r', 's': 's', 't': 't', 'u': 'u', 'v': 'v', 'w': 'w', 'x': 'x', 'y': 'y', 'z': 'z', 'İ': 'i', 'ı': 'i', 'ſ': 's', 'K': 'k'}

_TRANSLATION = {ord(k): v for k, v in CASE_TABLE.items()}

#: Minimum literal length accepted for a gate.
MIN_LITERAL_LEN = 3


def normalize_ci(text: str) -> str:
    """Project *text* onto the ``re.IGNORECASE`` ASCII-letter equivalence."""
    if _TRANSLATION:
        return text.translate(_TRANSLATION)
    return text


def _op_name(op) -> str:
    return getattr(op, "name", None) or str(op).rsplit(".", 1)[-1]


def _is_alpha_ascii(s: str) -> bool:
    return bool(s) and s.isascii() and s.isalpha()


def _literal_run(seq, i):
    """Return the string of the consecutive LITERAL ops starting at *i*."""
    chars = []
    j = i
    while j < len(seq) and _op_name(seq[j][0]) == "LITERAL":
        arg = seq[j][1]
        chars.append(arg if isinstance(arg, str) else chr(arg))
        j += 1
    return "".join(chars), j


def _nullable(seq) -> bool:
    """True when *seq* can match the empty string (conservative)."""
    for op, arg in seq:
        name = _op_name(op)
        if name in ("AT", "ASSERT", "ASSERT_NOT"):
            continue
        if name == "LITERAL":
            return False
        if name == "IN":
            continue
        if name == "SUBPATTERN":
            if _nullable(arg[3]):
                continue
            return False
        if name == "ATOMIC_GROUP":
            if _nullable(arg):
                continue
            return False
        if name == "BRANCH":
            if all(_nullable(b) for b in arg[1]):
                continue
            return False
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            if arg[0] < 1:
                continue
            if _nullable(arg[2]):
                continue
            return False
        return False
    return True


def _element_literals(seq, ignorecase: bool):
    """Literal set guaranteed by the concatenation *seq*, or None.

    A list means: any match of *seq* contains at least one of the listed
    literals.  ``None`` means "nothing provable for this element".
    """
    for idx, (op, arg) in enumerate(seq):
        name = _op_name(op)
        if name == "AT":
            continue
        if name in ("ASSERT", "ASSERT_NOT"):
            continue  # zero-width: consumes nothing, constrains no text
        if name == "LITERAL":
            run, _ = _literal_run(seq, idx)
            if ignorecase:
                if _is_alpha_ascii(run) and len(run) >= MIN_LITERAL_LEN:
                    return [run.lower()]
                continue
            if len(run) >= MIN_LITERAL_LEN:
                return [run]
            continue
        if name == "IN":
            continue  # character class: no multi-char literal guaranteed
        if name == "SUBPATTERN":
            _g, add, dele, p = arg
            if (add | dele) != 0:
                continue  # local flag change: case semantics differ
            sub = _element_literals(p, ignorecase)
            if sub:
                return sub
            continue
        if name == "ATOMIC_GROUP":
            sub = _element_literals(arg, ignorecase)
            if sub:
                return sub
            continue
        if name == "BRANCH":
            out: list[str] = []
            ok = True
            for branch in arg[1]:
                if _nullable(branch):
                    # This branch can match the empty string, so a match may
                    # take it and contribute no text: no literal is guaranteed.
                    ok = False
                    break
                sub = _element_literals(branch, ignorecase)
                if not sub:
                    ok = False
                    break
                out.extend(sub)
            if ok and out:
                return out
            continue
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            minimum, _max, sub = arg
            if minimum < 1:
                continue  # optional: may be absent from the match
            if _nullable(sub):
                continue
            lits = _element_literals(sub, ignorecase)
            if lits:
                return lits
            continue
        # Any other opcode (GROUPREF, GROUPREF_EXISTS, ...): nothing provable.
        continue
    return None


def derive_rule_literals(pattern: str, flags: int):
    """Necessary literal condition for *pattern*, or None when unprovable.

    When the private :mod:`re._parser` module is unavailable (or exposes an
    unexpected shape), *None* is returned for **every** pattern.  Callers then
    build no gate at all and the original regex scan runs unchanged, so an
    unsupported interpreter degrades to the published behaviour instead of
    silently dropping rules.
    """
    if _sre_parse is None or not hasattr(_sre_parse, "parse"):
        return None
    ignorecase = bool(flags & re.IGNORECASE)
    try:
        parsed = _sre_parse.parse(pattern, flags)
    except Exception:
        return None
    try:
        lits = _element_literals(parsed, ignorecase)
    except Exception:
        return None
    if not lits:
        return None
    if ignorecase:
        if not all(_is_alpha_ascii(l) for l in lits):
            return None
    return sorted({l.lower() for l in lits} if ignorecase else set(lits))
