"""Language-aware executable-view helpers for G6 enforcement.

Detection keeps raw findings. These helpers produce a *view* used only by
specific enforcement predicates (CLI endpoint and provider-env rules).
"""
from __future__ import annotations

import io
import re
import shlex
import tokenize
from typing import Dict, Tuple

from ._eval_context import eval_state


def _python_executable_view(source: str) -> str:
    lines = list(source.splitlines())
    drop = set()
    masks: dict[int, list] = {}
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError):
        return source
    significant = [t for t in toks if t.type not in (
        tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
        tokenize.ENDMARKER, tokenize.COMMENT,
    )]
    for i, t in enumerate(toks):
        if t.type == tokenize.COMMENT:
            # Preserve the executable prefix before an inline comment.
            for ln in range(t.start[0], t.end[0] + 1):
                if ln == t.start[0]:
                    masks.setdefault(ln, []).append((t.start[1], len(lines[ln - 1])))
                else:
                    drop.add(ln)
        if t.type == tokenize.STRING:
            prev = significant[max(0, significant.index(t) - 2): significant.index(t)]
            nxt_i = significant.index(t) + 1
            nxt = significant[nxt_i] if nxt_i < len(significant) else None
            is_print_literal = (
                len(prev) >= 2
                and prev[-2].type == tokenize.NAME and prev[-2].string == "print"
                and prev[-1].type == tokenize.OP and prev[-1].string == "("
                and nxt is not None and nxt.type == tokenize.OP and nxt.string == ")"
            )
            # Only a standalone triple-quoted literal is a docstring.  A
            # quoted value in a real assignment must stay executable.
            is_docstring = (
                t.string.startswith(("\"\"\"", "'''"))
                and (
                    not prev
                    or prev[-1].type in (
                        tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                        tokenize.NAME,
                    )
                    or prev[-1].string in (":", ";")
                )
            )
            if is_print_literal or is_docstring:
                for ln in range(t.start[0], t.end[0] + 1):
                    drop.add(ln)
    out = []
    for idx, line in enumerate(lines, 1):
        if idx in drop:
            out.append("")
            continue
        for start, end in sorted(masks.get(idx, []), reverse=True):
            line = line[:start] + " " * max(0, end - start) + line[end:]
        out.append(line)
    return "\n".join(out)


def _shell_executable_view(source: str) -> str:
    out = []
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append("")
            continue
        if re.match(r"(?i)^echo\s+", stripped):
            try:
                parts = shlex.split(stripped)
            except ValueError:
                out.append(line)
                continue
            if len(parts) >= 2 and not any(c in "".join(parts[1:]) for c in ("$(", "`", ";", "|", "&&")):
                out.append("")
                continue
        out.append(line)
    return "\n".join(out)


#: Bounded memo of executable-command views.
#:
#: ``executable_command_view`` is a *pure* function of ``(source,
#: tool_name)``: it reads no mutable module state, no clock and no
#: environment.  The B1 action path builds a view of the same command more
#: than once per tool call (the provider-environment-assignment check and
#: the CLI endpoint check each build one), and the same command recurs
#: across calls.  Memoizing the view therefore removes redundant work, not
#: work: every caller still receives the exact string the uncached
#: implementation would have produced.
#:
#: The cache is bounded so a long-lived process cannot grow it without
#: limit, and it is keyed on the exact ``(source, tool_name)`` pair, so
#: two different inputs never share an entry.
# The view cache is evaluation-local.  A process-global cache would retain
# arguments and could outlive the evaluation that produced it; see
# ``_eval_context``.  Outside an evaluation nothing is retained.


def executable_command_view(source: str, tool_name: str) -> str:
    """The executable projection of *source* for *tool_name*.

    Memoized only within one evaluation (see ``_eval_context``).  The returned
    string is immutable, so sharing it within that evaluation is safe.
    """
    if not source:
        return source
    memo = eval_state().setdefault("executable_view", {})
    key = (source, tool_name)
    cached = memo.get(key)
    if cached is not None:
        return cached
    if tool_name in ("execute_code", "python"):
        view = _python_executable_view(source)
    else:
        view = _shell_executable_view(source)
    memo[key] = view
    return view
