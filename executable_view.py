"""Language-aware executable-view helpers for G6 enforcement.

Detection keeps raw findings. These helpers produce a *view* used only by
specific enforcement predicates (CLI endpoint and provider-env rules).
"""
from __future__ import annotations

import io
import re
import shlex
import tokenize


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


def executable_command_view(source: str, tool_name: str) -> str:
    if not source:
        return source
    if tool_name in ("execute_code", "python"):
        return _python_executable_view(source)
    return _shell_executable_view(source)
