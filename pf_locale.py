"""Trusted language detection for the operator-facing approval card.

The card is the only part of the firewall that speaks to the operator, so it
is also the only part that has to answer in the operator's language. The
language is resolved from trusted sources only, in this order:

1. **The operator's configured locale** — ``HERMES_LANGUAGE`` or
   ``display.language`` in the Hermes config. Both are operator settings.
2. **The operator's own recent messages** — the newest ``user`` turns of
   this session, read through Hermes' own session API. Rows that Hermes
   writes itself (a context compaction summary) are not the operator's
   voice and are ignored.
3. **English** — the fallback when nothing trusted says otherwise.

What is deliberately *not* a language source: tool output, the command under
approval, file contents, web pages, README/AGENTS.md, third-party documents,
or any instruction embedded in untrusted content. A prompt-injection attempt
inside a file therefore cannot change the language of the card.

No operator text is written to a log or a file: the detection only counts
characters, in memory, and the counted text is discarded immediately.

The result is presentation-only. It never influences the firewall verdict,
the rule key, the enforcement decision, or the scope of a grant.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from .strings import DEFAULT_LANGUAGE

__all__ = ["detect_language", "normalize_language", "script_of"]

#: How many recent operator messages are inspected.
MESSAGE_WINDOW = 5

#: Rows fetched per backward page while looking for the operator's messages.
#: The message table stores tool and assistant rows too, so a small window can
#: contain no operator turn at all; the scan therefore pages backwards.
PAGE_ROWS = 100

#: How many backward pages may be scanned before giving up.
MAX_PAGES = 3

#: Minimum share of letters that the dominant script must hold.
SCRIPT_SHARE = 0.30

#: Minimum number of letters before a message can vote.
MIN_LETTERS = 4

#: Markers of rows that Hermes writes into the session itself. They are stored
#: with the operator's role but they are not the operator's voice: a context
#: compaction summary is written in English by the runtime and must not decide
#: the language of the card.
SYSTEM_ROW_MARKERS = ("[CONTEXT COMPACTION",)


def normalize_language(value: Any) -> str:
    """Map a locale id onto a supported card language.

    Only the three languages the card ships with are recognised. Anything
    else (including Hermes' wider language list) returns an empty string so
    that the caller moves on to the next trusted source.
    """
    text = str(value or "").strip().lower().replace("_", "-")
    if not text:
        return ""
    if text.startswith("zh"):
        # Simplified only: the card ships one Chinese catalog.
        if text in ("zh", "zh-cn", "zh-hans", "zh-hans-cn", "zh-sg", "zh-hans-sg"):
            return "zh-Hans"
        return ""
    if text.startswith("ru") or text in ("русский", "russian"):
        return "ru"
    if text.startswith("en"):
        return "en"
    return ""


def _configured_language() -> str:
    """The operator's explicitly configured locale, if there is one.

    ``HERMES_LANGUAGE`` and an explicitly written ``display.language`` in the
    Hermes config are operator settings. The *default* language is deliberately
    not consulted: the merged configuration always carries a default that
    Hermes injects, so reading it would silently pin every card to English.
    The raw config file is read instead - it contains only what the operator
    actually wrote.
    """
    env = os.environ.get("HERMES_LANGUAGE") or ""
    language = normalize_language(env)
    if language:
        return language
    try:
        from hermes_cli.config import read_raw_config_readonly

        configured = (read_raw_config_readonly().get("display") or {}).get("language")
    except Exception:
        return ""
    return normalize_language(configured)


def script_of(text: str) -> str:
    """The dominant script of *text*: ``ru``, ``zh`` or ``en`` (or empty)."""
    cyrillic = han = latin = 0
    for char in text:
        code = ord(char)
        if 0x0400 <= code <= 0x04FF:
            cyrillic += 1
        elif 0x4E00 <= code <= 0x9FFF or 0x3400 <= code <= 0x4DBF:
            han += 1
        elif (0x41 <= code <= 0x5A) or (0x61 <= code <= 0x7A):
            latin += 1
    total = cyrillic + han + latin
    if total < MIN_LETTERS:
        return ""
    if cyrillic / total >= SCRIPT_SHARE and cyrillic >= max(han, latin):
        return "ru"
    if han / total >= SCRIPT_SHARE and han >= max(cyrillic, latin):
        return "zh"
    if latin / total >= SCRIPT_SHARE:
        return "en"
    return ""


def _message_text(content: Any) -> str:
    """The plain text of a stored message."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)
    return ""


def _operator_messages(session_key: str) -> List[str]:
    """The last few operator messages of this session, oldest first.

    The session stores tool and assistant rows next to the operator's turns, so
    the scan pages backwards over the newest rows until enough operator
    messages are found. The page count is bounded, and the scan stops as soon
    as the window is full.

    The store pages back from the newest row but returns every page in
    chronological order, so the pages arrive newest-first. They are flipped back
    into one global chronological sequence before the window is taken: without
    that flip the newest operator turn - the one the card has to follow - is
    the first message the window drops.

    The store is opened read-only and released deterministically. A card must
    not take a write lock on the session store, and it must not leave a
    connection behind.
    """
    if not session_key:
        return []
    try:
        from hermes_state import SessionDB

        db = SessionDB(read_only=True)
    except Exception:
        return []
    pages: List[List[str]] = []
    try:
        offset = 0
        for _ in range(MAX_PAGES):
            try:
                rows = db.get_messages(session_key, latest=True, limit=PAGE_ROWS,
                                       offset=offset)
            except Exception:
                break
            if not rows:
                break
            page: List[str] = []
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                if str(row.get("role") or "") != "user":
                    continue
                text = _message_text(row.get("content"))
                if not text.strip():
                    continue
                if text.lstrip().startswith(SYSTEM_ROW_MARKERS):
                    continue
                page.append(text)
            pages.append(page)
            if sum(len(p) for p in pages) >= MESSAGE_WINDOW or len(rows) < PAGE_ROWS:
                break
            offset += PAGE_ROWS
    finally:
        try:
            db.close()
        except Exception:
            pass
    texts = [text for page in reversed(pages) for text in page]
    return texts[-MESSAGE_WINDOW:]


def _from_messages(session_key: str) -> str:
    """The language of the operator's own recent messages.

    The newest operator turn that carries a detectable script wins: the card
    follows the language the operator is currently using. Older turns are only
    consulted when the newest ones carry no script at all.
    """
    texts = _operator_messages(session_key)
    for text in reversed(texts):
        script = script_of(text)
        if script:
            return {"ru": "ru", "zh": "zh-Hans", "en": "en"}[script]
    return ""


def detect_language(session_key: str = "") -> str:
    """The language the approval card should be rendered in.

    Trusted sources only; see the module docstring. Never raises: a failure
    to resolve a language must not break the approval card, so it degrades to
    English.
    """
    try:
        configured = _configured_language()
        if configured:
            return configured
        from_messages = _from_messages(session_key)
        if from_messages:
            return from_messages
    except Exception:
        pass
    return DEFAULT_LANGUAGE


def resolve(session_key: str = "") -> Optional[str]:
    """Alias kept for call-site clarity."""
    return detect_language(session_key)
