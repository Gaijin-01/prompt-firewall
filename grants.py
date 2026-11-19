"""Scoped Intent Grant — operator-authorized instruction-surface writes (P0 remediation).

A grant exempts ONLY the durable-instruction-surface write denial for ONE exact,
reviewed write. It never bypasses the rest of the policy: ``evaluate_tool_call``
always runs in full, and the grant is consulted solely at the instruction-surface
branch. Every other rule (injection scan, credential paths, control-plane,
endpoint, exec gating) applies unchanged.

P0 remediation summary
-----------------------
* P0-1  The grant is passed INTO ``evaluate_tool_call``; it lifts only the
        instruction-surface denial. The hook no longer returns early.
* P0-2  The authorization command is ANCHORED: the entire operator message must
        be exactly the command (optional surrounding whitespace). Quoted,
        negated, embedded or otherwise ambiguous text yields no grant.
* P0-3  Provenance is checked against trusted Core fields: a user-facing
        ``platform`` (allowlist), a present ``sender_id``, and no
        ``parent_session_id``. cron / subagent / a2a / api / synthetic / goal
        turns and missing identities yield no grant. Provenance is NEVER inferred
        from message text.
* P0-4  Authorization binds canonical path + operation + SHA-256 of the exact
        proposed content + turn scope + one-shot consumption. A write whose
        content hash differs from the authorized hash is refused.
* P0-5  Only single-target atomic file tools (``write_file``) may receive the
        exemption. Shell / terminal / dynamic / mixed-effect commands never do.

Trust model (verified against Hermes Core source): ``pre_llm_call`` fires once
per real operator turn with the operator's clean ``user_message`` plus trusted
``sender_id`` / ``platform`` / ``parent_session_id`` / ``turn_id``. Tool-loop
follow-ups do not re-run it, so indirect tool output cannot mint a grant
directly. ``pre_tool_call`` carries the same ``session_id`` / ``turn_id``.
``approve`` is never used as a signal.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .policy import normalize_path, is_durable_instruction_surface


# --------------------------------------------------------------------------- #
# Provenance (P0-3)
# --------------------------------------------------------------------------- #

#: Platforms that represent a real operator typing a message. Anything not in
#: this set is treated as non-operator and yields no grant (fail-closed). cron,
#: subagent, a2a, api_server, kanban, bot_room, acp, synthetic and goal turns are
#: deliberately absent. ``webhook`` is removed: it is an unverified ingress whose
#: sender_id is not authenticated by the gateway allowlist.
USER_PLATFORMS: frozenset = frozenset({
    "telegram", "cli", "whatsapp", "discord", "slack", "signal", "matrix",
    "web", "desktop",
})


def _authorized_operator_ids(platform: str) -> set:
    """The configured authorized operator ids for ``platform``.

    Reads the gateway's own allowlist env var (``<PLATFORM>_ALLOWED_USERS``),
    which is the same source the gateway uses to authenticate inbound messages.
    A comma/space-separated list. Returns an empty set when unconfigured, which
    makes the grant fail closed (no configured operator => no authorization).
    """
    import os
    var = platform.upper() + "_ALLOWED_USERS"
    raw = os.environ.get(var, "") or ""
    ids = {tok.strip() for tok in raw.replace(",", " ").split() if tok.strip()}
    return ids


def _is_trusted_operator_turn(payload: Dict[str, Any]) -> bool:
    """True only for a verified human-operator turn.

    Requires: a user-facing platform; a present sender_id that matches the
    configured authorized operator allowlist for that platform (the same
    allowlist the gateway authenticates against); and no parent session (which
    would mark a fork / subagent). A nonempty sender_id alone is NOT sufficient —
    it must be an authorized operator. Missing/unverifiable identity is refused.
    Provenance comes from trusted Core fields + configured authorization, never
    from message text.
    """
    platform = str(payload.get("platform") or "").strip().lower()
    if platform not in USER_PLATFORMS:
        return False
    sender_id = str(payload.get("sender_id") or "").strip()
    if not sender_id:
        return False
    authorized = _authorized_operator_ids(platform)
    if not authorized or sender_id not in authorized:
        return False  # sender is not a configured authorized operator
    parent = str(payload.get("parent_session_id") or "").strip()
    if parent:
        return False  # fork / subagent turn
    return True


# --------------------------------------------------------------------------- #
# Authorization command (P0-2, anchored)
# --------------------------------------------------------------------------- #
#
# The ENTIRE operator message must be exactly one authorization command. Any
# leading/trailing prose, quotation, negation, or additional clause makes the
# message ambiguous and yields no grant. This is intentionally strict: the
# operator is authorizing a specific reviewed write, so the command must be
# deliberate and unambiguous.
#
# Grammar (case-insensitive):
#   authorize write to <path> sha256 <64-hex>
#   authorize write to <path> with sha256 <64-hex>
#
# The SHA-256 of the exact proposed file content is REQUIRED (P0-4): the grant
# authorizes one specific reviewed write, not arbitrary future content.

_COMMAND_RE = re.compile(
    r"^\s*authorize\s+write\s+to\s+(?P<path>\S+)\s+(?:with\s+)?sha256\s+(?P<sha>[0-9a-fA-F]{64})\s*$",
    re.IGNORECASE,
)


@dataclass
class _Grant:
    """One exact reviewed write, bound to a turn."""

    path: str            # canonical target path
    content_sha: str     # sha256 hex of the exact proposed content
    used: bool = False
    created_at: float = 0.0   # monotonic timestamp for TTL eviction


# Keyed by (session_id, turn_id). At most one grant per turn: a second command
# in the same turn replaces nothing (first wins) to avoid ambiguity.
_GRANTS: Dict[Tuple[str, str], _Grant] = {}
_LOCK = threading.Lock()

#: Grants expire after this many seconds even if never consumed, bounding both
#: lifetime and memory use. A turn is short; 10 minutes is generous.
GRANT_TTL_SECONDS: float = 600.0
#: Hard cap on stored grants to bound memory under pathological accumulation.
MAX_GRANTS: int = 256


def _evict_expired_locked(now: float) -> None:
    """Drop expired / used grants and enforce the size cap. Caller holds _LOCK."""
    expired = [k for k, g in _GRANTS.items()
               if g.used or (now - g.created_at) > GRANT_TTL_SECONDS]
    for k in expired:
        _GRANTS.pop(k, None)
    while len(_GRANTS) > MAX_GRANTS:
        oldest = min(_GRANTS, key=lambda k: _GRANTS[k].created_at)
        _GRANTS.pop(oldest, None)


def content_sha256(content: Any) -> str:
    """SHA-256 hex of the exact bytes a write would persist.

    Accepts str (encoded UTF-8) or bytes. Anything else returns "" (no match).
    """
    if isinstance(content, str):
        data = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray)):
        data = bytes(content)
    else:
        return ""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Capture (pre_llm_call)
# --------------------------------------------------------------------------- #

def capture_operator_grant(payload: Dict[str, Any]) -> None:
    """Record a grant iff this is a trusted operator turn carrying an exact,
    anchored authorization command. Otherwise do nothing (fail-closed)."""
    if not _is_trusted_operator_turn(payload):
        return
    message = payload.get("user_message")
    if not isinstance(message, str):
        return  # multimodal / structured content is not parsed
    session_id = str(payload.get("session_id") or "")
    turn_id = str(payload.get("turn_id") or "")
    if not session_id or not turn_id:
        return
    match = _COMMAND_RE.match(message)
    if not match:
        return  # not an exact anchored command -> no grant
    raw_path = match.group("path").strip().strip('"').strip("'")
    canonical = normalize_path(raw_path)
    if not canonical or not is_durable_instruction_surface(canonical):
        return  # only durable instruction surfaces can be granted
    sha = match.group("sha").lower()
    key = (session_id, turn_id)
    import time
    now = time.monotonic()
    with _LOCK:
        _evict_expired_locked(now)
        if key not in _GRANTS:  # first command in the turn wins
            _GRANTS[key] = _Grant(path=canonical, content_sha=sha, created_at=now)
            _evict_expired_locked(now)  # enforce cap after insertion


# --------------------------------------------------------------------------- #
# Query (used by policy at the instruction-surface branch)
# --------------------------------------------------------------------------- #

def peek_grant(session_id: str, turn_id: str) -> Optional[_Grant]:
    """Return the turn's grant without consuming it (for scope checks)."""
    with _LOCK:
        return _GRANTS.get((session_id or "", turn_id or ""))


def _grant_valid_locked(grant: Optional[_Grant], now: float) -> bool:
    """True iff the grant exists, is unused, and has NOT expired. Caller holds
    _LOCK. P0-B: expiry is enforced at point of use, even when no new grant has
    been captured (eviction-on-capture alone is insufficient)."""
    if grant is None or grant.used:
        return False
    if (now - grant.created_at) > GRANT_TTL_SECONDS:
        return False
    return True


def grant_matches(session_id: str, turn_id: str, canonical_path: str, content: Any) -> bool:
    """True iff an unused, unexpired grant for the turn authorizes THIS exact write.

    Read-only: does not consume. Used by the instruction-surface branch to lift
    the denial, and by the final protected-write decision to allow + consume.
    """
    key = (session_id or "", turn_id or "")
    sha = content_sha256(content)
    if not sha:
        return False
    import time
    with _LOCK:
        grant = _GRANTS.get(key)
        if grant is None or not _grant_valid_locked(grant, time.monotonic()):
            return False
        return grant.path == canonical_path and grant.content_sha == sha


def consume_grant(session_id: str, turn_id: str, canonical_path: str, content: Any) -> bool:
    """Consume the grant iff it authorizes THIS exact write.

    Requires: an unused, unexpired grant for the turn, a matching canonical path,
    and a content SHA-256 equal to the authorized hash. One-shot: a successful
    consumption marks the grant used. Any mismatch is refused without consuming.
    """
    key = (session_id or "", turn_id or "")
    sha = content_sha256(content)
    if not sha:
        return False
    import time
    with _LOCK:
        grant = _GRANTS.get(key)
        if grant is None or not _grant_valid_locked(grant, time.monotonic()):
            return False
        if grant.path != canonical_path:
            return False
        if grant.content_sha != sha:
            return False
        grant.used = True
        return True


def drop_turn_grant(session_id: str, turn_id: str) -> None:
    """Discard a turn's grant (turn end / hygiene)."""
    with _LOCK:
        _GRANTS.pop((session_id or "", turn_id or ""), None)


def reset_all_grants() -> None:
    """Clear every grant. Used by tests and on plugin reload."""
    with _LOCK:
        _GRANTS.clear()
