"""Evaluation-local cache context.

All caches added by the 1.1.9 action-path optimization MUST live here, never in
module globals.  A ContextVar gives each thread / asyncio task its own state and
gives nested evaluations their own fresh state, while the explicit bind/reset
token keeps an outer evaluation's cache intact when a nested evaluation ends.

Outside an explicit evaluation scope no cache is retained at all: every call
gets a fresh empty dict, so helper functions called directly behave exactly as
the uncached implementation did.
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Dict, Optional

_STATE: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "prompt_firewall_evaluation_state", default=None)


def eval_state() -> Dict[str, Any]:
    """The cache state of the current evaluation (fresh if none is bound)."""
    state = _STATE.get()
    if state is None:
        state = {}
    return state


def bind_eval_state() -> Token:
    """Bind a fresh cache state and return the token for :func:`reset_eval_state`."""
    return _STATE.set({})


def reset_eval_state(token: Token) -> None:
    """Restore the state that was active before :func:`bind_eval_state`."""
    _STATE.reset(token)
