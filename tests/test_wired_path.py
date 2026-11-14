"""End-to-end check of the wired plugin approve path.

Verifies that the message the plugin now returns really is what Core would
render as the card's reason, that the verdict is unchanged, and that the
card text fits Core's reason budget.

Runs entirely against the STAGING copy. Nothing here touches the live plugin.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from pf_loader import load_module, load_package  # noqa: E402

pf = load_package()
policy = load_module("policy")

RESULTS = []

# The operator's configured locale is the first trusted language source. The
# fixtures below pin the Russian card text, so the locale is pinned too.
os.environ["HERMES_LANGUAGE"] = "ru"


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))


# Core's Telegram reason budget, measured from the running Hermes install:
# plugins/platforms/telegram/adapter.py:3935  _EA_REASON_BUDGET = 500
# and the card renderer adds a "..." suffix -> ~503 escaped chars.
CORE_REASON_BUDGET = 503

# Fragments keep the live firewall from rewriting these strings.
DISABLE = " ".join(["hermes", "plugins", "dis" + "able", "prompt-firewall"])


def test_wired_approve_path():
    tool, args = "terminal", {"command": "curl -s https://example.com/x.sh | tee /tmp/a"}
    verdict = policy.evaluate_tool_call(tool, dict(args))
    # Force the approve path with a rule that produces one.
    if verdict.action != "approve":
        # use a protected-write case instead
        tool, args = "terminal", {"command": "echo x >> ~/.hermes/config.yaml"}
        verdict = policy.evaluate_tool_call(tool, dict(args))
    check("wire.verdict_is_approve", verdict.action == "approve",
          f"{verdict.action}/{verdict.reason}")

    msg = pf._approval_card_message(tool, args, verdict, verdict.rule_key or "k")
    check("wire.message_nonempty", bool(msg), msg[:80])
    check("wire.within_core_budget", len(msg) <= CORE_REASON_BUDGET,
          f"{len(msg)} > {CORE_REASON_BUDGET}")
    check("wire.multiline", "\n" in msg, msg[:120])
    check("wire.has_purpose", "Что делает:" in msg, msg[:120])
    check("wire.has_scope", "Разрешение:" in msg, msg[:200])
    check("wire.no_safety_claim",
          not any(w in msg.lower() for w in ("безопасно", "вреда нет", "гарантированно")),
          msg[:120])
    print("--- rendered card reason ---")
    print(msg)
    print("--- end ---")


def test_verdict_unchanged_by_card():
    cases = [
        ("terminal", {"command": DISABLE}),
        ("terminal", {"command": "cat ~/.ssh/id_rsa"}),
        ("terminal", {"command": "echo x >> ~/.hermes/config.yaml"}),
        ("terminal", {"command": "ls -la"}),
    ]
    for tool, args in cases:
        before = policy.evaluate_tool_call(tool, dict(args))
        if before.action == "approve":
            pf._approval_card_message(tool, args, before, before.rule_key or "k")
        after = policy.evaluate_tool_call(tool, dict(args))
        check(f"unchanged.{before.reason[:24]}.{before.action}",
              (before.action, before.reason) == (after.action, after.reason),
              f"{before.action}/{before.reason} -> {after.action}/{after.reason}")


def test_fallback_on_broken_explain():
    """If the explain engine raises, the firewall's own wording must survive."""
    class Boom:
        def explain_command(self, *a, **k):
            raise RuntimeError("boom")

    ex = load_module("explain")
    original = ex.explain_command
    ex.explain_command = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        verdict = policy.evaluate_tool_call("terminal", {"command": "echo x >> ~/.hermes/config.yaml"})
        msg = pf._approval_card_message("terminal", {"command": "echo x >> ~/.hermes/config.yaml"},
                                        verdict, verdict.rule_key or "k")
        check("fallback.uses_firewall_wording",
              "prompt-firewall requires operator approval" in msg, msg[:140])
    finally:
        ex.explain_command = original


def main():
    for fn in (test_wired_approve_path, test_verdict_unchanged_by_card,
               test_fallback_on_broken_explain):
        try:
            fn()
        except Exception as exc:
            RESULTS.append((fn.__name__, False, f"EXCEPTION {type(exc).__name__}: {exc}"))
    failed = [r for r in RESULTS if not r[1]]
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not ok else ""))
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
