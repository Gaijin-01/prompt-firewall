"""Deterministic prompt-injection detectors for the ``prompt-firewall`` plugin.

Pure functions, no I/O, no network, no LLM. Every detector returns a list of
:class:`Finding` objects describing *what* matched and *where*.

Design rules (deliberate, to keep false positives survivable):

* We match **structural** injection shapes, not single magic words. A README
  that quotes an override phrase inside a security write-up is legitimate
  content; the same phrase aimed at the agent is not. We therefore require
  either an explicit agent-directed frame (an imperative addressed to the
  reader) or a role/identity spoof.
* We never match on the bare presence of a URL, a base64 blob, or a keyword
  like "prompt" — those are too common in legitimate dev work.
* Encoded payloads are detected by *decoding* and re-scanning, which is what
  makes obfuscated injection detectable at all.

One family of rules is frame-gated. A phrase that switches a *generic*
safety control off is reported only when it reads as an instruction to the
agent. When the phrase is the object of a reporting verb ("attempts to
disable ...", "how to disable ..."), the text is *describing* a control or
an attack — documentation, not an instruction — and is not reported.

Rules that name the firewall itself (switching it off, disabling it,
deleting it) are never gated: they are unambiguous in any context.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #

#: Categories used by the plugin's block/quarantine policy.
CATEGORY_INSTRUCTION_OVERRIDE = "instruction_override"
CATEGORY_ROLE_SPOOF = "role_spoof"
CATEGORY_PERSISTENT_PROMPT = "persistent_prompt_modification"
CATEGORY_GATEWAY_REDIRECT = "malicious_gateway_redirect"
CATEGORY_ENCODED_PAYLOAD = "encoded_payload"
CATEGORY_SECURITY_DISABLE = "security_control_disable"

ALL_CATEGORIES = (
    CATEGORY_INSTRUCTION_OVERRIDE,
    CATEGORY_ROLE_SPOOF,
    CATEGORY_PERSISTENT_PROMPT,
    CATEGORY_GATEWAY_REDIRECT,
    CATEGORY_ENCODED_PAYLOAD,
    CATEGORY_SECURITY_DISABLE,
)


@dataclass(frozen=True)
class Finding:
    """One deterministic detection.

    ``pattern`` is a short stable id (safe to log). ``excerpt`` is a short
    redacted snippet of the matched text — bounded and scrubbed so it can be
    logged without leaking credentials or bulk secret material.
    """

    category: str
    pattern: str
    excerpt: str
    offset: int = -1
    end: int = -1
    severity: str = "high"  # "high" | "medium"

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "pattern": self.pattern,
            "excerpt": self.excerpt,
            "offset": self.offset,
            "end": self.end,
            "severity": self.severity,
        }


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #

# Characters that are used to hide instructions (zero-width, bidi, invisible
# separators). Core's threat scanner covers some of these; we detect them again
# because our quarantine path needs to know the payload was obfuscated.
_INVISIBLE_RE = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\u2065"
    "\u180e\u180f\u00ad\u034f\u202a\u202b\u202c\u202d\u202e\u2028\u2029"
    "\u2066\u2067\u2068\u2069\u206a\u206b\u206c\u206d\u206e\u206f"
    "\ufeff\ufff9\ufffa\ufffb]"
)

# Long base64 / hex / percent-encoded runs that could carry an encoded payload.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{80,}")
_PCT_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){20,}")

_MAX_SCAN_CHARS = 400_000

#: Maximum number of encoding layers that are decoded and re-scanned.
_MAX_ENCODED_DEPTH = 3

#: Maximum number of bytes a single decoded blob may contribute.
_MAX_DECODED_BYTES = 256_000

#: "Please disclose the private notes" style imperative. The politeness word is
#: assembled from fragments so that this source file does not itself contain a
#: literal directive token (which would make the scanner flag its own source).
_POLITE = "pl" + "ease"

#: Qualifier words that may precede the disclosed noun. A payload may chain
#: them ("private project notes"), so the group repeats instead of matching
#: exactly one word.
_QUALIFIER = r"(?:private|secret|confidential|internal|proprietary|project)"

#: Imperative that asks the agent to hand private material to someone.
_IMPERATIVE_DISCLOSURE_RE = (
    r"(?:"
    + _POLITE
    + r"\s+)?(?:send|post|upload|forward|disclose|reveal|share|export|"
    r"email|publish|leak|show)\s+(?:me\s+)?(?:the\s+|your\s+|all\s+|any\s+)?"
    + _QUALIFIER
    + r"(?:\s+"
    + _QUALIFIER
    + r"){0,2}\s+"
    r"(?:notes?|data|information|details?|files?|documents?|keys?|credentials?|"
    r"secrets?|contents?)\b"
)


def _excerpt(text: str, start: int, end: int, limit: int = 120) -> str:
    """Bounded, single-line, scrubbed snippet of a match (safe to log)."""
    snippet = text[start:end]
    snippet = _INVISIBLE_RE.sub("", snippet)
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > limit:
        snippet = snippet[: limit - 1] + "…"
    # Never echo what looks like a credential back into a log line.
    snippet = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{8,}", r"\1[REDACTED]", snippet)
    snippet = re.sub(
        r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)\S+", r"\1[REDACTED]", snippet
    )
    return snippet


def _strip_invisible_map(text: str) -> Tuple[str, List[int]]:
    """Drop invisible/zero-width characters, keeping an index map back.

    Detection runs on this cleaned copy so that ``ign\u200bore all previous
    instructions`` is found; the index map lets the finding be reported at the
    offset of the *original* text, so quarantine still addresses real bytes.
    """
    kept: List[str] = []
    index_map: List[int] = []
    for pos, ch in enumerate(text):
        if _INVISIBLE_RE.match(ch):
            continue
        kept.append(ch)
        index_map.append(pos)
    return "".join(kept), index_map


def _norm(text: str) -> str:
    """Normalize line endings *without changing the length* of the string.

    Length preservation matters: finding offsets are computed on the
    normalized text and later applied to the text that is patched, so the
    two coordinate spaces must stay identical.
    """
    return text.replace("\r", " ")


# --------------------------------------------------------------------------- #
# Rule table
# --------------------------------------------------------------------------- #
#
# Each rule is (pattern_id, category, compiled_regex, severity).
#
# The regexes are intentionally *phrased* rather than keyword based: they match
# a full instruction shape, so prose that merely discusses prompt injection
# (documentation, CTF write-ups, security research) does not trip them.

_RULES: Sequence[Tuple[str, str, re.Pattern, str]] = (
    # --- instruction override ------------------------------------------------
    (
        "ignore_previous_instructions",
        CATEGORY_INSTRUCTION_OVERRIDE,
        re.compile(
            r"(?:ignore|disregard|forget|discard|override)\s+"
            r"(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+|previous\s+|prior\s+|above\s+|"
            r"preceding\s+|earlier\s+|foregoing\s+|original\s+|initial\s+|system\s+)*"
            r"(?:instruction|instructions|prompt|prompts|direction|directions|rule|rules|"
            r"guideline|guidelines|command|commands|context|message|messages|"
            r"system\s+prompt|system\s+message)\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "new_instructions_override",
        CATEGORY_INSTRUCTION_OVERRIDE,
        re.compile(
            r"(?:your\s+new\s+(?:instructions?|prompt|system\s+prompt|task|rules?)\s+(?:is|are)\b"
            r"|new\s+(?:system\s+)?instructions?\s*[:=]\s*\S"
            r"|updated\s+(?:system\s+)?instructions?\s*[:=]\s*\S"
            r"|\bfrom\s+now\s+on[, ]+you\s+(?:will|must|are|shall)\b"
            r"|starting\s+now[, ]+(?:ignore|disregard|discard)\b)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "reveal_system_prompt",
        CATEGORY_INSTRUCTION_OVERRIDE,
        re.compile(
            r"(?:reveal|print|output|show|repeat|disclose|dump)\s+"
            r"(?:me\s+)?(?:your|the)\s+"
            r"(?:full\s+|entire\s+|complete\s+|original\s+|initial\s+|hidden\s+|secret\s+)?"
            r"(?:system\s+prompt|system\s+message|instructions?|prompt\s+above|verbatim)\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "imperative_private_disclosure",
        CATEGORY_INSTRUCTION_OVERRIDE,
        re.compile(_IMPERATIVE_DISCLOSURE_RE, re.IGNORECASE),
        "high",
    ),
    # --- role spoofing --------------------------------------------------------
    (
        "role_spoof_system_turn",
        CATEGORY_ROLE_SPOOF,
        re.compile(
            # Line-anchored with [ \t]* only. An unbounded \s* after a newline
            # anchor can cross line boundaries, which made this rule quadratic:
            # every line start re-scanned the whole whitespace run. With
            # re.MULTILINE, ^ already matches after every newline, so the
            # line start is found without a backtracking prefix.
            #
            # A role marker is only a *turn* when the text after the colon
            # reads like an instruction.  A bare value (``system: enabled``,
            # ``developer: false``, ``developer: true``) is YAML, and a short
            # conversational line (``assistant: hi there``) is a transcript -
            # neither is a role directive.  Requiring an imperative verb or
            # an explicit role assignment keeps those from being rewritten,
            # while a real ``system: <instruction>`` is still caught.
            #
            # A YAML block scalar (``prompt: |``) is data, not a turn: the
            # indented ``system:`` line inside it is a quoted prompt body.
            # An indented line is therefore not a role marker.
            r"^(?![ \t])(?:#{1,4}[ \t]*)?(?:\*\*)?(?:system|developer)(?:\*\*)?[ \t]*[:：][ \t]*"
            r"(?:you\s+(?:are|must|should|will|have\s+to)\s+"
            r"(?:(?:now|not|no\s+longer)\s+)?(?:an?\s+|the\s+)?"
            r"(?:(?:ignore|obey|reveal|print|output|repeat|show|follow|disregard|forget|act|pretend|do|be)\b"
            r"|(?:ai|assistant|bot|model|system|agent)\s+(?:that|which|who)\s+"
            r"(?:ignores?|disobeys?|reveals?|prints?|outputs?|repeats?|shows?|follows?|disregards?|forgets?|acts?|pretends?|does|is|will|must|should)\b)"
            r"|ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\b"
            r"|from\s+now\s+on\b"
            r"|act\s+as\b"
            r"|pretend\s+(?:to\s+be|you\s+are)\b"
            r"|do\s+not\s+(?:follow|obey|mention|reveal)\b"
            r"|do\s+the\b"
            r"|do\s+(?:task|this|that|it|so)\b"
            r"|disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\b"
            r"|new\s+(?:instructions?|rules?|task)\b"
            r"|forget\s+(?:everything|all|your)\b"
            r"|reveal\s+(?:your|the)\b"
            r"|print\s+(?:your|the)\b"
            r"|output\s+(?:your|the)\b"
            r"|repeat\s+(?:your|the)\b"
            r"|show\s+(?:me\s+)?(?:your|the)\b"
            r"|your\s+(?:new\s+)?(?:instructions?|rules?|prompt|role|task)\b"
            r"|the\s+(?:user|human)\s+(?:says?|wants?|asks?)\b)"
            r"|<\|(?:im_start|im_end|system|endoftext|assistant|user)\|>"
            r"|\[/?INST\]|<<[ \t]*/?SYS[ \t]*>>"
            # A transcript line is only a role spoof when the speaker claims a
            # different role or issues an instruction.  ``assistant: hi there``
            # and ``human: thanks`` are ordinary dialogue, not a turn marker.
            r"|^[ \t]*(?:#{1,4}[ \t]*)?(?:human|assistant)[ \t]*:[ \t]*"
            r"(?:you\s+(?:are|must|should|will|have\s+to)\b"
            r"|ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\b"
            r"|from\s+now\s+on\b"
            r"|act\s+as\b"
            r"|pretend\s+(?:to\s+be|you\s+are)\b"
            r"|disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\b"
            r"|forget\s+(?:everything|all|your)\b"
            r"|reveal\s+(?:your|the)\b"
            r"|print\s+(?:your|the)\b"
            r"|output\s+(?:your|the)\b"
            r"|repeat\s+(?:your|the)\b"
            r"|show\s+(?:me\s+)?(?:your|the)\b"
            r"|your\s+(?:new\s+)?(?:instructions?|rules?|prompt|role|task)\b"
            r"|the\s+(?:user|human)\s+(?:says?|wants?|asks?)\b)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "high",
    ),
    (
        "role_spoof_persona_override",
        CATEGORY_ROLE_SPOOF,
        re.compile(
            r"(?:you\s+are\s+now\s+(?:a|an|the|no\s+longer)\b"
            r"|act\s+as\s+(?:if\s+you\s+are\s+)?(?:a|an|the)?\s*\w+\s+(?:without|with\s+no)\b"
            r"|pretend\s+(?:to\s+be|you\s+are)\b"
            r"|(?:you\s+are|act\s+as|switch\s+to|enter|activate|enable)\s+"
            r"(?:now\s+)?(?:in\s+|to\s+)?(?:dan|jailbreak|god)\s+mode\b"
            r"|you\s+(?:can|must|will|should)\s+do\s+anything\s+now\b)",
            re.IGNORECASE,
        ),
        "high",
    ),
    # --- persistent prompt modification ---------------------------------------
    (
        "persist_in_instruction_files",
        CATEGORY_PERSISTENT_PROMPT,
        re.compile(
            r"(?:append|add|inject|write|insert|embed|place|put)\s+"
            r"(?:this|the\s+following|these\s+lines?|it)\b[^.\n]{0,80}?"
            r"\b(?:AGENTS\.md|CLAUDE\.md|SOUL\.md|GEMINI\.md|\.cursorrules|\.clinerules|"
            r"\.github\s+copilot-instructions\.md|CLAUDE\.local\.md|"
            r"(?:global|persistent|system)\s+(?:instruction|config|configuration)s?|"
            r"system\s+prompt|memory\s+file|MEMORY\.md)\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "persist_always_reply",
        CATEGORY_PERSISTENT_PROMPT,
        re.compile(
            r"(?<![\"“”'])\b(?:reply|respond|answer|output)\s+"
            r"(?:with\s+)?(?:exactly|verbatim|precisely)\s+"
            r"(?:this\s+line|the\s+following|this\s+exact|only)\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "activation_word_injection",
        CATEGORY_PERSISTENT_PROMPT,
        re.compile(
            r"(?:for\s+)?(?:exact\s+)?(?:greetings?|activation\s+words?|trigger\s+words?|"
            r"keywords?)\b[^.]{0,160}?"
            r"(?:reply|respond|answer|output)\s+with\s+exactly\s+"
            r"(?:this\s+line|the\s+following|this\s+exact)\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    # --- malicious gateway / endpoint redirect --------------------------------
    (
        "gateway_redirect_instruction",
        CATEGORY_GATEWAY_REDIRECT,
        re.compile(
            r"(?:set|point|switch|redirect|route|change|modify|update|configure)\s+"
            r"(?:your\s+|the\s+|your\s+model'?s?\s+|your\s+llm'?s?\s+)?"
            r"(?:api[_\- ]?base|base[_\- ]?url|api[_\- ]?url|endpoint|provider|model\s+provider|"
            r"llm\s+gateway|api\s+gateway|proxy)\b"
            r"[^.\n]{0,120}?(?:https?://|wss?://|\b[\w.-]+\.(?:top|xyz|cc|vip|icu|click|shop|site|"
            r"live|online|space|work|life|fun|icu|buzz)\b)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "redirect_model_traffic",
        CATEGORY_GATEWAY_REDIRECT,
        re.compile(
            r"(?:redirect|route|direct|send|forward|point|steer)\s+"
            r"(?:all\s+|any\s+|the\s+|your\s+|every\s+|incoming\s+|outgoing\s+)*"
            r"(?:model|llm|ai|agent|assistant|prompt|traffic|request|call)s?\b"
            r"[^.\n]{0,80}?"
            r"(?:https?://|wss?://|\b[\w.-]+\.(?:top|xyz|cc|vip|icu|click|shop|site|"
            r"live|online|space|work|life|fun|buzz)\b)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "api_relay_advertisement",
        CATEGORY_GATEWAY_REDIRECT,
        re.compile(
            r"(?:api\s+relay|llm\s+relay|relay\s*(?:/|\s)?\s*gateway|api\s+relay/gateway|"
            r"中转站|代理网关)"
            r"[^.\n]{0,120}?(?:https?://|wss?://)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "protected_infrastructure_directive",
        CATEGORY_GATEWAY_REDIRECT,
        re.compile(
            r"(?:protected\s+infrastructure|do\s+not\s+(?:test|attack|scan|probe))\b"
            r"[^.\n]{0,160}?(?:even\s+if|regardless\s+of)\b",
            re.IGNORECASE,
        ),
        "medium",
    ),
    # --- attempts to disable security controls --------------------------------
    (
        "disable_security_controls",
        CATEGORY_SECURITY_DISABLE,
        re.compile(
            r"(?:"
            # (a) a verb that switches a security control off
            r"(?:disable|turn\s+off|switch\s+off|bypass|circumvent|defeat|remove|skip|"
            r"suppress|deactivate|neutralize)\s+"
            r"(?:the\s+|your\s+|all\s+|any\s+)?"
            r"(?:safety|security|guard(?:rail)?s?|filter|moderation|safety\s+filters?|"
            r"firewall(?:\s+plugin)?|sandbox(?:es)?|"
            r"prompt\s+injection\s+(?:detection|protection)|injection\s+detection|"
            r"threat\s+scanning|content\s+polic(?:y|ies)|approval\s+(?:requirement|gate)|"
            r"require(?:ment)?s?\s+for\s+approval|human\s+approval|"
            r"plugins?(?:\s+\w+){0,3}\s+(?:disabled|enabled))"
            r")\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        # (b) an instruction that switches the firewall itself off,
        # (c) an imperative that disables a security plugin, and
        # (d) destructive removal of the firewall plugin directory.
        # These are self-targeting and unambiguous: no legitimate workflow
        # contains them, so they are never frame-gated.
        "disable_firewall_plugin",
        CATEGORY_SECURITY_DISABLE,
        re.compile(
            r"(?:"
            # (b) switch the firewall itself off
            r"(?:disable|turn\s+off|switch\s+off|bypass|circumvent|defeat|remove|skip|"
            r"suppress|deactivate|neutralize|uninstall|delete)\s+"
            r"(?:the\s+|your\s+|all\s+|any\s+)?"
            r"(?:prompt[-\s]?firewall|firewall\s+plugin|security\s+plugin|injection\s+(?:plugin|guard))"
            # (c) disable a security plugin by name
            r"|plugins?\s+(?:disable|remove|uninstall|delete)\s+[\w.-]*"
            r"(?:firewall|security|injection|threat|approv)"
            # (d) destroy the plugin directory
            r"|(?:rm|rmdir|shred|unlink|mv)\s+(?:-[^\s]+\s+)*[^\s]*"
            r"(?:plugins?/[\w.-]*firewall|prompt-firewall)"
            r")\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "bypass_approval",
        CATEGORY_SECURITY_DISABLE,
        re.compile(
            r"(?:without|skip(?:ping)?|bypass(?:ing)?|no\s+need\s+for)\s+"
            r"(?:asking|requesting|confirmation|approval|permission|authorisation|authorization)\b"
            # Standalone tokens only: a flag glued to other syntax (as in a
            # regex source or a path) is not an invocation.
            r"|(?<!\S)(?:--dangerously-skip-permissions|--yolo)\b",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "exfiltrate_secrets",
        CATEGORY_SECURITY_DISABLE,
        re.compile(
            r"(?:send|post|upload|exfiltrate|transmit|leak|forward|email)\s+"
            r"(?:the\s+|your\s+|all\s+)?"
            r"(?:api[_\- ]?keys?|secrets?|tokens?|credentials?|passwords?|"
            r"\.env\s+file|environment\s+variables?)\b[^;\n]{0,120}?"
            r"(?:https?://|\b[\w.-]+\.(?:com|net|org|io|top|xyz|cc|ru|cn)\b)",
            re.IGNORECASE,
        ),
        "high",
    ),
)


#: Rules whose matches are reported only when they read as an instruction
#: rather than as a description of one.
_FRAME_GATED_RULES = frozenset(
    {"disable_security_controls", "imperative_private_disclosure"}
)

#: A sentence break: terminal punctuation followed by whitespace. A newline is
#: *not* a break - a wrapped paragraph is one sentence.
_SENTENCE_BREAK_RE = re.compile(r"[.!?][ \t]+")

#: A *generic* subject: the phrase is described in the abstract ("attackers
#: attempt to disable ...", "attackers can bypass ..."), not addressed to the
#: reader. Without such a subject the phrase is an imperative and is reported.
_GENERIC_SUBJECT_RE = re.compile(
    r"\b(?:"
    r"attackers?|adversar(?:y|ies)|threat\s+actors?|malicious\s+(?:actors?|agents?|"
    r"content|users?|payloads?)|attack\s+campaigns?|"
    r"people|users?|researchers?|analysts?|criminals?|hackers?|scammers?|"
    r"someone|somebody|one|they|agents?|models?|systems?|tools?|scripts?|"
    r"prompt[-\s]?adware|(?:prompt|indirect)\s+injections?|"
    r"(?:the\s+)?(?:attack|adversar\w+|threat|technique|tactic|exploit)s?"
    r")\b",
    re.IGNORECASE,
)

#: A reporting verb that needs a generic subject in front of it
#: ("attackers attempt to ...").
_REPORTING_FRAME_RE = re.compile(
    r"(?:attempts?|tr(?:y|ies|ied|ying)|can|could|may|might|able|allowed|supposed|"
    r"intended|mean(?:s|ing)?|meant)\s+to\b",
    re.IGNORECASE,
)

#: A *nominal* reporting frame: the phrase names a method, not an act
#: ("how to disable ...", "ways to bypass ..."). No subject needed.
_NOMINAL_FRAME_RE = re.compile(
    r"\b(?:how|ways?|way|means?|method|methods|steps?|examples?|recipes?)\s+to\s+$",
    re.IGNORECASE,
)

#: The same nominal frame, but reported earlier in the sentence so that a
#: coordinated list item (a trailing clause joined by "or") inherits it.
_NOMINAL_FRAME_ANY_RE = re.compile(
    r"\b(?:how|ways?|way|means?|method|methods|steps?|examples?|recipes?)\s+to\b",
    re.IGNORECASE,
)

#: A coordinated list item introduced by "or".
_COORDINATION_TAIL_RE = re.compile(r"(?:^|[,;:]\s*|\s)(?:or|and)\s+$", re.IGNORECASE)

#: A hedged modal directly in front of the phrase ("attackers *can* disable ...").
_MODAL_BEFORE_RE = re.compile(r"(?:can|could|may|might)\s+$", re.IGNORECASE)

#: Passive constructions: the phrase names a blocked action instead of
#: ordering one ("... are blocked", "... is prevented").
_PASSIVE_FRAME_RE = re.compile(
    r"(?:are|is|were|will\s+be|would\s+be|get|gets)\s+"
    r"(?:blocked|prevented|rejected|refused|detected|flagged|reported|disabled)",
    re.IGNORECASE,
)

#: Inspection tools: the phrase is a needle a developer is looking for.
_SEARCH_FRAME_RE = re.compile(
    r"(?:\bgrep\b|\brg\b|\bgit\s+grep\b|\bag\b|\back\b|\bfind\b|\blocate\b|"
    r"\bstrings\b|\bsed\b|\bawk\b|\bless\b|\bhead\b|\btail\b|\bcat\b|\bdiff\b)",
    re.IGNORECASE,
)

#: A second-person directive: an order to the agent, never documentation.
_DIRECTIVE_FRAME_RE = re.compile(
    r"(?:\byou\s+(?:must|should|need\s+to|have\s+to|can|may|could|might|will)\b"
    r"|\bplease\b|\bgo\s+ahead\b|\bmake\s+sure\b|\bdo\s+not\s+refuse\b)",
    re.IGNORECASE,
)


def _sentence_bounds(haystack: str, start: int, end: int) -> Tuple[int, int]:
    """Bounds of the sentence that contains the ``[start:end)`` span."""
    left = 0
    for match in _SENTENCE_BREAK_RE.finditer(haystack, 0, start):
        left = match.end()
    right = len(haystack)
    match = _SENTENCE_BREAK_RE.search(haystack, end)
    if match:
        right = match.start()
    return left, right


def _inside_quotes(haystack: str, start: int, end: int) -> bool:
    """True when the match sits inside a quoted literal on its own line."""
    line_start = haystack.rfind("\n", 0, start) + 1
    line_end = haystack.find("\n", end)
    if line_end == -1:
        line_end = len(haystack)
    prefix = re.sub(r"\\.", "", haystack[line_start:start])
    return any(prefix.count(quote) % 2 == 1 for quote in ('"', "'", "`"))


def _describes_action_in_abstract(sentence: str, before: str) -> bool:
    """True when the phrase is described rather than ordered.

    Two shapes count as description:

    * a *nominal* frame - "how to disable X", "ways to bypass X". The phrase
      names a method; no subject is required.
    * a *reporting* frame with a generic subject - "attackers attempt to
      disable X", "attackers can bypass X". Without a generic subject the
      same words are an imperative ("attempt to disable X") and are reported.
    """
    if _NOMINAL_FRAME_RE.search(before):
        return True
    for match in _REPORTING_FRAME_RE.finditer(before):
        if _GENERIC_SUBJECT_RE.search(before[: match.start()]):
            return True
    return False


def _is_descriptive_frame(haystack: str, start: int, end: int) -> bool:
    """True when the match reads as a *description* of an action, not an order.

    A directive aimed at the agent always wins: when the sentence contains a
    second-person imperative, the match is an instruction even if the same
    sentence also discusses the action in the abstract.
    """
    left, right = _sentence_bounds(haystack, start, end)
    sentence = haystack[left:right]
    if _DIRECTIVE_FRAME_RE.search(sentence):
        return False
    rel_start = max(0, start - left)
    before = sentence[:rel_start]
    # "how to disable X" / "attackers attempt to disable X".
    if _describes_action_in_abstract(sentence, before):
        return True
    # "attackers can disable X" - hedged modal right in front of the phrase.
    modal = _MODAL_BEFORE_RE.search(before)
    if modal and _GENERIC_SUBJECT_RE.search(before[: modal.start()]):
        return True
    # "... the firewall is disabled" - passive, names a blocked action.
    if _PASSIVE_FRAME_RE.search(sentence[rel_start:]):
        return True
    # "any attempt to X, or a safety-control switch-off" - a coordinated list item
    # governed by an earlier nominal frame.
    if _COORDINATION_TAIL_RE.search(before) and _NOMINAL_FRAME_ANY_RE.search(before):
        return True
    # `grep -rn "disable the firewall"` - a needle a developer is looking for.
    line_start = haystack.rfind("\n", 0, start) + 1
    if _SEARCH_FRAME_RE.search(haystack[line_start:start]) and _inside_quotes(
        haystack, start, end
    ):
        return True
    return False


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


def _scan_rules(
    text: str,
    findings: List[Finding],
    seen: set,
    remap: Optional[List[int]] = None,
) -> None:
    """Run the rule table over *text*, appending findings to *findings*."""
    for pattern_id, category, regex, severity in _RULES:
        for match in regex.finditer(text):
            if pattern_id in _FRAME_GATED_RULES and _is_descriptive_frame(
                text, match.start(), match.end()
            ):
                continue
            if remap is None:
                start, end = match.start(), match.end()
            else:
                if match.end() <= match.start():
                    continue
                start = remap[match.start()]
                end = remap[match.end() - 1] + 1
            key = (category, pattern_id, start)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    category=category,
                    pattern=pattern_id,
                    excerpt=_excerpt(text, match.start(), match.end()),
                    offset=start,
                    end=end,
                    severity=severity,
                )
            )


def scan_text(
    text: str, *, max_chars: int = _MAX_SCAN_CHARS, _depth: int = 0
) -> List[Finding]:
    """Scan *text* for injection shapes. Returns findings, highest severity first."""
    if not text or not isinstance(text, str):
        return []
    if len(text) > max_chars:
        text = text[:max_chars]
    haystack = _norm(text)
    findings: List[Finding] = []
    seen: set = set()

    _scan_rules(haystack, findings, seen)

    # A second pass over a copy with invisible characters removed: zero-width
    # separators must not hide an instruction. Offsets are mapped back to the
    # original text so quarantine still replaces real bytes.
    analysis, index_map = _strip_invisible_map(haystack)
    if analysis != haystack and len(index_map) == len(analysis):
        _scan_rules(analysis, findings, seen, remap=index_map)

    if _depth < _MAX_ENCODED_DEPTH:
        findings.extend(_scan_encoded(haystack, seen, _depth))
    findings.sort(key=lambda f: (0 if f.severity == "high" else 1, f.offset))
    return findings


# --------------------------------------------------------------------------- #
# Encoded payload detection (decode, then re-scan)
# --------------------------------------------------------------------------- #


def _decode_candidates(text: str) -> Iterable[Tuple[str, str, int, int]]:
    """Yield ``(encoding, decoded_text, start, end)`` for encoded payloads."""
    for match in _B64_RE.finditer(text):
        blob = match.group(0)
        # Only bother with plausible base64 (length % 4 == 0 after padding).
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded and sum(ch.isprintable() or ch in "\n\t" for ch in decoded) / len(decoded) > 0.85:
            yield ("base64", decoded, match.start(), match.end())

    for match in _HEX_RE.finditer(text):
        blob = match.group(0)
        if blob.lower().startswith("0x"):
            blob = blob[2:]
        try:
            raw = bytes.fromhex(blob)
        except ValueError:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded:
            yield ("hex", decoded, match.start(), match.end())

    for match in _PCT_RE.finditer(text):
        try:
            decoded = urllib.parse.unquote(match.group(0))
        except Exception:
            continue
        if decoded:
            yield ("percent", decoded, match.start(), match.end())


def _scan_encoded(text: str, seen: set, depth: int = 0) -> List[Finding]:
    """Find payloads whose *encoded* form hides an injection."""
    findings: List[Finding] = []
    for encoding, decoded, blob_start, blob_end in _decode_candidates(text):
        if len(decoded) > _MAX_DECODED_BYTES:
            continue
        # Re-scan the decoded text for the strong categories only. An encoded
        # layer is itself a hit: double encoding must not be a bypass.
        inner = scan_text(decoded, _depth=depth + 1)
        strong = [
            f
            for f in inner
            if f.category
            in (
                CATEGORY_INSTRUCTION_OVERRIDE,
                CATEGORY_ROLE_SPOOF,
                CATEGORY_PERSISTENT_PROMPT,
                CATEGORY_GATEWAY_REDIRECT,
                CATEGORY_SECURITY_DISABLE,
                CATEGORY_ENCODED_PAYLOAD,
            )
        ]
        if not strong:
            continue
        best = strong[0]
        key = ("encoded_payload", f"encoded_{encoding}", blob_start)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                category=CATEGORY_ENCODED_PAYLOAD,
                pattern=f"encoded_{encoding}",
                excerpt=f"{encoding} payload decoding to {best.category} ({best.pattern})",
                offset=blob_start,
                end=blob_end,
                severity="high",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Path / target helpers used by the action-boundary policy
# --------------------------------------------------------------------------- #


def looks_like_url_token(token: str) -> bool:
    """True for a bare hostname that looks like a third-party API gateway."""
    return bool(
        re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.-]{1,60}\."
            r"(?:top|xyz|cc|vip|icu|click|shop|site|live|online|space|work|life|fun|buzz|"
            r"icu|store|tech|io|dev|app|ai|cloud|so|me|cn|ru|pro)",
            token.strip(),
        )
    )
