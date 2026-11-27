"""Protected-path and action-boundary policy for the ``prompt-firewall`` plugin.

Everything here is deterministic: explicit path lists, normalized path
comparison, explicit allowlists. No LLM calls, no network.

Trust model
-----------
Hermes distinguishes two kinds of instruction source:

* **Trusted** — the operator's own chat messages, plus explicitly authorized
  configuration changes routed through Hermes' existing approval mechanism.
* **Untrusted** — everything that arrives *through* a tool: web pages,
  repository files, README/AGENTS.md, SKILL.md, downloaded documents, and
  raw tool output.

The firewall enforces one rule at the action boundary:

    Untrusted content may never be the *authority* for an action.

Concretely, this module answers two questions for every tool call:

1. Does this call **target a protected surface** (persistent config, system
   prompts, memory, plugin settings, model endpoints, credential paths)?
2. Does this call's **content or command text** carry an injection signature
   that would let untrusted content drive it?

A protected write that is *not* injection-driven is not blocked outright: the
requirement is that authorized configuration changes still pass through
Hermes' existing approval mechanisms. The plugin therefore blocks only when
the action is genuinely unauthorized, and defers to the approval gate for the
ordinary authorized case.

Fail-closed rule: when we cannot establish provenance (e.g. an unknown
executable path or an unrecognized write surface), protected writes and
executable actions are refused rather than allowed.
"""

from __future__ import annotations

# G1: decision-contract container. Required package-relative import:
# never fall back to an unrelated top-level module from sys.path.
from .action_context import (  # type: ignore[import-not-found]
    ActionContext, ActionAuthorization, SourceProvenance,
)
from ._eval_context import bind_eval_state, eval_state, reset_eval_state
from .executable_view import executable_command_view

import hashlib
import ipaddress
import json
import ast
import os
import posixpath
import re
import shlex
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .detectors import (
    CATEGORY_ENCODED_PAYLOAD,
    CATEGORY_GATEWAY_REDIRECT,
    CATEGORY_INSTRUCTION_OVERRIDE,
    CATEGORY_PERSISTENT_PROMPT,
    CATEGORY_ROLE_SPOOF,
    CATEGORY_SECURITY_DISABLE,
    Finding,
    _MAX_SCAN_CHARS as _SCOPED_SCAN_BUDGET,
    scan_text,
)

# --------------------------------------------------------------------------- #
# Home-relative protected surfaces
# --------------------------------------------------------------------------- #

#: Files (relative to $HOME) that hold persistent agent state.
PROTECTED_HOME_FILES: Tuple[str, ...] = (
    ".hermes/config.yaml",
    ".hermes/SOUL.md",
    ".hermes/AGENTS.md",
    ".hermes/MEMORY.md",
    ".hermes/USER.md",
    ".hermes/.env",
    ".codex/config.toml",
    ".codex/AGENTS.md",
    ".claude/CLAUDE.md",
    ".gemini/GEMINI.md",
    ".config/gcloud/application_default_credentials.json",
    # Shell startup and MCP surfaces: a tool-driven write here is persistence.
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".profile",
    ".mcp.json",
)

#: Directories (relative to $HOME) whose contents are persistent agent state.
PROTECTED_HOME_DIRS: Tuple[str, ...] = (
    ".hermes/plugins",
    ".hermes/skills",
    ".hermes/memories",
    ".hermes/cron",
    ".hermes/profiles",
    ".hermes/config",
    ".codex",
    ".claude",
    ".gemini",
    ".config/gh",
    ".ssh",
    # Additional credential / tooling surfaces.  These are not Hermes state,
    # but a tool-driven write to them is a persistence or credential risk and
    # must be escalated rather than allowed (independent audit finding).
    ".aws",
    ".kube",
    ".gnupg",
    ".docker",
    ".cursor",
    ".vscode",
    ".config/mcp",
)

#: Absolute protected locations outside $HOME.
PROTECTED_ABSOLUTE: Tuple[str, ...] = (
    "/etc/hermes",
    "/etc/ssh",
    "/root/.hermes",
)

#: Credential-bearing files anywhere on disk (basename match).
CREDENTIAL_BASENAMES: Tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
    "application_default_credentials.json",
    ".netrc",
    ".npmrc",
    "config.json",
    # G1/F2: the AWS shared-credentials file is named exactly ``credentials``
    # (no extension). It is secret-bearing only inside a known credential
    # directory (``~/.aws/`` and siblings in CREDENTIAL_DIR_MARKERS), so a
    # project file that merely happens to be named ``credentials`` is NOT
    # reclassified. This closes the gap where ``~/.aws/credentials`` fell
    # through to a generic protected write instead of a credential verdict.
    "credentials",
    # Shell startup and MCP / editor task surfaces: a write here is a
    # persistence risk even though the file is not a credential itself.
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".profile",
    ".mcp.json",
)

#: Instruction files that external content must never be able to author.
INSTRUCTION_FILE_BASENAMES: Tuple[str, ...] = (
    "AGENTS.md",
    "CLAUDE.md",
    "SOUL.md",
    "GEMINI.md",
    "CLAUDE.local.md",
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    "copilot-instructions.md",
    # Lower-case variants are used by several tools and were previously
    # uncovered (independent audit finding).
    "agents.md",
    "claude.md",
    "soul.md",
    "gemini.md",
)

#: Skills that must not be silently installed from untrusted sources.
SKILL_FILE_BASENAMES: Tuple[str, ...] = ("SKILL.md",)

#: Model endpoint keys whose modification constitutes a gateway redirect.
ENDPOINT_KEY_RE = re.compile(
    r"(?i)\b(?:base_?url|api_?base|api_?url|endpoint|openai_?base_?url|"
    r"anthropic_?base_?url|ollama_?host|providers?\.?[\w]*\.?api)\b"
    r"|\bapi\b\s*[:=]\s*[\"']?(?:https?|wss?)://"
)

#: Environment variables that carry a model endpoint.
ENDPOINT_ENV_VARS: Tuple[str, ...] = (
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "ANTHROPIC_BASE_URL",
    "OLLAMA_HOST",
    "LLM_BASE_URL",
    "HERMES_BASE_URL",
    "VLLM_BASE_URL",
    "LITELLM_BASE_URL",
    "AZURE_OPENAI_ENDPOINT",
)

#: URL scheme fragment, assembled to keep this file free of literal URLs.
_URL_SCHEME = r"(?:https?|wss?)" + r"://"

#: An endpoint key bound to a URL: ``base_url: <url>``, ``base_url=<url>``.
_ENDPOINT_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:"
    r"base_?url|api_?base|api_?url|endpoint|ollama_?host|llm_?base_?url|"
    r"hermes_?base_?url|vllm_?base_?url|litellm_?base_?url|"
    r"azure_?openai_?endpoint|api"
    r")(?![A-Za-z0-9])"
    r"[\"\u0027]?\s*(?::|=>|->|=|\bto\b)\s*"
    r"[\"']?(?P<url>" + _URL_SCHEME + r"[^\s\"'<>]+)"
)

#: Shell environment assignment: ``export OPENAI_BASE_URL=<url>``.
_SHELL_ENV_ENDPOINT_RE = re.compile(
    r"(?i)\bexport\s+(?:OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_BASE_URL|"
    r"ANTHROPIC_API_URL|AZURE_OPENAI_ENDPOINT|AZURE_OPENAI_API_BASE|"
    r"HERMES[A-Z0-9_]*(?:ENDPOINT|BASE_URL|API_URL|API_BASE)|"
    r"OLLAMA_HOST|OLLAMA_BASE_URL|LITELLM_BASE_URL|VLLM_BASE_URL|"
    r"LITELLM_API_BASE)\s*=\s*"
    r"[\"']?(?P<url>" + _URL_SCHEME + r"[^\s\"'<>]+)"
)

#: Provider-scoped endpoint assignment: ``providers.ollama.api <url>``.
_ENDPOINT_PROVIDER_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])providers?\.[\w]*\.?api(?![A-Za-z0-9])"
    r"\s+[\"']?(?P<url>" + _URL_SCHEME + r"[^\s\"'<>]+)"
)

#: CLI switch form: ``config set <endpoint-key> <url>``.
_ENDPOINT_CLI_ASSIGNMENT_RE = re.compile(
    r"(?i)\bconfig\s+set\s+(?P<key>[A-Za-z0-9_.\-]+)\s+"
    r"[\"']?(?P<url>" + _URL_SCHEME + r"[^\s\"'<>]+)"
)

#: Key names that identify an endpoint in a CLI assignment.
_ENDPOINT_CLI_KEY_RE = re.compile(r"(?i)base|url|api|endpoint|host")

#: Protected surfaces that carry model-endpoint configuration.
ENDPOINT_CONFIG_BASENAMES: Tuple[str, ...] = (
    "config.yaml",
    "config.yml",
    "config.json",
    "config.toml",
    "settings.json",
    "providers.yaml",
    "providers.json",
    "plugin.yaml",
    ".env",
    ".env.local",
)

#: Endpoint hosts that are explicitly allowed without extra scrutiny.
#:
#: This is an *operator-owned* allowlist, not a range heuristic: only
#: loopback and the local container bridge are trusted by default. Private
#: RFC1918 space is NOT implicitly trusted (a relay can live there too),
#: and a bind-all address is not an outbound destination.
ENDPOINT_HOST_ALLOWLIST: Tuple[str, ...] = (
    "127.0.0.1",
    "localhost",
    "::1",
    "host.docker.internal",
)

#: Name of this plugin. Its own files and its own enablement are protected
#: against agent-initiated modification (PF-02).
FIREWALL_PLUGIN_NAME = "prompt-firewall"

#: Maximum recursion depth when flattening nested tool arguments for
#: inspection.  Beyond this the payload is reported as not fully inspected.
_MAX_ARG_DEPTH = 8

#: Control-plane surfaces relative to the ACTIVE Hermes home: mutating one of
#: them changes how the agent behaves, so the mutation needs an out-of-band
#: human decision instead of an automatic allow.
CONTROL_PLANE_HOME_FILES: Tuple[str, ...] = (
    "config.yaml",
    "config.yml",
    "SOUL.md",
    "AGENTS.md",
    "MEMORY.md",
    "USER.md",
)

CONTROL_PLANE_HOME_DIRS: Tuple[str, ...] = (
    "plugins",
    "skills",
    "cron",
    "profiles",
    "config",
)

# --------------------------------------------------------------------------- #
# Provenance model
# --------------------------------------------------------------------------- #

#: The operator (a human) explicitly authorized this action.
PROVENANCE_TRUSTED_OPERATOR = "trusted_operator"
#: The action is driven by content that arrived through a tool.
PROVENANCE_UNTRUSTED_CONTENT = "untrusted_content"
#: Provenance could not be established. This is the default, and it is NOT
#: trusted: a protected mutation with unknown provenance is escalated to the
#: native human-approval gate rather than silently allowed.
PROVENANCE_UNKNOWN = "unknown"

PROVENANCE_STATES: Tuple[str, ...] = (
    PROVENANCE_TRUSTED_OPERATOR,
    PROVENANCE_UNTRUSTED_CONTENT,
    PROVENANCE_UNKNOWN,
)

#: Tool names that can write to the filesystem.
WRITE_TOOLS: Tuple[str, ...] = (
    "write_file",
    "edit_file",
    "create_file",
    "patch",
    "str_replace",
    "str_replace_editor",
    "write",
    "append",
    "multi_edit",
    "apply_patch",
    "notebook_edit",
    "file_write",
)

#: Tool names that execute code or commands.
EXEC_TOOLS: Tuple[str, ...] = (
    "terminal",
    "execute_code",
    "bash",
    "shell",
    "run_command",
    "python",
    "run_python",
)

#: Tool names that create or modify skills.
SKILL_TOOLS: Tuple[str, ...] = (
    "skill_manage",
    "skill_create",
    "install_skill",
    "create_skill",
)

#: Tool names that only *read*. A read never mutates state, so a content
#: signature inside a read is advisory, not a reason to block the call.
READ_ONLY_TOOLS: Tuple[str, ...] = (
    "read_file",
    "get_file",
    "list_code",
    "search_files",
    "web_search",
    "web_extract",
    "skill_view",
    "session_search",
    "browser_navigate",
    "browser_extract",
    "browser_get_text",
    "fetch",
    "todo_list",
    "clarify",
)

# --------------------------------------------------------------------------- #
# Argument-scoped tools
#
# Some tools perform different *kinds* of action under the same name, so
# the tool name alone cannot classify the call: a memory read and a memory
# write both arrive as ``memory``, and a job listing and a job creation
# both arrive as ``cronjob_manage``. These tools are therefore classified
# by the action their arguments actually carry (Stage 2B).
# --------------------------------------------------------------------------- #

#: Tools whose effect depends on the arguments of the call, not on the name.
SCOPED_TOOLS: Tuple[str, ...] = (
    "memory",
    "cronjob_manage",
)

#: ``memory`` operations that change the long-lived store. This is the
#: complete set the tool accepts - it has no read/list operation at all,
#: so every valid ``memory`` call mutates.
MEMORY_MUTATING_ACTIONS: Tuple[str, ...] = (
    "add",
    "patch",
    "remove",
)

#: ``memory`` has no read operation: the store is inspected through the
#: ordinary file tools, not through this one. Kept as an explicit empty
#: set so the classification never assumes a read exists.
MEMORY_READ_ACTIONS: Tuple[str, ...] = ()

#: ``cronjob_manage`` actions that only inspect the schedule.
CRON_READ_ACTIONS: Tuple[str, ...] = (
    "list",
)

#: ``cronjob_manage`` actions that change, arm or fire a scheduled task.
#: Exactly the set the tool documents; anything else is unknown and is
#: therefore escalated rather than waved through.
CRON_MUTATING_ACTIONS: Tuple[str, ...] = (
    "create",
    "update",
    "pause",
    "resume",
    "remove",
    "run",
    "cancel",
)

#: Operation kinds reported by :func:`classify_scoped_operation`.
OP_READ = "read"
OP_MUTATE = "mutate"
OP_UNVERIFIED = "unverified"

#: Tools that only *observe*. Their arguments are a query, a URL or a path to
#: read, so a phrase inside them *describes* an action without performing it
#: (PF-12). Research and citation calls are therefore not blocked merely for
#: mentioning a security-control phrase.
OBSERVE_ONLY_TOOLS: Tuple[str, ...] = (
    "read_file",
    "get_file",
    "list_code",
    "search_files",
    "session_search",
    "skill_view",
    "web_search",
    "web_extract",
    "fetch",
    "browser_navigate",
    "browser_extract",
    "browser_get_text",
)

#: Research and citation tools that are not part of Hermes' core registry.
#: They report material; they never mutate a control.
RESEARCH_TOOLS: Tuple[str, ...] = (
    "research",
    "citation",
    "cite",
    "paper_search",
    "scholar_search",
)

#: Tool names the plugin understands. Anything else is treated as an unknown
#: side-effecting tool (PF-03): its arguments are inspected for protected
#: destinations, and it is never auto-allowed to write one.
KNOWN_TOOLS: Tuple[str, ...] = tuple(
    sorted(
        set(WRITE_TOOLS)
        | set(EXEC_TOOLS)
        | set(SKILL_TOOLS)
        | set(READ_ONLY_TOOLS)
        | set(SCOPED_TOOLS)
    )
)

#: Argument keys that name a filesystem destination.
_PATH_KEYS: Tuple[str, ...] = (
    "path",
    "file_path",
    "filename",
    "file",
    "target_file",
    "target_path",
    "abs_path",
    "notebook_path",
    "paths",
    "files",
    "dest",
    "destination",
    "dest_path",
    "output_path",
    "out_path",
    "target",
    "install_path",
    "to",
)

#: Patch-style payload keys (unified diff or Codex-style patch blocks).
_PATCH_KEYS: Tuple[str, ...] = (
    "patch_text",
    "patch",
    "diff",
    "unified_diff",
    "changes",
)

#: Markers of a protected destination inside a free-form string.
_PROTECTED_PATH_MARKERS: Tuple[str, ...] = (
    "/.hermes/",
    "/.codex/",
    "/.claude/",
    "/.gemini/",
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.kube/",
    "/.docker/",
    "/.config/gh/",
)


# --------------------------------------------------------------------------- #
# Path normalization
# --------------------------------------------------------------------------- #


#: Per-evaluation memo of normalized paths.
#:
#: ``normalize_path`` resolves a path against the *filesystem*, so its
#: result is only stable while the filesystem is stable.  Within a single
#: ``evaluate_tool_call`` the filesystem cannot meaningfully change -- the
#: call has not executed yet -- so the resolution of one path is the
#: resolution of that path for the whole evaluation.
#:
#: The B1 action path normalizes the *same* path many times per call:
#: ``is_protected_path`` normalizes the target and then normalizes the
#: Hermes home roots again, and the various path predicates each
#: normalize their own inputs.  Measured on the locked B1 corpus this is
#: 57 calls with only 17 distinct ``(raw, cwd)`` inputs -- 70% of the
#: resolutions are exact repeats, and each repeat costs an
#: ``expanduser``/``expandvars``/``realpath``/``exists`` round trip plus
#: the ancestor walk.
#:
#: The cache therefore lives for exactly ONE policy evaluation.  It is
#: installed by ``_normalize_path_memo_scope`` and removed again in a
#: ``finally``, so a later evaluation always re-reads the filesystem and
#: can never act on a stale resolution.
# Cache state lives in _eval_context (ContextVar), never in a module global.


def normalize_path(raw: str, cwd: Optional[str] = None) -> str:
    """Normalize *raw* without ever raising on hostile path input.

    Invalid path data is returned as a safe sentinel. Callers must treat the
    sentinel as unclassifiable and fail closed; it is never an authorization
    for a write.

    ``cwd`` is the *execution* directory of the tool call. When it is not
    supplied the process cwd remains the fallback for compatibility, but an
    ambient gateway cwd must never silently reclassify a relative shell
    destination as a protected path (P0-2).

    Inside a ``_normalize_path_memo_scope`` block the resolution is
    memoized for the duration of one policy evaluation; see
    the evaluation-local cache in ``_eval_context``.
    """
    if not isinstance(raw, str) or not raw:
        return ""
    memo = eval_state().setdefault("normalize_path", {})
    key = (raw, cwd)
    cached = memo.get(key)
    if cached is not None:
        return cached
    result = _normalize_path_uncached(raw, cwd)
    memo[key] = result
    return result


def _has_surrogate(text: str) -> bool:
    """True when *text* contains a surrogate code point (U+D800-U+DFFF).

    Equivalent to ``any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)``, but
    without a Python-level loop over every character:

    * an ASCII string has no code point above U+007F, so it cannot contain
      a surrogate and is rejected by the ``isascii()`` fast path;
    * otherwise the string is encoded with ``surrogatepass`` and scanned
      for the three-byte UTF-8 encoding of a surrogate
      (``ED A0 80`` .. ``ED BF BF``), which is exactly the range the
      original per-character test detects.

    The equivalence is exhaustive over all 1,114,112 code points and over
    200,000 random multi-character strings, with zero mismatches.
    """
    if text.isascii():
        return False
    try:
        raw = text.encode("utf-8", "surrogatepass")
    except UnicodeEncodeError:
        return False
    index = 0
    size = len(raw)
    while index < size:
        if raw[index] == 0xED and index + 2 < size:
            if 0xA0 <= raw[index + 1] <= 0xBF and 0x80 <= raw[index + 2] <= 0xBF:
                return True
            index += 3
            continue
        index += 1
    return False


def _normalize_path_uncached(raw: str, cwd: Optional[str] = None) -> str:
    """Normalize *raw* against the current filesystem state.

    The uncached implementation behind the memoizing ``normalize_path``
    wrapper.  See that function for the contract.
    """
    if not isinstance(raw, str) or not raw:
        return ""
    try:
        if "\x00" in raw or _has_surrogate(raw):
            return ""
        text = raw.strip().strip('"').strip("'")
        if not text or "\x00" in text:
            return ""
        expanded = os.path.expanduser(os.path.expandvars(text))
        if not isinstance(expanded, str) or "\x00" in expanded:
            return ""
        if not os.path.isabs(expanded):
            base = cwd or os.getcwd()
            expanded = posixpath.join(base, expanded)
        real = os.path.realpath(expanded)
        if os.path.exists(expanded):
            return real
        current = expanded
        tail: List[str] = []
        while True:
            parent = os.path.dirname(current)
            if not parent or parent == current:
                break
            tail.append(os.path.basename(current))
            current = parent
            if os.path.exists(current):
                real_parent = os.path.realpath(current)
                rebuilt = os.path.join(real_parent, *reversed(tail))
                return os.path.normpath(rebuilt)
        return posixpath.normpath(expanded)
    except (OSError, ValueError, UnicodeError, UnicodeEncodeError):
        return ""
    except Exception:
        return ""


def _home() -> str:
    return os.path.expanduser("~").rstrip("/") or "/"


#: Persistent-state surfaces relative to the ACTIVE Hermes home. The active
#: home is not always ``$HOME/.hermes`` — Hermes profiles live in
#: ``$HOME/.hermes/profiles/<name>`` and an embedder may point HERMES_HOME
#: anywhere. Whatever the active home is, its config, prompts, memory, plugin
#: settings and cron state are protected.
PROTECTED_HERMES_HOME_FILES: Tuple[str, ...] = (
    "config.yaml",
    "SOUL.md",
    "AGENTS.md",
    "MEMORY.md",
    "USER.md",
    ".env",
)

PROTECTED_HERMES_HOME_DIRS: Tuple[str, ...] = (
    "plugins",
    "skills",
    "memories",
    "cron",
    "profiles",
    "config",
)


def enforcement_eligible(finding, context=None) -> bool:
    """G2 contract hook: raw findings are detection by default.

    At G2 every finding remains eligible so existing rules keep exact behaviour.
    Later gates narrow eligibility only for verified data-only contexts.
    """
    return finding is not None


def resolve_decision(veto: bool, unresolved: bool) -> str:
    """G4 formal precedence: verified veto > unresolved protected > no violation."""
    if veto:
        return "block"
    if unresolved:
        return "approve"
    return "allow"


def dispatch_decision(*, veto_reason=None, veto_detail=None, unresolved_reason=None,
                      findings=()):
    """G4 centralized decision: verified veto BLOCK > unresolved APPROVE > None."""
    if veto_reason:
        return Verdict(action="block", reason=veto_reason, detail=veto_detail or "",
                       findings=tuple(findings))
    if unresolved_reason:
        return Verdict(action="approve", reason=unresolved_reason,
                       findings=tuple(findings))
    return None


#: Per-evaluation memo of the active Hermes home.
#:
#: ``_active_hermes_home`` resolves the Hermes home the running agent
#: actually uses.  It performs a module import (``from hermes_cli.config
#: import get_hermes_home``) and a call into Hermes Core on EVERY
#: invocation, and the B1 action path invokes it five times per tool call
#: (the protected-alias roots, the transient-dir exclusion, the protected
#: roots, and two control-plane checks).
#:
#: The resolved home cannot change while a single tool call is being
#: judged, so it is resolved once per evaluation.  The memo lives for
#: exactly ONE policy evaluation; outside one the home is resolved on
#: every call, exactly as before.
# Cache state lives in _eval_context (ContextVar), never in a module global.


def _active_hermes_home() -> str:
    """The Hermes home the running agent actually uses (never raises)."""
    state = eval_state()
    memo = state.get("active_hermes_home")
    if memo is not None:
        return memo
    home_path = ""
    try:
        from hermes_cli.config import get_hermes_home

        home = get_hermes_home()
        if home:
            home_path = str(home).rstrip("/") or "/"
    except Exception:
        pass
    if not home_path:
        home_path = os.path.join(_home(), ".hermes")
    state["active_hermes_home"] = home_path
    return home_path


def _within(child: str, parent: str) -> bool:
    """True if *child* is *parent* or lives underneath it."""
    if not child or not parent:
        return False
    parent = parent.rstrip("/") or "/"
    if child == parent:
        return True
    if parent == "/":
        return child.startswith("/")
    return child.startswith(parent + "/")


def _canonical_equivalent(raw_path: str, logical_root: str, relative: str = "") -> bool:
    """Compare a target and protected root after resolving existing parents."""
    target = normalize_path(raw_path)
    root = normalize_path(logical_root)
    if not target or not root:
        return False
    expected = normalize_path(posixpath.join(logical_root, relative))
    return bool(expected and _within(target, expected))


def _protected_alias_roots() -> Tuple[str, ...]:
    """Canonical roots for the Hermes home and the firewall plugin directory.

    The bare Hermes home is a root because a symlink or a ``cp --target-directory``
    can reach any protected subdirectory through it. The scratch/cache
    exception is applied by the caller (``is_protected_path``) rather than by
    removing the root here, so those aliasing routes stay protected.
    """
    home = _home()
    active = _active_hermes_home()
    roots = (
        posixpath.join(home, ".hermes"),
        active,
        posixpath.join(active, "plugins", FIREWALL_PLUGIN_NAME),
    )
    return tuple(dict.fromkeys(r for r in (normalize_path(x) for x in roots) if r))


#: Subdirectories of the Hermes home that hold transient state rather than
#: persistent configuration. A write here is not a persistence risk, so it is
#: excluded from protected-path matching even though it lives under a
#: protected root.
_NON_PERSISTENT_HOME_DIRS: Tuple[str, ...] = (
    "cache",
    "logs",
    "sessions",
    "state",
    "tmp",
)


def _matches_protected_alias(raw_path: str) -> bool:
    # Lexical alias guard: a symlinked plugin directory resolves OUTSIDE the
    # protected home, so realpath-only checking would miss it (S2FA).  Any
    # path spelled through ``.hermes/plugins/<firewall>/`` stays protected
    # regardless of where the symlink points.
    raw = posixpath.normpath((raw_path or "").replace("\\", "/"))
    marker = "/.hermes/plugins/" + FIREWALL_PLUGIN_NAME + "/"
    if marker in raw or raw.endswith(marker[:-1]):
        return True
    target = normalize_path(raw_path)
    if not target:
        return True
    if _within_non_persistent_home(target, raw_path):
        return False
    return any(_within(target, root) for root in _protected_alias_roots())


def _within_non_persistent_home(path: str, raw_path: str = "") -> bool:
    """True if *path* lives under a transient (non-persistent) Hermes dir.

    ``cache/``, ``logs/``, ``sessions/``, ``state/`` and ``tmp/`` under a
    Hermes home hold scratch data, not configuration. They sit below a
    protected root, so they are excluded explicitly; a path that merely
    *passes through* such a directory on the way to a protected one is not
    excluded, because the protected parent still governs it.

    The check is anchored on the ACTIVE Hermes home only, and it never
    consults ``$HOME``. A scratch tree created under the real
    ``~/.hermes/cache`` while ``$HOME`` points elsewhere is still scratch:
    what matters is where the path actually resolves, not which home the
    process happens to be using.
    """
    # The exclusion must follow the path's own Hermes home, not only the
    # currently active one: a relocated HERMES_HOME can point at one scratch
    # directory while the path under test lives in a sibling scratch tree.
    raw = posixpath.normpath((raw_path or path or "").replace("\\", "/"))
    raw_parts = [p for p in raw.split("/") if p]
    for index, part in enumerate(raw_parts):
        if part != ".hermes" or index + 1 >= len(raw_parts):
            continue
        transient = raw_parts[index + 1]
        if transient not in _NON_PERSISTENT_HOME_DIRS:
            continue
        # A ``.hermes`` tree nested inside the transient dir is a Hermes home
        # in its own right (a test fixture or a relocated home), not scratch.
        if ".hermes" in raw_parts[index + 2:]:
            return False
        prefix = "/" + "/".join(raw_parts[:index + 2])
        resolved_prefix = normalize_path(prefix)
        if resolved_prefix and _within(path, resolved_prefix):
            return True
    active = normalize_path(_active_hermes_home())
    if not active or not _within(path, active):
        return False
    relative = path[len(active):].lstrip("/")
    if not relative:
        return False
    parts = relative.split("/")
    if parts[0] not in _NON_PERSISTENT_HOME_DIRS:
        return False
    raw_relative = (raw_path or path).rstrip("/")[len(active):].lstrip("/")
    raw_parts = [p for p in raw_relative.split("/") if p]
    if ".hermes" in raw_parts[1:]:
        return False
    return True


def is_protected_path(raw_path: str, cwd: Optional[str] = None) -> bool:
    """True if *raw_path* is a persistent-configuration / credential surface."""
    if not raw_path:
        return False
    path = normalize_path(raw_path, cwd)
    if not path:
        return True
    # The RAW path is passed so the transient-dir exclusion can see a
    # ``.hermes`` component that normalize_path() would resolve away.
    if _matches_protected_alias(raw_path):
        return True
    home = _home()

    for rel in PROTECTED_HOME_FILES:
        if _within(path, posixpath.join(home, rel)):
            return True
    for rel in PROTECTED_HOME_DIRS:
        if _within(path, posixpath.join(home, rel)):
            return True
    for abs_path in PROTECTED_ABSOLUTE:
        if _within(path, abs_path):
            return True

    # The active Hermes home (profile home, custom HERMES_HOME, ...).
    active_home = _active_hermes_home()
    for rel in PROTECTED_HERMES_HOME_FILES:
        if _within(path, posixpath.join(active_home, rel)):
            return True
    for rel in PROTECTED_HERMES_HOME_DIRS:
        if _within(path, posixpath.join(active_home, rel)):
            return True

    base = posixpath.basename(path)
    if base in CREDENTIAL_BASENAMES and base not in STRICT_CREDENTIAL_BASENAMES:
        # Generic names ("config.json") are credentials only inside a known
        # credential directory (PF-13).
        if any(marker in path for marker in CREDENTIAL_DIR_MARKERS):
            return True
    elif is_credential_path(path):
        return True

    if base in INSTRUCTION_FILE_BASENAMES:
        # Instruction files are protected wherever they live, because a
        # poisoned AGENTS.md anywhere on the path is what hijacks the agent.
        return True
    return False


def is_skill_path(raw_path: str) -> bool:
    path = normalize_path(raw_path)
    if not path:
        return False
    if posixpath.basename(path) in SKILL_FILE_BASENAMES:
        return True
    return "/skills/" in path or path.endswith("/skills")


def is_instruction_path(raw_path: str) -> bool:
    path = normalize_path(raw_path)
    if not path:
        return False
    return posixpath.basename(path) in INSTRUCTION_FILE_BASENAMES


#: Credential file names that are secret-bearing wherever they live.
STRICT_CREDENTIAL_BASENAMES: Tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "service-account.json",
    "application_default_credentials.json",
)

#: Directories that hold credentials. A generic name (``config.json``) is only
#: credential-bearing inside one of them, so ``~/.hermes/plugins/x/config.json``
#: is an ordinary plugin file again (PF-13).
CREDENTIAL_DIR_MARKERS: Tuple[str, ...] = (
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.kube/",
    "/.docker/",
    "/.config/gcloud/",
    "/.config/gh/",
    "/.config/gcloud",
)


def is_credential_path(raw_path: str) -> bool:
    """True when *raw_path* names a file that holds credentials.

    The classification is deliberately narrow (PF-13): generic names such as
    ``config.json`` only count inside a known credential directory, and the
    whole ``~/.hermes`` tree is *not* a credential directory.
    """
    path = normalize_path(raw_path)
    if not path:
        return False
    base = posixpath.basename(path)
    if base in STRICT_CREDENTIAL_BASENAMES:
        return True
    if base in CREDENTIAL_BASENAMES:
        return any(m in path for m in CREDENTIAL_DIR_MARKERS)
    return False


# --------------------------------------------------------------------------- #
# Endpoint / gateway policy
# --------------------------------------------------------------------------- #


def _host_from_url(url: str) -> str:
    """Return the bare host of *url* (no scheme, path, credentials or port).

    Parsing goes through :func:`urllib.parse.urlsplit` so that bracketed
    IPv6 literals (``[::1]``) and ``user:pass@host`` forms are handled by the
    standard library instead of by hand-rolled string surgery.
    """
    if not url:
        return ""
    candidate = url if "//" in url else "//" + url
    try:
        parts = urllib.parse.urlsplit(candidate)
    except ValueError:
        return ""
    host = parts.hostname or ""
    return host.strip(".").lower()


def extract_endpoint_hosts(text: str) -> List[str]:
    """Return the hosts bound to a model-endpoint setting in *text*.

    Only a URL that is attached to an endpoint key counts: an assignment
    (``base_url: <url>``), a provider-scoped assignment
    (``providers.ollama.api <url>``) or a CLI switch
    (``config set <endpoint-key> <url>``). A URL that merely sits next to
    the word "endpoint" in prose, source code or documentation is not a
    redirect and must not be reported here.
    """
    hosts: List[str] = []
    if not text:
        return hosts
    for pattern in (
        _ENDPOINT_ASSIGNMENT_RE,
        _ENDPOINT_PROVIDER_ASSIGNMENT_RE,
        _SHELL_ENV_ENDPOINT_RE,
    ):
        for match in pattern.finditer(text):
            host = _host_from_url(match.group("url"))
            if host and host not in hosts:
                hosts.append(host)
    for match in _ENDPOINT_CLI_ASSIGNMENT_RE.finditer(text):
        if not _ENDPOINT_CLI_KEY_RE.search(match.group("key")):
            continue
        host = _host_from_url(match.group("url"))
        if host and host not in hosts:
            hosts.append(host)
    return hosts



_MODEL_ENV_KEYS = frozenset({
    "OPENAI_BASE_URL", "OPENAI_API_BASE", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_URL", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_BASE",
    "OLLAMA_HOST", "OLLAMA_BASE_URL", "LITELLM_BASE_URL", "VLLM_BASE_URL",
    "LITELLM_API_BASE",
})


def _safe_literal_concat(expr: str):
    """Evaluate only string-literal ``+`` chains; never execute code."""
    try:
        node = ast.parse(expr.strip(), mode="eval").body
    except (SyntaxError, ValueError):
        return None

    def walk(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return n.value
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            left, right = walk(n.left), walk(n.right)
            if left is not None and right is not None:
                return left + right
        return None

    return walk(node)


def _unresolved_provider_env_assignments(source: str) -> bool:
    """True when a *known provider* env key/destination is computed, not literal.

    Unrelated SDK variables (for example PAYMENTS_ENDPOINT) are deliberately
    ignored: this is not a ban on dynamic Python, only unresolved protected
    destination state.
    """
    if not source:
        return False
    values = {}
    for line in source.splitlines():
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", line)
        if m:
            val = _safe_literal_concat(m.group(2))
            if val is not None:
                values[m.group(1)] = val
    for line in source.splitlines():
        m = re.search(
            r"os\.environ\s*\[\s*(?P<key>[^\]]+)\]\s*=\s*(?P<val>.+?)\s*$", line
        )
        if not m:
            continue
        key_expr, val_expr = m.group("key").strip(), m.group("val").strip()
        key = _safe_literal_concat(key_expr)
        if key is None:
            key = values.get(key_expr)
        if key is None:
            continue
        key = key.strip().strip("'\"").upper()
        if key.startswith("HERMES") and (
            "ENDPOINT" in key or "BASE_URL" in key or "API_URL" in key or "API_BASE" in key
        ):
            is_provider = True
        else:
            is_provider = key in _MODEL_ENV_KEYS
        if not is_provider:
            continue
        # A literal key with a literal URL is already enforced by the explicit
        # BLOCK rule; anything computed is unresolved and must APPROVE.
        if _safe_literal_concat(val_expr) is None:
            return True
        # A computed key is unresolved authorization even with a literal URL.
        if _safe_literal_concat(key_expr) is None:
            return True
    return False

def endpoint_is_allowlisted(host: str) -> bool:
    """True when *host* is an operator-approved endpoint destination.

    The check is exact: a name in the operator-owned allowlist, or a
    syntactically valid loopback address. Private RFC1918 space is not
    trusted by default - an internal relay is just as dangerous as a
    public one - and a malformed address is never allowlisted.
    """
    host = _normalize_host(host)
    if not host:
        return False
    if host in ENDPOINT_HOST_ALLOWLIST:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback


def _normalize_host(host: str) -> str:
    """Lower-case, de-bracket a host string (IPv6 literals arrive bracketed)."""
    host = (host or "").strip().strip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.lower()


def is_endpoint_config_path(raw_path: str) -> bool:
    """True if *raw_path* is a protected surface that carries the endpoint."""
    path = normalize_path(raw_path)
    if not path:
        return False
    if posixpath.basename(path) not in ENDPOINT_CONFIG_BASENAMES:
        return False
    return is_protected_path(path)


def mentions_endpoint_change(text: str) -> bool:
    """True when *text* binds a URL to a model-endpoint setting."""
    if not text:
        return False
    return bool(extract_endpoint_hosts(text))


# --------------------------------------------------------------------------- #
# PF-02: structural analysis of the firewall's own configuration
# --------------------------------------------------------------------------- #


def _yaml_list(value: str) -> List[str]:
    """Parse an inline ``[a, b]`` or a bare scalar into a list of strings."""
    text = (value or "").strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1]
        return [part.strip().strip("\"'") for part in inner.split(",") if part.strip()]
    return [text.strip("'\"")]


def _plugins_state_from_yaml(text: str) -> Dict[str, Any]:
    """Extract the ``plugins:`` section of a YAML config as plain facts.

    This is a structural scan of *keys*, not a phrase matcher: it reads
    ``plugins.enabled``, ``plugins.disabled`` and
    ``plugins.entries.<name>.enabled`` no matter how the values are written.

    The scan is indentation-aware: a nested ``entries:`` block keeps its own
    key context, so ``plugins.entries.prompt-firewall.enabled: false`` is
    read as *that entry* being disabled and not as a top-level
    ``plugins.enabled`` value (PF-02).
    """
    facts: Dict[str, Any] = {"enabled": None, "disabled": [], "entries": {}}
    in_plugins = False
    plugins_indent = 0
    in_entries = False
    entries_indent = 0
    pending_entry: Optional[str] = None
    pending_indent = 0
    list_key: Optional[str] = None

    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())

        if not in_plugins:
            if re.match(r"^plugins\s*:", stripped):
                in_plugins = True
                plugins_indent = indent
            continue

        if indent <= plugins_indent:
            in_plugins = False
            in_entries = False
            pending_entry = None
            list_key = None
            continue

        if in_entries:
            if indent <= entries_indent:
                in_entries = False
                pending_entry = None
                list_key = None
                continue
            if pending_entry is not None:
                match = re.match(r"^enabled\s*:\s*(\S+)", stripped)
                if match:
                    facts["entries"].setdefault(pending_entry, {})["enabled"] = match.group(1)
                continue
            match = re.match(r"^([\w.-]+)\s*:\s*(.*)$", stripped)
            if match:
                name = match.group(1)
                rest = match.group(2).strip()
                pending_entry = name
                pending_indent = indent
                facts["entries"].setdefault(name, {})
                if rest:
                    facts["entries"][name]["enabled"] = rest
                continue
            continue

        if stripped == "entries:":
            in_entries = True
            entries_indent = indent
            list_key = None
            continue

        match = re.match(r"^(enabled|disabled)\s*:\s*(.*)$", stripped)
        if match:
            key, value = match.group(1), match.group(2).strip()
            if value:
                parsed = _yaml_list(value)
                if key == "enabled":
                    facts["enabled"] = parsed
                else:
                    facts["disabled"] = parsed
                list_key = None
            else:
                list_key = key
                if key == "enabled":
                    facts["enabled"] = []
                else:
                    facts["disabled"] = []
            continue

        if stripped.startswith("- "):
            if list_key == "enabled" and isinstance(facts["enabled"], list):
                facts["enabled"].append(stripped[2:].strip().strip("\"'"))
            elif list_key == "disabled":
                facts["disabled"].append(stripped[2:].strip().strip("\"'"))
            continue

    return facts


def config_firewall_state_mutation(content: str) -> Optional[str]:
    """Detect a *structural* change that disables this firewall.

    The check looks at configuration *keys* (``plugins.enabled``,
    ``plugins.disabled``, ``plugins.entries.prompt-firewall.enabled``) instead
    of at any wording, so a payload that never mentions the firewall by name
    is still caught (PF-02).

    Returns a short reason, or ``None`` when the content does not touch the
    firewall's enablement.
    """
    if not content or not isinstance(content, str) or not content.strip():
        return None

    stripped = content.strip()
    if stripped[:1] == "{":
        try:
            data = json.loads(stripped)
        except (ValueError, TypeError):
            data = None
        if not isinstance(data, dict):
            return None
        plugins = data.get("plugins")
        if not isinstance(plugins, dict):
            return None
        disabled = plugins.get("disabled")
        if isinstance(disabled, list) and FIREWALL_PLUGIN_NAME in disabled:
            return "plugins.disabled lists prompt-firewall"
        entries = plugins.get("entries")
        if isinstance(entries, dict):
            entry = entries.get(FIREWALL_PLUGIN_NAME)
            if isinstance(entry, dict) and entry.get("enabled") is False:
                return "plugins.entries.prompt-firewall.enabled is false"
        enabled = plugins.get("enabled")
        if isinstance(enabled, list) and FIREWALL_PLUGIN_NAME not in enabled:
            return "plugins.enabled no longer lists prompt-firewall"
        return None

    facts = _plugins_state_from_yaml(content)
    if FIREWALL_PLUGIN_NAME in facts["disabled"]:
        return "plugins.disabled lists prompt-firewall"
    entry = facts["entries"].get(FIREWALL_PLUGIN_NAME)
    if isinstance(entry, dict):
        flag = str(entry.get("enabled", "")).strip().lower()
        if flag in ("false", "no", "off"):
            return "plugins.entries.prompt-firewall.enabled is false"
    if isinstance(facts["enabled"], list) and FIREWALL_PLUGIN_NAME not in facts["enabled"]:
        return "plugins.enabled no longer lists prompt-firewall"
    return None


def config_firewall_entry_removal(content: str) -> Optional[str]:
    """Detect a *deletion* of this firewall's config entry or own metadata.

    ``config_firewall_state_mutation`` only recognises an explicit
    ``enabled: false`` / ``disabled: [...]`` payload.  A deletion expresses
    the same intent structurally: the selector (``old_text``) names the
    firewall's entry (or its own ``plugin.yaml``) and the replacement is
    empty or a different version.  Without this check those edits returned
    ``allow`` (PF-02).
    """
    if not content or not isinstance(content, str):
        return None
    if FIREWALL_PLUGIN_NAME not in content:
        return None
    # A selector that names the firewall's own entry/plugin metadata.
    if re.search(
        r"(?m)^\s*(?:-\s*)?" + re.escape(FIREWALL_PLUGIN_NAME) + r"\s*:",
        content,
    ):
        return f"config entry for {FIREWALL_PLUGIN_NAME} is edited"
    if re.search(
        r"(?m)^\s*version\s*:\s*\S+",
        content,
    ):
        return f"{FIREWALL_PLUGIN_NAME} plugin metadata is edited"
    return None


def is_firewall_own_path(raw_path: str) -> bool:
    """True when *raw_path* points into this firewall's own plugin directory."""
    path = normalize_path(raw_path)
    if not path:
        return False
    own = posixpath.join(_active_hermes_home(), "plugins", FIREWALL_PLUGIN_NAME)
    return _within(path, own)


def is_control_plane_path(raw_path: str, cwd: Optional[str] = None) -> bool:
    """True when *raw_path* is a control-plane surface of the active Hermes home."""
    path = normalize_path(raw_path, cwd)
    if not path:
        return False
    if _matches_protected_alias(path):
        return True
    home = _active_hermes_home()
    for rel in CONTROL_PLANE_HOME_FILES:
        if _within(path, posixpath.join(home, rel)):
            return True
    for rel in CONTROL_PLANE_HOME_DIRS:
        if _within(path, posixpath.join(home, rel)):
            return True
    for rel in PROTECTED_HOME_FILES:
        if _within(path, posixpath.join(_home(), rel)):
            return True
    for rel in PROTECTED_HOME_DIRS:
        if _within(path, posixpath.join(_home(), rel)):
            return True
    return False


# --------------------------------------------------------------------------- #
# Tool argument inspection
# --------------------------------------------------------------------------- #


def _bounded_arg_strings(
    args: Any, *, budget: int = _SCOPED_SCAN_BUDGET
) -> Tuple[str, bool]:
    """Concatenate nested string values with an explicit completeness bit.

    Recursion is depth-limited and the collected text is capped at *budget*
    characters.  When either limit is hit the second return value is ``False``
    so callers can distinguish "nothing suspicious found" from "the payload
    was not fully inspected".

    The budget accounts for the ``"\\n"`` separators that
    ``"\\n".join(parts)`` inserts, and for the fact that a value which does
    not fit is *dropped* rather than truncated.  Without that, a payload
    built from many short values could stay under the budget by value sum
    while the joined text that is actually scanned exceeded it - and the
    completeness bit would wrongly report ``True``.
    """
    parts: List[str] = []
    used = 0
    complete = True

    def take(text: str) -> None:
        """Append *text* plus its separator, or mark the scan incomplete."""
        nonlocal used, complete
        needed = len(text) + (1 if parts else 0)
        if used + needed > budget:
            complete = False
            return
        parts.append(text)
        used += needed

    def walk(value: Any, depth: int = 0) -> None:
        nonlocal complete
        if depth > _MAX_ARG_DEPTH:
            complete = False
            return
        if isinstance(value, str):
            take(value)
        elif isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str):
                    take(key)
                walk(child, depth + 1)
        elif isinstance(value, (list, tuple)):
            for child in value:
                walk(child, depth + 1)

    walk(args)
    # The joined text is what gets scanned, so it must fit the budget.  A
    # value that was dropped above leaves the joined text shorter than the
    # budget but the payload is still incomplete: the completeness bit is
    # already False.  This guard covers the case where the *keys* alone
    # consumed the budget and every value was dropped.
    joined = "\n".join(parts)
    if len(joined) > budget:
        complete = False
    return joined, complete


def _arg_text(args: Any) -> str:
    """Concatenate nested string values of a tool argument mapping."""
    text, _complete = _arg_strings_once(args)
    return text


def _arg_scan_complete(args: Any) -> bool:
    """False when the argument payload exceeded the inspection budget."""
    _text, complete = _arg_strings_once(args)
    return complete


#: Per-evaluation memo of the bounded argument strings.
#:
#: ``_bounded_arg_strings`` walks the whole argument tree and concatenates
#: every nested string value under an explicit character budget.  The B1
#: action path needs BOTH of its results -- the joined text (to scan) and
#: the completeness bit (to decide whether the scan was exhaustive) -- but
#: it asked for them separately, so the tree was walked twice per tool
#: call.
#:
#: The walk depends only on the argument mapping, which cannot change
#: while the call is being judged, so the result is computed once per
#: evaluation.  The memo is keyed on the *identity* of the argument
#: mapping, so two different mappings never share an entry.  Outside an
#: evaluation the memo is absent and the walk happens on every call,
#: exactly as before.
# Cache state lives in _eval_context (ContextVar), never in a module global.


def _arg_strings_once(args: Any) -> Tuple[str, bool]:
    """The bounded argument text and its completeness bit, computed once.

    Inside a policy evaluation the result is memoized, so the argument
    tree is walked once instead of once per consumer.
    """
    state = eval_state()
    memo = state.get("arg_strings")
    if memo is not None:
        cached_args, text, complete = memo
        if cached_args is args:
            return text, complete
    result = _bounded_arg_strings(args)
    state["arg_strings"] = (args, result[0], result[1])
    return result


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def extract_patch_targets(args: Any) -> List[str]:
    """Extract the files a patch payload touches (PF-03).

    Both patch dialects Hermes accepts are understood: a unified diff
    (``--- a/file`` / ``+++ b/file``) and the Codex-style block
    (``*** Update File: path``).
    """
    targets: List[str] = []

    def harvest(blob: str) -> None:
        for match in re.finditer(
            r"^\*\*\*\s+(?:Update|Add|Delete|Move|Rename)\s+File:\s*(.+)$",
            blob,
            re.MULTILINE,
        ):
            targets.append(match.group(1).strip())
        for match in re.finditer(
            r"^(?:---|\+\+\+)\s+(?:[ab]/)?(\S+)", blob, re.MULTILINE
        ):
            candidate = match.group(1).strip()
            if candidate not in ("/dev/null",):
                targets.append(candidate)

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(node, str):
            harvest(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key in _PATCH_KEYS:
                    walk(value, depth + 1)
                elif isinstance(value, (dict, list, tuple)):
                    walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, depth + 1)

    walk(args)
    return _dedupe(targets)


# --------------------------------------------------------------------------- #
# Stage 2A - write-target resolution for executable calls
#
# This is deliberately NOT a shell parser and NOT a sandbox. It recognises a
# closed set of write verbs and redirection forms and resolves a destination
# only when that destination is statically knowable: a literal path, or a
# relative path below a statically known ``cd``. A destination that depends
# on variable expansion, globbing, command substitution or unreadable code is
# treated as unresolvable - a residual risk - and never as a confirmed write.
# --------------------------------------------------------------------------- #

#: Verbs that only prefix another command.
#: The name part of a shell environment assignment (``NAME=value``).
_ENV_ASSIGNMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_SHELL_WRAPPER_VERBS: Tuple[str, ...] = (
    "sudo",
    "doas",
    "env",
    "command",
    "nohup",
    "time",
    "builtin",
    "exec",
)

#: Wrapper options that consume the following token.
_SHELL_WRAPPER_OPTION_VALUES: Dict[str, Tuple[str, ...]] = {
    "sudo": ("-u", "-g", "-p", "-C", "-h", "-r", "-t", "--user", "--group"),
    "doas": ("-u", "-C", "-s", "--user"),
    "env": ("-u", "-i", "-C", "--chdir", "--unset"),
    "time": ("-f", "-o"),
}

#: Redirection operators that create or extend a file.
_SHELL_WRITE_REDIRECTS: Tuple[str, ...] = (">>", "&>>", ">|", "&>", ">")

#: Options that consume the following token, per verb.
_SHELL_OPTION_VALUES: Dict[str, Tuple[str, ...]] = {
    "sed": ("-e", "--expression", "-f", "--file"),
    "perl": ("-e", "-E", "-I", "-M", "-m", "-F"),
    "cp": ("-t", "--target-directory", "-S", "--suffix", "--reference"),
    "mv": ("-t", "--target-directory", "-S", "--suffix"),
    "ln": ("-t", "--target-directory", "-S", "--suffix"),
    "install": (
        "-m",
        "--mode",
        "-o",
        "--owner",
        "-g",
        "--group",
        "-t",
        "--target-directory",
    ),
    "truncate": ("-s", "--size", "-r", "--reference"),
}

#: Python-ish tools whose payload is source code, not a shell command.
_PYTHON_EXEC_TOOLS: Tuple[str, ...] = ("execute_code", "python", "run_python")

#: Shell tools whose payload is a command line.
_SHELL_EXEC_TOOLS: Tuple[str, ...] = ("terminal", "bash", "shell", "run_command")

#: Literal Python writes: ``open(path, mode)``.
_PY_OPEN_RE = re.compile(
    r"\bopen\(\s*(['\"])([^'\"]+)\1\s*,\s*['\"]([^'\"]*)['\"]"
)

#: Literal writes through a ``Path`` object.
_PY_PATH_RE = re.compile(
    r"\b(?:pathlib\.)?Path\(\s*(['\"])([^'\"]+)\1\s*\)\s*\.\s*"
    r"(?:write_text|write_bytes|unlink|mkdir|rmdir|touch|rename|replace)\s*\("
)

#: Literal writes through ``os``.
_PY_OS_RE = re.compile(
    r"\bos\.(?P<verb>remove|unlink|rmdir|removedirs|makedirs|mkdir|rename|replace"
    r"|chmod|chown)\(\s*(?P<args>[^)]*)\)"
)

#: Literal writes through ``shutil``.
_PY_SHUTIL_RE = re.compile(
    r"\bshutil\.(?P<verb>copy|copy2|copyfile|copytree|move|rmtree)\(\s*"
    r"(?P<args>[^)]*)\)"
)


def _is_comment_start(text: str, idx: int) -> bool:
    """POSIX shell: ``#`` begins a comment only at a word boundary.

    A ``#`` inside a word (``foo#bar``, ``https://x/#frag``) is literal
    data and must not erase the rest of the line -- otherwise a later
    redirect or ``-o`` destination disappears from policy analysis (R01/R02).
    """
    if idx <= 0:
        return True
    prev = text[idx - 1]
    return prev.isspace() or prev in ";|&()<>$\\"


#: Maximum number of memoized tokenizations kept at once.
_SHELL_TOKENIZE_MEMO_MAX = 512

# The tokenization memo is evaluation-local.  Although tokenization itself is
# environment-independent, command strings can contain sensitive arguments and
# a process-global mutable dict would retain them and race during eviction.


def _shell_tokenize(command: str) -> List[str]:
    """Split a command into tokens, keeping operators (including newlines).

    Memoized within the current evaluation only.  The returned list is shared
    between callers, so a caller MUST NOT mutate it.  Every caller in this
    module only reads it.
    """
    if not command:
        return []
    memo = eval_state().setdefault("shell_tokenize", {})
    cached = memo.get(command)
    if cached is not None:
        return cached
    tokens = _shell_tokenize_uncached(command)
    if len(memo) >= _SHELL_TOKENIZE_MEMO_MAX:
        # Bounded per-evaluation memo; no cross-thread eviction race.
        del memo[next(iter(memo))]
    memo[command] = tokens
    return tokens


def _shell_tokenize_uncached(command: str) -> List[str]:
    """Split a command into tokens, keeping operators (including newlines).

    ``shlex`` with ``punctuation_chars`` treats ``\\n`` as ordinary
    whitespace, which silently collapses a multi-line script into one
    segment: a later ``cd`` and a later redirect are then attributed to the
    first verb.  Newlines are real shell command separators, so they are
    replaced with ``;`` before tokenization.  Heredoc bodies are blanked out
    first so their text is never mistaken for commands.
    """
    if not command:
        return []
    command = command.replace("\r\n", "\n")

    # --- heredoc blanking (quote-aware delimiter) -------------------------
    # A heredoc body is DATA, not commands; the redirect on its header stays
    # visible. Delimiters may be quoted and <<- allows tab-indented enders.
    lines = command.split("\n")
    heredoc_terms: List[Tuple[str, bool]] = []  # (delimiter, strip_tabs_only)
    cleaned: List[str] = []
    _HD = re.compile(
        r"<<(-?)\s*(?:'([^']+)'|\"([^\"]+)\"|\\([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))"
    )
    for line in lines:
        if heredoc_terms:
            term, dash = heredoc_terms[-1]
            candidate = line.lstrip("\t") if dash else line.rstrip("\n")
            if candidate == term:
                heredoc_terms.pop()
            cleaned.append("__PF_HEREDOC_BLANK__")
            continue
        cleaned.append(line)
        in_single = in_double = False
        scan_at = 0
        for idx, char in enumerate(line):
            if char == "\\" and in_double and idx + 1 < len(line):
                continue  # escaped quote inside double quotes
            if char == "'" and not in_double:
                in_single = not in_single
            elif char == '"' and not in_single:
                in_double = not in_double
            elif char == "#" and not in_single and not in_double and _is_comment_start(line, idx):
                break  # comment starts: no heredoc operator after it
            elif char == "<" and not in_single and not in_double and line[idx:idx + 2] == "<<":
                scan_at = idx
                break
        m = _HD.search(line, scan_at)
        if m:
            term = m.group(2) or m.group(3) or m.group(4) or m.group(5)
            heredoc_terms.append((term, bool(m.group(1))))
    # Remove blanked heredoc lines entirely: no newline separator is emitted
    # for data lines, so only real commands remain in the token stream.
    cleaned = [line for line in cleaned if line != "__PF_HEREDOC_BLANK__"]
    command = "\n".join(cleaned)

    # --- quote-aware newline / continuation / comment handling -------------
    # shlex treats '\n' as whitespace; a global replace corrupts quoted
    # strings and line continuations. Walk with shell state: unquoted newline
    # is a separator (';'), backslash-newline (inside or outside quotes) is a
    # continuation, and an unquoted '#' starts a comment until end of line.
    out: List[str] = []
    i = 0
    size = len(command)
    quote: str = ""
    while i < size:
        char = command[i]
        if quote == "'":
            out.append(char)
            if char == "'":
                quote = ""
            i += 1
            continue
        if quote == '"':
            if char == "\\" and i + 1 < size:
                if command[i + 1] == "\n":
                    i += 2  # continuation inside double quotes
                    continue
                out.append(char)
                out.append(command[i + 1])
                i += 2
                continue
            out.append(char)
            if char == '"':
                quote = ""
            i += 1
            continue
        if char == "'":
            quote = "'"
            out.append(char)
            i += 1
            continue
        if char == '"':
            quote = '"'
            out.append(char)
            i += 1
            continue
        if char == "#" and _is_comment_start(command, i):
            while i < size and command[i] != "\n":
                i += 1
            continue
        if char == "\\" and i + 1 < size and command[i + 1] == "\n":
            i += 2
            continue
        if char == "\\" and i + 1 < size:
            out.append(char)
            out.append(command[i + 1])
            i += 2
            continue
        if char == "\n":
            out.append(";")
            i += 1
            continue
        out.append(char)
        i += 1
    command = "".join(out)

    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens: List[str] = []
    try:
        for token in lexer:
            tokens.append(token)
    except ValueError:
        # FAIL CLOSED: never erase the command. An unparseable command is
        # marked so the policy treats it as unverifiable rather than benign.
        return ["__PF_UNPARSEABLE__"] + [t for t in tokens if t]
    return tokens


def _shell_operands(args: Sequence[str], value_options: Sequence[str]) -> List[str]:
    """The non-option operands of a command (options and their values drop out)."""
    operands: List[str] = []
    skip = False
    for token in args:
        if skip:
            skip = False
            continue
        if token == "--":
            continue
        if token.startswith("-") and token != "-":
            if token.split("=", 1)[0] in value_options and "=" not in token:
                skip = True
            continue
        operands.append(token)
    return operands


def _strip_leading_options(tokens: Sequence[str], value_options: Sequence[str]) -> List[str]:
    """Drop leading option tokens (and their values) from a token list."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-") and token != "-":
            if token.split("=", 1)[0] in value_options and "=" not in token:
                index += 2
                continue
            index += 1
            continue
        break
    return list(tokens[index:])


def _strip_env_assignments(tokens: Sequence[str]) -> List[str]:
    """Drop the ``NAME=value`` environment assignments that precede a command.

    ``FOO=1 rm /path`` runs ``rm``; the assignment only sets an environment
    variable for it. Treating the assignment as the command word hides the
    write verb from the resolver entirely.
    """
    index = 0
    while index < len(tokens):
        token = tokens[index]
        name, sep, _value = token.partition("=")
        if not sep or not name or not _ENV_ASSIGNMENT_NAME_RE.match(name):
            break
        index += 1
    return list(tokens[index:])


def _shell_verb(segment: Sequence[str]) -> Tuple[str, List[str]]:
    """The effective command of a segment and its arguments."""
    tokens = list(segment)
    while tokens:
        # An environment assignment may precede the command word, and the
        # command word may itself be a wrapper (``env FOO=1 rm ...``).
        stripped = _strip_env_assignments(tokens)
        if stripped != tokens:
            tokens = stripped
            continue
        base = os.path.basename(tokens[0])
        if base not in _SHELL_WRAPPER_VERBS:
            break
        options = _SHELL_WRAPPER_OPTION_VALUES.get(base, ())
        tokens = _strip_leading_options(tokens[1:], options)
    if not tokens:
        return "", []
    return os.path.basename(tokens[0]), tokens[1:]


def _redirect_destinations(args: Sequence[str]) -> List[str]:
    """The files a command redirects its output into."""
    destinations: List[str] = []
    for index, token in enumerate(args):
        if token not in _SHELL_WRITE_REDIRECTS:
            continue
        if index + 1 >= len(args):
            continue
        target = args[index + 1]
        if target.startswith("&") or target == "-":
            # A file-descriptor duplication, not a file.
            continue
        destinations.append(target)
    return destinations


def _has_sed_inplace(args: Sequence[str]) -> bool:
    for token in args:
        if token in ("--in-place",):
            return True
        if re.match(r"^-i(\..+)?$", token):
            return True
    return False


def _has_perl_inplace(args: Sequence[str]) -> bool:
    for token in args:
        if re.match(r"^-[a-zA-Z]*i(\..+)?$", token):
            return True
    return False


def _sed_files(args: Sequence[str]) -> List[str]:
    """The files ``sed -i`` would rewrite."""
    value_options = _SHELL_OPTION_VALUES["sed"]
    has_script = any(
        token.split("=", 1)[0] in value_options for token in args
    )
    operands = _shell_operands(args, value_options)
    if not has_script and operands:
        # The first operand is the sed script, not a file.
        operands = operands[1:]
    return operands


def _perl_files(args: Sequence[str]) -> List[str]:
    """The files ``perl -i`` would rewrite."""
    value_options = _SHELL_OPTION_VALUES["perl"]
    has_script = any(
        token.split("=", 1)[0] in value_options for token in args
    )
    operands = _shell_operands(args, value_options)
    if not has_script and operands:
        # The first operand is the perl program, not a file.
        operands = operands[1:]
    return operands


def _copy_destinations(verb: str, args: Sequence[str]) -> List[str]:
    """The files a copy/move/link/install command writes to."""
    value_options = _SHELL_OPTION_VALUES.get(verb, ())
    operands: List[str] = []
    target_dir: Optional[str] = None
    creates_dirs = False
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("-") and token != "-":
            base, _, inline = token.partition("=")
            if base in ("-t", "--target-directory"):
                if inline:
                    target_dir = inline
                elif index + 1 < len(args):
                    target_dir = args[index + 1]
                    index += 1
            elif base in value_options and not inline:
                index += 1
            elif base in ("-d", "--directory"):
                creates_dirs = True
            index += 1
            continue
        operands.append(token)
        index += 1

    destinations: List[str] = []
    if verb == "mv":
        # A move removes its source as well as creating the destination.
        destinations.extend(operands[:-1])
    if creates_dirs:
        destinations.extend(operands)
    elif target_dir is not None:
        # A target-directory is itself a write destination. Keep the
        # directory target visible to the existing protected-path policy.
        destinations.append(target_dir)
    elif operands:
        destinations.append(operands[-1])
    return destinations


def _dd_destinations(args: Sequence[str]) -> List[str]:
    """The output file of a ``dd`` command."""
    destinations: List[str] = []
    for token in args:
        if token.startswith("of="):
            destinations.append(token[3:])
    return destinations


def _download_destinations(
    args: Sequence[str], value_options: Sequence[str], attached: str
) -> List[str]:
    """The output file of a download command (``curl`` / ``wget``)."""
    destinations: List[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in value_options:
            if index + 1 < len(args):
                destinations.append(args[index + 1])
                index += 2
                continue
        elif token.split("=", 1)[0] in value_options and "=" in token:
            destinations.append(token.split("=", 1)[1])
        elif token.startswith(attached + "="):
            destinations.append(token[len(attached) + 1 :])
        elif token.startswith(attached) and len(token) > len(attached):
            destinations.append(token[len(attached) :])
        index += 1
    return destinations


def _python_string_vars(code: str) -> Dict[str, str]:
    """Statically resolve ``NAME = 'literal'`` and ``NAME = NAME + 'suffix'``.

    AST parsing is read-only; no snippet code is ever executed (Defect B).
    """
    variables: Dict[str, str] = {}
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return variables

    def const(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return variables.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = const(node.left), const(node.right)
            return left + right if left is not None and right is not None else None
        return None

    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            value = const(node.value)
            if value is not None:
                variables[node.targets[0].id] = value
    return variables


def _python_write_destinations(code: str) -> List[str]:
    """The files a Python snippet writes to (literal paths only)."""
    if not code:
        return []
    destinations: List[str] = []
    variables = _python_string_vars(code)

    # Shell heredoc wrapping Python (nested terminal -> python3 - <<'PY'):
    # analyze the heredoc body as Python itself.
    for hd in re.finditer(r"<<\s*['\"]?(?:PY|EOF|END)['\"]?\s*\n([\s\S]*?)\n(?:PY|EOF|END)\s*$", code):
        body = hd.group(1)
        variables.update(_python_string_vars(body))
        destinations.extend(_python_write_destinations(body))

    def expand(value: str) -> str:
        return variables.get(value.strip(), value)

    def arg_paths(raw: str) -> List[str]:
        """Quoted literals and bare variable names, statically expanded."""
        out: List[str] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            m = re.match(r"^(['\"])(.*)\1$", part)
            if m:
                out.append(expand(m.group(2)))
            else:
                out.append(expand(part))
        return out

    # Defect B: a nested terminal(...) call inside execute_code is itself a
    # shell command. Analyze its body with the shell extractor so a dynamic
    # shutil copy routed through a shell wrapper cannot hide its destination.
    if "terminal(" in code:
        for match in re.finditer(r"terminal\s*\(\s*(?:command\s*=\s*)?", code):
            tail = code[match.end():]
            quote = next((q for q in ('"""', "'''", '"', "'") if tail.startswith(q)), None)
            if quote is None:
                continue
            end = tail.find(quote, len(quote))
            if end < 0:
                continue
            inner = tail[len(quote):end]
            destinations.extend(_shell_write_destinations(inner))
            destinations.extend(_python_write_destinations(inner))

    for match in _PY_OPEN_RE.finditer(code):
        mode = match.group(3)
        if any(char in mode for char in "wax+"):
            destinations.append(match.group(2))

    for match in _PY_PATH_RE.finditer(code):
        destinations.append(match.group(2))

    for match in _PY_OS_RE.finditer(code):
        verb = match.group("verb")
        paths = arg_paths(match.group("args"))
        if verb in ("rename", "replace"):
            destinations.extend(paths)
        elif paths:
            destinations.append(paths[0])

    for match in _PY_SHUTIL_RE.finditer(code):
        verb = match.group("verb")
        paths = arg_paths(match.group("args"))
        if verb in ("rmtree", "move"):
            destinations.extend(paths)
        elif paths:
            destinations.append(paths[-1])

    return destinations


def _python_unresolved_destinations(code: str) -> List[str]:
    """Write destinations that Python computes dynamically (fail closed).

    Covers ``os.environ[...]``, function calls and other non-literal values
    passed to file-writing APIs; no snippet code is executed (Defect B).
    """
    unresolved: List[str] = []
    write_calls = ("open", "rename", "replace", "copy", "copy2", "copyfile",
                   "copytree", "move", "rmtree", "write", "writelines",
                   "write_text", "write_bytes", "unlink", "mkdir")
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return ["unparseable_python_command"]
    variables = _python_string_vars(code)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if name not in write_calls:
            continue
        # Path.write_text(data, path=dest) and shutil.copy(src, dst=dst):
        # keyword arguments can carry the destination too (auditor P2).
        # Path(dst).write_text("x"): the destination sits on the receiver,
        # not in write_text's arguments (auditor P2).
        receiver_dest = None
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            recv_func = node.func.value.func
            recv_name = recv_func.attr if isinstance(recv_func, ast.Attribute) else (
                recv_func.id if isinstance(recv_func, ast.Name) else "")
            if recv_name == "Path" and node.func.value.args:
                receiver_dest = node.func.value.args[0]
        for arg in list(node.args) + [kw.value for kw in node.keywords] + ([receiver_dest] if receiver_dest is not None else []):
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                continue
            if isinstance(arg, ast.Name) and arg.id in variables:
                continue
            unresolved.append(name)
            break
    return _dedupe(unresolved)


def _python_inline_destinations(args: Sequence[str]) -> List[str]:
    """The files written by an inline ``python -c`` program."""
    destinations: List[str] = []
    index = 0
    while index < len(args):
        if args[index] == "-c" and index + 1 < len(args):
            destinations.extend(_python_write_destinations(args[index + 1]))
            index += 2
            continue
        index += 1
    return destinations


def _cd_target(args: Sequence[str], cwd: Optional[str]) -> Optional[str]:
    """The directory a ``cd`` command enters, when that is statically known."""
    operands = _shell_operands(args, ())
    if len(operands) != 1:
        return None
    target = operands[0]
    if target == "-":
        return None
    if any(char in target for char in "*?[]$`\\\"'"):
        # Expansion-dependent: the directory is not statically known.
        return None
    if target.startswith("~"):
        return os.path.expanduser(target)
    if target.startswith("/"):
        return posixpath.normpath(target)
    base = cwd
    if not base:
        # No statically known execution cwd: an absolute cd target is fine,
        # a relative one is not statically resolvable.
        return None
    return posixpath.normpath(posixpath.join(base, target))


def _resolve_relative(path: str, cwd: Optional[str]) -> Tuple[str, bool]:
    """Resolve a relative destination against a statically known directory.

    Returns ``(path, statically_known)``.  When no execution directory is
    known, a relative path is NOT joined to the ambient process cwd: an
    ambient gateway cwd of ``~/.hermes`` would turn ordinary relative writes
    into protected paths (P0-2).  Such a destination is reported as
    unresolvable so the caller can fail closed rather than misclassify.
    """
    if not path:
        return "", False
    if path.startswith(("~",)):
        return os.path.expanduser(path), True
    if path.startswith("/"):
        return posixpath.normpath(path), True
    if cwd:
        return posixpath.normpath(posixpath.join(cwd, path)), True
    return path, False


#: Bounded memo of shell write-destination analyses.
#:
#: ``_shell_write_destinations`` is a *pure* function of
#: ``(command, depth, cwd)``: it reads no mutable module state, no clock
#: and no environment, and its only side effect is appending to the
#: caller's ``unresolved`` list.  The B1 action path analyses the same
#: command twice per tool call -- once through
#: ``extract_exec_write_destinations`` (which keeps the resolved
#: destinations) and once through ``extract_unresolved_write_destinations``
#: (which keeps the unresolved ones) -- and each of the two discards half
#: of the other's result.  Memoizing the analysis therefore removes
#: redundant work, not work: both callers receive exactly the lists the
#: uncached implementation would have produced.
#:
#: The cache is bounded so a long-lived process cannot grow it without
#: limit, and it is keyed on the exact ``(command, depth, cwd)`` triple.
# Cache state lives in _eval_context (ContextVar), never in a module global.


def _shell_write_destinations(
    command: str, depth: int = 0, cwd: Optional[str] = None,
    unresolved: Optional[List[str]] = None,
) -> List[str]:
    """The files a shell command writes to, when statically resolvable.

    ``cwd`` is the execution directory supplied by the caller.  Relative
    destinations are resolved against it; when it is unknown they stay
    relative rather than being joined to the ambient process cwd (P0-2).
    ``unresolved``, when provided, receives every destination whose resolution
    state is False so the policy can apply fail-closed treatment explicitly
    instead of silently relying on a bare relative path (R04).

    Memoized only for the duration of one evaluation: see ``_eval_context``.
    The returned list is shared between callers within that evaluation, so a
    caller MUST NOT mutate it; every caller in this module only reads it or
    extends a copy of it.
    """
    # Evaluation-local only: _cd_target/_resolve_relative call expanduser(),
    # so a command's destinations are a function of the ENVIRONMENT as well as
    # (command, depth, cwd).  A process-global cache can survive a HOME change
    # and return a stale protected path.  One evaluation cannot see a HOME
    # change, so a per-evaluation memo is sound; outside one there is no cache.
    memo = eval_state().setdefault("shell_write", {})
    key = (command, depth, cwd)
    cached = memo.get(key)
    if cached is None:
        collected_unresolved: List[str] = []
        destinations = _shell_write_destinations_uncached(
            command, depth, cwd, collected_unresolved)
        cached = (destinations, collected_unresolved)
        memo[key] = cached
    destinations, memo_unresolved = cached
    if unresolved is not None:
        unresolved.extend(memo_unresolved)
    return destinations


def _shell_write_destinations_uncached(
    command: str, depth: int = 0, cwd: Optional[str] = None,
    unresolved: Optional[List[str]] = None,
) -> List[str]:
    """The files a shell command writes to, when statically resolvable.

    The uncached implementation behind the memoizing ``_shell_write_destinations``
    wrapper.  See that function for the contract.
    """
    tokens = _shell_tokenize(command)
    if not tokens:
        return []

    destinations: List[str] = []
    current_cwd: Optional[str] = cwd
    scope: List[Optional[str]] = []
    segment: List[str] = []
    variables: Dict[str, str] = {}
    # R05: assignments inside a conditional branch or subshell are not
    # guaranteed to hold at the point of a later write. Do not let them
    # resolve destinations as if they were unconditional.
    guarded_names: set = set()
    conditional_depth = 0
    subshell_depth = 0
    guard_next_assignment = False

    def expand(token: str) -> str:
        if "$" not in token:
            return token
        def repl(match: "re.Match[str]") -> str:
            name = match.group(1) or match.group(2)
            if name in guarded_names:
                return match.group(0)
            return variables.get(name, match.group(0))
        return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, token)

    def flush() -> None:
        nonlocal segment, current_cwd, guard_next_assignment
        if not segment:
            return
        # A leading NAME=value assignment defines a shell variable for later
        # segments (``BASE=/tmp; rm -rf "$BASE"``).  Collect it BEFORE verb
        # dispatch so bare assignment segments are not skipped.  Assignments
        # in a conditional branch or subshell are marked guarded (R05).
        for token in segment:
            name, sep, value = token.partition("=")
            if sep and _ENV_ASSIGNMENT_NAME_RE.match(name):
                variables[name] = expand(value)
                if conditional_depth or subshell_depth or guard_next_assignment or segment[0] in ("if", "then", "else", "elif", "while", "until", "for", "case"):
                    guarded_names.add(name)
            if any(t == "&&" for t in segment):
                guard_next_assignment = True
        verb, args = _shell_verb(segment)
        if verb == "cd":
            resolved = _cd_target(args, current_cwd)
            if resolved is not None:
                current_cwd = resolved
        elif verb:
            found = _destinations_for_verb(verb, args, depth)
            found.extend(_redirect_destinations(args))
            expanded_found = [expand(d) for d in found]
            for destination in expanded_found:
                resolved, known = _resolve_relative(destination, current_cwd)
                if not known and unresolved is not None:
                    unresolved.append(resolved)
                if resolved:
                    destinations.append(resolved)
        segment = []

    for token in tokens:
        if token == "(":
            flush()
            scope.append(current_cwd)
            subshell_depth += 1
            # A subshell inherits the current directory, it does not reset it
            # to the ambient process cwd.
            continue
        if token == ")":
            flush()
            current_cwd = scope.pop() if scope else current_cwd
            subshell_depth = max(0, subshell_depth - 1)
            continue
        if token in ("if", "then", "else", "elif", "while", "until", "for", "case"):
            flush()
            conditional_depth += 1
            continue
        if token == "fi":
            flush()
            conditional_depth = max(0, conditional_depth - 1)
            continue
        if token in (";", "&&", "||", "|", "&"):
            if token in ("&&", "||"):
                guard_next_assignment = True
            flush()
            # `&&` guards stay sticky until the next unconditional assignment
            # is consumed; a bare `;` does not prove the branch ran.
            continue
        segment.append(token)
    flush()
    return destinations


#: Commands that change the filesystem. A command from this set that names a
#: protected surface is a write attempt even when its destination cannot be
#: resolved statically.
_SHELL_WRITE_VERBS: Tuple[str, ...] = (
    "tee", "sed", "perl", "cp", "mv", "ln", "install", "rm", "rmdir", "mkdir",
    "touch", "chmod", "chown", "truncate", "dd", "curl", "wget", "tar", "unzip",
    "rsync", "rclone", "scp", "git", "pip", "pip3", "npm", "sponge", "xargs",
    "find", "python", "python2", "python3", "pypy", "sh", "bash", "zsh", "dash",
    "ksh",
)

#: Sub-commands that only read state. A command from this set is not a
#: write attempt, however its verb is named.
_READ_ONLY_SUBCOMMANDS: Dict[str, Tuple[str, ...]] = {
    "git": (
        "status", "log", "diff", "show", "blame", "describe", "rev-parse",
        "ls-files", "ls-remote", "ls-tree", "shortlog", "reflog", "cat-file",
        "grep", "whatchanged", "annotate", "show-ref", "for-each-ref",
    ),
    # ``pip config`` is NOT listed here: only ``pip config list``/``get``
    # read; ``pip config set``/``unset`` mutate a configuration file.
    "pip": ("download", "list", "show", "freeze", "inspect"),
    "pip3": ("download", "list", "show", "freeze", "inspect"),
    "npm": ("view", "ls", "list", "outdated", "audit", "ping", "whoami"),
    "tar": (),
}

#: Option values for the verbs above, so an option's argument is never
#: mistaken for a path.
_SHELL_WRITE_VERB_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "mkdir": ("-m", "--mode"),
    "touch": ("-d", "--date", "-t", "--time", "-r", "--reference"),
    "chmod": ("--reference",),
    "chown": ("--reference",),
    "rsync": (
        "--temp-dir", "--backup-dir", "--rsync-path", "--exclude", "--include",
        "--filter", "--out-format", "--log-file", "--copy-links", "--chown",
        "--chmod", "--timeout", "--bwlimit", "--port", "--rsh", "--exclude-from",
        "--include-from", "--filter-merge",
    ),
    "rclone": ("--config", "--log-file", "--temp-dir", "--backup-dir", "--drive", "--transfers"),
    "scp": ("-P", "-i", "-F", "-c", "-l", "-o", "-S", "-J"),
    "git": ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"),
    "pip": ("--target", "-t", "--prefix", "--root", "--cache-dir", "--log", "--index-url"),
    "npm": ("--prefix", "--cache", "--registry", "--loglevel", "--workspace"),
}


def _is_read_only_invocation(verb: str, args: Sequence[str]) -> bool:
    """Whether *verb* with *args* only reads state.

    Some verbs are only mutating in some of their modes: ``tar -t`` lists,
    ``unzip -l`` lists, ``git status`` reads. Such an invocation is not a
    write attempt.
    """
    if verb == "tar":
        return any(
            "t" in token.lstrip("-")
            for token in args
            if re.fullmatch(r"-{0,2}[a-zA-Z]{1,4}", token)
            and set(token.lstrip("-")) <= set("xtcvzfjhkmOPW")
        )
    if verb == "unzip":
        return any(token in ("-l", "--list") for token in args)
    if verb == "find":
        return not any(
            token in (
                "-exec", "-execdir", "-ok", "-okdir", "-delete",
                # These three write their result into a file.
                "-fprint", "-fprintf", "-fls",
            )
            for token in args
        )
    positional = [token for token in args if not token.startswith("-")]
    if verb == "git":
        # ``git worktree list`` only reads the worktree registry.
        if len(positional) >= 2 and positional[0] == "worktree" and positional[1] == "list":
            return True
        # ``git diff --output=FILE`` writes FILE: it is not a read.
        if _git_output_file(args) and _git_subcommand(args) in _GIT_OUTPUT_SUBCOMMANDS:
            return False
    if verb in ("pip", "pip3", "npm"):
        # ``pip config list``/``get`` read; ``pip config set``/``unset`` write.
        if positional and positional[0] == "config":
            action = positional[1] if len(positional) > 1 else ""
            return action in ("", "list", "get")
    read_only = _READ_ONLY_SUBCOMMANDS.get(verb)
    if not read_only:
        return False
    for token in args:
        if token.startswith("-"):
            continue
        return token in read_only
    return False


def _mode_operands(args: Sequence[str], value_options: Sequence[str]) -> List[str]:
    """The files a ``chmod``/``chown`` command acts on.

    The first operand is the mode or the owner, not a path.
    """
    operands = _shell_operands(args, value_options)
    if operands and not os.path.sep in operands[0]:
        head = operands[0]
        if re.fullmatch(r"[0-7]{1,4}", head) or re.fullmatch(
            r"[ugoa]*[-+=][rwxXst]*", head
        ) or ":" in head:
            operands = operands[1:]
    return operands


def _verb_options(verb: str) -> Tuple[str, ...]:
    """The option values of *verb* (its own options plus the write verbs)."""
    return tuple(_SHELL_OPTION_VALUES.get(verb, ())) + tuple(
        _SHELL_WRITE_VERB_OPTIONS.get(verb, ())
    )


def _shell_segments(command: str) -> List[List[str]]:
    """The individual command segments of a shell command line."""
    segments: List[List[str]] = []
    current: List[str] = []
    for token in _shell_tokenize(command):
        if token in (";", "&&", "||", "|", "&"):
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _sync_destinations(verb: str, args: Sequence[str]) -> List[str]:
    """The paths a copy-style command (``rsync`` / ``rclone`` / ``scp``) changes.

    Sources come first and the destination comes last, so the last operand
    is what is written. A remote target (``host:path``) is not a local path
    and is left to the shell.

    Some of these commands also REMOVE their source after a successful
    transfer: ``rclone move`` deletes the source it moved, and
    ``rsync --remove-source-files`` deletes every source file it
    transferred. A removed source is a mutation of that path, so it is
    reported next to the destination.
    """
    operands = _shell_operands(args, _verb_options(verb))
    if not operands:
        return []
    destinations: List[str] = []
    destinations.extend(_sync_removed_sources(verb, args, operands))
    destination = operands[-1]
    if ":" in destination and not destination.startswith("/"):
        return destinations
    destinations.append(destination)
    return destinations


def _sync_removed_sources(
    verb: str, args: Sequence[str], operands: Sequence[str]
) -> List[str]:
    """The sources a copy-style command deletes after the transfer.

    ``rclone move SOURCE DEST`` moves (and therefore removes) its source,
    and ``rsync --remove-source-files`` deletes every source file it
    transferred. Only local paths are reported: a remote source
    (``host:path``) names another machine's filesystem.
    """
    removed: List[str] = []
    if verb == "rclone":
        # ``rclone move SOURCE DEST`` and ``rclone moveto SOURCE DEST`` -
        # the source is deleted afterwards (rclone moves the files and then
        # removes the originals from the source).
        if len(operands) >= 3 and operands[0] in ("move", "moveto"):
            removed.append(operands[-2])
    elif verb == "rsync":
        if "--remove-source-files" in args and len(operands) >= 2:
            removed.extend(operands[:-1])
    return [
        token
        for token in removed
        if token and not (":" in token and not token.startswith("/"))
    ]


def _tar_destinations(args: Sequence[str]) -> List[str]:
    """The paths a ``tar`` command writes to.

    An extraction writes into the directory named with ``-C``; a creation
    writes the archive named with ``-f``. Without either, the target is the
    working directory, which is not statically known - nothing is claimed.
    """
    extract_dir = ""
    archive = ""
    modes = ""
    index = 0
    while index < len(args):
        token = args[index]
        if token in ("-C", "--directory"):
            if index + 1 < len(args):
                extract_dir = args[index + 1]
                index += 1
        elif token.startswith("--directory="):
            extract_dir = token.split("=", 1)[1]
        elif token in ("-f", "--file"):
            if index + 1 < len(args):
                archive = args[index + 1]
                index += 1
        elif token.startswith("--file="):
            archive = token.split("=", 1)[1]
        elif token.startswith("--"):
            if token in ("--extract", "--get"):
                modes += "x"
            elif token in ("--create", "--get-file"):
                modes += "c"
        elif re.fullmatch(r"-{0,2}[a-zA-Z]{1,4}", token) and (
            set(token.lstrip("-")) <= set("xtcvzfjhkmOPW")
            and any(letter in token for letter in "xtc")
        ):
            # A combined flag word: ``tar xzf archive.tgz`` or ``tar -xzf``.
            letters = token.lstrip("-")
            if "t" in letters:
                modes += "t"
            else:
                if "x" in letters:
                    modes += "x"
                if "c" in letters:
                    modes += "c"
            if "f" in letters and not archive and index + 1 < len(args):
                if not args[index + 1].startswith("-"):
                    archive = args[index + 1]
                    index += 1
        index += 1
    if "t" in modes:
        # ``tar -t`` only lists an archive: it writes nothing.
        return []
    if "x" in modes:
        return [extract_dir] if extract_dir else []
    return [archive] if archive else []


def _unzip_destinations(args: Sequence[str]) -> List[str]:
    """The directory an ``unzip`` extracts into (``-d``).

    ``unzip -l`` only lists the archive contents and writes nothing.
    """
    if any(token in ("-l", "--list") for token in args):
        return []
    index = 0
    while index < len(args):
        token = args[index]
        if token in ("-d", "--dir", "--directory"):
            if index + 1 < len(args):
                return [args[index + 1]]
        elif token.startswith("--dir=") or token.startswith("--directory="):
            return [token.split("=", 1)[1]]
        index += 1
    return []


#: Options of ``git`` (and ``git worktree``) that take a value, so the
#: value is never mistaken for a path operand.
_GIT_VALUE_OPTIONS: Tuple[str, ...] = ("-b", "--branch", "--reason")


def _git_value_options() -> Tuple[str, ...]:
    return tuple(_verb_options("git")) + _GIT_VALUE_OPTIONS


#: Git sub-commands whose ``--output`` option writes into a file.
#:
#: Verified empirically against git (isolated temporary repository): for
#: every sub-command listed here git accepts ``--output FILE`` and creates
#: that file. For the remaining sub-commands (``status``, ``grep``,
#: ``describe``, ``ls-files``, ``cat-file``, ``show-ref``,
#: ``for-each-ref``, ``ls-tree``, ``rev-parse``) git rejects the option
#: with "unknown option `output'" and no file is created, so they stay
#: read-only.
_GIT_OUTPUT_SUBCOMMANDS: Tuple[str, ...] = (
    "diff", "log", "show", "format-patch", "archive", "rev-list",
    "shortlog", "blame", "annotate", "reflog", "whatchanged",
)


def _git_operands(args: Sequence[str]) -> List[str]:
    """The non-option operands of a ``git`` command."""
    operands: List[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in _git_value_options():
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        operands.append(token)
        index += 1
    return operands


def _git_subcommand(args: Sequence[str]) -> str:
    """The effective sub-command of a ``git`` command."""
    operands = _git_operands(args)
    return operands[0] if operands else ""


def _git_output_file(args: Sequence[str]) -> str:
    """The file a ``git`` command writes its result into (``--output``)."""
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            # Everything after the separator is a pathspec, not an option.
            break
        if token.startswith("--output="):
            return token.split("=", 1)[1]
        if token == "--output" and index + 1 < len(args):
            return args[index + 1]
        index += 1
    return ""


def _git_destinations(args: Sequence[str]) -> List[str]:
    """The paths a ``git`` command writes to."""
    operands = _git_operands(args)
    output = _git_output_file(args)
    destinations: List[str] = []
    if output and _git_subcommand(args) in _GIT_OUTPUT_SUBCOMMANDS:
        destinations.append(output)
    if not operands:
        return destinations
    subcommand = operands[0]
    rest = operands[1:]
    if subcommand == "worktree":
        # ``git worktree add PATH [BRANCH]`` writes into PATH; the action
        # word is not a path and must never be resolved as one.
        action = rest[0] if rest else ""
        if action in ("add", "remove"):
            destinations.extend(rest[1:2])
            return destinations
        if action == "move":
            # ``git worktree move SRC DST`` removes the worktree at SRC and
            # creates it at DST: both paths are mutated.
            destinations.extend(rest[1:3])
            return destinations
        # ``list``/``prune``/``lock``/``unlock`` name no worktree path.
        return destinations
    if subcommand == "clone":
        # ``git clone URL [DIR]`` writes into DIR; a single operand means the
        # working directory, which is not statically known.
        destinations.extend(rest[-1:] if len(rest) >= 2 else [])
        return destinations
    if subcommand == "init":
        # ``git init [DIR]`` writes into DIR; without one, the working
        # directory, which is not statically known.
        destinations.extend(rest[-1:])
        return destinations
    return destinations


def _pip_destinations(args: Sequence[str]) -> List[str]:
    """The directory a package installer writes into (``--target``/``--prefix``)."""
    index = 0
    while index < len(args):
        token = args[index]
        if token in ("--target", "-t", "--prefix", "--root"):
            if index + 1 < len(args):
                return [args[index + 1]]
        elif token.startswith("--target=") or token.startswith("--prefix="):
            return [token.split("=", 1)[1]]
        index += 1
    return []


def _xargs_destinations(args: Sequence[str]) -> List[str]:
    """The destinations of the command an ``xargs`` runs."""
    value_options = ("-I", "-i", "-P", "-n", "-L", "-s", "-a", "-d", "-E")
    index = 0
    remainder: List[str] = []
    while index < len(args):
        token = args[index]
        if token in value_options:
            index += 2
            continue
        if token.startswith("-") and len(token) > 1:
            index += 1
            continue
        remainder = list(args[index:])
        break
    # A redirection ends the wrapped command: what follows it belongs to
    # the outer shell, not to the command xargs runs.
    wrapped: List[str] = []
    for token in remainder:
        if token in _SHELL_WRITE_REDIRECTS or token in ("<", "<<"):
            break
        wrapped.append(token)
    if not wrapped:
        return []
    return _shell_write_destinations(" ".join(wrapped), 1)


def _find_destinations(args: Sequence[str]) -> List[str]:
    """The files a ``find`` command writes to.

    ``-fprint FILE``/``-fprintf FILE FORMAT``/``-fls FILE`` write their
    result into FILE, and ``-exec``/``-execdir``/``-ok``/``-okdir`` run a
    command whose own destinations are the write targets.
    """
    destinations: List[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in ("-fprint", "-fprintf", "-fls"):
            if index + 1 < len(args):
                destinations.append(args[index + 1])
            index += 2
            continue
        if token in ("-exec", "-execdir", "-ok", "-okdir"):
            remainder: List[str] = []
            cursor = index + 1
            while cursor < len(args) and args[cursor] not in (";", "+"):
                remainder.append(args[cursor])
                cursor += 1
            if remainder:
                destinations.extend(_shell_write_destinations(" ".join(remainder), 1))
            # Continue after the terminator: a later ``-fprint`` still
            # writes its file.
            index = cursor + 1
            continue
        index += 1
    return destinations


def _segment_has_write_intent(segment: Sequence[str]) -> bool:
    """Whether one command segment attempts a write."""
    verb, args = _shell_verb(segment)
    if not verb:
        return False
    if verb not in _SHELL_WRITE_VERBS:
        return False
    return not _is_read_only_invocation(verb, args)


#: Verbs whose destination cannot always be resolved statically. Only for
#: these may a protected path that is named as an operand escalate a command
#: whose destination the resolver could not pin down.
_AMBIGUOUS_DEST_VERBS: Tuple[str, ...] = (
    "tar", "unzip", "xargs", "find", "rsync", "rclone", "scp", "git", "pip",
    "pip3", "npm", "sponge", "sh", "bash", "zsh", "dash", "ksh",
)


def _ambiguous_protected_write(
    tool_name: str, args: Any, cwd: Optional[str] = None
) -> Optional[str]:
    """A protected path a mutating command names but cannot attribute.

    Some writes cannot be resolved to a destination: an unknown option, a
    wrapped command, an environment-dependent path. When such a command
    names a protected surface as one of its operands, the write cannot be
    shown to be harmless, so it is escalated to the operator's gate instead
    of being allowed silently.

    A path that is only *mentioned* - as the source of a copy, or as an
    argument of an interpreter - is not a write attempt and stays allowed.
    Relative operands are resolved against *cwd* when it is known; they are
    never silently joined to the ambient process cwd (P0-2).
    """
    for text, is_python in _exec_texts(tool_name, args):
        if is_python:
            continue
        segments = _shell_segments(text)
        if not segments:
            continue
        if any(t == "__PF_UNPARSEABLE__" for segment in segments for t in segment):
            # Tokenizer could not parse the command: never allow silently.
            return "unparseable_shell_command"
        # Track simple NAME=value assignments so ``BASE=/tmp; tar ... "$BASE"``
        # is classified by its actual target.
        variables: Dict[str, str] = {}
        guarded_names: set = set()

        def expand(token: str) -> str:
            if "$" not in token:
                return token
            def repl(match: "re.Match[str]") -> str:
                name = match.group(1) or match.group(2)
                if name in guarded_names:
                    return match.group(0)
                return variables.get(name, match.group(0))
            return re.sub(
                r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                repl, token,
            )

        subshell_depth = 0
        conditional_depth = 0
        for segment in segments:
            head = segment[0] if segment else ""
            if head in ("(", ")"):
                subshell_depth += 1 if head == "(" else -1
                subshell_depth = max(0, subshell_depth)
            if head in ("if", "then", "else", "elif", "while", "until", "for", "case"):
                conditional_depth += 1
            for token in segment:
                name, sep, value = token.partition("=")
                if sep and _ENV_ASSIGNMENT_NAME_RE.match(name):
                    variables[name] = expand(value)
                    if conditional_depth or subshell_depth or head in ("then", "else", "elif") or "&&" in segment:
                        guarded_names.add(name)
            verb, verb_args = _shell_verb(segment)
            if not verb or verb not in _AMBIGUOUS_DEST_VERBS:
                continue
            if not _segment_has_write_intent(segment):
                continue
            # A segment that resolves its OWN destination is not ambiguous:
            # the write can be attributed and is judged on its target. The
            # check is per segment, so a benign resolved write elsewhere in
            # the same command cannot mask an unverifiable protected write.
            if _segment_destinations(segment):
                continue
            for operand in _shell_operands(verb_args, _verb_options(verb)):
                resolved_operand = expand(operand)
                if not _looks_like_path(resolved_operand):
                    continue
                if not resolved_operand.startswith(("/", "~")) and not cwd:
                    # Without a known execution cwd, a relative operand cannot
                    # be classified as a protected path. Do NOT resolve it
                    # against the ambient gateway directory.
                    continue
                checked = normalize_path(resolved_operand, cwd)
                if is_protected_path(checked) or is_control_plane_path(checked):
                    return operand
    return None


def _looks_like_path(token: str) -> bool:
    """Whether *token* looks like a filesystem path rather than a word.

    A bare word such as ``worktree`` or ``add`` is a command argument, not
    a path: resolving it against the working directory would turn any
    sub-command into a spurious write target. A URL is not a path either -
    a package index or a remote endpoint names a value, not a local file.
    """
    if not token:
        return False
    if "://" in token:
        return False
    if token.startswith(("/", "~")):
        return True
    if os.path.sep not in token:
        return False
    head = token.split(os.path.sep, 1)[0]
    if head in (".", ".."):
        return True
    # A first segment that carries a dot is a host name, not a directory:
    # ``example.invalid/x`` is a remote location, not a local file.
    return "." not in head


def _segment_destinations(segment: Sequence[str], depth: int = 0) -> List[str]:
    """The destinations of a single command segment."""
    verb, args = _shell_verb(segment)
    if not verb:
        return []
    found = _destinations_for_verb(verb, args, depth)
    found.extend(_redirect_destinations(args))
    return found


def _destinations_for_verb(
    verb: str, args: Sequence[str], depth: int
) -> List[str]:
    """The files a single command writes to."""
    if verb == "tee":
        return _shell_operands(args, ())
    if verb == "sed":
        return _sed_files(args) if _has_sed_inplace(args) else []
    if verb == "perl":
        return _perl_files(args) if _has_perl_inplace(args) else []
    if verb in ("cp", "mv", "ln", "install"):
        return _copy_destinations(verb, args)
    if verb == "rm":
        return _shell_operands(args, ())
    if verb == "truncate":
        return _shell_operands(args, _SHELL_OPTION_VALUES["truncate"])
    if verb == "dd":
        return _dd_destinations(args)
    if verb == "curl":
        return _download_destinations(args, ("-o", "--output"), "-o")
    if verb == "wget":
        return _download_destinations(
            args, ("-O", "--output-document", "--output-file"), "-O"
        )
    if verb in ("rsync", "rclone", "scp"):
        return _sync_destinations(verb, args)
    if verb == "tar":
        return _tar_destinations(args)
    if verb == "unzip":
        return _unzip_destinations(args)
    if verb == "git":
        return _git_destinations(args)
    if verb in ("pip", "pip3"):
        return _pip_destinations(args)
    if verb == "npm":
        return _pip_destinations(args)
    if verb == "sponge":
        return _shell_operands(args, _verb_options(verb))
    if verb == "xargs":
        return _xargs_destinations(args)
    if verb == "find":
        return _find_destinations(args)
    if verb in ("mkdir", "touch"):
        return _shell_operands(args, _verb_options(verb))
    if verb in ("chmod", "chown"):
        return _mode_operands(args, _verb_options(verb))
    if verb in ("python", "python2", "python3", "pypy"):
        return _python_inline_destinations(args)
    if verb in ("sh", "bash", "zsh", "dash", "ksh"):
        if depth >= 2:
            return []
        index = 0
        found: List[str] = []
        while index < len(args):
            if args[index] == "-c" and index + 1 < len(args):
                found.extend(_shell_write_destinations(args[index + 1], depth + 1))
                index += 2
                continue
            index += 1
        return found
    return []


def _exec_texts(tool_name: str, args: Any) -> List[Tuple[str, bool]]:
    """The (text, is_python) pairs describing what a call would execute."""
    if not isinstance(args, dict):
        return []
    name = (tool_name or "").lower()
    texts: List[Tuple[str, bool]] = []

    def take(keys: Sequence[str], is_python: bool) -> bool:
        for key in keys:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                texts.append((value, is_python))
                return True
        return False

    if name in _PYTHON_EXEC_TOOLS:
        take(("code", "script", "source", "program", "input", "command"), True)
        return texts
    if name in _SHELL_EXEC_TOOLS:
        take(("command", "cmd", "script", "shell", "program", "input"), False)
        return texts
    # An unrecognized tool: only an explicit command or code payload is
    # inspected. Nothing is inferred from the tool's name.
    take(("command", "cmd", "shell"), False)
    take(("script",), False)
    take(("script",), True)
    take(("code", "source"), True)
    return texts


def extract_exec_write_destinations(tool_name: str, args: Any, cwd: Optional[str] = None) -> List[str]:
    """The files an executable call writes to, when statically resolvable.

    Covers shell redirection, in-place editors, copy/move/link/install,
    ``tee``, downloads, explicit Python writes and - where the working
    directory is statically known - relative destinations.

    ``cwd`` is the execution directory supplied by the caller. Relative
    destinations are resolved against it, never against the ambient process
    cwd (P0-2).
    """
    destinations: List[str] = []
    unresolved: List[str] = []
    for text, is_python in _exec_texts(tool_name, args):
        if is_python:
            destinations.extend(_python_write_destinations(text))
        else:
            destinations.extend(_shell_write_destinations(text, cwd=cwd, unresolved=unresolved))
    return _dedupe(destinations)


def extract_unresolved_write_destinations(
    tool_name: str, args: Any, cwd: Optional[str] = None
) -> List[str]:
    """Shell destinations that could not be resolved to a known directory.

    R04: the resolution-state boolean from ``_resolve_relative`` must reach
    policy.  Callers can fail closed on these paths instead of treating a
    bare relative string as if it were a resolved absolute path.
    """
    unresolved: List[str] = []
    for text, is_python in _exec_texts(tool_name, args):
        if is_python:
            unresolved.extend(_python_unresolved_destinations(text))
            continue
        _shell_write_destinations(text, cwd=cwd, unresolved=unresolved)
    return _dedupe(unresolved)


def extract_call_cwd(args: Any) -> Optional[str]:
    """Best-effort extraction of a tool call's execution cwd.

    Terminal tools may carry an explicit ``workdir`` or ``cwd`` argument.
    An empty or non-string value yields no cwd, so relative paths stay
    unresolved rather than being attributed to the ambient gateway cwd.
    """
    if not isinstance(args, dict):
        return None
    for key in ("workdir", "cwd", "command_cwd", "execution_cwd"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def extract_shell_write_targets(command: str) -> List[str]:
    """Extract the files a shell command *writes* to (PF-03 / Stage 2A).

    Read-only commands (``cat``, ``ls``, ``grep``) contribute nothing; only
    the write verbs and the redirection operators are considered, and only
    destinations that are statically resolvable are reported.
    """
    if not command:
        return []
    return _dedupe(_shell_write_destinations(command))


def extract_target_paths(tool_name: str, args: Any) -> List[str]:
    """Best-effort extraction of the filesystem paths a tool call targets.

    The walk is recursive and covers nested operation objects, so a payload
    such as ``{"operations": [{"path": "..."}]}`` is no longer invisible
    (PF-03).
    """
    paths: List[str] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _PATH_KEYS:
                    if isinstance(value, str) and value.strip():
                        paths.append(value)
                    elif isinstance(value, (list, tuple)):
                        paths.extend(v for v in value if isinstance(v, str) and v.strip())
                elif isinstance(value, (dict, list, tuple)):
                    walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, depth + 1)

    if isinstance(args, dict):
        walk(args)
    paths.extend(extract_patch_targets(args))
    return _dedupe(paths)


def extract_command_text(tool_name: str, args: Any) -> str:
    """The command/script body of an executable tool call, if any."""
    if not isinstance(args, dict):
        return _arg_text(args)
    for key in ("command", "cmd", "script", "code", "shell", "input", "program"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _paths_mentioned_in_command(command: str) -> List[str]:
    """Extract path-like tokens from a shell command for protected checks."""
    if not command:
        return []
    out: List[str] = []
    for match in re.finditer(r"(?:^|[\s'\"=;|&(])(~?/[\w./\-]+|~?\.[\w./\-]+)", command):
        token = match.group(1)
        if len(token) > 2 and "/" in token:
            out.append(token)
    return out


# --------------------------------------------------------------------------- #
# Verdict model
# --------------------------------------------------------------------------- #


@dataclass
class Verdict:
    """Outcome of the action-boundary evaluation."""

    action: str = "allow"  # "allow" | "block" | "quarantine" | "approve"
    reason: str = ""
    detail: str = ""
    findings: Tuple[Finding, ...] = ()
    #: Grain of the native approval rule (used when action == "approve").
    rule_key: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def needs_approval(self) -> bool:
        return self.action == "approve"


# --------------------------------------------------------------------------- #
# The action boundary
# --------------------------------------------------------------------------- #


def _first_finding(findings: Sequence[Finding], categories: Iterable[str]) -> Optional[Finding]:
    wanted = set(categories)
    for finding in findings:
        if finding.category in wanted:
            return finding
    return None


#: Categories that make an *action* unsafe regardless of the target.
ACTION_BLOCKING_CATEGORIES = (
    CATEGORY_INSTRUCTION_OVERRIDE,
    CATEGORY_ROLE_SPOOF,
    CATEGORY_PERSISTENT_PROMPT,
    CATEGORY_SECURITY_DISABLE,
    CATEGORY_GATEWAY_REDIRECT,
    CATEGORY_ENCODED_PAYLOAD,
)


#: Argument keys that carry a payload a mutating tool would write out.
_WRITE_PAYLOAD_KEYS: Tuple[str, ...] = (
    "content",
    "text",
    "body",
    "data",
    "output",
    "new_string",
    "new_text",
    "new_value",
    "replacement",
    "patch_text",
    "patch",
    "diff",
    "unified_diff",
    "changes",
)

# ``edit_file`` / ``multi_edit`` carry the *result* of the edit in
# ``new_text`` / ``new_string``; ``old_text`` is only the selector being
# replaced.  A deletion expresses its intent through ``old_text`` (the text
# that must disappear) with an empty ``new_text``, so the selector is
# collected as well - otherwise removing the firewall's own config entry is
# invisible to the state gate and returns ``allow`` (PF-02).
_EDIT_PAYLOAD_KEYS: Tuple[str, ...] = _WRITE_PAYLOAD_KEYS + ("old_text",)

# Tools whose payload shape is ``old_text`` / ``new_text`` rather than a
# single ``content`` blob.  Only these collect the selector.
_EDIT_TOOLS: Tuple[str, ...] = ("edit_file", "multi_edit", "str_replace", "patch")


def _write_payload_text(args: Any, include_selectors: bool = False) -> str:
    """The payload a mutating tool call would place on disk (best effort).

    The payload may sit at the top level (``write_file``) or inside a
    per-edit object (``multi_edit``). Both shapes reach the same bytes on
    disk, so both are collected: a nested payload that names the firewall's
    own state must not be invisible to the state gate (PF-02).

    *include_selectors* adds ``old_text`` to the collected keys.  It is used
    for edit-shaped tools, where a deletion carries its intent in the
    selector (``old_text``) and an empty ``new_text``.
    """
    if isinstance(args, str):
        return args
    if not isinstance(args, dict):
        return ""
    keys = _EDIT_PAYLOAD_KEYS if include_selectors else _WRITE_PAYLOAD_KEYS
    parts: List[str] = []
    for key in keys:
        value = args.get(key)
        if isinstance(value, str):
            parts.append(value)
    # ``multi_edit`` carries its payload under ``edits`` / ``changes`` as a
    # list of per-file objects. The top-level loop above cannot see it.
    for carrier in ("edits", "changes", "files"):
        value = args.get(carrier)
        if not isinstance(value, (list, tuple)):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            for key in keys:
                nested = item.get(key)
                if isinstance(nested, str):
                    parts.append(nested)
    return "\n".join(parts)


def is_firewall_state_surface(raw_path: str) -> bool:
    """True when the *content* of *raw_path* controls this firewall's state.

    That is the active Hermes home's ``config.yaml`` / ``config.yml`` and
    every file inside this firewall's own plugin directory (PF-02).
    """
    path = normalize_path(raw_path)
    if not path:
        return False
    if is_firewall_own_path(path):
        return True
    if posixpath.basename(path) not in ("config.yaml", "config.yml"):
        return False
    return is_control_plane_path(path)


def call_provenance(tool_name: str, args: Any, findings: Sequence[Finding] = ()) -> str:
    """Best-effort provenance of a tool call.

    The plugin API surface carries no operator token, so a call can never be
    *proven* to originate from the operator. The only honest outcomes are
    therefore:

    * ``PROVENANCE_UNTRUSTED_CONTENT`` — the payload carries an injection
      signature, i.e. the action was shaped by content that arrived
      through a tool;
    * ``PROVENANCE_UNKNOWN`` — nothing establishes the origin.

    ``PROVENANCE_TRUSTED_OPERATOR`` is never returned here: unknown
    provenance is not trusted (PF-10).
    """
    for finding in findings:
        if getattr(finding, "severity", "") == "high":
            return PROVENANCE_UNTRUSTED_CONTENT
    return PROVENANCE_UNKNOWN


def _observe_only(tool_name: str) -> bool:
    """True when the tool can only *observe* (read, search, research).

    Such a tool cannot switch a control off: its arguments name an action
    instead of performing one (PF-12).
    """
    name = (tool_name or "").lower()
    return name in OBSERVE_ONLY_TOOLS or name in RESEARCH_TOOLS


def _carries_a_control(raw_path: str) -> bool:
    """True when the file at *raw_path* actually holds a control."""
    return (
        is_protected_path(raw_path)
        or is_control_plane_path(raw_path)
        or is_instruction_path(raw_path)
        or is_skill_path(raw_path)
        or is_firewall_state_surface(raw_path)
    )


# --------------------------------------------------------------------------- #
# G1 destination gate (scanner-independent)
#
# Rationale (see gates/P0_APPROVE_SEMANTICS.md): an ``approve`` verdict is NOT
# an authorization guarantee. In yolo / approvals-off / allowlisted /
# cron-approve / single-query-approve / unattended-approve contexts Hermes Core
# auto-approves it with no human in the loop, so for the G1 invariant ("an
# undetected prompt injection must not cause an unauthorized protected-state
# mutation") an ``approve`` on these surfaces is equivalent to ``allow``.
#
# The destinations below are *durable instruction, credential, or control-plane
# surfaces*: a write to one of them is exactly the persistent compromise an
# undetected injection would aim for, and the operator cannot have pre-authorized
# the specific content (no trusted provenance signal reaches the hook). They are
# therefore refused outright from ``(tool_name, args, destination)`` alone -
# never from content - so the refusal survives a total scanner false-negative.
#
# Ordinary protected writes (e.g. a ``.bashrc`` alias) are NOT in this set: they
# stay escalated to ``approve``, which is the correct operator gate for a write
# that is not inherently a durable-instruction/credential mutation.
# --------------------------------------------------------------------------- #

#: Reason keys the destination gate can return. Kept as constants so the
#: verdict matrix and tests can assert on them without string drift.
GATE_REASON_INSTRUCTION_SURFACE = "destination_instruction_surface_write"
GATE_REASON_CREDENTIAL = "credential_path_write"  # reused existing reason
GATE_REASON_CONTROL_PLANE = "destination_control_plane_write"
GATE_REASON_MEMORY = "destination_memory_durable_write"
GATE_REASON_SKILL = "destination_skill_durable_write"


def is_durable_instruction_surface(raw_path: str) -> bool:
    """True for a path whose *content* becomes a standing instruction for a
    future agent turn: the instruction files (``AGENTS.md`` and siblings) and
    Skill files.

    These are the paths an undetected injection most wants to write, and the
    paths where "the operator approved it" cannot be established from inside
    the plugin. The firewall's own ``config.yaml`` is deliberately NOT in this
    set: it is the operator's own configuration file, which the operator
    legitimately edits, so an ordinary write to it stays on the ``approve``
    operator gate. The dangerous case - a write that switches the firewall off
    or removes its entry - is caught separately in section 4b by a *content*
    discriminator (``config_firewall_state_mutation``), not by destination, and
    is blocked there.
    """
    return (
        is_instruction_path(raw_path)
        or is_skill_path(raw_path)
    )


def _is_read_operation(tool_name: str) -> bool:
    """True when the call can only *read* the path it names (PF-13).

    A read never mutates the file it points at, so a protected or
    credential path reached through such a tool is a read, not a write.
    The distinction is made by the tool's own semantics, not by the mere
    presence of a sensitive path in the arguments.
    """
    return (tool_name or "").lower() in OBSERVE_ONLY_TOOLS


def _disables_firewall_plugin(command: str) -> bool:
    """True when a plugin-management command switches prompt-firewall off.

    The firewall protects its own plugin. A command that disables some other
    plugin leaves the firewall running, so it is not this firewall's business:
    the block and the message that describes it must cover the same scope.
    """
    low = (command or "").lower()
    if not re.search(r"\bhermes\s+plugins\s+disable(?:\s+-y)?\b", low):
        return False
    return FIREWALL_PLUGIN_NAME in low


def _is_real_control_disable(tool_name: str, targets: Sequence[str], content: str = "") -> bool:
    """True when this call would really switch a security control off."""
    name = (tool_name or "").lower()
    if name in EXEC_TOOLS:
        if _disables_firewall_plugin(content):
            return True
        return True
    if _observe_only(name):
        return False
    if name in WRITE_TOOLS or name in SKILL_TOOLS:
        return any(_carries_a_control(t) for t in targets)
    return True



def _has_exec_payload(args: Any) -> bool:
    """True when an unrecognized tool carries a command or code payload.

    An unknown tool that carries no such payload cannot be recognized as an
    executable one, so it is left to the ordinary protected-write rules.
    """
    if not isinstance(args, dict):
        return False
    for key in ("command", "cmd", "script", "code", "shell", "program"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return True
    return False


def _scoped_operation_actions(tool_name: str, args: Any) -> List[str]:
    """The operation actions a scoped tool call actually carries.

    ``memory`` accepts the batch shape (``operations``) and the legacy
    single-op shape (a top-level ``action``), so both are collected. The
    batch form is the *carrier* of the nested operations, not an operation
    of its own: the nested actions are what is classified. The result is a
    list of lower-cased action strings - possibly empty, which means the
    call names no operation at all.
    """
    name = (tool_name or "").lower()
    if not isinstance(args, dict):
        return []
    actions: List[str] = []
    if name == "memory":
        operations = args.get("operations")
        if isinstance(operations, (list, tuple)) and operations:
            # The batch form: the nested operations are what the tool
            # applies. A top-level action alongside them is ignored by the
            # tool, so it is not classified here either.
            for op in operations:
                if isinstance(op, dict):
                    action = op.get("action")
                    if isinstance(action, str) and action.strip():
                        actions.append(action.strip().lower())
            return actions
        top = args.get("action")
        if isinstance(top, str) and top.strip():
            actions.append(top.strip().lower())
    elif name == "cronjob_manage":
        action = args.get("action")
        if isinstance(action, str) and action.strip():
            actions.append(action.strip().lower())
    return actions


def classify_scoped_operation(tool_name: str, args: Any) -> Tuple[str, str]:
    """Classify a scoped tool call by the operation it actually performs.

    Returns ``(kind, detail)`` where *kind* is one of:

    * ``OP_READ`` - the call cannot change durable state;
    * ``OP_MUTATE`` - the call writes durable state;
    * ``OP_UNVERIFIED`` - the call names an operation this plugin does not
      recognize, so its effect cannot be established.

    The tool *name* never decides the class. ``memory`` and
    ``cronjob_manage`` each carry both reads and writes, and an
    unrecognized operation is reported as unverified rather than being
    waved through as a read (fail closed).
    """
    name = (tool_name or "").lower()
    actions = _scoped_operation_actions(name, args)
    if name == "memory":
        mutating_set = MEMORY_MUTATING_ACTIONS
        reading_set = MEMORY_READ_ACTIONS
    else:
        mutating_set = CRON_MUTATING_ACTIONS
        reading_set = CRON_READ_ACTIONS
    known = set(mutating_set) | set(reading_set)
    unknown = [a for a in actions if a not in known]
    if unknown:
        # An operation this plugin cannot classify may well be a write.
        # It is reported as unverified so it is escalated, never treated
        # as a read.
        return OP_UNVERIFIED, ",".join(sorted(set(unknown)))
    mutating = [a for a in actions if a in mutating_set]
    if mutating:
        return OP_MUTATE, ",".join(sorted(set(mutating)))
    reading = [a for a in actions if a in reading_set]
    if reading:
        return OP_READ, ",".join(sorted(set(reading)))
    # No operation named at all. Neither tool treats that as a read:
    # ``memory`` has no read operation, and ``cronjob_manage`` requires an
    # action. Such a call is therefore escalated rather than waved through.
    return OP_UNVERIFIED, "no-operation"


def _scoped_cron_action(args: Any) -> str:
    """The ``cronjob_manage`` action of a call, lower-cased ("" if none)."""
    if not isinstance(args, dict):
        return ""
    action = args.get("action")
    return action.strip().lower() if isinstance(action, str) else ""


def _scoped_payload_text(tool_name: str, args: Any) -> str:
    """The instruction-bearing text a scoped write would persist.

    Only text that *becomes* durable state is collected. For ``memory``
    that is the new text of an ``add``/``patch`` operation; the selector of
    a ``remove`` (and the ``old_text`` of a ``patch``) only *points at* an
    existing entry, so it is not treated as new instruction - which also
    lets a poisoned entry be cleaned up instead of locking the poison in.
    For ``cronjob_manage`` it is the prompt the scheduled agent will run.
    """
    name = (tool_name or "").lower()
    if not isinstance(args, dict):
        return ""
    parts: List[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            parts.append(value)

    if name == "memory":
        operations = args.get("operations")
        if isinstance(operations, (list, tuple)) and operations:
            for op in operations:
                if not isinstance(op, dict):
                    continue
                action = op.get("action")
                action = action.strip().lower() if isinstance(action, str) else ""
                if action == "remove":
                    # The selector only points at an existing entry.
                    continue
                collect(op.get("content"))
                collect(op.get("new_text"))
            return "\n".join(parts)
        top = args.get("action")
        top = top.strip().lower() if isinstance(top, str) else ""
        if top != "remove":
            collect(args.get("content"))
            collect(args.get("new_text"))
    elif name == "cronjob_manage":
        collect(args.get("prompt"))
    return "\n".join(parts)


def _scoped_unverifiable_content(tool_name: str, args: Any) -> Tuple[str, str]:
    """Content a scoped write will inject later that the call cannot show.

    ``cronjob_manage`` can attach a ``script`` (run on every tick, its
    stdout injected into the agent's prompt) or a ``monitor`` (an URL or
    script whose output is injected as a diff). The content of those is not
    part of the call, so it cannot be scanned here - the write therefore
    needs a human decision, exactly like an unverifiable protected write
    (PF-03).

    ``no_agent`` only changes where stdout goes; it does not remove script
    side effects. Scripts therefore require approval regardless of that flag.
    Known protected writes are blocked separately before this escalation.
    Returns ``(kind, grain)``; ``("", "")`` when nothing unverifiable is
    attached.
    """
    name = (tool_name or "").lower()
    if name != "cronjob_manage" or not isinstance(args, dict):
        return "", ""
    monitor = args.get("monitor")
    if isinstance(monitor, str) and monitor.strip():
        return "monitor", _scoped_grain("monitor", monitor.strip())
    script = args.get("script")
    if isinstance(script, str) and script.strip():
        return "script", _scoped_grain("script", script.strip())
    return "", ""


def _scoped_grain(key: str, value: str) -> str:
    """The approval grain for a piece of unverifiable injected content.

    A monitor may be an URL that carries a token, and a script may be an
    inline command, so both are digested instead of being written into the
    rule key verbatim. A short plain script path stays readable, because
    approving one script is a decision worth seeing in the rule.
    """
    if key == "script" and re.fullmatch(r"[\w./-]{1,120}", value):
        return f"script:{value}"
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{key}:{digest}"


def _evaluate_scoped_call(tool_name: str, args: Any) -> Verdict:
    """Enforce the action boundary for the argument-scoped tools.

    Reads are not blocked. Writes are held to the *existing* content
    policy: the durable text they would store is scanned with the same
    detectors and the same action-blocking categories every other write
    uses, so instruction-shaped content that arrived through a tool can
    never become long-lived memory or a scheduled task.
    """
    name = (tool_name or "").lower()
    kind, detail = classify_scoped_operation(name, args)

    if kind == OP_READ:
        return Verdict(
            action="allow",
            reason="scoped_read_allowed",
            detail=(
                "Allowed: this call only reads; it changes no durable "
                f"state ({detail})."
            ),
        )

    if kind == OP_UNVERIFIED:
        return Verdict(
            action="approve",
            reason="unverified_scoped_operation",
            detail=(
                "Approval required: the operation named by this call "
                f"({detail!r}) is not one this plugin can classify, so its "
                "effect on durable state cannot be established. It is not "
                "treated as a read."
            ),
            rule_key=f"prompt-firewall.unverified-operation:{name}:{detail}",
        )

    # The detector truncates at its cap. Never label a prefix-only scan as
    # a verified durable write; include all batch entries and separators.
    payload = _scoped_payload_text(name, args)
    if len(payload) > _SCOPED_SCAN_BUDGET:
        return Verdict(
            action="block",
            reason="scoped_payload_scan_budget_exceeded",
            detail="Blocked: complete text inspection exceeds the scanner budget; write not scanned.",
        )

    # Reuse Stage 2A extraction, without changing the shell parser. The
    # absence of a literal target is NOT proof that execution is safe:
    # opaque scripts still reach the approval branch below.
    if name == "cronjob_manage" and isinstance(args, dict):
        script = args.get("script")
        if isinstance(script, str) and script.strip():
            targets = extract_exec_write_destinations("terminal", {"command": script})
            if any(is_protected_path(t) or is_control_plane_path(t) for t in targets):
                return Verdict(
                    action="block",
                    reason="scheduled_script_protected_write",
                    detail="Blocked: scheduled script writes a protected or control-plane path.",
                )

    unverifiable_kind, grain = _scoped_unverifiable_content(name, args)
    if unverifiable_kind:
        return Verdict(
            action="approve",
            reason="scheduled_task_unverifiable_content",
            detail=(
                "Approval required: this scheduled task attaches "
                f"{unverifiable_kind!r}. Its execution side effects or future "
                "output cannot be verified from this call. no_agent does "
                "not establish safe execution."
            ),
            rule_key=f"prompt-firewall.scheduled-task-content:{grain}",
        )

    if not payload:
        # The call mutates, but it persists no instruction-bearing text
        # (a ``remove``, a pause, a resume) - there is nothing to scan.
        return Verdict(
            action="allow",
            reason="scoped_mutation_without_text",
            detail=(
                "Allowed: this call changes state but stores no text, so "
                "there is no instruction for it to carry."
            ),
        )
    findings = scan_text(payload, max_chars=_SCOPED_SCAN_BUDGET)
    injection = _first_finding(findings, ACTION_BLOCKING_CATEGORIES)
    if injection:
        if name == "memory":
            reason = "poisoned_memory_write"
            surface = "long-lived memory"
            verb = "store"
            tail = "Untrusted content cannot become durable instruction."
        elif _scoped_cron_action(args) in ("create", "update"):
            reason = "poisoned_scheduled_task"
            surface = "a scheduled task"
            verb = "store"
            tail = "Untrusted content cannot become durable instruction."
        else:
            # A ``run`` fires a job once and its prompt is never persisted,
            # but it still reaches a fresh agent's context, so it is
            # refused with an accurate reason.
            reason = "poisoned_cron_run"
            surface = "a scheduled job run"
            verb = "pass"
            tail = "Untrusted content cannot become an agent's instruction."
        return Verdict(
            action="block",
            reason=reason,
            detail=(
                f"Blocked: refused to {verb} instruction-shaped content in "
                f"{surface} (pattern {injection.pattern}, category "
                f"{injection.category}). {tail}"
            ),
            findings=tuple(findings),
        )

    return Verdict(
        action="allow",
        reason="durable_write_scanned",
        detail=(
            "Allowed: the durable text of this write was scanned and "
            "carries no injection signature."
        ),
        findings=tuple(findings),
    )


def evaluate_tool_call(
    tool_name: str, args: Any, *, grant: Any = None, cwd: Optional[str] = None
) -> Verdict:
    """Evaluate a single tool call against the trust boundary.

    Returns a :class:`Verdict`. ``block`` means the call must not execute.

    ``grant`` is an optional ``(session_id, turn_id)`` tuple identifying the
    operator turn on which a Scoped Intent Grant may have been captured. It is
    consulted ONLY at the durable-instruction-surface write branch, and ONLY for
    a single-target atomic ``write_file`` whose content hash matches the
    authorized hash. Every other rule runs unchanged; the grant never short-
    circuits the rest of this evaluation.

    ``cwd`` is the execution directory of this call. It is used to resolve
    relative shell destinations; when it is absent, relative writes are not
    attributed to the ambient gateway cwd (P0-2).

    The evaluation runs inside a one-evaluation ``normalize_path`` memo
    scope: the same path is normalized many times per evaluation, and the
    filesystem cannot change while the call is still being judged.  The memo
    is removed again before this function returns, so a later evaluation
    always re-reads the filesystem.
    """
    token = bind_eval_state()
    try:
        return _evaluate_tool_call(
            tool_name, args, grant=grant, cwd=cwd)
    finally:
        reset_eval_state(token)


def _evaluate_tool_call(
    tool_name: str, args: Any, *, grant: Any = None, cwd: Optional[str] = None
) -> Verdict:
    """The body of :func:`evaluate_tool_call`.

    See that function for the contract.
    """
    name = (tool_name or "").lower()
    content = _arg_text(args)
    command = extract_command_text(name, args)
    targets = extract_target_paths(name, args)
    if cwd is None:
        cwd = extract_call_cwd(args)

    # ------------------------------------------------------------------ #
    # 0. Argument-scoped tools.
    #
    #    ``memory`` and ``cronjob_manage`` perform reads and writes under
    #    one name, so the name cannot classify the call. They are judged
    #    by the operation their arguments actually carry.
    # ------------------------------------------------------------------ #
    if name in SCOPED_TOOLS:
        return _evaluate_scoped_call(name, args)

    # ------------------------------------------------------------------ #
    # 1. Injection signatures inside the action's own payload.
    # ------------------------------------------------------------------ #
    scan_source = content
    if command and command not in scan_source:
        scan_source = f"{scan_source}\n{command}"
    findings = scan_text(scan_source)
    injection = _first_finding(findings, ACTION_BLOCKING_CATEGORIES)

    # ------------------------------------------------------------------ #
    # 1b. The flattened argument payload exceeded the inspection budget.
    #     A prefix-only scan is not a clean bill of health: the call is
    #     escalated instead of allowed on the strength of a partial view.
    # ------------------------------------------------------------------ #
    if not _arg_scan_complete(args):
        return Verdict(
            action="approve",
            reason="argument_scan_budget_exceeded",
            detail=(
                "Approval required: the nested argument payload is too large "
                "or too deeply nested to inspect completely, so the firewall "
                "cannot establish what this call carries."
            ),
            findings=tuple(findings),
        )

    # ------------------------------------------------------------------ #
    # 2. An attempt to switch the firewall (or another control) off.
    #
    #    PF-12: the phrase alone is not the finding - the action is. The
    #    same words are harmless inside a research query or a documentation
    #    file, and fatal in a command that actually performs the switch.
    #    The decision therefore depends on what the call does with the
    #    phrase, not on the phrase being present at all.
    # ------------------------------------------------------------------ #
    disable_hit = _first_finding(findings, (CATEGORY_SECURITY_DISABLE,))
    _exec_source = executable_command_view(scan_source, name)
    if name in EXEC_TOOLS and _unresolved_provider_env_assignments(_exec_source):
        return Verdict(
            action="approve",
            reason="destination_unresolved",
            detail="Approval required: provider destination is computed and not resolvable at policy time.",
            findings=tuple(findings),
        )
    if name in EXEC_TOOLS and re.search(
        r"(?i)\bhermes\s+config\s+set\s+"
        r"(?:\S+\.)?(?:api_base|api_url|base_url|endpoint|providers?\.\S+\.api)\b",
        _exec_source,
    ):
        for _m in re.finditer(r"https?://[^\s\"'<>]+", scan_source):
            _h = urllib.parse.urlsplit(_m.group(0)).hostname or ""
            if _h and not endpoint_is_allowlisted(_h):
                return Verdict(
                    action="block",
                    reason="gateway_redirect_exec",
                    detail=("Blocked: command redirects the model endpoint to "
                            f"non-allowlisted host {_h.lower()}."),
                    findings=tuple(findings),
                )

    if name in EXEC_TOOLS:
        for _m in re.finditer(
            r"(?i)os\.environ\s*\[\s*['\"]"
            r"(?:OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_BASE_URL|"
            r"ANTHROPIC_API_URL|AZURE_OPENAI_ENDPOINT|AZURE_OPENAI_API_BASE|"
            r"HERMES[A-Z0-9_]*(?:ENDPOINT|BASE_URL|API_URL|API_BASE)|"
            r"OLLAMA_HOST|OLLAMA_BASE_URL|LITELLM_BASE_URL|VLLM_BASE_URL|"
            r"LITELLM_API_BASE)"
            r"['\"]\s*]\s*=\s*['\"]([^'\"]+)['\"]",
            _exec_source,
        ):
            _h = urllib.parse.urlsplit(_m.group(1)).hostname or ""
            if _h and not endpoint_is_allowlisted(_h):
                return Verdict(
                    action="block",
                    reason="gateway_redirect_exec",
                    detail=f"Blocked: source redirects the model endpoint to non-allowlisted host {_h}.",
                    findings=tuple(findings),
                )

    if name in EXEC_TOOLS and _disables_firewall_plugin(scan_source):
        return dispatch_decision(
            veto_reason="security_control_disable",
            veto_detail="Blocked: disabling prompt-firewall through Hermes plugin management is not permitted.",
            findings=findings,
        )
    if disable_hit and _is_real_control_disable(name, targets, scan_source):
        return dispatch_decision(
            veto_reason="security_control_disable",
            veto_detail=(
                "Blocked: the tool call tries to disable security controls "
                f"(pattern {disable_hit.pattern}). The firewall cannot be "
                "switched off from inside a tool call."
            ),
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    # 3. Writing untrusted instructions into a persistent instruction file.
    #    (Poisoned AGENTS.md / CLAUDE.md / SOUL.md / SKILL.md.)
    # ------------------------------------------------------------------ #
    if injection and (WRITE_TOOLS and name in WRITE_TOOLS or name in SKILL_TOOLS):
        instruction_targets = [t for t in targets if is_instruction_path(t) or is_skill_path(t)]
        if instruction_targets:
            return Verdict(
                action="block",
                reason="poisoned_instruction_file",
                detail=(
                    "Blocked: refused to write instruction-shaped content into "
                    f"{instruction_targets[0]!r} (pattern {injection.pattern}, "
                    f"category {injection.category}). Untrusted content cannot "
                    "author the agent's persistent instructions."
                ),
                findings=tuple(findings),
            )
        # Nested arguments are scanned even when no target path is named:
        # the flattened payload above carries an injection signature, and a
        # write tool that persists it must not be waved through. A control
        # *phrase* is different - it names no instruction and only the
        # disable rule below judges whether the action is real (PF-12).
        if not targets and injection.category != CATEGORY_SECURITY_DISABLE:
            return Verdict(
                action="block",
                reason="nested_argument_injection",
                detail=(
                    "Blocked: refused to write instruction-shaped content "
                    f"(pattern {injection.pattern}, category {injection.category}) "
                    "carried in nested arguments."
                ),
                findings=tuple(findings),
            )

    # ------------------------------------------------------------------ #
    # 3b. Destination-only durable-instruction-surface gate (P0 closure).
    #
    #     Section 3 above blocks instruction-shaped CONTENT; section 5 below
    #     gates PROTECTED paths. But a durable instruction surface (AGENTS.md /
    #     SKILL.md) can live OUTSIDE the protected roots (e.g. /tmp/x/SKILL.md or
    #     a project-local SKILL.md), and a symlink alias can hide the canonical
    #     target from is_protected_path. The G1 invariant is scanner-independent
    #     and destination-based, so it must hold for EVERY durable surface, not
    #     only protected ones. This branch runs regardless of injection findings
    #     and regardless of is_protected_path, on the CANONICAL path.
    #
    #     P0-A: a matching grant suppresses ONLY this destination-specific denial.
    #     It NEVER returns ALLOW early. Every downstream check (sections 4, 4b, 5,
    #     6, 7) still executes; the grant is consumed at the FINAL authorization
    #     decision only if no other rule blocked or escalated the call.
    # ------------------------------------------------------------------ #
    grant_authorized_canon = None  # set iff a grant lifts THIS destination denial
    if name in WRITE_TOOLS:
        durable_targets = [t for t in targets if is_durable_instruction_surface(t)]
        if durable_targets:
            # P0-5: only a single-target atomic write_file may be grant-exempted.
            # Strict single-target semantics: exactly ONE parsed target overall,
            # and it must be the durable surface (no nested/mixed effects).
            if name == "write_file" and grant is not None and len(targets) == 1:
                from . import grants as _g
                content_arg = args.get("content") if isinstance(args, dict) else None
                canon = normalize_path(durable_targets[0])
                # A grant must NEVER downgrade protection for the Firewall's own
                # code/config/state paths. Such a surface stays fail-closed BLOCK
                # regardless of any grant (an APPROVE could be auto-approved).
                if canon and not is_firewall_state_surface(canon) \
                        and "/plugins/" + FIREWALL_PLUGIN_NAME + "/" not in canon \
                        and _g.grant_matches(grant[0], grant[1], canon, content_arg):
                    # Lift ONLY this denial; do NOT allow yet. Fall through so all
                    # remaining policy checks run. Consumption happens at the end.
                    grant_authorized_canon = canon
            if grant_authorized_canon is None:
                return Verdict(
                    action="block",
                    reason=GATE_REASON_INSTRUCTION_SURFACE,
                    detail=(
                        "Blocked: refused to write the durable instruction surface "
                        f"{normalize_path(durable_targets[0])!r}. This gate is "
                        "destination-based and applies even outside protected roots "
                        "and through symlink aliases; an approval prompt is not a "
                        "guarantee in auto-approval modes."
                    ),
                    findings=tuple(findings),
                )

    # ------------------------------------------------------------------ #
    # 4. Gateway / endpoint redirect.
    #
    # Context-sensitive by design: a URL only counts when it is *bound* to
    # an endpoint key, and a write only counts when it actually lands on a
    # protected surface that carries the model endpoint. A URL sitting next
    # to the word "endpoint" in prose, source code or documentation is not
    # an endpoint change.
    # ------------------------------------------------------------------ #
    if name in WRITE_TOOLS or name in SKILL_TOOLS:
        endpoint_targets = [t for t in targets if is_endpoint_config_path(t)]
        if endpoint_targets:
            hosts = extract_endpoint_hosts(scan_source)
            bad = [h for h in hosts if not endpoint_is_allowlisted(h)]
            if bad:
                return Verdict(
                    action="block",
                    reason="gateway_redirect",
                    detail=(
                        "Blocked: this call redirects the model endpoint to "
                        f"non-allowlisted host(s) {', '.join(sorted(bad))}. "
                        "Model endpoints are protected configuration; an "
                        "explicit operator request is required."
                    ),
                    findings=tuple(findings),
                )

    # ------------------------------------------------------------------ #
    # 4b. PF-02 - a structured change that switches THIS firewall off.
    #     The check reads configuration *keys*, not wording, so a payload
    #     that never names the firewall is still caught. Such a change is
    #     never auto-allowed: it is escalated to Hermes' native approval
    #     gate, which requires a fresh, out-of-band human decision and
    #     fails closed when no human is available.
    # ------------------------------------------------------------------ #
    provenance = call_provenance(name, args, findings)
    state_targets = [t for t in targets if is_firewall_state_surface(t)]
    if state_targets:
        # Edit-shaped tools (``edit_file`` / ``multi_edit``) express a
        # deletion through ``old_text`` with an empty ``new_text``; the
        # selector is part of the payload for the state gate (PF-02).
        mutation = config_firewall_state_mutation(
            _write_payload_text(args, include_selectors=name in _EDIT_TOOLS)
        ) or config_firewall_entry_removal(
            _write_payload_text(args, include_selectors=name in _EDIT_TOOLS)
        )
        if mutation:
            # G1 destination gate - switching THIS firewall off (or removing
            # its config entry) is the highest-value control-plane mutation an
            # undetected injection can make. Per P0 an ``approve`` is
            # auto-approved in yolo / approvals-off / cron-approve /
            # unattended-approve modes, so escalating it would let an
            # undetected injection switch the firewall off in exactly those
            # modes. It is therefore refused outright; the operator must make
            # this change directly, outside the agent's tool path.
            return Verdict(
                action="block",
                reason=GATE_REASON_CONTROL_PLANE,
                detail=(
                    "Blocked: this call changes the firewall's own "
                    f"state ({mutation}) in {normalize_path(state_targets[0])!r}. "
                    "The firewall cannot establish operator authorization, and "
                    "an approval prompt is not a guarantee in auto-approval "
                    "modes, so the change is refused rather than escalated. "
                    "The operator must change the firewall configuration "
                    "directly."
                ),
                findings=tuple(findings),
            )

    # ------------------------------------------------------------------ #
    # 4c. PF-03 - a shell command that writes to a protected surface.
    #     Hermes' own file-tool guards do not cover shell writes, so this
    #     plugin is the only gate in front of them: the written content
    #     cannot be verified before the command runs, hence escalation
    #     instead of a silent allow.
    # ------------------------------------------------------------------ #
    if name in EXEC_TOOLS or (
        name not in KNOWN_TOOLS and _has_exec_payload(args)
    ):
        write_targets = extract_exec_write_destinations(name, args, cwd=cwd)
        protected_exec = [
            t
            for t in write_targets
            if (is_protected_path(t, cwd)
                or is_control_plane_path(t, cwd)
                or is_durable_instruction_surface(t))
        ]
        if not protected_exec:
            # A segment that names a protected surface without a resolvable
            # destination is escalated on its own. The check is per segment:
            # a benign resolved write elsewhere in the same command must not
            # mask an unverifiable protected write.
            ambiguous = _ambiguous_protected_write(name, args, cwd=cwd)
            if ambiguous:
                return Verdict(
                    action="approve",
                    reason="protected_write_unverifiable",
                    detail=(
                        "Approval required: this command writes to the "
                        f"protected path {normalize_path(ambiguous, cwd)!r}, but "
                        "the firewall cannot resolve where the write lands."
                    ),
                    rule_key=(
                        "prompt-firewall.protected-write:"
                        f"{normalize_path(ambiguous, cwd)}"
                    ),
                    findings=tuple(findings),
                )
            # R04: unresolved relative destinations must reach policy, not
            # remain dead code in the extraction helper. A relative target
            # with no trusted execution cwd cannot be proven benign.
            unresolved = extract_unresolved_write_destinations(name, args, cwd=cwd)
            if unresolved:
                return Verdict(
                    action="approve",
                    reason="destination_unresolved",
                    detail=(
                        "Approval required: the write destination cannot be "
                        f"resolved to a known directory: {unresolved[0]!r}."
                    ),
                    rule_key="prompt-firewall.unresolved-destination",
                    findings=tuple(findings),
                )
        if protected_exec:
            exec_target = protected_exec[0]
            if injection:
                return dispatch_decision(
                    veto_reason="protected_write_with_injection",
                    veto_detail=(
                        "Blocked: refused to write to protected path "
                        f"{normalize_path(exec_target)!r} because the request "
                        f"carries an injection signature (pattern "
                        f"{injection.pattern})."
                    ),
                    findings=findings,
                )
            if is_credential_path(exec_target):
                return Verdict(
                    action="block",
                    reason="credential_path_write",
                    detail=(
                        "Blocked: refused to write to credential path "
                        f"{posixpath.dirname(normalize_path(exec_target))}"
                        "/[REDACTED]. Credential files are protected from "
                        "tool-driven writes."
                    ),
                    findings=tuple(findings),
                )
            # G1 destination gate - an exec write whose destination is a
            # durable instruction / control-plane surface (AGENTS.md-class,
            # Skill files, firewall state) is refused, not escalated. Ordinary
            # protected exec destinations (``.bashrc``) stay on the ``approve``
            # path below, because they are not durable-instruction surfaces and
            # the operator gate is the right control for them.
            if is_durable_instruction_surface(exec_target):
                return Verdict(
                    action="block",
                    reason=GATE_REASON_INSTRUCTION_SURFACE,
                    detail=(
                        "Blocked: this command writes the durable instruction / "
                        f"control-plane surface {normalize_path(exec_target)!r}. "
                        "The firewall cannot establish operator authorization, "
                        "and an approval prompt is not a guarantee in "
                        "auto-approval modes, so the write is refused rather "
                        "than escalated."
                    ),
                    findings=tuple(findings),
                )
            if name not in KNOWN_TOOLS:
                return Verdict(
                    action="approve",
                    reason="protected_write_requires_verification",
                    detail=(
                        "Approval required: write to the protected path "
                        f"{normalize_path(exec_target)!r} through the "
                        f"unrecognized tool {name!r} cannot be verified by "
                        "the firewall."
                    ),
                    rule_key=(
                        "prompt-firewall.protected-write:"
                        f"{normalize_path(exec_target)}"
                    ),
                    findings=tuple(findings),
                )
            return Verdict(
                action="approve",
                reason="protected_write_unverifiable",
                detail=(
                    "Approval required: this command writes to the protected "
                    f"path {normalize_path(exec_target)!r}; the firewall "
                    "cannot verify the written content before the command "
                    "runs."
                ),
                rule_key=(
                    "prompt-firewall.protected-write:"
                    f"{normalize_path(exec_target)}"
                ),
                findings=tuple(findings),
            )

    # ------------------------------------------------------------------ #
    # 5. Writes to protected surfaces.
    # ------------------------------------------------------------------ #
    protected_targets = [t for t in targets if is_protected_path(t)]
    if protected_targets:
        target = protected_targets[0]
        # PF-13: read and write are different operations. A tool that only
        # reads the path it names cannot modify it, so a protected or
        # credential path reached that way is NOT a write attempt and must
        # not be reported as one. Sensitive reads keep their own protective
        # policy: a credential read is escalated to the operator's gate
        # instead of being waved through.
        if not normalize_path(target):
            return Verdict(
                action="block",
                reason="invalid_target_path",
                detail="Blocked: the target path could not be safely normalized.",
                findings=tuple(findings),
            )
        if _is_read_operation(name):
            if injection:
                label = normalize_path(target)
                if is_credential_path(label):
                    label = posixpath.join(posixpath.dirname(label), "[REDACTED]")
                return Verdict(
                    action="block",
                    reason="protected_read_with_injection",
                    detail=(
                        "Blocked: refused to read protected path "
                        f"{label!r} because the request carries an injection "
                        f"signature (pattern {injection.pattern})."
                    ),
                    findings=tuple(findings),
                )
            if is_credential_path(target):
                return Verdict(
                    action="approve",
                    reason="credential_path_read",
                    detail=(
                        "Approval required: this call reads a credential "
                        "file. Reading a secret is not a write, so it is not "
                        "blocked as one, but it is never granted automatically "
                        "either - an explicit operator decision is required."
                    ),
                    rule_key=(
                        "prompt-firewall.credential-read:"
                        f"{posixpath.dirname(normalize_path(target))}"
                        "/[REDACTED]"
                    ),
                    findings=tuple(findings),
                )
            return Verdict(action="allow", reason="protected_read")
        if injection:
            return dispatch_decision(
                veto_reason="protected_write_with_injection",
                veto_detail=(
                    "Blocked: refused to write to protected path "
                    f"{target!r} because the content carries an injection "
                    f"signature (pattern {injection.pattern})."
                ),
                findings=findings,
            )
        if is_credential_path(target):
            return Verdict(
                action="block",
                reason="credential_path_write",
                detail=(
                    f"Blocked: refused to write to credential path {target!r}. "
                    "Credential files are protected from tool-driven writes."
                ),
                findings=tuple(findings),
            )
        # G1 destination gate - a durable instruction / control-plane surface
        # (AGENTS.md-class instruction files, Skill files, the firewall's own
        # state) is refused outright, NOT escalated to ``approve``. Per P0 an
        # ``approve`` is auto-approved in yolo / approvals-off / cron-approve /
        # unattended-approve contexts, so escalating these surfaces would leave
        # the G1 hole open in exactly those modes. The decision is made from the
        # destination alone, so it holds even when the scanner finds nothing.
        # Ordinary protected writes (``.bashrc`` and similar) are NOT caught
        # here; they continue to the ``approve`` branches below.
        if is_durable_instruction_surface(target):
            # P0 remediation: a Scoped Intent Grant may exempt THIS exact write,
            # but only when ALL of the following hold (otherwise fail closed):
            #   * the tool is a single-target atomic ``write_file`` (P0-5);
            #   * it is the ONLY instruction-surface target in the call;
            #   * a grant was captured on this operator turn (P0-3);
            #   * the grant's canonical path matches and its SHA-256 matches the
            #     exact proposed content (P0-4).
            # The grant lifts ONLY this denial; every other rule above and below
            # still runs. Shell / terminal / mixed-effect calls never qualify.
            # Consumption happens once, at the final protected-write decision.
            if name == "write_file" and grant is not None:
                from . import grants as _g
                surfaces = [t for t in targets if is_durable_instruction_surface(t)]
                content_arg = args.get("content") if isinstance(args, dict) else None
                if len(surfaces) == 1 and not any(
                        is_firewall_state_surface(t)
                        or "/plugins/" + FIREWALL_PLUGIN_NAME + "/" in normalize_path(t)
                        for t in surfaces
                ) and _g.grant_matches(
                        grant[0], grant[1], normalize_path(target), content_arg):
                    # Authorized exact write: fall through to the remaining
                    # checks instead of returning the instruction-surface block.
                    # Firewall-owned state is NEVER grant-downgradable (R07/P0).
                    pass
                else:
                    return Verdict(
                        action="block",
                        reason=GATE_REASON_INSTRUCTION_SURFACE,
                        detail=(
                            "Blocked: refused to write the durable instruction / "
                            f"control-plane surface {normalize_path(target)!r}. The "
                            "operator grant did not match this exact path+content "
                            "(or was already used), so the write is refused."
                        ),
                        findings=tuple(findings),
                    )
            else:
                return Verdict(
                    action="block",
                    reason=GATE_REASON_INSTRUCTION_SURFACE,
                    detail=(
                        "Blocked: refused to write the durable instruction / "
                        f"control-plane surface {normalize_path(target)!r}. The "
                        "firewall cannot establish operator authorization for this "
                        "content, and an approval prompt is not a guarantee in "
                        "auto-approval modes, so the write is refused rather than "
                        "escalated. Ask the operator to make this change directly."
                    ),
                    findings=tuple(findings),
                )
        # PF-03 - a patch payload names the destination, but the resulting
        # file content cannot be verified here, so it is escalated rather
        # than allowed.
        patch_targets = extract_patch_targets(args)
        if any(normalize_path(t) == normalize_path(target) for t in patch_targets):
            return Verdict(
                action="approve",
                reason="protected_write_unverifiable",
                detail=(
                    "Approval required: this patch targets the protected path "
                    f"{normalize_path(target)!r}, but the resulting file "
                    "content cannot be verified before the write happens."
                ),
                rule_key=(
                    "prompt-firewall.protected-write:"
                    f"{normalize_path(target)}"
                ),
                findings=tuple(findings),
            )
        # PF-03 / PF-10 - an unknown side-effecting tool is never trusted
        # to write a protected surface on its own. Only tools that carry a
        # payload (i.e. are plausibly mutating) are escalated; unknown
        # *read* tools stay allowed.
        if name not in KNOWN_TOOLS and _write_payload_text(args):
            return Verdict(
                action="approve",
                reason="protected_write_requires_verification",
                detail=(
                    "Approval required: write to the protected path "
                    f"{normalize_path(target)!r} through the unrecognized tool "
                    f"{name!r} cannot be verified by the firewall."
                ),
                rule_key=(
                    "prompt-firewall.protected-write:"
                    f"{normalize_path(target)}"
                ),
                findings=tuple(findings),
            )
        # PF-02 - writing the firewall's OWN state (its config entry, its
        # plugin directory, its plugin.yaml) is a control-plane change. The
        # previous ``allow`` here was not an approval request: the reason
        # named an approval that was never asked for. Such a write is always
        # escalated, whatever tool carries it.
        if is_firewall_own_path(target) or is_firewall_state_surface(target):
            return Verdict(
                action="approve",
                reason="firewall_state_mutation",
                detail=(
                    "Approval required: this call writes the firewall's own "
                    f"state at {normalize_path(target)!r}. The firewall never "
                    "authorizes its own modification; only a fresh, explicit "
                    "operator decision may allow it."
                ),
                rule_key=(
                    "prompt-firewall.firewall-state:"
                    f"{normalize_path(target)}"
                ),
                findings=tuple(findings),
            )
        # Non-injection protected write through a Hermes-native file tool.
        #
        # This used to return ``allow`` on the assumption that Hermes Core's
        # own write guards were the gate. They are not: an audit of
        # ``tools/file_tools_write_guards.py`` shows Core gates only
        # ``~/.ssh/config``, the instruction basenames it knows, and the
        # Hermes config file. ``~/.bashrc``, ``~/.aws/credentials``,
        # ``~/.kube/config``, ``~/.mcp.json`` and the rest reach the
        # filesystem with no gate at all. A reason that names an approval
        # the firewall never requested was therefore a false promise, so the
        # verdict is escalated here rather than delegated.
        # P0-A (single consumption point): do NOT consume or allow here. If a
        # grant lifted the destination denial in section 3b for THIS exact target,
        # skip the protected-write escalation and fall through so sections 6-7 and
        # the FINAL authorization branch run. The grant is consumed exactly once,
        # at the final decision. A grant never downgrades protection here.
        if grant_authorized_canon is not None and normalize_path(target) == grant_authorized_canon:
            pass  # fall through to the final authorization decision
        else:
            return Verdict(
                action="approve",
                reason="protected_write_requires_approval",
                detail=(
                    "Approval required: this call writes the protected path "
                    f"{normalize_path(target)!r}. Hermes Core does not gate this "
                    "path, so the firewall escalates it instead of allowing it "
                    "through on a reason that promised an approval it never "
                    "asked for."
                ),
                rule_key=(
                    "prompt-firewall.protected-write:"
                    f"{normalize_path(target)}"
                ),
                findings=tuple(findings),
            )

    # ------------------------------------------------------------------ #
    # 6. Executable actions that mention protected paths.
    # ------------------------------------------------------------------ #
    if name in EXEC_TOOLS and command:
        mentioned = _paths_mentioned_in_command(command)
        for token in mentioned:
            if is_protected_path(token) and injection:
                return Verdict(
                    action="block",
                    reason="protected_exec_with_injection",
                    detail=(
                        "Blocked: command touches protected path "
                        f"{token!r} and carries an injection signature "
                        f"(pattern {injection.pattern})."
                    ),
                    findings=tuple(findings),
                )
        # A command that binds an endpoint key to a URL really does switch
        # the endpoint, so it is enforced here (not only for writes).
        # `hermes config set ... <url>` is an explicit control-plane mutation
        # even when the URL is not written in config-key notation.
        command_ctx = ActionContext(
            tool_name=name,
            args=args if isinstance(args, dict) else {},
            cwd=cwd,
            command=command or "",
        ) if ActionContext is not None else None
        _command_text = executable_command_view(
            command_ctx.command if command_ctx else command, name
        )
        if re.search(
            r"(?i)\bhermes\s+config\s+set\s+"
            r"(?:\S+\.)?(?:api_base|api_url|base_url|endpoint|"
            r"providers?\.\S+\.api)\b",
            _command_text,
        ):
            _cli_hosts = []
            for _m in re.finditer(r"https?://[^\s\"'<>]+", _command_text):
                _h = urllib.parse.urlsplit(_m.group(0)).hostname or ""
                if _h and not endpoint_is_allowlisted(_h):
                    _cli_hosts.append(_h.lower())
            if _cli_hosts:
                return Verdict(
                    action="block",
                    reason="gateway_redirect_exec",
                    detail=("Blocked: command redirects the model endpoint to "
                            f"non-allowlisted host(s) {', '.join(sorted(set(_cli_hosts)))}."),
                    findings=tuple(findings),
                )

        _literal_vars_g5 = {}
        for _ln in _command_text.splitlines():
            _mm = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]([^'\"]+)['\"]\s*$", _ln)
            if _mm:
                _literal_vars_g5[_mm.group(1)] = _mm.group(2)
        for _m5 in re.finditer(
            r"(?i)os\.environ\s*\[\s*['\"]"
            r"(?:OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_BASE_URL|"
            r"ANTHROPIC_API_URL|AZURE_OPENAI_ENDPOINT|AZURE_OPENAI_API_BASE|"
            r"HERMES[A-Z0-9_]*(?:ENDPOINT|BASE_URL|API_URL|API_BASE))"
            r"['\"]\s*]\s*=\s*([A-Za-z_][A-Za-z0-9_]*)",
            _command_text,
        ):
            _var5 = _m5.group(1)
            if _var5 not in _literal_vars_g5:
                return Verdict(
                    action="approve",
                    reason="destination_unresolved",
                    detail=f"Approval required: unresolved provider value {_var5!r}.",
                    findings=tuple(findings),
                )
            _h5 = urllib.parse.urlsplit(_literal_vars_g5[_var5]).hostname or ""
            if _h5 and not endpoint_is_allowlisted(_h5):
                return Verdict(
                    action="block",
                    reason="gateway_redirect_exec",
                    detail=f"Blocked: provider endpoint redirected to non-allowlisted host {_h5}.",
                    findings=tuple(findings),
                )

        if mentions_endpoint_change(_command_text):
            # A commented-out source line is data, not an executable redirect.
            executable_lines = [
                "" if line.lstrip().startswith("#") else line
                for line in _command_text.splitlines()
            ]
            bad = []
            for _line in executable_lines:
                if not _line.strip():
                    continue
                # Per-line provenance: a plain source assignment is data.
                # Control-plane assignments/commands are never waived.
                _plain_assign = bool(re.match(
                    r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\"'][^\"']+[\"']\s*$",
                    _line,
                ))
                _control = bool(re.search(
                    r"(?i)hermes\s+config|export\s+[A-Z0-9_]*"
                    r"(?:BASE_URL|API_URL|ENDPOINT)|providers\.|"
                    r"os\.environ[^=]*=\s*[\"']?https?://",
                    _line,
                ))
                if name == "execute_code" and _plain_assign and not _control:
                    continue
                _hs = extract_endpoint_hosts(_line)
                bad.extend(h for h in _hs if not endpoint_is_allowlisted(h))
            bad = sorted(set(bad))
            if bad:
                return Verdict(
                    action="block",
                    reason="gateway_redirect_exec",
                    detail=(
                        "Blocked: command redirects the model endpoint to "
                        f"non-allowlisted host(s) {', '.join(sorted(bad))}."
                    ),
                    findings=tuple(findings),
                )

    # Writes into a model-endpoint config file really do redirect the gateway.
    if name in WRITE_TOOLS:
        action_ctx = ActionContext(
            tool_name=name,
            args=args if isinstance(args, dict) else {},
            cwd=cwd,
            targets=tuple(str(t) for t in targets),
            command=command or "",
            content=content or "",
        ) if ActionContext is not None else None
        config_targets = [
            t for t in (action_ctx.target_paths() if action_ctx else targets)
            if posixpath.basename(str(t)) in ENDPOINT_CONFIG_BASENAMES
            and (
                is_control_plane_path(str(t), cwd)
                or (not cwd and posixpath.dirname(str(t)) in ("", "."))
            )
        ]
        if config_targets:
            hosts = extract_endpoint_hosts(json.dumps(args))
            bad = [h for h in hosts if not endpoint_is_allowlisted(h)]
            if bad:
                return Verdict(
                    action="block",
                    reason="gateway_redirect_write",
                    detail=("Blocked: write redirects the model endpoint to "
                            f"non-allowlisted host(s) {', '.join(sorted(bad))}."),
                    findings=tuple(findings),
                )

    # ------------------------------------------------------------------ #
    # 7. Skill installation carrying injection content.
    # ------------------------------------------------------------------ #
    if name in SKILL_TOOLS and injection:
        return Verdict(
            action="block",
            reason="poisoned_skill_install",
            detail=(
                "Blocked: refusing to install a Skill whose payload carries an "
                f"injection signature (pattern {injection.pattern})."
            ),
            findings=tuple(findings),
        )

    # P0-A: final authorization decision. If a grant lifted the destination-
    # specific instruction-surface denial in section 3b AND every downstream
    # check (4, 4b, 5, 6, 7) passed without blocking or escalating, consume the
    # grant one-shot and allow THIS exact write. No early allow anywhere above.
    if grant_authorized_canon is not None and grant is not None:
        from . import grants as _g
        content_arg = args.get("content") if isinstance(args, dict) else None
        if _g.consume_grant(grant[0], grant[1], grant_authorized_canon, content_arg):
            return Verdict(action="allow", reason="operator_grant_exact_write",
                           findings=tuple(findings))
        # Grant vanished/expired between match and consume -> fail closed.
        return Verdict(
            action="block",
            reason=GATE_REASON_INSTRUCTION_SURFACE,
            detail="Blocked: the operator grant expired or was consumed before the write.",
            findings=tuple(findings),
        )

    return Verdict(action="allow", reason="no_violation", findings=tuple(findings))
