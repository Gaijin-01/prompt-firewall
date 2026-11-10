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

import hashlib
import ipaddress
import json
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
    r"(?i)(?<![A-Za-z0-9])(?:"
    r"base_?url|api_?base|api_?url|endpoint|ollama_?host|llm_?base_?url|"
    r"hermes_?base_?url|vllm_?base_?url|litellm_?base_?url|"
    r"azure_?openai_?endpoint|api"
    r")(?![A-Za-z0-9])"
    r"[\"\u0027]?\s*(?::|=>|->|=|\bto\b)\s*"
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


def normalize_path(raw: str) -> str:
    """Normalize *raw* without ever raising on hostile path input.

    Invalid path data is returned as a safe sentinel. Callers must treat the
    sentinel as unclassifiable and fail closed; it is never an authorization
    for a write.
    """
    if not isinstance(raw, str) or not raw:
        return ""
    try:
        if "\x00" in raw or any(0xD800 <= ord(ch) <= 0xDFFF for ch in raw):
            return ""
        text = raw.strip().strip('"').strip("'")
        if not text or "\x00" in text:
            return ""
        expanded = os.path.expanduser(os.path.expandvars(text))
        if not isinstance(expanded, str) or "\x00" in expanded:
            return ""
        if not os.path.isabs(expanded):
            expanded = posixpath.join(os.getcwd(), expanded)
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


def _active_hermes_home() -> str:
    """The Hermes home the running agent actually uses (never raises)."""
    try:
        from hermes_cli.config import get_hermes_home

        home = get_hermes_home()
        if home:
            return str(home).rstrip("/") or "/"
    except Exception:
        pass
    return os.path.join(_home(), ".hermes")


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
    active = normalize_path(_active_hermes_home())
    if not active or not _within(path, active):
        return False
    relative = path[len(active):].lstrip("/")
    if not relative:
        return False
    parts = relative.split("/")
    if parts[0] not in _NON_PERSISTENT_HOME_DIRS:
        return False
    # A ``.hermes`` tree nested inside the transient dir is a Hermes home in
    # its own right (a test fixture or a relocated home), not scratch data.
    # The check runs on the UNRESOLVED path too: normalize_path() follows
    # symlinks, so a protected plugin dir reached through one loses the
    # ``.hermes`` component entirely.
    raw_relative = (raw_path or path).rstrip("/")[len(active):].lstrip("/")
    raw_parts = [p for p in raw_relative.split("/") if p]
    if ".hermes" in raw_parts[1:]:
        return False
    return True


def is_protected_path(raw_path: str) -> bool:
    """True if *raw_path* is a persistent-configuration / credential surface."""
    if not raw_path:
        return False
    path = normalize_path(raw_path)
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


def is_control_plane_path(raw_path: str) -> bool:
    """True when *raw_path* is a control-plane surface of the active Hermes home."""
    path = normalize_path(raw_path)
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
    text, _complete = _bounded_arg_strings(args)
    return text


def _arg_scan_complete(args: Any) -> bool:
    """False when the argument payload exceeded the inspection budget."""
    _text, complete = _bounded_arg_strings(args)
    return complete


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


def _shell_tokenize(command: str) -> List[str]:
    """Split a command line into tokens, keeping operators separate.

    ``shlex`` is used as a tokenizer only. It proves nothing about shell
    semantics - it merely lets the resolver below see ``>``, ``>>``, ``|``
    and friends as operators instead of gluing them onto a word.
    """
    if not command:
        return []
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens: List[str] = []
    try:
        for token in lexer:
            tokens.append(token)
    except ValueError:
        # Unbalanced quoting: the command cannot be read reliably, so no
        # destination is claimed from it.
        return []
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


def _shell_verb(segment: Sequence[str]) -> Tuple[str, List[str]]:
    """The effective command of a segment and its arguments."""
    tokens = list(segment)
    while tokens:
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


def _python_write_destinations(code: str) -> List[str]:
    """The files a Python snippet writes to (literal paths only)."""
    if not code:
        return []
    destinations: List[str] = []

    for match in _PY_OPEN_RE.finditer(code):
        mode = match.group(3)
        if any(char in mode for char in "wax+"):
            destinations.append(match.group(2))

    for match in _PY_PATH_RE.finditer(code):
        destinations.append(match.group(2))

    for match in _PY_OS_RE.finditer(code):
        verb = match.group("verb")
        paths = [
            value
            for _quote, value in re.findall(
                r"(['\"])([^'\"]+)\1", match.group("args")
            )
        ]
        if verb in ("rename", "replace"):
            destinations.extend(paths)
        elif paths:
            destinations.append(paths[0])

    for match in _PY_SHUTIL_RE.finditer(code):
        verb = match.group("verb")
        paths = [
            value
            for _quote, value in re.findall(
                r"(['\"])([^'\"]+)\1", match.group("args")
            )
        ]
        if verb in ("rmtree", "move"):
            destinations.extend(paths)
        elif paths:
            destinations.append(paths[-1])

    return destinations


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
    base = cwd or os.getcwd()
    return posixpath.normpath(posixpath.join(base, target))


def _resolve_relative(path: str, cwd: Optional[str]) -> str:
    """Resolve a relative destination against a statically known directory."""
    if not path:
        return ""
    if path.startswith(("/", "~")):
        return path
    if cwd:
        return posixpath.join(cwd, path)
    return path


def _shell_write_destinations(command: str, depth: int = 0) -> List[str]:
    """The files a shell command writes to, when statically resolvable."""
    tokens = _shell_tokenize(command)
    if not tokens:
        return []

    destinations: List[str] = []
    cwd: Optional[str] = None
    scope: List[Optional[str]] = []
    segment: List[str] = []

    def flush() -> None:
        nonlocal segment, cwd
        if not segment:
            return
        verb, args = _shell_verb(segment)
        if verb == "cd":
            resolved = _cd_target(args, cwd)
            if resolved is not None:
                cwd = resolved
        elif verb:
            found = _destinations_for_verb(verb, args, depth)
            found.extend(_redirect_destinations(args))
            for destination in found:
                resolved = _resolve_relative(destination, cwd)
                if resolved:
                    destinations.append(resolved)
        segment = []

    for token in tokens:
        if token == "(":
            flush()
            scope.append(cwd)
            cwd = None
            continue
        if token == ")":
            flush()
            cwd = scope.pop() if scope else None
            continue
        if token in (";", "&&", "||", "|", "&"):
            flush()
            continue
        segment.append(token)
    flush()
    return destinations


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


def extract_exec_write_destinations(tool_name: str, args: Any) -> List[str]:
    """The files an executable call writes to, when statically resolvable.

    Covers shell redirection, in-place editors, copy/move/link/install,
    ``tee``, downloads, explicit Python writes and - where the working
    directory is statically known - relative destinations. Read-only
    commands contribute nothing.
    """
    destinations: List[str] = []
    for text, is_python in _exec_texts(tool_name, args):
        if is_python:
            destinations.extend(_python_write_destinations(text))
        else:
            destinations.extend(_shell_write_destinations(text))
    return _dedupe(destinations)


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


def evaluate_tool_call(tool_name: str, args: Any) -> Verdict:
    """Evaluate a single tool call against the trust boundary.

    Returns a :class:`Verdict`. ``block`` means the call must not execute.
    """
    name = (tool_name or "").lower()
    content = _arg_text(args)
    command = extract_command_text(name, args)
    targets = extract_target_paths(name, args)

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
    if name in EXEC_TOOLS and _disables_firewall_plugin(scan_source):
        return Verdict(
            action="block",
            reason="security_control_disable",
            detail="Blocked: disabling prompt-firewall through Hermes plugin management is not permitted.",
            findings=tuple(findings),
        )
    if disable_hit and _is_real_control_disable(name, targets, scan_source):
        return Verdict(
            action="block",
            reason="security_control_disable",
            detail=(
                "Blocked: the tool call tries to disable security controls "
                f"(pattern {disable_hit.pattern}). The firewall cannot be "
                "switched off from inside a tool call."
            ),
            findings=tuple(findings),
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
        if injection.category != CATEGORY_SECURITY_DISABLE:
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
            return Verdict(
                action="approve",
                reason="firewall_state_mutation",
                detail=(
                    "Approval required: this call changes the firewall's own "
                    f"state ({mutation}) in {normalize_path(state_targets[0])!r}. "
                    "Only a fresh, explicit operator decision may authorize "
                    "it; the firewall never authorizes itself."
                ),
                rule_key=(
                    "prompt-firewall.firewall-state:"
                    f"{normalize_path(state_targets[0])}"
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
        write_targets = extract_exec_write_destinations(name, args)
        protected_exec = [
            t
            for t in write_targets
            if is_protected_path(t) or is_control_plane_path(t)
        ]
        if protected_exec:
            exec_target = protected_exec[0]
            if injection:
                return Verdict(
                    action="block",
                    reason="protected_write_with_injection",
                    detail=(
                        "Blocked: refused to write to protected path "
                        f"{normalize_path(exec_target)!r} because the request "
                        f"carries an injection signature (pattern "
                        f"{injection.pattern})."
                    ),
                    findings=tuple(findings),
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
            return Verdict(
                action="block",
                reason="protected_write_with_injection",
                detail=(
                    "Blocked: refused to write to protected path "
                    f"{target!r} because the content carries an injection "
                    f"signature (pattern {injection.pattern})."
                ),
                findings=tuple(findings),
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
        if mentions_endpoint_change(command):
            hosts = extract_endpoint_hosts(command)
            bad = [h for h in hosts if not endpoint_is_allowlisted(h)]
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

    return Verdict(action="allow", reason="no_violation", findings=tuple(findings))
