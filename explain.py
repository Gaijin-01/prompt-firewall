"""Deterministic, read-only explanation of a command for the approval card.

Purpose
-------
The approval card shows the operator *why* the firewall asked, but for a
plugin rule the card's "command" block is a synthetic label
(``<bash> (plugin approval rule)``) — the real command text never reaches the
operator. This module produces the human-readable explanation that fills that
gap: what the command does, why approval was requested, what the risks are, and
exactly how wide the granted scope will be.

Hard invariants
---------------
1. This module NEVER decides anything. It is called after the verdict exists and
   cannot change it: ``verdict_before == verdict_after``. It never approves,
   never blocks, never downgrades a block to an approval.
2. No LLM calls, no network, no subprocess, no filesystem access, no side
   effects. Pure string analysis over the command text.
3. It never claims safety. There is no "safe", no "no risk", no percentage. The
   only confidence statement is about *completeness of the analysis*, and it is
   phrased as such.
4. It never emits secrets or private paths beyond what the command already
   shows. The caller passes the command as it will be displayed.
5. Fail-safe: any internal problem returns a conservative "could not fully
   parse" explanation. It never guesses.

Honesty rules baked into the text
---------------------------------
* The command text itself is *not* reproduced here — the card cannot show it.
  The operator is told what it *does*, in plain language.
* ``session``/``always`` scope is described as rule-scoped, because that is what
  the Core actually persists (see ``tools/approval.py``: the key is
  ``plugin_rule:<rule_key>``, and the plugin's rule keys are path-scoped).
  Describing it as "this command only" would be a lie.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .strings import current_language, set_language, t

__all__ = [
    "Explanation",
    "explain",
    "explain_command",
    "render_card",
    "render_detail",
]


# --------------------------------------------------------------------------- #
# Limits — the card reason budget is 503 escaped chars (Telegram
# ``_EA_REASON_BUDGET = 500``). Everything is built to fit inside that.
# --------------------------------------------------------------------------- #

MAX_CARD_CHARS = 480          # self-imposed, below Core's 503 after escaping
MAX_DETAIL_CHARS = 4000        # expanded text, shown on request only
MAX_ACTIONS = 6
MAX_RISKS = 5
MAX_COMMAND_CHARS = 4000       # guard against pathological input


# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #

#: verb -> (short purpose, risk). Purpose is what it does; risk is the
#: honest worst case for that verb class, not a certainty.
def _verb_info():
    """Operator-facing mapping, rebuilt for the active language."""
    return     {
        "echo": (t('text.prints_text_to_the_terminal'), t('text.changes_nothing_on_disk')),
        "ls": (t('text.lists_the_directory_contents'), t('text.read_only_but_it_prints_file_names')),
        "find": (t('text.searches_for_files_by_pattern_in_the_dir'),
                 t('text.read_only_may_walk_a_large_number_of_fil')),
        "grep": (t('text.searches_for_strings_in_file_contents'), t('text.read_only_prints_the_matching_lines')),
        "head": (t('text.shows_the_beginning_of_the_file'), t('text.read_only')),
        "tail": (t('text.shows_the_end_of_the_file'), t('text.read_only')),
        "cat": (t('text.prints_the_file_contents'), t('text.read_only_prints_the_contents_in_full')),
        "timeout": (t('text.runs_a_command_with_a_time_limit'),
                    t('text.limits_the_runtime_but_the_command_insid')),
        "curl": (t('text.connects_to_a_network_address_and_prints'),
                 t('text.opens_an_outbound_network_connection_the')),
        "wget": (t('text.downloads_a_file_over_the_network'), t('text.opens_an_outbound_network_connection_and')),
        "rm": (t('text.deletes_files_or_directories'), t('text.deletes_data_recovery_depends_on_the_sys')),
        "mv": (t('text.moves_or_renames_a_file'), t('text.changes_where_the_data_lives')),
        "cp": (t('text.copies_a_file'), t('text.creates_a_new_file_the_original_is_uncha')),
        "tee": (t('text.writes_the_command_output_to_a_file_and_'),
                t('text.writes_data_to_a_file')),
        "ln": (t('text.creates_a_link_to_a_file'), t('text.creates_a_filesystem_entry')),
        "install": (t('text.installs_a_file_into_the_system'), t('text.writes_files_into_system_directories')),
        "mkdir": (t('text.creates_a_directory'), t('text.creates_a_filesystem_entry')),
        "touch": (t('text.creates_or_updates_a_file_by_timestamp'), t('text.changes_file_metadata')),
        "chmod": (t('text.changes_the_access_permissions_of_a_file'), t('text.changes_permissions_affects_access_to_th')),
        "chown": (t('text.changes_the_owner_of_a_file'), t('text.changes_ownership_affects_access_to_the_')),
        "dd": (t('text.copies_blocks_of_data_often_into_a_file_'),
               t('text.writes_data_with_the_wrong_arguments_it_')),
        "systemctl": (t('text.manages_system_services'), t('text.changes_the_state_of_system_services')),
        "service": (t('text.manages_system_services'), t('text.changes_the_state_of_system_services')),
        "kill": (t('text.sends_a_signal_to_a_process'), t('text.interrupts_the_process')),
        "pkill": (t('text.sends_a_signal_to_processes_by_name'), t('text.may_interrupt_several_processes')),
        "git": (t('text.runs_a_repository_operation'), t('text.may_change_the_state_of_the_repository')),
        "docker": (t('text.manages_containers'), t('text.changes_the_state_of_containers')),
        "ssh": (t('text.opens_an_ssh_connection_to_a_remote_host'),
                t('text.sends_data_to_another_host_and_runs_comm')),
        "scp": (t('text.copies_files_to_a_remote_host'), t('text.sends_data_to_another_host')),
        "rsync": (t('text.synchronizes_files_with_a_remote_host'), t('text.transfers_and_modifies_data')),
        "npm": (t('text.manages_node_js_packages'), t('text.may_download_and_run_code_from_the_netwo')),
        "pip": (t('text.manages_python_packages'), t('text.may_download_and_run_code_from_the_netwo')),
        "apt": (t('text.manages_system_packages'), t('text.changes_the_installed_system_packages')),
        "python": (t('text.runs_python_code'), t('text.runs_code_the_effect_depends_on_the_code')),
        "python3": (t('text.runs_python_code'), t('text.runs_code_the_effect_depends_on_the_code')),
    }


#: verbs whose whole purpose is to run something else.
def _shell_runners():
    """Operator-facing mapping, rebuilt for the active language."""
    return     {
        "sh": t('text.runs_a_shell_script'),
        "bash": t('text.runs_a_shell_script'),
        "zsh": t('text.runs_a_shell_script'),
        "dash": t('text.runs_a_shell_script'),
        "ksh": t('text.runs_a_shell_script'),
    }


#: verbs that wrap another command and change its effect.
def _wrappers():
    """Operator-facing mapping, rebuilt for the active language."""
    return     {
        "sudo": t('text.runs_a_command_with_superuser_privileges'),
        "doas": t('text.runs_a_command_with_elevated_privileges'),
        "env": t('text.runs_a_command_with_a_modified_environme'),
        "nohup": t('text.runs_a_command_in_the_background'),
        "time": t('text.measures_how_long_a_command_takes'),
        "xargs": t('text.runs_a_command_for_each_argument_it_find'),
        "watch": t('text.repeats_the_command'),
        "timeout": t('text.runs_a_command_with_a_time_limit'),
    }


#: read-only verbs: they do not change state by themselves.
_READ_VERBS: frozenset = frozenset(
    {"echo", "ls", "find", "grep", "head", "tail", "cat", "wc", "stat", "file",
     "pwd", "date", "whoami", "id", "ps", "df", "du", "which", "type", "env",
     "printenv", "uname", "hostname", "readlink", "realpath", "basename",
     "dirname", "sort", "uniq", "cut", "tr", "sed", "awk", "jq", "diff",
     "cmp", "test", "true", "false", "sleep"}
)

#: verbs that change state on disk.
_WRITE_VERBS: frozenset = frozenset(
    {"rm", "mv", "cp", "mkdir", "touch", "chmod", "chown", "ln", "dd", "tee",
     "truncate", "install", "rsync"}
)

#: verbs that talk to the network.
_NET_VERBS: frozenset = frozenset({"curl", "wget", "ssh", "scp", "sftp", "nc",
                                   "ncat", "telnet", "ftp", "rsync", "npm", "pip"})

#: verbs that run code.
_EXEC_VERBS: frozenset = frozenset({"python", "python3", "node", "perl", "ruby",
                                    "php", "java", "eval"})

#: verbs that destroy data. The operator must see these first, whatever the
#: text budget allows.
_DELETE_VERBS: frozenset = frozenset(
    {"rm", "rmdir", "shred", "srm", "unlink", "mkfs", "truncate", "dd"})

#: verbs that move data to another host.
_EXFIL_VERBS: frozenset = frozenset(
    {"scp", "sftp", "rsync", "ssh", "nc", "ncat", "socat", "ftp", "telnet",
     "mail", "mailx", "sendmail"})

#: verbs that raise privileges. Checked on the RAW first token: stripping the
#: wrapper would otherwise erase the very fact the operator must see.
_PRIV_VERBS: frozenset = frozenset({"sudo", "doas", "su", "pkexec", "setuid"})

#: curl/wget flags that upload data instead of only downloading it.
_UPLOAD_FLAGS: frozenset = frozenset(
    {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
     "-F", "--form", "--form-string", "-T", "--upload-file"})

#: HTTP methods that upload.
_UPLOAD_METHODS: frozenset = frozenset({"POST", "PUT", "PATCH"})

# Severity tiers. The card sorts by severity, so the most dangerous action in
# a chain is what survives the text budget. Deletion ranks first: its
# consequence cannot be undone, and the operator can still prevent it.
SEV_DELETE = 7
SEV_EXFIL = 6
SEV_PRIV = 6
SEV_WRITE = 4
SEV_EXEC = 4
SEV_NET = 3
SEV_REDIRECT = 2
SEV_CHAIN = 2
SEV_SENSITIVE = 2
SEV_NONE = 1


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Explanation:
    """A structured, human-facing description of one flagged tool call."""

    purpose: str = ""
    actions: Tuple[str, ...] = ()
    risk_notes: Tuple[str, ...] = ()
    trigger_reason: str = ""
    approval_scope: str = ""
    unknowns: Tuple[str, ...] = ()
    #: Completeness of the analysis — never a safety claim.
    analysis_complete: bool = True
    lang: str = "ru"

    def as_dict(self) -> Dict[str, object]:
        return {
            "purpose": self.purpose,
            "actions": list(self.actions),
            "risk_notes": list(self.risk_notes),
            "trigger_reason": self.trigger_reason,
            "approval_scope": self.approval_scope,
            "unknowns": list(self.unknowns),
            "analysis_complete": self.analysis_complete,
            "lang": self.lang,
        }


# --------------------------------------------------------------------------- #
# Tokenizing — reuse the plugin's own approach (shlex as a tokenizer only)
# --------------------------------------------------------------------------- #

def _tokenize(command: str) -> List[str]:
    """Split a command into tokens, keeping shell operators separate.

    ``shlex`` is a tokenizer, not a shell parser: it proves nothing about shell
    semantics. Unbalanced quoting yields no tokens, and the caller then says
    "could not fully parse" rather than guessing.
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
        return []
    return tokens


def _split_segments(tokens: Sequence[str]) -> List[List[str]]:
    """Split tokens into command segments on ``;`` ``&&`` ``||`` ``|`` ``&``."""
    segments: List[List[str]] = []
    current: List[str] = []
    for token in tokens:
        if token in (";", "&&", "||", "|", "&", "|&"):
            if current:
                segments.append(current)
            current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _basename(token: str) -> str:
    return os.path.basename(token.rstrip("/")) or token


def _strip_env_assignments(tokens: List[str]) -> List[str]:
    """Drop the ``NAME=value`` assignments that precede a command word.

    ``FOO=1 rm /path`` runs ``rm``. Reading the assignment as the command
    word made the explanation name the wrong command and lose the risk
    signal of the verb that actually runs.
    """
    index = 0
    while index < len(tokens):
        name, sep, _value = tokens[index].partition("=")
        if not sep or not name or not _ENV_ASSIGNMENT_NAME_RE.match(name):
            break
        index += 1
    return list(tokens[index:])


#: The name part of a shell environment assignment (``NAME=value``).
_ENV_ASSIGNMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

def _strip_wrappers(tokens: List[str], include_runners: bool = True) -> List[str]:
    """Drop leading wrapper verbs (and their value-taking options).

    With ``include_runners=False`` a shell runner terminates the strip instead
    of being removed: ``bash -lc '…'`` must not collapse into its payload
    string, because the payload is analysed as a segment of its own.
    """
    wrapper_option_values = {
        "sudo": ("-u", "-g", "-p", "-C", "-h", "-r", "-t", "--user", "--group"),
        "doas": ("-u", "-C", "-s", "--user"),
        "env": ("-u", "-i", "-C", "--chdir", "--unset"),
        "time": ("-f", "-o"),
        "timeout": ("-k", "-s"),
        "xargs": ("-n", "-P", "-I", "-d", "-a"),
    }
    tokens = list(tokens)
    while tokens:
        # An environment assignment (``FOO=1 rm ...``) is not the command:
        # it only sets a variable for the command that follows.
        stripped = _strip_env_assignments(tokens)
        if stripped != tokens:
            tokens = stripped
            continue
        base = _basename(tokens[0])
        if base in _shell_runners() and not include_runners:
            break
        if base not in _wrappers() and base not in _shell_runners():
            break
        consumes = wrapper_option_values.get(base, ())
        tokens = tokens[1:]
        while tokens and tokens[0] in consumes:
            tokens = tokens[1:]
            if tokens:
                tokens = tokens[1:]
        # A shell runner's payload flag (``-c``, ``-lc``) is not the command:
        # skip it so the next token is not mistaken for the verb.
        while tokens and tokens[0] in _SHELL_RUNNER_PAYLOAD_FLAGS:
            tokens = tokens[1:]
    return tokens


# --------------------------------------------------------------------------- #
# Feature detection
# --------------------------------------------------------------------------- #

def _has_redirect(tokens: Sequence[str]) -> bool:
    return any(t in (">", ">>", "&>", "&>>", ">|", "<") for t in tokens)


def _has_pipeline(tokens: Sequence[str]) -> bool:
    return "|" in tokens or "|&" in tokens


def _has_chaining(tokens: Sequence[str]) -> bool:
    return any(t in (";", "&&", "||", "&") for t in tokens)


def _nested_shell(tokens: Sequence[str]) -> Optional[str]:
    """The shell used as an inner interpreter, if the command starts one."""
    for token in tokens:
        base = _basename(token)
        if base in _shell_runners():
            return base
        if base not in _wrappers():
            return None
    return None


def _dev_tcp(tokens: Sequence[str]) -> bool:
    return any("/dev/tcp/" in t for t in tokens)


def _substitution_payloads(command: str) -> List[str]:
    """The text of every ``$( … )`` and backtick substitution in *command*.

    ``echo $(rm -rf DIR)`` runs ``rm``: the substitution is a command, not
    decoration, and it must be analysed like any other segment. The tokenizer
    splits ``$(`` into separate punctuation tokens, so the payloads have to be
    recovered from the raw text.
    """
    payloads: List[str] = []
    index = 0
    length = len(command)
    while index < length:
        if command.startswith("$(", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if command[cursor] == "(":
                    depth += 1
                elif command[cursor] == ")":
                    depth -= 1
                cursor += 1
            if depth == 0:
                payloads.append(command[index + 2:cursor - 1])
                index = cursor
                continue
            # Unbalanced: the substitution is cut off, which is itself a sign
            # that the command was truncated.
            payloads.append(command[index + 2:])
            break
        index += 1
    for match in re.finditer(r"`([^`]*)`", command):
        payloads.append(match.group(1))
    return payloads


def _substitution(command: str) -> bool:
    """Command substitution or eval present: analysis cannot be complete.

    Detected on the RAW text: the tokenizer turns ``$(`` into separate
    punctuation tokens, so a token-level check silently misses it.
    """
    if "$(" in command or "`" in command:
        return True
    try:
        tokens = _tokenize(command)
    except Exception:
        tokens = []
    return any(token in ("eval", "exec", "source") for token in tokens)


def _ends_mid_chain(command: str) -> bool:
    """True when the command stops on an operator: it looks cut off."""
    stripped = command.rstrip()
    if not stripped:
        return False
    if stripped.endswith(("|", "&", ">", "`")):
        return True
    if stripped.endswith("$(") or stripped.endswith("("):
        return True
    return False


def _is_upload(segment: Sequence[str]) -> bool:
    """True when the segment sends data out, rather than only fetching it."""
    for index, token in enumerate(segment):
        base = _basename(token)
        if base not in ("curl", "wget", "http", "httpie"):
            continue
        for item in segment[index + 1:]:
            if item in _UPLOAD_FLAGS:
                return True
            if item.upper() in _UPLOAD_METHODS:
                return True
            if item.startswith("-X") and item[2:].upper() in _UPLOAD_METHODS:
                return True
    return False


def _segment_verb_info(segment: Sequence[str]) -> Tuple[Optional[str], bool, bool]:
    """``(acting verb, raises privileges, uploads data)`` for one segment.

    The privilege flag is read from the RAW first token: stripping the
    wrapper would erase the very fact the operator must see.
    """
    if not segment:
        return None, False, False
    first = _basename(segment[0])
    privileged = first in _PRIV_VERBS
    stripped = _strip_wrappers(list(segment), include_runners=False)
    verb = _basename(stripped[0]) if stripped else None
    if verb in _shell_runners():
        # The runner is not the acting verb: its payload is analysed as a
        # segment of its own.
        verb = None
    return verb, privileged, _is_upload(segment)


def _segment_summary(segment: Sequence[str]) -> Optional[Tuple[int, str]]:
    """``(severity, plain-language action)`` for one segment, or None."""
    verb, privileged, uploads = _segment_verb_info(segment)
    if verb is None:
        return None
    severity = SEV_NONE
    parts: List[str] = []
    has_redirect = _has_redirect(segment)
    if verb in _DELETE_VERBS:
        severity = max(severity, SEV_DELETE)
        parts.append(_verb_info().get(verb, (t('text.deletes_data'), ""))[0])
    if uploads or verb in _EXFIL_VERBS:
        severity = max(severity, SEV_EXFIL)
        parts.append(t('text.sends_data_out'))
    if privileged:
        severity = max(severity, SEV_PRIV)
        parts.append(t('text.runs_with_elevated_privileges'))
    if verb in _WRITE_VERBS and verb not in _DELETE_VERBS:
        severity = max(severity, SEV_WRITE)
        parts.append(t('text.changes_files_on_disk'))
    if has_redirect and verb not in _WRITE_VERBS and verb not in _DELETE_VERBS:
        severity = max(severity, SEV_WRITE)
        parts.append(t('text.writes_output_to_a_file_redirect'))
    if verb in _EXEC_VERBS:
        severity = max(severity, SEV_EXEC)
        parts.append(t('text.runs_code_whose_effect_is_not_known_in_a'))
    if verb in _NET_VERBS:
        severity = max(severity, SEV_NET)
        parts.append(_verb_info().get(verb, (t('text.reaches_out'), ""))[0])
    if not parts:
        purpose, _ = _verb_info().get(verb, (None, None))
        if purpose is None:
            purpose = f"{t('text.runs_the_command')}{verb!r}"
        parts.append(purpose)
    return severity, "; ".join(parts)


def _ranked_actions(units: Sequence[Sequence[str]]) -> List[Tuple[int, str]]:
    """``(severity, action)`` for every segment of the command, worst first."""
    actions: List[Tuple[int, str]] = []
    seen: List[str] = []
    for tokens in units:
        for segment in _all_segments(tokens):
            summary = _segment_summary(segment)
            if summary is None:
                continue
            severity, text = summary
            if text in seen:
                continue
            seen.append(text)
            actions.append((severity, text))
    actions.sort(key=lambda item: -item[0])
    return actions


def _classify_verb(tokens: Sequence[str]) -> Optional[str]:
    stripped = _strip_wrappers(list(tokens))
    if not stripped:
        return None
    return _basename(stripped[0])


# --------------------------------------------------------------------------- #
# Purpose
# --------------------------------------------------------------------------- #

def _purpose(units: Sequence[Sequence[str]]) -> str:
    """One plain-language sentence describing what the command does.

    The chain's most dangerous action leads: the operator must learn what the
    command really does before anything else.
    """
    actions = _ranked_actions(units)
    if not actions:
        return t('text.could_not_parse_the_command')

    top = actions[0][1]
    tokens = units[0] if units else []
    if _nested_shell(tokens):
        return f"{top}{t('text.through_a_nested_shell')}"
    if len(actions) > 1:
        return f"{t('text.chain_of_commands_most_dangerous')}{top}"
    return top


#: Options of a shell runner that carry the command to run (``sh -c '…'``).
_SHELL_RUNNER_PAYLOAD_FLAGS: frozenset = frozenset({"-c", "-lc", "-ic", "-cl", "-ci"})


def _shell_payload(tokens: Sequence[str]) -> List[str]:
    """Tokens of the command carried by a ``sh -c '…'`` style runner.

    ``bash -lc 'curl … | tee …'`` runs an entire command line that this
    function must expose to the risk analysis — otherwise the outer segment
    looks like a harmless ``bash`` while the payload does the real work.
    """
    for index, token in enumerate(tokens):
        base = _basename(token)
        if base not in _shell_runners():
            continue
        rest = list(tokens[index + 1:])
        # The payload flag itself may be bundled: ``-lc`` carries the command.
        for candidate in rest:
            if candidate in _SHELL_RUNNER_PAYLOAD_FLAGS:
                continue
            if candidate.startswith("-") and len(candidate) <= 3:
                continue  # another option of the runner, e.g. ``-x``
            return _tokenize(candidate)
    return []


def _inner_command_summary(tokens: Sequence[str]) -> str:
    """Describe the command inside a ``sh -c '…'`` wrapper."""
    inner_tokens = _shell_payload(tokens)
    if not inner_tokens:
        return ""
    inner_verb = _classify_verb(inner_tokens)
    inner_purpose, _ = _verb_info().get(inner_verb or "", (None, None))
    if inner_purpose:
        return inner_purpose
    return f"{t('text.runs')}{inner_verb!r}" if inner_verb else ""


# --------------------------------------------------------------------------- #
# Risks
# --------------------------------------------------------------------------- #

def _all_segments(tokens: Sequence[str], depth: int = 0) -> List[List[str]]:
    """Every command segment, including the payload of a nested shell.

    ``bash -lc 'curl … | tee …'`` has two real commands in it: the outer
    ``bash`` and the inner pipeline. The inner one is what actually touches
    the network or the disk, so the risk analysis must see it.
    """
    segments = list(_split_segments(tokens))
    if depth >= 3:
        return segments
    for segment in segments:
        payload = _shell_payload(segment)
        if payload:
            segments.extend(_all_segments(payload, depth + 1))
    return segments


def _ranked_risks(units: Sequence[Sequence[str]]) -> List[Tuple[int, str]]:
    """``(severity, risk)`` pairs for the whole command, worst first.

    Sorted by severity so the risk line of the card leads with the most
    dangerous action: deletion, outbound transfer and privilege escalation
    must not be pushed out by the text budget.
    """
    verbs: set = set()
    privileged = False
    uploads = False
    segments: List[List[str]] = []
    for tokens in units:
        segments.extend(_all_segments(tokens))
        for segment in _all_segments(tokens):
            verb, priv, upl = _segment_verb_info(segment)
            if verb:
                verbs.add(verb)
            privileged = privileged or priv
            uploads = uploads or upl

    ranked: List[Tuple[int, str]] = []
    if verbs & _DELETE_VERBS:
        ranked.append((SEV_DELETE, t('text.deletes_data')))
    if uploads or (verbs & _EXFIL_VERBS):
        ranked.append((SEV_EXFIL, t('text.sends_data_out')))
    if privileged:
        ranked.append((SEV_PRIV, t('text.runs_with_elevated_privileges')))
    if (verbs & _WRITE_VERBS) - _DELETE_VERBS:
        ranked.append((SEV_WRITE, t('text.changes_files_on_disk')))
    if verbs & _EXEC_VERBS:
        ranked.append((SEV_EXEC, t('text.runs_code_whose_effect_is_not_known_in_a')))
    if verbs & _NET_VERBS:
        ranked.append((SEV_NET, t('text.opens_an_outbound_network_connection')))
    if any(_has_redirect(segment) for segment in segments):
        ranked.append((SEV_REDIRECT, t('text.redirects_output_to_a_file')))
    if any(_has_pipeline(segment) for segment in segments):
        ranked.append((SEV_CHAIN, t('text.pipeline_the_output_of_one_command_is_fe')))
    if any(_has_chaining(segment) for segment in segments):
        ranked.append((SEV_CHAIN, t('text.command_chain_several_commands_run_in_se')))
    if any(_dev_tcp(segment) for segment in segments):
        ranked.append((SEV_NET, t('text.opens_a_network_connection_directly_thro')))

    # A read of a sensitive-looking path is worth flagging.
    joined = " ".join(" ".join(tokens) for tokens in units)
    for marker in (".env", "id_rsa", "id_ed25519", "credentials", "secret",
                   ".aws/", ".ssh/", ".gnupg", "config.yaml"):
        if marker in joined:
            ranked.append((SEV_SENSITIVE,
                           t('text.touches_a_path_that_looks_like_configura')))
            break

    ranked.sort(key=lambda item: -item[0])
    return ranked[:MAX_RISKS]


# --------------------------------------------------------------------------- #
# Unknowns
# --------------------------------------------------------------------------- #

def _unknowns(tokens: Sequence[str], command: str, truncated: bool) -> List[str]:
    """Every reason the analysis is not complete.

    A non-empty result means the card must NOT claim a complete analysis.
    """
    unknowns: List[str] = []
    if not tokens:
        unknowns.append(t('text.the_command_could_not_be_parsed_in_full'))
        return unknowns
    if truncated:
        unknowns.append(t('text.the_command_is_longer_than_the_parsing_l'))
    if _substitution(command):
        unknowns.append(t('text.it_contains_a_substitution_or_eval_its_c'))
    if _nested_shell(tokens):
        unknowns.append(t('text.the_nested_command_was_not_parsed_in_ful'))
    if _dev_tcp(tokens):
        unknowns.append(t('text.direct_network_connections_were_not_chec'))
    if _ends_mid_chain(command):
        unknowns.append(t('text.the_command_looks_truncated_the_command_'))
    return unknowns


# --------------------------------------------------------------------------- #
# Approval scope — described from what Core actually persists
# --------------------------------------------------------------------------- #

def _scope_text(rule_key: str, lang: str = "ru") -> str:
    """Describe the real width of a granted approval.

    The Core persists ``plugin_rule:<rule_key>`` (see ``tools/approval.py``)
    and matches that key exactly, so a grant covers *every* call that produces
    the same rule key — not just the command that triggered the card. For the
    firewall the rule keys are path-scoped, so the scope is a specific file, a
    specific directory, or the whole rule. Which one it is must be stated:
    "some other command" would be a lie, and so would "the whole rule" when
    the key names one file.
    """
    kind, target = _scope_target(rule_key)
    shown = _clip_path(target)
    # The kind comes FIRST: the card clips this line, and a long path at
    # the front would eat the very word that says what the grant covers.
    if kind == "file":
        return t('scope.file') + shown
    if kind == "dir":
        return t('scope.directory') + shown
    if kind == "path":
        return t('scope.path') + shown
    if kind == "tool":
        return t('scope.tool') + shown + t('scope.always_on_disk')
    if kind == "rule":
        return t('scope.rule') + shown + t('scope.rule_tail')
    return t('scope.unknown')


#: Rule-key prefixes that name a single filesystem path.
_PATH_RULE_PREFIXES = (
    "prompt-firewall.protected-write:",
    "prompt-firewall.firewall-state:",
    "prompt-firewall.credential-read:",
)


def _scope_target(rule_key: str) -> Tuple[str, str]:
    """``(kind, target)`` — what a granted approval really covers.

    kind is one of ``file``, ``dir``, ``path`` (a path whose file/directory
    nature the rule does not state), ``tool``, ``rule`` or ``unknown``.
    """
    if not rule_key:
        return "unknown", ""
    for prefix in _PATH_RULE_PREFIXES:
        if rule_key.startswith(prefix):
            path = rule_key[len(prefix):]
            return _classify_path_kind(path), path
    if rule_key.startswith("prompt-firewall.unverified-operation:"):
        rest = rule_key.split(":", 2)
        name = rest[1] if len(rest) > 1 else ""
        return "tool", name
    if rule_key.startswith("prompt-firewall.scheduled-task-content:"):
        return "rule", rule_key.split(":", 1)[1]
    if rule_key == "prompt-firewall.control-plane":
        return "rule", "control-plane"
    return "unknown", rule_key


def _classify_path_kind(path: str) -> str:
    """``file``, ``dir`` or ``path`` for a rule-key path.

    The rule key stores the path string only; whether it names a file or a
    directory is known from the firewall's own protected-surface tables. When
    the path is not one of those surfaces the distinction is not available, and
    ``path`` says so instead of guessing.
    """
    if not path:
        return "unknown"
    try:
        from .policy import (PROTECTED_HERMES_HOME_DIRS, PROTECTED_HERMES_HOME_FILES,
                             PROTECTED_HOME_DIRS, PROTECTED_HOME_FILES)
    except Exception:
        return "path"
    normalized = path.rstrip("/")
    for relative in tuple(PROTECTED_HOME_DIRS) + tuple(PROTECTED_HERMES_HOME_DIRS):
        if normalized.endswith("/" + relative) or normalized == relative:
            return "dir"
    for relative in tuple(PROTECTED_HOME_FILES) + tuple(PROTECTED_HERMES_HOME_FILES):
        if normalized.endswith("/" + relative) or normalized == relative:
            return "file"
    return "path"


def _clip_path(path: str, limit: int = 60) -> str:
    """Shorten a path for the card without losing its tail."""
    text = str(path or "")
    if len(text) <= limit:
        return text
    return "…" + text[-(limit - 1):]


# --------------------------------------------------------------------------- #
# Trigger reason — plain language per firewall reason code
# --------------------------------------------------------------------------- #

def _reason_text():
    """Operator-facing mapping, rebuilt for the active language."""
    return     {
        "protected_write_unverifiable": (
            t('text.write_to_a_protected_path_the_content_ca')),
        "protected_write": t('text.write_to_a_protected_path'),
        "firewall_state_mutation": t('text.change_to_the_firewall_s_own_state'),
        "firewall_state_removal": t('text.removal_of_a_firewall_record'),
        "credential_read": t('text.read_of_a_path_that_looks_like_credentia'),
        "unverified_scoped_operation": (
            t('text.an_operation_the_firewall_could_not_clas')),
        "scheduled_task_unverifiable_content": (
            t('text.a_scheduled_task_with_unverifiable_conte')),
        "argument_scan_budget_exceeded": (
            t('text.the_arguments_are_too_large_or_too_deepl')),
        "unverified_operation": t('text.an_operation_the_firewall_could_not_clas'),
    }



def _trigger_text(reason: str, detail: str) -> str:
    """Short plain-language cause. Falls back to the detail, then to the code."""
    if reason in _reason_text():
        return _reason_text()[reason]
    if detail:
        # The detail is already an English sentence; keep it but mark it as the
        # firewall's own wording rather than inventing a translation.
        return f"{t('reason.matched')}{reason})"
    return f"{t('reason.matched')}{reason})"


# --------------------------------------------------------------------------- #
# Tool-level explanation (calls that carry no shell command)
# --------------------------------------------------------------------------- #

#: Tool -> (what it does, the risk of doing it), for calls with no command text.
def _tool_info():
    """Operator-facing mapping, rebuilt for the active language."""
    return     {
        "write": (t('text.writes_content_to_a_file'),
                  t('text.changes_the_file_contents_on_disk')),
        "write_file": (t('text.writes_content_to_a_file'),
                       t('text.changes_the_file_contents_on_disk')),
        "edit": (t('text.edits_a_file_in_place'), t('text.changes_the_file_contents_on_disk')),
        "multiedit": (t('text.edits_several_places_in_a_file'),
                      t('text.changes_the_file_contents_on_disk')),
        "patch": (t('text.applies_changes_to_a_file'), t('text.changes_the_file_contents_on_disk')),
        "create": (t('text.creates_a_file'), t('text.creates_a_filesystem_entry')),
        "delete": (t('text.deletes_a_file'), t('text.deletes_data')),
        "remove": (t('text.deletes_a_file'), t('text.deletes_data')),
        "move": (t('text.moves_a_file'), t('text.changes_where_the_data_lives')),
        "copy": (t('text.copies_a_file'), t('text.creates_a_new_file')),
        "read": (t('text.reads_a_file'), t('text.read_only_prints_the_file_contents')),
        "read_file": (t('text.reads_a_file'), t('text.read_only_prints_the_file_contents')),
        "download": (t('text.downloads_a_file_over_the_network'), t('text.opens_an_outbound_network_connection')),
        "upload": (t('text.uploads_a_file_over_the_network'), t('text.sends_data_out')),
        "browser": (t('text.drives_a_browser'), t('text.reaches_external_websites')),
        "web_search": (t('text.searches_the_web_for_information'), t('text.opens_an_outbound_network_connection')),
        "cronjob_manage": (t('text.manages_scheduled_tasks'),
                            t('text.creates_or_changes_tasks_that_run_later')),
        "memory": (t('text.changes_the_agent_s_long_term_memory'),
                   t('text.writes_data_to_persistent_storage')),
    }



def explain_tool_call(tool_name: str, args: Any, *, reason: str = "",
                      rule_key: str = "", lang: str = "") -> Explanation:
    """Explain a tool call that carries no shell command.

    A write-tool call has no command text to parse, but it is one of the most
    common cases that reach the approval card, so it still gets a real
    explanation: what the tool does, and what it would change.
    """
    lang = set_language(lang or current_language())
    name = (tool_name or "").lower()
    purpose, risk = _tool_info().get(name, (None, None))
    if purpose is None:
        purpose = f"{t('text.runs_the')}{name!r}{t('text.tool')}"
        risk = t('text.the_purpose_of_the_tool_was_not_recognis')

    paths: List[str] = []
    try:
        from .policy import extract_target_paths
        paths = list(extract_target_paths(tool_name, args) or [])[:3]
    except Exception:
        paths = []

    risks = [risk]
    if paths:
        risks.append(t('text.touches_a_protected_path_the_content_can'))

    # A tool call carries data, not a command: its content is never analysed,
    # so the analysis is never complete. Say so instead of implying that the
    # operation was understood in full.
    unknowns = [t('text.the_content_of_the_operation_is_not_pars')]
    if not paths:
        unknowns.append(t('text.the_target_of_the_operation_is_not_named'))

    return Explanation(
        purpose=purpose,
        actions=(f"{t('text.target')}{paths[0]}",) if paths else (),
        risk_notes=tuple(risks[:MAX_RISKS]),
        trigger_reason=_trigger_text(reason, ""),
        approval_scope=_scope_text(rule_key, lang),
        unknowns=tuple(unknowns),
        analysis_complete=False,
        lang=lang,
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def explain_command(command: str, *, reason: str = "", rule_key: str = "",
                    lang: str = "") -> Explanation:
    """Build a structured :class:`Explanation` for *command*.

    Pure: no verdict, no I/O, no side effects.
    """
    lang = set_language(lang or current_language())
    raw = command or ""
    truncated = len(raw) > MAX_COMMAND_CHARS
    text = raw[:MAX_COMMAND_CHARS] if truncated else raw

    tokens = _tokenize(text)
    parsed = bool(tokens)

    # A ``$( … )`` payload is a command of its own: it must be analysed with
    # the rest, or a hidden ``rm`` would go unmentioned.
    units: List[List[str]] = [tokens] if parsed else []
    for payload in _substitution_payloads(text):
        payload_tokens = _tokenize(payload)
        if payload_tokens:
            units.append(payload_tokens)

    unknowns = _unknowns(tokens, text, truncated)
    complete = parsed and not unknowns

    if units:
        purpose = _purpose(units)
        actions = [text for _, text in _ranked_actions(units)][:MAX_ACTIONS]
        ranked = _ranked_risks(units)
    else:
        purpose = t('text.could_not_parse_the_command')
        actions = []
        ranked = []

    risks = [text for _, text in ranked]
    if not risks:
        if complete:
            # Say what the analysis actually established, not that the command
            # is safe: an empty risk list means "nothing risky was
            # recognised", which is a statement about the analysis.
            risks.append(t('text.the_analysis_found_no_signs_of_writing_n'))
        else:
            risks.append(t('text.the_analysis_is_incomplete_the_signs_fou'))

    return Explanation(
        purpose=purpose,
        actions=tuple(actions),
        risk_notes=tuple(risks[:MAX_RISKS]),
        trigger_reason=_trigger_text(reason, ""),
        approval_scope=_scope_text(rule_key, lang),
        unknowns=tuple(unknowns),
        analysis_complete=complete,
        lang=lang,
    )


def explain(command: str, reason: str = "", scope: str = "", *,
            rule_key: str = "", lang: str = "") -> Explanation:
    """Convenience wrapper: ``explain(command, reason, scope)``.

    *scope* is accepted for call-site symmetry with the card renderer; the
    authoritative scope text is derived from *rule_key* because only the Core
    knows what a key really persists.
    """
    return explain_command(command, reason=reason, rule_key=rule_key or scope, lang=lang)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def render_card(explanation: Explanation, *, max_chars: int = MAX_CARD_CHARS) -> str:
    """Render the short card: what it does, why, the risk, the scope.

    Fits the Core reason budget. Deliberately terse — the operator reads this on
    a phone, mid-task.

    The budget is allocated by priority, not by truncation order: the danger
    line and the incompleteness marker are allocated FIRST, so deletion,
    outbound transfer and privilege escalation cannot be pushed off the card
    by a verbose scope or purpose line.
    """
    entries = [
        (3, 0, t('text.what_it_does'), explanation.purpose, 110),
        (2, 1, t('text.why_it_asks'), explanation.trigger_reason, 120),
        (0, 2, t('text.most_dangerous'), "; ".join(explanation.risk_notes[:3]), 165),
        (1, 3, t('text.scope'), explanation.approval_scope, 150),
        (0, 4, t('text.analysis'), "" if explanation.analysis_complete else
         t('text.incomplete_only_what_was_recognised_is_s'), 60),
    ]
    allocated: Dict[int, str] = {}
    remaining = max_chars
    for _priority, index, prefix, text, cap in sorted(entries, key=lambda e: (e[0], e[1])):
        if not text:
            continue
        overhead = len(prefix)
        if remaining < overhead + 12:
            continue
        room = min(cap, remaining - overhead)
        line = prefix + _clip(text, room)
        allocated[index] = line
        remaining -= len(line) + 1
    return "\n".join(allocated[index] for index in sorted(allocated))


def render_detail(explanation: Explanation, *, max_chars: int = MAX_DETAIL_CHARS) -> str:
    """Render the expanded breakdown (offered only where the UI can expand)."""
    lines: List[str] = []
    if explanation.purpose:
        lines.append(f"{t('text.what_it_does')}{explanation.purpose}")
    if explanation.actions:
        lines.append(t('text.parts') + "; ".join(explanation.actions))
    if explanation.trigger_reason:
        lines.append(f"{t('text.why_it_asks')}{explanation.trigger_reason}")
    if explanation.risk_notes:
        lines.append(t('text.risks') + "; ".join(explanation.risk_notes))
    if explanation.approval_scope:
        lines.append(f"{t('text.scope')}{explanation.approval_scope}")
    if explanation.unknowns:
        lines.append(t('text.what_stayed_unverified') + "; ".join(explanation.unknowns))
    lines.append(
        t('text.command_analysis') + (t('text.complete') if explanation.analysis_complete
                               else t('text.incomplete_some_nested_constructs_were_n'))
    )
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = _clip(text, max_chars)
    return text
