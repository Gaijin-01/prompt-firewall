# prompt-firewall

A deterministic prompt-injection firewall for [Hermes Agent](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins).

## Release 1.1.7 (final release candidate)

Version 1.1.7 supersedes the published 1.1.6 baseline. The frozen 1.1.7 checkpoint
(commit 9557c24e) is preserved unchanged for rollback; this RC adds, on top of it:

- **G1 destination gate** — scanner-independent, destination-based blocking of writes to durable
  instruction surfaces (`AGENTS.md` / `SKILL.md`) and the Firewall's own code/config/state, even
  outside protected roots and through symlink aliases. Forced-zero-scanner attack capture rose
  from 10/19 to 14/19; baseline 14/19 → 17/19.
- **E1 encoding normalization** — sparse percent-escapes and backslash-Unicode (`\uXXXX`,
  `\UXXXXXXXX`, `\xXX`) decoded before scanning; encoded attacks 0/70 → 70/70, 0 false positives
  on 1,758 benign documents.
- **Lazy `_FrameIndex`** — stdlib-only optimization; the frame index is built only when needed.
  ~1.64× faster on a 400 KB benign scan (p50 1010 ms → 618 ms), no behavior change.
- **Scoped Intent Grant** — a fail-closed, one-shot operator authorization for an exact reviewed
  write to a durable instruction surface: anchored whole-message command, authenticated sender
  against the configured operator allowlist, canonical path + SHA-256 of the exact content + turn
  scope + TTL. A grant lifts ONLY the destination-specific denial; the full policy always runs and
  the grant is consumed exactly once at the final decision. It never downgrades protection for the
  Firewall's own paths.
- **F2 credential protection** — corrected directory-scoped classification of `~/.aws/credentials`
  (a project file merely named `credentials` is not reclassified). Dangerous credential mutations
  and firewall-disable attempts now resolve to BLOCK rather than a potentially auto-approved APPROVE.

Known limitations (documented, not closed): Core-level TOCTOU on final-component inode swap;
operator phishing (bounded by one-shot/path/turn/content-hash/TTL); content-injection detection
remains scanner-dependent; grant provenance is narrower than full gateway authorization
(pairing/profile-only users excluded). See `gates/AUTHORIZATION_DESIGN.md` in the release archive.

It watches the **trust boundary**: content that arrives from outside (web pages, repository files, `README`/`AGENTS.md`/`SKILL.md`, downloaded documents, tool results) is *data*, never *authorization*. The plugin quarantines injection-shaped content before it reaches the model, and blocks at the action boundary any attempt to turn that content into agent instructions, skills, endpoints or configuration.

- **No LLM calls.** Every decision is a regex + policy evaluation.
- **No network access. No external dependencies.** Python standard library only.
- **Deterministic.** Same input -> same verdict, every time.
- **Public plugin surfaces only.** Three native Hermes hooks, no core changes, no monkey-patching.

## Install

From the Hermes plugin catalog, once this version is listed there (the catalog currently points at an earlier release):

```bash
hermes plugins install prompt-firewall
hermes plugins enable prompt-firewall
```

From a local checkout:

```bash
hermes plugins install /path/to/prompt-firewall
hermes plugins enable prompt-firewall
```

Or copy the plugin directory into `~/.hermes/plugins/prompt-firewall/` and run `hermes plugins enable prompt-firewall`.

## Declared capabilities

The plugin registers exactly three hooks, and nothing else:

| Hook | What it does |
|---|---|
| `transform_tool_result` | quarantines injection-shaped spans in untrusted tool output |
| `pre_tool_call` | evaluates a risky tool action and can return `block` or `approve` |
| `pre_llm_call` | states the trust boundary in the operator's turn and captures a Scoped Intent Grant from an explicit operator authorization command |

It registers no tools, no middleware and no provider profiles. It reads no credential stores. Two environment variables are read, and they are not equivalent: `HERMES_LANGUAGE` changes presentation only, while `HERMES_HOME` selects the active Hermes root and therefore the protected-path set.

`HERMES_LANGUAGE` selects the language of the approval card (section 4); it never influences a verdict. `HERMES_HOME` selects the active Hermes root - the home whose configuration, plugin directory and audit log are protected - so it does affect protected-path classification and can change the verdict for a path inside that home.

## What it does

### 1. `transform_tool_result` - quarantine untrusted output

Every non-trivial tool result is scanned. When an injection shape is found, the matched span is replaced with a `[QUARANTINED:<category>]` marker and the surrounding legitimate content is left untouched. The agent sees the *shape* of the problem without being handed the payload.

Detected shapes:

| Category | Examples |
|---|---|
| `instruction_override` | claims that earlier directives no longer apply; the matched span becomes a marker |
| `role_spoof` | forged system/developer turns, chat-template control tokens, persona takeover |
| `persistent_prompt_modification` | activation-word greeting hijacks, "reply with exactly" style capture |
| `malicious_gateway_redirect` | endpoint rebinding towards a non-allowlisted host, advertised API relays |
| `encoded_payload` | base64 / hex / percent-encoded payloads and backslash-Unicode escapes (`\uXXXX`, `\UXXXXXXXX`, `\xXX`) - decoded, then re-scanned |
| `security_control_disable` | attempts to switch off the firewall or other security controls |

### 2. `pre_tool_call` - enforce at the action boundary

Content cannot authorize itself. These are blocked outright:

- writes of instruction-shaped content into agent instruction files, e.g. `AGENTS.md`, `CLAUDE.md`, `SOUL.md`, `SKILL.md`;
- installing a Skill that carries injection content;
- redirecting the model endpoint to a non-allowlisted host - the URL must be
  *bound* to an endpoint key (`base_url: <url>`, `OPENAI_BASE_URL=<url>`,
  `hermes config set providers.ollama.api <url>`) **and** the write must land on a
  protected endpoint-config surface (`config.yaml`, `.env`, `plugin.yaml`, ...).
  A URL that merely sits next to the word *endpoint* in prose, source code or
  documentation is not an endpoint change and is not blocked;
- writing to a protected surface (config, prompts, memory, plugin settings, credential paths) with injection content;
- any attempt to disable the firewall or another safety control.

A plain, injection-free write to a protected surface is **not** blocked - it is passed through to Hermes' existing approval mechanism, so an explicitly authorized configuration change still works. The protected-surface path sets live in `policy.py`, not in this document.

### 3. `pre_llm_call` - state the trust boundary and capture operator grants

Injects a short notice into the operator's turn reminding the model that external content is data. It never overrides operator instructions.

In v1.1.7 this hook also captures a **Scoped Intent Grant**: when the authenticated operator sends an explicit, anchored authorization command on a trusted user-facing channel, the hook records a one-shot grant bound to the exact canonical path, the SHA-256 of the exact proposed content, the current session/turn, and a 600-second TTL. The grant later lifts ONLY the destination-specific instruction-write denial in `pre_tool_call`; every other policy check still runs and the grant is consumed exactly once at the final decision. It never applies to the Firewall's own code/config/state paths.

The command must be the whole message (anchored), from a sender on the configured `<PLATFORM>_ALLOWED_USERS` allowlist, on a trusted platform (webhook/cron/subagent/synthetic turns are denied). Practical form:

```
authorize write to /home/operator/project/AGENTS.md sha256 <64-hex-sha256-of-the-exact-content>
```

For example, to authorize an exact reviewed edit whose content hashes to
`2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae`:

```
authorize write to /home/operator/project/AGENTS.md sha256 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
```

The subsequent `write_file` to that exact path with byte-identical content is then allowed once; any change to the path or content, reuse, expiry, or a non-matching sender fails closed. This is a deliberate operator convention on a trusted channel, not cryptographic proof of physical human confirmation.

### 4. Approval card - what the operator is asked to approve

When Hermes Core asks the operator for approval, the plugin attaches a short
plain-language explanation of the pending action: what the command does, which paths or
systems it touches, what data it could copy out, and what privilege it escalates to. The
explanation is produced by a local string analysis (`explain.py`) - no LLM call, no
network, no subprocess, no filesystem access beyond reading the operator's own session.

The explanation never changes the verdict. It is attached to the `approve` message that
Core already renders; if the explain engine fails for any reason, the card falls back to
the unmodified firewall message, so the card can never affect enforcement.

**Localized cards.** The card is rendered in the operator's language. The language is
resolved only from trusted sources, in this order:

1. `HERMES_LANGUAGE` in the environment;
2. an explicitly written `display.language` in the Hermes configuration
   (the merged configuration always carries an injected default, which is
   not a choice and must not outrank the operator's own words);
3. the operator's own last few messages in the current session;
4. English (fallback).

Untrusted content - the command under approval, tool output, `README`/`AGENTS.md`,
downloaded documents - is never used as a language signal, and a command that asks for
another language does not switch the card. Operator messages are read to pick the
language; they are never stored by the plugin. Three catalogs ship with the plugin:
English, Russian and Simplified Chinese. Code, commands, paths and technical identifiers
are never translated.

Hermes Core does not currently expose a signal for "the operator explicitly chose a
language": the merged configuration always carries a default `display.language`,
so a plugin cannot tell an explicit choice from the default by reading it. The
plugin therefore reads the raw configuration file, where only what the operator
actually wrote is present, and falls back to the operator's own messages.

## Design notes

**Structure, not keywords.** A README quoting an override phrase inside a security write-up is legitimate; the same phrase aimed at the agent is not. Rules therefore require an explicit agent-directed frame (an imperative addressed to the reader, or a role/identity spoof) rather than the bare presence of a phrase.

One family of rules is frame-gated: a phrase that switches a *generic* safety control off is reported only when it reads as an instruction. A sentence *describing* such an attempt is documentation; a sentence *issuing* one is an attack. Rules that name the firewall itself are never gated - they are unambiguous in any context.

**Coordinates in one space.** Results arrive as a JSON envelope but are scanned and patched in the *decoded* content space, so a quarantine marker can never land on the wrong character of a neighbouring line.

**Fail closed where it matters.** Unknown provenance on a protected write is refused. Read-only content is flagged rather than blocked, so legitimate research work keeps working.

- A stock container/browser flag such as `--no-sandbox` inside a process listing is not a
  control disable; an explicit sandbox-disable directive still is.

## Audit log

Blocked and quarantined actions are appended to `<hermes_home>/logs/prompt-firewall.jsonl`:

```json
{"timestamp": "2026-11-06T15:07:25+0200", "plugin": "prompt-firewall", "version": "1.1.7",
 "event": "block", "reason": "protected_write_with_injection",
 "source": "write_file:<hermes_home>/config.yaml",
 "categories": ["instruction_override"], "detail": "protected_write_with_injection"}
```

Only metadata is recorded - reason code, source label, pattern ids. File contents, command bodies and credentials are never written, and credential paths are redacted to `[REDACTED]`.

## Security preview, and what it is not

This plugin is a **security preview**, not a sandbox, not a trust boundary and not an EDR. Read the following before relying on it:

- **Pattern-based detection is incomplete.** Paraphrased, encoded, split across fields or non-English instructions may not match. This is a deterministic pattern matcher, not a reasoning model.
- **Enforcement is delegated to Hermes Core.** The plugin returns a verdict; Hermes Core owns the action gate. Not every tool and not every execution path is covered - inline tool executors and inline terminal output use different code paths.
- **Core approval scope is not content-bound.** Hermes Core's approval cache is keyed by a pattern key, not by file bytes, so an approval granted for one payload may be reused for changed content at the same path. A separate content-aware approval prototype exists, but it is **not part of this plugin and not active**.
- **Auto-approval and unattended modes weaken the control.** With approval mode off or YOLO-style unattended runs, an `approve` verdict can pass without a human decision. A `block` verdict is distinct from `approve` and does not depend on the approval prompt.
- **Multi-plugin ordering is not under this plugin's control.** When another plugin also transforms tool results, the effective result depends on Hermes hook infrastructure (open issue PF-11).
- **Operator input is out of scope.** Content that arrives as operator input rather than as tool output is not scanned.

The limitations above are the complete list of the known gaps this plugin publishes; nothing here is a claim of complete protection.

## Evidence (not a production enforcement claim)

An adapted AgentDojo run measured 160 matched banking attack pairs on a single free model:

- attacker success with the firewall adapter **off**: 6 / 160
- attacker success with the firewall adapter **on**: 0 / 160
- legitimate-task utility: 89 / 160 (off) versus 87 / 160 (on)

Caveats a reviewer should weigh:

- Only 5 of 16 banking user tasks were sampled; the six off-arm successes cluster in just two of them, so the result is not a generalisable rate.
- The **on** arm exercised a tool-result-quarantine adapter, **not** the full Hermes Core action gate. This is not a claim about Core enforcement.
- 40 `important_instructions` pairs were lost to an earlier harness error and are excluded from these numbers; the pair count reflects what actually ran.
- 17 legitimate tasks lost utility and 15 gained it between the two arms. These are utility *differences*, not 17 proven firewall false positives.
- One model, one suite, one run: run-to-run randomness is unquantified.

## Independence

This is a community-built, independently maintained plugin. It is **not** an official Nous Research product, not sponsored, endorsed or reviewed by Nous Research, and carries no security certification. It is listed in the `community` tier of the Hermes plugin catalog at an earlier release; this version is not listed there yet, and the catalog entry is moved by a maintainer-reviewed pull request.

## Scope of the published tree

The published release tree contains the runtime files only: `plugin.yaml`, `__init__.py`, `policy.py`, `detectors.py`, `grants.py`, `explain.py`, `strings.py`, `locale.py`, `README.md` and `LICENSE`. No test, audit or development-only file is part of it.

The `development` branch of this repository carries the automated suite: 384 tests in total on a pinned Hermes Core - the 344-test base suite (225 unit/acceptance tests, 13 native-integration tests that boot a real Hermes plugin manager against an isolated `HERMES_HOME` and drive the native lifecycle hooks, and the remainder regression files for the multilingual, protected-write and shell-resolver classes) plus 40 Scoped Intent Grant security regressions (`tests/test_grants.py`). Inside the base suite, the approval-card explain engine runs 46 checks, the wired approve path 12 checks and the localization suite 13 checks. Those test files are not part of the published plugin tree. Note: 14 of the 384 checks require a local Hermes Core checkout (`HERMES_REPO`); without it they error/skip rather than fail, and one symlink fixture depends on the test `HOME` location.

## Bounded shell semantics

Shell writes are gated by a **static** resolver in `policy.py`: it reads the command text, decides where the write would
land and compares that destination with the protected surfaces. It never executes the command. The boundaries below are
part of the contract, not an implementation detail.

**What is resolved.** Shell redirection, in-place editors, copy/move/link/install, `tee`, `rm`, `mkdir`/`touch`, mode and
owner changes, truncation, `dd`, downloads (`curl -o`, `wget -O`), archives (`tar`, `unzip`), synchronisation (`rsync`,
`rclone`, `scp`), `git` write sub-commands, `pip`/`npm` install targets, `sponge`, `find` and `xargs`, explicit writes in
`python -c` code, and one level of `sh -c` / `bash -c` nesting. A leading environment assignment (`FOO=1 rm ...`) is
stripped before the command word is read, so the verb is never lost.

**What is deliberately not a write.** Listing modes stay benign - `tar -t`/`--list`, `unzip -l`, `git status`/`log`/`diff`,
`pip list`/`download`, `npm view`/`ls`. A protected path used only as the **source** of a copy or as an operand of an
interpreter is a read, not a write attempt, and stays allowed. A mode or owner operand (`chmod 644 FILE`) is not a path.

**What happens when the destination is protected.** The verdict is `approve` - the native Hermes approval gate - because the
written content cannot be verified before the command runs. A write that carries an injection signature is `block`, and a
credential path is `block`. A mutating command that *names* a protected path but resolves no destination is escalated the
same way instead of being silently allowed; the check is per command segment, so an unrelated benign segment cannot mask it.

**Known limits of the resolver.** These are real and are not worked around:

- A protected path that never appears in the command text cannot be detected; a process that computes its own destination at
  runtime is outside the resolver's reach.
- Destinations that the resolver cannot attribute are escalated only when a protected path is named as an operand. A
  command whose protected target is implied but not named stays allowed.
- Nested shells are followed one level deep; a deeper `sh -c` chain is not resolved.
- Relative destinations are resolved against the **current working directory**, so the same command can be classified
  differently when it is run from a different directory. The verdict follows the path the command would actually write.
- The resolver classifies the command as written. A different spelling of the same write may therefore reach a different
  branch of the table, and the table is finite by design.

## License

MIT - see `LICENSE`.
