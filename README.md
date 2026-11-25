# prompt-firewall

A deterministic prompt-injection firewall for [Hermes Agent](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins).

Version **1.1.8** is a plugin-only release candidate. It is not published to the catalog yet; the catalog currently points at v1.1.6. Production installations remain on the previously published version until a maintainer-reviewed catalog pull request moves the published pin.

## What changed in 1.1.8

- Policy fixes for P0-A (unreachable destination predicate), P0-B (dynamic destination handling through `execute_code` and filesystem operations) and P0-2 (CWD and shell-newline handling), each covered by targeted regression tests.
- Portable scratch-exclusion regression: a `.hermes/cache` path stays scratch when `HERMES_HOME` points at a different home. Negative fixtures assert that `.hermes/plugins/*`, `.hermes/config.yaml`, `.hermes/AGENTS.md`, `.hermes/SOUL.md`, nested `.hermes` homes, protected symlink aliases and `..` traversal remain protected.
- Protected-path and destination-based blocking improvements in `policy.py`.
- Scoped-grant and audit-attribution improvements in `__init__.py` and `action_context.py`.
- The public release tree retains seven regression-test files. With a compatible Hermes Core checkout, 298 tests pass; without `hermes_cli`, 284 pass and 14 Core-dependent cases cannot run. The larger pre-extraction dependency bundle and raw audit artifacts are distributed separately from the public plugin tree. The full 557-test result belongs to the complete pre-extraction candidate checkout, not to this tree.

The 1.1.7 baseline is preserved as published history. Version 1.1.8 does not rewrite or replace that history. The experimental Durable Ledger developed alongside this release is **not part of this plugin**: it is absent from the shipped tree and is not imported by any runtime module. No OS-backed monotonic trust, same-UID isolation, D12 rollback guarantee or native Core enforcement is claimed by this release.

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
| `pre_llm_call` | states the trust boundary in the operator's turn |

It registers no tools, no middleware and no provider profiles.

### Environment reads

The plugin reads the following environment variables at runtime. They are not all presentation-only; their exact influence is listed here.

| Variable | Required? | Influence |
|---|---|---|
| `HERMES_HOME` | optional | Selects the active Hermes root. Changes the protected-path set and therefore path classification and verdicts. Without it, the plugin asks `hermes_cli.config` and finally falls back to `~/.hermes`. |
| `HERMES_LANGUAGE` | optional | Presentation only: selects the approval-card language. Never changes a verdict. |
| `PROMPT_FIREWALL_MODE` | optional | Defaults to `runtime`. Any other value routes the audit sink to a mode-suffixed sibling file so test/probe runs cannot contaminate the live audit trail. Changes audit destination, not verdicts. |
| `PROMPT_FIREWALL_AUDIT_LOG` | optional | Explicit audit-log destination; overrides both mode-based routing and `HERMES_HOME`. Changes where audit records are written. |
| `HERMES_SESSION_ID` | optional | Session attribution copied into audit records when the hook payload does not provide a session id. |
| `<PLATFORM>_ALLOWED_USERS` | optional but authorization-critical | Gateway allowlist for a user-facing platform (for example `TELEGRAM_ALLOWED_USERS`). Used by `grants.py` to verify that a grant request comes from a configured authorized operator. Unset or empty means no operator is authorized and grants fail closed. Never derived from message text. |

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
| `encoded_payload` | base64 / hex / percent-encoded payloads - decoded, then re-scanned |
| `security_control_disable` | attempts to switch off the firewall or other security controls |

### 2. `pre_tool_call` - enforce at the action boundary

Content cannot authorize itself. These are blocked outright:

- writes of instruction-shaped content into agent instruction files, e.g. `AGENTS.md`, `CLAUDE.md`, `SOUL.md`, `SKILL.md`;
- installing a Skill that carries injection content;
- redirecting the model endpoint to a non-allowlisted host - the URL must be *bound* to an endpoint key (`base_url: <url>`, `OPENAI_BASE_URL=<url>`, `hermes config set providers.ollama.api <url>`) **and** the write must land on a protected endpoint-config surface (`config.yaml`, `.env`, `plugin.yaml`, ...). A URL that merely sits next to the word *endpoint* in prose, source code or documentation is not an endpoint change and is not blocked;
- writing to a protected surface (config, prompts, memory, plugin settings, credential paths) with injection content;
- any attempt to disable the firewall or another safety control.

A plain, injection-free write to a protected surface is **not** blocked - it is passed through to Hermes' existing approval mechanism, so an explicitly authorized configuration change still works. The protected-surface path sets live in `policy.py`, not in this document.

### 3. `pre_llm_call` - state the trust boundary

Injects a short notice into the operator's turn reminding the model that external content is data. It never overrides operator instructions.

### 4. Approval card - what the operator is asked to approve

When Hermes Core asks the operator for approval, the plugin attaches a short plain-language explanation of the pending action: what the command does, which paths or systems it touches, what data it could copy out, and what privilege it escalates to. The explanation is produced by a local string analysis (`explain.py`) - no LLM call, no network, no subprocess, no filesystem access beyond reading the operator's own session.

The explanation never changes the verdict. It is attached to the `approve` message that Core already renders; if the explain engine fails for any reason, the card falls back to the unmodified firewall message, so the card can never affect enforcement.

**Localized cards.** The card is rendered in the operator's language. The language is resolved only from trusted sources, in this order:

1. `HERMES_LANGUAGE` in the environment;
2. an explicitly written `display.language` in the Hermes configuration (the merged configuration always carries an injected default, which is not a choice and must not outrank the operator's own words);
3. the operator's own last few messages in the current session;
4. English (fallback).

Untrusted content - the command under approval, tool output, `README`/`AGENTS.md`, downloaded documents - is never used as a language signal, and a command that asks for another language does not switch the card. Operator messages are read to pick the language; they are never stored by the plugin. Three catalogs ship with the plugin: English, Russian and Simplified Chinese. Code, commands, paths and technical identifiers are never translated.

Hermes Core does not currently expose a signal for "the operator explicitly chose a language": the merged configuration always carries a default `display.language`, so a plugin cannot tell an explicit choice from the default by reading it. The plugin therefore reads the raw configuration file, where only what the operator actually wrote is present, and falls back to the operator's own messages.

## Design notes

**Structure, not keywords.** A README quoting an override phrase inside a security write-up is legitimate; the same phrase aimed at the agent is not. Rules therefore require an explicit agent-directed frame (an imperative addressed to the reader, or a role/identity spoof) rather than the bare presence of a phrase.

One family of rules is frame-gated: a phrase that switches a *generic* safety control off is reported only when it reads as an instruction. A sentence *describing* such an attempt is documentation; a sentence *issuing* one is an attack. Rules that name the firewall itself are never gated - they are unambiguous in any context.

**Coordinates in one space.** Results arrive as a JSON envelope but are scanned and patched in the *decoded* content space, so a quarantine marker can never land on the wrong character of a neighbouring line.

**Fail closed where it matters.** Unknown provenance on a protected write is refused. Read-only content is flagged rather than blocked, so legitimate research work keeps working.

- A stock container/browser flag such as `--no-sandbox` inside a process listing is not a control disable; an explicit sandbox-disable directive still is.

## Audit log

Blocked and quarantined actions are appended to `<hermes_home>/logs/prompt-firewall.jsonl`:

```json
{"timestamp": "2026-11-06T15:07:25+0200", "plugin": "prompt-firewall", "version": "1.1.8",
 "event": "block", "reason": "protected_write_with_injection",
 "source": "write_file:<hermes_home>/config.yaml",
 "categories": ["instruction_override"], "detail": "protected_write_with_injection"}
```

Only metadata is recorded - reason code, source label, pattern ids. File contents, command bodies and credentials are never written, and credential paths are redacted to `[REDACTED]`.

## Evidence and verification status

The public tree contains **22 files**: 15 runtime/document files plus **7 retained test files**. Git reports **23 tree entries** because `tests/` is itself counted as one tree entry. Audit logs, benchmark corpora, vendored Core test dependencies and research artifacts are not in the public tree; they live in a separate private audit package.

Verification has three distinct scopes. Do not conflate them:

| Scope | Prerequisites | Result |
|---|---|---|
| Complete pre-extraction candidate suite | Full source checkout with vendored Hermes Core test dependencies | 557 passed |
| Public retained suite, with Hermes Core | Public tree plus a Hermes Core checkout providing `hermes_cli` | **298 passed** |
| Public retained suite, without Hermes Core | Public tree only | **284 passed**; 14 Core-dependent cases cannot run |

Reproduce the public results:

```bash
# with Hermes Core available on PYTHONPATH
python3 -m pytest -q tests --import-mode=importlib -p no:cacheprovider

# without Hermes Core (14 native cases error/fail at setup: hermes_cli is absent)
python3 -m pytest -q tests --import-mode=importlib -p no:cacheprovider
```

The 557-pass result belongs to the **complete pre-extraction candidate suite**, not to this minimal public tree. It is preserved as historical verification evidence, not claimed as a current result of the public tree.

Native three-hook compatibility: 14 passed when Hermes Core is available. Focused security regressions (P0-A, P0-B, P0-2, scoped grants): all passed in the retained suite; raw logs are in the private audit package.

Performance: no material relative p95/p99 regression versus v1.1.7 (candidate p95 +0.33%, p99 -0.56% on the shared harness). No formal statistical equivalence test was run; equivalence is therefore **not claimed**. One pre-registered absolute budget (p95 of `transform_tool_result` <= 20 ms on a corpus containing two 200,000-character outputs) is **FAIL at 309 ms** for the candidate *and for both earlier versions* (v1.1.7: 308 ms, v1.1.6: 512 ms). This is a property of the scan budget, not a regression introduced in 1.1.8.

Independent exact-SHA review of the release tree is pending; publication is not authorized by this package.

AgentDojo-style adapter study (historical, 1.1.6-era, not a 1.1.8 enforcement claim): 160 matched banking attack pairs on one free model; attacker success 6/160 with the adapter off versus 0/160 with a tool-result-quarantine adapter on; legitimate-task utility 89/160 versus 87/160. Only 5 of 16 banking tasks were sampled, the on-arm did not exercise the Core action gate, 40 pairs were lost to a harness error, and run-to-run variance was not measured. These numbers are context only, not a general protection rate.

## Independence and community status

This is a community-built, independently maintained plugin. It is **not** an official Nous Research product, not sponsored, endorsed or reviewed by Nous Research, and carries no security certification. It is listed in the `community` tier of the Hermes plugin catalog at an earlier release; this version is not listed there yet. Catalog changes are made by maintainer-reviewed pull requests.

## Known limitations

No release of this plugin provides complete protection. The following gaps are published, not hidden:

- Detection is pattern-based. Paraphrased, encoded, split or non-English instructions may not match. Eight known false-positive cases remain unresolved.
- Enforcement is delegated to Hermes Core: the plugin returns a verdict, and Core owns the action gate. Not every tool or execution path is covered.
- F3: dynamic provider key/URL assignments may return ALLOW; Core impact is unknown.
- E2/E3/E5 remain open; there is no complete interference baseline or plugin validation in those areas.
- In auto-approval or unattended modes an `approve` verdict may pass without a human decision. A `block` verdict is a distinct veto and does not depend on the approval prompt. Real Core dispatch veto in every runner is not validated here.
- Core does not currently propagate the effective execution CWD into the hook. A relative destination may therefore be classified against a different base than the one a shell will use. Core-side changes are outside this plugin's scope.
- Core's approval cache is keyed by a pattern rather than file bytes, so approval for one payload may be reused for changed content at the same path. A content-aware approval prototype is not part of this plugin.
- Multi-plugin ordering is controlled by Hermes hook infrastructure, not by this plugin (open issue PF-11).
- Operator input is not scanned; only untrusted tool output is.
- The shell destination resolver is static: it never executes commands, follows nested shells only one level deep, and cannot see a destination computed at runtime.
- There is no OS-backed monotonic trust, no same-UID isolation and no rollback protection for plugin state. An attacker with write access to the plugin's own files can alter local state.
- Scoped grants are single-use within a process lifetime; they are not durable across restarts and are not protected against same-UID tampering.

`SECURITY_LIMITATIONS.md` in this tree is the canonical short list. The limits above are the complete set published for this release; nothing here claims complete protection.

## Scope of the published tree

The published tree contains 22 files (23 Git tree entries, counting the `tests/` directory): `plugin.yaml`, `__init__.py`, `action_context.py`, `detectors.py`, `executable_view.py`, `explain.py`, `grants.py`, `pf_locale.py`, `policy.py`, `strings.py`, `README.md`, `CHANGELOG.md`, `SECURITY_LIMITATIONS.md`, `LICENSE`, `.gitignore` and 7 retained regression files under `tests/`. Audit, benchmark and development-only files are not part of it; they live in a separate private audit package.

## Bounded shell semantics

Shell writes are gated by a **static** resolver in `policy.py`: it reads the command text, decides where the write would land and compares that destination with the protected surfaces. It never executes the command. The boundaries below are part of the contract, not an implementation detail.

**What is resolved.** Shell redirection, in-place editors, copy/move/link/install, `tee`, `rm`, `mkdir`/`touch`, mode and owner changes, truncation, `dd`, downloads (`curl -o`, `wget -O`), archives (`tar`, `unzip`), synchronisation (`rsync`, `rclone`, `scp`), `git` write sub-commands, `pip`/`npm` install targets, `sponge`, `find` and `xargs`, explicit writes in `python -c` code, and one level of `sh -c` / `bash -c` nesting. A leading environment assignment (`FOO=1 rm ...`) is stripped before the command word is read, so the verb is never lost.

**What is deliberately not a write.** Listing modes stay benign - `tar -t`/`--list`, `unzip -l`, `git status`/`log`/`diff`, `pip list`/`download`, `npm view`/`ls`. A protected path used only as the **source** of a copy or as an operand of an interpreter is a read, not a write attempt, and stays allowed. A mode or owner operand (`chmod 644 FILE`) is not a path.

**What happens when the destination is protected.** The verdict is `approve` - the native Hermes approval gate - because the written content cannot be verified before the command runs. A write that carries an injection signature is `block`, and a credential path is `block`. A mutating command that *names* a protected path but resolves no destination is escalated the same way instead of being silently allowed; the check is per command segment, so an unrelated benign segment cannot mask it.

**Known limits of the resolver.** These are real and are not worked around:

- A protected path that never appears in the command text cannot be detected; a process that computes its own destination at runtime is outside the resolver's reach.
- Destinations that the resolver cannot attribute are escalated only when a protected path is named as an operand. A command whose protected target is implied but not named stays allowed.
- Nested shells are followed one level deep; a deeper `sh -c` chain is not resolved.
- Relative destinations are resolved against the **current working directory**, so the same command can be classified differently when it is run from a different directory. The verdict follows the path the command would actually write.
- The resolver classifies the command as written. A different spelling of the same write may therefore reach a different branch of the table, and the table is finite by design.

## License

MIT - see `LICENSE`.
