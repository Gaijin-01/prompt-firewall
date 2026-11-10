# prompt-firewall

A deterministic prompt-injection firewall for [Hermes Agent](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins).

It watches the **trust boundary**: content that arrives from outside (web pages, repository files, `README`/`AGENTS.md`/`SKILL.md`, downloaded documents, tool results) is *data*, never *authorization*. The plugin quarantines injection-shaped content before it reaches the model, and blocks at the action boundary any attempt to turn that content into agent instructions, skills, endpoints or configuration.

- **No LLM calls.** Every decision is a regex + policy evaluation.
- **No network access. No external dependencies.** Python standard library only.
- **Deterministic.** Same input -> same verdict, every time.
- **Public plugin surfaces only.** Three native Hermes hooks, no core changes, no monkey-patching.

## Install

From the Hermes plugin catalog (once listed):

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

It registers no tools, no middleware, no provider profiles and no environment variables. It reads no environment variables and no credential stores.

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
- redirecting the model endpoint to a non-allowlisted host - the URL must be
  *bound* to an endpoint key (`base_url: <url>`, `OPENAI_BASE_URL=<url>`,
  `hermes config set providers.ollama.api <url>`) **and** the write must land on a
  protected endpoint-config surface (`config.yaml`, `.env`, `plugin.yaml`, ...).
  A URL that merely sits next to the word *endpoint* in prose, source code or
  documentation is not an endpoint change and is not blocked;
- writing to a protected surface (config, prompts, memory, plugin settings, credential paths) with injection content;
- any attempt to disable the firewall or another safety control.

A plain, injection-free write to a protected surface is **not** blocked - it is passed through to Hermes' existing approval mechanism, so an explicitly authorized configuration change still works. The protected-surface path sets live in `policy.py`, not in this document.

### 3. `pre_llm_call` - state the trust boundary

Injects a short notice into the operator's turn reminding the model that external content is data. It never overrides operator instructions.

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
{"timestamp": "2026-11-06T15:07:25+0200", "plugin": "prompt-firewall", "version": "1.1.4",
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

This is a community-built, independently maintained plugin. It is **not** an official Nous Research product, not sponsored, endorsed or reviewed by Nous Research, and carries no security certification. It is published in the `community` tier of the Hermes plugin catalog.

## Scope of the published tree

The published plugin tree (`main`) contains the runtime files only: `plugin.yaml`, `__init__.py`, `policy.py`, `detectors.py`, `README.md` and `LICENSE`. This `development` branch carries the automated suite of 225 unit/acceptance tests plus 13 native-integration tests that boot a real Hermes plugin manager against an isolated `HERMES_HOME` and drive the native lifecycle hooks. Those test files are not part of the published plugin tree.

## License

MIT - see `LICENSE`.
