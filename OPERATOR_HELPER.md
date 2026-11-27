# Prompt Firewall 1.1.9 — Operator Helper

This is the operator-facing guide for the deterministic `prompt-firewall` Hermes
plugin. It is a security-preview plugin, not a sandbox. It makes no network or
LLM calls and has no external runtime dependencies.

## 1. Install and activate

Hermes documents plugin installation and lifecycle commands at:

- <https://hermes-agent.nousresearch.com/docs/developer-guide/plugins>
- <https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins>
- <https://hermes-agent.nousresearch.com/docs/reference/cli-commands>

### Marketplace install

```bash
hermes plugins install prompt-firewall --no-enable
hermes plugins enable prompt-firewall
hermes plugins list --enabled --plain
hermes plugins doctor prompt-firewall --ci
```

`--no-enable` leaves an install disabled until it is explicitly enabled. The
plugin manifest declares version `1.1.9`, Hermes compatibility `>=0.22.7`, and
three hooks: `transform_tool_result`, `pre_tool_call`, and `pre_llm_call`.

### Pinned installation

For a reproducible manual install after the release is published, install the
immutable release tag and verify that its peeled commit matches the commit shown
in the signed/published release metadata:

```bash
hermes plugins install https://github.com/Gaijin-01/prompt-firewall.git \
  --ref v1.1.9 --no-enable
hermes plugins enable prompt-firewall
hermes plugins show prompt-firewall
```

Exact tag verification:

```bash
git ls-remote --tags https://github.com/Gaijin-01/prompt-firewall.git refs/tags/v1.1.9
# After cloning/fetching the tag:
git fetch --tags origin
git rev-parse refs/tags/v1.1.9^{commit}
# Compare this output byte-for-byte with the commit in the published release metadata.
```

For a local checkout, verify the release tag before installing:

```bash
git clone https://github.com/Gaijin-01/prompt-firewall.git /tmp/prompt-firewall-pinned
git -C /tmp/prompt-firewall-pinned fetch --tags origin
git -C /tmp/prompt-firewall-pinned rev-parse refs/tags/v1.1.9^{commit}
hermes plugins install /tmp/prompt-firewall-pinned --no-enable
```

Before publication, `v1.1.9` is intentionally not assumed to exist; use the
reviewed local package and its recorded commit only for pre-publication checks.

```bash
hermes plugins show prompt-firewall
grep -E '^(name|version|requires_hermes):' \
  "${HERMES_HOME:-$HOME/.hermes}/plugins/prompt-firewall/plugin.yaml"
```

### Update, status and uninstall

```bash
hermes plugins check-updates
hermes plugins update prompt-firewall
hermes plugins list --enabled --plain
hermes plugins doctor prompt-firewall --ci
```

To disable without removing files:

```bash
hermes plugins disable prompt-firewall
```

To remove the installed plugin:

```bash
hermes plugins disable prompt-firewall
hermes plugins remove prompt-firewall
```

Removal is not a rollback. Keep the exact previous commit available before
removing a live version.

### Controlled rollback to published 1.1.8

The published 1.1.8 commit is
`12e8199b38ef120311eeb0c66e583f773be2eef1`. In a maintenance window, verify the
SHA, disable/remove the current plugin, install the detached 1.1.8 checkout, run
doctor, and enable it only after inspection:

```bash
git clone https://github.com/Gaijin-01/prompt-firewall.git /tmp/prompt-firewall-118
git -C /tmp/prompt-firewall-118 checkout --detach 12e8199b38ef120311eeb0c66e583f773be2eef1
# Back up any local plugin data/configuration before this replacement.
hermes plugins disable prompt-firewall
hermes plugins remove prompt-firewall
hermes plugins install /tmp/prompt-firewall-118 --no-enable
hermes plugins doctor prompt-firewall --ci
hermes plugins enable prompt-firewall
```

Do not perform rollback from an active production incident without preserving
logs and the exact installed identity.

## 2. Profiles, `HERMES_HOME` and Telegram gateways

Hermes profiles and gateways can have separate homes and plugin sets. Resolve the
active profile's effective home before installing; do not assume every profile
shares `~/.hermes`:

```bash
printf 'HERMES_HOME=%s\n' "${HERMES_HOME:-$HOME/.hermes}"
HERMES_HOME=/path/to/profile-home hermes plugins list --user --plain
HERMES_HOME=/path/to/profile-home hermes plugins install prompt-firewall \
  --ref v1.1.9 --no-enable
```

Install and enable the plugin separately for each profile that must enforce it.
A plugin enabled in one profile is not evidence that another Telegram bot or
profile has loaded it. Restart/reload the relevant gateway according to the
Hermes deployment procedure after changing installed plugins; verify the loaded
profile and hook list in that gateway.

For operator grants, the plugin uses the gateway's trusted platform identity and
`<PLATFORM>_ALLOWED_USERS` allowlist. For Telegram this is typically
`TELEGRAM_ALLOWED_USERS`. Do not infer authorization from a Telegram display name
or from message text. A multi-bot deployment must configure the allowlist in the
profile/gateway that receives the operator turn.

## 3. What the verdicts mean

- **ALLOW** — the plugin found no policy reason to block or escalate this tested
  action. It is not a proof that the action is safe in every environment.
- **APPROVE** — the action is passed to Hermes Core's existing approval path.
  The plugin does not itself approve the action.
- **BLOCK** — the plugin refuses the action at the action boundary. Core-side
  dispatch behavior still depends on Hermes Core and runner configuration.
- **QUARANTINED** — a matched span in untrusted tool output is replaced with a
  `[QUARANTINED:<category>]` marker before the agent sees it.
- **Withheld output** — output beyond the scan budget, or output the plugin could
  not safely inspect, is withheld and replaced with a notice. A fast rejection,
  truncation or quarantine is not successful full-input analysis.

Treat an approval request as a security decision. Inspect the tool, destination,
content and explanation; reject unexpected scope. Do not approve a request merely
because it is labeled `APPROVE`, and do not treat a plugin `ALLOW` as operator
authorization.

## 4. Operator authorization and scoped grants

A scoped grant is narrowly defined. It can exempt only one exact durable
instruction-surface `write_file` operation; it does not bypass scanning, credential
checks, endpoint checks, control-plane rules, shell/terminal analysis or dynamic
writes.

The anchored operator message grammar is:

```text
authorize write to <path> sha256 <64-hex>
authorize write to <path> with sha256 <64-hex>
```

The entire operator message must be that command, with optional surrounding
whitespace. The grant requires:

- a trusted user-facing platform (`telegram`, `cli`, `whatsapp`, `discord`,
  `slack`, `signal`, `matrix`, `web` or `desktop`);
- a sender identity present and included in that platform's
  `<PLATFORM>_ALLOWED_USERS` allowlist;
- no parent session (not a subagent/fork/synthetic turn);
- the canonical exact path and SHA-256 of the exact proposed content;
- matching session and turn binding;
- one successful consumption only.

Grants expire after **600 seconds** and are checked at point of use. Used or
expired grants are evicted. Grants are process-lifetime state only: they are not
durable, same-UID protected or a substitute for Hermes Core authorization. Do not
put secrets in the authorization message; the content hash is not a secret vault.

## 5. Audit logs and safe diagnostics

By default, runtime records are written as JSONL to:

```text
$HERMES_HOME/logs/prompt-firewall.jsonl
```

The plugin-specific variables are:

- `HERMES_HOME` — active Hermes root and protected-path basis.
- `HERMES_LANGUAGE` — approval-card presentation language; not a verdict input.
- `PROMPT_FIREWALL_MODE` — `runtime` by default; non-runtime modes use a
  suffixed log such as `prompt-firewall.test.jsonl`.
- `PROMPT_FIREWALL_AUDIT_LOG` — explicit audit path; takes precedence over mode
  routing and `HERMES_HOME`.
- `HERMES_SESSION_ID` — fallback session attribution.
- `<PLATFORM>_ALLOWED_USERS` — authorization-critical operator allowlist.

Records contain metadata such as `timestamp`, `event_id`, `mode`, `plugin`,
`version`, `event`, `reason`, `source`, optional `categories`, optional
`session_id`/`tool_call_id`, and `scan_ms`, `policy_ms`, `audit_ms`. Detail is
bounded and paths containing credential filenames are redacted. Command bodies,
file contents and credentials are not intended to be written to the audit log.

Use a disposable profile and explicit probe log for diagnostics:

```bash
TMP_HOME=$(mktemp -d)
HERMES_HOME="$TMP_HOME" PROMPT_FIREWALL_MODE=probe \
  PROMPT_FIREWALL_AUDIT_LOG="$TMP_HOME/probe.jsonl" \
  hermes plugins doctor /path/to/prompt-firewall --ci
```

Inspect only the disposable log, then remove the disposable home after the
investigation. Never paste production JSONL, credentials, command bodies or
private paths into an issue report.

## 6. False positives and troubleshooting

1. Record the exact plugin commit, Hermes version, profile home, hook and a
   redacted minimal reproduction.
2. Check `hermes plugins list --json`, `hermes plugins show prompt-firewall`,
   and `hermes plugins doctor prompt-firewall --ci`.
3. Confirm the relevant gateway loaded the intended profile and plugin version.
4. For an approval request, inspect the destination and content before deciding;
   do not weaken the policy or broadly authorize a path to make a test pass.
5. Reproduce with a temporary `HERMES_HOME` and `PROMPT_FIREWALL_MODE=probe`.
6. If another plugin changes hook order or output, isolate the plugin set and
   report the observed hook ordering rather than guessing.

When `re._parser` is unavailable, the guarded fallback runs the original regex
scan for affected gates; it does not silently claim a skipped rule was analyzed.
The release parity result is bounded by the tested corpus.

## 7. Security boundaries and known limitations

Prompt Firewall is not a sandbox and does not provide OS isolation, same-UID
trust, durable grants, rollback guarantees or universal detection. Hermes Core
does not currently pass the effective execution CWD into the hook; a relative
path can therefore be classified against a different base than the shell will
use. This is a known limitation, not a guarantee that the verdict always matches
actual filesystem execution.

In auto-approval or unattended modes, an `APPROVE` verdict may pass without a
human decision. A `BLOCK` verdict is distinct, but Core-side dispatch in every
runner is not independently validated here. Core approval caching and plugin
ordering are outside this plugin's control. External adversarial evaluation is
**NOT VERIFIED**.

## 8. Reporting a reproducible issue safely

Include:

- plugin commit and `plugin.yaml` version;
- Hermes version and operating system;
- profile name/home class (redact the absolute path if private);
- hook name and redacted tool name/arguments;
- observed verdict and a short expected/actual description;
- whether the reproduction used a disposable `HERMES_HOME` and probe log.

Do not include API keys, OAuth tokens, cookies, credentials, private audit logs,
full command bodies, private repository contents or unredacted paths. Replace
sensitive values with `[REDACTED]`; provide a synthetic content hash where the
exact bytes are not safe to share.

Official Hermes references: [plugin guide](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins), [security guide](https://hermes-agent.nousresearch.com/docs/user-guide/security), [profiles](https://hermes-agent.nousresearch.com/docs/user-guide/profiles), and [updating](https://hermes-agent.nousresearch.com/docs/getting-started/updating).
