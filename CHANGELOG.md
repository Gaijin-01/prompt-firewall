# Changelog — prompt-firewall

## 1.1.7 (final release candidate, 2026-11-19)

Supersedes the published **1.1.6** baseline. The frozen 1.1.7 checkpoint
(commit `9557c24e62fc57d962b91da3ffdd386ff358b219`) is preserved unchanged for rollback.
Final RC commit: `05dd0d8a56ea2ea9606da75c24289795a5044919` (tag `v1.1.7-rc`,
branch `dev/pf-1.1.8-exp` — historical experiment name, not the release version).

### Added
- **G1 destination gate** — scanner-independent, destination-based blocking of writes to
  durable instruction surfaces (`AGENTS.md` / `SKILL.md`) and the Firewall's own
  code/config/state, even outside protected roots and through symlink aliases.
  Forced-zero-scanner attack capture 10/19 → 14/19; baseline 14/19 → 17/19.
- **E1 encoding normalization** — sparse percent-escapes and backslash-Unicode
  (`\uXXXX`, `\UXXXXXXXX`, `\xXX`) decoded before scanning. Encoded attacks 0/70 → 70/70;
  0 false positives on 1,758 benign documents.
- **Scoped Intent Grant** (`grants.py`, new stdlib-only module) — fail-closed, one-shot
  operator authorization for an exact reviewed write to a durable instruction surface:
  anchored whole-message command, authenticated sender against the configured operator
  allowlist, canonical path + SHA-256 of the exact content + turn scope + TTL (600 s, cap 256).
  A grant lifts ONLY the destination-specific denial; the full policy always runs; the grant
  is consumed exactly once at the final decision; it never downgrades protection for the
  Firewall's own paths.

### Changed
- **Lazy `_FrameIndex`** — the frame index is built only when needed (stdlib-only).
  ~1.64× faster on a 400 KB benign scan (p50 1010 ms → 618 ms); no behavior change.
- F2 credential taxonomy: `~/.aws/credentials` directory-scoped classification corrected.
- Firewall-state disable/removal and durable instruction-surface writes escalated to BLOCK
  (were APPROVE, which can be auto-approved in cron/yolo/unattended modes).

### Verification (pinned Hermes Core)
- Full suite: **384/384 PASS** (`HERMES_REPO=/home/operator/.hermes/hermes-agent`).
- Grant tests: **40/40 PASS**.
- G1 scanner-zero matrix: baseline **17/19**, false-negative **14/19**.
- Benign matrix: **0 unintended denials**.
- Adversarial counterexamples: **14/14 PASS, exit 0**.
- stdlib-only runtime confirmed; plugin.yaml identical to frozen; 3 hooks unchanged.

### Known limitations (documented, NOT closed)
- **Core-level TOCTOU** — final-component inode swap between policy-check and the actual
  write syscall requires fd pinning / O_NOFOLLOW at the tool executor; out of plugin scope.
- **Operator phishing** — a human tricked into typing the exact authorize command for
  malicious content; bounded by one-shot + path/turn/content-hash + TTL.
- **Scanner-dependent content detection** — content-injection detection relies on the
  scanner; the G1 scanner-independent invariant covers destination-based rules only.
- **Grant provenance narrower than full gateway authz** — pairing/profile-only authorized
  users cannot use the grant (fail-closed safe, usability restriction).
- `pre_llm_call` is a trusted per-turn channel, not cryptographic proof of physical human
  confirmation; the grant is a deliberate convention, not an Intent Token.

## 1.1.6 (published baseline)
- Published official baseline. See frozen history.
