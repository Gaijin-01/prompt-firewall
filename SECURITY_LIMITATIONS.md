# Security limitations

This is the canonical short list for prompt-firewall 1.1.8. Full detail is in README.md under "Known limitations".

- Detection is pattern-based and incomplete; eight known false-positive cases remain unresolved.
- F3: dynamic provider key/URL assignments can return ALLOW; Core impact unknown.
- E2/E3/E5 are not closed; no complete interference baseline or plugin validation exists for them.
- Enforcement is delegated to Hermes Core. In auto-approval or unattended modes an APPROVE verdict may pass without a human decision; BLOCK is a distinct veto, but Core-side dispatch in every runner is not validated here.
- Hermes Core does not propagate the effective execution CWD into the hook; relative destinations may be classified against a different base.
- No OS-backed monotonic trust, no same-UID isolation, no D12 rollback guarantee.
- Scoped grants are process-lifetime only and are not durable or same-UID protected.

The experimental Durable Ledger is not part of this release and is not imported at runtime.
