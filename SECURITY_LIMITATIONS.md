# Security limitations

This is the canonical short list for prompt-firewall 1.1.9. Full detail is in README.md under "Known limitations".

- Detection is pattern-based and incomplete; eight known false-positive cases remain unresolved.
- F3: dynamic provider key/URL assignments can return ALLOW; Core impact unknown.
- E2/E3/E5 are not closed; no complete interference baseline or plugin validation exists for them.
- Enforcement is delegated to Hermes Core. In auto-approval or unattended modes an APPROVE verdict may pass without a human decision; BLOCK is a distinct veto, but Core-side dispatch in every runner is not validated here.
- Hermes Core does not propagate the effective execution CWD into the hook; relative destinations may be classified against a different base.
- No OS-backed monotonic trust, no same-UID isolation, no D12 rollback guarantee.
- Scoped grants are process-lifetime only and are not durable or same-UID protected.
- The 1.1.9 scanner's literal-gate prefilter is a *performance* optimisation. A rule is skipped only when a mandatory literal has been proven absent, and the private `re._parser` module it uses is optional: without it the affected gates are disabled and the original regex scan runs instead. Parity with 1.1.8 is bounded by the tested corpus and is not a proof of all-input equivalence.
- The 20 ms p95 figure is a property of the benchmarked corpus, not a universal latency bound; a large finding-bearing document is slower than a benign one.

The experimental Durable Ledger and the frozen PF119 symbolic research are not part of this release and are not imported at runtime.
