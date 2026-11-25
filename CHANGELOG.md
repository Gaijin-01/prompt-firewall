# Changelog — prompt-firewall

## 1.1.8 (plugin-only release candidate, 2026-11-24)

Plugin-only update of the deterministic firewall. Baseline: published v1.1.7. No Core, OS-trust or Marketplace changes are part of this release.

### Fixed
- **P0-A**: unreachable G1 destination predicate; restored destination-based blocking of writes to durable instruction surfaces, including symlink aliases.
- **P0-B**: dynamic destination handling through `execute_code` and filesystem operations.
- **P0-2**: CWD and shell-newline handling; portable scratch exclusion now follows the path's own Hermes home rather than only the active one.
- Scratch exclusion under a relocated `HERMES_HOME` (regression from the 1.1.7 baseline).

### Added
- Portable regression coverage with negative fixtures for `.hermes/plugins/*`, `.hermes/config.yaml`, `.hermes/AGENTS.md`, `.hermes/SOUL.md`, nested `.hermes` homes, protected symlink aliases and `..` traversal.
- `action_context.py` with strict package-relative imports and centralized decision dispatch.
- Self-contained test dependency closure for the complete pre-extraction candidate checkout: its full suite runs without a Hermes Core checkout. That checkout is not shipped. The public tree retains 7 test files: 298 pass with a matching Hermes Core; 284 pass without Core, where the 14 Core-dependent cases cannot run.

### Changed
- Protected-path and destination-based blocking improvements in `policy.py`.
- Scoped-grant and audit-attribution improvements in `__init__.py`.

### Excluded
- Experimental P1 Durable Ledger: absent from the shipped tree and not imported by any runtime module.
- OS-backed monotonic trust, same-UID isolation, D12 rollback guarantees and native Core enforcement are not claimed or implemented by this release.

### Verification
- Public retained suite with Hermes Core: 298 passed; without Hermes Core: 284 passed, with 14 Core-dependent cases unable to run.
- The historical 557-pass full suite belongs to the complete pre-extraction candidate, not to this minimal public tree; it is preserved as historical evidence and is not claimed as a public-tree result.
- Performance: no material relative p95/p99 regression versus v1.1.7 (candidate p95 +0.33%, p99 -0.56%). No statistical equivalence test was run; equivalence is not claimed. The pre-registered absolute transform-tool-result p95 budget of 20 ms on a 200K-character corpus is FAIL at 309 ms for this candidate and for 1.1.7 (308 ms) and 1.1.6 (512 ms) alike; reported as a scan-budget limitation, not a 1.1.8 regression.

### Final cleanup
- Renamed `locale.py` to `pf_locale.py` to avoid shadowing Python's stdlib `locale` when the plugin root is early in `sys.path`; localization behavior and all three hook contracts are unchanged.
- Replaced personal paths in retained bypass fixtures with portable `tmp_path` fixtures; no fixture payload is executed.
- Corrected documentation to distinguish the 22-file public tree (23 Git tree entries) from the complete pre-extraction candidate, and disclosed all runtime environment reads.

## 1.1.7 (published release, 2026-11-19)

Supersedes the published **1.1.6** baseline. The frozen 1.1.7 checkpoint is preserved unchanged for rollback.

- **G1 destination gate** — scanner-independent, destination-based blocking of writes to durable instruction surfaces (`AGENTS.md` / `SKILL.md`) and the firewall's own code/config/state, even outside protected roots and through symlink aliases. Forced-zero-scanner attack capture 10/19 -> 14/19; baseline 14/19 -> 17/19.
- **E1 encoding normalization** — sparse percent-escapes and backslash-Unicode decoded before scanning. Encoded attacks 0/70 -> 70/70; 0 false positives on 1,758 benign documents.
- **Scoped Intent Grant** (`grants.py`) — fail-closed, one-shot operator authorization for an exact reviewed write to a durable instruction surface, with canonical path, content hash, turn scope and TTL. A grant lifts only the destination-specific denial; the full policy still runs and the grant is consumed once.
- **Lazy `_FrameIndex`** — frame index built only when needed; ~1.64x faster on a 400 KB benign scan with no behavior change.
- F2 credential taxonomy corrected for `~/.aws/credentials` directory-scoped classification.

## 1.1.6 (published baseline)
- Catalog pin `7c2dcdd638d2fb650dc4eb3dd0c670b0cac29d7a`; verified base release. Earlier history is preserved in the repository tags and release branches.
