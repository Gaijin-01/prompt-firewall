# Changelog — prompt-firewall

## 1.1.9 (plugin-only release candidate, 2026-11-27)

Plugin-only **performance** update of the deterministic firewall. Baseline: published v1.1.8. No Core, OS-trust, catalog or Marketplace changes are part of this release, and nothing has been pushed, published or deployed.

This release changes **only the scanner**. The action policy (`policy.py`), the grant model (`grants.py`), the hook modules and every other runtime module are byte-identical to published v1.1.8.

### Fixed
- **Unicode `IGNORECASE` fallback for the Cyrillic gates.** The `mixed_language_override` and `ignore_previous_instructions_ru` rules use `re.IGNORECASE`, but the case-folding projection used by the fast path folds ASCII only. A non-ASCII document is now admitted to those two rules conservatively, so an upper-cased Cyrillic phrase is still detected.
- **Missing role alternative.** The `role_spoof_system_turn` rule now accepts the `endoftext` role marker.
- **Hex decoder prefix.** The hex decoder strips an optional `0x` prefix before decoding.
- **Private `re._parser` dependency.** The candidate used the private CPython module `re._parser` to derive literal gates. That module is an implementation detail and may be absent or reshaped. Its use is now guarded: when it is unavailable the affected gates are **disabled** and the **original regex scan runs instead** — no rule is silently skipped. The parser-independent fallback derives exactly the same invisible-character set, so findings and their offsets are unchanged. `tests/test_prefilter_fallback.py` proves the fallback by re-importing the package with `re._parser` hidden and comparing the finding sets.

### Added
- `_prefilter.py`: conservative literal-gate derivation. A gate is only installed when a *mandatory* literal has been proven, so a gated rule can never be silently dropped.
- Permanent release tests: `tests/test_invisible_contract.py`, `tests/test_gate_contract.py`, `tests/test_security_controls.py`, `tests/test_prefilter_fallback.py`.
- Lazy invisible-character normalisation: a document with no invisible character is returned unchanged, with no index map materialised.
- Byte-level candidate scan for long base64 and hex runs, replacing two regex scans.

### Changed
- `detectors.py` only. `policy.py`, `grants.py`, `strings.py`, `explain.py`, `executable_view.py`, `action_context.py`, `pf_locale.py` and `__init__.py` are unchanged apart from the version constant.
- `tests/test_native_integration.py` now imports `pf_loader` itself, so the module is runnable on its own. Previously it only worked when a sibling test module had imported `pf_loader` first.

### Excluded
- The frozen PF119 symbolic research is **not** part of this release: it is absent from the shipped tree, is not imported by any runtime module, and no part of it is claimed as a shipped feature.
- OS-backed monotonic trust, same-UID isolation, rollback guarantees and native Core enforcement are not claimed or implemented by this release.
- No new ALLOW is introduced by the scanner change: the action policy is untouched.

### Fixed (release-lane follow-up, not part of the frozen scanner checkpoint)
- **Throughput accounting in the release benchmark runner.** The runner divided the one-pass corpus size by the summed wall time of *all* repetitions, under-reporting throughput by a factor of `reps` (300x for the release runs). The numerator is now `chars x reps`, and the pooled path uses `sum(cell_chars x cell_reps)`. The full benchmark was re-run from scratch and every derived artefact regenerated. The formula is pinned by `bench/test_throughput_accounting.py`. The frozen scanner checkpoint is unaffected: no runtime module changed.

### Verification
- Full public retained suite under a compatible Hermes Core: **319 passed** (298 published + 21 new).
- Public retained suite without Hermes Core (`hermes_cli` not importable): **305 passed**; 14 Core-dependent cases cannot run (13 error at setup, 1 fails).
- Native integration through Hermes Core's own plugin discovery and hook dispatcher (`invoke_hook`): **13 passed**, Core `0bf92a126102d274ff2d6a839cf8b83ab75ac3d0`.
- Differential against published v1.1.8 over 20 control and benign cells: **0 parity mismatches**; 13 required security detections all fire and 5 benign controls stay clean.
- Full B2 benchmark on the original archived corpus: 11 result cells and 10 B1 action cells, 300 measured samples each, fixed CPU affinity, one child process per variant, raw samples archived. See the release dossier for the measured p50/p95/p99/max and the actual chars/s.

### Known regression against the released 1.1.7 baseline (measured, not hidden)
- **The B1 `pre_tool_call` path is slower than 1.1.7.** Measured on the same run, the pooled B1 mean latency is ~15% higher than 1.1.7's and the pooled B1 p95 measures 1.0745x 1.1.7's. The B4 relative-regression gate therefore reads **FAIL**.
- This regression is **inherited from 1.1.8, not introduced by 1.1.9**: published 1.1.8 already measures 1.188x 1.1.7's B1 mean, the candidate's `policy.py` is byte-identical to published 1.1.8, and the candidate is not slower than published 1.1.8 on the same measurement. 1.1.8's `policy.py` differs from 1.1.7's and 1.1.8 added `executable_view.py`, `action_context.py` and `pf_locale.py` to the action path.
- The B4 **verdict is not stable**: over 12 independent repeats of the identical measurement, 8 passed and 4 failed, because the B1 p95 statistic sits at the sub-millisecond noise floor. The mean-latency regression is real; only the p95 boundary is unstable. Evidence: `bench/check_b4_stability.py`, `bench/check_b1_attribution.py`.

### Limitations
- Parity is bounded by the corpus. It is **not** a proof of all-input equivalence.
- The 20 ms p95 budget is a property of the scanned corpus, not a universal latency bound: large finding-bearing documents remain slower than benign ones.
- The published tree's "22 files / 23 tree entries" description in README.md is superseded by the file list in the release dossier for 1.1.9.

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
- Retained public regression tests and Core-dependent integration tests: 298 pass with a compatible Hermes Core; 284 pass without Core (14 Core-dependent cases unavailable). Full historical dependency closure is preserved in a separate private audit artifact.

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
