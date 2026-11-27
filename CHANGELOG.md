# Changelog — prompt-firewall

## 1.1.9 (plugin-only release candidate, 2026-11-27)

Plugin-only **performance** update of the deterministic firewall. Baseline: published v1.1.8. No Core, OS-trust, catalog or Marketplace changes are part of this release, and nothing has been pushed, published or deployed.

This release changes the scanner **and** the action path. Within the tested corpus, findings, coordinates, quarantine spans, withheld content, reason codes and hook decisions match the published comparison candidate; this is bounded parity, not a claim of universal all-input equivalence. The corrected action oracle records zero new ALLOW decisions on the tested security corpus.

### Fixed
- **Unicode `IGNORECASE` fallback for the Cyrillic gates.** The `mixed_language_override` and `ignore_previous_instructions_ru` rules use `re.IGNORECASE`, but the case-folding projection used by the fast path folds ASCII only. A non-ASCII document is now admitted to those two rules conservatively, so an upper-cased Cyrillic phrase is still detected.
- **Missing role alternative.** The `role_spoof_system_turn` rule now accepts the `endoftext` role marker.
- **Hex decoder prefix.** The hex decoder strips an optional `0x` prefix before decoding.
- **Private `re._parser` dependency.** The candidate used the private CPython module `re._parser` to derive literal gates. That module is an implementation detail and may be absent or reshaped. Its use is now guarded: when it is unavailable the affected gates are **disabled** and the **original regex scan runs instead** — no rule is silently skipped. The parser-independent fallback derives exactly the same invisible-character set, so findings and their offsets are unchanged. `tests/test_prefilter_fallback.py` proves the fallback by re-importing the package with `re._parser` hidden and comparing the finding sets.

### Added
- `_prefilter.py`: conservative literal-gate derivation. A gate is only installed when a *mandatory* literal has been proven, so a gated rule can never be silently dropped.
- Permanent release tests: `tests/test_invisible_contract.py`, `tests/test_gate_contract.py`, `tests/test_security_controls.py`, `tests/test_prefilter_fallback.py`, `tests/test_surrogate_scan.py`.
- Lazy invisible-character normalisation: a document with no invisible character is returned unchanged, with no index map materialised.
- Byte-level candidate scan for long base64 and hex runs, replacing two regex scans.
- `tests/test_surrogate_scan.py` proves the path normalizer's surrogate rejection is **exactly** equivalent to the original per-character test: exhaustively over all 1,114,112 Unicode code points and over 20,000 seeded random multi-character strings, with zero mismatches.

### Changed
- **The action path no longer repeats work it has already done.** The `pre_tool_call` policy evaluation was resolving the same shell command, the same executable view, the same write-destination analysis and the same path several times over. These are now computed once:
  - `policy.py` — `_shell_tokenize`, `_shell_write_destinations` and `executable_command_view` are memoized on their exact inputs; `normalize_path`, the bounded argument walk and the active Hermes home are resolved once per policy evaluation.
  The shell-tokenization memo is evaluation-local as well: raw command strings are not retained after evaluation and concurrent eviction cannot race.
  - `executable_view.py` — `executable_command_view` is memoized on the exact `(source, tool_name)` pair.
  - Every memo is scoped to a single evaluation (or a bounded cache keyed on the exact input), so a later evaluation always re-reads the filesystem and can never act on a stale resolution.
- `detectors.py` and `_prefilter.py` — the **frozen scanner**, byte-identical to the frozen Track B variant E checkpoint `fdd518226633eadcd0be3a1369b2e89e9efde562`.
- `grants.py`, `strings.py`, `explain.py`, `action_context.py` and `pf_locale.py` are unchanged.
- `tests/test_native_integration.py` now imports `pf_loader` itself, so the module is runnable on its own. Previously it only worked when a sibling test module had imported `pf_loader` first.

### Excluded
- The frozen PF119 symbolic research is **not** part of this release: it is absent from the shipped tree, is not imported by any runtime module, and no part of it is claimed as a shipped feature.
- OS-backed monotonic trust, same-UID isolation, rollback guarantees and native Core enforcement are not claimed or implemented by this release.
- **No new ALLOW is introduced.** The action-path work removes redundant computation only; the findings, coordinates, quarantine spans, withheld content and reason codes are unchanged, and the candidate ALLOWs nothing that 1.1.7 does not ALLOW.

### Fixed (release-lane follow-up, not part of the frozen scanner checkpoint)
- **Throughput accounting in the release benchmark runner.** The runner divided the one-pass corpus size by the summed wall time of *all* repetitions, under-reporting throughput by a factor of `reps` (300x for the release runs). The numerator is now `chars x reps`, and the pooled path uses `sum(cell_chars x cell_reps)`. The full benchmark was re-run from scratch and every derived artefact regenerated. The formula is pinned by `bench/test_throughput_accounting.py`. The frozen scanner checkpoint is unaffected: no runtime module changed.

### Verification
- Public retained suite under the available Hermes Core environment: **337 passed**; independent standalone run: **323 passed**; 14 Core-dependent cases remain **NOT VERIFIED independently**.
- Native integration through Hermes Core's own plugin discovery and hook dispatcher (`invoke_hook`): **13 passed**, Core `0bf92a126102d274ff2d6a839cf8b83ab75ac3d0`.
- Differential against published v1.1.8 over 20 control and benign cells: **0 parity mismatches**; 13 required security detections all fire and 5 benign controls stay clean.
- Corrected action oracle over 63 actual hook responses: **63/63 identical**, zero new ALLOW; scanner parity **20/20**; fallback **23/23**.
- Full B2 benchmark on the original archived corpus: 11 result cells and 10 B1 action cells, 300 measured samples each, fixed CPU affinity, one child process per variant, raw samples archived. Final candidate B2 p95 **17.8490 ms**, p99 **19.3100 ms**, maximum **40.2212 ms**; the 20 ms threshold is a p95/p99 corpus gate, not a universal maximum bound.

### The B1 regression against the released 1.1.7 baseline is CLOSED
- **Earlier candidates of this release inherited a B1 `pre_tool_call` regression from 1.1.8.** Published 1.1.8 already measured slower than 1.1.7 on the B1 mean, and 1.1.8's `policy.py` differs from 1.1.7's. The candidate inherited 1.1.8's action path byte-for-byte, so it inherited the regression; the B4 gate read **FAIL** and the verdict *flipped* between identical repeats (15/24 PASS, median ratio 0.9798), because the B1 p95 statistic sits at the sub-millisecond noise floor.
- **This release removes the inherited overhead.** The candidate's action path is now deliberately optimized, and the frozen scanner (`detectors.py`, `_prefilter.py`) is still byte-identical to the frozen checkpoint.
- **Measured on the final locked run** (same host, same corpus, same method, inside one benchmark run): candidate pooled B1 p95 **0.4027 ms** against 1.1.7's **0.5224 ms** — ratio **0.7709**; pooled B1 mean **0.2426 ms** against **0.3155 ms**. The B4 gate reads **PASS**.
- **Paired alternating AB/BA measurement** (`bench/check_b1_ab_ba.py`, 16 rounds, 300 reps x 10 B1 cells, one measurement of each variant per round in strictly alternating order): **16/16 rounds PASS**, median paired p95 ratio **0.7260**, and the run-order artefact — `|median(AB) - median(BA)|` — is **0.0119**. The independent two-round reproduction also passed with ratio **0.6791**; it is supportive, not a replacement for the 16-round evidence.
- Evidence: `bench/check_b1_ab_ba.py`, `bench/evidence/b1_ab_ba_oracle_corrected.json`, `bench/evidence/b1_attribution.json`. The AB/BA JSON stores round-level statistics; it does **not** claim to archive the individual raw samples for those rounds.

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
