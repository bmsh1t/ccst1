# Complete Repository-Root Injection Seams

## Goal

Allow every tool that reads configuration or mutable runtime artifacts relative
to the checkout to run against an isolated repository root, while preserving
existing CLI defaults and narrower path injection APIs.

## Background

Sixteen tools define `BASE_DIR` without the exact token `repo_root`:

`browser_evidence`, `browser_playwright_fallback`, `cf_solver`, `cve_hunter`,
`hypothesis_worker`, `json_inject_probe`, `remember`, `request_guard`, `resume`,
`scanner_pass_writer`, `sibling_worker`, `source_hunt`, `sql_parameter_probe`,
`vision_browser`, `waf_pass_plan`, and `zero_day_fuzzer`.

This is a candidate list, not the acceptance metric. Import bootstrapping and
defaults already replaceable through `evidence_root`, `recon_root`, `memory_dir`,
`scratch`, or explicit output paths are not missing repository seams.

## Requirements

- RR1: Classify each candidate as import-only, already injectable through a
  narrower root, or genuinely repository-root-dependent.
- RR2: For every genuine dependency, add one optional root argument at the
  highest shared function boundary and a `--repo-root` CLI option when the CLI
  itself selects repository-relative paths.
- RR3: Keep current checkout-relative behavior as the default. Reuse existing
  path, target identity, private artifact, and configuration helpers.
- RR4: Prove with `tmp_path` that explicit roots contain all mutable/config reads
  and writes and that no file is written to the source checkout.
- RR5: Do not rename existing narrower parameters merely to standardize spelling,
  and do not introduce RuntimeStore, a path service, or a generic context object.

## Acceptance Criteria

- [x] AC1: All sixteen candidates have a documented/tested classification.
- [x] AC2: Every genuine repository dependency accepts an isolated root through
  its importable API; applicable CLIs expose `--repo-root`.
- [x] AC3: Existing invocations without the new option preserve their paths and
  output schema.
- [x] AC4: Parameterized isolated-root tests observe no mutable writes beneath
  the real checkout.
- [x] AC5: Import-only and already-injectable modules receive no cosmetic
  `repo_root` parameter.
- [x] AC6: Focused tests and the core CI gate pass.

## Out of Scope

- Relocating source modules, changing package installation, Windows path/locking
  work, or centralizing all path calculation behind a new abstraction.
