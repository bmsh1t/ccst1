# Repository-Root Seam Implementation Plan

## Batch 1: Classify

- [x] Inspect all sixteen candidates and record `import-only`,
  `narrow-root-injected`, or `repo-root-dependent` with the owning symbol.
- [x] Exclude modules that already expose every runtime path needed by tests.
- [x] Identify current focused tests before editing each genuine dependency.

## Batch 2: Add Minimal Seams

- [x] Add optional `repo_root` only at each genuine shared boundary.
- [x] Add `--repo-root` only to CLIs that select repository-relative paths.
- [x] Replace only behavior-level `BASE_DIR` reads/writes; leave direct-execution
  import setup intact.
- [x] Reuse `target_storage_key`, config loading, private artifact helpers, and
  existing explicit path arguments.

## Batch 3: Isolated-Root Regressions

- [x] Add parameterized tests covering each changed boundary with `tmp_path`.
- [x] Assert source-checkout artifact paths are unchanged.
- [x] Verify default invocations remain backward compatible.

## Validation

- [x] Run the focused tests for changed modules.
- [x] Run the core CI command.
- [x] `rtk git diff --check`
- [x] Inspect for global root mutation, redundant parameters, duplicated path
  algorithms, unrelated rewrites, or writes escaping the supplied root.

## Rollback Point

Commit compatible seam groups separately if the changed module count is large;
each group must retain source-checkout defaults and independent tests.
