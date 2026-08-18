# Implementation Plan

## Batch 1: Sidecar Index And Query

- Extend `build_intel_review_projection()` with a bounded omitted-group index.
- Add structured advisory filtering, stable ordering, integer cursor validation,
  bounded page projection, and a read-only CLI in `tools/intel_artifact.py`.
- Add tests for multi-component fairness, query filters, stable pagination, stale
  cursor rejection, raw-owner immutability, and legacy fallback.

## Batch 2: Continuation And Autopilot Routing

- Add group disposition lookup through existing Queue metadata and owner binding.
- Emit `review_intel_group` after representative closure when omitted groups remain.
- Thread the new action through `autopilot_state.py`, `autopilot_bootstrap.py`,
  compact next-step text, lane selection and `/intel` command guidance.
- Add regression for representative-first ordering, group review handoff, group
  closure, raw-owner reactivation, and no repeated active work.

## Verification

- `python3 -m pytest -q tests/test_intel_continuation.py tests/test_intel_artifact.py`
  (or the repository's existing Intel test module if the latter is absent).
- Run focused Autopilot bootstrap/state tests covering the new action.
- `python3 -m py_compile tools/intel_artifact.py tools/intel_continuation.py tools/autopilot_bootstrap.py tools/autopilot_state.py`
- `git diff --check`.
- Inspect diff for raw-owner mutation, unbounded response paths, duplicate state
  owners, broad exception swallowing and unrelated dirty-file inclusion.

## Rollback Points

- Batch 1 is isolated to sidecar/query and can be reverted without changing Queue.
- Batch 2 is additive: removing `review_intel_group` restores the previous
  representative-only continuation while raw artifacts remain intact.

## Result

- Added a bounded omitted-group index and read-only filtered cursor query over
  the complete Intel owner.
- Added representative-first `review_intel_group` continuation with Queue-owned
  disposition and owner-refresh reactivation.
- Routed the action through compact Autopilot state, Checkpoint and operator docs.
- Verified 413 related Intel/Autopilot/Checkpoint tests, Python compilation and
  whitespace checks without touching runtime drift or unrelated dirty files.
