# Implementation Plan

## Batch 1: P0 Control Plane

- Add recon deadline/checkpoint helpers and phase guards.
- Add regression for deep run budget exhaustion and stale success markers.
- Add Autopilot regression for finalized findings plus stale scanner/static-asset
  candidates; assert `handoff`/current evidence route rather than `resume_untested`.

## Batch 2: Intel And Queue

- Add compact advisory projection and bounded action materialization.
- Replace per-advisory durable actions with one evidence-generation AI review
  packet per component, including representative advisories, provenance, counts,
  prior dispositions, and reactivation conditions.
- Normalize missing legacy action IDs at selection time and test repeated refresh
  stability, no duplicate actions, and no over-budget full-file reads.

## Batch 3: Persistence Projections

- Add Observation ownership classification and active-candidate filtering.
- Add parent Ledger aggregate summary and closure test across child target.
- Add bounded Journal warning/quarantine behavior with strict new-write tests.
- Add Runtime derived completion projection and stale-failure regression.

## Verification

- Run focused tests per batch, then cross-layer tests for `autopilot_state`, recon
  script, Intel, Queue, observation inventory, Ledger, journal, and runtime.
- Run `bash -n tools/recon_engine.sh`, `python3 -m compileall` on touched Python,
  `git diff --check`, and the existing pressure-test subset.
- Inspect diff for raw-artifact deletion, hidden fallbacks, duplicate owners, or broad
  exception swallowing before commit.
