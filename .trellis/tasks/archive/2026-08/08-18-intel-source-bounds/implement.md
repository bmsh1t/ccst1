# Implementation Plan

## Batch 1: Source Query Policy

- [x] Add one reusable policy decision for exact version/CPE, versionless product
  and generic service/banner identities.
- [x] Bound default NVD pages/records and emit coverage-gap metadata without
  changing advisory normalization or applicability semantics.
- [x] Add focused fixtures for WordPress, exact version/CPE and generic services.

## Batch 2: Explicit Long-Tail Paging

- [x] Add a bounded read-only NVD page helper/CLI using existing fetch/cache helpers.
- [x] Bind cursors to normalized query and source owner; reject stale or mismatched
  cursors.
- [x] Route the gap through existing Intel/Autopilot continuation and Queue review,
  without auto-materializing all advisory rows.

## Batch 3: Output And Regression

- [x] Audit default Intel output and log callers for full JSON duplication.
- [x] Keep historical artifacts and backups untouched; document explicit cleanup as
  a separate operation only if an existing retention owner is available.
- [x] Run focused source/engine/artifact/Autopilot tests, compilation and diff
  checks, then inspect the final diff for new state owners or broad fallbacks.

## Guardrails

- No external target requests.
- No database, event bus, Mutation Coordinator or new writer abstraction.
- No deletion or silent rewrite of existing target evidence.
- No subagents; implementation and verification remain in the primary session.

## Validation

- `563 passed` across Intel source/engine/continuation, Autopilot state,
  Checkpoint, Action Queue, Surface and operator-contract regressions.
- `python3 -m py_compile` passed for all modified Python modules.
- `git diff --check` passed.
- No external target request or historical artifact cleanup was performed.
