# Technical Design

## Boundaries

`recon_engine.sh` owns process/phase budgets and raw artifact publication.
`autopilot_state.py` owns next-action precedence, but reads owner projections.
`intel_engine.py`/`intel_continuation.py` own advisory normalization and the
bounded continuation view; `action_queue.py` owns durable action identity and
selection. `observation_inventory.py`, `evidence_ledger.py`,
`runtime_state.py`, and `memory/hunt_journal.py` remain separate owners.

## Incremental Changes

### AI / Deterministic Boundary

- Deterministic owners enforce scope, time/size budgets, stable identities,
  atomic persistence, dedupe, and closure invariants.
- AI receives bounded evidence packets and owns semantic decisions: whether a
  scanner delta is meaningful, which advisory fits an observed component/route,
  whether an external asset relationship is relevant, and which adjacent lane
  has the highest information gain.
- A deterministic filter may suppress only proven stale/finalized identities.
  Ambiguous signals stay visible as `parked` with evidence, reason, and a
  reactivation condition; they are not deleted or declared tested-clean.
- Queue materializes one AI review decision per evidence generation/component,
  not one durable action per advisory row. The AI decision writes back a small
  executable action or a final disposition through existing owners.

1. **Recon budget**
   - Establish a monotonic run deadline from `BBHUNT_RECON_SOFT_BUDGET_SECONDS`.
   - Add a cheap `budget_checkpoint <phase>` guard before each expensive phase.
   - Let already-running child commands finish only through their existing timeout;
     stop scheduling later phases when the deadline is reached.
   - Record `run_budget=partial` and a bounded reason. Existing raw artifacts remain
     available; no old canonical success marker is treated as current.

2. **Autopilot convergence**
   - Keep the existing explicit resume filter.
   - Add a final-state guard for scanner candidates whose evidence identity is
     already finalized or whose source is a static asset with no new observation.
   - Preserve visible candidates in the surface projection with a reason, while
     removing them from the active next-action pool.
   - Give AI a bounded `review_pool` containing deltas, provenance, prior
     disposition, and reactivation evidence instead of deciding usefulness from
     path suffixes alone.

3. **Intel/Queue budget**
   - Keep full `intel.json` as a raw/cache artifact, but build a compact bounded
     advisory projection for Autopilot (severity/applicability/high-value first).
   - Cap generated Intel review actions per generation and use existing dedupe keys.
     Normalize missing legacy IDs at selection time; do not rewrite historical Queue
     unless an explicit maintenance command is invoked.
   - Make continuation read the compact projection and final dispositions, so a
     completed advisory corpus returns `complete` without scanning 20k rows per refresh.
   - Group candidates by observed component/version and expose representative
     high-value evidence plus counts. AI selects at most one applicability
     hypothesis per group/generation, preserving access to the raw artifact.

4. **Observation / Ledger / Journal / Runtime**
   - Tag observations by ownership (`target`, `external`, `scanner`, `infra`) from
     source path and target ownership; only target-owned rows can be active candidates
     by default. Raw rows and counts remain lossless.
   - Add a parent-target aggregate Ledger summary that references child ledger paths
     and never duplicates entries.
   - Bound journal diagnostics by file fingerprint and process lifetime; retain strict
     validation for append and explicit repair/quarantine for legacy rows.
   - Make runtime derived status expose stale failure breadcrumbs separately from
     current recon/finding/queue readiness; Autopilot consumes the derived view.

## Compatibility And Failure Behavior

- Invalid/corrupt canonical JSON remains fail-fast for owner readers.
- Timeout/interruption is `partial`, never `clean` or `skipped`.
- Existing target-memory, raw URL corpus, child Ledgers, and legacy Queue rows remain readable.
- No real target or repository artifact is modified during tests; use `tmp_path` fixtures.
