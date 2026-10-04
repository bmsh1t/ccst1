# F05: actor coverage must respect current evidence authorization

## Goal

Make actor coverage reflect currently usable evidence so Context Pack, Checkpoint,
and the evidence summary do not hide unresolved actor gaps. Preserve historical
observations and the existing actor matching and result vocabulary.

## Background

- F05/P2 source: October 2 audit, `/tmp/ccst-audit-2026-10-02/AUDIT.md:58-64`.
- The saved `research/reproduce.py` was rerun on 2026-10-04 at HEAD `bcb6753`:
  changing registered bytes leaves peer `covered` and gaps at 4 while evidence
  becomes `partial` with one invalid operation. Restoring bytes returns healthy
  evidence without a Store revision change. History remains intact.
- Root cause: `tools/evidence_ledger.py:333-362,409-420` interprets historical
  actor results without current authorization or registration succession.
  `tools/current_truth.py:63-119` already computes the complete integrity scope,
  but exposes only five diagnostic samples, not that scope.
- Task creation and planning were approved in restored session
  `01a1021b-e6e5-78a2-a2a3-618838eeac4a`. The final plan was approved by the user’s “go” before implementation.

## Requirements

- R1: Actor coverage must use the authorization captured with the current evidence snapshot.
- R2: Preserve original records and latest-result precedence; invalidating a newer result must not revive older coverage.
- R3: Keep the existing Store/current-truth owners, public actor states, and read-only consumers.
- R4: Respect owner-derived registration succession. Superseded registrations
  cannot authorize actor coverage, even when their replacement has no observations
  or an earlier observation timestamp. Independent attempts remain independent.

## Acceptance Criteria

- [x] AC1 (R1): Changed, missing, explicitly unavailable, or revoked evidence makes
  its selected actor result `pending`, retaining the recorded result, timestamp,
  and reference. Damage to a control also invalidates its operation's subject.
- [x] AC2 (R1, R3): Healthy matching evidence retains existing states, including
  healthy historical v2/incomplete-identity actor behavior; no-record requirements
  remain `missing`. Restored bytes regain authorization on the next read unless
  an explicit availability/provenance event still denies it.
- [x] AC3 (R1, R2): A damaged newer result cannot expose an older same-key result
  as current. Local damage preserves independent healthy coverage; all damaged
  operations are considered even beyond the five displayed diagnostics.
- [x] AC4 (R1): Truncated or unlocalizable damage cannot authorize any matching
  actor result. Missing/unreadable Store behavior remains an explicit failure,
  never an empty healthy view or legacy fallback.
- [x] AC5 (R2, R4): Zero-observation and backdated replacements retire their
  predecessors. Other unsuperseded attempts still participate in normal ordering.
  Historical records and result counts remain available unchanged.
- [x] AC6 (R1, R3): Evidence summary, Context Pack, and Checkpoint use the
  authorization of their acquired snapshot without hidden rechecks or caches.
  Gaps remain advisory; reads do not change Store revision or create actions.

## Out of Scope

F04 or other audit repairs; execution scheduling or network activity; new scanners,
coverage policy, controllers, schema changes, automatic migration, real target state,
external report delivery, new identity requirements for actor coverage, and changes
to closure meaning. No new dependency or persisted authorization state.
