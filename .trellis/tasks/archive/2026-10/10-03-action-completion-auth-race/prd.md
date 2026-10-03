# F04: action completion evidence authorization race

## Goal

Prevent a new execution Action completion from committing while any artifact of
its operation proof is unavailable or revoked, including an invalidation committed
after file verification. Preserve the operator's claim and explicit recovery path.

## Requirements

- **R1 — Commit-time authorization:** Every artifact linked to the operation,
  including control/later artifacts, must remain authorized by its latest
  availability/provenance events when completion commits. A rejected completion
  preserves independently committed events and leaves the Action claimed.
- **R2 — Current state, not unrelated revision:** Unrelated Action/artifact writes
  must not invalidate otherwise valid proof. Explicit restoration before completion
  may restore authorization under the existing byte-revalidation rules; historic
  revocation is not a permanent veto.
- **R3 — Existing identity/recovery:** Keep current-claim/version, complete and
  unsuperseded proof, command-content identity and identical replay behavior.
  After refusal and explicit restoration, the same uncommitted completion command
  can be retried. Events after a committed completion do not rewrite that history.
- **R4 — Boundary:** Keep one Store owner. Operation-proof verification/hashing
  stays before the write transaction; the new event guard adds metadata reads
  only. Do not claim atomicity against uncoordinated filesystem changes or that
  this task eliminates all existing metadata-reference hashing inside writers.

## Acceptance Criteria

- [ ] **AC1 → R1:** Real temporary Store, real verification, then a second handle's
  `availability=unavailable` or `provenance=revoked` event before completion:
  reject for either the subject or a later/control artifact.
- [ ] **AC2 → R1/R3:** Rejection creates no completion row or command receipt;
  Action stays claimed at the same version/token. Revision equals the committed
  invalidation revision, not the pre-event revision. Raw and operation stay intact.
- [ ] **AC3 → R2/R3:** Valid proof, unrelated Action writes, unrelated artifact
  events, and revoke/unavailable followed by trusted/available restoration before
  the completion transaction all permit completion. Original successful command
  replay adds no revision/proof; refused commands can succeed after explicit restoration.
- [ ] **AC4 → R3:** Existing wrong claim/version, incomplete/superseded/unbound
  operation and damaged/previously invalidated artifact checks retain their behavior;
  work-artifact and receipt-based completion remain unchanged.
- [ ] **AC5 → R4:** With Action metadata references absent, a runnable check proves
  operation-proof verification hashes before the writer and the new event guard
  does not hash. No schema, public signature, dependency, automatic retry or
  network execution is introduced.

## Background

- Plan approved on 2026-10-03; task activated and implementation completed in this session.
- Baseline: `main` at `6d4f7f9`, after F03 product commit `b460f05`; clean worktree.
- Historical audit: `/tmp/ccst-audit-2026-10-02/AUDIT.md:50-56`, F04/P2.
- Current reproduction: `research/reproduce.py` / `research/reproduction.json`:
  revocation revision 5, completion revision 6, Action completed/version 3,
  claim cleared, artifact unauthorized. Only temporary state was mutated.
- Root boundary: `tools/target_store.py:915-917` verifies before the writer;
  `:994-1000` rechecks claim/outcome/supersession but not artifact events;
  `:1075-1081` owns latest events and `:1112-1140` owns their append.
  `:663-719` owns transaction, receipt replay and commit.
- Adjacent existing behavior: `_validate_action_refs` hashes `evidence_ref` and
  `baseline_ref` at `tools/target_store.py:768-772`, called inside the writer at
  `:942,957`. This includes persisted metadata; removing it is not part of F04.

## Out of Scope

F05 actor coverage and other audit findings; changing assessment/delivery/report
authorization, work-proof semantics, post-completion revocation/replay semantics,
schema or event history; existing metadata-reference hashing inside writers;
atomic locking of arbitrary filesystem writers;
automatic retries/reconciliation, live targets or global runtime sync.

Implementation still requires approval of the final plan.
