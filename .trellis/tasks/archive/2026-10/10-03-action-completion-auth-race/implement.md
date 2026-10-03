# F04 implementation plan

## Sequence

1. [x] Obtain explicit approval of the final plan, then `task.py start`. Recheck
   baseline/diff; read canonical architecture, owner contracts and exact code.
2. [x] Add `test_execution_completion_rechecks_artifact_authorization` in the
   existing Store tests. Use `make_store`, `create_action`, `observation`, a real
   bound attempt/complete operation, and a second real Store handle. Do not use
   `record()`, which creates an unbound attempt.
3. [x] Inject one event window after actual preflight and before the writer by
   wrapping `_command` only for the designated completion command, delegating
   unchanged to the original. No sleeps, threads or mocked authorization/SQL.
   Select artifacts by exact operation/step/kind, not arbitrary `LIMIT 1`.
4. [x] Cover unavailable/revoked subject and later control, valid/no event,
   unrelated Action/artifact events, and unavailable→available / revoked→trusted
   before mutation. Assert injection actually occurred and check AC1–AC4 facts.
   For denial, restore explicitly and retry the same completion; replay successful
   completion without new proof/audit/revision. Never treat a lock error as the
   expected authorization refusal.
5. [x] Add `test_execution_completion_verifies_operation_before_write_transaction`:
   use empty Action metadata, wrap the real `_connection` to track writer entry
   and the real `_artifact` to assert operation-proof hashing occurs only before
   it; require hashing to occur and completion to commit. Keep real SQLite.
   This does not test or fix existing metadata-reference hashing inside the writer.
6. [x] Establish red on a revoked-proof case, then add the metadata-only guard in
   `transition_action`; do not alter command material or shared receipt ordering.
7. [x] Update the existing transactional-state contract, then run one focused
   batch below. Independent full-scope review and main-thread diff inspection;
   fix only attributable in-scope issues. Ask before any scope expansion.
8. [ ] Present the exact three-file commit plan for approval, then commit and
   finish/archive this task only. No push or automatic next task.

## Planned focused check

First two nodes are planned additions. Existing node names were checked by AST;
none of this product-test batch has run during planning. Expected under 60 seconds.

```bash
python3 -m pytest -q \
  tests/test_target_store.py::test_execution_completion_rechecks_artifact_authorization \
  tests/test_target_store.py::test_execution_completion_verifies_operation_before_write_transaction \
  tests/test_target_store.py::test_execution_completion_rejects_unbound_stale_and_damaged_evidence \
  tests/test_target_store.py::test_completion_proof_and_audit_roll_back_together \
  tests/test_target_store.py::test_claims_are_compare_and_swap_and_concurrent_registration_is_idempotent \
  tests/test_target_store.py::test_non_execution_work_records_artifact_without_fabricating_http_evidence \
  tests/test_target_store.py::test_operation_verification_checks_all_material_in_one_snapshot \
  tests/test_target_store.py::test_artifact_invalidations_are_append_only_and_authorization_is_derived \
  tests/test_target_store.py::test_partial_recovery_requires_all_attempts_registered \
  tests/test_validation_runner.py::test_record_evidence_claim_stays_open_until_explicit_completion
```

No full suite, build, real target or new dependency is required by default. Broaden
only if observed cross-owner risk warrants it; record unrelated/environment failures.

## Planning evidence

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  .trellis/tasks/10-03-action-completion-auth-race/research/reproduce.py
```

2026-10-03 on `6d4f7f9`: exit 0; reproduced revoked revision 5 followed by completion
revision 6, `completed`, cleared claim and unauthorized artifact. This is bug
reproduction, not acceptance. Temporary Store only; historical audit script not run.

Final planning checks: `task.py validate` passed (3 implement / 2 check entries);
AST verified 8 existing nodes and distinguished the 2 planned additions. Manifest
paths/sizes and document whitespace/placeholders passed. Read-only plan review
found only the hash-boundary wording issue; main verified and corrected it.
Final product diff is empty, task status is `planning`, and implementation has not started.

## Review and rollback gates

- [x] New guard reads every relevant artifact's latest state on the same writer connection.
- [x] No operation-proof hashing moved into the writer, hashing in the new event
  guard, global/event-token CAS or digest changes; existing metadata hashing disclosed.
- [x] Negative tests distinguish genuine authorization rejection from lock/fixture errors.
- [x] Current restoration, retry, work-proof and F03 boundaries remain unchanged.
- [x] Reverting code does not mutate evidence/event/Action history.
