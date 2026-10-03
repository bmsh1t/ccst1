# F04 design proposal

Planning only. Baseline `6d4f7f9`; no product-code changes.

## Owner and flow

`action_queue._primary_resolve` → `TargetStore.transition_action` →
pre-transaction `verify_operation` → `_command` / `BEGIN IMMEDIATE` →
claim/version/outcome/supersession checks → completion proof + Action + audit commit.

`record_artifact_event` uses the same Store writer transaction. Verification's
read snapshot and file hashes are valid evidence at acquisition, but not a lock
on a later availability/provenance event. The reproduced gap is between these
two existing boundaries, not a Queue lifecycle problem.

## Minimal change

Inside the existing execution-completion mutation branch, after its claim-bound
complete/unsuperseded-operation check and before any completion insertion:

1. Read every distinct artifact ID linked through `observation_artifacts` to this
   exact operation, including control observations and all artifact kinds.
2. Use `_artifact_events(conn, artifact_id)` on the existing writer connection to
   read the latest event in each dimension. Reject a current `unavailable` or
   `revoked` state with `StoreError`, identifying the artifact/recovery boundary.
3. Otherwise continue the existing proof/Action/audit transaction unchanged.

Keep pre-transaction verification untouched. Do not call `_artifact_status`,
`_require_valid_artifact` or `_verify_operation` inside the writer: those hash files.
Reuse the event reader, not another latest-event query or persisted authorization
projection. A local metadata loop is sufficient; no new public API/helper is needed.

The write transaction serializes event writers with completion. A prior committed
invalidation is visible; a later writer cannot insert an event between this check
and completion commit. No hashes, file reads or network calls are added to the writer.

## Identity and compatibility

- Do not change `fields`/command material, operation IDs, schema, `_command`, or
  the existing early identical-receipt replay. Live revision/events are not
  command content and must not enter its digest.
- Check only artifacts of the supplied operation. Unrelated writes are not a
  conflict; avoid a blanket Store revision CAS.
- Latest-state semantics remain: explicit `available`/`trusted` restoration
  revalidates bytes through the existing event API. A restored proof can pass;
  do not require event IDs to remain identical to the earlier snapshot.
- A denied completion rolls back only its own facts. The earlier event remains;
  explicit restoration followed by the same completion command can succeed.
- Current preflight may already refuse direct Store replay after later evidence
  revocation/damage; Queue may return a saved resolve receipt. Preserve both paths.
  This task adds no post-completion history rewrite or replay guarantee.
- Work completion via artifact/receipt, assessments, reports and F03 remain unchanged.

## Guarantee limits and alternatives

This closes the Store-event authorization window, not arbitrary raw-file writes
after hashing. SQLite does not make files transactional; no stronger claim is made.
Byte tampering present at preflight still rejects through the existing verifier.

Existing `_validate_action_refs` also hashes Action `evidence_ref`/`baseline_ref`
inside the writer (`target_store.py:768-772,942,957`), including stored metadata.
That adjacent behavior is deferred: this proposal keeps operation-proof hashing
outside and adds no hashing in its event guard, not a general no-I/O writer claim.
The new boundary test deliberately omits these metadata references.

Rejected alternatives: hash again under the writer (long lock/I/O), hold a writer
across preflight (same problem), global revision CAS (unrelated-write conflicts),
event-token CAS (unnecessary conflicts after valid restoration), a new controller,
snapshot schema or automatic retry. If the user needs broader filesystem atomicity,
revise scope before implementation.

## Expected files and rollback

- `tools/target_store.py`: only the existing execution-completion mutation branch.
- `tests/test_target_store.py`: focused event-race/compatibility matrix and hash boundary.
- `.trellis/spec/backend/contracts/transactional-target-state.md`: existing completion
  contract, authorization matrix and test references; clarify the event/file boundary.

No Queue, Runner, architecture document, dependency or migration change. Revert
only code if necessary; never delete committed events, operations or completion
history. Uncommitted rejected commands remain retryable with intact evidence.
