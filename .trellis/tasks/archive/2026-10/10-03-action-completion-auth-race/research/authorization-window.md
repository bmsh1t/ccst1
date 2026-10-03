# F04 evidence and canonical reading index

## Evidence level

Main reproduced F04 on `main` / `6d4f7f9` with `research/reproduce.py`, using only a
temporary Store and a deterministic second-handle event. `reproduction.json` is
the observed result: revoke revision 5, completion revision 6, unauthorized artifact.
Historical source: `/tmp/ccst-audit-2026-10-02/AUDIT.md:50-56` and
`reproduce.py:136-165`; its module-level nine-audit loop was not executed.

One read-only test researcher returned AST/source evidence; the separate owner
research attempt was rate-limited. Main personally traced the owner and callers;
do not count the failed attempt as an independent review or test result.

## Required canonical documents

- `docs/architecture-contract.md`: read fully; domain ownership, transactions,
  immutable raw evidence and explicit limits of SQLite versus files.
- `.trellis/spec/backend/quality-guidelines.md`: minimal owner fixes, meaningful tests.
- `.trellis/spec/backend/error-handling.md`: visible failure and transaction rollback.
- `.trellis/spec/backend/contracts/transactional-target-state.md`: signatures
  (184–194), transaction/completion/attempt contracts (430–494), artifact events
  and authorization, validation matrix and existing test references.
- `.trellis/spec/backend/contracts/lifecycle-state.md:5-24`: owner separation.

## Source anchors (planning baseline)

| Source | Fact |
|---|---|
| `tools/target_store.py:898-1022` | Completion preflight precedes `_command`; execution mutation checks claim/complete/supersession, not latest artifact events |
| `:663-719` | Writer uses target lock and `BEGIN IMMEDIATE`; exact receipt replay precedes mutation; proof/action/revision/audit commit together |
| `:1046-1067` | `_artifact` hashes and checks file identity; do not move under writer |
| `:768-772,942,957` | Existing Action metadata-reference validation hashes inside mutation; outside this operation-proof fix |
| `:1075-1081` | `_artifact_events(conn, id)` returns latest event per dimension, no file I/O |
| `:1083-1098,1112-1140` | Availability/provenance combine with bytes; available/trusted restoration revalidates bytes |
| `:1932-1960` | Verification checks every distinct operation artifact, including controls; status helpers hash |
| `tools/action_queue.py:341-347,385-434` | Completion parser/resolve delegate to Store; saved receipt path is separate from a new completion |
| `tools/target_store.py:1338-1359` | Assessment has a separate preverification/mutation path; not assessed or changed by F04 |

Production `transition_action` calls occur only in `tools/action_queue.py:366,375,429`;
first two are claim paths. No caller-side workaround is required.

## Regression reuse and decisions

`tests/test_target_store.py:32,73,79` own Store/Action/raw fixtures; `record():93`
creates an unbound attempt and cannot prove this bug. Bound setup/completion is
`:1816-1842`; ten-artifact verification is `:831-861`; both event dimensions and
restoration are `:864-897`; proof/audit rollback is `:1789-1813`.

The implementation plan lists exact existing AST-checked nodes. Proposed new
tests cover the combined race, not a fake verifier or a timing-dependent thread.
Compare rejection revision to the committed second-writer event, not initial state.

Use latest relevant event states inside the existing transaction. Global revision
guards conflict on unrelated work; adding revision/event snapshots to command
material breaks replay; event-token comparison rejects valid restoration. Preserve
existing post-completion replay/preflight behavior, not a new permanent authorization
receipt. Uncoordinated file writes after preflight remain outside this Store-event fix.

Final read-only plan review confirmed the event guard, but found the original
hash-boundary wording was too broad because of existing metadata-reference hashing.
Main checked the original caller/helper code and narrowed PRD/design/test scope
to operation-proof verification and the new guard; the adjacent issue is explicitly
deferred, not claimed fixed. No product tests or code changes occurred in review.
