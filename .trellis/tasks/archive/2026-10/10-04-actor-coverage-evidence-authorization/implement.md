# F05 Execution Plan

## Start gate

- [x] Present the final PRD/design/validation summary and obtain subsequent user
  approval before `task.py start` or any product-code edit.
- [x] Confirm the existing task remains the implementation target and inspect the
  working tree. Do not create a second task or alter unrelated work.
- [x] Load curated context and the exact code to be edited; verify callers before
  changing the shared truth/reducer boundary.

## Ordered work

1. **Shared acquisition — `tools/current_truth.py`.** Name the existing complete
   invalid-event scope once, reuse it for closure suppression, and expose a sorted
   list or `None`. Keep history, health samples, localization, and I/O unchanged.
2. **Actor owner — `tools/evidence_ledger.py`.** Add the optional keyword scope,
   skip owner-superseded records before indexing, then gate the selected record.
   `build_summary` must pass scope explicitly from the same truth; no default
   authorization for an incomplete supplied snapshot.
3. **Owner regressions — `tests/test_evidence_ledger.py` and
   `tests/test_current_truth.py`.** Reuse real temporary Stores and existing tests
   where they establish the needed behavior. Keep the matrix below, not a new
   fixture framework or a second production reducer.
4. **Consumer regressions — existing actor tests in `tests/test_context_pack.py`
   and `tests/test_checkpoint.py`.** Retain their returned raw references, damage
   the fixture, rebuild, and assert decreased covered count, restored gaps,
   preserved history/diagnostics, unchanged Store binding, and no queued actions.
5. **Contract — `.trellis/spec/backend/contracts/validation-evidence.md`.** Extend
   the existing local-integrity/succession sections with the shared snapshot field,
   actor ordering, and compatibility boundary. Do not duplicate them in new specs.
6. Run the focused check, review the exact diff, and report the verified result.
   Fix only attributable failures. Commit/archive only through the normal review
   and approval flow.

## Regression matrix

| Case | Required proof | Owner |
| --- | --- | --- |
| Empty and healthy snapshots | Empty scope; ordinary missing/covered states; JSON serialization | Existing ledger/current-truth tests |
| Changed/deleted/unavailable/revoked evidence | Selected result pending; immutable latest fields and history; no older fallback | Parameterized ledger actor test |
| Control-only damage | Entire operation loses actor authorization, including its intact subject | Same matrix, real multi-observation registration |
| Byte restoration | Next acquisition restores coverage at the same revision; explicit denial events still win | Same actor test |
| Local damage and diagnostic cap | Six invalid operations produce six denied scopes despite five samples; healthy independent actor/closure survives | Extend local-damage current-truth regression |
| Global damage | Truncation, unlocalizable operation, or damaged incomplete identity gives `None`; matched actor pending, absent actor missing | Extend existing truncated-store stub |
| Supersession | Zero-observation or backdated successor retires predecessor; retired raw damage is not fresh damage; distinct unsuperseded attempt still participates | Parameterized ledger actor test |
| Historical v2/incomplete identity | Healthy actor coverage preserved while historical identity cannot close current closure | Existing incomplete test plus one v2 case |
| Fixed snapshot and later invalidation | Supplied truth renders its original scope without another read/hash; a fresh read observes invalidation | Strengthen existing summary-reuse test |
| Incomplete supplied truth | Missing new field fails instead of rereading or guessing authorization | Same reuse test |
| Consumer agreement | Actor gaps/counts and health reflect fresh evidence without writes/actions | Two existing consumer actor tests |

Use the real Store for evidence/events/succession. The existing
`record_observation` helper creates a new attempt and overwrites identity/detail;
it cannot directly create controls, same-attempt successors, or an explicit v2
record. Use the existing low-level registration patterns for those cases.
Complete identities are needed to prove *local* damage; incomplete identities
correctly exercise global denial instead.

## Focused validation

Run one batch, expected to fit the project's approximately 60-second targeted
budget; this is an estimate, not a measured post-change result:

```sh
python3 -m pytest -q \
  tests/test_evidence_ledger.py \
  tests/test_current_truth.py \
  tests/test_context_pack.py::test_context_pack_surfaces_actor_matrix_gaps \
  tests/test_checkpoint.py::test_checkpoint_surfaces_actor_matrix_gaps_without_creating_actions
```

These owner tests also retain Store error behavior, single-snapshot acquisition,
artifact rechecks, and unchanged closure interpretation. No build, browser test,
full suite, live target, or scanner run is needed by default. Broaden only when
an attributable dependency/contract change escapes this scope or the user asks.

Inspect the diff for duplicated authorization logic, hidden fallback reads,
history mutation, unexpected consumer changes, weak assertions, and unrelated
edits. The saved research reproducer documents the pre-fix bug; do not alter its
historical `reproduction.json` to disguise a baseline as a post-fix result.

## Planning verification recorded

- On 2026-10-04, ran `PYTHONDONTWRITEBYTECODE=1 python3 -B
  .trellis/tasks/10-04-actor-coverage-evidence-authorization/research/reproduce.py`:
  exit 0, `f05_reproduced=true`, unchanged revision/history.
- At the planning checkpoint, product implementation and post-change tests had not started.


## Implementation result — 2026-10-04

- User approved the final plan with “go”; the existing task was started before edits.
- Implemented both product owners, the four planned test files, and the existing
  evidence contract. No Store/schema/consumer production changes or target operations.
- The focused command above collected 74 cases: 72 passed; two new succession
  assertions expected `Z` rather than the Store's canonical `+00:00` timestamps.
  Corrected only those expectations. Ran
  `python3 -m pytest -q tests/test_evidence_ledger.py::test_actor_matrix_honors_registration_succession`:
  all 3 cases passed. All 74 unique focused cases have now passed across the runs.
- Independent read-only review covered all seven changed files: no blocking
  findings. Direct two-argument reducer compatibility was inspected, not separately
  executed. Main reviewed the diff; `git diff --check` passed.
- No additional lint, typecheck, build, or full-suite run: the focused behavior
  checks provide the applicable evidence. The user approved commit and archival; work commit is `70871aa`.

## Bug analysis

### 1. Root cause category

Cross-layer contract and test-coverage gap: the actor reducer received historical
records but not the integrity decision already used by closure.

### 2. Why fixes failed

No production fix failed. The initial test failure was an incorrect timestamp
representation expectation, not an ordering or authorization defect.

### 3. Prevention

One complete acquired scope drives both projections; tests reject diagnostic-sample
truncation, older-result revival, missed controls, and hidden snapshot rereads.

### 4. Systematic boundary

All production actor calls use the same summary. Context Pack and Checkpoint
regressions cover propagation without new actions or domain writes. No wider audit
repair or new authorization owner was introduced.

### 5. Knowledge capture

The existing `validation-evidence.md` contract now records the field, reduction
order, compatibility, error behavior, and required regression assertions.
