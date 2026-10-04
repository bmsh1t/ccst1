# F05 focused evidence — 2026-10-04

Base HEAD: `bcb6753`. These anchors describe pre-change code; follow symbol names
after implementation shifts lines. The main session read the architecture and
selected contracts directly. One read-only scout checked ordering/test edges;
the compatibility scout hit a rate limit, so the main session checked consumers.

## Existing owners and usable contract

- `tools/target_store.py:2485-2558`, `TargetStore.closure_records`: one checked
  metadata acquisition; complete invalid operations, per-acquisition artifact
  deduplication, and raw history returned separately. `:2516` derives superseded
  from operations, including successors without observations; `:2522` orders by
  observation time/revision/step; `:2543` excludes retired operations from checking.
- `tools/current_truth.py:63-119`, `_store_truth`: combines artifact and current
  v3 identity failures, expands whole-operation damage, and distinguishes local
  versus global denial. `:104` truncates display samples to five only.
- `tools/closure_projection.py:278-305`, `suppress_unauthorized_closures`: already
  accepts `invalid_event_ids` with `None` meaning global. `:315-319` separately
  excludes superseded registrations before closure interpretation.
- `tools/evidence_ledger.py:321-370`: actor key and latest reduction; it currently
  lacks integrity/succession checks. `:420` is its only production caller.
- `tools/evidence_identity.py:125,134-141`: actor covering results include signal
  and candidate; its completeness predicate does not require closure identity.

## Integration checks

Required source contract excerpt from
`.trellis/spec/backend/contracts/transactional-target-state.md:159-165`:

> `closure_records(limit=20000, verify=False)` preserves the ordinary facts-only
> query. `verify=True` explicitly acquires integrity for every operation on the
> same metadata connection/snapshot and returns `invalid_operations` separately
> from historical records. Current truth requires that checked read; a missing
> verifier is never treated as permission to skip integrity. Truncated prefixes
> remain damage and cannot authorize closure. Subsequent queries recheck bytes
> and artifact events even when the Store revision has not changed.

The source contract exceeds the 32 KiB injection limit; this bounded excerpt and
the anchors below avoid depending on a silently truncated injected document.
Consult the authoritative source sections directly if the boundary changes.

- `tools/evidence_ledger.py:386-420`: supplied `_truth` bypasses acquisition;
  otherwise summary uses current truth. The new field belongs to this internal
  snapshot contract, not a health-derived fallback.
- `tools/context_pack.py:921-929` and `tools/checkpoint.py:1064-1085` reuse one
  acquired truth for actor summaries. Existing public Pack shortcut inputs do
  not replace fresh owner acquisition (`tests/test_context_pack.py:301-325`).
- `tools/coverage_matrix.py:979-985,1309-1332` compares source/health/closure and
  fingerprints closure. The actor scope is additive; no consumer derives actor
  authorization from that fingerprint or stores a separate actor snapshot.
- `tests/test_exact_evidence_identity.py:165` serializes truth to JSON, and
  `tests/test_native_first_replay.py:176-180` compares repeated truth acquisitions.
  Use a sorted list, not a set, at the returned boundary.
- Focused caller/shape searches found no direct actor callers besides the summary
  and no handcrafted supplied truth requiring a compatibility fallback.

## Fixtures and counterexamples

- `tests/test_evidence_ledger.py:27-50`, `record_observation`: real temporary
  Store, distinct raw per attempt, increasing timestamps. It overwrites identity
  and detail, so controls/v2/succession require direct registration patterns.
- `tests/test_current_truth.py:411-447`: existing local damage/no-resurrection
  case; extend with complete actor-matching identities and more than five failures.
- `tests/test_current_truth.py:181-217`: small truncation stub avoids a 20k-row
  setup. `:321-340` snapshot reuse test currently intercepts only legacy loading;
  strengthen it to prohibit fresh acquisition and artifact verification too.
- `tests/test_target_store.py:1858-1872`: subject/control registration pattern.
  Controls use `identity_status=none` (`tools/target_store.py:1191-1193`).
- Empty successor must be `outcome=unknown` (`tools/target_store.py:1266`). A
  backdated successor is legal when both observations follow attempt start
  (`:1286`). Independent attempts share actor matching keys but not succession.
- `tests/test_evidence_ledger.py:208-219` already preserves incomplete-identity
  actor coverage; do not turn this repair into a v3-only policy.
- Consumer tests: `tests/test_context_pack.py:776` and
  `tests/test_checkpoint.py:1878`; actor gaps are context, never automatic actions
  (`.trellis/spec/backend/contracts/runtime-autopilot.md:52-66`).

## Reproduction

The saved local-only script was rerun successfully: after raw damage,
`ledger_status=partial`, `invalid_count=1`, but peer stayed `covered` with four
gaps. Byte restoration recovered health; revision/history did not change.
No live targets, scanners, or post-change tests were run during planning.
