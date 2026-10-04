# F05 Design: reuse acquired authorization for actor coverage

## Boundary

`TargetStore.closure_records(verify=True)` owns the checked metadata snapshot and
artifact verification. `current_truth._store_truth` owns local-versus-global
integrity scope. `evidence_ledger.actor_matrix_status` owns actor matching and
result interpretation. Consumers render that answer; they do not verify again.

Keep these owners. Product changes are limited to `tools/current_truth.py` and
`tools/evidence_ledger.py`. Store, closure reducer, Coverage, Context Pack, and
Checkpoint need no new algorithm, mutation, or production call path.

## Snapshot contract

Add `invalid_event_ids` to the current-truth result:

| Value | Meaning |
| --- | --- |
| `[]` | No integrity denial in this complete acquisition |
| Sorted, unique list of event IDs | Deny these records; other records retain their existing eligibility rules |
| `null` | Global denial: truncated acquisition or damage that cannot be safely localized |

This is JSON-safe, per-acquisition data, not a persistent schema or cache.
It conveys integrity only, not closure sufficiency, succession, or business policy.

Compute the set once using the existing `_store_truth` rules. Ready acquisitions
start with an empty set. Partial acquisitions retain the existing complete
invalid-operation set, whole-operation subject/control expansion, and localization
predicate. Pass the same set or `None` to `suppress_unauthorized_closures`, then
serialize it into the result. Keep closure outputs and diagnostic counts unchanged.
Never derive authority from `health.invalid_rows`, which intentionally holds five
display samples. Do not move file hashing or event reads into consumers.

## Actor reduction order

1. Ignore records marked `superseded` by the Store while building the actor index.
2. Select the latest remaining record for the existing endpoint/method/family/
   actor/object-scope/variant key, retaining Store ordering: observation timestamp,
   registration revision, then step.
3. If no record matches, emit `missing`.
4. If the selected event is denied, or the scope is global, emit `pending`.
5. Otherwise apply the unchanged completeness/side-effect predicate and existing
   result mapping, including `covered`, `blocked`, and `not_applicable`.

Damaged records remain in step 2: deleting them there would revive older results.
Supersession is different: the owner explicitly retired that registration before
interpretation. A separate unsuperseded attempt may still win after retirement;
there is no new actor-key tombstone or attempt grouping rule.

Preserve `latest_result`, `latest_ts`, and `evidence_ref` for denied matches.
Keep original `truth.records`, entry/result counts, and recent history unchanged.
Superseded-only requirements become `missing` with the existing empty latest fields.

## Wiring and compatibility

- Extend `actor_matrix_status(entries, requirements)` with an optional keyword-only
  `invalid_event_ids` argument accepting an immutable ID set or `None`; its default
  is an empty immutable set. Existing two-argument record-only calls retain their
  ordinary result mapping, with the intended supersession correction.
- `build_summary` explicitly reads the new field from its selected truth object,
  converts a list to an immutable set once per summary, and passes it to every
  actor reduction. Preserve `None`; never normalize it with `or []`.
- A supplied private `_truth` containing records but missing this field is an
  incomplete internal contract and must fail visibly. Do not silently accept it,
  infer scope from diagnostic samples, or acquire a replacement snapshot.
- Context Pack and Checkpoint already pass the same fresh truth to their summaries.
  Their production code and public output shapes stay unchanged. Preserve the
  existing fresh-read and Coverage comparison boundaries; this field does not
  introduce another cache or broaden that comparator's closure responsibility.
- Actor coverage is not closure: healthy v2/incomplete identities, signals, and
  candidates keep existing actor semantics. No new subject-only or v3 gate.
- Existing missing/unreadable Store errors, alias normalization, endpoint matching,
  public states, and no-action side effects stay unchanged.

## Risk and verification

Main risks are confusing `[]` with `null`, truncating authority to diagnostics,
filtering damaged history before reduction, and treating registration succession
as ordinary timestamp ordering. The regression matrix in `implement.md` targets
each separately, including control-only damage and immutable-snapshot reuse.

The two-argument reducer is a pure records API, not an integrity acquisition API.
All current production actor calls route through the summary and must pass scope.
The new truth field must remain deterministic and serializable for existing JSON
callers. Full-suite and performance work are deferred unless the focused check
reveals an attributable wider contract change.

## Rollout and rollback

No database upgrade, runtime installation, migration, or target operation is
needed. Deploy the two product changes together. If reverted, revert both as one
change; preserve task research and raw historical evidence. Do not restore old
target files or broaden the patch to other audit findings.
