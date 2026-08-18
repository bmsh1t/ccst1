# Technical Design

## Boundaries

- `tools/intel_artifact.py` remains the only owner of Intel artifact paths, validation, sidecar construction and read-only query projection.
- `intel.json` is the complete fact/cache owner. `intel-review.json` is a bounded index, not the candidate universe and not a closure ledger.
- `tools/intel_continuation.py` owns deterministic next-step selection. It may request group review, but it does not write Queue or Intel state.
- `tools/action_queue.py` remains the durable review/disposition owner. Group review metadata is an extension of the existing action schema, not a second state machine.
- `autopilot_bootstrap.py` and `autopilot_state.py` only compact and route the continuation contract.

## Data Flow

```text
intel.json (complete raw owner)
    -> intel-review.json (bounded selected + omitted group index)
    -> AI selects group/filter and invokes read-only query page
    -> AI decides applicability/defer/dismiss/next validation
    -> existing Action Queue metadata + final status
    -> continuation checks group disposition and resumes other lanes
```

## Sidecar Contract

Keep the current selected `groups` and `items`, adding a bounded `omitted_groups` list.
Each omitted entry contains only `group_key`, component name/version, advisory count,
maximum score, omitted count, and `reactivate_when`. `total_group_count` and
`truncated_group_count` remain diagnostics. The owner binding continues to include the
raw file stat tuple; no group contents are copied into the sidecar.

## Query Contract

Add a pure `query_intel_advisories(...)` helper and a small `intel_artifact.py` CLI entry.
The helper reads the validated raw owner, filters explicit structured fields, sorts by
existing severity/applicability/score/id order, and returns:

- `status`, `owner_path`, `owner_binding`, `query`;
- bounded `items` with the existing review projection plus bounded fixed ranges, local
  evidence refs and source refs;
- `total_matches`, `offset`, `limit`, `next_cursor`, `has_more`.

The cursor is an integer offset bound to the returned owner stat tuple and normalized
filters. A stale/malformed cursor fails closed with a diagnostic rather than silently
skipping rows. The page limit is fixed by the helper and cannot be used to request an
unbounded response.

## Continuation Contract

1. Preserve current inventory, freshness, web-intel, and final advisory checks.
2. Select high-value representatives first, exactly as today.
3. After those are closed, select the first sidecar group with `omitted_count > 0` or
   an omitted-group index entry that has no final Queue group disposition.
4. Return `action=review_intel_group` with group key, counts, representative IDs,
   owner binding, and a concrete query command hint. Do not claim complete.
5. `_final_queue_dispositions` recognizes a final `intel-advisory` Queue action whose
   metadata contains the same `intel_group_key` and `intel_owner_binding`; this is
   only a closure marker for that group. Advisory-level metadata continues to close
   individual applicability actions.
6. If the raw owner binding changes, all group dispositions are stale and the group is
   eligible again. Existing advisory-level version binding remains unchanged.

## Compatibility And Failure Behavior

- Valid sidecar avoids parsing the large raw owner on normal state refresh.
- Legacy or missing sidecar preserves the current raw-read fallback and behavior.
- Invalid raw JSON/schema remains an explicit `run_intel` error path.
- Query is read-only and never creates a Queue action by itself.
- Existing action types, statuses, target ownership, and atomic writes remain in use.

## Risks

- A page may still be large if advisory metadata is unusually verbose; bounded projection
  fields and a hard page cap contain this.
- Group review is intentionally AI-driven; deterministic code exposes facts and closure
  identity but does not decide exploitability or auto-create findings.
