# Technical Design

## Owners

- `tools/intel_sources.py`: source query policy, bounded NVD pages, source cursor
  and coverage-gap metadata. Reuse `cached_json_request` and existing cache
  validation; do not write target state.
- `tools/intel_engine.py`: assemble bounded source envelopes into the existing
  Intel artifact, preserve high-value exact-version results, and expose gaps.
- `tools/intel_artifact.py`: keep the existing bounded artifact/query contract;
  extend only where a source gap needs an explicit read-only page handoff.
- `tools/action_queue.py`: remains the only durable review/disposition owner.
- CLI/docs: explain that a gap is incomplete coverage and show the explicit
  page-query entry point.

## Default Data Flow

```text
technology inventory
    -> classify exact-version / versionless-product / generic-service query
    -> bounded NVD page(s) + source coverage gap
    -> intel.json + bounded sidecar
    -> Autopilot selects high-value representatives
    -> AI explicitly requests a gap page when evidence justifies it
    -> existing Queue/validation flow
```

The default path never loops through every remote page for a versionless
product. The first page is a bounded lead set, not a clean/completed result.

## Source Policy

Use an explicit policy function rather than scattered conditionals. It should
return query mode, reason, page/record budget and whether versionless fallback
is allowed. Exact version/CPE keeps the current high-value behavior. A named
versionless product gets a small representative budget and a gap. Generic
service/banner identities are skipped unless explicitly selected.

The implementation should retain the remote `totalResults` and next start index
in the gap. The cursor must include a normalized query fingerprint and source
owner binding, matching the safety contract already used by Intel paging.

## On-Demand Query

Expose a read-only NVD page helper/CLI using the existing source fetcher and
cache path. The result is a bounded projection with advisory identifiers,
component/query identity, applicability hints, source references, total/fetched
counts and `next_cursor`. It must never call `write_intel_artifact`, mutate
Queue/Finding, or claim that remaining pages are tested.

If the source cache is reused, only bounded response pages may be retained by
the query; do not create a second full raw owner. A failed provider returns a
blocked gap, not an empty success.

## Logging And Retention

Audit the Intel CLI entry points and shell callers. Default human output should
contain counts, source status, gap summaries and artifact paths only. Explicit
JSON output must remain bounded by the same projection limit. Do not delete old
logs/backups during refresh; a future retention command can be separate and
explicit.

## Verification

- Unit-test policy classification and NVD page truncation with synthetic
  `totalResults` larger than the configured bound.
- Test exact-version/CPE and generic-service branches.
- Test stable query cursor, stale-owner rejection, read-only behavior and gap
  reactivation.
- Test CLI/log output size and absence of full raw advisory arrays.
- Run focused Intel source/engine/artifact and Autopilot regressions, then
  compile and `git diff --check`.

## Rollback

The source policy and page-query changes are additive. Removing them restores
the prior broad source behavior while leaving existing bounded sidecar and
continuation logic intact. Historical artifacts are untouched in either case.
