# Bound Intel Source Expansion Without Losing On-Demand Depth

## Goal

Prevent a versionless product-level advisory query from turning a target Intel
artifact into a complete vendor history database. Keep default Intel collection
bounded and useful, while allowing AI to explicitly page the long tail when
there is target evidence or a high-value hypothesis.

## Evidence

- `recon/mofa.gov.mm/intel.json` is about 124 MB with 20,852 advisory rows.
- 19,711 rows are `wordpress` with no observed version; 20,847 rows have
  `applicability=unknown`, while only 5 are `affected`.
- Most rows come from NVD keyword expansion. The current mapping explicitly
  allows WordPress without a version and the NVD collector paginates until the
  remote `totalResults` boundary or its time budget.
- The same target has a roughly 124 MB Intel engine log and historical backups.
- The current bounded sidecar/query task protects Autopilot context and Queue
  consumption, but intentionally did not change source generation.

## Requirements

1. Make source expansion policy explicit:
   - exact version or CPE: allow bounded version-aware collection;
   - versionless named product: collect only a bounded representative page and
     emit a machine-readable coverage gap;
   - generic service/banner/unknown identity: do not issue a product-wide NVD
     query by default.
2. Preserve AI depth through a read-only, cursor-bound NVD page query that can
   be requested explicitly from a coverage gap. It must not write Intel,
   Finding or Queue state; existing source-cache conventions may be reused for
   bounded response caching.
3. Keep `intel.json` bounded by page/record limits. A bounded result must carry
   query identity, remote total, fetched count, next cursor and the reason for
   truncation. It must never be reported as complete coverage.
4. Keep exact-version/CPE high-value recall. Do not solve the size problem by
   disabling all versionless intelligence or by deleting advisory families.
5. Audit Intel CLI/log output so normal runs write summaries and bounded
   diagnostics, not a second full advisory JSON copy. Machine-readable output
   remains explicit and bounded.
6. Historical raw artifacts, backups, logs and Queue history remain readable and
   are not deleted or silently rewritten. Any retention/cleanup operation is
   explicit and separately auditable.
7. Reuse existing atomic cache/artifact writers, cursor/owner-binding helpers,
   Action Queue and coverage-gap contracts. No database, event bus, Mutation
   Coordinator or new writer abstraction.

## Acceptance Criteria

- [x] A versionless WordPress fixture does not materialize the full NVD catalog;
      its artifact stays within the configured page/record bound and exposes a
      coverage gap with query, total, fetched count and cursor.
- [x] Exact version and CPE fixtures retain their existing advisory coverage and
      applicability behavior, including high-impact advisories.
- [x] Generic service/banner fixtures skip product-wide NVD queries unless an
      explicit opt-in is present.
- [x] Explicit long-tail page queries are bounded, deterministic, cursor-bound
      to normalized query and source owner, and do not mutate Intel/Queue/Finding.
- [x] Replaying the same page query is stable; changing source owner or filter
      rejects the old cursor rather than silently skipping facts.
- [x] Default Intel output and logs contain no unbounded advisory dump; summary
      counts and coverage gaps remain available.
- [x] Existing artifacts and backups remain readable; no cleanup occurs as a
      side effect of Intel refresh.
- [x] Focused Intel/Autopilot regressions, compilation and diff checks pass;
      no external target scan is performed.

## Out Of Scope

- Deleting or compacting existing `intel.json`, `.bak`, evidence or Queue files.
- Replacing NVD/OSV/GitHub sources or changing advisory applicability semantics.
- Automatically creating Queue actions for every long-tail advisory.
- Adding a new persistence system or splitting the existing Intel/Autopilot
  coordinators.
- Processing `hunt.md` runtime drift.
