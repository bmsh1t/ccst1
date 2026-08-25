---
description: On-demand component intelligence for a target — version applicability, OSV/GHSA/NVD, KEV, EPSS, local scanner signals, and identity hints. Usage: /intel target.com
---

# /intel

Fetch actionable component intelligence for a target. This is the primary intel workflow.
Every result is an
advisory/hypothesis input, not a validated finding.

## Run This (the only required step)

```bash
python3 tools/intel_engine.py --target target.com
```

Optional when the tech stack is known:

```bash
python3 tools/intel_engine.py --target target.com --tech next.js:15.2.1,graphql
python3 tools/intel_engine.py --target target.com --json
```

`--json` is a bounded machine summary. The complete normalized owner remains at
`recon/<target>/intel.json`; the summary exposes `source_coverage_gaps` for
explicit long-tail review rather than copying the full advisory owner to stdout.

`--program` remains accepted for compatibility, but target/program disclosure
research is owned by `tools/disclosure_search.py` and the `disclosed-researcher`
workflow rather than the component advisory artifact.

## What This Does

- Rebuilds `recon/<target>/live/technology_inventory.json` from httpx JSONL or
  legacy text plus Nmap service/version/CPE artifacts, preserving observed
  component versions, ports, protocols, and host/URL evidence. A port without
  product identity is retained as an inventory observation but is not queried as a CVE.
  A named product without a version gets one bounded NVD representative page only
  when its mapping explicitly allows it; generic service/banner identities are
  skipped for product-wide NVD expansion.
- Queries exact package/version data from OSV where an ecosystem mapping exists,
  supplements it with GitHub Advisory, and uses NVD as a keyword fallback.
- Enriches matching CVEs with CISA KEV and batched EPSS data. Existing canonical
  Nuclei/CVE findings may add a local template signal; `/intel` does not run the
  template or create a finding.
- Runs optional identity intel only with `tools/intel_engine.py --with-identity`:
  `emailfinder` and `LeakSearch` via the shared Osmedeus-compatible tools directory or PATH.
- In the same main invocation, mines cached recon / JS / source artifacts for emails, internal hostnames, webhook URL patterns, secret prefixes, customer mentions, internal API paths, and employee handles; `local_intelligence` records `ok` or a diagnostic `error` without hiding advisory results.
- Atomically publishes schema-v2 `recon/<target>/intel.json`, then `/surface`
  consumes it through the shared Intel decoder.
- When official sources leave a bounded gap, `/autopilot` may collect verified
  Web Intel through `tools/web_intel_artifact.py`; search snippets alone never
  become advisory evidence. The recorder writes `evidence/<target>/web-intel/`.
- Appends identity/source context to `evidence/<target>/intelligence.md` and
  identity hints under `evidence/<target>/identity_intel/`.

## Applicability And Failure Semantics

- `affected`: an exact package/version query returned the advisory as applicable.
- `likely`: package identity is strong but exact version proof is incomplete.
- `unknown`: keyword/product relevance exists without trustworthy version-range proof.
- `not_affected`: reserved for explicit advisory/range evidence that excludes the
  observed version. An empty OSV exact-version response records a successful query
  with zero advisories; it is not a global clean verdict for the component.
- Each source records `ok`, `partial`, `unavailable`, or `error`, fetch time,
  cache/stale state, and an error summary. A single source failure preserves other
  results. If every advisory source is unavailable or fails, `intel.json` is still
  published with the source states and the CLI exits non-zero.
- `--json` writes only valid JSON to stdout; progress and diagnostics use stderr.
- `affected`, `likely`, `unknown`, and `not_affected` are applicability states,
  not finding lifecycle states. A Web claim must match the observed component
  name/version before it can be merged; a version mismatch stays `unknown`.

## Autopilot Continuation

When compact state returns `run_intel`, run `/intel` and refresh state. When it
returns `collect_web_intel`, use the bounded `recommended` query, verify the
source body, include the supporting exact `body_excerpt`, then record a
provider-neutral JSON payload. Select Grok Search or
Smartsearch for the query; do not call both unless the first result is insufficient
or conflicting.

```bash
python3 tools/web_intel_artifact.py record --target TARGET --input WEB_INTEL.json
python3 tools/intel_engine.py --target TARGET
```

When it returns `test_advisory_applicability`, add the advisory to the existing
`action_queue`, perform the smallest safe reachability/version check, preserve
raw evidence, and resolve the same action. A blocked provider or unavailable
source is recorded as `blocked`/handoff; it is never treated as clean.

When it returns `review_intel_group`, the bounded sidecar has closed its
representatives but still has raw advisory facts outside the default context.
Use the read-only query to inspect the group a page at a time; the query never
mutates Intel state:

```bash
python3 tools/intel_artifact.py query --target TARGET --component COMPONENT \
  [--version VERSION] [--host HOST] [--severity HIGH|CRITICAL] \
  [--applicability affected|likely|unknown] [--kev] [--cursor CURSOR] --limit 8
```

For a versionless product NVD coverage gap, use the cursor from the source gap
with the explicit read-only source pager. It only caches the requested NVD page
and never writes `intel.json`, Finding, or Queue state:

```bash
python3 tools/intel_sources.py nvd-page --component COMPONENT \
  [--version VERSION] [--keyword KEYWORD] [--cursor CURSOR] --limit 8
```

The cursor is bound to the normalized component/query and the NVD result-set
size. A changed query or result set is rejected as stale; a page with
`has_more=true` is not complete coverage.

After reviewing the pages, use the existing `tools/action_queue.py` add/resolve
commands. For a group-level disposition, keep `intel_group_key` and the exact
`intel_owner_binding` from state in metadata; do not create a finding merely
because an advisory exists. An owner refresh invalidates the old group
disposition and makes the group reviewable again.

## How To Use The Output

- CVE/advisory hits → review `applicability`, KEV/EPSS, source references, and
  the observed component version; then verify a reachable code path before testing.
- Disclosed-report patterns → transfer methodology, not payloads blindly.
- Emails/LeakSearch → SSO, invite, reset-flow, and tenant-discovery hypotheses; do not auto-login or credential-stuff.
- Internal hosts/webhook patterns/secret prefixes → pivot to source, JS, or exposure artifacts for the full evidence path.

## Related Helpers

- `tools/disclosure_search.py` / `disclosed-researcher`: targeted disclosed-report pattern transfer.
- `python3 tools/fresh_code.py --target target.com`: recent code/feature signals.
- `/surface target.com`: ranks intel-backed leads when artifacts exist.

These helpers are Claude-invoked and not auto-run by `/intel`; call them only
when the current hypothesis needs their specific signal.
