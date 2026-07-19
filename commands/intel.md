---
description: On-demand component intelligence for a target — version applicability, OSV/GHSA/NVD, KEV, EPSS, local scanner signals, and identity hints. Usage: /intel target.com
---

# /intel

Fetch actionable component intelligence for a target. This is the primary intel workflow;
legacy CVE-hunt entrypoints are compatibility paths only. Every result is an
advisory/hypothesis input, not a validated finding.

## Run This (the only required step)

```bash
python3 tools/intelligence_extractor.py target.com
python3 tools/intel_engine.py --target target.com
```

Optional when the tech stack is known:

```bash
python3 tools/intel_engine.py --target target.com --tech next.js:15.2.1,graphql
python3 tools/intel_engine.py --target target.com --json
```

`--program` remains accepted for compatibility, but target/program disclosure
research is owned by `tools/disclosure_search.py` and the `disclosed-researcher`
workflow rather than the component advisory artifact.

## What This Does

- Rebuilds `recon/<target>/live/technology_inventory.json` from httpx JSONL or
  legacy text, preserving observed component versions and host/URL evidence.
- Queries exact package/version data from OSV where an ecosystem mapping exists,
  supplements it with GitHub Advisory, and uses NVD as a keyword fallback.
- Enriches matching CVEs with CISA KEV and batched EPSS data. Existing canonical
  Nuclei/CVE findings may add a local template signal; `/intel` does not run the
  template or create a finding.
- Runs lightweight identity intel when tools exist: `emailfinder` and `LeakSearch` via the shared Osmedeus-compatible tools directory or PATH.
- Mines cached recon / JS / source artifacts for emails, internal hostnames, webhook URL patterns, secret prefixes, customer mentions, internal API paths, and employee handles.
- Atomically publishes schema-v2 `recon/<target>/intel.json`, then `/surface`
  consumes it through the shared Intel decoder.
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
