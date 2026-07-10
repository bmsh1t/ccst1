---
description: On-demand intelligence fetch for a target — CVEs, disclosed-report patterns, identity/leak hints, and local recon/source ammunition. Usage: /intel target.com
---

# /intel

Fetch actionable intelligence for a target. This is the primary intel workflow;
legacy CVE-hunt entrypoints are compatibility paths only. These are hypothesis
inputs, not findings.

## Run This (the only required step)

```bash
python3 tools/intelligence_extractor.py target.com
python3 tools/intel_engine.py --target target.com
```

Optional when tech/program is known:

```bash
python3 tools/intel_engine.py --target target.com --tech nextjs,graphql --program h1_handle
python3 tools/intel_engine.py --target target.com --json
```

## What This Does

- Matches visible tech against CVE/advisory/disclosed-report context.
- Runs lightweight identity intel when tools exist: `emailfinder` and `LeakSearch` via the shared Osmedeus-compatible tools directory or PATH.
- Mines cached recon / JS / source artifacts for emails, internal hostnames, webhook URL patterns, secret prefixes, customer mentions, internal API paths, and employee handles.
- Appends intelligence to `evidence/<target>/intelligence.md` and identity hints under `evidence/<target>/identity_intel/`.

## How To Use The Output

- CVE/advisory hits → verify affected version and reachable path before testing.
- Disclosed-report patterns → transfer methodology, not payloads blindly.
- Emails/LeakSearch → SSO, invite, reset-flow, and tenant-discovery hypotheses; do not auto-login or credential-stuff.
- Internal hosts/webhook patterns/secret prefixes → pivot to source, JS, or exposure artifacts for the full evidence path.

## Related Helpers

- `disclosed-researcher` Task: targeted disclosed-report pattern transfer.
- `python3 tools/fresh_code.py --target target.com`: recent code/feature signals.
- `/surface target.com`: ranks intel-backed leads when artifacts exist.

These helpers are Claude-invoked and not auto-run by `/intel`; call them only
when the current hypothesis needs their specific signal.
