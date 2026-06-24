---
description: Inspect and summarize the current target set before hunting or reporting. Documents target notes, host patterns, exclusions, and related context without acting as an execution gate. Usage: /scope <asset>
---

# /scope

Inspect and summarize the current target set before hunting or reporting.

`/scope` is a documentation and target-inventory helper. It does **not** decide
whether testing may continue.

## How To Use It

Use `/scope` when you want to:

- normalize a host / domain / URL / CIDR / list target into a clean target note
- summarize wildcard coverage, sibling hosts, path patterns, or likely related assets
- capture third-party hints, staging labels, account-gated notes, or target-history context for later replay
- write down exclusions that **you** want to remember for this run

## Target-Driven Semantics

- Treat the supplied target, IP, CIDR, or primary-domain batch list as the active execution target set.
- localhost, private IPs, CIDRs, and list inputs remain fully valid.
- External policy pages and metadata are optional context only.
- `scope_snapshot.json` is documentation, not a gate.

## Usage

```text
/scope api.target.com
/scope https://target.com/api/v2/users
/scope target-staging.company.com
/scope *.company.com
/scope 10.0.0.0/24
/scope targets.txt
```

## Suggested Output Shape

```text
TARGET SUMMARY
- Input: api.target.com
- Canonical target: api.target.com
- Kind: domain / url / ip / cidr / list
- Related hosts: *.target.com, target.com
- Notes: account-gated login, GraphQL, export endpoints, staging label, third-party hint
- Follow-up: recon -> surface -> hunt
```

## Practical Checks

You can still collect useful context:

1. **Canonicalize the target**
   - strip scheme/path noise when the goal is a host summary
   - keep the full URL when the exact path matters
2. **List related host patterns**
   - root host
   - wildcard sibling hosts
   - common API/admin/files/auth variants
3. **Capture execution notes**
   - account-gated surface
   - SPA / GraphQL / upload / export / webhook hints
   - third-party / staging / CDN observations
4. **Record next action**
   - `/recon`
   - `/surface`
   - `/hunt`
   - `/validate`

## Examples

**TARGET NOTE:**

"`api.target.com` is the active target host. Likely related patterns: `*.target.com`, `target.com`. App-like API surface; next action: `/recon api.target.com` then `/surface api.target.com`."

**URL NOTE:**

"`https://target.com/api/v2/users` stays inside the current target context. Preserve the exact path for later replay, then map sibling endpoints under `/api/v2/`."

**CIDR NOTE:**

"`10.0.0.0/24` is the active target block. Probe live services, cluster them by host header / title / certificate, and feed the live surface into `/surface`."
