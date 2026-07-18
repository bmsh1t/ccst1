---
description: Start active hunting on a target using cached recon, AI-first surface review, optional enrichment, hunt memory, and focused vulnerability testing. Usage: /hunt target.com
---

# /hunt

Active vulnerability hunting through Claude CLI. Run the production scanner when broad coverage is useful; otherwise use the surface review pack as evidence for Claude to choose exact probes.

Legacy CVE/report entrypoints remain available as compatibility paths, but the
primary workflows are `/intel` and `/report`.

## Run This (the only required step)

Replace `target.com` with the supplied target.

Before running active probes, load the minimal context pack:

```bash
python3 tools/context_pack.py --target target.com
```

```bash
python3 tools/hunt.py --target target.com --scan-only      # recon exists → scan cached surface
python3 tools/hunt.py --target target.com                  # recon if needed, then scan
python3 tools/hunt.py --target target.com --quick          # lower-cost path
python3 tools/hunt.py --target target.com --scan-only --scanner-full  # expanded scanner coverage; includes XSS unless skipped
```

Auth-aware examples:

```bash
python3 tools/hunt.py --target target.com --scan-only --auth-file .private/auth.json
BBHUNT_COOKIE='session=REDACTED' python3 tools/hunt.py --target target.com --scan-only --auth-from-env
```

Environment auth also supports `BBHUNT_AUTH_HEADER`; auth is propagated into
the Python helpers and shell recon / scanner toolchain where supported.

Success signal: `findings/<target>/summary.json`, `findings/<target>/findings.json`, or a concrete evidence/probe artifact is written. If no file is written, read the command output instead of restating the methodology.

## Default Hunt Loop

```text
1. LOAD      Run context-pack, then read /surface output, target memory, cached recon, findings, and guard hints
2. ROUTE     Select the main Skill using skills/runtime-protocol.md
3. REVIEW    Build an evidence-backed surface view; Claude chooses the highest-value workflow: account, admin, API, export, upload, webhook, GraphQL, invite, report/download
4. KNOWLEDGE Load only 1-2 relevant cards from knowledge/index.md when a lane needs deeper thinking
5. CHECK     Apply rules/red-lines.md before high-volume traffic, destructive changes to real data, active stored XSS payloads, or race-style load; HTTP method alone is not the boundary
6. ATTACK    Reduce one hypothesis to exact requests: auth, role, object, method, version, body diff
7. CHAIN     Check siblings, roles, versions, and side effects when a signal appears
8. RECORD    Preserve leads/signals/candidates with exact next evidence actions in target memory
9. COVERAGE  Apply rules/coverage-gate.md before finishing or rotating
10. VALIDATE Use `/validate` only when a Candidate is ready for report-quality proof
```

Do not become a passive scanner wrapper. Start with the most concrete evidence available.
`/hunt` does not generate report drafts by default; use `/report` or
`python3 tools/hunt.py --target target.com --report-only` after validation.

## Four-Layer Write-Back

During `/hunt`, write back concise state instead of relying on chat history:

```bash
python3 tools/target_memory.py lead "..."
python3 tools/target_memory.py next "..."
python3 tools/target_memory.py dead-end "..."
python3 tools/target_memory.py handoff "..."
```

At the end of a meaningful hunt pass, prefer checkpoint automation over manual
summary:

```bash
python3 tools/checkpoint.py --target target.com
```

Only use `--apply-target-memory` when the operator wants the target memory write
to happen automatically.

Use target memory this way:

- new plausible direction -> `lead`
- exact next evidence action -> `next`
- disproven or low-value lane -> `dead-end`
- stopping point or context-length risk -> `handoff`

Reusable lessons should be promoted through `/retrospect`, not copied directly
from a target into the knowledge base without review.

## Optional Enrichment Before Broad Scan

Use these only when the current surface shows the signal:

```bash
python3 tools/surface.py --target target.com
python3 tools/js_reader.py --target target.com
python3 tools/source_intel.py --target target.com
python3 tools/intelligence_extractor.py target.com
```

Then rerun:

```bash
python3 tools/surface.py --target target.com
```

Browser-state surfaces should use the shared browser evidence lane:

1. Prefer `tools/browser_evidence.py` with agent-browser CLI for routine automation, session reuse, snapshots, network, storage, and HAR evidence.
2. Use chrome-devtools MCP for deep live DevTools/network/console debugging.
3. Use playwright MCP or the explicit playwright-cli backend as compatibility fallbacks.
4. Import MCP artifacts with `python3 tools/browser_mcp_import.py --target <target> --network-json <file> --url <page-url>` so `recon/<target>/browser/`, `/surface`, `/checkpoint`, and `/autopilot` can continue on browser-observed XHR/API artifacts before converting them to curl/local probes.

## High-ROI Lanes

- **Auth / IDOR / role diff**: compare A/B users, object IDs, tenant/account IDs, export/download/report results.
- **403 / auth boundary**: try a small number of stack-specific path/header/method variants, then stop if responses are identical.
- **GraphQL**: inspect schema/operation names, compare auth on `query`, `node(id)`, and safe read operations; mutation execution requires explicit operator intent.
- **SSRF / webhook / async**: use `tools/oast_listen.py` only when a URL-fetch or webhook sink exists.
- **Upload/import/export**: confirm parser/authorization paths with minimal samples; record state-changing leads separately.
- **JWT/OIDC/SAML/OAuth**: decode and inspect issuer/JWKS/callback/state/session binding signals before probing.
- **SQL/NoSQL JSON body**: use surgical single-endpoint checks when body/parameter evidence exists; avoid broad sqlmap by default.
- **API leak / Swagger / Postman**: review `recon/<target>/exposure/` before widening.
- **IIS short filename**: when IIS is detected, use `shortscan <url> -s -p 1`; if `shortscan` is missing, keep a manual review hint instead of failing.

## Blind/OAST Workflow

```bash
python3 tools/oast_listen.py start --target target.com
python3 tools/oast_listen.py payloads --target target.com --vuln-class SSRF
python3 tools/oast_listen.py poll --target target.com
```

A callback is a Signal. Promote to Candidate only after you can tie it to a specific sink, request, and impact path.

## Scanner Controls

```bash
python3 tools/hunt.py --target target.com --scan-only --scanner-full
python3 tools/hunt.py --target target.com --scan-only --scanner-skip module1,module2
ALLOW_UNSAFE_HTTP_TESTS=1 python3 tools/hunt.py --target target.com --scan-only --scanner-full  # opt-in for side-effectful upload/MFA/SAML POST probes and PUT/PATCH method probes
```

- Standard/quick scanner skips XSS by default.
- `--scanner-full` expands active lanes and includes XSS unless explicitly skipped.
- `--scanner-skip` is per invocation only; do not inherit it across targets or sessions.
- Side-effect-capable scanner templates such as PUT/DELETE/PATCH method
  tampering, upload canary POST, MFA/OTP POST, and forged SAML POST are skipped
  unless `ALLOW_UNSAFE_HTTP_TESTS=1` is set for that invocation. This scanner
  guard does not forbid AI-guided replay of browser-observed POST, GraphQL read
  queries, search/filter POSTs, preview/validate-only flows, or test-owned
  reversible actions.

## Guardrails For Live Actions

- Reports are never auto-submitted.
- HTTP method alone is not a red line. Treat method as a side-effect hint and
  decide from the concrete operation, object, data scope, cleanup path, and
  observed request shape.
- Payment, billing, refund, credit, wallet, coupon, cart, checkout, and fund-transfer surfaces are valid high-value lanes; avoid only real money movement or irreversible lifecycle changes unless explicitly intended.
- Order/fulfillment/delivery/shipment/booking lifecycle write actions are Leads only; do not click, replay, race, or call them from this command.
- Stored XSS and live HTML/script injection are opt-in per current user turn; do not submit payloads by default.
- Request guard, rate limits, and cooldowns are advisory telemetry for pacing and replay, not a reason to stop thinking.

## When To Stop Or Rotate

Rotate when:

- three focused variants return identical status/body shape;
- no auth, object, role, parser, or sink evidence remains;
- the next step would be a state-changing action without explicit operator intent;
- the current first-review surface is exhausted and `/surface` only shows follow-up hints.

Then run:

```bash
python3 tools/checkpoint.py --target target.com
```

Use the checkpoint output to update target memory, explain remaining coverage,
and move to the next evidence-backed lane.
