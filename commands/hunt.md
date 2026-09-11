---
description: Start active hunting on a target using cached recon, AI-first surface review, optional enrichment, hunt memory, and focused vulnerability testing. Usage: /hunt target.com
---

# /hunt

Active vulnerability hunting through Claude CLI. Use the scanner as a bounded breadth and candidate sensor when useful; use surface evidence for Claude to choose exact probes and validation.

## 谁思考（认知归属）

参数认知归属见 `rules/tool-ai-boundary.md#谁思考`。本命令的关键分工：

| 输入 | 谁思考 |
|---|---|
| 假设选择、路线、验证深度 | **AI 判断** |
| probe 的 endpoint/method/actor/variant | **机器推导**（`--from-evidence`/`--from-probe`） |
| claim 的 family/technique/skill_route/risk_tier | **机器推导**（`--template idor-cross-actor` 等） |
| claim 四件套（hypothesis_id/expected_learning/kill_condition/decision_reason） | **AI 判断**（永不模板化） |
| target、ledger 落账、锁、witness | **机械** |

## Run This (the only required step)

Replace `target.com` with the supplied target.

Before running active probes, apply `skills/runtime-protocol.md#shared-knowledge-recall`.
When no matching Pack is available, build one:

```bash
python3 tools/context_pack.py --target target.com
```

For this hunting entrypoint, also read `rules/hunting.md`. It is the canonical
hunting semantics and is loaded on demand rather than by every context pack.

```bash
python3 tools/hunt.py --target target.com --scan-only      # recon exists → scan cached surface
python3 tools/hunt.py --target target.com                  # recon if needed, then scan
python3 tools/hunt.py --target target.com --quick          # lower-cost path
python3 tools/hunt.py --target target.com --scan-only --scanner-full  # expanded bounded scanner/candidate coverage; no fixed payload lanes
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

Fast path: when concrete evidence is already in hand (browser-observed requests,
cached recon artifacts, an explicit lead, or the selected Skill/card contents
already read in this conversation), go straight to step 5 ATTACK. The target and
scope confirmation in step 1 LOAD is not skippable — confirm target identity
before touching it.

```text
1. LOAD      Reuse or refresh context-pack, then read /surface output, target memory, cached recon, findings, and guard hints
2. ROUTE     Select the main Skill using skills/runtime-protocol.md
3. REVIEW    Build an evidence-backed surface view; Claude chooses the highest-value workflow: account, admin, API, export, upload, webhook, GraphQL, invite, report/download
4. KNOWLEDGE Read the selected Skill/cards through the shared recall rule; reuse contents already in context
5. ATTACK    Reduce one hypothesis to exact requests: auth, role, object, method, version, body diff
6. CHAIN     Check siblings, roles, versions, and side effects when a signal appears
7. RECORD    Preserve leads/signals/candidates with exact next evidence actions in target memory
8. COVERAGE  Apply rules/coverage-gate.md before finishing or rotating
9. VALIDATE Use `/validate` only when a Candidate is ready for report-quality proof
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

Checkpoint writes target memory automatically (see
`commands/checkpoint.md#写回契约权威定义`); pass `--no-apply-target-memory` only
when the operator explicitly wants the memory write skipped.

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

1. Use chrome-devtools MCP for deep live DevTools, Network, Console, DOM, performance, and runtime inspection.
2. Use Playwright MCP for page interaction, authenticated sessions, forms, screenshots, and multi-actor workflows.
3. Import MCP artifacts with `python3 tools/browser_mcp_import.py --target <target> --network-json <file> --url <page-url>` so `recon/<target>/browser/`, `/surface`, `/checkpoint`, and `/autopilot` can continue on browser-observed XHR/API artifacts before converting them to curl/local probes.

## High-ROI Lanes

- **Auth / IDOR / role diff**: compare A/B users, object IDs, tenant/account IDs, export/download/report results.
- **403 / auth boundary**: when a target-owned 401/403 has path, proxy, framework, or sibling evidence, let Claude select the exact path/header/method representation and execute it through browser, curl, or a raw sender. Use `validation_runner.py request-diff` only when the same-method one-dimension pair fits; otherwise retain raw evidence or a target-owned `finding_claim` for checkpoint. A status change alone is not proof.
- **GraphQL**: inspect schema/operation names, compare auth on `query`, `node(id)`, and safe read operations; mutation execution requires explicit operator intent.
- **SSRF / webhook / async**: use `tools/oast_listen.py` only when a URL-fetch or webhook sink exists.
- **Upload/import/export**: confirm parser/authorization paths with minimal samples; record state-changing leads separately.
- **JWT/OIDC/SAML/OAuth**: decode and inspect issuer/JWKS/callback/state/session binding signals before probing.
- **SQL/NoSQL JSON body**: use the target-observed body or parameter shape and let Claude choose a bounded direct request. Optionally use `validation_runner.py request-diff` for an exact same-method pair; time-shaped candidates use AI interleaved sampling with a stable trend. Keep baseline/variant evidence and stop on transport, WAF, or ordinary application noise; do not invoke a fixed matrix or encoder catalogue.
- **API leak / Swagger / Postman**: review `recon/<target>/exposure/` before widening.
- **IIS short filename**: when IIS is detected, use `shortscan <url> -s -p 1`; if `shortscan` is missing, keep a manual review hint instead of failing.

## Blind/OAST Workflow

```bash
python3 tools/oast_listen.py start --target target.com
python3 tools/oast_listen.py poll --target target.com
```

A callback is a Signal. Promote to Candidate only after you can tie it to a specific sink, request, and impact path.

## Scanner Controls

```bash
python3 tools/hunt.py --target target.com --scan-only --scanner-full
python3 tools/hunt.py --target target.com --scan-only --scanner-skip module1,module2
ALLOW_UNSAFE_HTTP_TESTS=1 python3 tools/hunt.py --target target.com --scan-only --scanner-full  # opt-in only for the scanner's guarded state-changing method checks
```

- SQLi, XSS, SSTI, upload, MFA, and SAML scanner lanes are candidate-only; AI selects the observed request and validation medium.
- `--scanner-full` increases bounded scanner inputs where supported; it does not add fixed payload or virtual-endpoint sweeps.
- Scanner `remaining` and `candidate_only` entries are residual work, never a clean or validated result.
- `--scanner-skip` is per invocation only; do not inherit it across targets or sessions.

## When To Stop Or Rotate

Rotate when:

- three focused variants return identical status/body shape;
- no auth, object, role, parser, or sink evidence remains;
- the current first-review surface is exhausted and `/surface` only shows follow-up hints.

Then run `/checkpoint target.com` (write-back contract in
`commands/checkpoint.md`): its output updates target memory, explains remaining
coverage, and moves to the next evidence-backed lane.
