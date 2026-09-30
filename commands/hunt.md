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
| probe 的 endpoint/method/actor/variant | **执行事实**（Probe/Runner 登记到 Store observation） |
| claim 的 family/technique/risk_tier | **AI 判断**（按当前假设填写 activation metadata；类别模板已退役） |
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

Success signal: a concrete scanner/probe artifact is written and any claimed domain registration has a Store receipt. Raw scanner summaries remain advisory. If no artifact is written, inspect the command result.

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

A signal with replayable evidence becomes a candidate finding through
the Store claim API in step 7 — without waiting for the operator to ask. Prose or a
raw probe alone is not a finding; `/validate` in step 9 can only run against a
finding that already exists in the target Store. This mirrors
autopilot's promotion contract (Lead -> Signal -> Candidate -> Validated Finding
through explicit claim/evidence registration and `/validate`), so hunting outside autopilot does not
silently drop candidates at session end.

Already-executed native/browser/multi-step evidence enters the same validation
path through `validation_runner.py record-evidence` after Candidate persistence
(contract: `docs/evidence-runners.md#native-evidence-registration`). Do not rerun
the experiment just to make it fit request-diff.

Do not become a passive scanner wrapper. Start with the most concrete evidence available.
`/hunt` does not generate report drafts by default; use `/report` or
`python3 tools/hunt.py --target target.com --report-only` after validation.

## Four-Layer Write-Back

Apply `skills/runtime-protocol.md#shared-memory-continuity`, as in ordinary
conversation and autopilot. Claude saves important progress without waiting for
a user reminder; bind each write to the current target:

```bash
python3 tools/target_memory.py lead "..." --target TARGET
python3 tools/target_memory.py next "..." --target TARGET
python3 tools/target_memory.py note "Unverified observation and remaining evidence gap" --target TARGET
python3 tools/target_memory.py handoff "..." --target TARGET
```

Use `dead-end` only with `--conditions`, `--reopen-when`, and an existing
`--operation-ref OPERATION_ID:0`; see `commands/target.md` for the evidence contract.
At the end of a meaningful hunt pass, inspect the read-only checkpoint:

```bash
python3 tools/checkpoint.py --target target.com
```

Checkpoint does not save target memory or create Findings/Actions (see
`commands/checkpoint.md`). Save useful progress explicitly with the target-memory
commands above; register Findings/Actions through their Store owners.

Reusable lessons should be promoted through `/retrospect`, not copied directly
from a target into the knowledge base without review.

## Optional Enrichment Before Broad Scan

Use these only when the current hypothesis needs the signal:

```bash
python3 tools/surface.py --target target.com
# Read exact cached JS/source paths with Claude Read/Grep when evidence warrants it.
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
- **403 / auth boundary**: when a target-owned 401/403 has path, proxy, framework, or sibling evidence, let Claude select the exact path/header/method representation and execute it through browser, curl, or a raw sender. Use `validation_runner.py request-diff` only when the same-method one-dimension pair fits; otherwise retain raw evidence for explicit Store claim/evidence registration. A status change alone is not proof.
- **GraphQL**: inspect schema/operation names and compare object/field authorization. Assess mutations by the actual side effects under `rules/red-lines.md` and current operator intent; test-owned reversible flows are not excluded merely because they use mutations.
- **SSRF / webhook / async**: use `tools/oast_listen.py` only when a URL-fetch or webhook sink exists.
- **Upload/import/export**: confirm parser/authorization paths with minimal samples; record state-changing leads separately.
- **JWT/OIDC/SAML/OAuth**: decode and inspect issuer/JWKS/callback/state/session binding signals before probing.
- **SQL/NoSQL JSON body**: use the target-observed body or parameter shape and let Claude choose a bounded direct request. Optionally use `validation_runner.py request-diff` for an exact same-method pair; time-shaped candidates use AI interleaved sampling with a stable trend. Keep baseline/variant evidence and stop on transport, WAF, or ordinary application noise; do not invoke a fixed matrix or encoder catalogue.
- **API leak / Swagger / Postman**: review `recon/<target>/exposure/` before widening.

## Blind/OAST Workflow

```bash
python3 tools/oast_listen.py start   --target target.com
python3 tools/oast_listen.py markers --target target.com --vuln-class ssrf --label img-fetch
python3 tools/oast_listen.py poll    --target target.com
```

Build your own payload around the marker host the `markers` command prints —
the tool contributes the unique identity, not the payload content. A callback
is a Signal; a callback carrying your marker_id attributes to the exact payload
and vuln class. Promote to Candidate only after you can tie it to a specific
sink, request, and impact path.

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

Then run `/checkpoint target.com` (read contract in `commands/checkpoint.md`) to
inspect remaining work and coverage. Explicitly save useful experience/handoff
through target memory; AI chooses the next evidence-backed lane.
