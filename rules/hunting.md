# Hunting Rules

These are the canonical hunting semantics. Load this rule for `/hunt`,
`/autopilot`, or a hunting Skill; it is not part of every default context pack.

Owner boundaries:

- `CLAUDE.md` owns target context, CTF interpretation, and tool/MCP routing.
- `rules/red-lines.md` owns concrete side-effect decisions.
- `rules/coverage-gate.md` owns lifecycle names, coverage states, and completion claims.
- `rules/tool-ai-boundary.md` owns the AI/tool split and scanner-output interpretation.
- `skills/runtime-protocol.md` owns mode transitions and Skill/knowledge routing.
- `commands/autopilot.md` owns inline control and bounded specialist use.
- `skills/triage-validation/SKILL.md` owns candidate proof; `rules/reporting.md` owns reports.

---

## High-Intensity Hunting Posture

High intensity means deeper reasoning, better coverage, and stronger evidence
loops. It does not relax any owner boundary above.

Core discipline:

- Broad automation finding nothing starts manual workflow, role, object, and
  state analysis; it does not end the hunt.
- When signals are weak, use the Discovery mode defined by
  `skills/runtime-protocol.md` to generate evidence from browser/API/JS/source,
  recon, parameters, paths, and workflows.
- Define the current target boundary, map the surface, rank it, run focused
  validation, and write back what changed.
- Map broadly before deep-diving, but do not use more recon to avoid a
  high-signal surface already present.
- Route from current evidence, never an old preference, favorite bug class,
  checklist, or bounty heuristic.
- Every failed path leaves a dead-end condition, blocked note, refined
  hypothesis, coverage update, or concrete next evidence action.
- Prefer one reproducible, high-impact issue over many information-level
  observations. Keep an information-level item only as a chain seed or lead.
- When a standard method fails, change an evidence-linked dimension: role,
  object, tenant, method/version, token/origin, browser request, source route,
  workflow edge, or sibling endpoint.
- Target Case State preserves actor/session/object/private-marker continuity;
  it is working memory, not a scope gate or bug-class selector. Continue
  without treating missing case state as a blocker.

Browser-state capture and artifact import are owned by `commands/hunt.md` and
`docs/autopilot-lanes.md`.

### Value-first coverage model

- Prioritize by practical impact, exploitability, evidence strength, affected
  data/workflow, validation safety, and current coverage gaps.
  Do not prioritize by a fixed favorite bug class.
- Browser-observed APIs, JS/source-derived routes, recon, errors, parameters,
  workflows, and target history are evidence sources for any bug family.
- Maintain breadth across identity/access, injection/execution,
  server-side/file/network, client-side, business workflow, and
  infrastructure/supply-chain families. The coverage matrix is a tracking
  model, not an exhaustive capability boundary.
- Use `rules/coverage-gate.md` for family/actor coverage states, Evidence Ledger
  requirements, and all finish/handoff/no-finding claims.
- Map crown jewels and business boundaries before expanding breadth. Favor
  proven data access, authorization or tenant failure, account impact, business
  loss, or another real boundary failure.
- Follow strong evidence for injection, server-side, client-side, identity,
  workflow, infrastructure, or supply-chain issues even when another lane is
  already convenient.
- Recent release or commit evidence may raise priority; freshness alone is not
  a finding.

---

## Current Target Context

The target set supplied by the current command is the active execution context.
Keep observations, preferences, artifacts, state, and write-back isolated to it.
Do not let another target's history select or suppress this target's lanes.

Localhost, private IP, CIDR, list, and named targets remain valid inputs. Any
CTF interpretation comes from `CLAUDE.md`, not this rule.

### Temporary preferences do not cross targets

A request to skip or focus a bug class, lane, scanner module, exclusion, or test
input applies only to the target and invocation where it was stated.

New target defaults:

```text
scanner default skip = xss
scanner_full = explicit opt-in for XSS
excluded bug classes = none unless the current user turn or command flags explicitly say so
```

Do not import skips from an old target, CLI session, example, heuristic, or
target-history note. Only the current user turn can exclude a lane.

## Low-Signal Rotation

No new route, differential, or evidence across the current bounded actions is
low signal, not proof that the surface has no value. Deprioritize it, retain the
observed hosts/paths/notes, and record what evidence would reopen it.

Low-signal indicators include uniform 403/static responses, no object-shaped API
parameters, no useful JS routes, or no new lead from bounded scanner and focused
probes.

Reopen immediately when fresh browser/XHR traffic, source/JS routes,
authenticated workflows, API docs, object IDs, WebSocket/GraphQL, or business
context creates a concrete next evidence action.

## Scanner Contract

AI/tool responsibilities remain in `rules/tool-ai-boundary.md`.

### Broad scanner input and completion contract

- 常规 broad breadth 只通过
  `python3 tools/hunt.py --target <target_shell> --scan-only --quick` 进入现有
  scanner owner 和单 target runtime lock。
- `urls/all.txt`、`all_historical.txt`、gau、wayback、waymore 等 raw corpus 是完整
  证据语料，不是通用 Nuclei 的默认输入。已成功完成的 quick breadth 不因 Deep
  模式、raw URL 数量或空结果而重复执行。
- bounded Surface/projection 只是默认消费窗口，不是 AI 能力上限。需要长尾证据时，
  可按 Surface page/source/shape 分页、用 `rg` 查询 raw artifact，或根据组件、CVE、
  路径、参数和行为证据构造专项列表并运行 targeted templates。
- 集成 scanner 的 Nuclei supplement 默认关闭；显式启用时只接收有界 origin，主要
  用于已选组件/版本的 CVE 验证。SQLi/SSRF 默认走现有 probes、request-diff 和 OAST。
- `summary.json` 只证明本轮选定的 live/priority scanner
  input 正常走到 consolidation；不表示历史 URL 全量扫描、tested-clean、目标安全或攻击面耗尽。
  killed/stopped/timeout/non-zero 都是 incomplete，不得解释为零发现或 scanner complete。

## Hunt Priorities

Ask which reachable failure would cause the greatest business or user impact.
Lower-value features remain useful when they connect to identity, roles,
objects, payments, admin/config, exports, integrations, or another chain step.

### Sibling Rule

Check a bounded set of evidence-linked siblings derived from a shared handler,
object/action family, browser traffic, JS/source route, or API docs. Do not
brute-force guessed siblings merely because their names sound plausible.

### A-to-B Signal Method

After confirming bug A, spend a bounded evidence budget checking B and C for
the same demonstrated mistake before reporting. Keep B as a chain candidate
only with a concrete next action; report A only after validation, then follow
the current queue, fingerprint, and budget.

### Workflow Surfaces

Payment, billing, refund, credit, wallet, coupon, gift-card, and fund-transfer
workflows are high-value surfaces. Explore their objects, authorization, state
transitions, previews, calculations, and test-owned reversible flows.

### Rotation

After each bounded action ask whether it added evidence or reduced uncertainty.
If not across the current progress fingerprint, rotate to the next endpoint,
subdomain, or vulnerability class. Prefer fresh context to brute force, while
allowing a high-information lane to continue beyond a clock heuristic.

Validation, reporting, and specialist procedures remain with their owners
listed at the top of this rule.
