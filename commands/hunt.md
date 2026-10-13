---
description: "Start active hunting on a target using cached recon, AI-first surface review, optional enrichment, hunt memory, and focused vulnerability testing. Usage: /hunt target.com"
---

# /hunt

Active vulnerability hunting through Claude CLI. Use the scanner as a bounded breadth and candidate sensor when useful; use surface evidence for Claude to choose exact probes and validation.

## 谁思考（认知归属）

参数认知归属见 `rules/tool-ai-boundary.md` 的“谁思考”一节。本命令的关键分工：

| 输入 | 谁思考 |
|---|---|
| 假设选择、路线、验证深度 | **AI 判断** |
| probe 的 endpoint/method/actor/variant | **执行事实**（Probe/Runner 登记到 Store observation） |
| claim 的 family/technique/risk_tier | **AI 判断**（按当前假设填写 activation metadata；类别模板已退役） |
| claim 四件套（hypothesis_id/expected_learning/kill_condition/decision_reason） | **AI 判断**（永不模板化） |
| target、ledger 落账、锁、witness | **机械** |

## Start From Current Evidence

Replace `target.com` with the supplied target.

Before touching the target, recover its current owner facts and Scope/Auth through
`skills/runtime-protocol.md#shared-memory-continuity`. Apply shared knowledge recall
when an information gap needs it; reuse still-current facts and already-read methods.
When the current target context is missing, read it through:

```bash
python3 tools/context_pack.py --target target.com
```

Context Pack 中的 `hot_methods` 是 6k 本地快照的只读指针。按当前信息缺口读取
`ready` 项；`missing`、`changed` 或 `invalid_manifest` 只表示源健康问题，不能作为
方法正文、执行路线或权限依据。热方法读取不会创建 Action/Finding，也不会替代当前
目标的 Scope/Auth、TargetStore 事实和证据门。

For this hunting entrypoint, also read `rules/hunting.md`. It is the canonical
hunting semantics and is loaded on demand rather than by every context pack.

For a genuinely new target, explicitly initialize it through
`python3 tools/target_store.py init --store --target TARGET` before owner writes;
`tools/hunt.py` also owns initialization when starting a selected recon/scanner pass.
Legacy, damaged or fenced state is a recovery condition, not permission to initialize
over it. Context Pack and ordinary queries never initialize a missing Store.

Run recon/scanning only when the current information gap calls for that breadth;
an existing request, source path or evidence-backed lead can go straight to the
selected bounded investigation. The scanner is not a prerequisite for `/hunt`:

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

For business-model maintenance, hypothesis selection, rotation and cross-stage
questions use `skills/src-hunting/SKILL.md` on demand, not for every action. These are shared methods, not
permission to keep running automatically after the requested hunt pass.

## Shared Investigation, Not Another Loop

`skills/src-hunting/SKILL.md` owns the question, competing explanations, smallest
discriminating experiment, evidence interpretation and rotation. This entry adds
no ordered LOAD/ROUTE/REVIEW/RECORD pipeline or per-action Skill result form.
Do not rescan, reread the catalog or run a full coverage review merely to move
between hypotheses. Current Scope/Auth, execution admission and owner receipts
remain mandatory when applicable.

A signal with replayable evidence becomes a candidate finding through
the Store claim API as soon as its evidence gate is met — without waiting for the
operator to ask or for a summary boundary. Prose or a raw probe alone is not a
finding; `/validate` can only run against a
finding that already exists in the target Store. `rules/coverage-gate.md` owns
Lead -> Signal -> Candidate -> Validated Finding evidence requirements;
`docs/evidence-runners.md` owns explicit Candidate/evidence registration. Persist
useful candidates before the pass ends, independently of execution mode.

Already-executed native/browser/multi-step evidence enters the same validation
path through `validation_runner.py record-evidence` after Candidate persistence
(contract: `docs/evidence-runners.md#native-evidence-registration`). Do not rerun
the experiment just to make it fit request-diff.

Do not become a passive scanner wrapper. Start with the most concrete evidence available.
`/hunt` does not generate report drafts by default; use `/report` or
`python3 tools/hunt.py --target target.com --report-only` after validation.

## Four-Layer Write-Back

Apply `skills/runtime-protocol.md#shared-memory-continuity` and its
`skills/runtime-protocol.md#cognitive-write-timing`, as in ordinary conversation
and autopilot. These are alternatives for a real event or handoff, not a four-command
tail after every action. Claude saves important progress without waiting for a
user reminder; bind each needed write to the current target:

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

Refresh `/surface` after new artifacts arrive, not twice against unchanged inputs.
For browser-state surfaces, read and apply
`docs/autopilot-lanes.md#browser-source-and-js`: choose one visible backend, preserve
and import artifacts, then close it under that shared contract. Reading a lane
contract does not enable automatic continuation.

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

Use `skills/src-hunting/SKILL.md#evidence-driven-rotation` to compare evidence
delta, remaining budget, prerequisites and kill/reopen conditions. Repeated status
or body shapes alone do not establish exhaustion or impose a fixed retry count.

At a path decision, save only the changed conclusion, blocker or reopening
condition through its existing owner, then follow the next evidence-backed question.
A rotation alone does not require `/checkpoint`, a new handoff or a full coverage
summary. At the end of the hunt pass, use the read-only Checkpoint above and apply
`rules/coverage-gate.md`; a bounded stop leaves residual work explicit and is not
an exhaustion claim.
