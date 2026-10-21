---
description: "Start active hunting on a target using cached recon, AI-first surface review, optional enrichment, hunt memory, and focused vulnerability testing. Usage: /hunt target.com"
---

# /hunt

Active vulnerability hunting through Claude CLI. Use the scanner as a bounded breadth and candidate sensor when useful; use surface evidence for Claude to choose exact probes and validation.

## 谁思考（认知归属）

参数认知归属见 `rules/ccst/tool-ai-boundary.md` 的“谁思考”一节。本命令的关键分工：

| 输入 | 谁思考 |
|---|---|
| 假设选择、路线、验证深度 | **AI 判断** |
| 实验的 endpoint/method/actor/variant | **执行事实**（原生材料经登记入口保存为 Store observation） |
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

6k 方法直接读取 `skills/src-hunter/知识库/`；按信息缺口展开完整正文，复用仍有效的已读内容。
Context Pack 只补当前目标事实与证据，不要求方法 catalog/read 中间层。
共同读取和维护边界见 `skills/runtime-protocol.md#shared-knowledge-recall`。

For this entrypoint read `rules/ccst/hunting.md` and follow `rules/README.md` to capture
the complete 6k dig-scope/src-value rules and site-opening shortlist. The originals
own hunting cadence/probes; hunting.md binds engineering constraints, not another workflow.

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
python3 tools/hunt.py --target target.com                  # explicitly select Recon + scanner pipeline
python3 tools/hunt.py --target target.com --quick          # lower-cost path
python3 tools/hunt.py --target target.com --scan-only --scanner-full  # larger bounded upstream origin batch
```

The default Hunt CLI runs Recon and scanner; `--recon-only` skips the scanner,
not individual Recon stages. These are explicit pipeline choices, not the default
route for an evidence-led conversation or a missing-inventory state.

Auth-aware examples:

```bash
python3 tools/hunt.py --target target.com --scan-only --auth-file .private/auth.json
BBHUNT_COOKIE='session=REDACTED' python3 tools/hunt.py --target target.com --scan-only --auth-from-env
```

Environment auth also supports `BBHUNT_AUTH_HEADER`; auth is propagated into
the Python helpers and shell recon / scanner toolchain where supported.

For scanner execution, inspect status, raw JSONL, logs, exit code and input remainder in
`findings/<target-key>/nuclei_runs/<run-id>/summary.json`. The latest summary also
represents running, skipped, unavailable or incomplete states; its presence is not
completion. Successful execution of selected templates is not audited coverage.
Native review registers an actual supported candidate through existing owners;
raw output does not create or assess a Finding automatically.

For business-model maintenance, hypothesis selection, rotation and cross-stage
questions use `skills/src-hunter/SKILL.md` on demand, not for every action. These are shared methods, not
permission to keep running automatically after the requested hunt pass.

## Shared Investigation, Not Another Loop

`skills/src-hunter/SKILL.md` owns the question, competing explanations, smallest
discriminating experiment, evidence interpretation and rotation. This entry adds
no ordered LOAD/ROUTE/REVIEW/RECORD pipeline or per-action Skill result form.
Do not rescan, reread the catalog or run a full coverage review merely to move
between hypotheses. Current Scope/Auth, execution admission and owner receipts
remain mandatory when applicable.

A signal with replayable evidence becomes a candidate finding through
the Store claim API as soon as its evidence gate is met — without waiting for the
operator to ask or for a summary boundary. Prose or a raw probe alone is not a
finding; `/validate` can only run against a
finding that already exists in the target Store. `rules/ccst/coverage-gate.md` owns
Lead -> Signal -> Candidate -> Validated Finding evidence requirements;
`docs/evidence-runners.md` owns explicit Candidate/evidence registration. Persist
useful candidates before the pass ends, independently of execution mode.

Already-executed native/browser/multi-step evidence enters the same validation
path through `validation_runner.py record-evidence` after Candidate persistence
(contract: `docs/evidence-runners.md#native-evidence-registration`). Do not rerun
the experiment merely to obtain a validation summary.

Without a Finding, retain the same real execution through the separate
`validation_runner.py record-observation` entry
(`docs/evidence-runners.md#native-observation-registration`). It registers ordered
observations with no verdict, not a placeholder Candidate. Use its actual operation/
step references for conditional experience and handoff; retry registration without
replaying actions, and supplement the same attempt with the original predecessor.

Do not become a passive scanner wrapper. Start with the most concrete evidence available.
Save confirmed A immediately. Once its evidence and destination gates pass, draft
under complete 6k report-format and publish through `/report`; optional B/C never
delay it. The report-only Hunt CLI indexes existing reports rather than authoring prose.

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
- **403 / auth boundary**: when a target-owned 401/403 has path, proxy, framework, or sibling evidence, let Claude select the exact path/header/method representation and execute it through browser, curl, or a raw sender. Retain each raw request/response and register native evidence through the existing Store boundary. A status change alone is not proof.
- **GraphQL**: inspect schema/operation names and compare object/field authorization. Assess mutations by the actual side effects under `rules/ccst/red-lines.md` and current operator intent; test-owned reversible flows are not excluded merely because they use mutations.
- **SSRF / webhook / async**: use `tools/oast_listen.py` only when a URL-fetch or webhook sink exists.
- **Upload/import/export**: confirm parser/authorization paths with minimal samples; record state-changing leads separately.
- **JWT/OIDC/SAML/OAuth**: decode and inspect issuer/JWKS/callback/state/session binding signals before probing.
- **SQL/NoSQL JSON body**: use the target-observed body or parameter shape and the complete src-value parameter/probe requirements; select stack-appropriate probes, encoding and request positions. Choose browser, native HTTP or a raw sender for the observed experiment; time-shaped candidates use AI interleaved sampling with a stable trend. Keep baseline/variant evidence; transport/WAF noise is not a finding. Probe requirements do not imply an automatic fixed tool pipeline.
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

Use `skills/src-hunter/SKILL.md#evidence-driven-rotation` to compare evidence
delta, remaining budget, prerequisites and kill/reopen conditions. Repeated status
or body shapes alone do not establish exhaustion or impose a fixed retry count.

At a path decision, save only the changed conclusion, blocker or reopening
condition through its existing owner, then follow the next evidence-backed question.
A rotation alone does not require `/checkpoint`, a new handoff or a full coverage
summary. At the end of the hunt pass, use the read-only Checkpoint above and apply
`rules/ccst/coverage-gate.md`; a bounded stop leaves residual work explicit and is not
an exhaustion claim.
