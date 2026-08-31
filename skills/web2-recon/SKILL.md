---
name: web2-recon
description: Evidence-driven Web2 attack-surface decisions. Use when a target needs discovery, surface review, or a bounded recon follow-up; use /recon for execution and existing tools for deterministic artifacts.
---

# Web2 Recon Decision Skill

Choose the next evidence-producing recon action from the current target state.
This is a decision layer, not a fixed scanner recipe. `/recon` remains the
operator entrypoint and owns the command/artifact contract; deterministic tools
own collection, scope filtering, raw evidence, and resumable cursors.

## Boundary and Inputs

Read the current target record and bounded Context Pack before choosing a lane:

- `memory/goals/active.json` or `python3 tools/target_memory.py show`;
- the current `recon/<target_key>/recon_manifest.jsonl`, Surface projection, and
  Action Queue/Checkpoint hints when present;
- supplied scope, authentication/client context, browser/source evidence, and
  prior leads, dead ends, blocked prerequisites, and reopen conditions.

Recon may create target-owned surface facts, Leads, Signals, and next actions.
It does not own Findings, Coverage, Queue lifecycle, or Target Memory schema;
不拥有 finding、Surface、queue、coverage 或 target-memory 状态; write those
through their existing owners. A response status or technology name
is a signal, never a vulnerability conclusion.

## Evidence-Driven Decision Tree

Select the branch with the clearest expected learning, highest plausible value,
and lowest reversible cost. Branches are alternatives, not a mandatory order.

| Observed state | Preferred decision | Handoff |
|---|---|---|
| No active target or scope context | Establish the target record and stop before network work | `commands/target.md` / runtime protocol |
| No inventory or a materially stale inventory | Run the appropriate `/recon` profile and preserve raw output | `/recon TARGET [--quick|--deep]` |
| Inventory exists but the valuable surface is unclear | Refresh the bounded Surface view and ask one feature-level question | `/surface`, `tools/surface.py` |
| Browser, JS, source, schema, or history names a missing host/path/parameter | Choose one evidence-linked expansion, not a generic dictionary | `tools/dns_expand.py --reason <evidence>`, focused FFUF, `/js-read` |
| Authenticated API exposes object or role state | Compare the same object/action across owned actors before broad probes | `web2-vuln-classes`, actor-pair evidence |
| Upload, URL fetch, GraphQL, realtime, import/export, or payment evidence appears | Preserve the request shape and route to the matching card/validation lane | `/surface`, selected Knowledge card, `/validate` |
| Exposure, component, source, or CI/CD artifact appears | Record provenance and test applicability before any active follow-up | `/intel`, source or CI/CD tool |
| Recon is low-signal but still underexplored | Run one bounded discovery action with a reopen condition; keep unknowns open | `/recon`, browser/source evidence, or a targeted tool |

### Target-specific Branching

Classify the supplied input as domain, IP/CIDR, host:port, URL seed, or a
primary-domain list. Use `tools.target_paths` semantics through existing
commands; never invent a storage key or merge list targets by filename. For
localhost, lab, private-scope, and supplied target-set runs, keep the supplied
target record and the same artifact contract; bounty ROI only affects attention,
not scope or completion.

## ROI and Feature Choice

Rank candidate surfaces by observed business value and information gain, not by
stack name or a favorite bug class. Prefer a concrete feature boundary such as:

1. authentication, session, tenant, and actor/object transitions;
2. payments, billing, credits, refunds, orders, and other integrity state;
3. data export, search, upload/import, URL fetch, webhooks, and background jobs;
4. admin, configuration, debug, source, and management surfaces;
5. ordinary pages and long-tail paths after the higher-value questions have a
   bounded next action.

The order is advisory. A fresh high-value Candidate, new identity, or new
behavioral signal can preempt it. Technology detection narrows a hypothesis but
does not select a finding or load a complete framework playbook.

## Action and Evidence Contract

Before claiming a bounded action, record the smallest useful tuple in the
existing action/evidence owner:

```text
goal/hypothesis -> input and source_refs -> route -> expected_learning
                -> owner budget/risk -> stop condition -> reopen condition
```

The action must identify its target and auth context, preserve the normal
baseline, and change one meaningful boundary at a time. Keep raw requests,
responses, hashes, timestamps, tool/version metadata, and artifact paths in the
target-owned run. Summaries and model explanations are projections; they cannot
replace raw evidence or promote a Lead.

Use the existing `/recon`, `/surface`, `/js-read`, `tools/recon_engine.sh`, and
`tools/recon_adapter.py` entrypoints. Do not copy their flags or parser rules
into this Skill. Detailed FFUF operation and artifact handling live in the
focused discovery section of `commands/recon.md`.

## Profile and Artifact Compatibility

- `/recon` and fresh `/autopilot` use normal Recon by default; `--quick` lowers
  cost and `--deep` enables the deeper JS path.
- Raw hosts, URLs, JS, parameters, and exposure observations remain lossless.
  Filtered/ordered views are projections and never shrink the authoritative raw
  corpus.
- `recon_engine.sh TARGET` keeps its direct full behavior. Deep JS, source-map,
  dynamic-chunk, and runtime work becomes a separate evidence-selected lane.
- Bounded scanner or FFUF output is a breadth signal. It does not claim
  exhaustive coverage, tested-clean status, or report readiness.
- Existing artifacts remain target-owned, including `recon_manifest.jsonl`,
  `live/urls.txt`, `urls/raw/`, `urls/with_params.txt`, `js/`, `dirs/`, and
  `exposure/`. Use current artifact bindings when resuming; do not overwrite a
  prior run merely to make a summary look complete.

## Focused Discovery Boundary

The automatic **baseline FFUF** lane is a bounded breadth sensor. **Focused
fuzz** is an **AI 显式选择** discovery action only when same-target evidence
supports a concrete template, naming dialect, parameter, or request shape. A
baseline with zero hits does not justify focused fuzz; specifically, never use a
`baseline 零命中而自动转入 focused fuzz` rule.

For a focused run, the model supplies the rationale and expected learning while
the existing command/tool owns rate, scope, controls, raw output, and summary.
The candidate list must be target-derived, bounded, deduplicated, and tied to
`seed_refs`, `transformation`, and `evidence_grade`; **不得机械合并整份通用大字典**.
不以模型自报数字置信度代替证据。
Keep each run isolated under
`recon/<target_key>/focused_fuzz/`; `wordlist.txt`,
`dirs/ffuf_results.jsonl.gz`, and `dirs/ffuf_summary.json` are run artifacts,
not Finding, Surface, Queue, Coverage, or Target Memory owners.

Interpret route differences (including 200, 401, 403, 405/`Allow`, redirects,
SPA/soft-404, 登录跳转, WAF pages, and framework errors) as Signals until a
same-method, same-auth baseline, random miss/control, and a bounded replay answer
the question. `auth_context` records only an anonymous/session label or evidence
reference. 路由差异只形成 Signal; do not turn a route signal into a Candidate or
change request methods automatically.

### Missing Parameter Signal / Target-Specific Params

When a page, API, history, source, schema, browser request, or sibling endpoint
shows a missing/null/type/schema validation signal, load
`knowledge/cards/missing-parameter-discovery.md`.

Recon records the baseline and a target-derived vocabulary, then hands a small
Lead/next action to the vulnerability Skill. It does not treat an error as a
finding, bulk-enumerate real users, export sensitive data, or turn the vocabulary
into a fixed dictionary.

### Pattern-Based Directory Fuzzing

When paths, filenames, API prefixes, parameters, hosts, static assets, or short
codes reveal a naming pattern, load
`knowledge/cards/path-pattern-management-exposure.md`. Produce a bounded,
read-only sibling hypothesis from real target tokens. Record source references,
authentication context, controls, and a stop condition; do not spray generic
management paths or import suspected keys into cloud panels.

## Boundary-First Pattern Router

Use the evidence shape to choose a boundary, then stop when its question is
answered:

```text
boundary -> baseline -> hidden surface -> bug family
         -> primitive -> connector -> impact
```

Examples of route signals are intentionally compact:

- browser/API/role/object differences -> actor-pair replay and access-control
  evidence;
- parser, proxy, encoding, cache, or normalization differences -> the matching
  boundary card and a controlled baseline comparison;
- Source/config/secret/file read signal -> source or exposure review with
  provenance, not an automatic finding;
- realtime, GraphQL, gRPC, or LLM/RAG evidence -> the matching on-demand card
  and existing replay/tool path; no protocol-specific runner is implied;
- payload, bypass, sink, or grep detail -> load the selected deep reference
  only when the current evidence calls for it; avoid broad payload spraying.

## Stop, Reopen, and Handoff

After every bounded action, compare the current progress fingerprint:

```text
hypothesis + surface + actor/state + observation kind + evidence reference
```

- **continue** when evidence changes, uncertainty falls, or a bounded connector
  becomes testable;
- **rotate** after homogeneous no-information results, a repeated fingerprint,
  an owner budget or prerequisite boundary, or a higher-value route;
- **stop** when the lane kill condition is met, preserving the evidence and a
  concrete reopen condition;
- **handoff** when another Skill, card, tool, or validation owner must answer the
  next question.

Elapsed time alone never closes Recon, claims coverage, or justifies rotation.
Per-action tool budgets remain valid only when the owning tool enforces them.
不设置全局轮数上限; after each result choose again from current
evidence. Low-signal or skipped phases stay visible as `unknown`, `blocked`,
`lead`, or `dead-end` with their reason and reopen condition.

Write leads and dead ends through the existing target-memory owner, for example
`tools/target_memory.py lead` and `tools/target_memory.py dead-end`, and let
`rules/coverage-gate.md`, Evidence Ledger, Checkpoint, and reporting rules own
completion and validation. Recon never declares a target clean merely because a
bounded lane ended normally.

## Local / Lab / Supplied Target Shortcut

For a local, lab, or supplied target set, use the same target record, scope
checks, raw artifact paths, and evidence gates. The shortcut changes tool
availability or cost choices only; it does not bypass provenance, ownership,
replay, or write-back requirements.

## References

- `/recon`: production execution and operator-facing artifact contract.
- `/surface`: rebuildable attack-surface projection.
- `/js-read`: evidence-selected JS/source analysis.
- `tools/recon_engine.sh`, `tools/recon_adapter.py`, `tools/dns_expand.py`:
  deterministic execution and summaries.
- `knowledge/cards/coverage-prompts.md`: evidence-driven coverage questions.
