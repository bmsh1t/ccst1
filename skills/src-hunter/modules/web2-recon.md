# Web2 Recon Decision Module

内部完整方法，按当前问题读取；不是独立原生 Skill，不自动启动执行或委派。
返回 [src-hunter 调查主干](../SKILL.md)；恢复/写回仍归 `skills/runtime-protocol.md`。

适用：Use when a target needs attack-surface discovery, surface review, or a bounded recon follow-up — it decides the next evidence-producing recon action from current target state (which lane, what artifact, what it answers). A decision layer, not a scanner recipe; the /recon command owns command execution and artifacts, and deterministic tools own collection, scope filtering, and resumable cursors.

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

Recon may create target-owned surface facts, Leads, Signals, and next-action
proposals. It does not own Findings, Coverage, Queue lifecycle, or Target Memory
schema. Surface facts are submitted through the existing Surface owner; Recon
must never write or mutate the rebuildable Surface projection directly. A
response status or technology name is a signal, never a vulnerability
conclusion.

## Evidence-Driven Decision Tree

Select the branch with the clearest expected learning, highest plausible value,
and lowest reversible cost. Branches are alternatives, not a mandatory order.

| Observed state | Preferred decision | Handoff |
|---|---|---|
| No active target or scope context | Establish the target record and stop before network work | `commands/target.md` / runtime protocol |
| No inventory or a materially stale inventory | Compare available request/source/browser evidence and the current information gap; choose bounded collection only if useful | Native evidence or explicitly selected `/recon TARGET [--quick|--deep]` |
| Inventory exists but the valuable surface is unclear | Refresh the bounded Surface view and ask one feature-level question | `/surface`, `tools/surface.py` |
| Browser, JS, source, schema, or history names a missing host/path/parameter | Choose one evidence-linked expansion, not a generic dictionary | `tools/dns_expand.py --reason <evidence>`, focused FFUF, native Read/Grep |
| Authenticated API exposes object or role state | Compare the same object/action across owned actors before broad probes | `knowledge/playbooks/web2-evidence-contracts.md`, actor-pair evidence |
| Upload, URL fetch, GraphQL, realtime, import/export, or payment evidence appears | Preserve the request shape and route to the matching card/validation lane | `/surface`, selected Knowledge card, `/validate` |
| Exposure, component, source, or CI/CD artifact appears | Record provenance and test applicability before any active follow-up; a concrete framework/version fingerprint may justify current `/intel` research, chosen by Claude | `/intel`, source or CI/CD tool |
| Bot-manager or anti-bot challenge blocks content (challenge page instead of real content, or transport-dependent resets) | Do not deepen URL collection against a challenge wall; compare the same path across available transports and choose one that returns real content before any further recon phase | browser lane |
| A third-party-hosted host or service carries multiple page, behavioral, or brand evidence points tying it to the target organization | Record the ownership observation at `confidence: high` with multiple `sources`, so it routes to `scope-review` with a forced in-scope/external/excluded decision; ownership evidence never expands authorization, and only an explicit target set makes it testable | `tools/recon_candidates.py`, `/surface`, `/scope` |
| Recon is low-signal but still underexplored | Run one bounded discovery action with a reopen condition; keep unknowns open | `/recon`, browser/source evidence, or a targeted tool |

### Target-specific Branching

Classify the supplied input as domain, IP/CIDR, host:port, URL seed, or a
primary-domain list. Use `tools.target_paths` semantics through existing
commands; never invent a storage key or merge list targets by filename. For
localhost, lab, private-scope, and supplied target-set runs, keep the supplied
target record and the same artifact contract; bounty ROI only affects attention,
not scope or completion.

### Login / Missing JavaScript

A login page is not the end of the target. Look for the actual business API,
same-host gateway, permitted redirect destination or already available source
and request evidence. If JavaScript is absent or unavailable, choose another
evidence plane rather than waiting or repeating same-skin login probes. A real
login form may warrant [credential review](credential-attack.md), not automatic
live guessing. Once a test session is available, compare objects, actors and
workflow state. Preserve unknowns and Scope boundaries when a prerequisite is missing.

### Origin/Host Clues

Origin IP/range, ASN, SAN/CNAME, or edge/direct response differences are
Host/SNI comparison candidates.

## Local Question Selection

Within the question supplied by the main session, choose the collection method
that best distinguishes the competing explanations with reversible cost. Return
new business/actor/workflow evidence, unexpected high-value signals and proposed
pivots to `skills/src-hunter/SKILL.md`; Recon does not rank the whole target or
own global stopping. Technology narrows a local hypothesis, not a finding.

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

Use native Read/Grep and the existing `/recon`, `/surface`, `tools/recon_engine.sh`, and
`tools/recon_adapter.py` entrypoints. Do not copy their flags or parser rules
into this module. Detailed FFUF operation and artifact handling live in the
focused discovery section of `commands/recon.md`.

## Profile and Artifact Compatibility

- Explicit `/recon` selects the existing full profile; `--quick` lowers cost and
  `--deep` enables the deeper JS path. Fresh `/autopilot` does not select Recon
  merely because inventory is absent. Pending collection is optional, not a
  reason to rerun the whole pipeline; invalid cursors require owner repair.
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
Lead/next action to the vulnerability method. It does not treat an error as a
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

## Local Stop and Handoff

Stop collection when the delegated question is answered, its evidence-bound kill
condition is met, prerequisites fail or the execution owner budget ends. Return
what changed, contrary evidence, raw references, missing conditions and a useful
next discriminating check using the real-handoff contract in
`skills/src-hunter/SKILL.md#real-delegation-and-execution-handoff`.
Pure same-session reading does not need a filled result form.

Low-signal and untested material remain unknown/blocked with reasons. Proposed
new target priorities and global continue/rotate decisions return to the main
session; Recon does not declare a target clean after bounded collection. Save
accepted leads/dead ends through the existing target-memory owner; Coverage,
Action closure and validation retain their existing owners.

## Local / Lab / Supplied Target Shortcut

For a local, lab, or supplied target set, use the same target record, scope
checks, raw artifact paths, and evidence gates. The shortcut changes tool
availability or cost choices only; it does not bypass provenance, ownership,
replay, or write-back requirements.

## References

- `/recon`: production execution and operator-facing artifact contract.
- `/surface`: rebuildable attack-surface projection.
- Claude native Read/Grep: evidence-selected JS/source analysis.
- `tools/recon_engine.sh`, `tools/recon_adapter.py`, `tools/dns_expand.py`:
  deterministic execution and summaries.
- `knowledge/cards/coverage-prompts.md`: evidence-driven coverage questions.
