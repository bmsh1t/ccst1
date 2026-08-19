---
description: AI-first autonomous hunt loop for one target or a target list.
allowed-tools:
  - Bash
  - Agent
  - "mcp__Playwright__*"
  - "mcp__chrome-devtools__*"
  - "mcp__fofamap__*"
---
# /autopilot
<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST
{"schema_version":1,"paths":[{"kind":"commands","relative_path":"autopilot.md"},{"kind":"commands","relative_path":"autopilot-round.md"},{"kind":"agents","relative_path":"autopilot.md"},{"kind":"skills","relative_path":"runtime-protocol.md"}],"mcp_contracts":["mcp__Playwright__*","mcp__chrome-devtools__*","mcp__fofamap__*"]}
AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->
Authoritative bootstrap contract (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Formal arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep] [--max-lanes N] [--auth-file PATH] [--context-file=PATH]`, where `<target>` may be a domain/IP/CIDR, a readable text list, or a schema-v1 JSON Scope manifest. `--context-file` accepts only an owner-generated batch continuation under repository state.
## Runtime Preflight
Obey bootstrap `action` before any other step. `ask_target` asks for the exact target;
`stop_invalid_arguments` reports `arguments.errors`; `stop_invalid_scope`/`stop_invalid_context` report bounded `error` and stop; `stop_state_error`/`stop_runtime_error` report bounded `error` and stop; `stop_runtime_drift` reports compact critical runtime paths/counts, points to `/sync-check`, requests explicit confirmation before any sync, and stops. Advisory runtime drift is reported but does not block. Never sync automatically. Only `continue` may act.
The bootstrap already ran arguments, read-only runtime compare, advisory capability profile, then compact target state. Arguments/runtime remain the only blocking gates. Treat
`capabilities` as advisory: `session_managed` names are not availability claims; use MCP only when visible in this Claude session and use a listed fallback otherwise. Missing/degraded
tools never block, trigger installation or request it, count as tested-clean, or hide material
limits in the handoff. Use the matching `capabilities.lanes` record only to explain local readiness or choose a viable fallback; it never overrides the owner-selected Action Queue/state lane. Within one invocation, do not rerun the same failed source/tool; preserve
cached/stale evidence as partial/blocked. `tools/external_arsenal.sh --versions` is diagnostics-only, never startup.
For browser work, select one active backend for the invocation from evidence before the first MCP call: Chrome DevTools MCP for deep Network/Runtime/Console/performance, or Playwright MCP for interaction/auth/workflow capture. Keep the other backend available for a later invocation. Never probe both for availability, and never run both browser backends concurrently. Reuse a matching selected-backend session and close stale pages before opening a new context. Do not close or switch an authenticated/stateful workflow mid-lane; switch only after its evidence and recoverable state are persisted, and close the current native session first.
Run project commands as `cd -- <repo_root_shell> && ...`. Use
`arguments.target_shell`, expand `arguments.hunt_auth_flags` (or
`--auth-file <arguments.auth_file_shell>`) only when present, and apply
`arguments.recon_flags` only to fresh/refresh recon. Obey parsed cadence,
`quick`, `deep`, and `invocation_batch` exactly. `--quick` lowers recon cost;
never skips browser/source/validation or implies completion. `arguments.seed_url` is an
exact first-contact browser/source/workflow seed for the canonical target.
Before the first network lane for a public target, inspect `config.json.resin`; when enabled,
follow `docs/resin-proxy.md` to export one stable sticky environment via `CredentialStore`.
When the same baseline cannot access the target through sticky and the issue is exit-related rather than
path/auth/application behavior, select one new sticky account and replay it once; keep that account for subsequent
commands. Use rotate only on explicit request; bypass it for localhost/private targets, never print the token, and
never persist proxy setup or state.
Treat the supplied target set as the active execution target set; `ctf_mode` is the
authoritative lab target record. External policy is advisory audit/replay context;
do not require public-program, written-permission, or ownership-confirmation.
Target isolation follows a new target default: the built-in XSS lane skip is explicit,
and `/pickup` does **not** replay previous target skips or scanner decisions.
`/autopilot` runs inline in the current Claude session as the sole controller and does not create/resume legacy `agent_session.json`; specialists default to zero.
At most one bounded specialist may be invoked through Claude Code's `Agent` tool for one evidence question. The invoked specialist must not spawn nested agents, run full recon/scans, write final closure, or control finish. After using one, this invocation cannot call a second specialist.
Bootstrap emits one `state.lane_contract` pointer. Before executing a named lane, read only
`state.lane_contract.ref` (or the matching section for a newly observed signal) from
`docs/autopilot-lanes.md`; it is execution detail, not a second controller. Every lane still
inherits this command's Scope/Auth, evidence, checkpoint, Action Queue, loop-guard, and finish
contracts.
Before active hunting begins, load `rules/hunting.md` for its canonical hunting
semantics. Fresh Recon is not active hunting: when `state.next_action=run_recon`,
execute the selected lane directly; refresh state after it completes. The
default context pack intentionally does not load this rule.
Tool discovery stays in `docs/tool-index.md`; concrete evidence may select
`tools/dns_expand.py --reason`, `tools/deep_js_packer.py`,
`tools/disclosure_search.py`, or `tools/sibling_generator.py` without loading
their full documentation here; host count alone is not a trigger, JS volume
alone is not a trigger, and partial/unavailable tool output remains open.
## State Consumption Loop
```text
fresh: TARGET -> RECON -> BUSINESS/CROWN JEWELS -> SURFACE/CONTEXT -> BROWSER/SOURCE/JS TRUTH -> SCANNER QUICK -> WORKFLOW -> HYPOTHESIS -> MINIMAL PROOF -> CHAIN -> VALIDATE -> RECORD/CHECKPOINT
existing: LOAD -> REVIEW EVIDENCE -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT
```
Every invocation is state-first. Bootstrap `ctf_mode`, compact `state`, and advisory
`capabilities` are the only initial inputs. Branch only after that state read;
missing/stale/invalid is work, not no surface. State tools are not a pre-flight checklist.
For each iteration, keep the reasoning loop explicit:
`inspect candidate/context -> AI choose and activate one hypothesis -> claim -> execute one
bounded action -> read Runner observation -> AI resolve one continuation or kill -> refresh
bounded state`. The controller must consume structured `next_action` and the durable Action Queue; use bounded
`next_step`, and never treat a single negative request as permission to move on:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded
```
When `next_action=run_recon`, immediately run the selected Recon command from
the lane contract with `arguments.recon_flags`, then refresh bounded state. Do
not perform another context or documentation pass before that action.
For substantive candidates, claim the exact action with the evidence-backed activation contract
before replay (surface review, runtime wait, recovery, and reporting remain versionless):
```bash
cd -- <repo_root_shell> && python3 tools/action_queue.py claim --target <target_shell> --id <id> --metadata-json '<activation-object>'
```
The activation object records `depth_contract_version=1`, target-specific `hypothesis_id`, open
`family`/`technique`, selected Skill/knowledge references, one `active_dimension`,
`expected_learning`, `kill_condition`, `risk_tier`, and `max_hypothesis_actions` no greater than the
queued item's `metadata.max_hypothesis_actions_cap`. Read that stored cap from the selected Action
before claim. The stored cap is Queue-owned: never include `max_hypothesis_actions_cap` in claim
metadata or try to repair/increase it during claim. If it is missing, refresh and re-ingest the
checkpoint action; if it is invalid, stop and preserve it for Action Queue owner repair. If claim
exits non-zero, inspect its stderr and the stored Action once, then stop that claim path instead of
guessing fields or retrying the same contract. The
Queue computes execution identity and rejects same endpoint/method/family/technique/
actor/object/workflow/dimension work without new evidence or a recorded repeat reason. After the
deterministic Runner writes `last_outcome`, `tested_dimensions`, replayable evidence refs,
operation ID, and a bounded observation, it keeps the versioned action `running`. An explicit
`observation_kind=baseline_only` records the safe baseline for the next AI decision but cannot
support a kill.
The AI then resolves it with exactly one evidence-backed continuation (`sibling`, `bypass`,
`identity`, `object`, `parser`, `transport`, `workflow`, `chain`, `rotation`, or `blocked`) or a
supported `kill_condition_met=true`; missing outcome write-back, tested dimensions, or the next
decision leaves the action recoverable and blocks exhaustion. Materialize at most one continuation
child while preserving the versioned hypothesis, activation, parent, and evidence lineage.
In deep mode, a concrete API/browser-XHR surface requires an evidence-linked
depth pack: run the observed GET/query path and the observed POST JSON/form path
when applicable. GET-only is not API completion; OPTIONS/HEAD remain passive
checks, and default probing never adds PUT/PATCH/DELETE. After a negative result,
record the selected sibling/variant/actor/workflow/chain dimension plus
`hypothesis`, `tested_dimensions`, `expected_learning`, `kill_condition`, and `next_question` in the
existing Action Queue metadata. For legacy/versionless manual actions only, use
`tools/action_queue.py add --metadata-json '{"hypothesis_id":"H-1","tested_dimensions":["sibling"],"expected_learning":"...","kill_condition":"...","next_question":"..."}'`;
the parser accepts only a JSON object and rejects credential-bearing fields before any queue write.
For `depth_contract_version=1`, Runner owns `last_outcome`, `tested_dimensions`, and
`runner_operation_id`; AI claim/resolve metadata must not fabricate them. This is the existing Action
Queue, not a new state owner. A partial tool cursor or unused depth dimension
is resumable work, not tested-clean.

Deep lanes keep the normal per-invocation caps unless `--deep` is active. In deep
mode, parameter discovery, JSON injection, and zero-day fuzzing may project a
larger bounded budget from URL/parameter breadth, response variance, and
high-value evidence; every projection has a hard maximum and records
`partial_on_exhaustion=true`. A larger projection never bypasses Scope/Auth or
the WAF plan cap, and exhaustion with an incomplete cursor remains resumable.

Every checkpoint-generated substantive Action Queue item carries the selected
`skill_route` and its `required_dimensions`; the queue validates that route
before persistence. AI may override the selected Skill, but must record the
replacement route and reason in the same metadata. Hand-written advisory queue
items remain compatible when `route_required` is not set.

When resolving a legacy/versionless action, preserve its structured metadata through
`tools/action_queue.py resolve --metadata-json`; `last_outcome`, `tested_dimensions`,
`next_question`, `expected_learning`, `kill_condition`, and `pivot_hints` keep their compatible
merge behavior. A versioned AI resolve supplies only one continuation or supported kill plus optional
bounded capability primitives; it consumes Runner-owned observation fields already on the action.
The JSON must be an object and must not contain credentials or authorization headers.
If Checkpoint projects `capability-chain-review`, treat it as advisory: do not execute the primitive
directly. If one bounded chain is executable, add one normal versioned chain action with the persisted
parent/hypothesis/evidence lineage before resolving the review; otherwise resolve it as blocked/dead-end.
The review never changes existing running, validation, candidate, report, or Closure priority.

Named action mechanics, replay commands, recon continuation, list selection, and owner
write-back rules live in the selected lane section. Claim durable queue work before replay;
never treat prose or a raw endpoint as evidence. If `state.root_claim_next` exists, run `/checkpoint`
so `finding_index` creates the canonical candidate and queue action before using
its ID. Refresh state after every owner write-back.
## Execution Invariants
Expert Hunter Autopilot is AI-first: Claude judges priority, impact, chain fit,
promotion, reopen, and finish; deterministic owners preserve schema, evidence,
replay, and durable state. Follow `skills/runtime-protocol.md`,
`rules/tool-ai-boundary.md`, `rules/red-lines.md`, and
`rules/hunting.md#broad-scanner-input-and-completion-contract`.
Super-pentester priority is business impact > workflow evidence > crown-jewel
hypothesis > scanner/coverage hints. Scanner quick is an advisory breadth sensor,
and scanner-negative is not completion.
Business Model Read: after fresh Recon starts, write or refresh
`evidence/<target>/business_model.md` from observed application purpose, actors,
private objects, trust boundaries, sensitive workflows, and likely crown jewels.
A fresh file may be reused for 30 days.
Promote Lead -> Signal -> Candidate -> Validated Finding only with practical,
replayable raw request/response or a locatable evidence ref. Canonical finding
writes go through `finding_index` and `/validate`, never direct `findings.json`
edits. Partial/blocked is unresolved, not tested-clean; placeholder reports are
not report-ready.
Four-layer memory is the external brain, not the steering wheel:
`target memory / case state -> Skill -> 1-2 matching cards/references -> checks`.
These are decision inputs, not first-contact controllers or closure evidence.
## Transition And Finish Contract
Apply `arguments.checkpoint_trigger`: paranoid after each substantive state
change, normal after a coherent lane batch, yolo only on blocker/handoff/finish.
Every cadence writes evidence state. After a primary Candidate/Validated result,
try one bounded evidence-fit sibling or chain. On 401/403/404/405/415 or parser
delta, try one evidence-linked bypass family or close it. After three homogeneous
no-information results, resolve and rotate to one adjacent high-value lane.
Refresh rotating form/session tokens from the legitimate baseline before replay.
After every substantive lane, request the explicit read-only loop guard with `cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json`.
Obey `loop_guard.verdict`. On `rotate`, do not continue the reported `endpoint_family` × `vuln_class` in this invocation; prefer its bounded `rotation_target` when present, or choose another adjacent high-value lane.
`continue` preserves `loop_guard.next_action`. The guard never overrides runtime waits, candidate validation, report work, or durable Action Queue work; their authoritative next action remains in force.
`--deep` is a value-first comprehensive depth flag, not a checklist or favorite bug
class. With `invocation_batch.bounded`, execute at most `max_lanes` named
substantive lanes; after lane N do not execute a newly discovered queue item.
Checkpoint/sync the durable queue, state the handoff, and end. Browser/source
discoveries become next-invocation work, not lane N+1.
Finish on evidence state, not a tool checklist. `working_hypothesis` must be resolved, blocked, dead-end, Candidate, or Validated Finding. Check `oast_listen` when used; resolve or record high-value action-gated scanner leads and every matrix gap. If Playwright/Chrome MCP was used, persist/import the required artifacts and close the native browser session before handoff or finish; a failed/unavailable close is `partial`/`blocked`, never a reason to open another session.
Immediately before any target-exhaustion claim, run the ordered coverage review and explicit read-only verdict below; an absent or empty matrix never proof of coverage. Consult available `evidence/<target>/intelligence.md`, browser, JS, source, and exposure evidence.
```bash
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py rebuild --target <target_shell>
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py find-gaps --target <target_shell>
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```
Read `closure.verdict`, `closure.can_claim_exhausted`, `closure.reasons`, and advisory `closure.rotation_hint`. Only `verdict=finish` with `can_claim_exhausted=true` permits a `finish/complete/exhausted` claim; `handoff` preserves durable work and `blocked` records the terminal prerequisite blocker.
When `max_lanes` was reached, pass `--max-lanes-reached`; it always requires handoff. A pending report is a closure asset, not a stop signal. Active durable work, pending validation/report, partial browser/source/intel, or untouched high-value work means `handoff/partial`, never `finish/complete/exhausted`.
Checkpoint unresolved work in the existing Action Queue instead of passive TODOs.
Passing `check_autopilot_run.py` proves state-chain integrity, not target exhaustion.
In the final handoff/finish response, use the classification criteria (not the
write commands) in `knowledge/promotion-rules.md` and `rules/retrospective.md`
to emit exactly one presentation-only section per bounded invocation:

```text
Memory recommendations
- promote: transferable lesson, or none + reason
- target-only: current-target fact or handoff, or none
- reject: noisy, unverified, sensitive, duplicated, or overfit material, or none
```

Promotion requires a locatable target-owned evidence ref, destination layer, reusable value,
one next action, and one stop/validation condition. Recommendations never write state or alter
routing, budgets, Queue/finding lifecycle, closure, or next action. End with target, mode,
strongest evidence, findings/candidates, blockers/dead ends, this section, and the next best action.
