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
{"schema_version":1,"paths":[{"kind":"commands","relative_path":"autopilot.md"},{"kind":"commands","relative_path":"autopilot-round.md"},{"kind":"skills","relative_path":"runtime-protocol.md"}],"mcp_contracts":["mcp__Playwright__*","mcp__chrome-devtools__*","mcp__fofamap__*"]}
AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->
Authoritative bootstrap contract (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Formal arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep [--max-lanes N]] [--auth-file PATH] [--context-file=PATH]`; `--max-lanes` is valid only with `--deep` and bounds a deep invocation batch. `<target>` may be a domain/IP/CIDR, a readable text list, or a schema-v1 JSON Scope manifest. `--context-file` accepts only an owner-generated batch continuation under repository state.
## Runtime Preflight
Run the embedded bootstrap before reading lane contracts, Resin configuration, Recon
instructions, or target-specific documents. Do not parallel-read those documents first.
Obey bootstrap `action` before any other step. `ask_target` asks for the exact target;
`stop_invalid_arguments` reports `arguments.errors`; `stop_invalid_scope`/`stop_invalid_context` report bounded `error` and stop; `stop_state_error`/`stop_runtime_error` report bounded `error` and stop; `stop_runtime_drift` reports compact critical runtime paths/counts, points to `/sync-check`, requests explicit confirmation before any sync, and stops. Advisory runtime drift is reported but does not block. Never sync automatically. Only `continue` may act.
The bootstrap already ran arguments, read-only runtime compare, advisory capability profile, then compact target state. Arguments/runtime remain the only blocking gates. Treat
`capabilities` as advisory: `session_managed` names are not availability claims; use MCP only when visible in this Claude session and use a listed fallback otherwise. Missing/degraded
tools never block, trigger installation or request it, count as tested-clean, or hide material
limits in the handoff. Use the matching `capabilities.lanes` record only to explain local readiness or choose a viable fallback; it never overrides the owner-selected Action Queue/state lane. Within one invocation, do not rerun the same failed source/tool; preserve
cached/stale evidence as partial/blocked. `tools/external_arsenal.sh --versions` is diagnostics-only, never startup.
Browser/source lanes follow the selected contract in
`docs/autopilot-lanes.md#browser-source-and-js`; that section owns backend choice,
fallback, recovery, import, switching, and close rules. Choose one visible backend
or the target-owned fallback, and never probe both or switch mid-workflow.
Run project commands as `cd -- <repo_root_shell> && ...`. Use
`arguments.target_shell`, expand `arguments.hunt_auth_flags` (or
`--auth-file <arguments.auth_file_shell>`) only when present, and apply
`arguments.recon_flags` only to fresh/refresh recon. Obey parsed cadence,
`quick`, `deep`, and `invocation_batch` exactly. `--quick` lowers recon cost;
never skips browser/source/validation or implies completion. `arguments.seed_url` is an
exact first-contact browser/source/workflow seed for the canonical target.
After bootstrap, before the first network lane, inspect `config.json.resin`; when enabled,
inline the one stable sticky export from `docs/resin-proxy.md` in the same shell command as the lane.
When sticky access is blocked, use current evidence and the request budget to decide whether to reuse or switch
available sticky account environments and how much to retry; impose no fixed count. Use rotate only on explicit
request, bypass it for localhost/private targets, and never print the token or persist proxy setup.
Apply `rules/hunting.md` target-isolation/new-target defaults to the supplied target set.
`/pickup` never replays another target's skips or scanner decisions.
DNS expansion remains an advisory audit/replay lane; host count alone is not a trigger, and it requires target-specific evidence plus `--reason`.
`/autopilot` runs inline in the current AI session and remains the sole
writer/closure controller.
Specialists default to zero. If delegation is justified, load
`docs/autopilot-lanes.md#inline-specialist-propagation` for the single delegation
contract, including bounded questions, mode propagation, and batch limits. The
inline controller remains the only owner of lane claims, state write-back, and
closure; optional `recon-ranker` stays read-only and never becomes a lane owner.
Before a named lane, use the literal `state.lane_contract.ref` from
`docs/autopilot-lanes.md` and read only that section. Before substantive
Queue claim/resolve, read its `State And Queue` section and consume the bootstrap
`activation_contract` projection; do not reconstruct a second claim schema here.
Before active hunting begins, load `rules/hunting.md` for its canonical hunting
semantics. Fresh Recon is not active hunting: when `state.hard_gate.action=run_recon`
(and when `state.next_action=run_recon` for older readers),
execute the selected lane directly; refresh state after it completes. The
default context pack intentionally does not load this rule.
Tool discovery stays in `docs/tool-index.md`; evidence may select its helpers
without loading their full docs here. Host/JS volume alone is not a trigger, and
partial/unavailable output remains open.
Concrete JS bundle gaps may select `tools/deep_js_packer.py`; target-specific naming
evidence may select `tools/dns_expand.py`. Neither helper is a baseline lane.
## State Consumption Loop
```text
fresh: TARGET -> RECON -> BUSINESS/CROWN JEWELS -> SURFACE/CONTEXT -> BROWSER/SOURCE/JS TRUTH -> SCANNER QUICK -> WORKFLOW -> HYPOTHESIS -> MINIMAL PROOF -> CHAIN -> VALIDATE -> RECORD/CHECKPOINT
existing: LOAD -> REVIEW EVIDENCE -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT
```
Every invocation is state-first. Bootstrap `state` and advisory `capabilities` are
the only initial inputs. Branch only after that state read;
missing/stale/invalid is work, not no surface. State tools are not a pre-flight checklist.
Hypothesis generation is AI-owned: derive any family, primitive, or chain, including RCE and families
outside the canonical Coverage taxonomy, from evidence/unknowns/contradictions. `knowledge_cards` are
context, never conclusions; Case State/Queue `vuln_class` is a compatibility string. Only an owner-backed
Matrix terminal state or a complete evidence-backed identity candidate may close canonical Coverage;
unknown/incomplete work stays open.
For each iteration, keep the reasoning loop explicit:
`inspect candidate/context -> AI choose and activate one hypothesis -> claim -> execute one
bounded action -> read Runner observation -> AI resolve one continuation or kill -> refresh
bounded state`. Obey a non-empty `state.hard_gate` exactly. Otherwise choose one runnable item
from `state.priority_frontier`; array order is not priority. Compare practical business impact,
evidence strength, crown-jewel/chain fit, expected information gain, request cost, and starvation
of `closure_blocking` work. A weaker historical Queue/Case/Resume item must not automatically
preempt a stronger Surface/Finding/Intel candidate. Selection changes execution order only: it
never bypasses the selected item's evidence/owner contract, relabels deferred work as tested-clean,
or removes it from Closure. The controller must consume structured `next_action` and the durable Action Queue as
compatibility projections and owner contracts. With one frontier item, execute it directly; with none, use
`state.fallback_action` and bounded `next_step`. Never treat a single negative request as permission to move on:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded
```

Before selecting another substantive lane, run a compact phase gate in the same AI turn:
what exact target-owned evidence did this lane add, which high-value surface remains unknown
or was ruled out, and why the next action has better information gain than rotate or stop.
Put the answers in the existing `decision`/`next_action` heartbeat; do not create another
state, queue, or checklist owner. If the gate has no evidence-backed answer, resolve the lane
as a bounded dead-end/blocker or handoff instead of silently widening work.

When starting a target, entering a high-value feature, or rotating after a
stalled lane, recall `Developer-View Pre-Hunt Recall` in
`skills/bb-methodology/SKILL.md`. Keep it as a soft reasoning prompt: record
target-specific answers in existing state fields and do not turn it into a
second gate, fixed vulnerability order, or Queue action list.

When the selected action is `run_recon`, immediately run the selected Recon command from
the lane contract with `arguments.recon_flags`, then refresh bounded state.
Treat this as a mechanical dispatch: the next tool call starts Recon; lane preparation belongs in that call,
and the controller polls or refreshes only after dispatch.
For substantive candidates, apply the lane's evidence-backed activation contract
and claim the exact action before replay:
```bash
cd -- <repo_root_shell> && python3 tools/action_queue.py claim --target <target_shell> --id <id> --metadata-json '<activation-object>'
```
The Queue owns activation caps, identity/dedup, Runner fields, continuation
lineage, and prevents sensitive values from entering state or logs. On claim
failure inspect stderr/stored state once; never guess or retry the contract.
Runner observation leaves the action
`running`; the controller resolves that action with one primary continuation or
supported kill. Independent follow-ups require separately claimed actions within
the batch budget. Missing outcome/decision remains recoverable and blocks closure.
In deep mode, a concrete API/browser-XHR surface requires an evidence-linked
depth pack built from target-observed request shapes. A single passive observation
is not API completion. Negative results record the next evidence-linked
dimension/question in the existing Queue. Partial cursors
or unused dimensions are resumable work, not tested-clean.

Deep lanes keep the normal per-invocation caps unless `--deep` is active. In deep
mode, parameter discovery, candidate extraction, and zero-day fuzzing may project
a larger bounded budget from URL/parameter breadth, response variance, and
high-value evidence; every projection has a hard maximum and records
`partial_on_exhaustion=true`. A larger projection never bypasses Scope/Auth or
the selected runner/request cap, and exhaustion with an incomplete cursor remains
resumable.

Named action mechanics, replay commands, recon continuation, list selection, and owner
write-back rules live in the selected lane section. Claim durable queue work before replay;
never treat prose or a raw endpoint as evidence. If `state.root_claim_next` exists, run `/checkpoint`
so `finding_index` creates the canonical candidate and queue action before using
its ID. Refresh state after every owner write-back.
## Execution Invariants
Expert Hunter Autopilot is AI-first: the current AI session judges priority, impact,
chain fit, promotion, reopen, and finish; deterministic owners preserve schema,
evidence, replay, and durable state. Follow `skills/runtime-protocol.md`,
`rules/tool-ai-boundary.md`, and
`rules/hunting.md#broad-scanner-input-and-completion-contract`.
Use `rules/hunting.md` value-first priorities; scanner quick is an advisory breadth
sensor, and scanner-negative is not completion.
Business Model Read: after fresh Recon starts, write or refresh
`evidence/<target>/business_model.md` from observed application purpose, actors,
private objects, trust boundaries, sensitive workflows, and likely crown jewels;
a fresh file may be reused for 30 days.
Promote Lead -> Signal -> Candidate -> Validated Finding only with practical,
replayable raw request/response or a locatable evidence ref. Canonical finding
writes go through `finding_index` and `/validate`; partial/blocked is unresolved,
not tested-clean, and placeholder reports are not report-ready.
Apply the four-layer routing in `skills/runtime-protocol.md`; memory/cards are decision
inputs, never first-contact controllers or closure evidence.
## Transition And Finish Contract
Apply `arguments.checkpoint_trigger`: paranoid after each substantive state
change, normal after a coherent lane batch, yolo only on blocker/handoff/finish.
Every cadence writes evidence state. After a primary Candidate/Validated result,
try one bounded evidence-fit sibling or chain. On 401/403/404/405/415 or parser
delta, try one evidence-linked bypass family or close it. After three homogeneous
no-information results, resolve and rotate to one adjacent high-value lane.
Refresh rotating form/session tokens from the legitimate baseline before replay.
After every substantive lane, request the explicit read-only loop guard with `cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json`.
This projection also returns bounded `control` (`hard_gate`, `priority_frontier`,
`next_action`, and `fallback_action`); use it as the post-lane state refresh and do
not run a second ordinary state read unless a later owner write requires a fresh
snapshot. Obey `loop_guard.verdict`. On `rotate`, do not
continue the reported `endpoint_family` × `vuln_class` in this invocation; prefer its
bounded `rotation_target` when present, or choose another adjacent high-value lane.
`continue` preserves owner state. The guard never overrides `state.hard_gate`, an
already-claimed lane, or any selected item's evidence/owner constraints; otherwise
select from the returned `control.priority_frontier`.
`--deep` is a value-first comprehensive depth flag, not a checklist or favorite bug
class. With `invocation_batch.bounded`, execute at most `max_lanes` named
substantive lanes; after lane N do not execute a newly discovered queue item.
Evidence import, owner write-back, cleanup, checkpoint, and closure are not new
lanes and must still complete. Newly discovered work becomes next-invocation work.
Finish on evidence state, not a tool checklist. Resolve/block/dead-end/promote the
`working_hypothesis`; drain used `oast_listen` and record high-value scanner leads
and matrix gaps. Persist/import browser artifacts and close its native session;
failed close is `partial`/`blocked` and forbids a replacement in this invocation.
Immediately before any target-exhaustion claim, run the ordered coverage review and explicit read-only verdict below; an absent or empty matrix never proof of coverage. Consult available `evidence/<target>/intelligence.md`, browser, JS, source, and exposure evidence.
```bash
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py rebuild --target <target_shell>
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py find-gaps --target <target_shell> --limit 50
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```
The bounded `find-gaps --limit 50` output is an AI review window of semantic
gaps by default (`relevance_score > 0`). Use `--all` when raw endpoint x class
coverage is needed; this changes only the view, not matrix state. Its
`total` and `truncated` fields are advisory display metadata; the complete
matrix remains the closure owner input, and a truncated window never means
coverage is complete.
Read `closure.verdict`, `closure.can_claim_exhausted`, `closure.reasons`, and advisory `closure.rotation_hint`. Only `verdict=finish` with `can_claim_exhausted=true` permits a `finish/complete/exhausted` claim; `handoff` preserves durable work and `blocked` records the terminal prerequisite blocker.
Before accepting a target-wide `finish`, perform one cross-source review over the current
Surface, Coverage, Ledger, Finding, Browser/JS/Source/Intel evidence and residual unknowns.
Record it through the existing Checkpoint owner with `--record-global-review`; include the
returned `closure.snapshot_digest`, at least one current target-owned non-empty
`evidence_refs` entry, the review decision, and either `complete` or a `follow_up` mapped to
an existing active Queue action. A missing, stale, or invalid review yields
`global_review_required`, `global_review_stale`, or `global_review_invalid` and cannot be
replaced by prose or a new state file. A valid `follow_up` keeps the existing Queue route
active; it does not create a second controller or state machine.
The Checkpoint write shape is:
```bash
python3 tools/checkpoint.py --target <target_shell> --record-global-review \
  --review-status complete --snapshot-digest <closure.snapshot_digest> \
  --evidence-refs-json '["evidence/<target_key>/review/summary.json"]' \
  --cross-source-links-json '["browser -> JS -> Source"]' \
  --residual-unknowns-json '[]' --decision "<decision>" --json
```
Reaching `max_lanes` ends target work for this invocation, then Closure recomputes from current owners; the budget alone never requires another round. A pending report is a closure asset, not a stop signal. Active substantive Queue work, pending validation/report, partial browser/source/intel, or untouched high-value work means `handoff/partial`, never `finish/complete/exhausted`.
Missing owner/peer actor or session context is reported in `closure.actor_context_gap` as a non-blocking, lane-local coverage gap. It does not mean that the test lacks external permission, does not stop anonymous or unrelated lanes, and does not permit the affected access-control cells to be marked `tested_clean`.
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
