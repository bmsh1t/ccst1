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
Run embedded bootstrap before lane contracts/Resin/Recon/target docs; do not parallel-read.
Obey its `action` first: `ask_target` asks for the exact target,
`stop_invalid_arguments` reports `arguments.errors`; `stop_invalid_scope`/`stop_invalid_context`
and `stop_state_error`/`stop_runtime_error` return bounded `error`; critical `stop_runtime_drift`
reports compact critical runtime
paths/counts, points to `/sync-check`, requests explicit confirmation before any sync, and
stops. Advisory drift does not block. Never sync
automatically. Only `continue` may act.
Bootstrap order is arguments, read-only runtime compare, advisory capability profile, then
compact target state. Arguments/runtime remain the only blocking gates. Treat `capabilities`
as advisory: `session_managed` names are not availability claims; use MCP only when visible
in this Claude session or a listed fallback. Missing/degraded tools never block, trigger
installation, count as tested-clean, or hide limits in the handoff.
Matching `capabilities.lanes` only explains readiness/fallback; it never overrides
owner-selected Action Queue/state lane. Within one invocation, do not rerun the same failed
source/tool; preserve cached/stale evidence as partial/blocked. `tools/external_arsenal.sh
--versions` is diagnostics-only, never startup.
Browser/source uses `docs/autopilot-lanes.md#browser-source-and-js`; obey its
backend/fallback/recovery/import/switch/close contract. Choose one visible backend or
target-owned fallback; never probe both or switch mid-workflow.
Run project commands as `cd -- <repo_root_shell> && ...`; use `arguments.target_shell`,
`arguments.hunt_auth_flags`/`--auth-file <arguments.auth_file_shell>` when present, and
`arguments.recon_flags` only for fresh/refresh recon. Obey cadence, `quick`, `deep`, and
`invocation_batch`; `--quick` lowers recon cost but never skips browser/source/validation or
implies completion. `arguments.seed_url` is exact first-contact seed for target.
Before the first network lane, inspect `config.json.resin`; when enabled, inline its stable
sticky export from `docs/resin-proxy.md` in the same shell command. If blocked, use current evidence and the request budget to decide reuse/switch and retry depth; use no fixed count.
Rotate only on request, bypass localhost/private targets, never print the token, and never
persist proxy setup. Apply `rules/hunting.md` target-isolation/new-target defaults;
`/pickup` never replays another target's skips or scanner decisions. DNS expansion is
advisory: host count alone is not a trigger; target-specific evidence plus `--reason` is
required.
Asset relation candidates use the compact AI triage contract in
`docs/autopilot-lanes.md#credentials-and-asset-expansion`: return `related`, `uncertain`, or
`unrelated` with a bounded reason and source refs. Related only changes priority, uncertain
stays passive, and unrelated stays out of active Context/Surface/Queue/Coverage/Closure;
only existing `in_scope` permits active validation.
Observed login forms route to the bounded baseline policy in
`skills/credential-attack/SKILL.md`; this review never authorizes live `/spray`.
`/autopilot` runs inline in the current AI session and remains the sole writer/closure
controller and only owner of lane claims/state write-back. Specialists default to zero;
justified delegation loads
`docs/autopilot-lanes.md#inline-specialist-propagation` for its single delegation contract
and bounded questions/mode/batch rules.
optional `recon-ranker` stays read-only and is never a lane owner. Before a named lane, use the
literal `state.lane_contract.ref` from `docs/autopilot-lanes.md` and read only that section. Before
substantive Queue claim/resolve, read `State And Queue` and consume bootstrap
`activation_contract`; never reconstruct a second claim schema.
Before active hunting, load `rules/hunting.md`. Fresh Recon is not active hunting: when
`state.hard_gate.action=run_recon` (and when `state.next_action=run_recon` for older readers), execute the
selected lane directly and refresh after completion; the default context pack does not load
this rule. Tool discovery stays in `docs/tool-index.md`; host/JS volume alone is not a trigger
and partial/unavailable output remains open. Concrete JS gaps may select
`tools/deep_js_packer.py`; target naming evidence may select `tools/dns_expand.py`; neither
helper is a baseline lane.

Invoke setup helpers on demand: self-owned test-account email verification uses
`/root/tool/aitool/zocom/mail_receiver.py`; Cloudflare clearance uses `tools/cf_solver.py`.
Persist results through private AuthSession/Case State; failures remain `blocked`/`partial` and
never become clean.

## State Consumption Loop
```text
fresh: TARGET -> RECON -> BUSINESS/CROWN JEWELS -> SURFACE/CONTEXT -> BROWSER/SOURCE/JS TRUTH -> SCANNER QUICK -> WORKFLOW -> HYPOTHESIS -> MINIMAL PROOF -> CHAIN -> VALIDATE -> RECORD/CHECKPOINT
existing: LOAD -> REVIEW EVIDENCE -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT
```
Every invocation is state-first. Bootstrap `state` and advisory `capabilities` are the only
initial inputs. Branch only after that state read. Missing/stale/invalid is work, not no
surface, and state tools are not a pre-flight checklist. Hypothesis generation is AI-owned:
derive any family, primitive, or chain, including RCE and families outside the canonical
Coverage taxonomy, from evidence and unknowns. `knowledge_cards` are
context, never conclusions; Case State/Queue `vuln_class` is a compatibility string. Only an
owner-backed Matrix terminal state or complete evidence-backed identity candidate closes
canonical Coverage; unknown/incomplete work stays open.
Keep each iteration explicit:
`inspect candidate/context -> AI choose and activate one hypothesis -> claim -> execute one
bounded action -> read Runner observation -> AI resolve one continuation or kill -> refresh
bounded state`. Obey a non-empty `state.hard_gate` exactly. Otherwise choose one runnable
item from `state.priority_frontier`; array order is not priority. Compare business impact,
evidence strength, crown-jewel/chain fit, expected information gain, request cost, and
starvation of `closure_blocking` work. A weaker historical Queue/Case/Resume item must not
automatically preempt a stronger Surface/Finding/Intel candidate. Selection changes order only:
never bypasses the selected item's evidence/owner contract, relabel deferred work as tested-clean,
or remove it from Closure. Consume structured `next_action` and the durable Action Queue as
compatibility projections/owner contracts. With one frontier item execute it; with none use
`state.fallback_action` and bounded `next_step`. Never treat a single negative request as
permission to move on:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded
```
Before selecting another substantive lane, run a compact phase gate in the same AI turn:
what exact target-owned evidence did this lane add, which high-value surface remains unknown
or was ruled out, and why the next action has better information gain than rotate or stop. Put
answers in the existing `decision`/`next_action` heartbeat; do not create another state,
queue, or checklist owner. Without an evidence-backed answer, resolve a bounded
dead-end/blocker or handoff instead of silently widening work.

Run a mid-run review when new assets or cross-source evidence arrive, a phase changes, a
blocker/rotation occurs, or a bounded batch ends. This mid-run review is delta-based, not a
fixed sequence: inspect the bounded `surface`, `observation_inventory`,
`recon_artifacts.asset_relations`, `structured_findings.chain_context`, and all bounded owner
projections (Coverage, Ledger, Finding, Queue, Case State, Runtime/Auth). AI may return one
`related`, `uncertain`, or `unrelated` relation decision with a bounded reason and source refs,
then re-rank or add a hypothesis through existing `decision`/`next_action` fields. This is
incremental review, not a new owner or checklist; external context never directly blocks
Closure, and only unresolved target-owned work can block closure.

When starting a target, entering a high-value feature, or rotating after a stalled lane,
recall `Developer-View Pre-Hunt Recall` in `skills/bb-methodology/SKILL.md` as a soft reasoning prompt. Record target-specific answers in existing fields; never make it a second gate, fixed vulnerability order, or Queue action list.

When the selected action is `run_recon`, immediately run the selected Recon command from the
lane contract with `arguments.recon_flags`, then refresh bounded state. This is mechanical
dispatch: the next tool call starts Recon; preparation belongs there and polling/refreshing
comes only after dispatch.
For substantive candidates, apply the lane's evidence-backed activation contract
and claim the exact action before replay:
```bash
cd -- <repo_root_shell> && python3 tools/action_queue.py claim --target <target_shell> --id <id> --metadata-json '<activation-object>'
```
Queue owns activation caps, identity/dedup, Runner fields, continuation lineage, and keeps
sensitive values out of state/logs. On claim failure inspect stderr/stored state once;
never guess or retry. Runner observation leaves the action `running`; resolve it with one
primary continuation or supported kill. Independent follow-ups need separately claimed
actions within the batch budget; missing outcome/decision remains recoverable and blocks
closure. In deep mode, a concrete API/browser-XHR surface needs an evidence-linked depth pack
from target-observed request shapes; one passive observation is not API completion. Negative
results record the next evidence-linked dimension/question in Queue; partial cursors or
unused dimensions remain resumable, not tested-clean.

Deep lanes keep normal caps unless `--deep`; parameter discovery, candidate extraction, and
zero-day fuzzing may project a larger bounded budget from URL/parameter breadth, response
variance, and high-value evidence. Each projection has a hard maximum and
`partial_on_exhaustion=true`, never bypasses Scope/Auth or runner/request caps, and leaves an
incomplete cursor resumable.

Named action mechanics, replay, recon continuation, list selection, and owner write-back live
in the selected lane section. Claim durable Queue work before replay; prose or a raw endpoint
is never evidence. If `state.root_claim_next` exists, run `/checkpoint` so `finding_index`
creates the canonical candidate and Queue action before using its ID. Refresh after every
owner write-back.
## Execution Invariants
Expert Hunter Autopilot is AI-first: the current AI session judges priority, impact, chain
fit, promotion, reopen, and finish; deterministic owners preserve schema, evidence, replay,
and durable state. Follow `skills/runtime-protocol.md`, `rules/tool-ai-boundary.md`, and
`rules/hunting.md#broad-scanner-input-and-completion-contract`.
Use `rules/hunting.md` value-first priorities; scanner quick is an advisory breadth sensor,
and scanner-negative is not completion. Business Model Read: after fresh Recon starts, write
or refresh `evidence/<target>/business_model.md` from observed purpose, actors, private
objects, trust boundaries, sensitive workflows, and crown jewels; a fresh file may be reused
for 30 days.
Promote Lead -> Signal -> Candidate -> Validated Finding only with practical, replayable raw
request/response or a locatable evidence ref. Canonical finding writes go through
`finding_index` and `/validate`; partial/blocked is unresolved, not tested-clean, and
placeholder reports are not report-ready. Apply the four-layer routing in `skills/runtime-protocol.md`;
memory/cards are decision inputs, never first-contact
controllers or closure evidence.
## Transition And Finish Contract
Apply `arguments.checkpoint_trigger`: paranoid after each substantive state change,
normal after a coherent lane batch, yolo only on blocker/handoff/finish. Every cadence
writes evidence state; after a primary Candidate/Validated result try one bounded
evidence-fit sibling or chain, on 401/403/404/405/415 or parser delta try one
evidence-linked bypass family or close it, and after three homogeneous no-information
results resolve and rotate to one adjacent high-value lane. Refresh rotating
form/session tokens from the legitimate baseline before replay.

After every substantive lane, request the explicit read-only loop guard with
`cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json`.
This projection also returns bounded `control` (`hard_gate`, `priority_frontier`,
`next_action`, and `fallback_action`); use it as the post-lane state refresh and do not
run a second ordinary state read unless a later owner write requires a fresh snapshot.
Obey `loop_guard.verdict`. On `rotate`, do not continue the reported `endpoint_family` ×
`vuln_class` in this invocation; prefer its bounded `rotation_target` when present.
`continue` preserves owner state. The guard never overrides `state.hard_gate`, an
already-claimed lane, or any selected item's evidence/owner constraints; otherwise
select from the returned `control.priority_frontier`.

`--deep` is a value-first comprehensive depth flag, not a checklist or favorite bug class.
With `invocation_batch.bounded`, execute at most `max_lanes` named substantive lanes; after lane N do not execute a newly discovered queue item. Evidence import, owner write-back, cleanup, checkpoint, and closure are not new lanes and must still complete; Newly discovered work becomes next-invocation work. Finish on evidence state, not a tool checklist:
resolve/block/dead-end/promote the `working_hypothesis`, drain used `oast_listen`, record
high-value scanner leads/matrix gaps, persist/import browser artifacts and close its native session. Failed close is `partial`/`blocked` and forbids a replacement here.

Before any target-exhaustion claim, run ordered coverage review and read-only verdict;
an absent/empty matrix never proves coverage:
```bash
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py rebuild --target <target_shell>
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py find-gaps --target <target_shell> --limit 50
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```
Bounded `find-gaps --limit 50` is semantic-gap review (`relevance_score > 0`); use `--all`
for raw endpoint x class coverage. View only; `total`/`truncated` are advisory, complete matrix remains the closure owner
input, and a truncated window never means coverage is complete.
Read `closure.verdict`, `closure.can_claim_exhausted`, `closure.reasons`, and advisory
`closure.rotation_hint`. Only `verdict=finish` with `can_claim_exhausted=true` permits a
`finish/complete/exhausted` claim; `handoff` preserves durable work and `blocked` records
terminal prerequisite blocker.

Before target-wide `finish`, run Global Review over bounded summaries, then inspect referenced
evidence on demand. Review Surface and Observation long-tail; Coverage/Ledger/Finding; Case
State and business-chain; pending Queue, unfinished reports, and Runtime state; recon asset
relations and `chain_context`; Browser/JS/Source/Intel artifacts; Scope Review, external
dependencies, and blocked items; residual unknowns, including unconfirmed high-value candidates.
Do not load all raw files at once. AI may re-rank or add hypotheses, but only unresolved
target-owned work can block closure; external/uncertain/unrelated relation context remains
passive. Record the review through the Checkpoint owner with
`--record-global-review`, returned `closure.snapshot_digest`, at least one current
target-owned non-empty `evidence_refs`, the decision, and `complete` or `follow_up` mapped to
an active Queue action. Missing/stale/invalid review yields `global_review_required`,
`global_review_stale`, or `global_review_invalid`; prose/new state cannot replace it. Valid
`follow_up` keeps Queue active. Checkpoint shape:
```bash
python3 tools/checkpoint.py --target <target_shell> --record-global-review \
  --review-status complete --snapshot-digest <closure.snapshot_digest> \
  --evidence-refs-json '["evidence/<target_key>/review/summary.json"]' \
  --cross-source-links-json '["browser -> JS -> Source"]' \
  --residual-unknowns-json '[]' --decision "<decision>" --json
```

Reaching `max_lanes` ends target work for this invocation; Closure recomputes from
owners and the budget alone never requires another round. Pending report is closure asset;
it does not stop. Active substantive Queue work, pending validation/report, partial
browser/source/intel, or untouched high-value work means `handoff/partial`, never
`finish/complete/exhausted`. Missing owner/peer actor/session context ->
`closure.actor_context_gap`, a non-blocking lane-local coverage gap; it does not stop
anonymous/unrelated lanes or permit affected access-control cells to be `tested_clean`.
Checkpoint unresolved work in existing Action Queue, not passive TODOs. Passing
`check_autopilot_run.py` proves state-chain integrity, not target exhaustion.
In the final handoff/finish response, use the classification criteria (not the write
commands) in `knowledge/promotion-rules.md` and `rules/retrospective.md` to emit exactly
one presentation-only section per bounded invocation:
```text
Memory recommendations
- promote: transferable lesson, or none + reason
- target-only: current-target fact or handoff, or none
- reject: noisy, unverified, sensitive, duplicated, or overfit material, or none
```
Promotion requires a locatable target-owned evidence ref, destination layer, reusable value,
one next action, and one stop/validation condition. Recommendations never write state or
alter routing, budgets, Queue/finding lifecycle, closure, or next action. End with target,
mode, strongest evidence, findings/candidates, blockers/dead ends, this section, and the
next best action.
