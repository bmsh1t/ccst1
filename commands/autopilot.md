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
Run project commands as `cd -- <repo_root_shell> && ...`. Use
`arguments.target_shell`, expand `arguments.hunt_auth_flags` (or
`--auth-file <arguments.auth_file_shell>`) only when present, and apply
`arguments.recon_flags` only to fresh/refresh recon. Obey parsed cadence,
`quick`, `deep`, and `invocation_batch` exactly. `--quick` lowers recon cost;
never skips browser/source/validation or implies completion. `arguments.seed_url` is an
exact first-contact browser/source/workflow seed for the canonical target.
Treat the supplied target set as the active execution target set; `ctf_mode` is the
authoritative lab target record. External policy is advisory audit/replay context;
do not require public-program, written-permission, or ownership-confirmation.
`/autopilot` runs inline in the current Claude session as the sole controller and does not create/resume legacy `agent_session.json`; specialists default to zero.
At most one bounded specialist may be invoked through Claude Code's `Agent` tool for one evidence question. The invoked specialist must not spawn nested agents, run full recon/scans, write final closure, or control finish. After using one, this invocation cannot call a second specialist.
Bootstrap emits one `state.lane_contract` pointer. Before executing a named lane, read only
`state.lane_contract.ref` (or the matching section for a newly observed signal) from
`docs/autopilot-lanes.md`; it is execution detail, not a second controller. Every lane still
inherits this command's Scope/Auth, evidence, checkpoint, Action Queue, loop-guard, and finish
contracts.
## State Consumption Loop
```text
fresh: TARGET -> RECON -> BUSINESS/CROWN JEWELS -> SURFACE/CONTEXT -> BROWSER/SOURCE/JS TRUTH -> SCANNER QUICK -> WORKFLOW -> HYPOTHESIS -> MINIMAL PROOF -> CHAIN -> VALIDATE -> RECORD/CHECKPOINT
existing: LOAD -> REVIEW EVIDENCE -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT
```
Every invocation is state-first. Bootstrap `ctf_mode`, compact `state`, and advisory
`capabilities` are the only initial inputs. Branch only after that state read;
missing/stale/invalid is work, not no surface. State tools are not a pre-flight checklist.
For each iteration: consume structured `next_action` and the durable Action Queue; use bounded `next_step`, then choose
one smallest evidence-producing action, execute it, write evidence, then refresh bounded state before choosing again:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded
```
In deep mode, a concrete API/browser-XHR surface requires an evidence-linked
depth pack: run the observed GET/query path and the observed POST JSON/form path
when applicable. GET-only is not API completion; OPTIONS/HEAD remain passive
checks, and default probing never adds PUT/PATCH/DELETE. After a negative result,
record the selected sibling/variant/actor/workflow/chain dimension plus
`hypothesis`, `tested_dimensions`, `expected_learning`, `kill_condition`, and `next_question` in the
existing Action Queue metadata (for manual write-back, use `tools/action_queue.py add --metadata-json '{"hypothesis_id":"H-1","tested_dimensions":["sibling"],"expected_learning":"...","kill_condition":"...","next_question":"..."}'`; the parser accepts only a JSON object and rejects credential-bearing fields before any queue write; this is the existing Action Queue, not a new state owner). A partial tool cursor or unused depth dimension
is resumable work, not tested-clean.

When resolving an existing action, preserve the same structured metadata through
`tools/action_queue.py resolve --metadata-json`; `last_outcome`,
`tested_dimensions`, `next_question`, `expected_learning`, `kill_condition`, and
`pivot_hints` merge into the existing action metadata without creating another
state owner. The JSON must be an object and must not contain credentials or
authorization headers.

Named action mechanics, replay commands, recon continuation, list selection, and owner
write-back rules live in the selected lane section. Claim durable queue work before replay;
never treat prose or a raw endpoint as evidence. If `state.root_claim_next` exists, run `/checkpoint`
so `finding_index` creates the canonical candidate and queue action before using
its ID. Refresh state after every owner write-back.
On-demand index (references only): `run_recon` uses
`python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --recon-only`;
`prepare_surface_context` uses `python3 tools/surface.py --target <target_shell> --refresh`;
usable cache inspection may read `tools/context_pack.py` and
`tools/observation_inventory.py summary`; breadth uses
`python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --scan-only --quick`.
`wait_recon` / `wait_scan`: wait or poll; Runtime phase locks are the final duplicate-launch guard.
`collect_candidate_evidence` preserves `missing_labels` and `next_actions`;
`resume_action_queue` claims before replay with
`python3 tools/action_queue.py claim --target <target_shell>`, then
`python3 tools/action_queue.py resolve --target <target_shell> --id <id> --status <state> --evidence <why> [--metadata-json <object>]`;
`validate_finding` remains state-gated: Do not call `/validate` until state returns `validate_finding`;
the non-TTY owner is `python3 tools/validate.py --target <target_shell> --finding-id <id> --decision-json <json_file_shell> --json`; the JSON file path is never inline.
Deterministic replay is
`python3 tools/validation_runner.py <lane> --target <target_shell> ...` (its first positional
argument is `<lane>` and it never accepts `--decision-json`). For a readable text list or JSON
Scope manifest, keep the parent `scope_ref/scope_hash` attached to each selected asset. Every
listed `in_scope` asset may enter surface/context/browser/scan/hunt; an `out_of_scope` match always
wins. Keep unlisted discovery URLs as `external-chain-context` or `scope-review` until the
manifest/list is explicitly updated. Never scan the list or manifest file itself. When selecting
one asset, first run `python3 tools/autopilot_continuation.py create --parent-target <scope_ref> --selected-target <domain> [--auth-file <auth_file_shell>]`, then invoke `/autopilot <domain> --context-file=<returned-path>`; bootstrap validates and applies the parent Scope/Auth before bounded state or target I/O.
Browser imports use
`tools/browser_mcp_import.py` with `--auth-required` for authenticated captures. JS packing uses
`tools/deep_js_packer.py` only with concrete evidence; JS volume alone is not a trigger;
partial/unavailable stays open. DNS expansion
uses `tools/dns_expand.py --reason` only when evidence triggers it; host count alone is not a trigger.
Known software uses `tools/intel_engine.py`; AI must select a reachable advisory before a targeted
probe, and use `knowledge/cards/wordpress-surface-intelligence.md` for WordPress context.
Focused fuzz is an optional AI-selected discovery action via `skills/web2-recon/SKILL.md`.
`Discovery / Exploitation / Validation Modes`: evidence-driven depth does not mean evidence-only
testing; Actively generate new evidence and let AI override ordering with reason and write-back.
AI override may skip, reorder, combine, or invent a better evidence action.
`Case-State First, Not Case-State Only`: case-state-validation and case-state-enrichment are
continuity, not a scope gate; stale state does not block AI override. `Credential Lane`: `/autopilot` may select
through `skills/credential-attack/`; Password brute force, default credential checks, and password spray are not
absolute red lines or a mandatory last lane.
Byte-exact work uses `tools/sender_semantics.py --require` and `tools/smuggling_executor.py --variant`.
Red-line checks are narrow side-effect checks, not authorization or ownership gates; active stored
XSS payload, change real account or permission state, and trigger CI/CD/deployment side effects require current-turn intent.
`tools/observation_inventory.py summary` remains advisory; never route every untouched observation
to a Skill. SQL/JSON/WAF and 401/403 details, including `tools/json_inject_probe`,
`tools/sql_parameter_probe`, and `tools/bypass_403.sh`, are in the selected lane contract.
## Execution Invariants
Expert Hunter Autopilot is AI-first: Claude judges priority, impact, chain fit,
promotion, reopen, and finish. Tools preserve schema, raw evidence, replay,
diffs, and durable state. Follow `rules/tool-ai-boundary.md`; rankings, cards,
scanner output, coverage gaps, and runner labels are advisory and reopenable.
Super-pentester priority is business impact > workflow evidence > crown-jewel
hypothesis > scanner/coverage hints. Scanner quick is a breadth sensor and
advisory lead source; scanner-negative is not completion. Follow
`rules/hunting.md#broad-scanner-input-and-completion-contract`: never feed raw
historical corpora directly to general nuclei, never repeat breadth only because
Deep mode or raw volume is large, and treat killed/stopped/timeout/non-zero as
incomplete. Bounded Surface is the default window, not an AI capability limit.
General Nuclei breadth is origin-deduplicated and bounded to 50/100/200 targets
for quick/standard/full (`BB_NUCLEI_MAX_TARGETS` overrides); `summary.json`
records available and selected origin counts. Long-tail paths/components/CVEs
need a reviewed evidence-backed list.
Business Model Read: before recon or after first recon, maintain
`evidence/<target>/business_model.md` using the `agent.py` directive.
Promote Lead -> Signal -> Candidate -> Validated Finding only with practical,
replayable raw request/response or a locatable evidence ref. Canonical finding
writes go through `finding_index` and `/validate`, never direct `findings.json`
edits. A root claim is an unvalidated candidate input; tool/browser success and
terminal prose are not lifecycle transitions. Partial/blocked is unresolved,
not tested-clean. A report draft with placeholders is not report-ready.
Four-layer memory is the external brain, not the steering wheel:
`target memory / target case state -> skill routing -> knowledge cards -> checks`.
When a linked case-state backlog is blocked, state projects `recover_hypothesis`
with an empty replay command; record the bounded recovery step before creating a
fresh backlog and never replay the blocked runner implicitly.
Use `reference_hints` and 1-2 matching knowledge cards/on-demand references; do
not let them drive first contact. Observation top-K, `remaining`, and untouched
long tail are completeness windows. Never route every untouched observation to
a Skill or treat the window as closure.
Use `/observations` to reopen evidence-driven long-tail work.
## Evidence-Triggered Lane Pointers
Before unusual helpers, scan `docs/tool-index.md` once and read only the selected
section of `docs/autopilot-lanes.md`. Discovery is evidence-generating, not evidence-only:
AI may skip, reorder, combine, or invent a better evidence action, but must record the reason,
red-line status, stop condition, and write-back. The lane document covers browser/source/JS,
software/intel, SQL/JSON/WAF, access limits, workflow/timing, credentials, asset expansion,
and wire/live-action boundaries. Canonical contracts remain
`skills/runtime-protocol.md`, `rules/red-lines.md`, `rules/coverage-gate.md`, `rules/hunting.md`,
`rules/tool-ai-boundary.md`, `rules/web-intel.md`, `knowledge/index.md`,
`tools/checkpoint.py`, `tools/action_queue.py`, `tools/coverage_matrix.py`,
`tools/evidence_ledger.py`, and `docs/evidence-runners.md`.
- Discovery / Exploitation / Validation Modes use the same evidence rubric and write-back.
- Credential Lane: use only the controlled lane contract; missing hygiene becomes queued work.
Legacy-only `--parallel`, `--max-parallel`, `--parallel-hypotheses`,
`--self-review`, and `--calibrate-patterns` are invalid inline. Use
`python3 agent.py --target <target_shell> ...`; baseline legacy runs use
`python3 tools/hunt.py --target <target_shell> --agent`.
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
Finish on evidence state, not a tool checklist. `working_hypothesis` must be resolved, blocked, dead-end, Candidate, or Validated Finding. Check `oast_listen` when used; resolve or record high-value action-gated scanner leads and every matrix gap.
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
End with target, mode, strongest evidence, findings/candidates, blockers/dead ends, and next best action. If the bounded invocation reached `max_lanes`, its terminal handoff overrides target exhaustion; unresolved durable work is expected.
