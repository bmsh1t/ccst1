---
description: AI-first autonomous hunt loop for one target or a target list.
allowed-tools:
  - Bash
  - Agent
  - "mcp__Playwright__*"
  - "mcp__chrome-devtools__*"
---
# /autopilot
Authoritative bootstrap contract (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"`
Formal arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep] [--max-lanes N] [--auth-file PATH]`, or one readable primary-domain list.
## Runtime Preflight
Obey bootstrap `action` before any other step. `ask_target` asks for the exact target;
`stop_invalid_arguments` reports `arguments.errors`; `stop_state_error`/`stop_runtime_error` report bounded `error` and stop; `stop_runtime_drift` reports compact runtime counts, points to `/sync-check`, requests explicit confirmation before any sync, and stops. Never sync automatically. Only `continue` may act.
The bootstrap already ran arguments, read-only runtime compare, advisory capability profile, then compact target state. Arguments/runtime remain the only blocking gates. Treat
`capabilities` as advisory: `session_managed` names are not availability claims; use MCP only when visible in this Claude session and use a listed fallback otherwise. Missing/degraded
tools never block, trigger installation or request it, count as tested-clean, or hide material
limits in the handoff. Within one invocation, do not rerun the same failed source/tool; preserve
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
- `run_recon`: when `state.recon.cidr_continuation.status=pending`, continue once with
  `BBHUNT_CIDR_OFFSET=<next_offset> python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --recon-only`; otherwise omit the offset. Keep exact recon flags; never restart a pending CIDR at zero or discard prior pages. If `state.dir_fuzz_rotation.pending=true`, rerun the same bounded Recon so its FFUF target ledger advances to the next live services; `live/urls.txt` remains the complete source.
- `wait_recon` / `wait_scan`: wait or poll, then refresh state. Runtime phase
  locks are the final duplicate-launch guard.
- usable cache: inspect `tools/surface.py`, `tools/context_pack.py`, and
  `tools/observation_inventory.py summary` before the later breadth pass
  `python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>]
  --scan-only --quick`.
- `prepare_surface_context`: run one explicit `python3 tools/surface.py --target <target_shell> --refresh`,
  verify its bounded projection, load context, then refresh state.
- `collect_candidate_evidence`: consume `state.structured_next.rubric.next_actions`, or
  a reviewed `state.memory_candidate_next` locatable `evidence_ref`; preserve
  `missing_labels` and refresh. Prose or `raw_endpoint` alone is not evidence.
- `validate_finding`: Do not call `/validate` until state returns
  `validate_finding`. The non-TTY owner is
  `python3 tools/validate.py --target <target_shell> --finding-id <id>
  --decision-json <json_file_shell> --json`; the JSON file path is never inline.
- `resume_action_queue`: run
  `python3 tools/action_queue.py claim --target <target_shell>`, perform the
  claimed or resumed durable replay, then run
  `python3 tools/action_queue.py resolve --target <target_shell> --id <id> --status <state> --evidence <why>`
  and refresh.
- `resume_case_state`: follow `state.case_state.top_next_action`; run its
  redacted validation command when ready. Otherwise, enrich or create the owner
  backlog with `tools/target_case_state.py`, write back through that owner, then
  refresh.
- `review_validation_candidate`, `complete_report_draft`, `run_intel`,
  `collect_web_intel`, `test_advisory_applicability`, and
  `recon_no_live_hosts` retain their owner-defined stop/write-back semantics.
If `state.root_claim_next` exists, run `/checkpoint` so `finding_index` creates
the canonical candidate and queue action, refresh, then use the canonical ID.
Matching deterministic replay follows `docs/evidence-runners.md` and
`python3 tools/validation_runner.py <lane> --target <target_shell> ...`; its first
positional argument is `<lane>` and it never accepts `--decision-json`.
For a readable primary-domain list, the list context is recon/handoff only; run batch recon
only for `run_batch_recon`; never scan the list/index. Stop on `invalid_batch_target`
or `batch_failed`; otherwise select one completed domain, then rerun
`autopilot_state.py --target <domain> --bounded`. Only the selected domain may enter surface/context/browser/scan/hunt.
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
Use `reference_hints` and 1-2 matching knowledge cards/on-demand references; do
not let them drive first contact. Observation top-K, `remaining`, and untouched
long tail are completeness windows. Never route every untouched observation to
a Skill or treat the window as closure.
Use `/observations` to reopen evidence-driven long-tail work.
## Evidence-Triggered Lane Pointers
Before unusual helpers, scan `docs/tool-index.md` once. Canonical contracts are
`skills/runtime-protocol.md`, `rules/red-lines.md`, `rules/coverage-gate.md`,
`rules/hunting.md`, `rules/tool-ai-boundary.md`, `rules/web-intel.md`,
`knowledge/index.md`, `tools/checkpoint.py`, `tools/action_queue.py`,
`tools/coverage_matrix.py`, `tools/evidence_ledger.py`, and `docs/evidence-runners.md`.
- Discovery / Exploitation / Validation Modes: evidence-driven depth does not
  mean evidence-only testing. Actively generate new evidence when surface is
  weak; turn concrete signals into minimal proof; validate Candidates with the
  evidence rubric. AI override may skip, reorder, combine, or invent a better
  evidence action, with reason, red-line status, stop condition, and write-back.
- Browser/source/JS: browser actions use only visible Playwright/Chrome MCP. Never
  run `agent-browser` or `playwright-cli` through Bash. First use: harmless page-list/session probe;
  retry once only for timeout, disconnect, or closed-context errors. Missing/configuration/permission/protocol
  errors do not retry. After a second failure, checkpoint the blocker in the existing
  Action Queue, pivot to JS/source/API evidence, and probe again only next invocation,
  after repair, or on explicit operator retry. On success import native artifacts via
  `tools/browser_mcp_import.py` (`--auth-required` for authenticated captures).
  Missing Network/state stays partial. Use `tools/source_intel.py`/`tools/js_reader.py`;
  `tools/deep_js_packer.py` requires concrete runtime/chunk/source-map evidence; JS volume alone is not a trigger.
  partial/unavailable stays open.
- Known software: concrete version -> `tools/intel_engine.py`; AI must select a reachable advisory before targeted probe; refresh state. WordPress/WPScan: `knowledge/cards/wordpress-surface-intelligence.md`. Exchange/OWA/EWS/Autodiscover evidence -> `python3 tools/eburst_lane.py --target <target_shell>` for the bounded interface check; use `/spray` for reviewed credentials.
- SQL/JSON/WAF: `live/wafw00f_hits.txt` is sampled host-level context, not per-request proof. For a reviewed same-target POST/JSON shape, run `python3 -m tools.json_inject_probe --target <target_shell> --endpoints-file <reviewed-jsonl> [--auth-file <auth_file_shell>] --no-default-seeds --max-requests <budget>` and read `findings/<target-key>/poc/json_inject/summary.json`; for reviewed GET/query or form inputs, use `python3 -m tools.sql_parameter_probe --target <target_shell> --urls-file <query_urls> [--auth-file <auth_file_shell>]` or `--form-file <form-jsonl> [--auth-file <auth_file_shell>]`. Both adapters use the same bounded SQL matrix and at most two budgeted SQLi/XSS semantic variants after a new block (baseline-relative); read the lane `summary.json`. `429`, transport failure, block pages, and WAF observations are not findings. Use result-diff or bounded sqlmap only for an evidence-backed raw request; never spray because parameters or a WAF exist.
- Workflow sequence: when imported HAR/browser Network evidence contains at least two ordered same-target business requests, run `python3 tools/workflow_sequence.py --target <target_shell> --evidence-ref <repo-evidence-json>`; it performs one bounded remove/repeat perturbation, refreshes declared per-step tokens, writes raw traffic privately, and leaves the result in Action Queue. Mutation/unknown steps remain `manual_required` unless the current turn supplies the red-line flag.
- Timing SQL: when a time-shaped candidate or explicit SQL timing evidence remains after result-diff, run `python3 tools/timing_sql_runner.py --target <target_shell> --url <target-url> --param <name> --variant-value <controlled-delay>` with an explicit request cap. It interleaves baseline/variant samples and requires a stable median/MAD trend; one slow response, `429`, WAF block, or transport error stays partial.
- Case state: case-state-validation and case-state-enrichment are high-value continuity;
  Case-State First, Not Case-State Only: not a scope gate or bug-class selector. Stale/missing
  cannot block fresh evidence/AI override; use `tools/target_case_state.py`, `tools/case_state_seed.py`, and runners.
- Credential Lane: `/autopilot` may select the controlled
  `skills/credential-attack/` flow when login value, reviewed identities,
  lockout/rate, shortlist, dry-run/preflight, audit, and stop-on-hit gates exist.
  Password brute force, default credential checks, and password spray are not
  absolute red lines or a mandatory last lane. Missing hygiene becomes a queued action.
- Focused fuzz is an optional AI-selected discovery action; DNS expansion is also AI-selected, and canonical contracts live in `skills/web2-recon/SKILL.md`.
  DNS expansion requires a concrete naming/certificate/JS/source gap and calls `tools/dns_expand.py --target <target_shell> --reason "<evidence>"`; host count alone is not a trigger, and generation/resolution/scope/merge stay tool-owned.
- Generic asset-relationship expansion is optional and evidence-triggered: use only
  organization/brand, certificate, ASN/origin, registrant, supplier, public-source,
  or existing relationship evidence, or explicit intent; skip simple labs, localhost,
  and isolated IP/CIDR without organization evidence. Quick requires explicit intent;
  normal gets one pass at depth 1; deep may recurse to depth 3; full may recurse to
  depth 4. Follow only majority/control relationships, dedupe `entity_ref` (or
  source/entity), and stop after two empty domain levels or budget exhaustion. Use
  structured public sources; Chrome DevTools MCP is public/no-credential only, writes
  locatable `source_ref` facts, and never calls `browser_mcp_import.py` or Browser
  Surface. Normalize to `recon/<target-key>/exposure/asset_relation_observations.jsonl`
  with optional `entity_ref`, `parent_ref`, `ownership_pct`, and `depth`, run
  `python3 tools/recon_candidates.py --target <target_shell>`, and refresh
  `/surface`/`/checkpoint`. Resolve `asset-scope-review`; only tool-derived `in_scope`
  is executable, while `scope-review`, `external-chain-context`, `excluded`, and
  `unknown` retain lossless raw evidence. FofaMap (`mcp__fofamap__*`) is one optional
  FOFA/Shodan adapter for a concrete coverage gap; do not call it every round or
  install it when missing. Future Quake/Hunter adapters use the same contract. Never
  send active validation requests to a returned third-party asset solely because a
  relationship source reported it.
- Byte-exact HTTP/cache/desync uses `tools/sender_semantics.py --require` and
  `tools/smuggling_executor.py --variant`; read `disposition=manual_required` as a
  capability handoff, not a verified smuggling result. Browser evidence cannot prove
  wire absence.
- Live-Action Boundaries: `rules/red-lines.md` is canonical. Red-line checks are
  narrow side-effect checks, not authorization or ownership gates. A current-turn
  request that names an action already supplies its opt-in; do not ask for a
  separate authorization statement. Pause for ambiguous target, missing required
  credentials, new off-set target, report submission, or concrete irreversible/
  high-pressure side effects. Controlled credential
  testing and OAST are not red lines; active stored XSS payload, change real
  account or permission state, and trigger CI/CD/deployment side effects require
  explicit current-turn intent.
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
