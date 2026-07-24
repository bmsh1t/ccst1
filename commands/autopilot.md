---
description: Expert Hunter AI-first autonomous hunt loop — recon/cache state, review surface evidence, enrich with browser/source/JS, hunt, validate candidates, report validated findings, and checkpoint useful memory. Usage: /autopilot target.com [--paranoid|--normal|--yolo|--quick|--deep] [--max-lanes N] [--auth-file PATH] or /autopilot targets.txt
allowed-tools: Bash
---
# /autopilot
Authoritative bootstrap contract (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"`
Obey bootstrap `action` before any other step: `ask_target` asks for the exact target;
`stop_invalid_arguments` reports `arguments.errors`; `stop_runtime_drift` reports
the compact runtime counts and stops. Only `continue` may act. Use
`arguments.target_shell` for Bash, expand `arguments.hunt_auth_flags` (equivalently
`--auth-file <arguments.auth_file_shell>`) on hunt/recon/scan when non-null, use `arguments.recon_flags` only on fresh/refresh recon, and obey
the parsed cadence/quick/deep/max_lanes values exactly. `--quick` lowers recon cost but never
skips browser/source/validation or implies completion; scanner quick remains a
breadth sensor. `--deep` increases value-first depth without relaxing red lines. If
`invocation_batch.bounded` is true, its `max_lanes` is a current-invocation boundary:
after that many substantive lanes checkpoint, preserve the durable queue, give a handoff,
and end; browser/source discoveries become next-invocation work, not lane N+1.
On `continue`, treat `capabilities` as advisory: `session_managed` names are not availability claims; use MCP only when visible in this Claude session, otherwise follow a viable fallback/recommended path. Missing/degraded tools never block, trigger installation, request installation permission, or count as tested-clean; record material limits in the handoff.
Expert Hunter Autopilot for Claude CLI. Claude is the hunter; tools are memory,
evidence, replay, and summary aids.
Execution contract: `/autopilot` runs inline in the current Claude session as the sole controller and does not create/resume legacy `agent_session.json`; specialists default to zero, and at most one bounded specialist may answer one evidence question without spawning agents, running full recon/scans, writing final closure, or controlling finish. After using one, this invocation cannot call a second specialist.
## Runtime Preflight
The bootstrap already performed the startup sequence in this order: arguments,
read-only runtime compare, advisory capability profile, then compact target state. Never repeat or bypass it; arguments/runtime remain the only blocking gates. Compact state is a read-only control-plane projection: it may stat recon and read bounded manifest-bound summaries, but never scans `with_params.txt`, parses full `observations.json`, ranks surface, syncs inventory, or writes target state; only exact-hit `surface_projection` supplies ranked candidates, and missing/stale/invalid remains explicit work rather than no surface.
Run every project command as `cd -- <repo_root_shell> && ...`; do not derive a
second root from the current cwd. Runtime drift: show `/sync-check`, request
explicit confirmation before any sync, and never sync automatically.
```text
fresh: TARGET -> RECON -> BUSINESS/CROWN JEWELS -> SURFACE/CONTEXT -> BROWSER/SOURCE/JS TRUTH -> SCANNER QUICK -> WORKFLOW -> HYPOTHESIS -> MINIMAL PROOF -> CHAIN -> VALIDATE -> RECORD/CHECKPOINT
existing: LOAD -> REVIEW EVIDENCE -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT
```
Super-pentester priority: business impact > workflow evidence > crown-jewel hypothesis > scanner/coverage hints. Scanner quick is a breadth sensor and advisory lead source; scanner-negative is not completion. Broad scanner execution follows `rules/hunting.md#broad-scanner-input-and-completion-contract`: use `tools/hunt.py --target <target_shell> --scan-only --quick` for the normal breadth pass; never feed raw historical corpora directly to general nuclei. A successful quick pass is not repeated because Deep mode or raw URL volume is large. Bounded Surface is the default window, not an AI capability limit: page/search raw evidence or build evidence-driven targeted lists/templates when needed. killed/stopped/timeout/non-zero is incomplete, never zero findings or scanner complete.
## Tool Index
Before unusual/non-default helpers, scan `docs/tool-index.md` once per session.
Canonical runtime references: `skills/runtime-protocol.md`, `rules/red-lines.md`,
`rules/coverage-gate.md`, `rules/hunting.md`, `rules/tool-ai-boundary.md`, `knowledge/index.md`,
`tools/action_queue.py`, `tools/coverage_matrix.py`, `tools/evidence_ledger.py`, `tools/observation_inventory.py`, `rules/web-intel.md`, and `docs/evidence-runners.md`. These are navigation aids, not a state machine.
## Four-Layer Automation
Four-layer memory is the external brain, not the steering wheel:
```text
target memory / target case state -> skill routing -> knowledge cards -> checks
```
Every invocation is state-first: bootstrap `ctf_mode` and compact `state`, plus advisory `capabilities`, are the
only initial inputs. Branch only after that state read; after a long phase, refresh with:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded
# next_action=run_recon: launch once; expand arguments.recon_flags exactly
cd -- <repo_root_shell> && python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --recon-only [--quick|--deep]
# usable cache: inspect surface/context before a later quick scan
cd -- <repo_root_shell> && python3 tools/surface.py --target <target_shell>
cd -- <repo_root_shell> && python3 tools/context_pack.py --target <target_shell> && python3 tools/observation_inventory.py summary --target <target_shell>
cd -- <repo_root_shell> && python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --scan-only --quick
```
If state returns `wait_recon` / `wait_scan`, do not start that phase again;
wait/poll, then rerun state before continuing. Runtime phase locks are the final
duplicate-launch guard. `review_validation_candidate` reviews raw runner evidence before `/validate`; `resume_action_queue` executes its durable replay; `prepare_surface_context` runs one explicit `surface.py --refresh`, verifies the new bounded projection, then loads `context_pack`; `recon_no_live_hosts` records the offline blocker and never reruns automatically. Refresh recon only when missing, thin, stale, or contradicted by fresh evidence. Recon completion normally builds the exact URL index and first projection once; finalizer failure preserves raw recon and leaves this explicit recovery action.
`collect_candidate_evidence` consumes `state.structured_next.rubric.next_actions`, or `state.memory_candidate_next` only after its locatable `evidence_ref` is reviewed; otherwise collect raw request/response and never promote prose alone. If `state.root_claim_next` exists, it is an unvalidated root JSON claim: first run `/checkpoint` so `finding_index` reconciles it into the canonical candidate and durable queue, refresh state, then pass that canonical `structured_next.id` to `python3 tools/validation_runner.py <lane> --target <target_shell> --finding-id <id> ...` when a matching bounded runner captures raw proof; its first positional argument is `<lane>`, and `validation_runner.py` never accepts `--decision-json`. Preserve named `missing_labels`, then rerun state. Do not call `/validate` until state returns `validate_finding`. `complete_report_draft` fills its linked draft placeholders without reopening validated evidence.
If `arguments.seed_url` is non-null, inspect `<seed_url_shell>` through browser/source/workflow evidence before historical focus or score hints, even for existing canonical target state.
For a readable primary-domain list, the list context is recon/handoff only:
1. Run `autopilot_state.py --target targets.txt --bounded` before batch recon.
2. Run `hunt.py --target targets.txt --recon-only` only when state says `run_batch_recon`; expand `arguments.recon_flags` exactly, and never scan the list/index. `invalid_batch_target` / `batch_failed` stop without automatic retry.
3. Read `recon/<list-stem>/ai_handoff.md` and `surface_ranking.txt`, select one completed domain, then rerun `autopilot_state.py --target <domain> --bounded`.
4. Only the selected domain may enter surface/context/browser/scan/hunt; do not aggregate active work across the batch.
For existing single targets, run a closed-state sanity check before executing a historical `continue_last_focus`, resume target, or `/surface` score hint:
```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --no-refresh-coverage
cd -- <repo_root_shell> && python3 tools/action_queue.py summary --target <target_shell>
```
If checkpoint/action_queue show no executable next action, treat those historical
hints as context rather than commands. Re-open them only when fresh
browser/source/JS/recon evidence or business context contradicts the recorded
closure.
Use `context_pack.py` for compact route hints, `reference_hints`, and
1-2 knowledge cards / on-demand references that match current evidence. Do not let
them drive first contact. `target_case_state.py`, `case_state_seed.py`,
`checkpoint.py`, `action_queue.py`, `coverage_matrix.py`, `evidence_ledger.py`,
and `validation_runner.py` are not a pre-flight checklist; use them only when
they reduce drift, preserve actor/session/object continuity, or produce stable
evidence.
Checkpoint can emit target-memory write-back proposals:
```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell>
```
Review the proposal and apply target memory only when it is useful; stale/noisy state must not block recon, browser/source enrichment, AI-selected pivots, or a better live hypothesis. Observation inventory is a completeness reminder, not an execution queue: before declaring surface exhaustion, inspect its bounded untouched/stale summary or page the long tail with `/observations`; promote an item only when Claude can state the evidence question. A top-K/review window or `remaining` count never closes the overflow, and only explicit observation `touch` changes lifecycle. Never route every untouched observation to a Skill or enqueue it automatically.
## Authorization Posture
Treat the supplied target set as the active authorized execution set for this
run. Do not pause for routine recon/scanning/hunting authorization re-checks.
Do not require public-program, written-permission, or ownership-confirmation
text for localhost/private IP/CIDR/list inputs or lab runs; `ctf_mode` is the
authoritative lab target record. External policy stays advisory audit/replay
context, not an execution gate.
Pause only for ambiguous target identity, unavailable credentials needed for the
next step, a new target outside the supplied set, report submission, or concrete
destructive/irreversible/high-pressure side effects.
## Business Model Read
Before recon or immediately after first recon output, write/read
`evidence/<target>/business_model.md`; this points to the `agent.py` system
prompt directive without duplicating a fixed workflow taxonomy.
## Discovery / Exploitation / Validation Modes
Evidence-driven depth does not mean evidence-only testing.
- Discovery mode: when evidence is weak or surface is underexplored, actively generate new evidence from browser-observed APIs, JS/source-derived routes, cached recon, API docs/leaks, hidden parameters, path-pattern siblings, component/CVE intelligence, roles, objects, and workflow mapping.
- Exploitation mode: when a host/path/parameter/component/version/behavior signal exists, turn it into the smallest safe replay, diff, sibling expansion, bypass, OAST, CVE applicability, or chain-building step.
- Validation mode: when a Candidate exists, prove practical impact with the lowest-impact replay/diff and the `/validate` evidence rubric.
Focused fuzz is an optional AI-selected discovery action only when browser/JS/source/API/recon evidence supports one concrete template and bounded, deduplicated wordlist. Baseline FFUF is an automatic breadth sensor; an empty baseline does not trigger focused fuzz. Keep each run under isolated `recon/<target_key>/focused_fuzz/<run_id>/` raw/summary artifacts, then write the AI judgment through `target_memory.py lead/dead-end`; never auto-expand surface, queue, or coverage.
When same-target seeds expose a naming dialect, preserve seed-linked structure/semantic transformations before fuzzing, then use random-miss response groups to decide the next bounded round; route existence remains a Signal, not a vulnerability Candidate.
AI override is first-class: skip, reorder, combine, or invent the next action
when evidence supports it. State the reason, red-line status, next verification
step, and stop condition. Tool recommendations are advisory, not hard rails.
## Browser / Source / JS Enrichment
Prefer browser-state truth over guessed routes:
1. `tools/browser_evidence.py` with agent-browser CLI for routine automation, session reuse, snapshots, network, storage, and HAR evidence.
2. chrome-devtools MCP for deep live DevTools/network/console debugging.
3. playwright MCP or the explicit playwright-cli backend as compatibility fallbacks.
4. Import useful MCP artifacts with `tools/browser_mcp_import.py` so `recon/<target>/browser/`, `/surface`, `/checkpoint`, and `/autopilot` share the same browser-observed API surface.
Use `cd -- <repo_root_shell> && python3 tools/js_reader.py --target <target_shell>` for JS materials and
`cd -- <repo_root_shell> && python3 tools/source_intel.py --target <target_shell> [--repo-path <repo>]` for
source/route/auth logic. AI should turn these hints into concrete replay drafts,
not just tool rankings.
For byte-exact HTTP/cache/smuggling/desync work, use
`tools/sender_semantics.py --require <capabilities>` and
`tools/smuggling_executor.py --variant <variant>`; browser evidence cannot prove
wire-level absence.
## Core Decision Loop
1. Load target freshness and existing evidence; fresh targets start with recon, existing targets start with cache/state.
2. Model BUSINESS/CROWN JEWELS: actors, private objects, workflows, admin/config/payment/data flows, trust boundaries.
3. Build a surface/context evidence pack; AI chooses priority.
4. Capture real browser/source/JS/API request shapes when they can change the next test; scanner quick is only a later breadth signal.
5. Hunt one high-value hypothesis with MINIMAL PROOF; then attempt CHAIN EXPANSION through role/object/state/method/parser/cache/source/integration pivots.
6. Promote Lead -> Signal -> Candidate -> Validated Finding only with replayable evidence and practical impact; only a same-target structured finding plus locatable raw request/response or `evidence_ref` may be called confirmed/validated. Canonical finding lifecycle writes go through `finding_index`/`/validate`, never direct `findings.json` edits; the only non-TTY signature is `python3 tools/validate.py --target <target_shell> --finding-id <id> --decision-json <json_file_shell> --json`, where `--decision-json` is a JSON file path, never inline JSON.
7. REPORT/CHECKPOINT only after AI judges stronger validation/chain/coverage actions no longer outrank the pending report; target-memory remains lead/candidate, and a draft with placeholders is not report-ready or submittable.
### High-impact success handoff
Treat reproduced exploit behavior or browser-observed impact as evidence, not a finding lifecycle transition. For RCE/SSRF/XXE/deserialization/upload/JWT lanes, preserve exact raw request/response or a locatable browser artifact; when no runner exists, write a target-owned root claim JSON with `kind: "finding_claim"`, `schema_version: 1`, `title`, `target`, `vuln_class`/`type`, known `endpoint`/`path`, impact, and evidence refs, then run `/checkpoint` so the owner creates the candidate/action. Do not reuse another tool's status/summary JSON as a claim.
Missing endpoint data remains an explicit incomplete claim; never fabricate the target root as a URL. Refresh state, use the canonical ID for `/validate`, or close the action as blocked/dead-end; terminal prose alone is never confirmed/validated.
## Actionable Evidence Continuation Contract
Claude must not turn an evidence-backed next step into a passive TODO. `tools/checkpoint.py` automatically syncs its executable proposals through the action-queue owner; use
`cd -- <repo_root_shell> && python3 tools/action_queue.py next --target <target_shell>` and
`cd -- <repo_root_shell> && python3 tools/action_queue.py resolve --target <target_shell> --id <id> --status <state> --evidence <why>`.
Use `cd -- <repo_root_shell> && python3 tools/action_queue.py ingest-checkpoint --target <target_shell>` only for an explicit legacy/manual checkpoint recovery. Applies to known product/CMS/plugin/theme/library versions,
exposed routes, authz/IDOR, SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection,
parser/file/network/client/business lanes. Do not overfit this contract into a fixed checklist.
When a primary lane is blocked, do not checkpoint/finish immediately if adjacent high-value lanes remain. Continue with the smallest applicable adjacent lane first, and only stop after the remaining high-value lanes are tested, blocked, dead-end, or not applicable.
## Compact Transition Gate
- Apply `arguments.checkpoint_trigger`: paranoid after each substantive state change; normal after a coherent lane batch; yolo only on blocker/handoff/finish. Every mode writes evidence state.
- After a primary Candidate/Validated result, evaluate one bounded evidence-fit sibling or chain before closing; do not expand a generic checklist.
- On 401/403/404/405/415 or a parser delta, select one evidence-linked bypass family or explicitly close that route.
- After three homogeneous no-information results, resolve the current action and rotate to one adjacent high-value lane.
- Before replaying a rotating form/session token, refresh it from the legitimate baseline page/session.
## Known Software Intelligence Lane
This is one specialization of the Actionable Evidence Continuation Contract:
when a concrete product/plugin/theme/library/version appears, it must not stop
at "needs CVE lookup." This also covers identified network services. Run `cd -- <repo_root_shell> && python3 tools/intel_engine.py --target <target_shell>`
and `cd -- <repo_root_shell> && python3 tools/cve_hunter.py <target_shell>`. For `next_action=run_intel`, run Intel then refresh state; for `collect_web_intel`, verify source bodies, record `tools/web_intel_artifact.py`, then rerun Intel; for `test_advisory_applicability`, add one durable action whose evidence names the advisory, component, and observed version, then test reachability/version evidence before resolving it. Start with schema-v2 OSV exact package/version, GitHub Advisory/NVD, CISA KEV, batched EPSS, local Nuclei, source status, and applicability; provider failure is blocked/handoff, never clean.
Also check NVD, GitHub Advisory, WPScan/vulnerability DB, vendor changelog, and reachability (for example, WordPress Tribe Events 6.16.3) before recording tested/dead-end/blocked/lead/signal/candidate.
## Case-State First, Not Case-State Only
If checkpoint exposes `case-state-validation` or `case-state-enrichment`, prefer
it before generic coverage gaps because actor/session/object continuity is high
value. This is not a hard rail: missing, stale, empty, or irrelevant case state
must never block discovery, browser/JS/source enrichment, surface-review hunting,
or AI-generated chain pivots. Case state is not a scope gate, permission gate,
bug-class selector, or IDOR-only workflow; AI override may pursue fresher
business-impact evidence.
Useful commands:

```bash
cd -- <repo_root_shell> && python3 tools/target_case_state.py summary --target <target_shell> --json
cd -- <repo_root_shell> && python3 tools/case_state_seed.py --target <target_shell> --json
cd -- <repo_root_shell> && python3 tools/validation_runner.py idor-actor-pair --target <target_shell> --from-case-state
```
## Evidence Runners
For repeatable replay/diff, use `docs/evidence-runners.md` and keep the AI in
charge of interpretation. Runners should preserve raw baseline/variant evidence,
diff summaries, risk/red-line status, and stop conditions; they must not convert
weak hints into findings.
Runner labels such as `tested_clean` are execution-layer labels, not final truth;
if raw evidence or business/object/role semantics contradict the label, reopen
or upgrade the lead and record why.

```bash
cd -- <repo_root_shell> && python3 tools/validation_runner.py authz-public-exposure --target <target_shell> --url <url>
cd -- <repo_root_shell> && python3 tools/validation_runner.py sqli-result-diff --target <target_shell> --url '<url>' --param q --baseline-value test --variant-value '<variant>'
cd -- <repo_root_shell> && python3 tools/evidence_ledger.py summary --target <target_shell>
```
## After `run_vuln_scan`
Rerun/read surface before declaring exhaustion. Inspect action-gated scanner leads,
including `findings/<target>/manual_review/unsafe_skipped.txt` and
`standard_public_metadata.txt`. Treat weak template hits as `lead`, stable diffs as `signal`,
and exact replay plus practical impact as `candidate`. Side-effect
scanner templates skipped unless `ALLOW_UNSAFE_HTTP_TESTS=1` was set, so they
are not tested-clean. If unresolved action-gated leads remain, checkpoint instead
of finishing.
## Next Action Consumption Loop
Checkpoint and memory queues are candidate sets, not orders:
```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell>
# normal checkpoint already synchronized the durable queue
cd -- <repo_root_shell> && python3 tools/action_queue.py next --target <target_shell>
cd -- <repo_root_shell> && python3 tools/action_queue.py summary --target <target_shell>
```
Read `recommended_executable_action`, `next_action_queue`, and the Memory action queue.
If coverage is near 0%, do not end with only a report suggestion, stale
queue item, or scanner summary; generate/execute the smallest safe evidence step
or write a precise blocker. Claude may skip, reorder, or override queue items
when browser/source/recon evidence shows a better move.
Final queue statuses are not immutable truth; reopen an item when raw evidence
or business context contradicts an earlier tested/dead-end/n/a label.
## Question -> Tool Reference (advisory, not routing)
This reference is advisory, not routing and not a state machine.

| Question | Cheap route |
|---|---|
| What surface matters most? | AI review over `/surface` evidence pack; `recon-ranker` may assist |
| JS secrets/endpoints/sinks? | `js-reader` Task + `tools/js_reader.py` |
| Candidate evidence enough? | `validator` Task + `/validate` |
| A -> B chain fit? | `chain-builder` Task |
| Report ready? | `report-writer` Task |
| Coverage hints still actionable? | `cd -- <repo_root_shell> && python3 tools/coverage_matrix.py find-gaps --target <target_shell>` |
| Same disclosed pattern? | `disclosed-researcher` Task or knowledge card source IDs |
| Recent code/changelog activity? | `tools/fresh_code.py` |
| sibling endpoints? | `tools/sibling_generator.py` |
| Blind callback needed? | `tools/oast_listen.py` |
## Deep Mode
`--deep` is a value-first comprehensive depth flag, not a checkpoint mode.
Substantive actions are actions that add, confirm, disprove, block, or record
target evidence; do not pad the run with repeated scans or cosmetic steps.
With `--max-lanes N`, choose at most N named substantive lanes in this invocation;
after lane N do not execute a newly discovered queue item. Run checkpoint (which syncs the
queue), inspect the handoff, state the remaining next action, and finish naturally.
Use `rules/hunting.md#high-intensity-hunting-posture` and the value-first
coverage model. do not lock onto authz/IDOR or any other fixed favorite class;
rotate by evidence across SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection,
unsafe deserialization, LFI/RFI/path traversal, upload/parser, OAuth/JWT/CSRF,
XSS/DOM, race/state-machine, cloud/CI/CD/secret, business logic, and known
software intelligence. Scanner-negative is only a signal to deepen manual/AI
work.
Deep Exhaustion Checklist: recon/state/surface consulted; browser/source/JS/API
context used or ruled out; scanner leads manually followed; high-value workflow
and crown-jewel hypotheses tried; coverage matrix rebuilt; Evidence Ledger /
actor matrix reviewed; unresolved actions recorded with reasons.

```bash
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py rebuild --target <target_shell>
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py find-gaps --target <target_shell>
cd -- <repo_root_shell> && python3 tools/evidence_ledger.py summary --target <target_shell>
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell>
cd -- <repo_root_shell> && python3 tools/action_queue.py summary --target <target_shell>
```
## Credential Lane
Credential testing is controlled and evidence-driven, not a default brute-force habit or absolute red line. Require a concrete login endpoint, success/failure signal, reviewed usernames, an AI-produced finite `spray-shortlist.txt`, rate/lockout discipline, input-bound dry-run, audit, and stop-on-hit. Candidate pools and login discovery are not live inputs; known usernames may skip OSINT, while inferred and confirmed identities remain separate.
If self-owned lab/authorized test account registration needs email verification, `/root/tool/aitool/zocom/mail_receiver.py` may be used as a setup aid; store only final auth headers in `.private/` or through `target_case_state.py add-session` (which writes a private reference, never header values to public case state). If hygiene is missing, record a next action instead of launching guesses or dropping the lane.
`/autopilot` may select this lane when evidence supports it; Password brute force, default credential checks, and password spray are not absolute red lines, and it
is not a requirement that every other lane fails first. Unattended live execution must carry matching `--preflight`; summaries return to the existing queue/memory/finding flow, not a new Credential state owner.
## Live-Action Boundaries
Canonical source: `rules/red-lines.md`. Never auto-submit reports. Avoid concrete
destructive, irreversible, high-pressure, persistent-payload, real-money,
permission, CI/CD, or real-business side effects unless explicitly intended in
the current turn. HTTP method alone is not the boundary: browser-observed POST,
GraphQL reads, search/filter POSTs, preview/validate-only flows, and test-owned
reversible actions can be valid evidence paths.
Red-line checks are narrow safety checks, not broad workflow blockers. Controlled
credential testing and OAST are not red lines when bounded; active stored XSS payload,
actions that change real account or permission state, or trigger CI/CD/deployment
side effects require explicit current-turn intent.
Legacy-only `--parallel`, `--max-parallel`, `--parallel-hypotheses`, `--vision`,
`--self-review`, and `--calibrate-patterns` are invalid inline; use `cd -- <repo_root_shell> && python3 agent.py --target <target_shell> ...`
for those options; baseline local-agent runs use `cd -- <repo_root_shell> && python3 tools/hunt.py --target <target_shell> --agent`.
## Finish Condition
Finish on evidence state, not a tool checklist: `working_hypothesis` is resolved, killed, blocked, or promoted to Candidate / Validated Finding.
- If `invocation_batch.bounded` reached `max_lanes`, checkpoint/sync and terminal handoff override target-exhaustion bullets below; unresolved durable actions are intentional next-invocation work.
- `oast_listen` is checked when blind/OAST testing was used.
- No unresolved high-value action-gated scanner lead remains; otherwise checkpoint instead of finishing.
- No unresolved AI-actionable high-value matrix gap remains after reviewing `cd -- <repo_root_shell> && python3 tools/coverage_matrix.py rebuild --target <target_shell>`, `cd -- <repo_root_shell> && python3 tools/coverage_matrix.py find-gaps --target <target_shell>`, checkpoint output, browser/source/JS evidence, and business context; raw matrix gaps are hints, not finish blockers, and absent or empty matrix is not proof of coverage.
- `evidence/<target>/intelligence.md`, browser, JS, source, exposure, and knowledge context were consulted when available.
- Target memory has a useful handoff when the target is not genuinely exhausted.
- A pending report is a closure asset, not a stop signal; continue hunting when stronger live evidence, browser/source leads, or high-value business workflows remain.
End with target, mode, strongest evidence, findings/candidates, blockers/dead ends, and next best action.
