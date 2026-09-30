---
description: On-demand lane contracts for the inline Autopilot controller.
---

# Autopilot Lane Contracts

`commands/autopilot.md` is the controller. The bootstrap `state.lane_contract`
already inlines the selected section's text when `text_available=true` — use
that inline text directly. Only when it is not inlined (or when a newly
observed evidence signal selects a different section) read that one section
from this file, named by the bootstrap `state.lane_contract.ref`. Do not load
this whole file into every invocation. Also read `State And Queue` before any
substantive Queue claim/resolve. Every lane remains subject to the
controller's Scope/Auth, evidence, checkpoint, Action Queue, loop-guard, and
finish contracts.

Add a dedicated lane only when shared runners cannot express the required input,
observation, or evidence semantics and the execution is stable, repeatable, and
reusable across targets. Keep one-off target cases as bounded AI-selected evidence
actions. Ordinary Card changes do not require a new lane.

## Inline Specialist Propagation

The supported Claude inline delegation path receives mode and budget from the
same bootstrap object as the controller. Every specialist handoff includes the
literal values `arguments.deep` and `invocation_batch.bounded`,
`invocation_batch.max_lanes`, and `invocation_batch.handoff`; specialists do not
reparse slash-command text or infer a mode from the objective. For
`arguments.deep=true`, include the label `DEEP HUNT MODE` and apply the
value-first comprehensive-depth contract to the assigned lane while preserving
the controller's `max_lanes` boundary. For `arguments.deep=false`, keep normal
depth. A specialist reports its effective mode and batch boundary; the inline
controller alone claims lanes, writes owner state, and decides closure.

### Handoff Content Pack (mandatory)

Mode/budget propagation alone does not make a specialist effective: a
sub-agent sees only the dispatch text, not the controller's conversation.
Every dispatch description must therefore carry a content pack:

- **已完成 (done so far)**: a compact summary of confirmed facts for this
  target — enumerated subdomains/ports, confirmed URLs, known hypotheses and
  their status, relevant evidence refs. Read these from target memory facts
  and Store-backed evidence views instead of re-deriving them.
- **本轮只做 (this round only)**: the single sub-goal, plus an explicit
  no-repeat boundary — e.g. "do not re-run full subdomain enumeration;
  only probe the three new hosts listed". Incremental work names its delta.
- **证据指针与格式**: evidence file paths with the expected read shape
  (JSON key, line range, or summary), and for any image/captcha input the
  absolute path plus the expected output format. A specialist cannot see the
  controller's tool outputs; pointers must be self-describing.
- **专家匹配理由**: one sentence why this specialist (not another lane)
  fits the sub-goal, so a mismatched dispatch is reviewable.

Pre-dispatch completeness check: if the target identifier or the test scope
is missing from what the specialist would receive, the dispatch is forbidden —
ask the user or collect the evidence first instead of delegating an
under-specified task.

Specialists without owner-write access end their report with a structured
「待落库」 tail (fact key, summary, evidence refs, suggested owner action);
the controller writes each entry back immediately through the existing
Store commands (`target_memory.py fact/lead/next`, Action Queue, native evidence registration)
before starting the next lane. The controller does not assume the specialist
already recorded anything.

## State And Queue

All ordinary domain commands require an explicitly initialized target Store.
`hunt.py` initializes a new target before execution; other callers use
`python3 tools/target_store.py init --store --target <target_shell>` explicitly.
Legacy data needs explicit import; missing/fenced/damaged state needs recovery.
Checkpoint, Pickup and preflight never initialize, import, or recreate old owners.

- Already-executed browser/native/multi-step evidence uses
  `validation_runner.py record-evidence` with an existing Finding and explicit
  attempt ID. It sends no requests. Raw material and its private exact request
  identity are published before one Store operation registers observations and
  links. Registration retry uses the saved attempt/material; a real rerun needs
  a new attempt. Unknown family remains intact.
- AI selects work. `action_queue.py claim --target <target_shell> --id <id>`
  requires an explicit ID; metadata may describe the judgment but cannot forge
  execution fields, change identity without a repeat reason, or carry credentials.
  `--from-evidence` and automatic Skill routes are retired. The Store enforces
  claim/CAS, execution-key conflicts, evidence ownership and completion proof.
- Action Queue is a thin Store adapter. List is read-only; completion is an
  explicit resolve with a claim-bound operation, registered artifact, or domain
  command receipt. Runner registration and report generation never complete it.
  Non-HTTP review work uses a concrete subject without invented endpoint/family.
- Already-claimed work remains visible for recovery. Pending actions have a
  bounded stable-ID page, exact remaining count and expansion command. Coverage,
  raw claims, scanner/source material and actor gaps remain separate evidence;
  Checkpoint does not turn them into actions or choose a new route.
- New follow-ups require explicit actions. Conditional primitives, negative
  results and next intent go through Experience commands with their conditions
  and evidence; neither recall nor Checkpoint generates chains automatically.
- `wait_recon` / `wait_scan` reflect live phase locks. Wait or poll, then refresh;
  locks remain the duplicate-launch guard.
- `/validate` reads a complete decision through
  `python3 tools/validate.py --target <target_shell> --finding-id <id> --decision-json <json_file_shell> --json`.
  Scaffold and preflight are read-only. Validation publishes AI report text,
  records separate technical/destination judgments and registers eligible reports.
  Same-decision retry retains the bytes; a revised decision needs current
  predecessor IDs and a new report path. `/report` consumes the registered body.
- Read state once per iteration and expand only the missing evidence. Refresh
  after a domain mutation; a prior revision cannot authorize current delivery.
- Case contains actors, sessions, objects and current premises. It has no second
  queue or automatic replay. Missing context limits that comparison only; AI can
  select other work. Use `target_case_state.py` to save the needed context.
- Raw root claims do not become Findings merely by reading Checkpoint. Explicit
  scanner-material registration creates immutable review work; AI creates a
  concrete Finding when its target/endpoint/method/family are known.
- Matching deterministic replay follows `docs/evidence-runners.md` and `python3 tools/validation_runner.py <lane> --target <target_shell> ...`; its first positional argument is `<lane>` and it never accepts `--decision-json`.
- `request-diff` is the shared request-pair primitive. AI supplies the exact
  baseline/variant and `active_dimension`; SQLi/NoSQLi/etc. are classifiers, not
  separate fixed-input lanes. Unsupported wire formats remain `manual_required`.
- `request-diff` is optional. Claude chooses browser, native HTTP, MCP or an
  existing runner to fit the experiment; comparisons are not forced into a
  same-method pair. Retain raw evidence and use the existing owner interfaces.
  Undeclared or unmet expectations stay candidates, not automatic clean results.
- Explicitly state-changing Scanner probes, currently the retained HTTP method
  tampering check, require `ALLOW_UNSAFE_HTTP_TESTS=1`. Without that opt-in the
  request is skipped and recorded in `manual_review/unsafe_skipped.txt`; the
  resulting review item is not a clean result. HTTP method names alone do not
  classify every probe as state-changing.
- For a readable text list or schema-v1 JSON Scope manifest, run batch recon only for `run_batch_recon`; never scan the list/manifest file itself. Stop on `invalid_batch_target` or `batch_failed`. For one completed `in_scope` asset, run `python3 tools/autopilot_continuation.py create --parent-target <scope_ref> --selected-target <domain> [--auth-file <auth_file_shell>]`, then invoke `/autopilot <domain> --context-file=<returned-path>`; bootstrap validates the parent `scope_ref/scope_hash` before target I/O. Unlisted discovery remains context/review, and `out_of_scope` always wins.

## Recon And Surface

- `run_recon`: execute directly from this lane. When
  `state.recon.cidr_continuation.status=pending`, continue once with
  `BBHUNT_CIDR_OFFSET=<next_offset> python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --recon-only`; otherwise omit the offset. Append `arguments.recon_flags` exactly. Never restart a pending CIDR at zero or discard prior pages. If `state.dir_fuzz_rotation.pending=true`, rerun the same bounded Recon so its FFUF target ledger advances to the next live services; `live/urls.txt` remains the complete source.
- Before a breadth helper, inspect `tools/surface.py`, `tools/context_pack.py`, and `tools/observation_inventory.py summary` when a usable cache exists. A later breadth pass is `python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --scan-only --quick`.
- General Nuclei breadth is origin-deduplicated and capped at 50/100/200 targets for quick/standard/full (`BB_NUCLEI_MAX_TARGETS` overrides); `summary.json` records available and selected origin counts. Long-tail paths, components, and CVEs require a reviewed evidence-backed list.
- `prepare_surface_context`: run one explicit `python3 tools/surface.py --target <target_shell> --refresh`, verify its bounded projection, load context, then refresh state.
- `collect_candidate_evidence`: consume `state.structured_next.rubric.next_actions`, or a reviewed `state.memory_candidate_next` locatable `evidence_ref`; preserve `missing_labels` and refresh. Prose or `raw_endpoint` alone is not evidence.
- Observation top-K and `remaining` are attention windows, not closure; use `/observations` for evidence-driven long-tail review.
- Before unusual helpers, scan `docs/tool-index.md` once. Canonical contracts are `skills/runtime-protocol.md`, `rules/coverage-gate.md`, `rules/hunting.md`, `rules/tool-ai-boundary.md`, `rules/web-intel.md`, `knowledge/index.md`, `tools/checkpoint.py`, `tools/action_queue.py`, `tools/coverage_matrix.py`, `tools/evidence_ledger.py`, and `docs/evidence-runners.md`.

## Browser Source And JS

- Browser actions use only visible Playwright/Chrome MCP when available, with one active backend at a time: choose Chrome DevTools MCP for deep Network/Runtime/Console/performance work, or Playwright MCP for page interaction, authentication, and workflow capture. If neither backend is usable, capture one target-owned page with `python3 tools/browser_playwright_fallback.py --target <target_shell> --url <seed_url>`; it uses the installed Python Playwright package and never installs a browser. Choose from evidence before making any MCP call; never probe both for availability (sequentially or concurrently) because a probe may start both browsers, and never run both concurrently. Never run `agent-browser` or `playwright-cli` through Bash. First use is a harmless page-list/session probe: reuse a matching same-target session, or close stale/unrelated pages before opening a context. Retry once only for timeout, disconnect, or closed-context errors; missing/configuration/permission/protocol errors do not retry.
- After a second failure, checkpoint the blocker in the existing Action Queue, pivot to JS/source/API evidence, and probe again only next invocation, after repair, or on explicit operator retry. On success import native artifacts via `tools/browser_mcp_import.py` (`--auth-required` for authenticated captures). Missing Network/state stays partial.
- Reuse one visible browser/MCP session per invocation. Never close or switch while an authenticated or stateful workflow still depends on in-memory browser state. If unique evidence requires the other backend, switch only at a lane boundary after the current workflow is complete and its artifacts plus recoverable session references are persisted; otherwise defer that backend to the next invocation. Close the current session first, record the handoff, and open the replacement only after the close succeeds. After importing the required artifacts, call the session's native `browser_close`/equivalent before handoff, finish, or an intentional pivot; do not open a second session to replace an unclosed one. If close is unavailable or fails, record the browser session as `partial`/`blocked` and leave the next invocation to repair it.
- When a browser round lane finishes with the focused capture manifest as its
  `evidence_ref` (`evidence/<target_key>/browser/pending-import-manifest.json`
  with a `{"captures": [...]}` body), `python3 tools/checkpoint.py
  --record-round-lane-result` auto-imports that manifest through the
  `browser_mcp_import` owner function - the AI does not need to remember a
  separate importer call. The import result is recorded on the lane heartbeat
  (`browser_import`); import failure is a lane warning (`status: failed` with
  reason), never a heartbeat failure. An `already_recorded` replay never
  re-imports; manual `--focused-manifest` runs remain available for
  non-round-lane imports.
- Read exact source/JS artifacts with Claude native Read/Grep or bounded delegation.
  Raw observations do not create Queue work; only an explicit owner claim does.
  `tools/deep_js_packer.py` requires concrete runtime/chunk/source-map evidence;
  JS volume alone is not a trigger. Partial/unavailable stays open.


## Software And Intel

- Known software: concrete version -> `tools/intel_engine.py`; select a reachable advisory before targeted probe and refresh state. WordPress/WPScan: `knowledge/cards/wordpress-surface-intelligence.md`. Exchange/OWA/EWS/Autodiscover evidence -> `python3 tools/eburst_lane.py --target <target_shell>` for the bounded interface check; use `/spray` for reviewed credentials.
- If a concrete component/version appears, query advisory sources, map affected/fixed ranges, and record `applicability`, source failure/staleness, and route reachability separately. Do not pair default Intel with a broad CVE sweep; use `/scan-cves` or `tools/cve_scan.sh` only after AI selects a reachable advisory.
- `review_intel_group` is an AI review handoff, not a new scanner lane. Use the bounded
  read-only query (`python3 tools/intel_artifact.py query --target <target_shell> --component <component> [--version <version>] --cursor <cursor>`)
  to page omitted advisory facts. Then add or resolve one existing `intel-advisory`
  Action Queue item with `intel_group_key` and the returned `intel_owner_binding`; use
  `tested` for reviewed/no actionable item, `dead-end`/`n/a` for dismissed, and
  `blocked` for deferred provider or evidence work. Never treat the group index alone
  as a finding or tested-clean result.

## SQL JSON And WAF

- `live/wafw00f_hits.txt` is sampled host-level context. AI chooses the target-observed POST/JSON/query/form shape and exact test input, then uses browser/MCP/curl/raw sender directly.
- Use `validation_runner.py request-diff` only for an exact same-method, one-dimension HTTP pair that benefits from stable replay, response diff, and canonical evidence. Time-shaped candidates use AI interleaved sampling with a stable median/MAD trend. `429`, transport failure, block pages, and WAF observations are not findings; never run a fixed matrix merely because parameters or a WAF exist.
- Direct or browser evidence that does not fit request-diff remains raw evidence or a target-owned `finding_claim` until ready; explicitly persist the Candidate through `TargetStore.create_finding` and use `record-evidence` for formal validation. Checkpoint only reads the saved state.

## Access Limit

- A path/proxy/framework/sibling/normalization signal may trigger an AI-selected exact request for any 401/403/404/405/415 access boundary; WAF is context, not a prerequisite. Execute through browser/curl/raw sender, and use `validation_runner.py request-diff` only when its one-dimension contract fits. Preserve raw evidence; AI submits technical and delivery judgments through `/validate`. A status change alone is not proof.
- Invoke setup helpers on demand: `/root/tool/aitool/zocom/mail_receiver.py` (environment-provided helper, not part of this repo) for self-owned test-account email verification, or `tools/cf_solver.py` for Cloudflare clearance. Persist results through private AuthSession/Case State and keep failures `blocked`/`partial`.

## Workflow Timing And Case State

- When imported HAR/browser Network evidence contains at least two ordered same-target business requests, the AI replays the flow with one bounded remove/repeat perturbation per step, refreshing short-lived tokens observed in the flow, and preserves raw traffic as private evidence; a response difference stays a candidate until AI reviews impact and replayability.
- When a time-shaped candidate or explicit SQL timing evidence remains after result-diff, the AI runs interleaved baseline/variant samples with an explicit request cap and requires a stable median/MAD trend; one slow response, `429`, WAF block, or transport error stays partial.
- Case-State First, Not Case-State Only: `case-state-enrichment` (the actor/session/object context a role-differential test still lacks) is high-value continuity, not a scope gate or bug-class selector. Case State carries context only — no backlog and no route score — so stale/missing case state cannot block fresh evidence/AI override; use `tools/target_case_state.py`, and the action source for actionable work.

## Credentials And Asset Expansion

- A real login form (including admin/back-office) routes to the bounded baseline policy in `skills/credential-attack/SKILL.md`; that Skill owns default/common weak-password checks and the stable-account exception. The baseline is preparation-only; default/common weak-password checks and password spray are not mandatory last lanes. Credential Lane may be selected for live work only when login value, observed protocol/signals, lockout/rate controls, dry-run/preflight, audit, and stop-on-hit gates exist.
- Focused fuzz (`skills/web2-recon/SKILL.md`) and DNS expansion are optional AI-selected discovery actions. DNS expansion requires a concrete naming/certificate/JS/source gap and calls `python3 tools/dns_expand.py --target <target_shell> --reason "<evidence>"`; host count alone is not a trigger. Generation/resolution/scope/merge stay tool-owned.
- Generic asset-relationship expansion is optional and evidence-triggered: use organization/brand, certificate, ASN/origin, registrant, supplier, public-source, or existing relationship evidence, or explicit intent; skip simple labs, localhost, and isolated IP/CIDR without organization evidence. Quick requires explicit intent; normal performs one pass with depth 1; deep may recurse to depth 3; full may recurse to depth 4.
- Follow only majority/control relationships, dedupe `entity_ref` (or source/entity), and stop after two empty domain levels or budget exhaustion. Use structured public sources; Chrome DevTools MCP is public/no-credential only and writes locatable `source_ref` facts. Normalize to `recon/<target-key>/exposure/asset_relation_observations.jsonl`, run `python3 tools/recon_candidates.py --target <target_shell>`, and refresh `/surface`/`/checkpoint`.
- Relation candidates are AI-routed from the bounded `value`, `asset_type`, `relation`, `related`, `signals`, `sources`, `source_refs`, `confidence`, and `scope_status` fields. Return one `related`, `uncertain`, or `unrelated` decision with a short evidence-based `reason` and bounded `source_refs`; related only raises priority, uncertain stays passive, and unrelated is omitted from active Context/Surface/Queue/Coverage/Closure. This decision never changes Scope; only existing `in_scope` is executable. Keep raw observations for audit and rebuild.
- A third-party-hosted host or service with multiple page, behavioral, or brand evidence points tying it to the target organization is a first-class ownership signal: record it as `confidence: high` with multiple `sources` so it routes to `scope-review` and gets a forced decision, rather than leaving it as passive context. Ownership evidence never expands authorization; only an explicit target set makes the asset testable.
- Resolve `asset-scope-review`; only tool-derived `in_scope` is executable, while `scope-review`, `external-chain-context`, `excluded`, and `unknown` retain lossless raw evidence. FofaMap (`mcp__fofamap__*`) is one optional FOFA/Shodan adapter for a concrete coverage gap; do not call it every round or install it when missing. Future Quake/Hunter adapters use the same contract. Never send active validation requests to a returned third-party asset solely because a relationship source reported it.

## Wire And Live-Action Boundaries

- Byte-exact HTTP/cache/desync gates the sender with `tools/sender_semantics.py --require`; an unsupported sender capability is a handoff, not a verified smuggling result. Browser evidence cannot prove wire absence.
- Preserve unavailable credentials, off-target requests, report submission, and other execution blockers as blocked or untested, never tested-clean.
