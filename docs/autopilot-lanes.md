---
description: On-demand lane contracts for the inline Autopilot controller.
---

# Autopilot Lane Contracts

`commands/autopilot.md` is the controller. Read only the section named by
bootstrap `state.lane_contract.ref` (or the section matching a newly observed
evidence signal) before executing that lane. Do not load this whole file into
every invocation. Also read `State And Queue` before any substantive Queue
claim/resolve. Every lane remains subject to the controller's Scope/Auth, evidence,
checkpoint, Action Queue, loop-guard, and finish contracts.

Add a dedicated lane only when shared runners cannot express the required input,
observation, or evidence semantics and the execution is stable, repeatable, and
reusable across targets. Keep one-off target cases as bounded AI-selected evidence
actions. Ordinary Card changes do not require a new lane.

## State And Queue

- Every substantive candidate is claimed before replay with
  `python3 tools/action_queue.py claim --target <target_shell> --id <id> --metadata-json '<activation-object>'`.
  Activation records `depth_contract_version=1`, target `hypothesis_id`, open
  `family`/`technique`, selected Skill/knowledge refs, one `active_dimension`,
  `expected_learning`, `kill_condition`, `risk_tier`, and `max_hypothesis_actions`
  no greater than the stored `metadata.max_hypothesis_actions_cap`. The cap is
  Queue-owned: never submit, repair, or increase it in claim metadata. Missing cap
  requires checkpoint re-ingest; invalid cap remains for owner repair. On claim
  failure inspect stderr and stored state once, then stop without guessing/retry.
- Queue identity rejects duplicate endpoint/method/family/technique/actor/object/
  workflow/dimension work without new evidence or a recorded repeat reason.
  Runner alone writes `last_outcome`, `tested_dimensions`, replayable refs, and
  `runner_operation_id`, keeping the action `running`; `baseline_only` cannot kill.
- Resolve each action with one evidence-backed continuation (`sibling`, `bypass`,
  `identity`, `object`, `parser`, `transport`, `workflow`, `chain`, `rotation`, or
  `blocked`) or supported `kill_condition_met=true`. At most one child preserves
  parent/hypothesis/evidence lineage; independent follow-ups are separate claimed
  actions within the batch budget. Missing outcome/decision blocks closure.
- Legacy/versionless `action_queue.py add/resolve --metadata-json` accepts only a
  JSON object, preserves `next_question`, `expected_learning`, `kill_condition`,
  `pivot_hints`, and other compatible structured fields, and rejects credentials
  or authorization headers. Versioned AI metadata never fabricates Runner fields.
- Checkpoint-generated substantive items carry validated `skill_route` and
  `required_dimensions`; AI override records the replacement route/reason.
  Hand-written advisory items remain compatible without `route_required`.
- `capability-chain-review` is advisory. Materialize one normal versioned chain
  action with persisted lineage when executable; otherwise resolve blocked/dead-end.
  It never changes running, validation, candidate, report, or Closure priority.
- `wait_recon` / `wait_scan`: wait or poll, then refresh state. Runtime phase locks are the final duplicate-launch guard.
- `validate_finding`: call `/validate` only when state returns `validate_finding`. The non-TTY owner is `python3 tools/validate.py --target <target_shell> --finding-id <id> --decision-json <json_file_shell> --json`; the JSON file path is never inline.
- `resume_action_queue`: run `python3 tools/action_queue.py claim --target <target_shell>`, perform the claimed or resumed durable replay, then run `python3 tools/action_queue.py resolve --target <target_shell> --id <id> --status <state> --evidence <why>` and refresh.
- `resume_case_state`: follow `state.case_state.top_next_action`; run its redacted validation command when ready. Otherwise enrich or create the owner backlog with `tools/target_case_state.py`, write back through that owner, then refresh. If state projects `recover_hypothesis` with an empty replay command, record that bounded recovery before creating a fresh backlog; never replay the blocked runner implicitly.
- `review_validation_candidate`, `complete_report_draft`, `run_intel`, `collect_web_intel`, `test_advisory_applicability`, `review_intel_group`, and `recon_no_live_hosts` retain their owner-defined stop/write-back semantics.
- If `state.root_claim_next` exists, run `/checkpoint` so `finding_index` creates the canonical candidate and queue action, refresh, then use the canonical ID.
- Matching deterministic replay follows `docs/evidence-runners.md` and `python3 tools/validation_runner.py <lane> --target <target_shell> ...`; its first positional argument is `<lane>` and it never accepts `--decision-json`.
- `request-diff` is the shared request-pair primitive. AI supplies the exact
  baseline/variant and `active_dimension`; SQLi/NoSQLi/etc. are classifiers, not
  separate fixed-input lanes. Unsupported wire formats remain `manual_required`.
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

- Browser actions use only visible Playwright/Chrome MCP, with one active backend at a time: choose Chrome DevTools MCP for deep Network/Runtime/Console/performance work, or Playwright MCP for page interaction, authentication, and workflow capture. Choose from evidence before making any MCP call; never probe both for availability (sequentially or concurrently) because a probe may start both browsers, and never run both concurrently. Never run `agent-browser` or `playwright-cli` through Bash. First use is a harmless page-list/session probe: reuse a matching same-target session, or close stale/unrelated pages before opening a context. Retry once only for timeout, disconnect, or closed-context errors; missing/configuration/permission/protocol errors do not retry.
- After a second failure, checkpoint the blocker in the existing Action Queue, pivot to JS/source/API evidence, and probe again only next invocation, after repair, or on explicit operator retry. On success import native artifacts via `tools/browser_mcp_import.py` (`--auth-required` for authenticated captures). Missing Network/state stays partial.
- Reuse one visible browser/MCP session per invocation. Never close or switch while an authenticated or stateful workflow still depends on in-memory browser state. If unique evidence requires the other backend, switch only at a lane boundary after the current workflow is complete and its artifacts plus recoverable session references are persisted; otherwise defer that backend to the next invocation. Close the current session first, record the handoff, and open the replacement only after the close succeeds. After importing the required artifacts, call the session's native `browser_close`/equivalent before handoff, finish, or an intentional pivot; do not open a second session to replace an unclosed one. If close is unavailable or fails, record the browser session as `partial`/`blocked` and leave the next invocation to repair it.
- Use `tools/source_intel.py`/`tools/js_reader.py`; `tools/deep_js_packer.py` requires concrete runtime/chunk/source-map evidence; JS volume alone is not a trigger. Partial/unavailable stays open.

## Software And Intel

- Known software: concrete version -> `tools/intel_engine.py`; select a reachable advisory before targeted probe and refresh state. WordPress/WPScan: `knowledge/cards/wordpress-surface-intelligence.md`. Exchange/OWA/EWS/Autodiscover evidence -> `python3 tools/eburst_lane.py --target <target_shell>` for the bounded interface check; use `/spray` for reviewed credentials.
- If a concrete component/version appears, query advisory sources, map affected/fixed ranges, and record `applicability`, source failure/staleness, and route reachability separately. Do not pair default Intel with `tools/cve_hunter.py`; use `/scan-cves`, `tools/cve_scan.sh`, or that compatibility entry only after AI selects a reachable advisory.
- `review_intel_group` is an AI review handoff, not a new scanner lane. Use the bounded
  read-only query (`python3 tools/intel_artifact.py query --target <target_shell> --component <component> [--version <version>] --cursor <cursor>`)
  to page omitted advisory facts. Then add or resolve one existing `intel-advisory`
  Action Queue item with `intel_group_key` and the returned `intel_owner_binding`; use
  `tested` for reviewed/no actionable item, `dead-end`/`n/a` for dismissed, and
  `blocked` for deferred provider or evidence work. Never treat the group index alone
  as a finding or tested-clean result.

## SQL JSON And WAF

- `live/wafw00f_hits.txt` is sampled host-level context. For reviewed same-target POST/JSON run `python3 -m tools.json_inject_probe --target <target_shell> --endpoints-file <reviewed-jsonl> --no-default-seeds --max-requests <budget>`; query/form use `tools.sql_parameter_probe` with the same target and input file.
- Both share the bounded SQL matrix and baseline-relative WAF handling: defaults to four evidence-linked semantic variants and permits at most eight; no plan keeps static fallback at two. Read `poc/json_inject/summary.json`/lane summary. `429`, transport failure, block pages, and WAF observations are not findings; never spray because parameters or a WAF exist.
- Partial summaries carry an input-fingerprint cursor; rerun the lane for the untested endpoint tail. Changed fingerprints restart the snapshot. Use result-diff/sqlmap only for an evidence-backed request.

## Access Limit

- A path/proxy/framework/sibling/normalization signal may trigger a plan for any 401/403/404/405/415 access boundary; WAF is context, not a prerequisite. Run only `tools/bypass_403.sh --plan <plan> --target <target_shell> --queue` for AI-selected probes; it owns Scope/Auth/budget/method/evidence.
- Use `summary.json` and classify `blocked|edge_passed|candidate|needs_review|partial`. Budget-truncated probe IDs and `partial` must be resumed in a later plan round. No plan keeps the 64-request fallback (adjust with `--max-requests`); a status change alone is not proof.

## Workflow Timing And Case State

- When imported HAR/browser Network evidence contains at least two ordered same-target business requests, run `python3 tools/workflow_sequence.py --target <target_shell> --evidence-ref <repo-evidence-json>`. It performs one bounded remove/repeat perturbation, refreshes declared per-step tokens, writes raw traffic privately, and leaves the result in Action Queue. The runner records observed requests and response differences; the AI reviews the resulting evidence.
- When a time-shaped candidate or explicit SQL timing evidence remains after result-diff, run `python3 tools/timing_sql_runner.py --target <target_shell> --url <target-url> --param <name> --variant-value <controlled-delay>` with an explicit request cap. It interleaves baseline/variant samples and requires a stable median/MAD trend; one slow response, `429`, WAF block, or transport error stays partial.
- Case-State First, Not Case-State Only: case-state-validation and case-state-enrichment are high-value continuity, not a scope gate or bug-class selector. Stale/missing cannot block fresh evidence/AI override; use `tools/target_case_state.py`, `tools/case_state_seed.py`, and runners.

## Credentials And Asset Expansion

- Credential Lane may be selected through `skills/credential-attack/` when login value, reviewed identities, lockout/rate, shortlist, dry-run/preflight, audit, and stop-on-hit gates exist. Password brute force, default credential checks, and password spray are not mandatory last lanes; missing hygiene becomes a queued action.
- Focused fuzz (`skills/web2-recon/SKILL.md`) and DNS expansion are optional AI-selected discovery actions. DNS expansion requires a concrete naming/certificate/JS/source gap and calls `python3 tools/dns_expand.py --target <target_shell> --reason "<evidence>"`; host count alone is not a trigger. Generation/resolution/scope/merge stay tool-owned.
- Generic asset-relationship expansion is optional and evidence-triggered: use organization/brand, certificate, ASN/origin, registrant, supplier, public-source, or existing relationship evidence, or explicit intent; skip simple labs, localhost, and isolated IP/CIDR without organization evidence. Quick requires explicit intent; normal gets one pass at depth 1; deep may recurse to depth 3; full may recurse to depth 4.
- Follow only majority/control relationships, dedupe `entity_ref` (or source/entity), and stop after two empty domain levels or budget exhaustion. Use structured public sources; Chrome DevTools MCP is public/no-credential only and writes locatable `source_ref` facts. Normalize to `recon/<target-key>/exposure/asset_relation_observations.jsonl`, run `python3 tools/recon_candidates.py --target <target_shell>`, and refresh `/surface`/`/checkpoint`.
- Resolve `asset-scope-review`; only tool-derived `in_scope` is executable, while `scope-review`, `external-chain-context`, `excluded`, and `unknown` retain lossless raw evidence. FofaMap (`mcp__fofamap__*`) is one optional FOFA/Shodan adapter for a concrete coverage gap; do not call it every round or install it when missing. Future Quake/Hunter adapters use the same contract. Never send active validation requests to a returned third-party asset solely because a relationship source reported it.

## Wire And Live-Action Boundaries

- Byte-exact HTTP/cache/desync uses `tools/sender_semantics.py --require` and `tools/smuggling_executor.py --variant`; read `disposition=manual_required` as a capability handoff, not a verified smuggling result. Browser evidence cannot prove wire absence.
- Preserve unavailable credentials, off-target requests, report submission, and other execution blockers as blocked or untested, never tested-clean.
