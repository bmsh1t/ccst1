---
description: On-demand lane contracts for the inline Autopilot controller.
---

# Autopilot Lane Contracts

`commands/autopilot.md` is the controller. Read only the section named by
bootstrap `state.lane_contract.ref` (or the section matching a newly observed
evidence signal) before executing that lane. Do not load this whole file into
every invocation. Every lane remains subject to the controller's Scope/Auth,
evidence, checkpoint, Action Queue, loop-guard, and finish contracts.

## State And Queue

- `run_recon`: when `state.recon.cidr_continuation.status=pending`, continue once with
  `BBHUNT_CIDR_OFFSET=<next_offset> python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --recon-only`; otherwise omit the offset. Keep exact recon flags; never restart a pending CIDR at zero or discard prior pages. If `state.dir_fuzz_rotation.pending=true`, rerun the same bounded Recon so its FFUF target ledger advances to the next live services; `live/urls.txt` remains the complete source.
- `wait_recon` / `wait_scan`: wait or poll, then refresh state. Runtime phase locks are the final duplicate-launch guard.
- `validate_finding`: call `/validate` only when state returns `validate_finding`. The non-TTY owner is `python3 tools/validate.py --target <target_shell> --finding-id <id> --decision-json <json_file_shell> --json`; the JSON file path is never inline.
- `resume_action_queue`: run `python3 tools/action_queue.py claim --target <target_shell>`, perform the claimed or resumed durable replay, then run `python3 tools/action_queue.py resolve --target <target_shell> --id <id> --status <state> --evidence <why>` and refresh.
- `resume_case_state`: follow `state.case_state.top_next_action`; run its redacted validation command when ready. Otherwise enrich or create the owner backlog with `tools/target_case_state.py`, write back through that owner, then refresh.
- `review_validation_candidate`, `complete_report_draft`, `run_intel`, `collect_web_intel`, `test_advisory_applicability`, and `recon_no_live_hosts` retain their owner-defined stop/write-back semantics.
- If `state.root_claim_next` exists, run `/checkpoint` so `finding_index` creates the canonical candidate and queue action, refresh, then use the canonical ID.
- Matching deterministic replay follows `docs/evidence-runners.md` and `python3 tools/validation_runner.py <lane> --target <target_shell> ...`; its first positional argument is `<lane>` and it never accepts `--decision-json`.
- For a readable text list or schema-v1 JSON Scope manifest, run batch recon only for `run_batch_recon`; never scan the list/manifest file itself. Stop on `invalid_batch_target` or `batch_failed`; otherwise select one completed `in_scope` asset, preserve bootstrap `scope_ref/scope_hash`, and rerun `autopilot_state.py --target <domain> --bounded`. Unlisted discovery remains context/review, and `out_of_scope` always wins.

## Recon And Surface

- Before a breadth helper, inspect `tools/surface.py`, `tools/context_pack.py`, and `tools/observation_inventory.py summary` when a usable cache exists. A later breadth pass is `python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --scan-only --quick`.
- `prepare_surface_context`: run one explicit `python3 tools/surface.py --target <target_shell> --refresh`, verify its bounded projection, load context, then refresh state.
- `collect_candidate_evidence`: consume `state.structured_next.rubric.next_actions`, or a reviewed `state.memory_candidate_next` locatable `evidence_ref`; preserve `missing_labels` and refresh. Prose or `raw_endpoint` alone is not evidence.
- Before unusual helpers, scan `docs/tool-index.md` once. Canonical contracts are `skills/runtime-protocol.md`, `rules/red-lines.md`, `rules/coverage-gate.md`, `rules/hunting.md`, `rules/tool-ai-boundary.md`, `rules/web-intel.md`, `knowledge/index.md`, `tools/checkpoint.py`, `tools/action_queue.py`, `tools/coverage_matrix.py`, `tools/evidence_ledger.py`, and `docs/evidence-runners.md`.

## Browser Source And JS

- Browser actions use only visible Playwright/Chrome MCP. Never run `agent-browser` or `playwright-cli` through Bash. First use is a harmless page-list/session probe; retry once only for timeout, disconnect, or closed-context errors. Missing/configuration/permission/protocol errors do not retry.
- After a second failure, checkpoint the blocker in the existing Action Queue, pivot to JS/source/API evidence, and probe again only next invocation, after repair, or on explicit operator retry. On success import native artifacts via `tools/browser_mcp_import.py` (`--auth-required` for authenticated captures). Missing Network/state stays partial.
- Use `tools/source_intel.py`/`tools/js_reader.py`; `tools/deep_js_packer.py` requires concrete runtime/chunk/source-map evidence; JS volume alone is not a trigger. Partial/unavailable stays open.

## Software And Intel

- Known software: concrete version -> `tools/intel_engine.py`; select a reachable advisory before targeted probe and refresh state. WordPress/WPScan: `knowledge/cards/wordpress-surface-intelligence.md`. Exchange/OWA/EWS/Autodiscover evidence -> `python3 tools/eburst_lane.py --target <target_shell>` for the bounded interface check; use `/spray` for reviewed credentials.
- If a concrete component/version appears, query advisory sources, map affected/fixed ranges, and record `applicability`, source failure/staleness, and route reachability separately. Do not pair default Intel with `tools/cve_hunter.py`; use `/scan-cves`, `tools/cve_scan.sh`, or that compatibility entry only after AI selects a reachable advisory.

## SQL JSON And WAF

- `live/wafw00f_hits.txt` is sampled host-level context. For reviewed same-target POST/JSON run `python3 -m tools.json_inject_probe --target <target_shell> --endpoints-file <reviewed-jsonl> --no-default-seeds --max-requests <budget>`; query/form use `tools.sql_parameter_probe` with the same target and input file.
- Both share the bounded SQL matrix and baseline-relative WAF handling: defaults to four evidence-linked semantic variants and permits at most eight; no plan keeps static fallback at two. Read `poc/json_inject/summary.json`/lane summary. `429`, transport failure, block pages, and WAF observations are not findings; never spray because parameters or a WAF exist.
- Partial summaries carry an input-fingerprint cursor; rerun the lane for the untested endpoint tail. Changed fingerprints restart the snapshot. Use result-diff/sqlmap only for an evidence-backed request.

## Access Limit

- A path/proxy/framework/sibling/normalization signal may trigger a plan for any 401/403/404/405/415 access boundary; WAF is context, not a prerequisite. Run only `tools/bypass_403.sh --plan <plan> --target <target_shell> --queue` for AI-selected probes; it owns Scope/Auth/budget/method/evidence.
- Use `summary.json` and classify `blocked|edge_passed|candidate|needs_review|partial`. Budget-truncated probe IDs and `partial` must be resumed in a later plan round. No plan keeps the 64-request fallback (adjust with `--max-requests`); a status change alone is not proof.

## Workflow Timing And Case State

- When imported HAR/browser Network evidence contains at least two ordered same-target business requests, run `python3 tools/workflow_sequence.py --target <target_shell> --evidence-ref <repo-evidence-json>`. It performs one bounded remove/repeat perturbation, refreshes declared per-step tokens, writes raw traffic privately, and leaves the result in Action Queue. Mutation/unknown steps remain `manual_required` unless the current turn supplies the red-line flag.
- When a time-shaped candidate or explicit SQL timing evidence remains after result-diff, run `python3 tools/timing_sql_runner.py --target <target_shell> --url <target-url> --param <name> --variant-value <controlled-delay>` with an explicit request cap. It interleaves baseline/variant samples and requires a stable median/MAD trend; one slow response, `429`, WAF block, or transport error stays partial.
- Case-State First, Not Case-State Only: case-state-validation and case-state-enrichment are high-value continuity, not a scope gate or bug-class selector. Stale/missing cannot block fresh evidence/AI override; use `tools/target_case_state.py`, `tools/case_state_seed.py`, and runners.

## Credentials And Asset Expansion

- Credential Lane may be selected when login value, reviewed identities, lockout/rate, shortlist, dry-run/preflight, audit, and stop-on-hit gates exist. Password brute force, default credential checks, and password spray are not mandatory last lanes; missing hygiene becomes a queued action.
- Focused fuzz and DNS expansion are optional AI-selected discovery actions. DNS expansion requires a concrete naming/certificate/JS/source gap and calls `python3 tools/dns_expand.py --target <target_shell> --reason "<evidence>"`; host count alone is not a trigger. Generation/resolution/scope/merge stay tool-owned.
- Generic asset-relationship expansion is optional and evidence-triggered: use organization/brand, certificate, ASN/origin, registrant, supplier, public-source, or existing relationship evidence, or explicit intent; skip simple labs, localhost, and isolated IP/CIDR without organization evidence. Quick requires explicit intent; normal gets one pass at depth 1; deep may recurse to depth 3; full may recurse to depth 4.
- Follow only majority/control relationships, dedupe `entity_ref` (or source/entity), and stop after two empty domain levels or budget exhaustion. Use structured public sources; Chrome DevTools MCP is public/no-credential only and writes locatable `source_ref` facts. Normalize to `recon/<target-key>/exposure/asset_relation_observations.jsonl`, run `python3 tools/recon_candidates.py --target <target_shell>`, and refresh `/surface`/`/checkpoint`.
- Resolve `asset-scope-review`; only tool-derived `in_scope` is executable, while `scope-review`, `external-chain-context`, `excluded`, and `unknown` retain lossless raw evidence. FofaMap (`mcp__fofamap__*`) is one optional FOFA/Shodan adapter for a concrete coverage gap; do not call it every round or install it when missing. Future Quake/Hunter adapters use the same contract. Never send active validation requests to a returned third-party asset solely because a relationship source reported it.

## Wire And Live-Action Boundaries

- Byte-exact HTTP/cache/desync uses `tools/sender_semantics.py --require` and `tools/smuggling_executor.py --variant`; read `disposition=manual_required` as a capability handoff, not a verified smuggling result. Browser evidence cannot prove wire absence.
- `rules/red-lines.md` is canonical. Red-line checks are narrow side-effect checks, not authorization or ownership gates. A current-turn request that names an action supplies its opt-in. Pause for ambiguous target, missing required credentials, new off-set target, report submission, or concrete irreversible/high-pressure side effects.
