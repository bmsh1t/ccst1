# Current Context Summary

Updated: 2026-09-01
Project: `/root/tool/ccst(rename-_Ya66f2)/ccst`

## Core Decisions

- AI is the decision controller: it prioritizes value, correlates evidence, expands attack chains, and chooses the next lane.
- Tools are deterministic executors: they enforce scope and authentication boundaries, perform requests, preserve raw evidence, and write replayable state.
- `/autopilot` is the long-running controller; `/autopilot-round` is one bounded round; `/loop` can repeat rounds. `commands/autopilot.md` is the authoritative controller contract.
- Preserve raw attack surface and raw artifacts. Filtering, ranking, request budgets, and summaries may reduce noise, but must not delete or hide raw inputs.
- Persistent control state remains split across Checkpoint, Observation Inventory, Evidence Ledger, Action Queue, and Finding lifecycle. Do not create a second state owner.

## Architecture and Key Files

- `tools/scope_context.py`: canonical target scope for domains, IPs, CIDRs, wildcards, ports, lists, manifests, and `out_of_scope` exclusions.
- `tools/autopilot_state.py`: canonical autopilot projection, closure decisions, blockers, and continuation state.
- `tools/autopilot_bootstrap.py`: compact control-plane context for a new round/session.
- `tools/checkpoint.py`: durable progress and handoff records.
- `tools/observation_inventory.py` / `tools/action_queue.py` / `tools/evidence_ledger.py`: observations, executable next actions, and evidence ownership.
- `tools/recon_engine.sh`: baseline reconnaissance and artifact production.
- `tools/vuln_scanner.sh`: bounded Nuclei and passive candidate extraction with explicit residual accounting; it does not provide fixed payload sweeps.
- `tools/validation_runner.py`, `tools/workflow_sequence.py`, and `tools/timing_sql_runner.py`: optional deterministic evidence/replay primitives selected by AI when their contracts fit.
- `tools/oast_listen.py`: listener lifecycle and callback correlation only; test inputs remain AI-selected.
- `tools/deep_js_packer.py`, `tools/source_intel.py`, `tools/js_reader.py`: JS and Source Map evidence lanes.
- `tools/browser_mcp_import.py` / `tools/vision_browser.py`: independent browser evidence import and inspection.
- `tools/takeover_scanner.sh` / `tools/analyze_takeover_findings.py`: takeover candidates and evidence only.

## Completed Capabilities

- Recon covers assets, DNS, HTTP/WAF, URLs, JS/API, OpenAPI, cloud, identity, and CI/CD signals.
- Passive discovery sources are merged with atomic artifacts; optional DNS permutation, deep JS, browser, Source Map, and takeover lanes are evidence-triggered rather than forced into baseline Recon.
- Related-company/subsidiary and supply-chain leads can be retained as context. Only in-scope assets are actively requested; third-party, CDN, OAuth, webhook, GitHub/Docker, and similar relations remain leads unless explicitly in scope.
- AI selects target-observed request shapes and test inputs for SQL/JSON/WAF and uses browser, curl, raw sender, or an optional canonical runner; no fixed matrix or encoder plan is required.
- Nuclei remains useful for explicitly selected product/CVE templates and bounded breadth context. Scanner-negative and candidate-only output never establish completion.
- WAF responses are advisory context. Any representation change is an AI-selected, target-evidence-bound request with the existing Scope/Auth, rate, red-line, and evidence rules.
- Takeover stops at DNS/CNAME chain, provider fingerprint, HTTP evidence, false-positive state, and Action Queue candidate. Final provider claim/ownership verification stays manual.
- Shuji is used for Source Map source recovery. There is no generic AST or arbitrary deobfuscation framework.
- Large URL/inventory handling uses lossless raw artifacts, exact identity, bounded ranking, summaries, cursors, and cached projections; scanner input selection is bounded without shrinking the stored attack surface.
- Agent policy is documented in root `AGENTS.md`: ordinary subagents use the global default profile; Trellis roles are explicit exceptions; project dispatch remains inline.

## Verification Baseline

- Last recorded full test baseline: `3546 passed` (Wave 9, 2026-09-01).
- `knowledge_audit.py --strict`: passed.
- `runtime_doctor.py --fail-on-drift`: drift `0`.
- Recent policy checks and `git diff --check`: passed.
- Wave 8 activity documents and Claude runtime are synchronized; Wave 9 local fixture and full quality gates passed.

## Remaining or Deferred

- Continue the planned ten-change observation period for Skill/Knowledge/Rules-only maintenance ratio; do not manufacture commits to satisfy the metric.
- No new implementation gap was introduced by Wave 0-9; preserve existing owner and heartbeat contracts rather than adding a parallel state system.
- Deferred by explicit decision: generic AST/arbitrary deobfuscation, low-level HTTP/2 desync packet generation, generic fully automated OAuth login orchestration, and automatic takeover claim/ownership proof.
- No need to add a second browser queue, force DNS/takeover into baseline Recon, or turn `.trellis/`, `.codex/`, or `AGENTS.md` into application functionality.

## Non-Negotiable Constraints

- Capability and coverage take priority over token reduction.
- Never optimize by dropping raw URLs, long-tail findings, failure semantics, authentication boundaries, or state closure.
- Keep AI reasoning for judgment and expansion; keep network execution, scope, evidence, and replay deterministic and fail-closed.
- Reuse existing helpers and state projections before adding abstractions or dependencies.
- Keep optional specialist lanes evidence-triggered and bounded; do not silently convert candidates into verified findings.
- Run a focused validation for every non-trivial change and inspect the final diff for scope regressions, duplicate state owners, hidden fallbacks, and unrelated edits.
