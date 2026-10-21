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
{"schema_version":3,"paths":[{"kind":"commands","relative_path":"autopilot.md"},{"kind":"commands","relative_path":"autopilot-round.md"},{"kind":"skills","relative_path":"runtime-protocol.md"},{"kind":"skills","relative_path":"src-hunter/SKILL.md"},{"kind":"skills","relative_path":"src-hunter/modules/web2-recon.md"},{"kind":"skills","relative_path":"src-hunter/modules/triage-validation.md"},{"kind":"skills","relative_path":"src-hunter/modules/report-writing.md"},{"kind":"skills","relative_path":"src-hunter/知识库/README.md"},{"kind":"skills","relative_path":"src-hunter/知识库/打穿短表.md"}],"mcp_contracts":["mcp__Playwright__*","mcp__chrome-devtools__*","mcp__fofamap__*"]}
AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->
Authoritative bootstrap contract (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep [--max-lanes N]] [--auth-file PATH] [--context-file=PATH]`.

## Shared Automation
Round hooks only for `/autopilot-round`.

### Startup And Recovery
Only fresh Bootstrap `action=continue` acts; else request target/report error.
Critical drift: confirm `/sync-check`; no auto-sync/install.
Use `cd -- <repo_root_shell> &&`, `arguments.target_shell`, optional
`--auth-file <arguments.auth_file_shell>` and exact `arguments.seed_url`.
Retain `--context-file <arguments.context_file_shell>` when present (also in
`arguments.hunt_auth_flags`). Unsupported executor: never drop context; use the
continuation-aware HTTP boundary in `docs/autopilot-lanes.md#recon-and-surface`.
At start/target change/resume/compaction, read/apply complete
`skills/runtime-protocol.md#shared-memory-continuity`. Check inherited judgments against current commands,
not all source; unchecked = inherited/unverified.
On demand: `skills/src-hunter/SKILL.md`. Do not loop `/hunt`.
Before hunting apply `rules/ccst/hunting.md`; before network use `config.json.resin` via
`docs/resin-proxy.md` in the same shell. Never output secrets/persist proxy setup.
Only session-visible MCP; presence is not readiness. Missing/failed stays partial/blocked;
no failed source/tool retries this invocation.
Session owns claims/writes/closure. Default zero specialists; delegate per
`docs/autopilot-lanes.md#inline-specialist-propagation`; `recon-ranker` optional/read-only.
Reuse `state.lane_contract` at `text_available=true`; otherwise/new selection read that section in
`docs/autopilot-lanes.md`.

### State Consumption Loop
1. Consume Bootstrap `state`, then fresh `control`; obey `state.hard_gate`. Missing/stale/partial
   is not clean. `wait_recon`/`wait_scan`: poll lock and refresh, never duplicate-launch.
2. AI selects `owner_continuations`; order is advisory; respect `runnable=false`.
   Read selected evidence/owner contracts before execution; retain deferred work.
   `handoff` returns to `src-hunter`; inventory/residuals never mandate Recon/Checkpoint.
3. Round: claim per Round Mechanics before any action, including Recon or validation.
   A missing-round refusal requires prepare followed by a fresh lane claim with `allowed=true`;
   prepare alone never authorizes execution. Report claims bind the selected Finding/assessment/delivery.
4. Execute once. Selected `run_recon`: `arguments.recon_flags` plus full-state/cursor contract
   in `docs/autopilot-lanes.md#recon-and-surface`; otherwise the selected lane.
   Before Action-bound execution read
   `docs/autopilot-lanes.md#state-and-queue` and `docs/evidence-runners.md#绑定已认领行动`;
   Claim/bind with the same explicit `--actor OPERATOR`.
   Failed claim: inspect once; never guess/retry.
5. Register/resolve/kill as applicable; require actual receipts. Missing outcomes stay recoverable;
   never replay unknown effects. No Finding: `record-observation` per
   `docs/evidence-runners.md#native-observation-registration`; existing Candidate: `record-evidence`.
6. Round terminal heartbeat first; then exactly one post-lane refresh:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json
```
Use fresh `control`; re-read only after owner writes. Failed reads stop stale work; recover.
`loop_guard.repetition_facts` is advisory, not above gates/claims. Decide continue/rotate/stop in-turn;
write decision/next_action on rotation/blocker/stall only; Round heartbeats remain mandatory.
Review bounded owner/Surface/observation deltas on new evidence/assets, phase change,
blocker/rotation/batch end. Waits/later writes: `--bounded` alone.

### Execution Invariants
Per `rules/ccst/tool-ai-boundary.md`/`rules/ccst/coverage-gate.md`, evidence-supported families/primitives/chains
remain eligible. Scanner-negative/incomplete/memory proves no Coverage. Scope/Auth, request caps,
partial cursors hold. Quick only lowers Recon cost; deep is value-first.
Validation/publication: `commands/validate.md`/`commands/report.md`; no placeholder reports/auto-submission.
Without an operator-declared external destination, deliver internally: Q7 records
`internal delivery: not-applicable` and publication proceeds — never stop a round to ask
for a platform. External submission stays a manual operator action.

### Transition And Finish Contract
Read-only snapshots: `arguments.checkpoint_trigger`; cognitive writes:
`skills/runtime-protocol.md#cognitive-write-timing`. All modes save evidence immediately.
Do not delay confirmed A for B/C.
`max_lanes` limits new lanes, not evidence import/owner write-back/cleanup/Checkpoint/Closure;
budget alone never requires another round. Resolve hypotheses; drain used `oast_listen`; preserve leads/gaps.
Import/close browser artifacts/session; failed close stays partial/blocked, no replacement.
Save memory/current handoff via Shared Memory Continuity before pause/handoff/finish. Register unresolved
Actions before read-only Checkpoint.
Before exhaustion: Coverage `rebuild` then `find-gaps` per `rules/ccst/coverage-gate.md`, then read-only Closure:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```
Missing/empty/truncated data prove nothing. Global Review covers bounded Surface/Observation
long-tail, Coverage/Ledger/Finding, Case/business chains, Queue/pending reports/Runtime, asset relations/
`chain_context`, Browser/JS/Source/Intel, Scope/external dependencies/blockers/residual candidates.
Expand needed evidence; external relations passive. `commands/checkpoint.md`
`--record-global-review` binds current snapshot/evidence; `follow_up` needs active Queue work.
Re-read Closure after writes. Exhaustion requires
`closure.verdict=finish` + `can_claim_exhausted=true`. Pending owners need handoff; bounded stop is not exhausted. Actor gaps are cell-local;
observation residuals create no mandatory actions.
End: target/mode, evidence, findings/candidates, blockers/dead ends, next action, plus
exactly one presentation-only `Memory recommendations` section in this final response
only (promote / target-only / reject; `none` + reason per empty bucket). Use criteria from
`knowledge/promotion-rules.md`/`rules/ccst/retrospective.md`; advisory, no writes or
routing/budget/Queue/lifecycle/closure changes. Promotion stays review-gated.
