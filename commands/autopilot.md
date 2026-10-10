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
Arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep [--max-lanes N]] [--auth-file PATH] [--context-file=PATH]`.
Defaults: paranoid, normal depth, unbounded lanes.

## Shared Automation
Round hooks only for `/autopilot-round`,
never merely deep/bounded flags.

### Startup And Recovery
Only fresh Bootstrap `action=continue` acts; otherwise request target/report Bootstrap error. Critical drift: confirm
`/sync-check`; no auto-sync/install.
Use `cd -- <repo_root_shell> &&`, `arguments.target_shell`, optional
`--auth-file <arguments.auth_file_shell>` and exact `arguments.seed_url`.
At start, target change or resume/compaction, read/apply complete
`skills/runtime-protocol.md#shared-memory-continuity`. Check inherited judgments against current commands,
not all source; label unchecked judgments inherited/unverified.
On demand: `skills/runtime-protocol.md#shared-knowledge-recall`, `skills/bug-bounty/SKILL.md`,
`skills/bb-methodology/SKILL.md`. Do not loop `/hunt`.
Apply `rules/hunting.md` before hunting; before network: `config.json.resin` via `docs/resin-proxy.md`
in the same shell. Never output secrets/persist proxy setup.
Presence is not readiness. Only session-visible MCP; missing/failed stays partial/blocked.
No failed source/tool retries this invocation.
Claims/writes/closure stay with this session; default zero specialists. Delegate per
`docs/autopilot-lanes.md#inline-specialist-propagation`; `recon-ranker` optional/read-only.
Reuse `state.lane_contract` at `text_available=true`; otherwise/new selection read that section in
`docs/autopilot-lanes.md`. Tools: `docs/tool-index.md`.

### State Consumption Loop
1. Consume Bootstrap `state`, then refreshed `control`; obey `state.hard_gate`. Missing/stale/partial
   is not clean. `wait_recon`/`wait_scan`: poll live lock and refresh, never duplicate-launch.
2. AI selects `owner_continuations`; order is advisory. Read selected evidence/owner contracts before
   execution; retain deferred work. If empty use `state.fallback_action`/`next_step`.
3. Round only: claim lane per Round Mechanics before any action (Recon too).
4. Execute once. `run_recon`: dispatch with `arguments.recon_flags` before preparation/refresh/hunting rules.
   Otherwise use selected lane. Before Action-bound execution read
   `docs/autopilot-lanes.md#state-and-queue` and `docs/evidence-runners.md#绑定已认领行动`;
   Claim/bind per those protocols, with the same explicit `--actor OPERATOR`.
   Failed claim: inspect once; never guess/retry.
5. Register/resolve/kill as applicable; require actual receipts. Missing outcomes remain recoverable;
   never replay unknown effects. Independent native evidence may register unbound.
6. Round terminal heartbeat first; then exactly one post-lane refresh:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json
```
Use fresh `control`; re-read only after owner writes. Failed reads stop stale work; recover.
`loop_guard.repetition_facts` is advisory, never overrides hard gates/claims. Decide continue/rotate/stop in-turn;
write decision/next_action only on rotation/blocker/stall, unlike mandatory Round heartbeats.
Review bounded owner/Surface/observation deltas on new evidence/assets, phase change,
blocker/rotation or batch end. For waits/later writes use `--bounded` alone.

### Execution Invariants
Per `rules/tool-ai-boundary.md`/`rules/coverage-gate.md`, evidence-supported families/primitives/chains
remain eligible. Scanner-negative/incomplete/memory proves no Coverage. Scope/Auth, request caps,
partial cursors hold. Quick only lowers Recon cost; deep is value-first.
Validation/publication: `commands/validate.md`/`commands/report.md`;
no placeholder reports/auto-submission.

### Transition And Finish Contract
Follow `arguments.checkpoint_trigger`; all modes save evidence. Do not delay confirmed A for B/C.
`max_lanes` limits only new lanes, not evidence import/owner write-back/cleanup/Checkpoint/Closure;
budget alone never requires another round. Resolve hypotheses; drain used `oast_listen`; preserve leads/gaps.
Import/close browser artifacts/session; failed close stays partial/blocked, no replacement.
Save memory/current handoff via Shared Memory Continuity before pause/handoff/finish. Register unresolved
Actions before read-only Checkpoint.
Before exhaustion: Coverage `rebuild` then `find-gaps` per `rules/coverage-gate.md`, then read-only Closure:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```
Empty/missing matrices or truncated windows prove nothing. Global Review covers bounded Surface/Observation
long-tail, Coverage/Ledger/Finding, Case/business chains, Queue/pending reports/Runtime, asset relations/
`chain_context`, Browser/JS/Source/Intel, Scope/external dependencies/blockers/residual candidates.
Expand evidence as needed; external relations passive. Record via `commands/checkpoint.md`
`--record-global-review` with current snapshot/evidence; `follow_up` needs active Queue work.
Re-read Closure after writes. Exhaustion requires current
`closure.verdict=finish` + `can_claim_exhausted=true`. Pending owners need handoff; bounded stop is not exhausted. Actor gaps are cell-local;
observation residuals create no mandatory actions.
End: target/mode, evidence, findings/candidates, blockers/dead ends, next action, plus
exactly one presentation-only `Memory recommendations` section in this final response
only (promote / target-only / reject, classified via the criteria — not write commands —
in `knowledge/promotion-rules.md`/`rules/retrospective.md`; `none` + reason per empty
bucket; advisory, never writes state or alters routing/budgets/Queue/lifecycle/closure).
Promotion stays review-gated: `knowledge/promotion-rules.md`/`rules/retrospective.md`.
