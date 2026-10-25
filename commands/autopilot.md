---
description: AI-first autonomous hunt loop for one target or a target list.
allowed-tools:
  - Bash
  - Agent
  - Skill
  - "mcp__Playwright__*"
  - "mcp__chrome-devtools__*"
  - "mcp__fofamap__*"
---
# /autopilot

Automatically continue `src-hunter` in this session using existing execution,
validation and report commands.

## Usage

```text
/autopilot target.com
/autopilot https://target.com/app --normal --deep
/autopilot target.com --quick --deep --max-lanes 16
/autopilot targets.txt --normal
```

Checkpoint cadence: `--paranoid` (default) per substantive change, `--normal` per
batch, `--yolo` at blockers/handoff/finish. Cadence never authorizes stopping.
`--quick` lowers Recon cost; `--deep` follows evidence and value. Deep accepts
`--max-lanes N` (1–32 new investigation work items).

<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST
{"schema_version":3,"paths":[{"kind":"commands","relative_path":"autopilot.md"},{"kind":"commands","relative_path":"autopilot-round.md"},{"kind":"skills","relative_path":"runtime-protocol.md"},{"kind":"skills","relative_path":"src-hunter/SKILL.md"},{"kind":"skills","relative_path":"src-hunter/modules/web2-recon.md"},{"kind":"skills","relative_path":"src-hunter/modules/triage-validation.md"},{"kind":"skills","relative_path":"src-hunter/modules/report-writing.md"},{"kind":"skills","relative_path":"src-hunter/知识库/README.md"},{"kind":"skills","relative_path":"src-hunter/知识库/打穿短表.md"}],"mcp_contracts":["mcp__Playwright__*","mcp__chrome-devtools__*","mcp__fofamap__*"]}
AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->
Authoritative bootstrap contract (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep [--max-lanes N]] [--auth-file PATH] [--context-file=PATH]`.

## Shared Automation

Round mechanics belong to `/autopilot-round`; ordinary runs only recover existing Round work.

### State Consumption Loop

1. **Start or resume.** Only fresh Bootstrap `action=continue` admits work; obey
   `state.hard_gate`; report missing input/error. Confirm critical drift
   through `/sync-check`; never auto-sync/install. After admission checks, Bootstrap
   initializes a single-target Store before reading state; lists initialize each
   selected target through the execution owner. Start, switch, resume or compaction:
   apply `skills/runtime-protocol.md#shared-memory-continuity` from `state.target_memory`.

2. **Continue.** Recover unfinished execution first; Round recovery uses
   `commands/autopilot-round.md`. On `wait_recon`/`wait_scan`, poll and refresh
   without duplicate launches. Otherwise apply [Investigation Skill](#investigation-skill).
   A new/empty target with no prior work or usable supplied request/source/browser
   evidence starts with `/recon`, preserving `arguments.recon_flags`, seed URL and
   auth/context. Supplied usable evidence may start the investigation directly.
   After Recon's Surface finalizer, read the material and choose the next question.
   Before relying on history or repeating an experiment, apply
   `skills/runtime-protocol.md#problem-recall`; use returned corrections and conditions.
   `owner_continuations` order is advisory; keep deferred work and obey `runnable=false`.
   Existing-target gaps mandate neither Recon nor Checkpoint. Do not loop `/hunt`.

3. **Execute and save.** Read evidence and the selected `docs/autopilot-lanes.md`
   section; reuse matching `state.lane_contract` at `text_available=true`.
   Before the first native request, read `docs/evidence-runners.md#在执行时捕获原件`.
   Execute once; immediately apply `skills/runtime-protocol.md#5-execution-and-write-back`.
   Save accepted memory deltas under `skills/runtime-protocol.md#cognitive-write-timing`.
   Round claims before execution and writes its terminal heartbeat after write-back.

4. **Refresh.** After each action and any terminal heartbeat, run below once.
   Use fresh `control`; failed reads require recovery. When ready, use
   `commands/validate.md` and `commands/report.md` with the same write-back/refresh
   cycle, then return to step 2. Apply the Finish Contract before stopping.

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json
```

Apply `rules/ccst/hunting.md`. Use Bootstrap's quoted root/target, exact seed URL and
`arguments.hunt_auth_flags`. For bound context or `run_recon`, follow
`docs/autopilot-lanes.md#recon-and-surface`; never drop context. Network calls use
`docs/resin-proxy.md` in the same shell.

Before Action work read `docs/autopilot-lanes.md#state-and-queue` and
`docs/evidence-runners.md#绑定已认领行动`. Inspect failed Action claims once; never guess/retry.
Use visible MCP only; missing/failed stays partial/blocked. Retry only when the
selected contract permits. Default zero specialists; delegation follows
`docs/autopilot-lanes.md#inline-specialist-propagation`; this session owns writes.

`loop_guard` is advisory. Review bounded deltas at new evidence, phase change,
blocker, rotation or batch end. Waits/later writes use `--bounded` alone; reread
only after owner writes. Use `arguments.checkpoint_trigger` for snapshots and
save decision-relevant memory under `skills/runtime-protocol.md#cognitive-write-timing`.

### Investigation Skill

Before new investigation, apply `skills/runtime-protocol.md#native-skill-loading`
and `skills/runtime-protocol.md#shared-knowledge-recall` in this session.

### Transition And Finish Contract

Continue after publication. Stop only for user/scope/budget limits, a blocker
preventing useful work, or evidence-based lack of worthwhile next work. Apply
`rules/ccst/coverage-gate.md`; explain why and remaining leads. `handoff` alone
is no stop reason. Consider independent paths after a writer or cleanup failure.

`max_lanes` stops new work. Complete evidence, write-back, cleanup, Checkpoint and
Closure afterward; budget alone requires no new round. Before leaving: resolve hypotheses,
register pending Actions before Checkpoint, drain used `oast_listen`, import/close
browser work under its lane contract, and save memory/current handoff.
Use `commands/target.md#交接与证据` for handoff and consume its receipt.
External submission remains manual.

Before exhaustion, run Coverage `rebuild` then `find-gaps`, and read Closure:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```

Apply `commands/checkpoint.md#global-review`; incomplete evidence proves nothing.
Reread after writes. Exhaustion requires `closure.verdict=finish` and
`can_claim_exhausted=true`.

Final output: target/mode, evidence, findings/candidates, blockers, next action;
exactly one final-only, presentation-only `Memory recommendations` section
(promote / target-only / reject; empty buckets: `none` + reason), under
`knowledge/promotion-rules.md` and `rules/ccst/retrospective.md`. Advice causes no
writes or routing/budget/lifecycle changes; promotion stays review-gated.
