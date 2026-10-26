---
description: AI-first autonomous hunt loop for one target or a target list.
allowed-tools:
  - Bash
  - Agent
  - TaskOutput
  - TaskStop
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
/autopilot target.com --quick --deep
/autopilot targets.txt --normal
```

Checkpoint cadence: `--paranoid` (default) per substantive change, `--normal` per
batch, `--yolo` at blockers/handoff/finish. Cadence never authorizes stopping.
`--quick` lowers Recon cost; `--deep` follows evidence and value. No project-default
time, cost or lane limit applies. `--deep --max-lanes N` optionally sets an explicit
limit of 1–32 new investigation work items; omit it to continue without a lane cap.

<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST
{"schema_version":3,"paths":[{"kind":"commands","relative_path":"autopilot.md"},{"kind":"commands","relative_path":"autopilot-round.md"},{"kind":"commands","relative_path":"recon.md"},{"kind":"skills","relative_path":"runtime-protocol.md"},{"kind":"skills","relative_path":"src-hunter/SKILL.md"},{"kind":"skills","relative_path":"src-hunter/modules/web2-recon.md"},{"kind":"skills","relative_path":"src-hunter/modules/triage-validation.md"},{"kind":"skills","relative_path":"src-hunter/modules/report-writing.md"},{"kind":"skills","relative_path":"src-hunter/知识库/README.md"},{"kind":"skills","relative_path":"src-hunter/知识库/打穿短表.md"}],"mcp_contracts":["mcp__Playwright__*","mcp__chrome-devtools__*","mcp__fofamap__*"]}
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
   selected target through the execution owner. Bind the supplied domain, IP/CIDR,
   host:port, URL or list as fixed-target scope under `rules/dig-scope-workflow.md` §0.
   Domain Recon may discover in-scope subdomains; missing history or loading a Skill
   does not turn the target into group/brand discovery or a campaign seed queue.
   Start, switch, resume or compaction:
   apply `skills/runtime-protocol.md#shared-memory-continuity` from `state.target_memory`.
   Carry any explicit user/host time, cost or lane limit. Treat absent limits as
   unset; do not invent a deadline, allocation or write-back cutoff.
   When a limit exists, retain its starting clock/cost and reserve needed write-back
   time. Resume/compaction preserves that boundary unless explicitly changed.

2. **Continue.** Recover unfinished execution first; read Bootstrap's
   `state.round_progress` and use `commands/autopilot-round.md` for existing Round work.
   No prior Round means no Round recovery. Completed lanes allow further investigation
   unless an explicit limit was reached. Settling an inherited Round returns here.
   On `wait_recon`/`wait_scan`, poll and refresh
   without duplicate launches. A background task handle keeps this invocation
   active: wait through native TaskOutput/Read, respecting any explicit limit, then
   resume here; a pending notification is not a final response or handoff boundary.
   Before selecting or executing new work (including
   fresh Recon), load `src-hunter` in this parent session through the native `Skill`
   tool as shown in [Investigation Skill](#investigation-skill).
   `state.next_action=run_recon` is the initial default for a new/empty target.
   Without prior work or usable supplied request/source/browser evidence, start
   target I/O with `/recon`, preserving `arguments.recon_flags`,
   seed URL and auth/context. Do not precede it with ad-hoc probes to create material.
   Supplied usable evidence may start the investigation directly.
   After Recon's Surface finalizer, read the material and apply [Surface Review](#surface-review)
   before choosing the next question.
   Before relying on history or repeating an experiment, apply
   `skills/runtime-protocol.md#problem-recall`; use returned corrections and conditions.
   `owner_continuations` order is advisory; keep deferred work and obey `runnable=false`.
   Existing-target gaps mandate neither Recon nor Checkpoint. Do not loop `/hunt`.

3. **Execute and save.** Read evidence and the selected `docs/autopilot-lanes.md`
   section; reuse matching `state.lane_contract` at `text_available=true`.
   Apply `skills/runtime-protocol.md#5-execution-and-write-back`; before the first
   native request read `docs/evidence-runners.md#在执行时捕获原件`.
   Save accepted memory deltas under `skills/runtime-protocol.md#cognitive-write-timing`.
   Round claims before execution and writes its terminal heartbeat after write-back.

4. **Refresh.** After each action and any terminal heartbeat, run below once.
   Use fresh `control`, including `control.next_step`; expand changed or unread material
   through `surface_projection.path` and `surface_projection.continuation.command`. `surface.review_window`
   counts describe the display window, not tested coverage. Missing/stale material
   needs raw-source reading or an explicit refresh when needed; failed reads require recovery.
   Empty `control.owner_continuations` returns to step 2 to select investigation. When ready, use
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
selected contract permits. Surface review follows the rule below; specialists
are optional for bounded independent questions. Delegation follows
`docs/autopilot-lanes.md#inline-specialist-propagation`; this session owns writes.

`loop_guard` is advisory. Review bounded deltas at new evidence, phase change,
blocker, rotation or batch end. Waits/later writes use `--bounded` alone; reread
only after owner writes. Use `arguments.checkpoint_trigger` for snapshots and
save decision-relevant memory under `skills/runtime-protocol.md#cognitive-write-timing`.

### Investigation Skill

Apply `skills/runtime-protocol.md#native-skill-loading` in this parent session:
actually invoke `Skill({"skill":"src-hunter","args":"<current target type/Scope, fresh or resumed, available evidence, deep, explicit limits or unset>"})`
when its complete body is absent. Child reading and description metadata are not
parent body context. Reuse retained context; apply Shared Knowledge Recall to the question.

### Surface Review

After Recon, compare available business and technical surfaces in this parent session
before choosing the next question. Apply `rules/src-value-hunting.md` §1.1 when stronger
evidence changes the default priority; keep unread or missing material explicit.

`recon-ranker` is an optional read-only second opinion. Select it when independent
review would help a concrete prioritization or missed-path question, whether after
Recon, at stagnation or before evidence-based finish. Multiple subdomains, the first
post-Recon choice, resume/compaction or lane/round completion alone do not trigger it.
When the next experiment is clear, continue in-session. Reuse the prior answer for
unchanged materials and question, including through the existing handoff.

If selected, invoke the native `Agent` tool with `recon-ranker` and `run_in_background=false`.
Read `docs/autopilot-lanes.md#recon-ranker-review` for the dispatch pack; include the
concrete question, actual deep mode and a bounded review allocation. Honor any explicit
parent limit; this review allocation never ends the parent investigation.
Wait for its result before choosing or executing the dependent experiment;
an asynchronous dispatch acknowledgment is not the review. Apply the result or state
its failure before proceeding in-session.
User/scope/explicit-limit stops and execution recovery take precedence.
If a selected review cannot run because the Agent tool/role is unavailable or fails, report it as incomplete
and continue in-session with src-hunter; do not retry repeatedly or claim a review occurred.

### Transition And Finish Contract

Continue after publication. Stop only for a user instruction, scope or explicit user/host limit, a blocker
preventing useful work, or evidence-based lack of worthwhile next work. Apply
`rules/ccst/coverage-gate.md`; explain why and remaining leads. `handoff` alone
is no stop reason. Unresolved observations or reviewed deferrals keep Closure at
`handoff`; they do not prove a blocker. `stagnant_prerequisite` retains the local
failure and guard as a handoff to independent investigation. Consider independent
paths after a writer or cleanup failure.

Only an explicitly supplied `max_lanes` stops new work by count. Per-request timeouts,
rate limits, collector batches and review deadlines bound that operation, not this investigation.
Complete evidence, write-back, cleanup, Checkpoint and Closure before leaving: resolve hypotheses,
register pending Actions before Checkpoint, drain used `oast_listen`, import/close
browser work under its lane contract, and save memory/current handoff.
Use `commands/target.md#交接与证据` for handoff and consume its receipt.
External submission remains manual.

When stopping at an explicit limit, name its user/host source and show the measured
elapsed time, lane count or cost against it. Cost requires actual receipts and the
allocation's starting value; unknown usage is not exhaustion. Without an explicit
limit, return to step 2 while worthwhile work remains. Saving a next action or
reaching a report/checkpoint never creates a stopping limit.

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
