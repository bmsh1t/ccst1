---
description: Run one bounded, resumable /autopilot round for native /loop scheduling.
allowed-tools:
  - Bash
  - Agent
  - ToolSearch
  - CronList
  - CronDelete
  - "mcp__Playwright__*"
  - "mcp__chrome-devtools__*"
---
# /autopilot-round

Authoritative round bootstrap (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json --round-defaults -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"`
Native fixed-loop prompt identity (do not reinterpret): `/autopilot-round $ARGUMENTS`

Formal arguments are identical to `/autopilot`: `<target>
[--paranoid|--normal|--yolo] [--quick] [--deep] [--max-lanes N]
[--auth-file PATH]`, or one readable primary-domain list. Round defaults are
`--normal --deep --max-lanes 3`; an explicit formal argument wins. The existing
bootstrap/parser is the only argument owner.

## Bootstrap Gate

Obey bootstrap `action` exactly as `commands/autopilot.md` requires. Only
`continue` may proceed. For `ask_target`, `stop_invalid_arguments`, or
`stop_runtime_drift`, `stop_runtime_error`, or `stop_state_error`, preserve the bounded bootstrap reason, apply the terminal
cron cleanup below, emit `STATUS: ERROR reason=<bounded-summary>`, and stop. Do
not sync runtime automatically and do not perform a target action before the
read-only precheck below.

## Read-Only Terminal Precheck

Using bootstrap `repo_root_shell` and `arguments.target_shell`, run exactly one
state-only precheck without `--max-lanes-reached`:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```

For STATUS selection, read only `closure.verdict`,
`closure.can_claim_exhausted`, `closure.reasons`, `closure.next_action`, and
`structured_findings.reported`. `closure.round_progress` is the bounded recovery
projection for an active lane/round and may only explain its owner-selected
handoff. For terminal residual blind spots only, also
read the bounded `browser_evidence.present/ready`, `repo_source_available`,
`repo_source_summary.status`, `recon_blocker`,
`observation_inventory.status/reason`, and bootstrap
`capabilities.missing_core/missing_optional`; these advisory facts never select
or override STATUS. Project through the Status Projection below. `finish` or
`blocked` is terminal: project its STATUS, apply terminal cron cleanup, emit,
and stop without any target action. `handoff` is the only verdict that may enter
a round. A missing, damaged, inconsistent, or unknown closure/verdict follows
the same cleanup, emits `STATUS: ERROR`, and stops.

Before target work, start or resume the checkpoint-owned round budget:

```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --round-begin --max-lanes <invocation_batch.max_lanes> --json
```

Treat its `round_progress` as authoritative. A resumed round keeps its original
limit and lane heartbeats after context/process loss. Resume any lane whose
heartbeat is still `status=started` before selecting new work.

## One Canonical Round

After a non-terminal precheck, read and obey `commands/autopilot.md` as the sole
controller contract. Do not execute its embedded bootstrap again and do not
copy or reinterpret its hunt, state, checkpoint, coverage, closure, loop-guard,
red-line, credential-hygiene, or report rules here.

Consume at most bootstrap `invocation_batch.max_lanes` named substantive lanes.
Immediately before each substantive lane, derive a stable ID from the owner ID
when available, otherwise `<lane-kind>:<endpoint-or-artifact>`, then run:

```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane --lane <stable_lane_id> --max-lanes <invocation_batch.max_lanes> --json
```

Execute the lane only when `allowed=true`. `already_claimed` resumes interrupted
work without consuming another slot. `already_completed` or `already_blocked`
must not replay target work; use its recorded decision, evidence reference, and
next action. `budget_exhausted` skips target work and goes directly to
checkpoint/final closure.

After target work and before selecting another lane or requesting closure,
record its terminal heartbeat:

```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane-result --lane <stable_lane_id> --lane-status <completed_or_blocked> --decision <decision_shell> --evidence-ref <evidence_ref_shell> --next-action <next_action_shell> --json
```

Keep decision, evidence reference, and next action bounded and single-line.
Use a locatable owner artifact for every completed lane; a blocked lane may use
literal `none` when it has no evidence, and any terminal lane may use `none`
when it has no next action. Never store raw responses,
prompts, credentials, tokens, cookies, or authorization headers in the heartbeat.
The terminal write is idempotent; a conflicting rewrite or write failure stops
target work. The heartbeat is recovery context, not a second action owner:
write every unresolved terminal `next_action` through its existing owner or the
Action Queue before round closure. A round with any `started` lane cannot close.

After every terminal lane heartbeat, use the canonical `--loop-check --json` guard.
When the lane budget is consumed, checkpoint the completed batch and durable
queue, but leave newly discovered work for the next scheduled invocation.

## Final Closure And Status

After the canonical checkpoint/write-back, rebuild and review coverage before
requesting the final owner verdict:

```bash
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py rebuild --target <target_shell>
cd -- <repo_root_shell> && python3 tools/coverage_matrix.py find-gaps --target <target_shell>
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-closure --json
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json [--max-lanes-reached]
```

Include `--max-lanes-reached` only when the immediately preceding
`--record-round-closure` output has `round_progress.budget_reached` set to true;
never infer it from model-side counting.
Then apply the same Status Projection and terminal
cron cleanup before emitting. After a successful bootstrap, closure owner fields
alone select STATUS; model prose, scanner-negative output, coverage score, and
the run-contract checker never override them.

## Status Projection

- `finish` + `can_claim_exhausted=true` + integer
  `structured_findings.reported > 0`:
  `STATUS: DONE residual_blind_spots=<bounded-labels|none-recorded>`
- `finish` + `can_claim_exhausted=true` + integer
  `structured_findings.reported == 0`:
  `STATUS: EXHAUSTED reason=evidence-bounded`, then
  `RESIDUAL_BLIND_SPOTS: <bounded-labels|none-recorded>`
- `handoff`: `STATUS: CONTINUE next_action=<bounded-summary>`
- `blocked`: `STATUS: BLOCKED reason=<bounded-summary>`
- Any other shape: `STATUS: ERROR reason=<bounded-summary>`

Keep `next_action` and `reason` to one line and at most 160 characters. For
DONE/EXHAUSTED, emit at most five labels already evidenced by bootstrap/state,
chosen from missing auth actors, browser evidence, source evidence, proxy
evidence, failed tools, or an unobserved workflow prerequisite. Do not create a
new blind-spot store or speculate beyond state. If none is represented, emit
`none-recorded`; this means no current-state gap was recorded, not universal
absence.

`EXHAUSTED` is evidence-bounded under the currently known Surface, actors,
workflows, identities, available tools, coverage matrix, Action Queue, and
side-effect boundaries. It does not prove that every payload, identity, timing,
business state, or vulnerability has been exhausted. `DONE` adds at least one
canonical generated report but has the same closure and blind-spot limits.

## Native Loop Ownership

Recommended scheduler entry:

```text
/loop 10m /autopilot-round TARGET --normal --deep --max-lanes 3
```

This interval form creates a native fixed-interval cron job; native `/loop` owns
recurrence and this wrapper owns only terminal cleanup. For `STATUS: CONTINUE`,
do not call CronList or CronDelete and leave the recurring job active. Before
emitting DONE, EXHAUSTED, BLOCKED, or ERROR, call CronList once and delete every
recurring job whose `prompt` exactly equals the expanded Native fixed-loop
prompt identity above. Never delete by target substring, cadence alone, or job
position. If either cron tool is deferred, load exactly CronList and CronDelete
through ToolSearch once before listing. No exact match means the command was
invoked directly or the job is already absent; emit the computed terminal
STATUS. A CronList/CronDelete error instead emits
`STATUS: ERROR reason=loop-cancel-failed` so cancellation failure is not hidden.
Never create or modify a cron job from this wrapper.

One loop owns one target. If a turn is interrupted, the next round resumes from
existing target state/checkpoint; it does not resume a legacy
`agent.py --agent` session.

All `commands/autopilot.md` pause boundaries remain unchanged. In particular,
never auto-submit reports or cross its destructive, irreversible, target,
credential, or current-turn confirmation boundaries.
