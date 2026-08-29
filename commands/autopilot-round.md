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
  - "mcp__fofamap__*"
---
# /autopilot-round

Authoritative round bootstrap (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json --round-defaults -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Native fixed-loop prompt identity (do not reinterpret): `/autopilot-round $ARGUMENTS`

Arguments match `/autopilot`. Defaults are `--normal --deep --max-lanes 8`;
an active round keeps its checkpoint-owned `max_lanes`. The bootstrap parser is
the only argument owner.

## Bootstrap Gate

Obey bootstrap `action`. Only `continue` may proceed. For `ask_target`,
`stop_invalid_arguments`, `stop_invalid_scope`, `stop_invalid_context`,
`stop_runtime_drift`, `stop_runtime_error`, or `stop_state_error`, perform
terminal cron cleanup, emit `STATUS: ERROR reason=<bounded-summary>`, and stop.
Do not sync runtime or perform a target action first.

## Prepare And Terminal Precheck

Run prepare once:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_round.py prepare --target <target_shell> --max-lanes <invocation_batch.max_lanes> --json
```

The coordinator performs the read-only terminal precheck before starting or
resuming the checkpoint-owned round. For STATUS, consume only
`closure.verdict`, `closure.can_claim_exhausted`, `closure.reasons`,
`closure.next_action`, and `structured_findings.reported`. Residual blind-spot
labels may use the bounded advisory fields already returned by bootstrap/state.
These fields never override STATUS.

`status=terminal` with Closure `finish` or `blocked` is terminal: clean up the
exact loop, emit STATUS, and stop without target work. Missing, damaged,
inconsistent, or unknown Closure is `STATUS: ERROR` after cleanup. For
`status=started|resumed`, recover any lane whose heartbeat remains `started`.

The legacy state-only projection is a compatibility adapter for callers that
cannot use the coordinator; do not run it in addition to `prepare`.

## Round Mechanics

Read and obey `commands/autopilot.md` as the sole controller contract. This
wrapper only carries the bounded round mechanics and does not repeat its route,
evidence, red-line, or completion rules. Consume at most
`invocation_batch.max_lanes` substantive lanes and use the controller-selected
owner/action. If no lane is executable, preserve the existing handoff and move
to closure.

Claim the selected stable lane:

```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane --lane <stable_lane_id> --max-lanes <invocation_batch.max_lanes> --json
```

Proceed only when `allowed=true`. `already_claimed` resumes interrupted work;
`already_completed`, `already_blocked`, `budget_exhausted`, and
`passive_lane_rejected` do not replay target work.

After the owner action, record one terminal heartbeat:

```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane-result --lane <stable_lane_id> --lane-status <completed_or_blocked> --decision <decision_shell> --evidence-ref <evidence_ref_shell> --next-action <next_action_shell> --json
```

Completed lanes require a non-empty target-owned evidence artifact; blocked
lanes may use `none`. Heartbeats contain no raw responses, prompts, credentials,
tokens, cookies, or authorization headers. A round with any `started` lane
cannot close.

After every terminal heartbeat, run the read-only loop guard:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json
```

When the lane budget is consumed, checkpoint and leave new work for the next
invocation.

## Settle And Status

After terminal heartbeats, run the deterministic settle operation:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_round.py settle --target <target_shell> --json
```

Settle refuses `started` lanes, performs owner write-back and final Closure, and
leaves the round active when Surface is stale or unavailable. Repeating settle
after completion is read-only (`status=already_settled`) and never replays target
work. Budget exhaustion ends target work for this invocation; it does not itself
select `STATUS: CONTINUE`.

Project STATUS from the final owner fields:

- `finish` + `can_claim_exhausted=true` + `structured_findings.reported > 0`:
  `STATUS: DONE residual_blind_spots=<bounded-labels|none-recorded>`
- `finish` + `can_claim_exhausted=true` + `structured_findings.reported == 0`:
  `STATUS: EXHAUSTED reason=evidence-bounded`, then
  `RESIDUAL_BLIND_SPOTS: <bounded-labels|none-recorded>`
- `handoff`: `STATUS: CONTINUE next_action=<bounded-summary>`
- `blocked`: `STATUS: BLOCKED reason=<bounded-summary>`
- Any other shape: `STATUS: ERROR reason=<bounded-summary>`

For DONE/EXHAUSTED, emit at most five labels already evidenced by
bootstrap/state. Do not create a blind-spot store or speculate beyond state.
`EXHAUSTED` is evidence-bounded, not proof that every payload, identity,
timing, business state, or vulnerability has been exhausted.
An `closure.actor_context_gap` is a lane-local residual for owner/peer
comparison. It is non-blocking and must not be rendered as a missing external
test authorization; anonymous and other independent lanes may still finish.

## Native Loop Ownership

Recommended scheduler entry:

```text
/loop 10m /autopilot-round TARGET --normal --deep --max-lanes 8
```

Native `/loop` owns the fixed-interval cron job. For `STATUS: CONTINUE`, do not
call CronList or CronDelete. Before DONE, EXHAUSTED, BLOCKED, or ERROR, call
CronList once and delete only jobs whose `prompt` exactly equals the expanded
fixed-loop prompt identity. Never delete by target substring, cadence, or job
position. If cleanup fails, emit `STATUS: ERROR reason=loop-cancel-failed`.
Never create or modify a cron job from this wrapper. One loop owns one target;
interrupted turns resume from checkpoint/state.
