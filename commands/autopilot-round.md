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

Arguments are identical to `/autopilot`. Round defaults are
`--normal --deep --max-lanes 8`. Explicit formal arguments set the budget when
starting a new round; resuming an active round keeps the checkpoint-owned
`max_lanes`. The bootstrap parser is the only argument owner.

## Bootstrap Gate

Obey bootstrap `action`. Only `continue` may proceed. For `ask_target`,
`stop_invalid_arguments`, `stop_invalid_scope`, `stop_invalid_context`,
`stop_runtime_drift`, `stop_runtime_error`, or
`stop_state_error`, preserve the bounded reason, apply the terminal cron
cleanup, emit `STATUS: ERROR reason=<bounded-summary>`, and stop. Do not sync
runtime automatically and do not perform a target action first.

## Prepare And Read-Only Terminal Precheck

Run the deterministic prepare operation once:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_round.py prepare --target <target_shell> --max-lanes <invocation_batch.max_lanes> --json
```

The legacy state-only projection remains a compatibility adapter for callers
that cannot use the coordinator; do not run it in addition to `prepare`:

```bash
# python3 tools/checkpoint.py --target <target_shell> --round-begin --max-lanes <invocation_batch.max_lanes> --json
# python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```

The coordinator runs the read-only terminal precheck before beginning or
resuming the checkpoint-owned round. For STATUS selection, read only `closure.verdict`,
`closure.can_claim_exhausted`, `closure.reasons`, `closure.next_action`, and
`structured_findings.reported`. For terminal residual blind spots only, read
the bounded browser/source/recon/observation/runtime/capability fields already
returned by bootstrap/state; these advisory facts never select or override
STATUS.

`status=terminal` with Closure `finish` or `blocked` is terminal: project STATUS, apply terminal cron cleanup,
emit, and stop without any target action. Missing, damaged, inconsistent, or
unknown closure is `STATUS: ERROR` after terminal cleanup.
For `status=started|resumed`, treat `round_progress` as authoritative. Resume
any lane whose heartbeat is still `status=started` before selecting new work.

## One Canonical Round

read and obey `commands/autopilot.md` as the sole controller contract. Do not
execute its embedded bootstrap again or restate its hunt, state, red-line,
coverage, validation, report, queue, or closure rules here.

Consume at most bootstrap `invocation_batch.max_lanes` substantive lanes. Obey a
non-empty bootstrap `state.hard_gate`; otherwise select one runnable item from
`state.priority_frontier` using the canonical controller's value judgment. The
frontier only changes cross-owner execution order; execute through the selected
item's canonical owner and evidence contract. If no frontier item is executable,
use `state.fallback_action` or persist the existing blocker/handoff instead of
asking the operator to choose a direction. Never replace selected work with
passive `idle`, `no-change`, or monitoring lanes. Derive `<stable_lane_id>` from
the owner ID or stable `<lane-kind>:<endpoint-or-artifact>` identity, then claim
the heartbeat:

```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane --lane <stable_lane_id> --max-lanes <invocation_batch.max_lanes> --json
```

Execute only when `allowed=true`. `already_claimed` resumes interrupted work;
`already_completed` or `already_blocked` must not replay target work.
`budget_exhausted` or `passive_lane_rejected` proceeds to final closure without
target work.

After target work, record one terminal heartbeat:

```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane-result --lane <stable_lane_id> --lane-status <completed_or_blocked> --decision <decision_shell> --evidence-ref <evidence_ref_shell> --next-action <next_action_shell> --json
```

Completed lanes require an existing, non-empty, target-owned evidence artifact.
Completed `coverage:*` lanes must reference the canonical Coverage Matrix,
Action Queue, or Evidence Ledger artifact after owner write-back; a narrative
Markdown disposition is not completion evidence.
Blocked lanes may use literal `none`. Never store raw responses, prompts,
credentials, tokens, cookies, or authorization headers in a heartbeat. The
heartbeat is recovery context, not a second action owner; persist unresolved
work through its existing owner or the Action Queue before round closure. A
round with any `started` lane cannot close.

After every terminal lane heartbeat, run the canonical `--loop-check --json` guard.
When the lane budget is consumed, checkpoint and leave new work for the
next invocation.

## Final Closure And Status

After the terminal lane heartbeats, run the deterministic settle operation. The
coordinator performs the canonical checkpoint/write-back for this round:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_round.py settle --target <target_shell> --json
```

The legacy owner commands remain valid compatibility adapters. The coordinator
executes their equivalent order; do not repeat them after `settle`:

```bash
# python3 tools/coverage_matrix.py rebuild --target <target_shell>
# python3 tools/coverage_matrix.py find-gaps --target <target_shell> --limit 50
# python3 tools/checkpoint.py --target <target_shell> --record-round-closure --json
# python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```

The bounded `find-gaps --limit 50` output is an AI review window only. Its
`total` and `truncated` fields are advisory display metadata; the complete
matrix remains the closure owner input, and a truncated window never means
coverage is complete.

The coordinator refuses any `started` lane before writes, then orders Coverage
refresh/checkpoint build, Action Queue sync, round closure, and final bounded
Closure projection. Repeating settle after round completion is read-only and
returns `status=already_settled`; it never replays target work.

`round_progress.budget_reached` only ends target work for this invocation. The
final verdict is recomputed from current Queue, Finding, Case State, coverage,
and evidence owners; budget exhaustion alone never selects `STATUS: CONTINUE`.
After a successful bootstrap, closure owner fields alone select STATUS; model
prose, scores, scanner output, gaps, and run-contract checks never override them.

## Status Projection

- `finish` + `can_claim_exhausted=true` +
  `structured_findings.reported > 0`: `STATUS: DONE residual_blind_spots=<bounded-labels|none-recorded>`
- `finish` + `can_claim_exhausted=true` +
  `structured_findings.reported == 0`: `STATUS: EXHAUSTED reason=evidence-bounded`, then
  `RESIDUAL_BLIND_SPOTS: <bounded-labels|none-recorded>`
- `handoff`: `STATUS: CONTINUE next_action=<bounded-summary>`
- `blocked`: `STATUS: BLOCKED reason=<bounded-summary>`
- Any other shape: `STATUS: ERROR reason=<bounded-summary>`

For DONE/EXHAUSTED, emit at most five labels already evidenced by bootstrap/state.
Do not create a new blind-spot store or speculate beyond state. `none-recorded`
means no current-state gap was recorded, not universal absence.

`EXHAUSTED` is evidence-bounded and does not prove that every payload, identity,
timing, business state, or vulnerability has been exhausted. `DONE` adds a
canonical generated report but keeps the same closure limits.

## Native Loop Ownership

Recommended scheduler entry:

```text
/loop 10m /autopilot-round TARGET --normal --deep --max-lanes 8
```

Native `/loop` owns the fixed-interval cron job. For `STATUS: CONTINUE`, do not
call CronList or CronDelete. Before emitting DONE, EXHAUSTED, BLOCKED, or ERROR,
call CronList once and delete jobs whose `prompt` exactly equals the expanded
Native fixed-loop prompt identity. Never delete by target substring, cadence
alone, or job position. If deferred, load exactly CronList and CronDelete through
ToolSearch once. No exact match means direct invocation or prior cleanup. A tool
error emits `STATUS: ERROR reason=loop-cancel-failed`. Never create or modify a
cron job from this wrapper.

One loop owns one target. Interrupted turns resume from checkpoint/state, not a
legacy agent session. All `commands/autopilot.md` pause boundaries remain
unchanged: never auto-submit reports or cross its red-line, target, or credential
boundaries.
