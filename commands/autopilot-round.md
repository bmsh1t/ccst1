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

Defaults: `--normal --deep --max-lanes 16`; arguments match `/autopilot`.
Active checkpoint owns `max_lanes`.

## Bootstrap Gate
Only fresh Bootstrap `action=continue` proceeds; otherwise terminal cron cleanup, then
`STATUS: ERROR reason=<bounded-summary>`; stop before target work/sync.
Read complete H2 `commands/autopilot.md#shared-automation` with this Bootstrap, excluding main Bootstrap.
Never invoke `/autopilot`.

## Prepare And Terminal Precheck
Run once; no state precheck:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_round.py prepare --target <target_shell> --max-lanes <invocation_batch.max_lanes> --json
```
`started|resumed`: recover `started` heartbeats; enter Shared Automation.
`terminal`: no target work; Status/cleanup. Other results: Status, skipping lanes/settle.

## Round Mechanics
Use Shared Automation's selected action. None executable: handoff/closure.
Claim round lane before execution; distinct from Action id/token/actor:
```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane --lane <stable_lane_id> --max-lanes <invocation_batch.max_lanes> --json
```
Only `allowed=true` proceeds; recover `already_claimed`; never replay other refusals.
Terminal heartbeat after registration/resolve:
```bash
cd -- <repo_root_shell> && python3 tools/checkpoint.py --target <target_shell> --record-round-lane-result --lane <stable_lane_id> --lane-status <completed_or_blocked> --decision <decision_shell> --evidence-ref <evidence_ref_shell> --next-action <next_action_shell> --json
```
Completed needs nonempty target-owned evidence; blocked permits `none`. No raw responses/prompts/credentials.
`started` lanes forbid closure. Claim/result errors: ERROR; preserve recovery, stop new work.

## Settle And Status
After heartbeats and shared saving/cleanup:
```bash
cd -- <repo_root_shell> && python3 tools/autopilot_round.py settle --target <target_shell> --json
```
`settled`/`already_settled` complete only this round; no memory save, Queue sync or Surface refresh.
Missing, malformed, or stale Surface never blocks settle or flips a settled round back to active; it keeps the
Surface-backed advisory lead open until a later explicit `/surface` refresh.
### Status
First validate coordinator `status`/`round_progress`; unknown/malformed means ERROR.
Prepare/settle/replay `review_required`: shared Global Review + fresh Closure; no new lane/round.
After review discard old coordinator status; project current
`closure` and `structured_findings.reported`:
- Review still required: `STATUS: CONTINUE next_action=global-review`
- `closure.verdict=finish` + `can_claim_exhausted=true`: reported > 0 → `STATUS: DONE`; reported == 0 →
  `STATUS: EXHAUSTED reason=evidence-bounded`.
- `handoff`: `STATUS: CONTINUE next_action=<closure.next_action>`
- `blocked`: `STATUS: BLOCKED reason=<closure.reasons>`
- Other/missing/malformed: `STATUS: ERROR reason=<bounded-summary>`
DONE appends `residual_blind_spots=<labels|none-recorded>`;
EXHAUSTED adds `RESIDUAL_BLIND_SPOTS: <labels|none-recorded>`. At most five Bootstrap/state-evidenced labels;
no STATUS override or blind-spot store. Evidence-bounded, not exhaustive.

## Native Loop Ownership
One target per native `/loop` fixed-interval cron job:
```text
/loop 10m /autopilot-round TARGET --normal --deep --max-lanes 16
```
`STATUS: CONTINUE`: no CronList/CronDelete.
Before DONE/EXHAUSTED/BLOCKED/ERROR, CronList once; delete only jobs whose `prompt` exactly equals
the expanded fixed-loop prompt identity, never by substring/cadence/position.
Cleanup failure: `STATUS: ERROR reason=loop-cancel-failed`. Never create or modify cron jobs.
