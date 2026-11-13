---
description: Run one resumable /autopilot round, optionally bounded for native /loop scheduling.
allowed-tools:
  - Bash
  - Agent
  - TaskOutput
  - TaskStop
  - Skill
  - ToolSearch
  - CronList
  - CronDelete
  - "mcp__Playwright__*"
  - "mcp__chrome-devtools__*"
  - "mcp__fofamap__*"
---
# /autopilot-round

Authoritative round bootstrap (do not reinterpret): !`python3 tools/autopilot_host.py entry --session-id "${CLAUDE_SESSION_ID}" --round-defaults -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Complete original sources (ordered parts):
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 0`
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 1`
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 2`
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 3`
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 4`
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 5`
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 6`
!`python3 tools/autopilot_host.py body --round-defaults --session-id "${CLAUDE_SESSION_ID}" --part 7`

Native fixed-loop prompt identity (do not reinterpret): `/autopilot-round $ARGUMENTS`

Defaults: `--normal --deep`; arguments match `/autopilot`. No lane cap is added.
Optional `--max-lanes N` sets an explicit cap. Active checkpoints retain their saved
cap or unset value across resume; omission does not erase an existing round's limit.

## Bootstrap Gate
If `action=read_bootstrap`, read the exact `bootstrap_path` fully and use that JSON below.
Missing/truncated output is an error; never select an older file.
Only fresh Bootstrap `action=continue` proceeds; otherwise terminal cron cleanup, then
`STATUS: ERROR reason=<bounded-summary>`; stop before target work/sync.
Apply the complete delivered `skills/autopilot-protocol.md` with this Bootstrap.
Every numbered body must be complete and match `host.source_sha256`;
missing/truncated output or `CCST_AUTOPILOT_INCOMPLETE` forbids investigation.
Never invoke `/autopilot`.
Bootstrap initializes the single-target Store before prepare; the shared opening
conditions apply after the round starts and its selected lane is claimed.

## Prepare And Terminal Precheck

Apply the complete [Prepare And Terminal Precheck](../skills/autopilot-round-protocol.md#prepare-and-terminal-precheck) delivered above;
reuse its current body without a second read.

## Round Mechanics

[Round Mechanics](../skills/autopilot-round-protocol.md#round-mechanics).

## Correct A Completed Lane Reference

[Correct A Completed Lane Reference](../skills/autopilot-round-protocol.md#correct-a-completed-lane-reference).

## Settle And Status

[Settle And Status](../skills/autopilot-round-protocol.md#settle-and-status).

### Status

[Status](../skills/autopilot-round-protocol.md#status).

## Native Loop Ownership

[Native Loop Ownership](../skills/autopilot-round-protocol.md#native-loop-ownership).
