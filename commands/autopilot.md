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
Optional `--max-seconds=SECONDS` binds an explicit elapsed-time limit at entry;
omit it for no time cap. Combine value options as `--option=value` within the
existing nine-token inline argument limit.

<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST
{"schema_version":4,"host_hooks":true,"paths":[{"kind":"commands","relative_path":"autopilot.md"},{"kind":"commands","relative_path":"autopilot-round.md"},{"kind":"commands","relative_path":"recon.md"},{"kind":"skills","relative_path":"runtime-protocol.md"},{"kind":"skills","relative_path":"autopilot-protocol.md"},{"kind":"skills","relative_path":"autopilot-round-protocol.md"},{"kind":"skills","relative_path":"src-hunter/SKILL.md"},{"kind":"skills","relative_path":"src-hunter/modules/web2-recon.md"},{"kind":"skills","relative_path":"src-hunter/modules/triage-validation.md"},{"kind":"skills","relative_path":"src-hunter/modules/report-writing.md"},{"kind":"skills","relative_path":"src-hunter/知识库/README.md"},{"kind":"skills","relative_path":"src-hunter/知识库/打穿短表.md"}],"mcp_contracts":["mcp__Playwright__*","mcp__chrome-devtools__*","mcp__fofamap__*"]}
AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->
Authoritative bootstrap contract (do not reinterpret): !`python3 tools/autopilot_host.py entry --session-id "${CLAUDE_SESSION_ID}" -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Complete original sources (ordered parts):
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 0`
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 1`
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 2`
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 3`
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 4`
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 5`
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 6`
!`python3 tools/autopilot_host.py body --session-id "${CLAUDE_SESSION_ID}" --part 7`

Arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep [--max-lanes N]] [--auth-file PATH] [--context-file=PATH] [--max-seconds=SECONDS]`.

Only Bootstrap `action=continue` with every complete numbered body and matching
`host.source_sha256` admits work. Missing/truncated output or
`CCST_AUTOPILOT_INCOMPLETE` forbids investigation; never use an older body.

## Shared Automation

Apply the complete [Shared Automation](../skills/autopilot-protocol.md#shared-automation) delivered above;
reuse its current body without a second read.

### State Consumption Loop

[State Consumption Loop](../skills/autopilot-protocol.md#state-consumption-loop).

### Investigation Skill

[Investigation Skill](../skills/autopilot-protocol.md#investigation-skill).

### Surface Review

[Surface Review](../skills/autopilot-protocol.md#surface-review).

### Transition And Finish Contract

[Transition And Finish Contract](../skills/autopilot-protocol.md#transition-and-finish-contract).
