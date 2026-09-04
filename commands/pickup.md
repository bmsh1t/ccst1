---
description: Continue a previous hunt on a target — shows hunt history, untested endpoints, and memory-informed suggestions. `/resume` is a reserved Claude Code command; use `/pickup`. Usage: /pickup target.com
---

# /pickup

> `/resume` is a reserved Claude Code command. Use `/pickup` as the primary command for continuing a previous hunt.

Continue a previous hunt on a target.

## Use When

- You want to see where a target left off before continuing
- You want target-level memory, structured findings, runtime state, and untested
  surface in one place
- You want a safe resume from target-owned state

## Do Not Use When

- You are starting a completely new target with no history
- You only need current surface evidence review; `/surface` is better for that

## Inputs

- `hunt-memory/targets/<target>.json`
- `hunt-memory/journal.jsonl`
- `findings/<target>/findings.json`
- `state/<target>/session.json`
- Cached recon health and repo-source summary when present
- Checkpoint summary from `python3 tools/checkpoint.py --target <target> --no-refresh-coverage`;
  this updates only the bounded runtime-v2 checkpoint witness

## Outputs

- Hunt history
- Untested surface summary
- Pending validation/report suggestions
- Runtime-stage / recon-cache context for the next command choice
- Checkpoint current action, recent evidence, blocker, next action, coverage
  gaps, and target-memory write-back proposals

## Artifacts Written

- `state/<target_key>/checkpoint_latest.json`
- `/pickup` does not apply target-memory write-back or modify knowledge/Skills/rules

## Resume Source

- Target-level memory and structured findings
- Runtime state and recon cache health

`/pickup` reads target-level memory and structured findings. It does **not** replay
temporary operator preferences such as skipped scanner modules, focus
lanes, or "ignore this bug class" instructions; those must be restated in the
current turn if you really want them.

## When to Use `/pickup`

| Need | Use |
|---|---|
| Check where this target left off | `/pickup target.com` |
| Continue testing this target | `/hunt target.com` or `/autopilot target.com --normal` |

## What This Does

1. Reads the target profile from `hunt-memory/targets/<target>.json`
2. Shows hunt history (sessions, findings, payouts)
3. Lists untested endpoints from last recon
4. Shows structured finding follow-up from `findings/<target>/findings.json`
5. Suggests the next validation or report command when a candidate is pending
6. Suggests techniques based on tech stack + pattern DB
7. Shows the current action, recent evidence, blocker, next action, and
   target-memory write-back proposal while recording only the bounded
   runtime-v2 witness
8. Asks: continue hunting, checkpoint write-back, validate/report pending findings, or re-run recon?

## Usage

```text
/pickup target.com
```

## Output

The terminal summary is target-specific and includes only fields available from
current state. It may contain:

- `PICKUP: <target>` and hunt history (`Sessions`, `Last hunt`, `Total time`,
  `Journal`, and confirmed Finding summary when present).
- Recent Findings, the latest session snapshot, and recent guard advisories when
  available.
- Repo source, last workflow, and recon-cache context when available.
- Structured Findings with owner-verified totals/statuses and pending
  validation/report references or commands. A separate bounded Chain Context
  may show external dependencies and evidence references without promoting them
  to target Findings or executable endpoints.
- Checkpoint: `Decision`, `Next action`, `Current action`, `Recent
  evidence`, `Blocker`, optional `Recommended skill`, `High-value gaps`,
  `Target write-back proposals`, and an optional `Suggested command`.
  Checkpoint data is read-only here; target write-back remains explicit.
- Untested Surface with the cached endpoint count/list or an empty-cache notice.
- Memory Suggestions from available target-compatible memory and pattern hints.
- Actions: [r] Continue hunting untested endpoints; [c] Run checkpoint write-back when ready; [n] Re-run recon first (surface may have changed); and [s] Show full hunt journal for this target.

## If No Previous Hunt

```text
No previous hunt data for <target>.
Run /recon <target> first, then /hunt <target>.
```
