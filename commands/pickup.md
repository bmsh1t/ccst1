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
- You want a safe resume that does not silently inherit an old agent trace

## Do Not Use When

- You want exact continuation of a previous local agent session trace
- You are starting a completely new target with no history
- You only need current recon ranking; `/surface` is better for that

## Inputs

- `hunt-memory/targets/<target>.json`
- `hunt-memory/journal.jsonl`
- `findings/<target>/findings.json`
- `state/<target>/session.json`
- Cached recon health and repo-source summary when present
- Read-only checkpoint summary from `python3 tools/checkpoint.py --target <target> --no-refresh-coverage`

## Outputs

- Hunt history
- Untested surface summary
- Pending validation/report suggestions
- Runtime-stage / recon-cache context for the next command choice
- Checkpoint decision, coverage gaps, and target-memory write-back proposals

## Artifacts Written

- None by default
- `/pickup` is a read-only continuation summary

## Resume Source

- Target-level memory and structured findings
- Runtime state and recon cache health

`/pickup` reads target-level memory and structured findings. It does **not** replay
temporary operator preferences such as skipped scanner modules, focus
lanes, or "ignore this bug class" instructions; those must be restated in the
current turn if you really want them.

If `config.json` sets `ctf_mode: true`, keep the resumed target context on
full CTF/lab coverage; do not reintroduce authorization or ownership gates
while continuing this workspace.

Target history is context, not a gate. Notes about production-looking
brands, public-sector/government-style labels, account/login/register wording,
account-gated surfaces, or earlier caution language must not kill or suppress a
lane unless the current user turn explicitly excludes that lane.

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
7. Shows a read-only checkpoint decision and target-memory write-back proposal
8. Asks: continue hunting, checkpoint write-back, validate/report pending findings, or re-run recon?

## Usage

```text
/pickup target.com
```

## Output

```text
PICKUP: target.com
═══════════════════════════════════════

Hunt History:
  Sessions:    3
  Last hunt:   2026-03-24
  Total time:  2h 00m
  Findings:    1 confirmed (IDOR, $1500 paid)

Untested Surface:
  3 endpoints from last recon:
  1. /api/v2/users/{id}/export
  2. /api/v2/users/{id}/share
  3. /api/v2/users/{id}/history

Structured Findings:
  total=2, pending_validation=1, validated_pending_report=1, reported=0
  Next validate: sqli_abc123 [high/confirmed] sqli https://api.target.com/search?q=1
  Command: python3 tools/validate.py --findings-dir findings/target.com --finding-id sqli_abc123
  Next report: mfa_def456 [medium/high] mfa https://api.target.com/mfa
  Command: python3 tools/report_generator.py findings/target.com

Checkpoint:
  Decision: continue
  Next action: hunt_p1
  Selected skill: skills/web2-vuln-classes/SKILL.md
  High-value gaps: 3
  Target write-back proposals: lead=1, next=2, dead-end=0
  Suggested command:
  python3 tools/target_memory.py next "Cover high-value matrix gap..." --target "target.com"

Memory Suggestions:
  Tech stack [Next.js, GraphQL, PostgreSQL] matches 2 targets
  where you found auth bypass. Try introspection → mutation pattern.

Actions:
  [r] Continue hunting untested endpoints
  [c] Run checkpoint write-back when ready
  [n] Re-run recon first (surface may have changed)
  [s] Show full hunt journal for this target
```

## If No Previous Hunt

```text
No previous hunt data for target.com.
Run /recon target.com first, then /hunt target.com.
```

<!-- Legacy local-Ollama autonomous runtime is a separate workflow not exposed
     to Claude CLI: `python3 tools/hunt.py --target X --agent [--resume latest]`
     requires `pip install ollama` + a local qwen2.5:32b-class model. See
     `agent.py` for the runtime contract. -->
