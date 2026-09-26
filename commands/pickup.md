---
description: Continue a previous hunt on a target — shows hunt history, untested endpoints, and memory-informed suggestions. `/resume` is a reserved Claude Code command; use `/pickup`. Usage: /pickup target.com
---

# /pickup

> `/resume` is a reserved Claude Code command. Use `/pickup` as the primary command for continuing a previous hunt.

Continue a previous hunt on a target.

Apply `skills/runtime-protocol.md#shared-memory-continuity`. Saved target memory
is sufficient to resume; a previous autopilot run or legacy hunt profile is not
required. This command restores context, not permission to start extra testing.

## Use When

- You want to see where a target left off before continuing
- You want target-level memory, structured findings, runtime state, and untested
  surface in one place
- You want a safe resume from target-owned state

## Do Not Use When

- You are starting a completely new target with no history
- You only need current surface evidence review; `/surface` is better for that

## Inputs

- Initialized target Store: goal, advisory notes, conditional experience, Case and Actions
- `hunt-memory/journal.jsonl`
- Store Findings, technical assessments and delivery/report records
- `state/<target>/session.json`
- Cached recon health and repo-source summary when present
- Checkpoint follow-up built internally through `build_checkpoint(..., refresh_coverage=False)`;
  this is read-only, including when invoked by the standalone Checkpoint CLI

## Outputs

- Target-memory source path and available structured leads
- Hunt history
- Untested surface summary
- Pending validation/report suggestions
- Runtime-stage / recon-cache context for the next command choice
- Checkpoint current action, recent evidence, blocker, next action, coverage
  gaps, and target-memory write-back proposals

## Artifacts Written

- None. `/pickup` does not publish a witness or write target memory/Queue.

## Resume Source

- Target-level memory and structured findings
- Runtime state and recon cache health

Use the returned recall command, cursor and item IDs to expand saved goals, notes,
conditions, next intentions and handoff. The default preview is not the full
memory, and a SQLite path is not a text-reading command. Reading `/pickup` does
not change the active-target pointer.

Finding, tested-endpoint and untested-endpoint collections also default to five
items each. `domain_windows` records exact totals, returned counts, remaining
counts, order and a root/target-bound expansion command. Use that command
(`--json --full`) to retrieve complete collections; owner metadata does not
duplicate their contents. These are output windows, not a claim that all
underlying Coverage/history reads are bounded.

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

1. Reads the current Store's saved intent and experience
2. Shows hunt history (sessions, findings, payouts)
3. Lists a bounded endpoint preview from current Coverage, with exact totals and full expansion
4. Shows current Store Finding and report follow-up
5. Suggests the next validation or report command when a candidate is pending
6. Provides the target-memory reference; Claude recalls relevant experience as needed
7. Shows the current action, recent evidence, blocker, next action, and
   advisory target-memory write-back proposal without publishing a witness
8. Presents continuation, fresh Checkpoint, validation/report and recon commands

## Usage

```text
/pickup target.com
```

```bash
python3 tools/resume.py --target TARGET
python3 tools/resume.py --target TARGET --json
python3 tools/resume.py --target TARGET --json --full
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
  evidence`, `Blocker`, `High-value gaps`,
  `Target write-back proposals`, and an optional `Suggested command`.
  Checkpoint data is read-only here; target write-back remains explicit.
- Untested Surface with the cached endpoint count/list or an empty-cache notice.
- Memory Suggestions with available tech-stack context; use the target-memory
  reference or shared recall for relevant experience.
- Actions: [r] Continue hunting untested endpoints; [c] Read a fresh Checkpoint; save handoff through target memory; [n] Re-run recon first (surface may have changed); and [s] Show full hunt journal for this target.

## If No Previous Hunt

An initialized empty Store returns its empty current context. An uninitialized
target requires explicit `target_store.py init --store --target TARGET`; legacy
or damaged targets require their explicit import/recovery flow. Missing state is
never silently read as an empty legacy history.
