---
description: Check whether the current repo runtime files match the Claude CLI installed runtime, then optionally sync them. Usage: /sync-check [--sync] [--prune] [--kind commands,agents,skills]
---

# /sync-check

Inspect disk drift between this repo and the selected Claude runtime root
(default `~/.claude/`). Disk parity does not inspect a running host's cached Skills.

## Why This Exists

This project has two states:

1. **Repo state** — files under `commands/`, `agents/`, `skills/`
2. **Installed runtime state** — files under `~/.claude/commands`,
   `~/.claude/agents/claude-bug-bounty`, and `~/.claude/skills`

If you pull new changes but do not refresh the installed runtime, Claude CLI can
keep using old command/agent definitions even though the repo looks correct.

## Usage

```bash
/sync-check
/sync-check --kind commands,agents
/sync-check --sync --kind commands,agents
/sync-check --sync --prune --kind commands
/sync-check --sync --prune --kind commands,agents,skills  # required for an entry cutover
```

## What This Does

Runs:

```bash
python3 tools/runtime_doctor.py [args]
```

and reports:

- `OK` — repo and runtime file match
- `DIFF` — both exist but contents differ
- `MISSING` — repo file is not installed into runtime
- `EXTRA` — runtime has a file that the repo no longer provides

## Recommended Use

- After pulling updates
- When Claude CLI behavior does not match the current repo
- Before debugging model pins, prompt drift, or stale slash-command behavior

## Sync Notes

- `--sync` preflights the whole selected batch under one installer lock before
  copying or pruning any payload or changing the receipt. Conflicts reject the
  whole batch; creating the root/lock is not filesystem-level read-only behavior.
- `--prune` removes only unchanged, receipt-owned retired files for the selected
  kinds. Unowned files are preserved; locally modified owned files are preserved
  and reported as conflicts. Known retired identities and renamed/duplicate
  `src-hunter` entries are inspected across this root's Skill tree; unowned entries
  cannot be adopted merely because their bytes match. Uninspectable paths fail visibly.
- Runtime command files named `.disabled.<name>.md` are treated as an
  intentional disabled state for the matching repo command. `/sync-check`
  preserves that disabled state instead of re-enabling the command by mistake.
- Skills live in Claude's shared global `~/.claude/skills` directory, so
  unrelated external skills are ignored instead of being reported as drift.
- Use `--fail-on-drift` for a full installed-inventory check; critical-only
  checks do not cover every Skill or entry file.

## Single-entry Cutover And Recovery

- Use a fixed, complete checkout in a maintenance window. An entry cutover needs
  all three kinds and `--prune`; generic later partial sync remains available.
- Before payload, `.ccst-entry-migration.json` binds this root, direction,
  source/executor/method/native fingerprints, before/after receipt and every file
  operation. Publish non-entry resources, retire unchanged owned old entries,
  then publish the new entry last. Verify all bytes and entries before the receipt.
- Interruption is `partial`, not success. Retry only the same fixed source/executor,
  roots and full sync mode. The record permits only its exact before/after states;
  third-state user edits, different sources and unplanned identities are preserved
  and rejected. A recorded receipt phase permits only final verification/receipt
  completion and record cleanup, never another payload replay.
- Compare only reports pending and blocks critical readiness; it never recovers.
  Do not delete the record or use an old installer to force a rollback. Reverse
  migration needs approval, a fixed prior asset set and this migration-aware tool.
- Root CLAUDE/rules/tools/knowledge are not copied. Only this runtime root was
  inspected; other roots and host caches require separate verification. This is
  not a cross-file atomic, crash-durable or zero-downtime installation guarantee.
