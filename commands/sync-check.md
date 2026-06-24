---
description: Check whether the current repo runtime files match the Claude CLI installed runtime, then optionally sync them. Usage: /sync-check [--sync] [--prune] [--kind commands,agents,skills]
---

# /sync-check

Inspect runtime drift between this repo and what Claude CLI actually loads from
`~/.claude/`.

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

- `--sync` copies the current repo files into the Claude runtime directories.
- `--prune` also removes runtime-only extras for the selected kinds. Use this
  when you renamed or removed a repo-managed command/agent and want Claude CLI
  to stop seeing the stale runtime file immediately.
- Runtime command files named `.disabled.<name>.md` are treated as an
  intentional disabled state for the matching repo command. `/sync-check`
  preserves that disabled state instead of re-enabling the command by mistake.
- Skills live in Claude's shared global `~/.claude/skills` directory, so
  unrelated external skills are ignored instead of being reported as drift.
