<!-- TRELLIS:START -->
# Trellis Instructions

These instructions are for AI assistants working in this project.

This project is managed by Trellis. The working knowledge you need lives under `.trellis/`:

- `.trellis/workflow.md` — development phases, when to create tasks, skill routing
- `.trellis/spec/` — package- and layer-scoped coding guidelines (read before writing code in a given layer)
- `.trellis/workspace/` — per-developer journals and session traces
- `.trellis/tasks/` — active and archived tasks (PRDs, research, jsonl context)

If a Trellis command is available on your platform (e.g. `/trellis:finish-work`, `/trellis:continue`), prefer it over manual steps. Not every platform exposes every command.

If you're using Codex or another agent-capable tool, additional project-scoped helpers may live in:
- `.agents/skills/` — reusable Trellis skills
- `.codex/agents/` — optional custom subagents

Managed by Trellis. Edits outside this block are preserved; edits inside may be overwritten by a future `trellis update`.

<!-- TRELLIS:END -->

## Codex Agent Profile

- 普通 Codex 子代理默认使用全局 `/root/.codex/agents/default.toml`。
- 原生 Agent 派发使用 `agent_type="default"`、`fork_turns="none"`，不覆盖
  `model` 或 `reasoning_effort`。
- `trellis-implement`、`trellis-check` 和 `trellis-research` 仅作为显式
  Trellis 角色保留；当前项目的 `codex.dispatch_mode` 继续使用 `inline`。
