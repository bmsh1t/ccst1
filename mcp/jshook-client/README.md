# JSHook MCP Integration

Connect Claude Bug Bounty to a local JSHook MCP server for runtime JavaScript
hooking and browser-side behavior evidence.

## What This Adds

With JSHook MCP connected, Claude Code can use a JavaScript-hooking MCP tool
surface when a target needs deeper browser runtime inspection, such as:

- dynamic route and SPA state changes
- `fetch` / XHR / WebSocket call sites
- client-side auth or role checks
- DOM source/sink and event-handler behavior
- token, localStorage, sessionStorage, and runtime config reads
- postMessage / origin / frame boundary observations

This is an optional external Claude MCP capability. It does **not**
automatically integrate with `/recon`, `/surface`, `/autopilot`, or `agent.py`.
Use it when chrome-devtools MCP or playwright MCP shows that runtime JS behavior
is the next useful evidence source.

## Setup

### 1. Prepare your JSHook MCP checkout

Install or build your local JSHook MCP server outside this repository. This
repo only ships the Claude Code config template.

Example shape:

```bash
cd /absolute/path/to/jshook-mcp
npm install
npm run build
```

If your JSHook MCP server uses a different entrypoint, adjust `config.json`
accordingly.

### 2. Optional environment variables

```bash
export JSHOOK_TARGET="http://127.0.0.1:3002"
export JSHOOK_PROFILE_DIR="$HOME/.jshook-profile"
```

Use whatever variables your JSHook MCP server expects. The template passes these
two through as common runtime hints only.

### 3. Add the Claude Code MCP configuration

Merge the `jshook` entry from this directory's `config.json` into
`~/.claude/settings.json` under `mcpServers`.

```bash
claude config edit
```

Replace this placeholder path:

```text
/absolute/path/to/jshook-mcp/dist/server.js
```

with your local JSHook MCP server entrypoint.

### 4. Suggested project workflow

1. Use chrome-devtools MCP for live network/console evidence when available.
2. Use playwright MCP for automated interaction and snapshots.
3. Use JSHook MCP when runtime JavaScript hooks can answer a specific question
   better than plain network capture.
4. Export or summarize useful artifacts into `recon/<target>/browser/` when
   possible so `/surface`, `/checkpoint`, and `/autopilot` can continue from
   the same evidence stream.

## Notes

- Keep JSHook artifacts target-scoped; do not put tokens, cookies, one-time
  values, or target-specific payloads into global docs or knowledge cards.
- JSHook evidence is a lead until it is replayed or validated through the normal
  evidence gates.
- This repo does not vendor or install JSHook itself.
