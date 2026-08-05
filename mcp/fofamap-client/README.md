# FofaMap MCP (FOFA + Shodan)

Connect Claude Bug Bounty to an external FofaMap checkout so Claude Code can
query FOFA and Shodan through one MCP server.

## What This Adds

With FofaMap MCP connected, Claude Code can use FofaMap's existing asset
search tools, including:

- FOFA asset search
- FOFA host aggregation
- Shodan asset search
- Shodan host profile lookups

This is an optional external Claude MCP capability. It is not run on every
Recon or Autopilot round. When the server is visible in the current session,
`/autopilot` and `/autopilot-round` may call it on an evidence-triggered asset
intelligence lane; missing MCP availability is advisory and does not block the
run.

## Setup

### 1. Install FofaMap dependencies

```bash
cd /absolute/path/to/FofaMap
pip3 install -r requirements.txt
```

### 2. Initialize FofaMap

```bash
cd /absolute/path/to/FofaMap
python3 fofamap.py init
```

Credential ownership stays with FofaMap:

- FOFA credentials live in `config/settings.yaml`
- Shodan can use `config/settings.yaml` or `SHODAN_API_KEY`

### 3. Optional: export Shodan key via environment variable

```bash
export SHODAN_API_KEY="your-shodan-api-key"
```

For persistent use, add it to `~/.zshrc` or `~/.bashrc`.

### 4. Add the Claude Code MCP configuration

Merge the `fofamap` entry from this directory's `config.json` into
`~/.claude/settings.json` under `mcpServers`.

```bash
claude config edit
```

Replace this placeholder path:

```text
/absolute/path/to/FofaMap/mcp_server.py
```

with your local FofaMap checkout path.

### 5. Verify

Start Claude Code and verify the FofaMap MCP server is visible. Autopilot may
use it only for a concrete coverage gap or target-relevant asset relationship.
Normalize selected results into the existing
`recon/<target-key>/exposure/asset_relation_observations.jsonl` contract, then
run `tools/recon_candidates.py` and refresh `/surface`/`/checkpoint`.

## Notes

- One server provides both FOFA and Shodan capabilities.
- This repo does not modify FofaMap's credential-loading logic.
- FofaMap results remain passive asset-relation evidence; they are not direct
  scan targets until the existing target-scope check accepts them.
- The repo does not add a second asset state owner or run FofaMap by default.
