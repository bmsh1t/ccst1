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

This is an optional external Claude MCP capability. It does **not**
automatically integrate with `/recon`, `/surface`, `/autopilot`, or `agent.py`.
Use it when you want FOFA/Shodan search at the Claude tool layer.

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

Start Claude Code and ask it to use the FofaMap MCP server for FOFA or Shodan
asset lookups. If the connection works, Claude can call FofaMap's MCP tools
directly.

## Notes

- One server provides both FOFA and Shodan capabilities.
- This repo does not modify FofaMap's credential-loading logic.
- This repo does not automatically feed FofaMap results into the built-in
  `/recon`, `/surface`, `/autopilot`, or `agent.py` flows.
