#!/bin/bash
# Claude Bug Bounty — install skills, slash commands, and agents into Claude Code.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

prompt_yes_no() {
    local prompt="$1"
    local answer=""
    local old_stty=""

    # In some terminals or Claude Code wrappers, Enter can arrive as CR/LF.
    # Bash read strips LF but keeps CR. Disable echo while reading, then print
    # the normalized answer ourselves so CR never appears as a visible ^M.
    if [ ! -r /dev/tty ]; then
        echo "${prompt}n"
        return 1
    fi

    printf "%s" "${prompt}" > /dev/tty
    old_stty="$(stty -g < /dev/tty 2>/dev/null || true)"
    if [ -n "${old_stty}" ]; then
        stty -echo < /dev/tty 2>/dev/null || true
    fi
    IFS= read -r answer < /dev/tty || answer=""
    if [ -n "${old_stty}" ]; then
        stty "${old_stty}" < /dev/tty 2>/dev/null || true
    fi
    answer="${answer//$'\r'/}"
    printf "%s\n" "${answer}" > /dev/tty
    [[ "${answer}" =~ ^[Yy]$ ]]
}

INSTALL_DIR="${HOME}/.claude/skills"
mkdir -p "${INSTALL_DIR}"

echo "Installing Claude Bug Bounty skills..."
echo ""

for shared_skill_file in "${SCRIPT_DIR}"/skills/*.md; do
    [ -e "$shared_skill_file" ] || continue
    cp "$shared_skill_file" "${INSTALL_DIR}/$(basename "$shared_skill_file")"
    echo "✓ Installed shared skill file: $(basename "$shared_skill_file")"
done

# Copy all skills
for skill_dir in "${SCRIPT_DIR}"/skills/*/; do
    skill_name=$(basename "$skill_dir")
    mkdir -p "${INSTALL_DIR}/${skill_name}"
    cp "${skill_dir}SKILL.md" "${INSTALL_DIR}/${skill_name}/SKILL.md"
    echo "✓ Installed skill: ${skill_name}"
done

# Install commands
COMMANDS_DIR="${HOME}/.claude/commands"
mkdir -p "${COMMANDS_DIR}"

for cmd_file in "${SCRIPT_DIR}"/commands/*.md; do
    cmd_name=$(basename "$cmd_file")
    disabled_path="${COMMANDS_DIR}/.disabled.${cmd_name}"
    active_path="${COMMANDS_DIR}/${cmd_name}"
    if [ -f "${disabled_path}" ] && [ ! -f "${active_path}" ]; then
        cp "$cmd_file" "${disabled_path}"
        echo "✓ Installed command (preserved disabled state): ${cmd_name}"
        continue
    fi
    cp "$cmd_file" "${active_path}"
    echo "✓ Installed command: ${cmd_name}"
done

# Install agents
AGENTS_DIR="${HOME}/.claude/agents/claude-bug-bounty"
mkdir -p "${AGENTS_DIR}"

for agent_file in "${SCRIPT_DIR}"/agents/*.md; do
    agent_name=$(basename "$agent_file")
    cp "$agent_file" "${AGENTS_DIR}/${agent_name}"
    echo "✓ Installed agent: ${agent_name}"
done

echo ""
echo "Done! Skills installed to ${INSTALL_DIR}"
echo "Commands installed to ${COMMANDS_DIR}"
echo "Agents installed to ${AGENTS_DIR}"
echo "Re-run this installer after pulling updates so Claude Code sees the latest slash commands."
echo "For drift checks without a full reinstall, use: python3 tools/runtime_doctor.py"
echo ""

# Offer Burp MCP setup
echo "─────────────────────────────────────────────"
echo "Optional: Burp Suite MCP Integration"
echo "─────────────────────────────────────────────"
echo ""
echo "Connect to PortSwigger's Burp MCP server for live HTTP traffic visibility."
echo "See mcp/burp-mcp-client/README.md for setup instructions."
echo ""
if prompt_yes_no "Set up Burp MCP now? (y/N): "; then
    echo ""
    echo "To connect Burp MCP, add this to your Claude Code settings:"
    echo ""
    echo "  claude config edit"
    echo ""
    echo "Then add to the mcpServers section:"
    cat "${SCRIPT_DIR}/mcp/burp-mcp-client/config.json" | grep -A 10 '"burp"'
    echo ""
    echo "And set your Burp API key:"
    echo "  export BURP_API_KEY=\"your-api-key-here\""
    echo ""
fi

echo "─────────────────────────────────────────────"
echo "Optional: Caido MCP Integration"
echo "─────────────────────────────────────────────"
echo ""
echo "Connect to Caido MCP for live HTTP traffic visibility."
echo "See mcp/caido-mcp-client/README.md for PAT or OAuth setup instructions."
echo ""
if prompt_yes_no "Set up Caido MCP now? (y/N): "; then
    echo ""
    echo "To connect Caido MCP, add this to your Claude Code settings:"
    echo ""
    echo "  claude config edit"
    echo ""
    echo "Then add to the mcpServers section:"
    cat "${SCRIPT_DIR}/mcp/caido-mcp-client/config.json" | grep -A 8 '"caido"'
    echo ""
    echo "Set your Caido URL and PAT:"
    echo "  export CAIDO_URL=\"http://127.0.0.1:8080\""
    echo "  export CAIDO_PAT=\"your-personal-access-token\""
    echo ""
    echo "Or use OAuth login once:"
    echo "  CAIDO_URL=http://localhost:8080 caido-mcp-server login"
    echo ""
fi

echo "─────────────────────────────────────────────"
echo "Optional: FofaMap MCP (FOFA + Shodan)"
echo "─────────────────────────────────────────────"
echo ""
echo "Connect Claude Code to an external FofaMap checkout for optional FOFA and"
echo "Shodan asset-search tools through one MCP server."
echo "See mcp/fofamap-client/README.md for setup instructions."
echo ""
if prompt_yes_no "Set up FofaMap MCP now? (y/N): "; then
    echo ""
    echo "First prepare your external FofaMap checkout:"
    echo "  cd /absolute/path/to/FofaMap"
    echo "  pip3 install -r requirements.txt"
    echo "  python3 fofamap.py init"
    echo ""
    echo "FOFA credentials stay in FofaMap's config/settings.yaml."
    echo "Shodan can use config/settings.yaml or SHODAN_API_KEY."
    echo "To use environment injection for Shodan:"
    echo "  export SHODAN_API_KEY=\"your-shodan-api-key\""
    echo ""
    echo "Then add this to your Claude Code settings:"
    echo ""
    echo "  claude config edit"
    echo ""
    echo "Then add to the mcpServers section:"
    cat "${SCRIPT_DIR}/mcp/fofamap-client/config.json" | grep -A 8 '"fofamap"'
    echo ""
    echo "Replace /absolute/path/to/FofaMap/mcp_server.py with your local FofaMap path."
    echo ""
    echo "This is an optional external Claude MCP capability only."
    echo "It does not automatically integrate with /recon, /surface, /autopilot, or agent.py."
    echo ""
fi

echo "Repo-local runtime:"
echo "  Claude Code should be launched from this repo so tools/ and memory/ paths resolve."
echo "  cd ${SCRIPT_DIR}"
echo "  claude"
echo ""
echo "Optional config:"
echo "  cp ${SCRIPT_DIR}/config.example.json ${SCRIPT_DIR}/config.json"
echo "  # adjust API keys, output paths, and other local preferences as needed"
echo ""
echo "Start hunting:"
echo "  claude"
echo "  /recon target.com"
echo "  /hunt target.com"
echo "  /source-hunt target.com --repo-path /path/to/local/repo"
echo "  /autopilot target.com --normal"
echo "  /sync-check"
echo ""
echo "Direct scanner controls through the installed /hunt workflow:"
echo "  python3 tools/hunt.py --target target.com --scan-only --scanner-full"
echo "  # Optional per-invocation exclusion only when explicitly requested now:"
echo "  python3 tools/hunt.py --target target.com --scan-only --scanner-skip module1,module2"
echo ""
echo "Specialized agents:"
echo "  Installed under ${AGENTS_DIR}"
