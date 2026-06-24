"""Regression tests for optional MCP integration docs."""

from pathlib import Path
import json


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_fofamap_mcp_template_exposes_single_server_with_shodan_env_passthrough():
    config = json.loads((REPO_ROOT / "mcp" / "fofamap-client" / "config.json").read_text(encoding="utf-8"))

    server = config["mcpServers"]["fofamap"]
    assert server["command"] == "python3"
    assert server["args"] == ["/absolute/path/to/FofaMap/mcp_server.py"]
    assert server["env"]["SHODAN_API_KEY"] == "${SHODAN_API_KEY}"


def test_fofamap_mcp_docs_explain_scope_and_setup_boundary():
    content = "\n".join(
        (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "CLAUDE.md",
            "install.sh",
            "mcp/fofamap-client/README.md",
        )
    ).lower()

    assert "fofamap mcp (fofa + shodan)" in content
    assert "optional external" in content
    assert "does **not** automatically integrate with `/recon`, `/surface`, `/autopilot`" in content
    assert "claude config edit" in content
    assert "python3 fofamap.py init" in content
    assert "shodan_api_key" in content
