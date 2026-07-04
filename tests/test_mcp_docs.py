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
    assert "automatically integrate" in content
    assert "/recon" in content
    assert "/surface" in content
    assert "/autopilot" in content
    assert "claude config edit" in content
    assert "python3 fofamap.py init" in content
    assert "shodan_api_key" in content


def test_jshook_mcp_template_exposes_single_server_with_runtime_env_passthrough():
    config = json.loads((REPO_ROOT / "mcp" / "jshook-client" / "config.json").read_text(encoding="utf-8"))

    server = config["mcpServers"]["jshook"]
    assert server["command"] == "node"
    assert server["args"] == ["/absolute/path/to/jshook-mcp/dist/server.js"]
    assert server["env"]["JSHOOK_TARGET"] == "${JSHOOK_TARGET}"
    assert server["env"]["JSHOOK_PROFILE_DIR"] == "${JSHOOK_PROFILE_DIR}"


def test_jshook_mcp_docs_explain_scope_and_setup_boundary():
    content = "\n".join(
        (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "CLAUDE.md",
            "install.sh",
            "mcp/jshook-client/README.md",
        )
    ).lower()

    assert "jshook mcp" in content
    assert "optional external" in content
    assert "automatically integrate" in content
    assert "/recon" in content
    assert "/surface" in content
    assert "/autopilot" in content
    assert "claude config edit" in content
    assert "jshook_target" in content
    assert "jshook-mcp" in content
