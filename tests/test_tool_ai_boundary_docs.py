"""Regression tests for the AI/tool boundary contract."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_tool_ai_boundary_rule_defines_ai_as_judgment_layer():
    text = _read("rules/tool-ai-boundary.md")

    assert "AI judges. Tools preserve evidence." in text
    assert "工具不得最终判断" in text
    assert "advisory hint" in text
    assert "low-priority / reopenable" in text
    assert "no finding proven in this runner scope" in text
    assert "CLI/agent/command 文案必须说明它们只是 advisory hints" in text


def test_autopilot_runtime_references_tool_ai_boundary():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")
    context_loading = _read("rules/context-loading.md")
    tool_index = _read("docs/tool-index.md")

    for text in (command, agent, context_loading, tool_index):
        assert "rules/tool-ai-boundary.md" in text


def test_claude_facing_prompts_do_not_reintroduce_tool_authority_phrases():
    combined = "\n".join(
        _read(path)
        for path in (
            "commands/autopilot.md",
            "commands/surface.md",
            "commands/checkpoint.md",
            "commands/context-pack.md",
            "agents/autopilot.md",
            "agents/recon-ranker.md",
        )
    )

    forbidden = (
        "Kill List (skip)",
        "always P1",
        "score determines priority",
        "tested_clean = safe",
        "scanner-negative = complete",
        "No high-value matrix gap remains",
    )
    for phrase in forbidden:
        assert phrase not in combined

    assert "AI chooses priority" in combined or "AI-selected" in combined
    assert "advisory" in combined
    assert "reopen" in combined
