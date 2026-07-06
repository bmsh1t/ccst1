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
            "commands/js-read.md",
            "commands/pickup.md",
            "agents/autopilot.md",
            "agents/js-reader.md",
            "agents/recon-agent.md",
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
        "prioritized attack surface report",
        "ranked hunting hypotheses",
        "ranked attack-surface leads",
        "current recon ranking",
    )
    for phrase in forbidden:
        assert phrase not in combined

    assert "AI chooses priority" in combined or "AI-selected" in combined
    assert "advisory" in combined
    assert "reopen" in combined


def test_coverage_and_checkpoint_treat_gaps_as_ai_actionable_hints():
    coverage_gate = _read("rules/coverage-gate.md")
    coverage_matrix = _read("tools/coverage_matrix.py")
    checkpoint = _read("commands/checkpoint.md")

    assert "evidence hint ledger" in coverage_gate
    assert "AI-actionable `find-gaps`" in coverage_gate
    assert "raw `find-gaps` 可以被 Claude" in coverage_gate
    assert "not a fixed execution checklist" in coverage_matrix
    assert "which coverage hints still need explanation" in coverage_matrix
    assert "AI-actionable coverage hint" in checkpoint
    assert "有 high-value coverage gap" not in checkpoint


def test_autopilot_flow_uses_review_evidence_not_rank_as_stage():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    assert "LOAD -> REVIEW EVIDENCE -> ENRICH" in command
    assert "LOAD -> REVIEW EVIDENCE -> ENRICH" in agent
    assert "LOAD -> RANK -> ENRICH" not in command
    assert "LOAD -> RANK -> ENRICH" not in agent
