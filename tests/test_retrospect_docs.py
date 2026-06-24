"""Regression tests for retrospective automation prompts."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_retrospect_command_is_a_routing_decision_not_plain_summary():
    text = _read("commands/retrospect.md")

    assert "分流决策器" in text
    assert "RETROSPECTIVE DECISION" in text
    assert "python3 tools/autopilot_state.py --target <target> --json" in text
    assert "python3 tools/surface.py --target <target> --json" in text
    assert "python3 tools/checkpoint.py --target <target> --json" in text
    assert "python3 tools/coverage_matrix.py rebuild --target <target>" in text
    assert "python3 tools/coverage_matrix.py find-gaps --target <target>" in text
    assert "source checkpoint:" in text
    assert "Target write-back:" in text
    assert "Knowledge promotions:" in text
    assert "Skill changes:" in text
    assert "Rule changes:" in text
    assert "safe auto-write:" in text
    assert "needs human review:" in text


def test_retrospect_command_requires_proposed_entries_and_human_review_boundary():
    text = _read("commands/retrospect.md")

    assert "Evidence pattern:" in text
    assert "Why it matters:" in text
    assert "Next action:" in text
    assert "Stop condition:" in text
    assert "Validation requirement:" in text
    assert "知识库、Skills、Rules 默认只输出建议，不自动改文件" in text
    assert "目标层写回可以自动执行" in text


def test_retrospective_rule_defines_safe_automation_boundary():
    text = _read("rules/retrospective.md")

    assert "自动证据读取" in text
    assert "RETROSPECTIVE DECISION" in text
    assert "tools/checkpoint.py" in text
    assert "target_write_back" in text
    assert "tools/coverage_matrix.py rebuild --target <target>" in text
    assert "## 自动化边界" in text
    assert "写目标层 lead / next / dead-end / handoff" in text
    assert "修改知识卡" in text
    assert "修改 Skill" in text
    assert "修改 Rules" in text
    assert "只建议 patch，需人工确认" in text
    assert "删除或覆盖已有经验" in text


def test_retrospective_rule_forces_specific_targets_for_promotions():
    text = _read("rules/retrospective.md")

    for card in (
        "knowledge/cards/api-idor.md",
        "knowledge/cards/auth-access.md",
        "knowledge/cards/ssrf-url-fetch.md",
        "knowledge/cards/graphql.md",
        "knowledge/cards/upload-parser.md",
        "knowledge/cards/race-conditions.md",
        "knowledge/cards/dead-ends.md",
        "knowledge/cards/coverage-prompts.md",
    ):
        assert card in text

    assert "target skill" in text
    assert "target rule" in text
    assert "为什么不是知识库或 Skill 问题" in text
