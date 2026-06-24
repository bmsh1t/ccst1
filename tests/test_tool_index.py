"""Tests for docs/tool-index.md — Claude CLI quick-reference completeness."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_INDEX = REPO_ROOT / "docs" / "tool-index.md"
AUTOPILOT_MD = REPO_ROOT / "commands" / "autopilot.md"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"


def test_tool_index_exists():
    assert TOOL_INDEX.is_file(), "docs/tool-index.md must exist"


def test_tool_index_lists_at_least_60_tools():
    text = TOOL_INDEX.read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if line.startswith("| `tools/")]
    assert len(rows) >= 60, f"tool-index must list ≥60 tools, found {len(rows)}"


def test_tool_index_categories_present():
    text = TOOL_INDEX.read_text(encoding="utf-8")
    for section in (
        "## 1. Recon",
        "## 2. Discovery",
        "## 3. Vuln",
        "## 4. Browser",
        "## 5. Auth",
        "## 6. OAST",
        "## 7. Hunt orchestration",
    ):
        assert section in text, f"missing section: {section!r}"


def test_tool_index_quick_pick_table_present():
    text = TOOL_INDEX.read_text(encoding="utf-8")
    assert "Quick-pick by symptom" in text


def test_tool_index_flags_underused_tools():
    text = TOOL_INDEX.read_text(encoding="utf-8")
    # The four underused-tool surfaces we explicitly want Claude aware of.
    for forgotten in ("h1_race", "h1_oauth_tester", "h1_mutation_idor", "zero_day_fuzzer"):
        assert forgotten in text, f"underused tool not surfaced: {forgotten}"


def test_autopilot_md_references_tool_index():
    text = AUTOPILOT_MD.read_text(encoding="utf-8")
    assert "tool-index.md" in text, "commands/autopilot.md must reference tool-index.md"


def test_claude_md_canonical_references_includes_tool_index():
    text = CLAUDE_MD.read_text(encoding="utf-8")
    assert "tool-index.md" in text, "CLAUDE.md Canonical References must include tool-index.md"


def test_tool_index_entries_under_120_chars():
    """One-line descriptions should stay terse so Claude can scan fast."""
    text = TOOL_INDEX.read_text(encoding="utf-8")
    over_long = [
        line
        for line in text.splitlines()
        if line.startswith("| `tools/") and len(line) > 200
    ]
    assert not over_long, f"rows too long: {over_long[:3]}"
