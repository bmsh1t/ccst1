"""Regression tests for skill responsibility boundaries."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_bug_bounty_skill_routes_methodology_instead_of_duplicating_it():
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")

    assert "# Methodology Boundary" in bug_bounty
    assert "skills/bb-methodology/SKILL.md" in bug_bounty
    assert "# TOP 1% HACKER MINDSET" not in bug_bounty
    assert "## PART 1: MINDSET" in methodology
    assert "### Phase 0: SESSION START" in methodology


def test_triage_validation_keeps_seven_question_gate_shape():
    text = (REPO_ROOT / "skills" / "triage-validation" / "SKILL.md").read_text(encoding="utf-8")

    assert "7-Question Gate" in text
    assert "### Q7b: Verify the identity boundary" in text
    assert "### Q8:" not in text
