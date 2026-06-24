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


def test_hidden_sqli_surfaces_are_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")

    assert "knowledge/cards/sqli-hidden-surfaces.md" in runtime
    assert "### SQLi Lane Flow" in web2
    assert "Header lane" in web2
    assert "Path lane" in web2
    assert "Hidden-param lane" in web2
    assert "knowledge/cards/sqli-hidden-surfaces.md" in bug_bounty
    assert "Hidden SQLi surface" in methodology
