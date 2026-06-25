"""Regression tests for skill responsibility boundaries."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

ARTICLE_DERIVED_CARDS = [
    "knowledge/cards/auth-hidden-switches.md",
    "knowledge/cards/missing-parameter-discovery.md",
    "knowledge/cards/path-pattern-management-exposure.md",
    "knowledge/cards/sqli-hidden-surfaces.md",
]


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
    assert "示例输入面按证据选择，不是固定顺序" in web2
    assert "not a fixed checklist" in web2
    assert "knowledge/cards/sqli-hidden-surfaces.md" in bug_bounty
    assert "Hidden SQLi surface" in methodology


def test_hidden_auth_switches_are_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")

    assert "knowledge/cards/auth-hidden-switches.md" in runtime
    assert "### Hidden Auth Switch Lane" in web2
    assert "owned/test account baseline" in web2
    assert "Do not default to password brute force" in web2
    assert "skills/credential-attack/" in web2
    assert "manual `/spray`" in web2
    assert "### Path 8: Hidden Auth Switches" in bug_bounty
    assert "context-pack auth-hidden" in methodology


def test_missing_parameter_discovery_is_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    recon = (REPO_ROOT / "skills" / "web2-recon" / "SKILL.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")

    assert "knowledge/cards/missing-parameter-discovery.md" in runtime
    assert "### Missing Parameter Signal / Target-Specific Params" in recon
    assert "### Missing Parameter Signal Lane" in web2
    assert "Do not bulk-enumerate real users" in web2
    assert "### Missing Parameter Signal" in bug_bounty
    assert "context-pack missing-param" in methodology


def test_path_pattern_management_exposure_is_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    recon = (REPO_ROOT / "skills" / "web2-recon" / "SKILL.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")

    assert "knowledge/cards/path-pattern-management-exposure.md" in runtime
    assert "### Pattern-Based Directory Fuzzing" in recon
    assert "### Management Exposure Lane" in web2
    assert "Do not import keys into cloud panels" in web2
    assert "### Path Pattern / Management Exposure" in bug_bounty
    assert "context-pack path-pattern" in methodology


def test_controlled_credential_testing_is_not_an_absolute_red_line():
    red_lines = (REPO_ROOT / "rules" / "red-lines.md").read_text(encoding="utf-8")
    router = (REPO_ROOT / "rules" / "playbook-router.md").read_text(encoding="utf-8")

    assert "受控口令测试不是红线" in red_lines
    assert "口令爆破、默认凭据检查、password spray 本身不是绝对红线" in red_lines
    assert "手动流程" in red_lines
    assert "弱口令爆破不是绝对红线" in router


def test_article_derived_cards_are_native_recall_cards():
    banned_terms = ["本文", "原文", "这篇", "只吸收", "不吸收", "Knowledge card role", "recall/association"]

    for rel_path in ARTICLE_DERIVED_CARDS:
        text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")

        assert "## 能力定位" in text
        assert "候选假设" in text
        assert "发散问题" in text
        assert "最小验证提示" in text
        for term in banned_terms:
            assert term not in text
