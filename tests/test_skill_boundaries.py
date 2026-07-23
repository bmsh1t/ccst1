"""Regression tests for skill responsibility boundaries."""

import math
import re
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
    assert "Q1-Q5 failure, or Q7 with no valid chain path → **DO_NOT_REPORT**" in text
    assert "Q6 proves only a lower impact → **DOWNGRADE**" in text
    assert "Q7 has a concrete but unproven connector → **CHAIN_REQUIRED**" in text
    assert "All required evidence passes → **REPORT**" in text


def test_triage_validation_routes_chain_eligible_never_submit_items_by_precedence():
    text = (REPO_ROOT / "skills" / "triage-validation" / "SKILL.md").read_text(encoding="utf-8")

    assert "route with this precedence" in text
    assert "candidate already demonstrates the full chain end to end" in text
    assert "→ **REPORT** at the chained severity" in text
    assert "concrete next hop exists" in text
    assert "→ **CHAIN_REQUIRED**, not DO_NOT_REPORT" in text
    assert '"Standalone / alone" in the NEVER SUBMIT list' in text
    assert "it does not forbid the chained finding" in text
    assert "demonstrated chain → REPORT" in text
    assert "concrete-but-unbuilt chain → CHAIN_REQUIRED" in text
    assert "bare primitive with no next hop" in text
    assert "DO_NOT_REPORT" in text


def _cvss31_score(vector: str) -> float:
    """按 CVSS 3.1 基础分公式计算 vector，避免文档分数与向量再次漂移。"""
    metrics = dict(part.split(":", 1) for part in vector.split("/"))
    scope_changed = metrics["S"] == "C"
    weights = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    privilege_weights = (
        {"N": 0.85, "L": 0.68, "H": 0.5}
        if scope_changed
        else {"N": 0.85, "L": 0.62, "H": 0.27}
    )

    confidentiality = weights["CIA"][metrics["C"]]
    integrity = weights["CIA"][metrics["I"]]
    availability = weights["CIA"][metrics["A"]]
    impact_subscore = 1 - (
        (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )
    if scope_changed:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (
            impact_subscore - 0.02
        ) ** 15
    else:
        impact = 6.42 * impact_subscore

    if impact <= 0:
        return 0.0
    exploitability = (
        8.22
        * weights["AV"][metrics["AV"]]
        * weights["AC"][metrics["AC"]]
        * privilege_weights[metrics["PR"]]
        * weights["UI"][metrics["UI"]]
    )
    raw_score = (
        min(1.08 * (impact + exploitability), 10)
        if scope_changed
        else min(impact + exploitability, 10)
    )
    return math.ceil((raw_score - 1e-10) * 10) / 10


def _cvss31_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def test_triage_validation_cvss31_rows_match_vectors_and_severity():
    text = (REPO_ROOT / "skills" / "triage-validation" / "SKILL.md").read_text(encoding="utf-8")
    rows = re.findall(
        r"^\| (?P<finding>[^|]+?) \| (?P<score>\d+\.\d) \| "
        r"(?P<severity>Critical|High|Medium|Low) \| "
        r"(?P<vector>AV:[^|]+?) \|$",
        text,
        flags=re.MULTILINE,
    )

    assert len(rows) == 9
    for finding, documented_score, documented_severity, vector in rows:
        calculated_score = _cvss31_score(vector.strip())
        assert float(documented_score) == calculated_score, finding
        assert documented_severity == _cvss31_severity(calculated_score), finding


def test_triage_validation_keeps_preseverity_and_retraction_discipline():
    skill = (REPO_ROOT / "skills" / "triage-validation" / "SKILL.md").read_text(encoding="utf-8")
    command = (REPO_ROOT / "commands" / "validate.md").read_text(encoding="utf-8")

    assert "## PRE-SEVERITY GATE" in skill
    assert "Complete chain" in skill
    assert "theoretical blast radius" in skill
    assert "does not erase the Candidate or create Q8" in skill
    assert "## RETRACTION DISCIPLINE" in skill
    assert "validation_status=rejected" in skill
    assert "disproving evidence" in skill
    assert "source_guard" in skill
    assert "单行精确 `quote`" in skill
    assert "skills/triage-validation/SKILL.md" in command
    assert "PRE-SEVERITY GATE" in command
    assert "RETRACTION DISCIPLINE" in command
    assert "**REPORT:**" in command
    assert "**CHAIN_REQUIRED:**" in command
    assert "**DOWNGRADE:**" in command
    assert "**DO_NOT_REPORT:**" in command
    assert "**KILL:**" not in command


def test_payload_reference_requires_stateful_chain_continuity():
    reference = (
        REPO_ROOT / "skills" / "security-arsenal" / "references" / "payload-families.md"
    ).read_text(encoding="utf-8")

    assert "## 状态型链路连续性" in reference
    assert "leak -> use" in reference
    assert "同一进程" in reference
    assert "显式恢复" in reference


def test_hidden_sqli_surfaces_are_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")
    card = (REPO_ROOT / "knowledge" / "cards" / "sqli-hidden-surfaces.md").read_text(encoding="utf-8")

    assert "knowledge/cards/sqli-hidden-surfaces.md" in runtime
    assert "### SQLi Lane Flow" in web2
    assert "示例输入面按证据选择，不是固定顺序" in web2
    assert "not a fixed checklist" in web2
    assert "knowledge/cards/sqli-hidden-surfaces.md" in bug_bounty
    assert "Hidden SQLi surface" in methodology
    assert "## 候选形态示例" in card
    assert "X-Forwarded-For" in card
    assert "sibling 参数复用" in card
    assert "不是固定字典" in card


def test_hidden_auth_switches_are_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")
    card = (REPO_ROOT / "knowledge" / "cards" / "auth-hidden-switches.md").read_text(encoding="utf-8")
    context_pack = (REPO_ROOT / "tools" / "context_pack.py").read_text(encoding="utf-8")

    assert "knowledge/cards/auth-hidden-switches.md" in runtime
    assert "### Hidden Auth Switch Lane" in web2
    assert "owned/test account baseline" in web2
    assert "Do not silently fall into password brute force" in web2
    assert "skills/credential-attack/" in web2
    assert "controlled `/spray`" in web2
    assert "### Path 8: Hidden Auth Switches" in bug_bounty
    assert "context-pack auth-hidden" in methodology
    assert "## 候选形态示例" in card
    assert "soap=true" in card
    assert "isAdmin=true" in card
    assert "不是固定字典" in card
    assert "管理员预留特权参数" in context_pack


def test_access_control_boundary_matrix_is_part_of_skill_flow():
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    card = (REPO_ROOT / "knowledge" / "cards" / "auth-access.md").read_text(encoding="utf-8")
    context_pack = (REPO_ROOT / "tools" / "context_pack.py").read_text(encoding="utf-8")

    assert "### Access-Control Boundary Matrix" in web2
    assert "method diff -> path/header rewrite -> raw replay" in web2
    assert "X-Original-URL" in web2
    assert "Referer" in web2
    assert "Playwright request/raw replay" in web2
    assert "URL-based access 最小验证" in card
    assert "Referer-based access 最小验证" in card
    assert "raw replay" in card
    assert "浏览器 fetch 不能设置受限头时不要据此停止" in context_pack


def test_boundary_router_uses_distilled_project_shape_not_raw_ctf_refs():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")

    assert "## 2.2 Web 深水区启发式路由" in runtime
    assert "boundary -> baseline -> hidden surface -> bug family -> primitive -> connector -> impact" in runtime
    assert "不照搬 CTF 的 flag 路径" in runtime

    assert "## Boundary-First Pattern Router" in web2
    assert "/root/tool/ccst/ctf-skills" not in web2
    assert "boundary -> baseline -> hidden surface -> bug family" in web2
    assert "primitive -> connector -> impact" in web2
    assert "Source/config/secret/file read signal" in web2
    assert "broad payload spraying" in web2

    assert "### Boundary Pivot Prompts" in methodology
    assert "/root/tool/ccst/ctf-skills" not in methodology
    assert "Primitive:" in web2
    assert "Connector:" in web2
    assert "Do not copy flag" in methodology
    assert "/root/tool/ccst/ctf-skills" not in runtime


def test_layer_placement_standard_keeps_skills_small_and_project_aligned():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")

    assert "## 2.3 层级归属标准" in runtime
    assert "符合当前项目架构" in runtime
    assert "Skill 不是越大越好" in runtime
    assert "会改变执行路线、判断顺序、阶段切换、升级/停止条件" in runtime
    assert "技巧、payload、bypass、案例、经验、发散思路、补充 checklist" in runtime
    assert "`deep_refs`" in runtime
    assert "Tools / action queue" in runtime
    assert "Rules / checks" in runtime
    assert "不确定归属时，先放知识库或 `deep_refs`" in runtime
    assert "不为“让 Skill 知道更多”扩写 Skill" in runtime


def test_missing_parameter_discovery_is_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    recon = (REPO_ROOT / "skills" / "web2-recon" / "SKILL.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")
    card = (REPO_ROOT / "knowledge" / "cards" / "missing-parameter-discovery.md").read_text(encoding="utf-8")

    assert "knowledge/cards/missing-parameter-discovery.md" in runtime
    assert "### Missing Parameter Signal / Target-Specific Params" in recon
    assert "### Missing Parameter Signal Lane" in web2
    assert "Do not bulk-enumerate real users" in web2
    assert "### Missing Parameter Signal" in bug_bounty
    assert "context-pack missing-param" in methodology
    assert "## 候选形态示例" in card
    assert "tenantId" in card
    assert "includeDeleted" in card
    assert "不是固定字典" in card


def test_path_pattern_management_exposure_is_part_of_skill_flow():
    runtime = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    recon = (REPO_ROOT / "skills" / "web2-recon" / "SKILL.md").read_text(encoding="utf-8")
    web2 = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")
    bug_bounty = (REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md").read_text(encoding="utf-8")
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")
    card = (REPO_ROOT / "knowledge" / "cards" / "path-pattern-management-exposure.md").read_text(encoding="utf-8")

    assert "knowledge/cards/path-pattern-management-exposure.md" in runtime
    assert "### Pattern-Based Directory Fuzzing" in recon
    assert "### Management Exposure Lane" in web2
    assert "Do not import keys into cloud panels" in web2
    assert "### Path Pattern / Management Exposure" in bug_bounty
    assert "context-pack path-pattern" in methodology
    assert "## 候选形态示例" in card
    assert "manifest.json" in card
    assert "data/manage-data" in card
    assert "不是固定字典" in card


def test_controlled_credential_testing_is_not_an_absolute_red_line():
    red_lines = (REPO_ROOT / "rules" / "red-lines.md").read_text(encoding="utf-8")
    router = (REPO_ROOT / "rules" / "playbook-router.md").read_text(encoding="utf-8")

    assert "受控口令测试不是红线" in red_lines
    assert "口令爆破、默认凭据检查、password spray 本身不是绝对红线" in red_lines
    assert "`/autopilot`" in red_lines
    assert "可以在证据驱动下选择该 lane" in red_lines
    assert "弱口令爆破不是绝对红线" in router


def test_autopilot_can_select_controlled_credential_lane():
    autopilot = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
    spray = (REPO_ROOT / "commands" / "spray.md").read_text(encoding="utf-8")
    tool_index = (REPO_ROOT / "docs" / "tool-index.md").read_text(encoding="utf-8")

    assert "## Credential Lane" in autopilot
    assert "`/autopilot` may select" in autopilot
    assert "Password brute force, default credential checks, and password spray are not" in autopilot
    assert "Controlled credential spray" in spray
    assert "Credential breakthrough lane selected" in tool_index


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
