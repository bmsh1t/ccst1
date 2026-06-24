"""Regression tests for high-intensity hunting posture documentation."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_hunting_rules_define_high_intensity_without_high_pressure():
    text = _read("rules/hunting.md")

    assert "## High-Intensity Hunting Posture" in text
    assert "High intensity means deeper reasoning" in text
    assert "never means high-pressure traffic" in text
    assert "bypassing `rules/red-lines.md`" in text
    assert "Do not use \"scanned\" as a synonym for \"tested.\"" in text


def test_hunting_rules_tie_depth_to_coverage_and_actor_matrix():
    text = _read("rules/hunting.md")

    assert "Before finish, handoff, or \"no finding\" summaries" in text
    assert "coverage matrix" in text
    assert "Evidence Ledger" in text
    assert "actor/object/replay gaps" in text
    assert "anonymous, owner, peer, low_role, cross_tenant" in text


def test_hunting_rules_use_value_first_comprehensive_vuln_coverage():
    text = _read("rules/hunting.md")

    assert "Value-first coverage model" in text
    assert "Do not prioritize by a fixed favorite bug class" in text
    assert "SQLi, NoSQLi, command injection, SSTI, RCE" in text
    assert "SSRF, XXE, LFI/RFI/path traversal" in text
    assert "unsafe deserialization" in text
    assert "Browser-observed APIs, JS/source-derived routes" in text
    assert "evidence sources" in text


def test_bb_methodology_references_high_intensity_hunting_posture():
    text = _read("skills/bb-methodology/SKILL.md")

    assert "rules/hunting.md#high-intensity-hunting-posture" in text
    assert "不来自高压流量、凑步骤或破坏性利用" in text
    assert "高价值漏洞族覆盖模型" in text
    assert "不固定偏向某几个漏洞类别" in text
