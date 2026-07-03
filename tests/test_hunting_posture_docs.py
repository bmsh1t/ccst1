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


def test_runtime_protocol_preserves_discovery_driven_exploration():
    text = _read("skills/runtime-protocol.md")

    assert "Discovery / Exploitation / Validation modes" in text
    assert "Evidence-driven depth does not mean evidence-only testing" in text
    assert "Discovery-driven discovery" in text
    assert "actively generate new evidence" in text
    assert "AI override" in text
    assert "red-line status" in text


def test_autopilot_docs_keep_discovery_as_first_class_mode():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    for text in (command, agent):
        assert "Discovery / Exploitation / Validation Modes" in text
        assert "Evidence-driven depth does not mean evidence-only testing" in text
        assert "actively generate new evidence" in text
        assert "browser-observed APIs" in text
        assert "JS/source-derived routes" in text
        assert "component/CVE intelligence" in text
        assert "AI override" in text
        assert "not hard rails" in text


def test_case_state_first_docs_do_not_make_it_a_hard_rail():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")
    validate = _read("commands/validate.md")
    hunting = _read("rules/hunting.md")

    for text in (command, agent):
        assert "Case-State First, Not Case-State Only" in text
        assert "case-state-validation" in text
        assert "case-state-enrichment" in text
        assert "not a scope gate" in text
        assert "AI override" in text

    assert "Case-State-First Validation" in validate
    assert "runtime memory that feeds deterministic evidence runners" in validate
    assert "not a substitute for `/validate`" in validate
    assert "complete-backlog" in validate

    assert "Target Case State" in hunting
    assert "not a scope gate or" in hunting
    assert "bug-class selector" in hunting
    assert "without treating missing case state as a blocker" in hunting


def test_coverage_gate_treats_underexplored_unknown_as_gap():
    text = _read("rules/coverage-gate.md")

    assert "## Discovery Gap" in text
    assert "`unknown` is not a final completion state" in text
    assert "surface is underexplored" in text
    assert "actively generate new evidence" in text
    assert "不能把它写成 `tested`" in text
