"""Regression tests for high-intensity hunting posture documentation."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_hunting_rules_define_high_intensity_without_high_pressure():
    text = _read("rules/hunting.md")

    assert "## High-Intensity Hunting Posture" in text
    assert "High intensity means deeper reasoning" in text
    assert "It does not relax any owner boundary above" in text
    assert "`rules/red-lines.md` owns concrete side-effect decisions" in text
    assert "`rules/coverage-gate.md` owns lifecycle names" in text


def test_hunting_rules_tie_depth_to_coverage_and_actor_matrix():
    text = _read("rules/hunting.md")

    assert "family/actor coverage states" in text
    assert "Evidence Ledger" in text
    assert "all finish/handoff/no-finding claims" in text
    assert "rules/coverage-gate.md" in text


def test_hunting_rules_delegate_lifecycle_and_side_effect_owners():
    text = _read("rules/hunting.md")

    for owner in (
        "`CLAUDE.md` owns target context",
        "`rules/red-lines.md` owns concrete side-effect decisions",
        "`rules/coverage-gate.md` owns lifecycle names",
        "`rules/tool-ai-boundary.md` owns the AI/tool split",
        "`skills/runtime-protocol.md` owns mode transitions",
        "`commands/autopilot.md` owns inline control",
        "`skills/triage-validation/SKILL.md` owns candidate proof",
        "`rules/reporting.md` owns reports",
    ):
        assert owner in text
    assert "`docs/autopilot-lanes.md`" in text


def test_hunting_rules_keep_value_first_priorities_without_copying_coverage_owner():
    text = _read("rules/hunting.md")

    assert "Value-first coverage model" in text
    assert "Do not prioritize by a fixed favorite bug class" in text
    assert "Browser-observed APIs, JS/source-derived routes" in text
    assert "evidence sources" in text
    assert "identity/access, injection/execution" in text
    assert "infrastructure/supply-chain families" in text
    assert "not an exhaustive capability boundary" in text
    assert "Map crown jewels and business boundaries" in text
    assert "Recent release or commit evidence may raise priority" in text
    assert "Use `rules/coverage-gate.md` for family/actor coverage states" in text


def test_bb_methodology_references_high_intensity_hunting_posture():
    text = _read("skills/bb-methodology/SKILL.md")

    assert "rules/hunting.md#high-intensity-hunting-posture" in text
    assert "角色/对象差异、边界推理和复盘" in text
    assert "不来自高压流量、凑步骤或破坏性利用" not in text
    assert "高价值漏洞族覆盖模型" in text
    assert "不固定偏向某几个漏洞类别" in text


def test_bb_methodology_keeps_developer_view_recall_soft_and_target_specific():
    text = _read("skills/bb-methodology/SKILL.md")

    assert "### Developer-View Pre-Hunt Recall" in text
    for marker in (
        "mental model",
        "crown jewel",
        "developer empathy",
        "trust boundaries",
        "Feature over endpoint",
        "Authorization inconsistency",
        "Think second-order",
        "Compare clients and diffs",
        "Keep the checklist soft",
        "What is the business model",
        "What stack, authentication model",
        "What changed recently",
        "Which two actor",
        "What is today's highest-information question",
        "goal`, `known_facts`, `hypothesis`",
        "fixed vulnerability list",
    ):
        assert marker in text
    assert "not a mandatory" in text


def test_autopilot_references_developer_view_recall_without_new_owner():
    text = _read("commands/autopilot.md")

    assert "Developer-View Pre-Hunt Recall" in text
    assert "skills/bb-methodology/SKILL.md" in text
    assert "soft reasoning prompt" in text
    assert "second gate" in text
    assert "Queue action list" in text


def test_runtime_protocol_preserves_discovery_driven_exploration():
    text = _read("skills/runtime-protocol.md")

    assert "Discovery / Exploitation / Validation modes" in text
    assert "Evidence-driven depth does not mean evidence-only testing" in text
    assert "Discovery-driven discovery" in text
    assert "actively generate new evidence" in text
    assert "AI selection / override" in text


def test_autopilot_docs_keep_discovery_as_first_class_mode():
    command = _read("commands/autopilot.md") + _read("skills/runtime-protocol.md")
    agent = _read("agents/autopilot.md")
    command_lower = command.lower()

    assert "Discovery / Exploitation / Validation modes" in command
    assert "evidence-driven depth does not" in command_lower
    assert "actively generate new evidence" in command_lower
    assert "AI selection / override" in command
    assert "skills/runtime-protocol.md" in command
    for marker in (
        "Evidence-driven depth does not mean evidence-only testing",
        "browser-observed APIs",
        "JS/source-derived routes",
        "component/CVE intelligence",
        "not hard rails",
    ):
        assert marker in agent


def test_case_state_first_docs_do_not_make_it_a_hard_rail():
    command = _read("commands/autopilot.md") + _read("docs/autopilot-lanes.md")
    agent = _read("agents/autopilot.md")
    validate = _read("commands/validate.md")
    hunting = _read("rules/hunting.md")

    assert "Case-State First, Not Case-State Only" in command
    assert "case-state-validation" in command
    assert "case-state-enrichment" in command
    assert "not a scope gate" in command
    assert "AI override" in command
    for marker in (
        "Case-State First, Not Case-State Only",
        "case-state-validation",
        "case-state-enrichment",
        "not a scope gate",
        "AI override",
    ):
        assert marker in agent

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


def test_phase_rotation_and_triage_use_observable_progress_not_clock_rules():
    methodology = _read("skills/bb-methodology/SKILL.md")
    hunting = _read("rules/hunting.md")
    triage = _read("skills/triage-validation/SKILL.md")
    chain = _read("commands/chain.md") + _read("agents/chain-builder.md")

    for text in (methodology, hunting):
        assert "progress fingerprint" in text
        assert "evidence delta" in text
        assert "owner budget" in text
        assert "prerequisite" in text
        assert "Elapsed time alone" in text

    for marker in (
        "evidence gates, not a timer",
        "Elapsed time alone never makes a Candidate report-ready",
        "Evidence-completeness rule",
        "Repeated bounded failure",
    ):
        assert marker in triage
    for forbidden in ("5-minute rule", "30+ min", "2 minutes", "5 minutes", "10 minutes"):
        assert forbidden not in triage

    assert "Evidence-Bounded Transition Rules" in chain
    assert "progress fingerprint repeats" in chain
    assert "20-minute" not in chain
    assert "30+ min" not in chain


def test_coverage_gate_requires_three_axis_feature_workflow_closure():
    text = _read("rules/coverage-gate.md")

    assert "## Feature / Workflow Closure" in text
    assert "Before any feature or workflow is summarized as `tested`" in text
    assert "Input surface" in text
    assert "Behavior/state surface" in text
    assert "Validation depth" in text
    assert "including whether only one variant was tried" in text
    assert "Do not add a parallel coverage state or schema" in text
