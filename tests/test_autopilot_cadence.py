"""Compact prompt contract for commands/autopilot.md and agents/autopilot.md.

The old Mandatory Reflection Cadence was intentionally moved out of the main
prompt. The new contract keeps slash-command/agent prompts short and points
Claude at canonical runtime files/tools instead of embedding long checklists.
"""
from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
COMMAND = REPO_ROOT / "commands" / "autopilot.md"
AGENT = REPO_ROOT / "agents" / "autopilot.md"
LANES = REPO_ROOT / "docs" / "autopilot-lanes.md"
RUNTIME = REPO_ROOT / "skills" / "runtime-protocol.md"


def _read(path: pathlib.Path) -> str:
    assert path.exists(), f"{path} missing"
    return path.read_text(encoding="utf-8")


def test_autopilot_routes_lane_detail_on_demand():
    """The controller routes lane detail instead of embedding another playbook."""
    command = _read(COMMAND)
    agent = _read(AGENT)

    assert "state.lane_contract.ref" in command
    assert "docs/autopilot-lanes.md" in command
    assert "read only" in " ".join(command.split()).lower()
    assert agent  # optional specialist prompt remains a separate entry point


def test_autopilot_references_canonical_runtime_layers():
    command = _read(COMMAND)
    agent = _read(AGENT)
    combined = "\n".join((command, agent, _read(LANES), _read(RUNTIME)))

    for marker in (
        "tools/context_pack.py",
        "skills/runtime-protocol.md",
        "rules/red-lines.md",
        "rules/coverage-gate.md",
        "rules/hunting.md",
        "knowledge/index.md",
        "docs/tool-index.md",
        "tools/action_queue.py",
        "tools/coverage_matrix.py",
        "tools/evidence_ledger.py",
    ):
        assert marker in combined, f"missing canonical reference: {marker}"


def test_autopilot_uses_context_pack_reference_hints_without_embedding_tables():
    command = _read(COMMAND)
    agent = _read(AGENT)
    combined = f"{command}\n{agent}"

    assert "reference_hints" in combined
    assert "on-demand references" in combined

    embedded_table_markers = (
        "SSRF IP Bypass Table",
        "Open Redirect Bypass Table",
        "File Upload Bypass Table",
        "Modern SQLi WAF Bypass",
        "XSS Sinks (grep for these)",
    )
    for marker in embedded_table_markers:
        assert marker not in combined


def test_autopilot_keeps_decision_loop_without_legacy_cadence_bulk():
    command = _read(COMMAND)
    flat = " ".join(f"{command}\n{_read(LANES)}\n{_read(RUNTIME)}".split())

    for marker in (
        "Expert Hunter Autopilot",
        "fresh: TARGET -> RECON -> BUSINESS/CROWN JEWELS -> SURFACE/CONTEXT -> BROWSER/SOURCE/JS TRUTH -> SCANNER QUICK -> WORKFLOW",
        "LOAD -> REVIEW EVIDENCE -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT",
        "State Consumption Loop",
        "Execution Invariants",
        "Discovery / Exploitation / Validation modes",
        "state.lane_contract.ref",
        "Credential Lane",
        "Transition And Finish Contract",
    ):
        assert marker in flat

    # Do not reintroduce the old prompt-heavy cadence/checklist block.
    legacy_markers = (
        "### After every tool result",
        "[H] hypothesis alive?",
        "[N] next_question?",
        "[P] sibling/bypass/chain?",
        "## Step 0.5: Target Fingerprint",
        "## Step 0.6: Stack Recall",
    )
    for marker in legacy_markers:
        assert marker not in command


def test_expert_hunter_startup_is_state_first_then_evidence_driven():
    command = _read(COMMAND)
    agent = _read(AGENT)
    combined = f"{command}\n{agent}"

    for marker in (
        "Super-pentester priority",
        "business impact > workflow evidence > crown-jewel",
        "Every invocation is state-first",
        "scanner quick",
        "breadth sensor",
        "advisory lead source",
        "scanner-negative is not completion",
        "Branch only after that state",
        "Four-layer memory is the external brain, not the steering wheel",
        "BUSINESS/CROWN JEWELS",
        "MINIMAL PROOF",
        "-> CHAIN ->",
        "do not let them drive first contact",
    ):
        assert marker in combined

    agent_four_layer = agent.split("## Four-Layer Runtime", 1)[1].split(
        "## Case-State First", 1
    )[0]
    assert "tools/coverage_matrix.py rebuild --target <target>" not in agent_four_layer
    assert "tools/coverage_matrix.py find-gaps --target <target>" not in agent_four_layer
    assert "tools/checkpoint.py --target <target>" not in agent_four_layer


def test_deep_mode_points_to_coverage_tools_instead_of_embedded_lab_fixtures():
    command = _read(COMMAND)
    hunting = _read(REPO_ROOT / "rules" / "hunting.md")

    assert "`--deep` is a value-first comprehensive depth flag" in command
    assert "rules/hunting.md#broad-scanner-input-and-completion-contract" in command
    assert "tools/coverage_matrix.py find-gaps" in command
    assert "tools/action_queue.py" in command
    assert "High-Intensity Hunting Posture" in hunting
    assert "Value-first coverage model" in hunting

    # Cadence lab fixtures are no longer required for the compact prompt model.
    assert "evidence/cadence-labs" not in command


def test_compact_transition_contract_preserves_cadence_and_single_specialist_budget():
    command = _read(COMMAND)
    agent = _read(AGENT)
    combined = f"{command}\n{agent}"

    for marker in (
        "## Transition And Finish Contract",
        "after each substantive state change",
        "coherent lane batch",
        "blocker/handoff/finish",
        "bounded evidence-fit sibling or chain",
        "401/403/404/405/415",
        "three homogeneous no-information results",
        "rotating form/session token",
    ):
        assert marker in combined

    assert "After using one, this invocation cannot call a second specialist." in command
