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


def _read(path: pathlib.Path) -> str:
    assert path.exists(), f"{path} missing"
    return path.read_text(encoding="utf-8")


def test_autopilot_prompts_stay_compact():
    """Main prompts should remain routers, not giant embedded playbooks."""
    command = _read(COMMAND)
    agent = _read(AGENT)

    assert len(command.splitlines()) <= 280
    assert len(agent.splitlines()) <= 220


def test_autopilot_references_canonical_runtime_layers():
    command = _read(COMMAND)
    agent = _read(AGENT)
    combined = f"{command}\n{agent}"

    for marker in (
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


def test_autopilot_keeps_decision_loop_without_legacy_cadence_bulk():
    command = _read(COMMAND)
    flat = " ".join(command.split())

    for marker in (
        "LOAD -> RANK -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT",
        "Discovery / Exploitation / Validation Modes",
        "Known Software Intelligence Lane",
        "Deep Mode",
        "Credential Lane",
        "Finish Condition",
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


def test_deep_mode_points_to_coverage_tools_instead_of_embedded_lab_fixtures():
    command = _read(COMMAND)

    assert "Deep Exhaustion Checklist" in command
    assert "python3 tools/coverage_matrix.py rebuild --target target.com" in command
    assert "python3 tools/coverage_matrix.py find-gaps --target target.com" in command
    assert "python3 tools/action_queue.py summary --target target.com" in command

    # Cadence lab fixtures are no longer required for the compact prompt model.
    assert "evidence/cadence-labs" not in command
