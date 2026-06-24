"""Tests for the working_hypothesis discipline in agent.py system prompt.

Discipline (per PRD C4): assertions only verify ANCHOR FIELD NAMES are
present in the produced prompt. NO assertion on specific sentences /
phrasing. This lets the prompt evolve freely without test churn.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent import _build_agent_system


# Anchor field names that MUST appear verbatim in the produced system
# prompt. Contract 1 in design.md. Tests fail loudly if any name is
# dropped during prompt evolution.
_REQUIRED_ANCHORS = (
    "working_hypothesis",
    "evidence_for",
    "evidence_against",
    "next_question",
    "expected_learning",
    "kill_condition",
)


class TestWorkingHypothesisAnchors:

    def test_anchors_present_in_default_prompt(self):
        prompt = _build_agent_system()
        for anchor in _REQUIRED_ANCHORS:
            assert anchor in prompt, f"missing anchor field name: {anchor}"

    def test_anchors_present_in_paranoid_mode(self):
        prompt = _build_agent_system(autopilot_mode="paranoid")
        for anchor in _REQUIRED_ANCHORS:
            assert anchor in prompt

    def test_anchors_present_in_normal_mode(self):
        prompt = _build_agent_system(autopilot_mode="normal")
        for anchor in _REQUIRED_ANCHORS:
            assert anchor in prompt

    def test_anchors_present_in_yolo_mode(self):
        prompt = _build_agent_system(autopilot_mode="yolo")
        for anchor in _REQUIRED_ANCHORS:
            assert anchor in prompt

    def test_anchors_present_in_quick_mode(self):
        prompt = _build_agent_system(quick_mode=True)
        for anchor in _REQUIRED_ANCHORS:
            assert anchor in prompt

    def test_anchors_present_in_ctf_mode(self):
        prompt = _build_agent_system(ctf_mode=True)
        for anchor in _REQUIRED_ANCHORS:
            assert anchor in prompt


class TestWorkingHypothesisSection:

    def test_section_heading_present(self):
        """Section label must exist so operators can locate the discipline."""
        prompt = _build_agent_system()
        assert "WORKING HYPOTHESIS" in prompt.upper()

    def test_skip_clause_present(self):
        """The mechanical-obvious skip rule must exist so the discipline is
        not abused as a finish-without-thinking gate. We check for the
        key idea (a skip clause exists) without locking specific wording."""
        prompt = _build_agent_system()
        # Either of these phrasings is acceptable.
        assert "no hypothesis update" in prompt.lower() or "may omit emission" in prompt.lower()

    def test_custom_probe_allowance_present(self):
        """Agent must be told explicitly that custom probes are allowed,
        otherwise the predefined tool list becomes an implicit options[]
        cage. Checks for the structural idea, not specific wording."""
        prompt = _build_agent_system()
        lowered = prompt.lower()
        # Two ideas must both appear in the same section: 'custom probe' and
        # the freedom phrasing. Both are validated independently to allow
        # the wording to be rephrased.
        assert "custom probe" in lowered
        assert "not in the predefined" in lowered or "explicitly allowed" in lowered


class TestAntiRegression:
    """C4 (PRD): tests must not assert on specific prompt-text substrings
    beyond anchor names. These checks codify that constraint: if a future
    test author wants to pin a sentence, they will see THIS file's pattern
    and follow it instead."""

    def test_anchor_set_is_six(self):
        """If a future PR adds anchors, update this count. If it removes,
        likewise. Lock the canonical set so it does not silently drift."""
        assert len(_REQUIRED_ANCHORS) == 6

    def test_anchor_names_are_snake_case(self):
        """Style invariant — keeps future grep patterns simple."""
        for anchor in _REQUIRED_ANCHORS:
            assert "_" in anchor or anchor.islower()
            assert anchor == anchor.lower()
