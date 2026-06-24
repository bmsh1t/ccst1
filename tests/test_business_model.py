"""Tests for the Step 0 business model directive in agent.py + autopilot.md.

Discipline (per PRD C4): assertions only verify ANCHOR field names /
heading presence / structural ideas. NO assertion on specific sentences.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent import _build_agent_system


# Section headers that must appear in the business_model.md template
# directive. These are the anchors a downstream agent can grep for to
# navigate the document; content under each is free text.
_REQUIRED_BUSINESS_MODEL_HEADERS = (
    "What this company sells",
    "Top 3 revenue-generating workflows",
    "Top 3 brand-damage scenarios",
    "Subdomain / path map to revenue surface",
    "Features added in last 90 days",
)


class TestBusinessModelInSystemPrompt:

    def test_step_0_directive_present(self):
        prompt = _build_agent_system()
        # Heading anchor only — not a specific sentence.
        assert "BUSINESS MODEL" in prompt.upper()

    def test_business_model_filepath_referenced(self):
        """Agent must know where to write the file."""
        prompt = _build_agent_system()
        assert "business_model.md" in prompt
        assert "evidence/" in prompt

    def test_30_day_ttl_present(self):
        """The skip-when-fresh rule must exist to prevent re-running every
        session. Checks for the idea, not the exact phrasing."""
        prompt = _build_agent_system()
        lowered = prompt.lower()
        assert "30 days" in lowered or "30-day" in lowered

    def test_required_section_headers_named(self):
        """The five document section anchors must be named in the prompt
        so the agent produces a navigable document."""
        prompt = _build_agent_system()
        for header in _REQUIRED_BUSINESS_MODEL_HEADERS:
            assert header in prompt, f"missing business_model.md anchor: {header}"

    def test_step_0_before_recon_constraint(self):
        """The directive must indicate Step 0 runs BEFORE run_recon, otherwise
        the timing intent is lost. Idea check, not sentence check."""
        prompt = _build_agent_system()
        lowered = prompt.lower()
        assert "before run_recon" in lowered or "before recon" in lowered

    def test_step_0_present_across_modes(self):
        for mode in ("paranoid", "normal", "yolo"):
            prompt = _build_agent_system(autopilot_mode=mode)
            assert "BUSINESS MODEL" in prompt.upper()
            assert "business_model.md" in prompt


class TestBusinessModelInAutopilotCommand:

    def _autopilot_md(self) -> str:
        path = REPO_ROOT / "commands" / "autopilot.md"
        return path.read_text(encoding="utf-8")

    def test_step_0_heading_includes_business_model(self):
        text = self._autopilot_md()
        # New heading shape must reference Business Model Read.
        assert "Business Model Read" in text

    def test_business_model_pointer_present(self):
        """commands/autopilot.md must point to the agent.py directive
        without duplicating it — checks pointer is present."""
        text = self._autopilot_md()
        assert "business_model.md" in text
        # Pointer to agent.py system prompt presence (idea check)
        lowered = text.lower()
        assert "agent.py" in lowered or "system prompt" in lowered

    def test_no_taxonomy_enumeration_added(self):
        """C1 anti-options[] check: the autopilot.md must NOT enumerate a
        fixed taxonomy of workflows / boundaries / vuln classes for Step 0."""
        text = self._autopilot_md()
        # If the document contains all of these as a single bullet list,
        # that would be a taxonomy enumeration we want to avoid.
        forbidden_combos = [
            ["onboarding", "checkout", "payout", "refund"],
            ["cross-tenant", "cross-account", "cross-role"],
        ]
        for combo in forbidden_combos:
            hits = sum(1 for token in combo if token.lower() in text.lower())
            # All four tokens together would indicate enumeration. Allow at
            # most 2 by accident.
            assert hits < len(combo), (
                f"possible taxonomy enumeration in autopilot.md: {combo}"
            )


class TestAntiRegression:

    def test_working_hypothesis_block_still_present(self):
        """PR-5 must not regress PR-4. Working hypothesis anchors must still
        appear in the system prompt."""
        prompt = _build_agent_system()
        for anchor in (
            "working_hypothesis",
            "next_question",
            "kill_condition",
        ):
            assert anchor in prompt

    def test_step_0_does_not_add_new_finish_blocker(self):
        """C3 (PRD): no new finish blocker added. Step 0 must NOT instruct
        the agent that finish is blocked on business_model.md presence —
        finish is a state check, not a flow gate."""
        prompt = _build_agent_system()
        lowered = prompt.lower()
        # Look for forbidden idioms that would gate finish on Step 0.
        forbidden = (
            "cannot finish without business_model",
            "do not call finish until business_model",
            "finish blocked",
        )
        for phrase in forbidden:
            assert phrase not in lowered, f"forbidden finish-blocker phrase: {phrase}"
