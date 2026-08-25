"""Regression tests for the Claude CLI Business Model read contract."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


class TestBusinessModelInAutopilotCommand:
    def _autopilot_md(self) -> str:
        return (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")

    def test_step_0_heading_includes_business_model(self):
        assert "Business Model Read" in self._autopilot_md()

    def test_inline_business_model_contract_is_self_contained(self):
        text = self._autopilot_md()
        section = text.split("Business Model Read:", 1)[1].split("Promote Lead", 1)[0]
        assert "business_model.md" in section
        assert "after fresh Recon starts" in section
        assert "30 days" in section

    def test_no_taxonomy_enumeration_added(self):
        text = self._autopilot_md().lower()
        for combo in (
            ("onboarding", "checkout", "payout", "refund"),
            ("cross-tenant", "cross-account", "cross-role"),
        ):
            assert sum(token in text for token in combo) < len(combo)
