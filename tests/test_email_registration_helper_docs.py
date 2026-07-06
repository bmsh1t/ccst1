"""Regression tests for optional email verification helper documentation."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = "/root/tool/aitool/zocom/mail_receiver.py"


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_auth_sessions_documents_optional_mail_receiver_setup():
    text = _read("docs/auth-sessions.md")

    assert "Optional test-account email verification" in text
    assert HELPER in text
    assert "self-owned test" in text
    assert "account setup / case-state enrichment" in text
    assert ".private/<target>.json" in text
    assert "case_state.json" in text


def test_autopilot_mentions_mail_receiver_without_turning_it_into_attack_lane():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    for text in (command, agent):
        assert HELPER in text
        assert "self-owned" in text
        assert "setup aid" in text
        assert ".private/" in text
        assert "case_state" in text

    combined = f"{command}\n{agent}"
    assert "not a default brute-force" in combined
    assert "stop-on-hit" in combined
