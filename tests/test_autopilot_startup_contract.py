"""Claude CLI `/autopilot` 状态优先与 batch handoff 契约。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_slash_command_reads_state_before_any_long_phase():
    text = _read("commands/autopilot.md")
    startup = text.index("Every invocation is state-first")
    state_read = text.index("python3 tools/autopilot_state.py --target target.com", startup)
    recon = text.index("python3 tools/hunt.py --target target.com --recon-only", state_read)
    surface = text.index("python3 tools/surface.py --target target.com", state_read)
    scan = text.index("python3 tools/hunt.py --target target.com --scan-only --quick", state_read)

    assert state_read < recon < surface < scan
    assert "Runtime phase locks are the final\nduplicate-launch guard" in text


def test_slash_command_limits_batch_to_recon_and_single_domain_handoff():
    text = " ".join(_read("commands/autopilot.md").split())

    assert "the list context is recon/handoff only" in text
    assert "never scan the list/index" in text
    assert "select one completed domain, then rerun `autopilot_state.py --target <domain>`" in text
    assert "Only the selected domain may enter surface/context/browser/scan/hunt" in text


def test_optional_agent_uses_the_same_state_first_contract():
    text = " ".join(_read("agents/autopilot.md").split())

    assert "run `python3 tools/autopilot_state.py --target <target>` exactly once before choosing fresh, existing, or batch behavior" in text
    assert "Never scan or actively hunt the batch index" in text
    assert "Runtime phase locks are the final duplicate-launch guard" in text
