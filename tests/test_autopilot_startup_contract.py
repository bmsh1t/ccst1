"""Claude CLI `/autopilot` 状态优先与 batch handoff 契约。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_slash_command_reads_state_before_any_long_phase():
    text = _read("commands/autopilot.md")
    bootstrap = text.index("tools/autopilot_bootstrap.py")
    preflight = text.index("## Runtime Preflight")
    state_contract = text.index("compact target state", preflight)
    startup = text.index("Every invocation is state-first")
    state_read = text.index("python3 tools/autopilot_state.py --target <target_shell>", startup)
    recon = text.index("python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --recon-only", state_read)
    surface = text.index("python3 tools/surface.py --target <target_shell>", state_read)
    scan = text.index("python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --scan-only --quick", state_read)

    assert bootstrap < preflight < state_contract < state_read < recon < surface < scan
    assert "Runtime phase locks are the final\nduplicate-launch guard" in text


def test_slash_command_runtime_preflight_is_read_only_and_fail_fast():
    text = _read("commands/autopilot.md")
    preflight = text.split("## Runtime Preflight", 1)[1].split("## Tool Index", 1)[0]

    assert "arguments,\nread-only runtime compare, then compact target state" in preflight
    assert "Only `continue` may act" in text
    assert "cd -- <repo_root_shell> &&" in preflight
    flat_preflight = " ".join(preflight.split())
    assert "request explicit confirmation before any sync" in flat_preflight
    assert "never sync automatically" in flat_preflight
    assert "--sync" not in preflight
    assert "python3 tools/runtime_doctor.py" not in preflight


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


def test_command_and_optional_agent_share_candidate_evidence_routing():
    command = " ".join(_read("commands/autopilot.md").split())
    agent = " ".join(_read("agents/autopilot.md").split())

    for text in (command, agent):
        assert "collect_candidate_evidence" in text
        assert "missing_labels" in text
        assert "next_actions" in text
        assert "validate_finding" in text
    assert "Do not call `/validate` until state returns `validate_finding`" in command
    assert "Use `/validate` only after state returns `validate_finding`" in agent
