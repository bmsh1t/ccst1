"""Claude CLI `/autopilot` 状态优先与 batch handoff 契约。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_slash_command_reads_state_before_any_long_phase():
    text = " ".join(_read("commands/autopilot.md").split())
    lanes = " ".join(_read("docs/autopilot-lanes.md").split())
    bootstrap = text.index("tools/autopilot_bootstrap.py")
    preflight = text.index("## Runtime Preflight")
    capabilities = text.index("advisory capability profile", preflight)
    state_contract = text.index("compact target state", preflight)
    startup = text.index("Every invocation is state-first")
    state_read = text.index("python3 tools/autopilot_state.py --target <target_shell>", startup)
    assert bootstrap < preflight < capabilities < state_contract < state_read
    assert "python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --recon-only" in lanes
    assert "tools/surface.py" in lanes
    assert "python3 tools/hunt.py --target <target_shell> [--auth-file <auth_file_shell>] --scan-only --quick" in lanes
    assert "Runtime phase locks are the final duplicate-launch guard" in lanes


def test_slash_command_runtime_preflight_is_read_only_and_fail_fast():
    text = _read("commands/autopilot.md")
    preflight = text.split("## Runtime Preflight", 1)[1].split("## State Consumption Loop", 1)[0]

    flat_preflight = " ".join(preflight.split())
    assert "arguments, read-only runtime compare, advisory capability profile, then compact target state" in flat_preflight
    assert "Arguments/runtime remain the only blocking gates" in flat_preflight
    assert "Only `continue` may act" in text
    assert "cd -- <repo_root_shell> &&" in preflight
    assert "requests explicit confirmation before any sync" in flat_preflight
    assert "Never sync automatically" in flat_preflight
    assert "--sync" not in preflight
    assert "python3 tools/runtime_doctor.py" not in preflight


def test_slash_command_consumes_capabilities_as_advisory_only():
    text = " ".join(_read("commands/autopilot.md").split())

    assert "Treat `capabilities` as advisory" in text
    assert "`session_managed` names are not availability claims" in text
    assert "use MCP only when visible in this Claude session" in text
    assert "Missing/degraded tools never block" in text
    assert "trigger installation" in text
    assert "count as tested-clean" in text


def test_slash_command_preserves_parent_scope_for_multi_asset_handoff():
    text = " ".join(_read("docs/autopilot-lanes.md").split())

    assert "text list or schema-v1 JSON Scope manifest" in text
    assert "never scan the list/manifest file itself" in text
    assert "parent `scope_ref/scope_hash`" in text
    assert "tools/autopilot_continuation.py create" in text
    assert "`out_of_scope` always wins" in text


def test_optional_agent_uses_the_same_state_first_contract():
    text = " ".join(_read("agents/autopilot.md").split())

    assert "run `python3 tools/autopilot_state.py --target <target> --bounded` exactly once before choosing fresh, existing, or batch behavior" in text
    assert "Never scan or actively hunt the batch index" in text
    assert "Runtime phase locks are the final duplicate-launch guard" in text


def test_command_and_optional_agent_share_candidate_evidence_routing():
    command = " ".join(
        (_read("commands/autopilot.md") + _read("docs/autopilot-lanes.md")).split()
    )
    agent = " ".join(_read("agents/autopilot.md").split())

    for text in (command, agent):
        assert "collect_candidate_evidence" in text
        assert "missing_labels" in text
        assert "next_actions" in text
        assert "validate_finding" in text
    assert "call `/validate` only when state returns `validate_finding`" in command
    assert "Use `/validate` only after state returns `validate_finding`" in agent
