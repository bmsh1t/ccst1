"""Claude CLI `/autopilot` inline 与 legacy agent 入口分离契约。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_slash_command_runs_inline_with_one_controller_and_bounded_specialist():
    text = _read("commands/autopilot.md")
    normalized = " ".join(text.split())

    assert "runs inline in the current Claude session as the sole controller" in normalized
    assert "does not create/resume legacy `agent_session.json`" in normalized
    assert "specialists default to zero" in normalized
    assert "At most one bounded specialist" in normalized
    assert "The invoked specialist must not spawn nested agents, run full recon/scans, write final closure, or control finish" in normalized
    assert "--isolated" not in text


def test_slash_command_uses_authoritative_parser_and_rejects_legacy_flags():
    text = _read("commands/autopilot.md")
    normalized = " ".join(text.split())

    assert 'allowed-tools:' in text
    assert '- Bash' in text
    assert '- Agent' in text
    assert 'mcp__Playwright__*' in text
    assert 'mcp__chrome-devtools__*' in text
    assert "through Claude Code's `Agent` tool" in normalized
    assert 'tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"' in text
    assert "git rev-parse --show-toplevel" in text
    assert "Authoritative bootstrap contract (do not reinterpret)" in normalized
    assert "Only `continue` may act" in normalized
    assert "invalid inline" in normalized
    assert "python3 agent.py --target <target_shell>" in normalized
    assert "python3 tools/hunt.py --target <target_shell> --agent" in normalized
    assert "repo_root_shell" in normalized
    assert '"$ARGUMENTS"' not in text


def test_inline_auth_and_seed_contract_uses_formal_arguments_only():
    command = _read("commands/autopilot.md")
    readme = _read("README.md")
    product = _read("docs/PRODUCT.md")

    assert "[--auth-file PATH]" in command
    assert "arguments.seed_url" in command
    assert "arguments.hunt_auth_flags" in command
    assert "arguments.auth_file_shell" in command
    assert "cd -- <repo_root_shell> &&" in command
    assert "/autopilot target.com --normal --auth-file .private/auth.json" in readme
    assert "/autopilot target.com --normal, use" not in readme
    assert "URL 目标保留 canonical host state" in product


def test_bounded_deep_invocation_handoffs_instead_of_expanding_new_lanes():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    assert "[--max-lanes N]" in command
    assert "invocation_batch.bounded" in command
    assert "browser/source discoveries become next-invocation work, not lane n+1" in " ".join(command.split()).lower()
    assert "after lane N do not execute a newly discovered queue item" in command
    assert "terminal handoff overrides target exhaustion" in command
    assert "checkpoint/sync durable queue" in agent


def test_browser_first_use_probe_retries_only_transient_session_failures():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "browser actions use only visible playwright/chrome mcp" in command
    assert "never run `agent-browser` or `playwright-cli` through bash" in command
    assert "first use" in command
    assert "harmless page-list/session probe" in command
    assert "retry once" in command
    assert "timeout, disconnect, or closed-context errors" in command
    assert "missing/configuration/permission/protocol errors do not retry" in command
    assert "checkpoint the blocker in the existing action queue" in command
    assert "pivot to js/source/api evidence" in command
    assert "next invocation, after repair, or on explicit operator retry" in command


def test_incomplete_durable_state_is_handoff_not_target_exhaustion():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "active durable work, pending validation/report" in command
    assert "partial browser/source/intel, or untouched high-value work" in command
    assert "`handoff/partial`" in command
    assert "never `finish/complete/exhausted`" in command
    assert "passing `check_autopilot_run.py` proves state-chain integrity, not target exhaustion" in command


def test_finish_contract_rebuilds_coverage_then_reads_explicit_closure_verdict():
    command = _read("commands/autopilot.md")
    normalized = " ".join(command.split()).lower()

    rebuild = "python3 tools/coverage_matrix.py rebuild --target <target_shell>"
    gaps = "python3 tools/coverage_matrix.py find-gaps --target <target_shell>"
    closure = "python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --json"
    assert command.count(rebuild) == 1
    assert command.index(rebuild) < command.index(gaps) < command.index(closure)
    assert "only `verdict=finish` with `can_claim_exhausted=true`" in normalized
    assert "--max-lanes-reached" in command


def test_substantive_lanes_obey_explicit_loop_guard_without_overriding_durable_work():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "after every substantive lane" in command
    assert "autopilot_state.py --target <target_shell> --bounded --loop-check --json" in command
    assert "obey `loop_guard.verdict`" in command
    assert "do not continue the reported `endpoint_family` × `vuln_class`" in command
    assert "bounded `rotation_target` when present" in command
    assert "never overrides runtime waits, candidate validation, report work, or durable action queue work" in command


def test_failed_sources_and_tools_are_suppressed_within_one_invocation():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "within one invocation, do not rerun the same failed source/tool" in command
    assert "preserve cached/stale evidence as partial/blocked" in command
    assert "tools/external_arsenal.sh --versions" in command
    assert "diagnostics-only, never startup" in command


def test_optional_autopilot_agent_is_not_the_slash_command_backend():
    text = _read("agents/autopilot.md")
    normalized = " ".join(text.split())

    assert "explicitly invoked optional Claude subagent" in normalized
    assert "not the implicit backend of the `/autopilot` slash command" in normalized
    assert "its caller owns the target boundary, state write-back, and result collection" in normalized


def test_operator_docs_separate_inline_autopilot_from_legacy_agent_sessions():
    claude = " ".join(_read("CLAUDE.md").split())
    readme = " ".join(_read("README.md").split())
    product = " ".join(_read("docs/PRODUCT.md").split())

    for text in (claude, readme):
        assert "current Claude session" in text

    for text in (claude, readme, product):
        assert "tools/hunt.py" in text
        assert "--agent" in text

    assert "当前 Claude 会话" in product
    assert "Continue this target in the current Claude session" in readme
    assert "Explicit legacy local-agent runs" in readme
    assert "默认的 `/autopilot target.com` 或 agent 运行会创建新的本地 session" not in product
    assert "默认会创建新的本地 agent session" not in product
    assert "默认创建新的本地 agent session" not in product


def test_legacy_agent_resume_entrypoints_remain_documented():
    combined = "\n".join((_read("README.md"), _read("docs/PRODUCT.md")))

    assert "python3 tools/hunt.py --target target.com --agent --resume latest" in combined
    assert "python3 tools/hunt.py --target target.com --agent --resume <session_id>" in combined
