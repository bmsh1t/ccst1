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
    assert "at most one bounded specialist" in normalized
    assert "without spawning agents, running full recon/scans, writing final closure, or controlling finish" in normalized
    assert "--isolated" not in text


def test_slash_command_uses_authoritative_parser_and_rejects_legacy_flags():
    text = _read("commands/autopilot.md")
    normalized = " ".join(text.split())

    assert 'allowed-tools: Bash' in text
    assert 'tools/autopilot_args.py --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6"' in text
    assert "Authoritative argument contract (do not reinterpret)" in normalized
    assert "only `continue` may act" in normalized
    assert "invalid inline" in normalized
    assert "python3 agent.py --target <target>" in normalized
    assert "python3 tools/hunt.py --target <target> --agent" in normalized
    assert '"$ARGUMENTS"' not in text


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
