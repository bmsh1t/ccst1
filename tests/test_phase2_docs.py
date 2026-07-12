"""Phase 2 文档主工作流提示的回归测试。"""

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(*relative_paths: str) -> str:
    return "\n".join((REPO_ROOT / path).read_text(encoding="utf-8") for path in relative_paths)


@pytest.mark.parametrize(
    ("relative_path", "expected"),
    [
        ("README.md", "legacy cve/report entrypoints remain available as compatibility paths"),
        ("CLAUDE.md", "legacy cve/report entrypoints remain available as compatibility paths"),
        ("commands/hunt.md", "legacy cve/report entrypoints remain available as compatibility paths"),
    ],
)
def test_primary_workflow_docs_reference_intel_report_and_compatibility_path(
    relative_path: str,
    expected: str,
):
    content = _read(relative_path).lower()

    assert "/intel" in content
    assert "/report" in content
    assert expected in content


def test_intel_doc_marks_legacy_cve_entrypoints_as_compatibility_paths_only():
    content = _read("commands/intel.md").lower()

    assert "primary intel workflow" in content
    assert "compatibility paths only" in content


def test_report_doc_marks_legacy_report_entrypoints_as_compatibility_paths_only():
    content = _read("commands/report.md").lower()

    assert "primary reporting workflow" in content
    assert "compatibility paths only" in content
    assert "seven_question_gate_passed: true" in content
    assert "four_validation_gates_passed: true" in content
    assert "all_gates_passed: true" in content


def test_claude_code_target_isolation_docs_prevent_inherited_scanner_skips():
    content = _read(
        "CLAUDE.md",
        "commands/hunt.md",
        "commands/autopilot.md",
        "commands/pickup.md",
        "agents/autopilot.md",
        "FAQ.md",
    ).lower()

    assert "new target default" in content
    assert "built-in xss lane skip" in content
    assert "--scanner-full" in content
    assert "per-current-target and per-current-invocation only" in content
    assert "does **not** replay" in content
    assert "previous target" in content
    assert "ctf_mode" in content


def test_ctf_prompt_docs_do_not_turn_target_history_into_lane_kills():
    content = _read(
        "CLAUDE.md",
        "SKILL.md",
        "commands/hunt.md",
        "commands/autopilot.md",
        "commands/pickup.md",
        "agents/autopilot.md",
        "rules/hunting.md",
        "skills/bug-bounty/SKILL.md",
    ).lower()

    assert "production-looking brands" in content
    assert "public-sector/government-style labels" in content
    assert "account/login/register wording" in content
    assert "old target-history caution notes" in content
    assert "only the current user turn can exclude a lane" in content
    assert "excluded bug classes = none unless the current user turn or command flags explicitly say so" in content
    assert "authoritative lab target record" in content
    assert "public-program, written-permission, or ownership-confirmation" in content

    forbidden_lane_kill_phrases = [
        "real government",
        "misuse boundary",
        "fictitious account",
        "pdot is not that",
        "not a ctf",
        "cannot verify authorization",
        "program-scope validation",
        "public bug bounty program",
        "real public site",
        "active authorized test scope",
        "current target scope explicitly says so",
        "in-scope boundary",
    ]
    for phrase in forbidden_lane_kill_phrases:
        assert phrase not in content


def test_prompt_docs_document_iis_shortscan_lane():
    content = _read("commands/hunt.md", "agents/autopilot.md").lower()

    assert "iis short filename" in content
    assert "shortscan <url> -s -p 1" in content
    assert "shortscan" in content
    assert "missing" in content


def test_docs_document_auth_aware_hunt_and_autopilot_usage():
    readme = _read("README.md").lower()
    command_docs = _read("commands/hunt.md", "commands/autopilot.md", "agents/autopilot.md").lower()

    assert "--auth-file" in readme
    assert "bbhunt_cookie" in readme
    assert "--auth-file" in command_docs
    assert "--auth-from-env" in command_docs
    assert "bbhunt_auth_header" in command_docs
    assert "shell recon / scanner" in command_docs


def test_auth_reference_docs_and_private_dir_ignore_exist():
    readme = _read("README.md").lower()
    auth_doc = _read("docs/auth-sessions.md").lower()
    auth_example = (REPO_ROOT / "docs" / "auth.example.json").read_text(encoding="utf-8").lower()
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").lower()

    assert "docs/auth-sessions.md" in readme
    assert ".private/" in gitignore
    assert "the `.private/` directory is gitignored" in auth_doc
    assert "copy this to .private/<target>.json" in auth_example


def test_resume_docs_explain_storage_key_for_cidr_and_host_list_targets():
    content = _read("README.md", "commands/autopilot.md").lower()

    assert "targets/<storage-key>/sessions/<session_id>/" in content
    assert "cidr targets replace `/` with `_`" in content
    assert "host-list" in content
    assert "list filename stem plus a canonical-path digest" in content


def test_tracked_claude_hook_contract_is_complete():
    payload = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    hooks = payload["hooks"]

    # 个人 .claude/settings.json 属于 runtime 配置，不能作为仓库质量门输入。
    events = {item.get("event") for item in hooks}
    assert {"SessionStart", "SessionStop", "Stop"} <= events
    assert all(str(item.get("command") or "").strip() for item in hooks)


def test_claude_code_prompt_files_are_utf8_and_not_corrupted():
    """Prompt files may be Chinese or English.

    Current project AGENTS.md explicitly allows Chinese comments/docs, so the
    useful invariant is not "English only"; it is that Claude-facing prompt
    files remain UTF-8 readable and do not contain replacement-character
    corruption from bad merges or encoding mistakes.
    """
    prompt_files = [REPO_ROOT / "CLAUDE.md", REPO_ROOT / "SKILL.md"]
    for prompt_dir in ("commands", "agents", "skills", "rules"):
        prompt_files.extend((REPO_ROOT / prompt_dir).rglob("*.md"))

    offenders = []
    for path in prompt_files:
        text = path.read_text(encoding="utf-8")
        if "\ufffd" in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert offenders == []


def test_execution_flow_files_are_utf8_and_not_corrupted():
    """Execution-flow files may contain Chinese under current project rules."""
    flow_files = [REPO_ROOT / "README.md", REPO_ROOT / "agent.py", REPO_ROOT / "install.sh"]
    for flow_dir in ("tools", "scripts", "hooks", "mcp", ".claude"):
        root = REPO_ROOT / flow_dir
        if root.exists():
            flow_files.extend(
                path for path in root.rglob("*")
                if path.is_file() and path.suffix in {".md", ".py", ".sh", ".js", ".json"}
            )

    offenders = []
    for path in flow_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        if "\ufffd" in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert offenders == []
