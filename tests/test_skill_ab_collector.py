"""Offline contract tests for the Claude CLI A/B collector."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_DIR = REPO_ROOT / "tests" / "skill-validator"
if str(VALIDATOR_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATOR_DIR))

import ab_collect  # noqa: E402
from ab_runner import load_jsonl, summarize_rows  # noqa: E402


def _fake_claude(path: Path) -> Path:
    path.write_text(
        """#!/usr/bin/env python3
import json
import sys

if '--version' in sys.argv:
    print('claude-test')
else:
    print(json.dumps({
        'structured_output': {'verdict': 'safe'},
        'usage': {'input_tokens': 2, 'output_tokens': 3},
        'num_turns': 2,
        'total_cost_usd': 0.5,
        'duration_ms': 12,
    }))
""",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | 0o111)
    return path


def _fake_failure_claude(path: Path) -> Path:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
import time

if '--version' in sys.argv:
    print('claude-test')
else:
    mode = os.environ.get('FAKE_MODE')
    if mode == 'empty':
        pass
    elif mode == 'mixed':
        print('progress: starting')
        print(json.dumps({'structured_output': {'verdict': 'safe'}}))
    elif mode == 'nonzero':
        print(json.dumps({'structured_output': {'verdict': 'safe'}}))
        raise SystemExit(7)
    elif mode == 'timeout':
        time.sleep(0.2)
    else:
        print(json.dumps({'structured_output': {'verdict': 'safe'}}))
""",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | 0o111)
    return path


def _cases(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "case_id": "CASE",
                "prompt": "Return the safe fixture verdict.",
                "oracle_label": "safe",
                "oracle_status": "passed",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_build_command_only_changes_skill_switch(tmp_path):
    common = {
        "verdicts": ["vulnerable", "safe"],
        "model": "MODEL",
        "tools": "Bash",
        "setting_sources": "user",
        "permission_mode": "auto",
        "max_turns": 4,
        "max_budget_usd": "1",
    }
    off = ab_collect.build_command("claude", "TASK", condition="skills_off", **common)
    on = ab_collect.build_command("claude", "TASK", condition="skills_on", **common)

    assert "--disable-slash-commands" in off
    assert "--disable-slash-commands" not in on
    assert [item for item in off if item != "--disable-slash-commands"] == on


def test_parse_native_json_result_extracts_metrics():
    result = ab_collect.parse_result(
        json.dumps(
            {
                "structured_output": {"verdict": "safe"},
                "usage": {"input_tokens": 4, "output_tokens": 6},
                "num_turns": 3,
                "total_cost_usd": 0.25,
                "duration_ms": 125,
            }
        ),
        duration_ms=999,
    )

    assert result == {
        "verdict": "safe",
        "turns": 3,
        "tokens": 10,
        "cost_usd": 0.25,
        "duration_ms": 125.0,
    }


def test_parse_native_json_result_keeps_observable_behavior_metrics():
    result = ab_collect.parse_result(
        json.dumps(
            {
                "structured_output": {
                    "verdict": "safe",
                    "hypothesis_selected": True,
                    "evidence_complete": False,
                    "invalid_route": False,
                    "coverage_progress": 2,
                }
            }
        ),
        duration_ms=10,
    )

    assert result["hypothesis_selected"] is True
    assert result["evidence_complete"] is False
    assert result["invalid_route"] is False
    assert result["coverage_progress"] == 2


def test_collector_writes_rows_and_manifest_without_network(tmp_path):
    fake = _fake_claude(tmp_path / "claude")
    cases = _cases(tmp_path / "cases.jsonl")
    home = (tmp_path / "home").resolve()
    home.mkdir()
    output = tmp_path / "runs" / "rows.jsonl"

    assert (
        ab_collect.main(
            [
                str(cases),
                "--output",
                str(output),
                "--home",
                str(home),
                "--cwd",
                str(REPO_ROOT),
                "--claude",
                str(fake),
                "--model",
                "MODEL",
            ]
        )
        == 0
    )

    rows = load_jsonl(output)
    result = summarize_rows(rows)
    assert len(rows) == 2
    assert result["invalid_row_count"] == 0
    assert result["paired_delta"]["case_count"] == 1
    assert result["metrics"]["skills_on"]["tokens"]["mean"] == 5.0
    manifest = json.loads(
        output.with_suffix(".manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["model"] == "MODEL"
    assert manifest["claude_version"] == "claude-test"
    assert manifest["conditions"] == ["skills_off", "skills_on"]
    assert manifest["provenance"]["staged_home"] == str(home)
    assert manifest["provenance"]["runtime_root"] == str(home / ".claude")
    assert manifest["provenance"]["install_script"]["sha256"].startswith("sha256:")
    assert "runtime_doctor" in manifest["provenance"]


def test_existing_keys_ignore_retryable_rows(tmp_path):
    output = tmp_path / "rows.jsonl"
    output.write_text(
        "\n".join(
            [
                json.dumps({"case_id": "DONE", "condition": "skills_on", "rep": 1, "verdict": "safe"}),
                json.dumps({"case_id": "UNKNOWN", "condition": "skills_on", "rep": 1, "verdict": "unknown"}),
                json.dumps({"case_id": "ERROR", "condition": "skills_on", "rep": 1, "verdict": "safe", "agent_error": "timeout"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert ab_collect._existing_keys(output) == {("DONE", "skills_on", 1)}


def test_append_resume_replaces_retryable_row_without_duplicate_pair(tmp_path):
    output = tmp_path / "rows.jsonl"
    old = {
        "case_id": "CASE",
        "condition": "skills_on",
        "rep": 1,
        "verdict": "unknown",
        "agent_error": "timeout",
    }
    output.write_text(json.dumps(old) + "\n", encoding="utf-8")

    ab_collect._replace_row(
        output,
        {
            "case_id": "CASE",
            "condition": "skills_on",
            "rep": 1,
            "verdict": "safe",
        },
    )

    rows = load_jsonl(output)
    assert rows == [{"case_id": "CASE", "condition": "skills_on", "rep": 1, "verdict": "safe"}]


def test_collector_returns_error_when_native_result_has_no_structured_verdict(tmp_path):
    fake = tmp_path / "claude"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('claude-test')\n"
        "else:\n"
        "    print(json.dumps({'result': 'no schema'}))\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | 0o111)
    cases = _cases(tmp_path / "cases.jsonl")
    home = tmp_path / "home"
    home.mkdir()
    output = tmp_path / "rows.jsonl"

    assert (
        ab_collect.main(
            [
                str(cases),
                "--output",
                str(output),
                "--home",
                str(home),
                "--claude",
                str(fake),
            ]
        )
        == 2
    )
    result = summarize_rows(load_jsonl(output))
    assert result["valid_row_count"] == 0
    assert result["invalid_row_count"] == 2


@pytest.mark.parametrize(
    ("mode", "expected_error", "timeout"),
    [("empty", "invalid_json", 1.0), ("mixed", "invalid_json", 1.0),
     ("nonzero", "nonzero_exit", 1.0), ("timeout", "timeout", 0.02)],
)
def test_run_case_keeps_failure_reason_in_a_complete_result_row(
    tmp_path, mode, expected_error, timeout
):
    fake = _fake_failure_claude(tmp_path / "claude")
    row = ab_collect._run_case(
        fake,
        {
            "case_id": "CASE",
            "prompt": "Return the safe fixture verdict.",
            "oracle_label": "safe",
            "oracle_status": "passed",
        },
        condition="skills_on",
        rep=1,
        verdicts=["vulnerable", "safe"],
        model=None,
        tools="",
        setting_sources="user",
        permission_mode="auto",
        max_turns=1,
        max_budget_usd=None,
        cwd=REPO_ROOT,
        env={**os.environ, "FAKE_MODE": mode},
        timeout=timeout,
    )

    assert row["case_id"] == "CASE"
    assert row["condition"] == "skills_on"
    assert row["rep"] == 1
    assert row["oracle_label"] == "safe"
    assert row["oracle_status"] == "passed"
    assert row["verdict"] == "unknown"
    assert row["agent_error"] == expected_error
    assert row["duration_ms"] >= 0


def test_dry_run_does_not_write_output_or_manifest(tmp_path, capsys):
    fake = _fake_claude(tmp_path / "claude")
    cases = _cases(tmp_path / "cases.jsonl")
    home = tmp_path / "home"
    home.mkdir()
    output = tmp_path / "rows.jsonl"

    assert (
        ab_collect.main(
            [
                str(cases),
                "--output",
                str(output),
                "--home",
                str(home),
                "--claude",
                str(fake),
                "--dry-run",
            ]
        )
        == 0
    )
    printed = capsys.readouterr().out
    assert '"condition": "skills_off"' in printed
    assert "--disable-slash-commands" in printed
    assert not output.exists()
    assert not output.with_suffix(".manifest.json").exists()


@pytest.mark.parametrize("bad", ["", "skills", "skills_on,unknown"])
def test_condition_parser_rejects_invalid_values(bad):
    if bad:
        with pytest.raises(ValueError):
            values = ab_collect._parse_csv(bad, name="conditions")
            if any(value not in ab_collect.CONDITIONS for value in values):
                raise ValueError("unknown condition")
    else:
        with pytest.raises(ValueError):
            ab_collect._parse_csv(bad, name="conditions")
