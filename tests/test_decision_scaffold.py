"""Decision scaffolds: machine-filled input skeletons, judgment fields stay AI-owned."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.decision_scaffold import (
    VALIDATE_AI_FIELDS_NOTE,
    build_validate_scaffold,
)
from tools.validate import SEVEN_QUESTION_DEFINITIONS


def _seed_finding(repo: Path, target: str = "t.example") -> Path:
    key = target.replace(":", "-")
    findings_dir = repo / "findings" / key
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "target": target,
                "findings": [
                    {
                        "id": "F-1",
                        "type": "auth_bypass",
                        "url": f"http://{target}/rest/basket/6",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    # owner-bound runner run
    run_dir = repo / "evidence" / key / "validation" / "F-1" / "20260911T000000Z-abcd1234"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "summary.json").write_text(
        json.dumps({"schema_version": 1, "finding_id": "F-1", "result": "tested_finding"}),
        encoding="utf-8",
    )
    return findings_dir


def test_validate_scaffold_prefills_mechanical_fields(tmp_path):
    findings_dir = _seed_finding(tmp_path)
    scaffold = build_validate_scaffold(
        tmp_path, findings_dir, {"id": "F-1", "url": "http://t.example/rest/basket/6", "type": "auth_bypass"}, target="t.example"
    )
    assert scaffold["schema_version"] == 2
    assert scaffold["finding_id"] == "F-1"
    assert scaffold["endpoint"] == "http://t.example/rest/basket/6"
    assert scaffold["evidence"]["runner_summary"].endswith(
        "evidence/t.example/validation/F-1/20260911T000000Z-abcd1234/summary.json"
    )
    assert scaffold["evidence"]["runner_summary"] in scaffold["evidence"]["refs"]
    assert scaffold["report"]["path"] == "findings/t.example/F-1-report.md"


def test_validate_scaffold_leaves_judgment_fields_empty(tmp_path):
    """AI 判断字段不预填（同 claim 模板的分桶纪律）。"""
    findings_dir = _seed_finding(tmp_path)
    scaffold = build_validate_scaffold(
        tmp_path, findings_dir, {"id": "F-1", "url": "http://t.example/x", "type": "auth_bypass"}, target="t.example"
    )
    assert scaffold["impact"] == ""
    assert all(item["passed"] is None for item in scaffold["gates"].values())
    assert all(item["basis"] == "" for item in scaffold["seven_question_gate"]["questions"].values())
    assert scaffold["cvss"]["score"] == 0.0
    assert scaffold["report"]["content"] == ""


def test_validate_scaffold_covers_all_seven_questions(tmp_path):
    findings_dir = _seed_finding(tmp_path)
    scaffold = build_validate_scaffold(
        tmp_path, findings_dir, {"id": "F-1", "url": "http://t.example/x", "type": "auth_bypass"}, target="t.example"
    )
    expected_keys = {key for key, _ in SEVEN_QUESTION_DEFINITIONS}
    assert set(scaffold["seven_question_gate"]["questions"]) == expected_keys


def test_validate_scaffold_warns_without_runner_run(tmp_path):
    findings_dir = _seed_finding(tmp_path)
    # 删除 runner run
    for p in (tmp_path / "evidence").rglob("summary.json"):
        p.unlink()
    scaffold = build_validate_scaffold(
        tmp_path, findings_dir, {"id": "F-1", "url": "http://t.example/x", "type": "auth_bypass"}, target="t.example"
    )
    assert scaffold["evidence"]["runner_summary"] == ""
    assert scaffold["_scaffold_warnings"]
    assert "--finding-id F-1" in scaffold["_scaffold_warnings"][0]


def test_validate_scaffold_ignores_mismatched_runner_finding_id(tmp_path):
    """finding_id 不匹配的 run 不绑（防挑错 run）。"""
    findings_dir = _seed_finding(tmp_path)
    run = next((tmp_path / "evidence").rglob("summary.json"))
    payload = json.loads(run.read_text(encoding="utf-8"))
    payload["finding_id"] = "OTHER-FINDING"
    run.write_text(json.dumps(payload), encoding="utf-8")
    scaffold = build_validate_scaffold(
        tmp_path, findings_dir, {"id": "F-1", "url": "http://t.example/x", "type": "auth_bypass"}, target="t.example"
    )
    assert scaffold["evidence"]["runner_summary"] == ""


def test_resolve_scaffold_is_retired():
    """原生能力审计（2026-09-13）：resolve 空白骨架已退役——回显几个空字段
    并预选 kind=sibling 是在替 AI 起草判断，AI 按 Queue 已发布的 schema
    直接提交 continuation。"""
    import tools.decision_scaffold as ds

    assert not hasattr(ds, "build_resolve_scaffold")


def test_validate_cli_scaffold_roundtrip(tmp_path, capsys):
    """端到端：CLI scaffold 输出可解析、含全部键。"""
    import sys

    sys.path.insert(0, str(tmp_path))
    _seed_finding(tmp_path)
    from tools.validate import main as validate_main

    rc = validate_main(
        [
            "--findings-dir",
            str(tmp_path / "findings" / "t.example"),
            "--finding-id",
            "F-1",
            "--scaffold",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_id"] == "F-1"
    assert payload["schema_version"] == 2
    assert payload["evidence"]["runner_summary"]


def test_resolve_cli_rejects_missing_and_empty_status():
    """Step-1 收尾回归：resolve 缺 --status 或传空串必须 argparse 拒绝。

    旧代码在 main() 里引用已不存在的 parser 局部变量，实际抛
    NameError 而非干净的用法错误（审计 step1-review #1）。
    """
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path

    tools_dir = _Path(__file__).resolve().parent.parent / "tools"
    for argv in (
        ["resolve", "--target", "t.example", "--id", "AQ-1"],
        ["resolve", "--target", "t.example", "--id", "AQ-1", "--status", ""],
    ):
        result = subprocess.run(
            [_sys.executable, str(tools_dir / "action_queue.py"), *argv],
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert result.returncode == 2, f"expected argparse rejection for {argv}"
        assert "NameError" not in result.stderr
        assert "--status" in result.stderr
