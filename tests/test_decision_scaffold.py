"""Decision scaffolds: machine-filled input skeletons, judgment fields stay AI-owned."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.decision_scaffold import (
    VALIDATE_AI_FIELDS_NOTE,
    build_resolve_scaffold,
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


def test_resolve_scaffold_prefills_dimension_from_metadata():
    action = {"id": "AQ-1", "metadata": {"active_dimension": "path:/rest/basket/1"}}
    scaffold = build_resolve_scaffold(action)
    assert scaffold["continuation"]["dimension"] == "path:/rest/basket/1"
    assert scaffold["continuation"]["question"] == ""
    assert scaffold["continuation"]["expected_learning"] == ""
    assert scaffold["continuation"]["reason"] == ""


def test_resolve_scaffold_degrades_without_metadata():
    scaffold = build_resolve_scaffold({"id": "AQ-1"})
    assert scaffold["continuation"]["dimension"] == ""


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
