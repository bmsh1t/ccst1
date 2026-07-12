"""Runtime artifact contract tests for /autopilot pressure runs."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from tools.checkpoint import build_checkpoint, write_checkpoint_witness
from tools.runtime_state import update_runtime_state

SCRIPT = Path(__file__).resolve().parent / "skill-validator" / "check_autopilot_run.py"
SPEC = importlib.util.spec_from_file_location("check_autopilot_run", SCRIPT)
assert SPEC and SPEC.loader
check_autopilot_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_autopilot_run)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def _write_passing_run(repo: Path, target: str = "demo.test") -> None:
    state_dir = repo / "state" / target
    evidence_dir = repo / "memory" / "evidence" / target
    update_runtime_state(
        repo,
        target,
        mode="autopilot",
        last_executed_workflow="checkpoint",
    )
    write_checkpoint_witness(
        repo,
        target,
        {
            "context_pack": {
                "selected_skill": "skills/web2-vuln-classes/SKILL.md",
                "knowledge_cards": ["knowledge/cards/server-side-template-injection.md"],
                "reference_hints": [
                    {"path": "skills/security-arsenal/references/payload-families.md"}
                ],
            }
        },
    )
    _write_json(
        state_dir / "action_queue.json",
        {
            "actions": [
                {
                    "id": "AQ-0001",
                    "status": "tested",
                    "type": "ssti",
                    "action": "python3 tools/context_pack.py --target demo.test --focus ssti",
                    "command_hint": "python3 tools/context_pack.py --target demo.test --focus ssti",
                    "stop_condition": "Stop after a harmless parser probe shows no render delta.",
                }
            ]
        },
    )
    _write_jsonl(
        evidence_dir / "ledger.jsonl",
        [
            {
                "target": "demo.test",
                "endpoint": "/profile",
                "raw_endpoint": "/profile?name={{probe}}",
                "evidence_ref": "evidence/demo.test/raw/ssti_probe_001.json",
                "result": "tested_clean",
            }
        ],
    )


def test_passing_fixture_satisfies_autopilot_run_contract(tmp_path):
    _write_passing_run(tmp_path)

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is True
    assert result["score"] == 100
    assert result["max_score"] == 100
    assert result["grade"] == "pass"
    assert all(check["passed"] for check in result["checks"].values())
    assert all(check["score"] == check["max_score"] for check in result["checks"].values())


def test_cli_returns_zero_for_passing_run(tmp_path, capsys):
    _write_passing_run(tmp_path)

    exit_code = check_autopilot_run.main([
        "--repo-root",
        str(tmp_path),
        "--target",
        "demo.test",
    ])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "score: 100/100" in output
    assert "grade: pass" in output
    assert "RESULT: PASS" in output


def test_missing_context_pack_artifact_fails_context_check(tmp_path):
    _write_passing_run(tmp_path)
    (tmp_path / "state" / "demo.test" / "checkpoint_latest.json").unlink()

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 70
    assert result["grade"] == "needs_review"
    assert result["checks"]["context_pack"]["passed"] is False
    assert result["checks"]["context_pack"]["score"] == 0
    assert "selected_skill" in result["checks"]["context_pack"]["missing"]


def test_runtime_v2_session_remains_minimal_and_witness_supplies_context(tmp_path):
    _write_passing_run(tmp_path)
    session = json.loads(
        (tmp_path / "state" / "demo.test" / "session.json").read_text(encoding="utf-8")
    )
    witness = json.loads(
        (tmp_path / "state" / "demo.test" / "checkpoint_latest.json").read_text(encoding="utf-8")
    )

    assert session["schema_version"] == 2
    assert "context_pack" not in session
    assert witness["kind"] == "autopilot_checkpoint_witness"
    assert witness["context_pack"]["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert check_autopilot_run.check_run(tmp_path, "demo.test")["passed"] is True


def test_real_checkpoint_projection_satisfies_runtime_v2_context_contract(tmp_path):
    _write_passing_run(tmp_path)

    checkpoint = build_checkpoint(
        tmp_path,
        target="demo.test",
        refresh_coverage=False,
    )
    result = check_autopilot_run.check_run(tmp_path, "demo.test")
    witness = json.loads(
        (tmp_path / "state" / "demo.test" / "checkpoint_latest.json").read_text(encoding="utf-8")
    )

    assert result["passed"] is True
    assert result["checks"]["context_pack"]["score"] == 30
    assert witness["context_pack"]["selected_skill"] == checkpoint["context_pack"]["selected_skill"]
    assert witness["context_pack"]["knowledge_cards"] == checkpoint["context_pack"]["knowledge_cards"]


def test_natural_language_only_action_fails_executable_check(tmp_path):
    _write_passing_run(tmp_path)
    queue_path = tmp_path / "state" / "demo.test" / "action_queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["action"] = "Investigate the template injection signal manually."
    queue["actions"][0]["command_hint"] = "manual browser review"
    _write_json(queue_path, queue)

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 75
    assert result["grade"] == "needs_review"
    assert result["checks"]["executable_action"]["passed"] is False
    assert result["checks"]["executable_action"]["score"] == 0
    assert result["checks"]["executable_action"]["missing"] == ["script_or_command_action"]


def test_missing_raw_evidence_fails_evidence_check(tmp_path):
    _write_passing_run(tmp_path)
    _write_jsonl(
        tmp_path / "memory" / "evidence" / "demo.test" / "ledger.jsonl",
        [{"target": "demo.test", "endpoint": "/profile", "result": "tested_clean"}],
    )

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 75
    assert result["grade"] == "needs_review"
    assert result["checks"]["evidence_path"]["passed"] is False
    assert result["checks"]["evidence_path"]["score"] == 0
    assert result["checks"]["evidence_path"]["missing"] == ["evidence_ref_or_raw_endpoint"]


def test_active_only_queue_fails_resolution_check(tmp_path):
    _write_passing_run(tmp_path)
    queue_path = tmp_path / "state" / "demo.test" / "action_queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["status"] = "queued"
    _write_json(queue_path, queue)

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 90
    assert result["grade"] == "needs_review"
    assert result["checks"]["queue_resolution_and_stop"]["passed"] is False
    assert result["checks"]["queue_resolution_and_stop"]["score"] == 10
    assert "final_status" in result["checks"]["queue_resolution_and_stop"]["missing"]


def test_high_risk_default_stop_condition_fails_stop_check(tmp_path):
    _write_passing_run(tmp_path)
    queue_path = tmp_path / "state" / "demo.test" / "action_queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["stop_condition"] = check_autopilot_run.DEFAULT_STOP_CONDITION
    _write_json(queue_path, queue)

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 90
    assert result["grade"] == "needs_review"
    assert result["checks"]["queue_resolution_and_stop"]["passed"] is False
    assert result["checks"]["queue_resolution_and_stop"]["score"] == 10
    assert "custom_stop_condition_for_high_risk" in result["checks"]["queue_resolution_and_stop"]["missing"]


def test_cli_json_includes_scores(tmp_path, capsys):
    _write_passing_run(tmp_path)

    exit_code = check_autopilot_run.main([
        "--repo-root",
        str(tmp_path),
        "--target",
        "demo.test",
        "--json",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["score"] == 100
    assert payload["max_score"] == 100
    assert payload["grade"] == "pass"
    assert payload["checks"]["context_pack"]["score"] == 30
