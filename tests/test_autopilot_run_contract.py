"""Runtime artifact contract tests for /autopilot pressure runs."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from tools.checkpoint import build_checkpoint, write_checkpoint_witness
from tools.runtime_state import update_runtime_state
from tools.target_store import TargetStore

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


def _write_passing_run(repo: Path, target: str = "demo.test", *, command=True,
                       complete=True, stop=None, observation=True) -> TargetStore:
    store = TargetStore(repo, target)
    store.initialize()
    raw_evidence_path = repo / "evidence" / target / "raw" / "ssti_probe_001.json"
    _write_json(raw_evidence_path, {"target": target, "request": "GET /profile HTTP/1.1",
                                   "response": "HTTP/1.1 200 OK"})
    update_runtime_state(repo, target, mode="autopilot", last_executed_workflow="checkpoint")
    write_checkpoint_witness(repo, target, {"context_pack": {
        "knowledge_cards": ["knowledge/cards/server-side-template-injection.md"],
        "reference_hints": [],
    }})
    store.create_action(
        command_id="create", action_id="AQ-0001", intent="Compare template rendering",
        execution_key="render-probe", endpoint=f"https://{target}/profile", family="ssti", actor="test",
        metadata={"action_context": {
            "command_hint": "python3 tools/context_pack.py --target demo.test --focus ssti"
                            if command else "manual browser review",
            "stop_condition": stop if stop is not None else "Stop after one harmless parser comparison.",
        }},
    )
    if observation:
        store.transition_action(command_id="claim", action_id="AQ-0001", expected_version=1,
                                status="claimed", actor="test")
        store.start_attempt(attempt_id="attempt", source="native", actor="test",
                            started_at="2026-09-24T00:00:00Z", action_id="AQ-0001", claim_token="claim")
        operation = store.record_execution(
            attempt_id="attempt", outcome="complete", actor="test", observations=[{
                "endpoint": f"https://{target}/profile", "method": "GET", "family": "ssti",
                "observed_at": "2026-09-24T00:00:00Z", "description": "No render difference observed",
                "artifacts": {"response": raw_evidence_path.relative_to(repo).as_posix()}, "state_changing": False,
            }],
        )
        if complete:
            store.transition_action(command_id="complete", action_id="AQ-0001", expected_version=2,
                                    status="completed", actor="test", claim_token="claim", reason="Recorded comparison",
                                    completion={"operation_id": operation["entity_id"]})
    return store


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
    assert result["checks"]["context_pack"]["missing"] == [
        "context_pack_used",
        "knowledge_cards_or_reference_hints",
    ]


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
    assert witness["context_pack"]["knowledge_cards"] == [
        "knowledge/cards/server-side-template-injection.md"
    ]
    assert check_autopilot_run.check_run(tmp_path, "demo.test")["passed"] is True


def test_real_checkpoint_projection_satisfies_runtime_v2_context_contract(tmp_path):
    _write_passing_run(tmp_path)

    before = (tmp_path / "state/demo.test/checkpoint_latest.json").read_bytes()
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
    assert checkpoint["runtime_witness"]["status"] == "not_published"
    assert (tmp_path / "state/demo.test/checkpoint_latest.json").read_bytes() == before
    assert witness["context_pack"]["knowledge_cards"]


def test_natural_language_only_action_fails_executable_check(tmp_path):
    _write_passing_run(tmp_path, command=False)

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 75
    assert result["grade"] == "needs_review"
    assert result["checks"]["executable_action"]["passed"] is False
    assert result["checks"]["executable_action"]["score"] == 0
    assert result["checks"]["executable_action"]["missing"] == ["script_or_command_action"]


def test_missing_raw_evidence_fails_evidence_check(tmp_path):
    _write_passing_run(tmp_path)
    (tmp_path / "evidence/demo.test/raw/ssti_probe_001.json").unlink()

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 75
    assert result["grade"] == "needs_review"
    assert result["checks"]["evidence_path"]["passed"] is False
    assert result["checks"]["evidence_path"]["score"] == 0
    assert result["checks"]["evidence_path"]["missing"] == ["registered_intact_raw_evidence"]


def test_raw_endpoint_only_does_not_satisfy_evidence_contract(tmp_path):
    _write_passing_run(tmp_path, observation=False)
    _write_jsonl(tmp_path / "memory/evidence/demo.test/ledger.jsonl", [{
        "endpoint": "/profile", "raw_endpoint": "/profile?name=test", "result": "tested_clean",
        "evidence_ref": "evidence/demo.test/raw/ssti_probe_001.json",
    }])

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["checks"]["evidence_path"]["passed"] is False
    assert result["checks"]["evidence_path"]["missing"] == ["registered_intact_raw_evidence"]


def test_active_only_queue_fails_resolution_check(tmp_path):
    _write_passing_run(tmp_path, complete=False)

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is False
    assert result["score"] == 90
    assert result["grade"] == "needs_review"
    assert result["checks"]["queue_resolution_and_stop"]["passed"] is False
    assert result["checks"]["queue_resolution_and_stop"]["score"] == 10
    assert "final_status" in result["checks"]["queue_resolution_and_stop"]["missing"]


def test_raw_claim_does_not_create_work_or_override_current_facts(tmp_path):
    _write_passing_run(tmp_path)
    claim_path = tmp_path / "findings" / "demo.test" / "manual-sqli.json"
    _write_json(
        claim_path,
        {
            "title": "Manual SQLi claim",
            "severity": "critical",
            "endpoint": "/rest/products/search",
            "vuln_class": "SQLi",
            "poc": "curl https://demo.test/rest/products/search?q=...",
            "impact": "claimed database access",
        },
    )

    result = check_autopilot_run.check_run(tmp_path, "demo.test")

    assert result["passed"] is True
    assert TargetStore(tmp_path, "demo.test").page("findings")["total"] == 0
    assert TargetStore(tmp_path, "demo.test").page("actions")["total"] == 1


def test_direct_validated_json_cannot_replace_store_observations(tmp_path):
    _write_passing_run(tmp_path, observation=False)
    findings_path = tmp_path / "findings" / "demo.test" / "findings.json"
    _write_json(
        findings_path,
        {
            "schema_version": 1,
            "target": "demo.test",
            "findings": [
                {
                    "id": "manual-validated",
                    "type": "ssti",
                    "url": "https://demo.test/profile",
                    "validation_status": "validated",
                    "report_status": "not_generated",
                    "validation_summary": "evidence/demo.test/raw/ssti_probe_001.json",
                }
            ],
        },
    )

    result = check_autopilot_run.check_run(tmp_path, "demo.test")
    assert result["passed"] is False
    assert result["checks"]["evidence_path"]["passed"] is False
    assert TargetStore(tmp_path, "demo.test").page("findings")["total"] == 0


def test_registered_evidence_tamper_fails_without_erasing_history(tmp_path):
    store = _write_passing_run(tmp_path)
    before = store.binding()
    (tmp_path / "evidence/demo.test/raw/ssti_probe_001.json").write_text("changed")
    result = check_autopilot_run.check_run(tmp_path, "demo.test")
    assert result["passed"] is False
    assert "changed" in result["checks"]["evidence_path"]["evidence"]
    assert store.binding() == before
    assert store.page("operations")["total"] == 1


def test_high_risk_default_stop_condition_fails_stop_check(tmp_path):
    _write_passing_run(tmp_path, stop=check_autopilot_run.DEFAULT_STOP_CONDITION)

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
