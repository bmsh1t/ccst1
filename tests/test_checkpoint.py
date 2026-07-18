"""Tests for tools/checkpoint.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import checkpoint as checkpoint_module
import finding_index
from action_queue import _checkpoint_item_to_action, _dedupe_key, load_queue, save_queue
from checkpoint import (
    _build_next_action_queue,
    _align_decision_with_default_candidate,
    _coverage_gap_validation_path,
    _decide,
    _dead_end_proposals,
    _filter_final_action_queue_items,
    _lead_proposals,
    _matrix_summary,
    _next_proposals,
    _select_default_candidate,
    apply_target_memory,
    build_checkpoint,
    format_checkpoint,
)
from evidence_ledger import record_entry
from runtime_state import runtime_phase_lock, update_runtime_state
from target_case_state import add_actor, add_backlog, add_object, add_session


def _seed_recon(repo_root: Path, target: str, urls: list[str]) -> None:
    recon_dir = repo_root / "recon" / target
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [FastAPI,React] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "\n".join(urls) + "\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
    (recon_dir / "urls" / "all.txt").write_text(
        "\n".join(urls) + "\n",
        encoding="utf-8",
    )
    (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")


def test_checkpoint_without_recon_recommends_refresh_recon(tmp_path):
    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)
    witness_path = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    witness = json.loads(witness_path.read_text(encoding="utf-8"))

    assert checkpoint["decision"] == "refresh-recon"
    assert checkpoint["target"] == "target.com"
    assert any("/recon target.com" in item for item in checkpoint["target_write_back"]["next"])
    assert checkpoint["recommended_executable_action"]["type"] == "recon"
    assert checkpoint["default_candidate"] == checkpoint["recommended_executable_action"]
    assert (
        checkpoint["recommended_executable_action"]["command_hint"]
        == 'python3 tools/hunt.py --target "target.com" --recon-only && '
        'python3 tools/surface.py --target "target.com" && '
        'python3 tools/checkpoint.py --target "target.com"'
    )
    assert "CHECKPOINT DECISION" in output
    assert "Default candidate (compat pointer):" in output
    assert "Apply status: not applied" in output
    assert checkpoint["runtime_witness"]["path"] == "state/target.com/checkpoint_latest.json"
    assert witness["kind"] == "autopilot_checkpoint_witness"
    assert witness["context_pack"]["selected_skill"] == checkpoint["context_pack"]["selected_skill"]


def test_checkpoint_fails_explicitly_on_corrupt_case_state(tmp_path):
    path = tmp_path / "state" / "target.com" / "case_state.json"
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid target case state JSON"):
        build_checkpoint(tmp_path, target="target.com")


def test_checkpoint_cli_syncs_durable_action_queue_idempotently(tmp_path, capsys):
    first_exit = checkpoint_module.main([
        "--repo-root",
        str(tmp_path),
        "--target",
        "target.com",
        "--no-refresh-coverage",
        "--json",
    ])
    first = json.loads(capsys.readouterr().out)
    queue_path = tmp_path / "state" / "target.com" / "action_queue.json"
    witness_path = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    first_queue = load_queue(tmp_path, "target.com")
    witness = json.loads(witness_path.read_text(encoding="utf-8"))

    assert first_exit == 0
    assert queue_path.is_file()
    assert first_queue["actions"]
    assert first["action_queue_sync"]["path"] == str(queue_path)
    assert first["action_queue_sync"]["stats"]["added"] >= 1
    assert witness["action_queue"]["synchronized"] is True
    assert witness["action_queue"]["path"] == "state/target.com/action_queue.json"

    second_exit = checkpoint_module.main([
        "--repo-root",
        str(tmp_path),
        "--target",
        "target.com",
        "--no-refresh-coverage",
        "--json",
    ])
    second = json.loads(capsys.readouterr().out)
    second_queue = load_queue(tmp_path, "target.com")

    assert second_exit == 0
    assert second["action_queue_sync"]["stats"]["added"] == 0
    assert len(second_queue["actions"]) == len(first_queue["actions"])


def test_checkpoint_cli_fails_fast_without_overwriting_corrupt_action_queue(tmp_path, capsys):
    queue_path = tmp_path / "state" / "target.com" / "action_queue.json"
    queue_path.parent.mkdir(parents=True)
    queue_path.write_text('{"actions":', encoding="utf-8")
    original = queue_path.read_bytes()

    exit_code = checkpoint_module.main(
        [
            "--repo-root",
            str(tmp_path),
            "--target",
            "target.com",
            "--no-refresh-coverage",
            "--json",
        ]
    )

    error = capsys.readouterr().err
    assert exit_code == 2
    assert "checkpoint action queue preflight failed" in error
    assert str(queue_path) in error
    assert queue_path.read_bytes() == original


def test_checkpoint_cli_reconciles_root_json_claim_and_links_durable_actions(tmp_path, capsys):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "manual-sqli.json").write_text(
        json.dumps(
            {
                "title": "Manual SQLi claim",
                "severity": "critical",
                "endpoint": "/rest/products/search",
                "vuln_class": "SQLi",
                "poc": "curl https://target.com/rest/products/search?q=...",
                "impact": "claimed database access",
            }
        ),
        encoding="utf-8",
    )

    exit_code = checkpoint_module.main([
        "--repo-root",
        str(tmp_path),
        "--target",
        "target.com",
        "--no-refresh-coverage",
        "--json",
    ])
    checkpoint = json.loads(capsys.readouterr().out)
    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    finding = payload["findings"][0]
    queue = load_queue(tmp_path, "target.com")

    assert exit_code == 0
    assert checkpoint["root_finding_claim_sync"]["status"] == "updated"
    assert finding["validation_status"] == "candidate"
    assert finding["evidence_rubric"]["ready"] is False
    assert any(
        (item.get("metadata") or {}).get("finding_id") == finding["id"]
        for item in queue["actions"]
    )


def test_checkpoint_recovers_incomplete_root_claim_without_target_root_url(tmp_path, capsys):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "jwt-claim.json").write_text(
        json.dumps(
            {
                "title": "JWT authentication bypass",
                "target": "target.com",
                "vulnerability_class": "JWT",
                "impact": "Forged token reaches the administrator view.",
            }
        ),
        encoding="utf-8",
    )

    exit_code = checkpoint_module.main([
        "--repo-root",
        str(tmp_path),
        "--target",
        "target.com",
        "--no-refresh-coverage",
        "--json",
    ])
    checkpoint = json.loads(capsys.readouterr().out)
    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    finding = payload["findings"][0]
    queue = load_queue(tmp_path, "target.com")

    assert exit_code == 0
    assert finding["url"] == ""
    assert finding["claim_status"] == "incomplete"
    assert "endpoint" in finding["incomplete_fields"]
    assert checkpoint["structured_findings"]["pending_validation"] == 1
    assert any(
        (item.get("metadata") or {}).get("finding_id") == finding["id"]
        for item in queue["actions"]
    )


def test_checkpoint_prioritizes_pending_validation(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "F-1",
                    "type": "idor",
                    "severity": "high",
                    "confidence": "confirmed",
                    "url": "https://api.target.com/api/org/123/users",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                }
            ]
        }),
        encoding="utf-8",
    )
    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "validate"
    assert checkpoint["structured_findings"]["pending_validation"] == 1
    assert any("F-1" in item for item in checkpoint["target_write_back"]["next"])
    assert checkpoint["recommended_executable_action"]["type"] == "candidate-evidence-gap"
    assert checkpoint["recommended_executable_action"]["command_hint"] == "fill missing rubric evidence, then /validate"
    assert any(
        item["type"] == "validation"
        for item in checkpoint["next_action_queue"]
    )


def test_checkpoint_runtime_wait_marker_preempts_pending_validation(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://target.com/api/orders/1"])
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "F-wait-scan",
                    "type": "idor",
                    "severity": "high",
                    "confidence": "confirmed",
                    "url": "https://target.com/api/orders/1",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                }
            ]
        }),
        encoding="utf-8",
    )
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )

    with runtime_phase_lock(tmp_path, "target.com", "scan"):
        checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)

        assert checkpoint["decision"] == "wait_scan"
        assert checkpoint["next_action"] == "wait_scan"
        assert checkpoint["next_action_queue"] == []
        assert checkpoint["default_candidate"] == {}
        assert checkpoint["recommended_executable_action"]["type"] == "wait_scan"
        assert checkpoint["recommended_executable_action"]["status"] == "transient"
        assert checkpoint["target_write_back"]["next"] == []


def test_checkpoint_orphan_scan_marker_releases_pending_validation(tmp_path):
    """进程退出后遗留 marker 不能让 checkpoint 继续返回 wait_scan。"""
    _seed_recon(tmp_path, "target.com", ["https://target.com/api/orders/1"])
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "F-orphan-scan",
                    "type": "idor",
                    "severity": "high",
                    "confidence": "confirmed",
                    "url": "https://target.com/api/orders/1",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                }
            ]
        }),
        encoding="utf-8",
    )
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)

    assert checkpoint["decision"] == "validate"
    assert checkpoint["next_action"] != "wait_scan"
    assert checkpoint["recommended_executable_action"]["type"] != "wait_scan"


def test_checkpoint_runtime_recon_wait_marker_preempts_pending_validation(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "F-wait-recon",
                    "type": "idor",
                    "severity": "high",
                    "confidence": "confirmed",
                    "url": "https://target.com/api/orders/1",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                }
            ]
        }),
        encoding="utf-8",
    )
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="recon_running",
        last_executed_workflow="run_recon_started",
    )

    with runtime_phase_lock(tmp_path, "target.com", "recon"):
        checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)

        assert checkpoint["decision"] == "wait_recon"
        assert checkpoint["next_action"] == "wait_recon"
        assert checkpoint["next_action_queue"] == []
        assert checkpoint["default_candidate"] == {}
        assert checkpoint["recommended_executable_action"]["type"] == "wait_recon"
        assert checkpoint["recommended_executable_action"]["status"] == "transient"
        assert checkpoint["target_write_back"]["next"] == []


def test_checkpoint_displays_runner_candidates_as_advisory_evidence(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://target.com/rest/basket/6"])
    validation_dir = tmp_path / "evidence" / "target.com" / "validation" / "idor-basket"
    validation_dir.mkdir(parents=True)
    (validation_dir / "summary.json").write_text(
        json.dumps(
            {
                "lane": "idor_actor_pair",
                "finding_id": "idor-basket",
                "url": "https://target.com/rest/basket/6",
                "method": "GET",
                "result": "tested_finding",
                "candidate_ready": True,
                "evidence_rubric": {
                    "status": "candidate-ready",
                    "ready": True,
                    "summary": "authz:candidate-ready",
                },
            }
        ),
        encoding="utf-8",
    )
    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert checkpoint["validation_runner_candidates"][0]["id"] == "idor-basket"
    assert checkpoint["next_action_queue"][0]["type"] == "validation"
    assert "Review validation-runner candidate idor-basket" in checkpoint["next_action_queue"][0]["action"]
    assert "Validation runner candidates (advisory; require /validate before report):" in output
    assert "idor-basket [idor_actor_pair/tested_finding]" in output
    assert checkpoint["decision"] != "report"


def test_checkpoint_ignores_off_target_direct_finding_followup(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "OFFTARGET-IDOR",
                    "type": "idor",
                    "severity": "high",
                    "confidence": "confirmed",
                    "url": "https://steamcommunity.com/sharedfiles/filedetails/?id=1969196030",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                },
                {
                    "id": "TARGET-AUTHZ",
                    "type": "auth_bypass",
                    "severity": "high",
                    "confidence": "high",
                    "url": "https://api.target.com/rest/admin/application-configuration",
                    "validation_status": "validated",
                    "report_status": "not_generated",
                },
            ]
        }),
        encoding="utf-8",
    )
    finding_index.update_finding_status(
        findings_dir,
        "TARGET-AUTHZ",
        validation_status="validated",
        report_status="not_generated",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "report"
    assert checkpoint["structured_findings"]["pending_validation"] == 0
    assert checkpoint["structured_findings"]["validated_pending_report"] == 1
    assert checkpoint["structured_findings"]["next_report"]["id"] == "TARGET-AUTHZ"
    assert "OFFTARGET-IDOR" not in json.dumps(checkpoint["next_action_queue"])


def test_checkpoint_keeps_report_queued_without_outranking_high_value_hunt(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/admin/export?order_id=42",
    ])
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "TARGET-AUTHZ",
                    "type": "auth_bypass",
                    "severity": "high",
                    "confidence": "high",
                    "url": "https://api.target.com/rest/admin/application-configuration",
                    "validation_status": "validated",
                    "report_status": "not_generated",
                },
            ]
        }),
        encoding="utf-8",
    )
    finding_index.update_finding_status(
        findings_dir,
        "TARGET-AUTHZ",
        validation_status="validated",
        report_status="not_generated",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] in {"continue", "hunt"}
    assert checkpoint["recommended_executable_action"]["type"] != "report"
    assert checkpoint["next_action"] == checkpoint["recommended_executable_action"]["type"]
    assert "next_action=report" not in checkpoint["target_write_back"]["handoff"]
    report_action = next(item for item in checkpoint["next_action_queue"] if item["type"] == "report")
    assert report_action["metadata"]["finding_id"] == "TARGET-AUTHZ"
    assert report_action["priority"] >= 90


def test_checkpoint_decision_treats_pending_report_as_reportable_asset_not_stop_condition():
    state = {
        "has_recon": True,
        "structured_findings": {
            "validated_pending_report": 1,
            "next_report": {"id": "F-REPORT"},
        },
        "surface": {"stats": {"p1": 1, "p2": 0}},
        "recommended_targets": [{"url": "https://api.target.com/api/admin/export"}],
    }

    assert _decide(state, coverage_gaps=[], actor_gaps=[], case_state={}) == "hunt"

    report_only_state = {
        "has_recon": True,
        "structured_findings": {
            "validated_pending_report": 1,
            "next_report": {"id": "F-REPORT"},
        },
        "surface": {"stats": {"p1": 0, "p2": 0}},
        "recommended_targets": [],
    }
    assert _decide(report_only_state, coverage_gaps=[], actor_gaps=[], case_state={}) == "report"


def test_checkpoint_decision_ignores_non_actionable_pending_validation():
    state = {
        "has_recon": True,
        "structured_findings": {
            "pending_validation": 1,
            "evidence_gap_count": 1,
            # generic弱线索没有 next_validation，只保留统计，不应驱动 validate。
            "validated_pending_report": 1,
            "next_report": {"id": "F-REPORT"},
        },
        "surface": {"stats": {"p1": 1, "p2": 0}},
        "recommended_targets": [{"url": "https://api.target.com/api/admin/export"}],
    }

    assert _decide(state, coverage_gaps=[], actor_gaps=[], case_state={}) == "hunt"

    report_only_state = {
        "has_recon": True,
        "structured_findings": {
            "pending_validation": 1,
            "evidence_gap_count": 1,
            "validated_pending_report": 1,
            "next_report": {"id": "F-REPORT"},
        },
        "surface": {"stats": {"p1": 0, "p2": 0}},
        "recommended_targets": [],
    }
    assert _decide(report_only_state, coverage_gaps=[], actor_gaps=[], case_state={}) == "report"


def test_checkpoint_handoff_next_action_does_not_reuse_stale_runtime_state(tmp_path, monkeypatch):
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *args, **kwargs: {
            "has_recon": True,
            "next_action": "continue_last_focus",
            "structured_findings": {
                "pending_validation": 1,
                "evidence_gap_count": 1,
            },
            "surface": {"stats": {"review_pool": 0, "p1": 0, "p2": 0, "workflow_leads": 0}},
            "recommended_targets": [],
            "validation_runner_candidates": [],
        },
    )
    monkeypatch.setattr(
        checkpoint_module,
        "build_context_pack",
        lambda *args, **kwargs: {"phase": "recon", "selected_skill": "", "knowledge_cards": []},
    )
    monkeypatch.setattr(checkpoint_module, "rebuild_matrix", lambda *args, **kwargs: {"endpoints": []})
    monkeypatch.setattr(checkpoint_module, "save_matrix", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        checkpoint_module,
        "build_evidence_summary",
        lambda *args, **kwargs: {"actor_matrix": {"gap_count": 0, "gaps": []}},
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "handoff"
    assert checkpoint["next_action"] == "handoff"
    assert checkpoint["recommended_executable_action"] == {}
    assert "next_action=continue_last_focus" not in checkpoint["target_write_back"]["handoff"]


def test_matrix_summary_separates_raw_and_actionable_coverage_gaps():
    matrix = {
        "endpoints": [
            {
                "endpoint": "/rest/admin/application-configuration",
                "weight": 5.0,
                "cells": {"RCE": {"status": "untested"}},
            }
        ]
    }
    gaps = [
        {
            "endpoint": "/rest/admin/application-configuration",
            "vuln_class": "RCE",
            "weight": 5.0,
            "relevance_score": 0,
        },
        {
            "endpoint": "/api/search",
            "vuln_class": "SQLi",
            "weight": 5.0,
            "relevance_score": 7,
        },
    ]

    summary = _matrix_summary(matrix, gaps)

    assert summary["high_value_gaps_count"] == 2
    assert summary["actionable_high_value_gaps_count"] == 1


def test_report_action_stays_above_advisory_surface_review_but_below_high_value_actions():
    queue = _build_next_action_queue([
        "Draft report for validated finding F-REPORT; do not submit without human review.",
        "Review surface candidate https://api.target.com/api/admin/export: focused authz replay",
        "Cover high-value matrix gap: /api/admin/export x Authz (weight=5, relevance=8: admin path).",
        "Secondary-sweep lead [open-200-api-review]: Anonymous API returned 200. "
        "Artifact=findings/target/manual_review/open_200_api.txt. Why it matters: review. "
        "Next action: sample body. Stop condition: keep demoted unless concrete evidence appears.",
    ], "target.com")

    by_type = {item["type"]: item for item in queue}
    assert by_type["coverage-gap"]["priority"] > by_type["report"]["priority"]
    assert by_type["surface-review"]["priority"] < by_type["report"]["priority"]
    assert by_type["report"]["priority"] > by_type["secondary-sweep"]["priority"]
    assert by_type["report"]["metadata"]["finding_id"] == "F-REPORT"


def test_default_candidate_uses_action_queue_selection_for_executable_surface_review():
    queue = _build_next_action_queue(
        [
            "Draft report for validated finding F-REPORT; do not submit without human review.",
            (
                "Review surface candidate https://api.target.com/api/users: baseline authz checks. "
                "Replay draft: Run authenticated role replay from case_state: "
                "`python3 tools/validation_runner.py authz-role-replay --target \"target.com\" "
                "--url \"https://api.target.com/api/users\" --from-case-state --repeat 2`."
            ),
        ],
        "target.com",
    )

    assert queue[0]["type"] == "report"  # checkpoint 原始候选仍按 priority 排序。
    selected = _select_default_candidate("target.com", queue)

    assert selected["type"] == "surface-review"
    assert selected["metadata"]["endpoint"] == "/api/users"


def test_default_candidate_keeps_report_above_advisory_surface_review():
    queue = _build_next_action_queue(
        [
            "Draft report for validated finding F-REPORT; do not submit without human review.",
            "Review surface candidate https://api.target.com/api/catalog: advisory review only.",
        ],
        "target.com",
    )

    selected = _select_default_candidate("target.com", queue)

    assert selected["type"] == "report"
    assert selected["metadata"]["finding_id"] == "F-REPORT"


def test_decision_aligns_to_report_when_filtering_leaves_only_report():
    assert _align_decision_with_default_candidate(
        "hunt",
        {"type": "report", "metadata": {"finding_id": "F-REPORT"}},
    ) == "report"
    assert _align_decision_with_default_candidate(
        "hunt",
        {"type": "surface-review"},
    ) == "hunt"
    assert _align_decision_with_default_candidate(
        "validate",
        {"type": "report"},
    ) == "validate"


def test_checkpoint_replaces_replay_with_existing_candidate_evidence_gap(tmp_path):
    target = "target.com"
    surface_item = _build_next_action_queue(
        [
            (
                "Review surface candidate https://api.target.com/api/users: baseline authz checks. "
                "Replay draft: `python3 tools/validation_runner.py authz-role-replay "
                "--target \"target.com\" --url \"https://api.target.com/api/users\"`."
            )
        ],
        target,
    )[0]
    existing = _checkpoint_item_to_action(target, surface_item)
    existing.update(
        {
            "id": "AQ-0001",
            "status": "candidate",
            "type": "candidate-evidence-gap",
            "action": "Candidate evidence gap for api/users; do not rerun the same replay.",
            "next_question": "Fill missing policy evidence.",
            "command_hint": "fill missing rubric evidence, then /validate",
        }
    )
    save_queue(tmp_path, target, {"schema_version": 1, "target": target, "actions": [existing]})

    filtered = _filter_final_action_queue_items(tmp_path, target, [surface_item])
    selected = _select_default_candidate(target, filtered)

    assert filtered[0]["type"] == "candidate-evidence-gap"
    assert filtered[0]["status"] == "candidate"
    assert selected["type"] == "candidate-evidence-gap"
    assert "do not rerun" in selected["action"]


def test_checkpoint_keeps_unmatched_active_candidate_evidence_gap(tmp_path):
    target = "target.com"
    stale_candidate = _checkpoint_item_to_action(
        target,
        _build_next_action_queue(
            [
                (
                    "Review surface candidate https://api.target.com/api/users: baseline authz checks. "
                    "Replay draft: `python3 tools/validation_runner.py authz-role-replay "
                    "--target \"target.com\" --url \"https://api.target.com/api/users\"`."
                )
            ],
            target,
        )[0],
    )
    stale_candidate.update(
        {
            "id": "AQ-0001",
            "status": "candidate",
            "type": "candidate-evidence-gap",
            "priority": 60,
            "action": "Candidate evidence gap for api/users; fill policy evidence.",
            "next_question": "Fill missing policy evidence.",
            "command_hint": "fill missing rubric evidence, then /validate",
        }
    )
    save_queue(tmp_path, target, {"schema_version": 1, "target": target, "actions": [stale_candidate]})

    fresh_surface = _build_next_action_queue(
        ["Review surface candidate https://api.target.com/v3/: advisory browser-state-first review."],
        target,
    )[0]

    filtered = _filter_final_action_queue_items(tmp_path, target, [fresh_surface])
    selected = _select_default_candidate(target, filtered)

    assert any(item["type"] == "candidate-evidence-gap" for item in filtered)
    assert selected["type"] == "candidate-evidence-gap"
    assert "api/users" in selected["action"]


def test_checkpoint_drops_active_candidate_superseded_by_validated_endpoint(tmp_path):
    target = "target.com"
    active_candidate = _checkpoint_item_to_action(
        target,
        _build_next_action_queue(
            [
                (
                    "Review surface candidate https://api.target.com/api/users: baseline authz checks. "
                    "Replay draft: `python3 tools/validation_runner.py authz-role-replay "
                    "--target \"target.com\" --url \"https://api.target.com/api/users\"`."
                )
            ],
            target,
        )[0],
    )
    active_candidate.update({
        "id": "AQ-0001",
        "status": "candidate",
        "type": "candidate-evidence-gap",
        "action": "Candidate evidence gap for authz-role-replay-api_users.",
        "metadata": {
            "endpoint": "/api/users",
            "url": "https://api.target.com/api/users",
            "finding_id": "authz-role-replay-api_users",
        },
    })
    validated = dict(active_candidate)
    validated.update({
        "id": "AQ-0002",
        "status": "validated",
        "result": "validation-summary=evidence/target.com/validate/F-1/summary.json",
    })
    save_queue(
        tmp_path,
        target,
        {"schema_version": 1, "target": target, "actions": [active_candidate, validated]},
    )

    fresh_surface = _build_next_action_queue(
        ["Review surface candidate https://api.target.com/v3/: advisory browser-state-first review."],
        target,
    )[0]

    filtered = _filter_final_action_queue_items(tmp_path, target, [fresh_surface])

    assert all(item.get("type") != "candidate-evidence-gap" for item in filtered)


def test_checkpoint_keeps_validate_action_when_only_runner_marked_validated(tmp_path):
    target = "target.com"
    item = _build_next_action_queue(
        [
            (
                "Run /validate for finding AUTHZ-SYNC on https://target.com/api/Feedbacks; "
                "verify replay, A/B diff, impact, evidence rubric, and red-line safety before report."
            )
        ],
        target,
    )[0]
    action = _checkpoint_item_to_action(target, item)
    action.update({
        "id": "AQ-0001",
        "status": "validated",
        "result": "validation-runner-result=tested_finding; summary=evidence/target.com/validation/authz/summary.json",
        "dedupe_key": _dedupe_key(action),
    })
    save_queue(
        tmp_path,
        target,
        {"schema_version": 1, "target": target, "actions": [action]},
    )

    filtered = _filter_final_action_queue_items(tmp_path, target, [item])

    assert filtered == [item]


def test_checkpoint_queues_candidate_evidence_gap_before_validate(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "SQLI-1",
                    "type": "sqli",
                    "severity": "high",
                    "confidence": "medium",
                    "url": "https://api.target.com/search?q=1",
                    "summary": "possible SQL injection",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                }
            ]
        }),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Candidate evidence gap for finding SQLI-1" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert checkpoint["recommended_executable_action"]["type"] == "candidate-evidence-gap"


def test_checkpoint_treats_candidate_ready_with_missing_labels_as_evidence_gap(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "IDOR-BASKET",
                    "type": "idor",
                    "severity": "medium",
                    "confidence": "confirmed",
                    "url": "https://target.com/rest/basket/6",
                    "validation_status": "candidate",
                    "report_status": "not_generated",
                    "evidence_rubric": {
                        "rubric_id": "authz",
                        "status": "candidate-ready",
                        "ready": True,
                        "score": 90,
                        "missing_labels": ["target-owned business impact"],
                        "next_actions": [
                            "Tie the diff to concrete target-owned impact before reporting.",
                        ],
                    },
                }
            ]
        }),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "validate"
    assert checkpoint["recommended_executable_action"]["type"] == "candidate-evidence-gap"
    assert "target-owned business impact" in checkpoint["recommended_executable_action"]["action"]
    assert checkpoint["next_action_queue"][0]["type"] == "candidate-evidence-gap"


def test_checkpoint_queues_secret_verification_lane_from_repo_source_summary(tmp_path):
    exposure_dir = tmp_path / "findings" / "target.com" / "exposure"
    exposure_dir.mkdir(parents=True)
    (exposure_dir / "repo_source_meta.json").write_text(
        json.dumps({"status": "ok", "source_kind": "local", "clone_performed": False}),
        encoding="utf-8",
    )
    (exposure_dir / "repo_summary.md").write_text(
        "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 0\n",
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Secret verification lane" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert any(
        item["type"] == "secret-verification"
        for item in checkpoint["next_action_queue"]
    )


def test_checkpoint_queues_unsafe_skipped_review_from_manual_review_artifact(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/profile"])
    manual_dir = tmp_path / "findings" / "target.com" / "manual_review"
    manual_dir.mkdir(parents=True)
    (manual_dir / "unsafe_skipped.txt").write_text(
        "2026-06-07T00:00:00Z\tmethod=PUT\tlabel=HTTP method tampering probes\turl=https://api.target.com/profile\treason=requires opt-in\n",
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Review action-gated scanner lane" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    review_action = next(item for item in checkpoint["next_action_queue"] if item["type"] == "action-gated-review")
    assert review_action["redline_required"] is True
    assert review_action["metadata"]["unsafe_skipped_id"]
    assert review_action["metadata"]["artifact"] == "findings/target.com/manual_review/unsafe_skipped.txt"


def test_checkpoint_queues_secondary_sweep_for_demoted_manual_review_leads(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/profile"])
    manual_dir = tmp_path / "findings" / "target.com" / "manual_review"
    manual_dir.mkdir(parents=True)
    (manual_dir / "open_200_api.txt").write_text(
        "[OPEN-200-REVIEW] 200 1200 https://api.target.com/profile\n",
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Secondary-sweep lead [open-200-api-review]" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    action = next(item for item in checkpoint["next_action_queue"] if item["type"] == "secondary-sweep")
    assert action["command_hint"] == "review demoted raw artifact; re-promote only with concrete secret/chain evidence"
    assert action["metadata"]["lead_category"] == "open-200-api-review"
    assert action["metadata"]["artifact"] == "findings/target.com/manual_review/open_200_api.txt"


def test_checkpoint_suppresses_secondary_sweep_when_artifact_endpoint_closed_by_ledger(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/profile"])
    manual_dir = tmp_path / "findings" / "target.com" / "manual_review"
    manual_dir.mkdir(parents=True)
    (manual_dir / "open_200_api.txt").write_text(
        "[OPEN-200-REVIEW] 200 1200 https://api.target.com/profile\n",
        encoding="utf-8",
    )
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/profile",
        vuln_class="Authz",
        result="tested_clean",
        source="ai-review",
        workflow="secondary-sweep",
        evidence_ref="findings/target.com/manual_review/open_200_api.txt",
        notes="AI reviewed anonymous 200 body and found no secret/config/business-impact evidence.",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert not any(
        "Secondary-sweep lead [open-200-api-review]" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert not any(
        "Anonymous API endpoints returned substantial 200 responses" in item
        for item in checkpoint["target_write_back"]["lead"]
    )
    assert not any(item["type"] == "secondary-sweep" for item in checkpoint["next_action_queue"])


def test_lead_proposals_skip_ledger_closed_surface_candidate():
    proposals = _lead_proposals(
        {
            "has_recon": True,
            "surface": {
                "p1": [
                    {
                        "url": "https://api.target.com/api/Feedbacks",
                        "reasons": ["API endpoint"],
                        "suggested": "validate auth_bypass evidence from auth_bypass/unauth_api_access.txt",
                        "scanner_findings": [{"type": "auth_bypass"}],
                    }
                ],
                "workflow_leads": [],
            },
        },
        {"hypothesis_seeds": []},
        target="target.com",
        evidence_summary={
            "closed_cells": [
                {
                    "endpoint": "/api/Feedbacks",
                    "vuln_class": "Authz",
                    "result": "tested_finding",
                    "ts": "2026-07-06T00:00:00Z",
                }
            ]
        },
    )

    assert all("/api/Feedbacks" not in item for item in proposals)


def test_lead_proposals_keep_unknown_surface_type_fail_open():
    proposals = _lead_proposals(
        {
            "has_recon": True,
            "surface": {
                "p1": [
                    {
                        "url": "https://api.target.com/api/Feedbacks",
                        "reasons": ["API endpoint"],
                        "suggested": "review unusual scanner signal",
                        "scanner_findings": [{"type": "unknown-custom-signal"}],
                    }
                ],
                "workflow_leads": [],
            },
        },
        {"hypothesis_seeds": []},
        target="target.com",
        evidence_summary={
            "closed_cells": [
                {
                    "endpoint": "/api/Feedbacks",
                    "vuln_class": "Authz",
                    "result": "tested_finding",
                    "ts": "2026-07-06T00:00:00Z",
                }
            ]
        },
    )

    assert any("/api/Feedbacks" in item for item in proposals)


def test_checkpoint_keeps_open_200_secondary_sweep_without_authz_ledger_closure(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/profile"])
    manual_dir = tmp_path / "findings" / "target.com" / "manual_review"
    manual_dir.mkdir(parents=True)
    (manual_dir / "open_200_api.txt").write_text(
        "[OPEN-200-REVIEW] 200 1200 https://api.target.com/profile\n",
        encoding="utf-8",
    )
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/profile",
        vuln_class="SQLi",
        result="tested_clean",
        source="ai-review",
        workflow="pressure-test",
        notes="SQLi lane was tested, but anonymous 200 exposure review is still unclosed.",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Secondary-sweep lead [open-200-api-review]" in item
        for item in checkpoint["target_write_back"]["next"]
    )


def test_public_metadata_secondary_sweep_does_not_outrank_ranked_surface():
    queue = _build_next_action_queue([
        "Secondary-sweep lead [public-metadata]: Standard public metadata endpoints were demoted. "
        "Artifact=findings/target.com/manual_review/standard_public_metadata.txt. "
        "Why it matters: standard metadata. Next action: review only for unusual fields. "
        "Stop condition: keep demoted unless concrete evidence appears.",
        "Review surface candidate https://api.target.com/rest/admin/application-version: "
        "capture baseline first",
    ], "target.com")

    by_type = {item["type"]: item for item in queue}
    public_meta = next(item for item in queue if item.get("metadata", {}).get("lead_category") == "public-metadata")
    assert public_meta["priority"] < by_type["surface-review"]["priority"]


def test_checkpoint_surfaces_high_value_coverage_gaps(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/v1/admin/users?isAdmin=true&userId=1001",
    ])

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "continue"
    assert checkpoint["coverage"]["summary"]["high_value_gaps_count"] > 0
    assert any(
        "Cover high-value matrix gap" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert checkpoint["next_action_queue"]
    assert any(item["type"] == "coverage-gap" for item in checkpoint["next_action_queue"])
    assert checkpoint["recommended_executable_action"]["status"] == "ready"
    assert checkpoint["coverage"]["high_value_gaps"][0]["vuln_class"] == "Authz"
    coverage_action = next(item for item in checkpoint["next_action_queue"] if item["type"] == "coverage-gap")
    assert coverage_action["metadata"]["endpoint"] == "/api/v1/admin/users"
    assert coverage_action["metadata"]["vuln_class"] == "Authz"
    assert coverage_action["metadata"]["relevance_score"] > 0
    assert "Validation path:" in coverage_action["action"]
    assert coverage_action["metadata"]["validation_path"]
    assert "Capture the exact method, URL, headers, body" in coverage_action["metadata"]["validation_path"]
    assert (tmp_path / "evidence" / "target.com" / "coverage_matrix.json").is_file()


def test_checkpoint_does_not_queue_zero_relevance_coverage_gap():
    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": []},
        coverage_gaps=[
            {
                "endpoint": "/rest/admin",
                "vuln_class": "RCE",
                "weight": 5.0,
                "relevance_score": 0,
                "relevance_reason": "",
            }
        ],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={},
        evidence_summary={},
    )
    queue = _build_next_action_queue(proposals, "target.com")

    assert not any("Cover high-value matrix gap" in item for item in proposals)
    assert not any(item["type"] == "coverage-gap" for item in queue)


def test_checkpoint_still_queues_semantically_relevant_coverage_gap():
    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": []},
        coverage_gaps=[
            {
                "endpoint": "/rest/order-history",
                "vuln_class": "IDOR",
                "weight": 3.0,
                "relevance_score": 3,
                "relevance_reason": "object reference path/parameter",
            }
        ],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={},
        evidence_summary={},
    )
    queue = _build_next_action_queue(proposals, "target.com")

    assert any("Cover high-value matrix gap" in item for item in proposals)
    coverage_action = next(item for item in queue if item["type"] == "coverage-gap")
    assert coverage_action["metadata"]["relevance_score"] == 3


def test_path_only_authz_coverage_gap_is_baseline_first():
    validation_path = _coverage_gap_validation_path({
        "endpoint": "/rest/admin",
        "vuln_class": "Authz",
        "weight": 5.0,
        "relevance_score": 5,
        "relevance_reason": "admin/internal path",
        "observed_params": [],
    })

    assert "baseline GET or observed-method replay" in validation_path
    assert "authz-public-exposure" in validation_path
    assert "two-actor" not in validation_path


def test_checkpoint_skips_parent_only_authz_gap_when_child_validated():
    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": []},
        coverage_gaps=[
            {
                "endpoint": "/rest/admin",
                "vuln_class": "Authz",
                "weight": 5.0,
                "relevance_score": 5,
                "relevance_reason": "admin/internal path",
                "observed_params": [],
            },
            {
                "endpoint": "/api/v1/admin/users",
                "vuln_class": "Authz",
                "weight": 5.0,
                "relevance_score": 8,
                "relevance_reason": "privilege/role parameter",
                "observed_params": ["role"],
            },
        ],
        matrix={
            "endpoints": [
                {
                    "endpoint": "/rest/admin/application-configuration",
                    "cells": {"Authz": {"status": "tested_finding"}},
                }
            ]
        },
        target="target.com",
        context_pack={},
        evidence_summary={},
    )

    assert not any("Cover high-value matrix gap: /rest/admin x Authz" in item for item in proposals)
    assert any("Cover high-value matrix gap: /api/v1/admin/users x Authz" in item for item in proposals)


def test_checkpoint_skips_coverage_gap_closed_by_evidence_ledger():
    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": [], "surface": {"workflow_leads": []}},
        coverage_gaps=[
            {
                "endpoint": "/rest/products/search",
                "vuln_class": "XSS",
                "weight": 3.0,
                "relevance_score": 5,
                "relevance_reason": "reflection/DOM input surface",
                "observed_params": ["q"],
            }
        ],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={},
        evidence_summary={
            "closed_cells": [
                {
                    "endpoint": "/rest/products/search",
                    "vuln_class": "XSS",
                    "result": "tested_finding",
                    "evidence_ref": "evidence/target.com/browser/dom_xss.txt",
                }
            ]
        },
    )

    assert not any("Cover high-value matrix gap: /rest/products/search x XSS" in item for item in proposals)


def test_checkpoint_filters_actions_already_final_in_action_queue(tmp_path):
    item = {
        "id": "A1",
        "priority": 72,
        "type": "secondary-sweep",
        "status": "ready",
        "action": "Secondary-sweep lead [public-metadata]: Standard public metadata endpoints were demoted. Artifact=findings/target.com/manual_review/standard_public_metadata.txt.",
        "command_hint": "review demoted raw artifact; re-promote only with concrete secret/chain evidence",
        "redline_required": False,
        "stop_condition": "record tested, blocked, dead-end, candidate, or validated finding before moving to the next queued action",
        "metadata": {
            "lead_category": "public-metadata",
            "artifact": "findings/target.com/manual_review/standard_public_metadata.txt",
        },
    }
    action = _checkpoint_item_to_action("target.com", item)
    action["id"] = "AQ-0001"
    action["status"] = "dead-end"
    action["dedupe_key"] = _dedupe_key(action)
    save_queue(
        tmp_path,
        "target.com",
        {
            "schema_version": 1,
            "target": "target.com",
            "actions": [action],
        },
    )

    assert _filter_final_action_queue_items(tmp_path, "target.com", [item]) == []


def test_checkpoint_surfaces_actor_matrix_gaps(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/accounts/42/export?account_id=42",
    ])
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42/export",
        vuln_class="IDOR",
        actor="owner",
        object_scope="own",
        variant="baseline",
        result="tested_clean",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert checkpoint["evidence_ledger"]["entry_count"] == 1
    assert checkpoint["evidence_ledger"]["actor_matrix"]["gap_count"] > 0
    assert any(
        "Cover actor matrix gap" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert any(item["type"] == "actor-gap" for item in checkpoint["next_action_queue"])
    assert "Evidence ledger:" in output
    assert "actor matrix gaps:" in output
    assert "Next action queue:" in output
    assert "Default candidate (compat pointer):" in output


def test_checkpoint_surfaces_open_ledger_candidate_for_ai_validation(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://target.com/profile/image/url"])
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/profile/image/url",
        method="POST",
        vuln_class="SSRF",
        actor="owner",
        object_scope="own",
        variant="replay",
        result="candidate",
        replayed=True,
        state_changing=True,
        redline_checked=True,
        evidence_ref="evidence/target.com/complex/ssrf.json",
        notes="server-side URL fetch stored response",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert checkpoint["evidence_ledger"]["open_candidates"][0]["endpoint"] == "/profile/image/url"
    assert any(
        "Run /validate for ledger candidate POST /profile/image/url x SSRF" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert any(item["type"] == "validation" for item in checkpoint["next_action_queue"])
    assert "open candidates: 1" in output
    assert "POST /profile/image/url x SSRF" in output


def test_next_proposals_only_queue_anonymous_actor_gap_without_case_state():
    gaps = [
        {
            "endpoint": "/api/orders/123",
            "method": "GET",
            "vuln_class": "IDOR",
            "actor": "anonymous",
            "object_scope": "none",
            "variant": "unauth_denied",
            "expected": "deny",
            "status": "missing",
        },
        {
            "endpoint": "/api/orders/123",
            "method": "GET",
            "vuln_class": "IDOR",
            "actor": "owner",
            "object_scope": "own_object",
            "variant": "baseline",
            "expected": "allow",
            "status": "missing",
        },
        {
            "endpoint": "/api/orders/123",
            "method": "GET",
            "vuln_class": "IDOR",
            "actor": "peer",
            "object_scope": "other_object_same_org",
            "variant": "id_swap",
            "expected": "deny_or_no_data",
            "status": "missing",
        },
    ]

    proposals = _next_proposals(
        state={"has_recon": True, "surface": {}, "recommended_targets": []},
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={},
        evidence_summary={"actor_matrix": {"gaps": gaps}},
        case_state={"actors": 0, "sessions": 0, "objects": 0},
    )

    actor_gap_proposals = [
        item for item in proposals
        if item.startswith("Cover actor matrix gap:")
    ]
    assert len(actor_gap_proposals) == 1
    assert "with anonymous/none/unauth_denied" in actor_gap_proposals[0]
    assert not any("with owner/own_object/baseline" in item for item in actor_gap_proposals)
    assert not any("with peer/other_object_same_org/id_swap" in item for item in actor_gap_proposals)
    assert any(item.startswith("Case-state enrichment lead:") for item in proposals)

    queue = _build_next_action_queue(proposals, "target.com")
    actor_action = next(item for item in queue if item["type"] == "actor-gap")
    assert actor_action["redline_required"] is False
    enrichment = next(item for item in queue if item["type"] == "case-state-enrichment")
    assert enrichment["redline_required"] is False
    assert enrichment["metadata"]["missing_evidence"] == [
        "actor",
        "session",
        "business object",
    ]


def test_next_proposals_queue_role_actor_gaps_when_case_state_ready():
    gaps = [
        {
            "endpoint": "/api/orders/123",
            "method": "GET",
            "vuln_class": "IDOR",
            "actor": "anonymous",
            "object_scope": "none",
            "variant": "unauth_denied",
            "expected": "deny",
            "status": "missing",
        },
        {
            "endpoint": "/api/orders/123",
            "method": "GET",
            "vuln_class": "IDOR",
            "actor": "owner",
            "object_scope": "own_object",
            "variant": "baseline",
            "expected": "allow",
            "status": "missing",
        },
        {
            "endpoint": "/api/orders/123",
            "method": "GET",
            "vuln_class": "IDOR",
            "actor": "peer",
            "object_scope": "other_object_same_org",
            "variant": "id_swap",
            "expected": "deny_or_no_data",
            "status": "missing",
        },
    ]

    proposals = _next_proposals(
        state={"has_recon": True, "surface": {}, "recommended_targets": []},
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={},
        evidence_summary={"actor_matrix": {"gaps": gaps}},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    assert any("with owner/own_object/baseline" in item for item in proposals)
    assert any("with peer/other_object_same_org/id_swap" in item for item in proposals)
    assert not any(item.startswith("Case-state enrichment lead:") for item in proposals)

    queue = _build_next_action_queue(proposals, "target.com")
    actor_actions = [item for item in queue if item["type"] == "actor-gap"]
    assert len(actor_actions) == 3


def test_checkpoint_prioritizes_case_state_validation_backlog(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/rest/order-history/123",
    ])
    add_actor(tmp_path, "target.com", actor="user_a", role="user", label="owner")
    add_actor(tmp_path, "target.com", actor="user_b", role="user", label="peer")
    add_session(
        tmp_path,
        "target.com",
        session="sess_owner",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner-token",
    )
    add_session(
        tmp_path,
        "target.com",
        session="sess_peer",
        actor="user_b",
        kind="bearer",
        header_value="Bearer peer-token",
    )
    add_object(
        tmp_path,
        "target.com",
        object_ref="order_123",
        object_type="order",
        object_id="123",
        owner_actor="user_a",
        endpoint="https://api.target.com/rest/order-history/123",
        private_marker="owner@example.test",
    )
    add_backlog(
        tmp_path,
        "target.com",
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
        required_evidence=["owner session", "peer session", "owner private marker"],
        stop_condition="peer 403/404 or no private marker",
        chain_extensions_if_blocked=["try export endpoint", "try mobile API equivalent"],
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert checkpoint["decision"] == "continue"
    assert checkpoint["target_write_back"]["next"][0].startswith("Case-state validation backlog val_001:")
    assert checkpoint["recommended_executable_action"]["type"] == "case-state-validation"
    assert checkpoint["recommended_executable_action"]["metadata"]["backlog_id"] == "val_001"
    assert checkpoint["recommended_executable_action"]["metadata"]["runner"] == "idor-actor-pair"
    assert checkpoint["recommended_executable_action"]["metadata"]["owner_actor"] == "user_a"
    assert checkpoint["recommended_executable_action"]["metadata"]["peer_actor"] == "user_b"
    assert checkpoint["recommended_executable_action"]["metadata"]["object_ref"] == "order_123"
    assert checkpoint["recommended_executable_action"]["metadata"]["endpoint"] == "https://api.target.com/rest/order-history/123"
    assert "--from-case-state" in checkpoint["recommended_executable_action"]["command_hint"]
    assert "--backlog-id val_001" in checkpoint["recommended_executable_action"]["command_hint"]
    assert checkpoint["case_state"]["pending_validation_backlog"] == 1
    assert checkpoint["case_state"]["top_next_action"]["backlog_id"] == "val_001"
    assert "Case state:" in output
    assert "pending backlog: 1" in output


def test_checkpoint_surfaces_case_state_enrichment_when_evidence_missing(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/rest/order-history/123",
    ])
    add_actor(tmp_path, "target.com", actor="user_a", role="user", label="owner")
    add_actor(tmp_path, "target.com", actor="user_b", role="user", label="peer")
    add_session(
        tmp_path,
        "target.com",
        session="sess_owner",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner-token",
    )
    add_object(
        tmp_path,
        "target.com",
        object_ref="order_123",
        object_type="order",
        object_id="123",
        owner_actor="user_a",
        endpoint="https://api.target.com/rest/order-history/123",
    )
    add_backlog(
        tmp_path,
        "target.com",
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
        required_evidence=["owner session", "peer session", "owner private marker"],
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["target_write_back"]["next"][0].startswith("Case-state enrichment backlog val_001:")
    assert checkpoint["recommended_executable_action"]["type"] == "case-state-enrichment"
    assert checkpoint["recommended_executable_action"]["metadata"]["backlog_id"] == "val_001"
    assert checkpoint["recommended_executable_action"]["metadata"]["missing_evidence"] == [
        "peer session",
    ]
    assert "replay_draft" not in checkpoint["recommended_executable_action"]["metadata"]
    assert checkpoint["recommended_executable_action"]["command_hint"] == "enrich actor/session/object/private-marker evidence in case_state"


def test_checkpoint_surfaces_optional_case_state_marker_gap_without_blocking_replay(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/rest/order-history/123",
    ])
    add_actor(tmp_path, "target.com", actor="user_a", role="user", label="owner")
    add_actor(tmp_path, "target.com", actor="user_b", role="user", label="peer")
    add_session(tmp_path, "target.com", session="sess_owner", actor="user_a", kind="bearer", header_value="Bearer owner-token")
    add_session(tmp_path, "target.com", session="sess_peer", actor="user_b", kind="bearer", header_value="Bearer peer-token")
    add_object(
        tmp_path,
        "target.com",
        object_ref="order_123",
        object_type="order",
        object_id="123",
        owner_actor="user_a",
        endpoint="https://api.target.com/rest/order-history/123",
    )
    add_backlog(
        tmp_path,
        "target.com",
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["target_write_back"]["next"][0].startswith("Case-state validation backlog val_001:")
    assert "Optional evidence gaps: owner private marker." in checkpoint["target_write_back"]["next"][0]
    assert checkpoint["recommended_executable_action"]["type"] == "case-state-validation"
    assert checkpoint["recommended_executable_action"]["metadata"]["optional_evidence_gaps"] == ["owner private marker"]
    assert checkpoint["recommended_executable_action"]["metadata"].get("missing_evidence", []) == []


def test_checkpoint_surfaces_case_state_seed_opportunity_from_object_endpoint(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/rest/order-history/123",
    ])

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["case_state_seed"]["status"] == "suggestions"
    assert checkpoint["case_state_seed"]["suggested_objects"][0]["object_ref"] == "order_123"
    assert checkpoint["target_write_back"]["next"][0].startswith("Case-state seed opportunity:")
    assert checkpoint["recommended_executable_action"]["type"] == "case-state-seed"
    assert checkpoint["recommended_executable_action"]["metadata"]["object_ref"] == "order_123"
    assert checkpoint["recommended_executable_action"]["metadata"]["runner"] == "idor-actor-pair"
    assert checkpoint["recommended_executable_action"]["metadata"]["missing_evidence"] == [
        "owner session",
        "peer session",
        "owner private marker",
    ]
    assert "tools/case_state_seed.py" in checkpoint["recommended_executable_action"]["command_hint"]


def test_checkpoint_demotes_endpointless_case_state_seed_to_enrichment(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/rest/languages",
    ])
    add_actor(tmp_path, "target.com", actor="user_a", role="user")
    add_actor(tmp_path, "target.com", actor="user_b", role="user")
    add_session(
        tmp_path,
        "target.com",
        session="sess_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner",
    )
    add_session(
        tmp_path,
        "target.com",
        session="sess_b",
        actor="user_b",
        kind="bearer",
        header_value="Bearer peer",
    )
    browser_dir = tmp_path / "recon" / "target.com" / "browser"
    browser_dir.mkdir(parents=True)
    (browser_dir / "object_probe.json").write_text(
        json.dumps({"addressId": 7}),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    seed_action = next(
        item for item in checkpoint["next_action_queue"]
        if item.get("metadata", {}).get("object_ref") == "address_7"
    )

    assert checkpoint["case_state_seed"]["status"] == "suggestions"
    assert seed_action["type"] == "case-state-enrichment"
    assert seed_action["priority"] < 70
    assert seed_action["metadata"]["missing_evidence"] == ["object endpoint"]
    assert checkpoint["recommended_executable_action"]["type"] != "case-state-seed"
    assert "endpoint discovery lead" in seed_action["action"]


def test_checkpoint_queues_cross_evidence_convergence(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/admin/export?order_id=42",
    ])
    recon_dir = tmp_path / "recon" / "target.com"
    browser_dir = recon_dir / "browser"
    js_intel_dir = tmp_path / "findings" / "target.com" / "js_intel"
    source_intel_dir = tmp_path / "findings" / "target.com" / "source_intel"
    browser_dir.mkdir(parents=True)
    js_intel_dir.mkdir(parents=True)
    source_intel_dir.mkdir(parents=True)

    converged_url = "https://api.target.com/api/admin/export?order_id=42"
    (browser_dir / "xhr_endpoints.txt").write_text(converged_url + "\n", encoding="utf-8")
    (browser_dir / "api_endpoints.txt").write_text(converged_url + "\n", encoding="utf-8")
    (js_intel_dir / "hypotheses.json").write_text(
        json.dumps({
            "endpoints": [
                {"method": "POST", "path": "/api/admin/export?order_id=42", "auth_required": "true"}
            ],
            "attack_surface_leads": [],
            "graphql_operations": [],
        }),
        encoding="utf-8",
    )
    (source_intel_dir / "routes.json").write_text(
        json.dumps({"routes": [{"route": "/api/admin/export?order_id=42", "method": "POST"}]}),
        encoding="utf-8",
    )
    (source_intel_dir / "hypotheses.jsonl").write_text(
        json.dumps({
            "type": "idor",
            "candidate": "/api/admin/export?order_id=42",
            "reason": "admin export route uses order_id",
            "source": "routes/export.py",
        }) + "\n",
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Cross-evidence high-value surface" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert any(item["type"] == "evidence-convergence" for item in checkpoint["next_action_queue"])
    assert any(
        item["command_hint"] == "focused replay with browser/JS/source evidence"
        for item in checkpoint["next_action_queue"]
    )


def test_next_proposals_skip_ranked_surface_when_endpoint_already_has_tested_finding():
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": "https://api.target.com/api/admin/users?isAdmin=true",
                    "suggested": "prioritize authz checks",
                }
            ],
            "surface": {},
        },
        coverage_gaps=[],
        matrix={
            "endpoints": [
                {
                    "endpoint": "/api/admin/users",
                    "cells": {"Authz": {"status": "tested_finding"}},
                }
            ]
        },
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
    )

    assert not any(
        "Review surface candidate https://api.target.com/api/admin/users" in item
        for item in proposals
    )


def test_next_proposals_skip_ranked_surface_when_ledger_has_tested_clean():
    url = "https://api.target.com/rest/admin/application-version"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                }
            ],
            "surface": {
                "p1": [{"url": url, "suggested": "prioritize authenticated/browser-observed authz and workflow checks"}],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={
            "recent_entries": [
                {
                    "endpoint": "/rest/admin/application-version",
                    "vuln_class": "Authz",
                    "result": "tested_clean",
                }
            ]
        },
    )

    assert not any(
        "Review surface candidate https://api.target.com/rest/admin/application-version" in item
        for item in proposals
    )


def test_next_proposals_rolls_past_covered_ranked_surfaces():
    covered_finding = "https://api.target.com/api/admin/users"
    covered_ledger = "https://api.target.com/rest/admin/application-version"
    fresh = "https://api.target.com/api/orders"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": covered_finding,
                    "suggested": "prioritize authz checks",
                },
                {
                    "url": covered_ledger,
                    "suggested": "prioritize authz checks",
                },
                {
                    "url": fresh,
                    "suggested": "baseline authz and business-logic checks",
                },
            ],
            "surface": {
                "p1": [
                    {"url": covered_finding, "suggested": "prioritize authz checks"},
                    {"url": covered_ledger, "suggested": "prioritize authz checks"},
                    {"url": fresh, "suggested": "baseline authz and business-logic checks"},
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={
            "endpoints": [
                {
                    "endpoint": "/api/admin/users",
                    "cells": {"Authz": {"status": "tested_finding"}},
                }
            ]
        },
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={
            "recent_entries": [
                {
                    "endpoint": "/rest/admin/application-version",
                    "vuln_class": "Authz",
                    "result": "tested_clean",
                }
            ]
        },
    )

    assert not any(covered_finding in item for item in proposals)
    assert not any(covered_ledger in item for item in proposals)
    assert any(fresh in item for item in proposals)


def test_next_proposals_keeps_ranked_surface_candidates_after_secondary_sweeps():
    urls = [
        "https://api.target.com/api/one",
        "https://api.target.com/api/two",
        "https://api.target.com/api/three",
        "https://api.target.com/api/four",
    ]
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {"url": url, "suggested": "baseline authz and business-logic checks"}
                for url in urls
            ],
            "surface": {
                "p1": [
                    {"url": url, "suggested": "baseline authz and business-logic checks"}
                    for url in urls
                ],
                "workflow_leads": [
                    {
                        "category": "open-200-api-review",
                        "title": "Anonymous API endpoints returned substantial 200 responses",
                        "artifact": "findings/target/manual_review/open_200_api.txt",
                        "rationale": "manual review",
                        "next_action": "sample raw bodies",
                    },
                    {
                        "category": "public-metadata",
                        "title": "Standard public metadata endpoints were demoted",
                        "artifact": "findings/target/manual_review/public_metadata.txt",
                        "rationale": "metadata",
                        "next_action": "review only for chain pivots",
                    },
                ],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
    )

    ranked = [item for item in proposals if item.startswith("Review surface candidate ")]
    assert len(ranked) == 4
    assert any(urls[-1] in item for item in ranked)


def test_ranked_surface_proposal_includes_replay_draft_and_metadata():
    url = "https://app.target.com/api/admin/export?order_id=42"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "browser_observed": True,
                        "js_intel_endpoints": [{"method": "POST", "auth_required": "true"}],
                        "source_intel_hypotheses": [{"type": "idor", "reason": "admin export route uses order_id"}],
                        "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "Replay draft:" in ranked_text
    assert "Ledger skeleton:" in ranked_text
    assert "browser-observed request/response baseline first" in ranked_text
    assert "prefer POST replay" in ranked_text
    assert "First capture/register actor, session, and object context" in ranked_text
    assert "two-actor replay evidence" in ranked_text

    queue = _build_next_action_queue([ranked_text], "target.com")
    ranked_action = queue[0]
    assert ranked_action["type"] == "surface-review"
    assert ranked_action["metadata"]["url"] == url
    assert ranked_action["metadata"]["endpoint"] == "/api/admin/export"
    assert "browser-observed request/response baseline first" in ranked_action["metadata"]["replay_draft"]
    assert "Ledger skeleton:" not in ranked_action["metadata"]["replay_draft"]
    skeleton = ranked_action["metadata"]["ledger_record_skeleton"]
    assert "python3 tools/evidence_ledger.py record" in skeleton
    assert "--endpoint \"/api/admin/export\"" in skeleton
    assert "--method \"POST\"" in skeleton
    assert "--vuln-class \"IDOR\"" in skeleton
    assert "--actor \"anonymous\"" in skeleton
    assert "--variant \"context_prereq\"" in skeleton
    assert "--browser-observed" in skeleton
    assert "--state-changing" not in skeleton
    assert "--redline-checked" not in skeleton


def test_ranked_surface_role_replay_when_case_state_ready():
    url = "https://app.target.com/api/admin/export?order_id=42"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "browser_observed": True,
                        "js_intel_endpoints": [{"method": "POST", "auth_required": "true"}],
                        "source_intel_hypotheses": [{"type": "idor", "reason": "admin export route uses order_id"}],
                        "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "authz-role-replay" in ranked_text
    assert "use registered case_state owner/peer sessions" in ranked_text
    assert "First capture/register actor, session, and object context" not in ranked_text

    action = _build_next_action_queue([ranked_text], "target.com")[0]
    skeleton = action["metadata"]["ledger_record_skeleton"]
    assert "--actor \"owner\"" in skeleton
    assert "--variant \"role_diff\"" in skeleton


def test_ranked_surface_auth_workflow_requires_exact_request_before_role_replay():
    url = "https://app.target.com/rest/user/login"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "baseline authz and business-logic checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "suggested": "baseline authz and business-logic checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "auth-workflow endpoint; exact method/body required before replay" in ranked_text
    assert "Capture the exact auth workflow request first" in ranked_text
    assert "authz-role-replay" not in ranked_text
    assert "default GET role replay" in ranked_text

    action = _build_next_action_queue([ranked_text], "target.com")[0]
    skeleton = action["metadata"]["ledger_record_skeleton"]
    assert "--variant \"exact_request_required\"" in skeleton
    assert "--actor \"anonymous\"" in skeleton
    assert "capture exact observed method" in skeleton


def test_ranked_surface_redirect_parameter_uses_parameter_behavior_first():
    url = "https://app.target.com/redirect?to=https://example.test"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "input tampering and auth boundary checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "suggested": "input tampering and auth boundary checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "parameter-behavior-first redirect/url input; avoid role replay" in ranked_text
    assert "Run parameter-behavior validation first" in ranked_text
    assert "authz-role-replay" not in ranked_text
    assert "owner/peer role replay" in ranked_text

    action = _build_next_action_queue([ranked_text], "target.com")[0]
    skeleton = action["metadata"]["ledger_record_skeleton"]
    assert "--vuln-class \"OpenRedirect\"" in skeleton
    assert "--variant \"parameter_behavior\"" in skeleton
    assert "--actor \"anonymous\"" in skeleton


def test_ranked_surface_parent_prefix_uses_route_prefix_triage():
    url = "https://app.target.com/api"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {"url": url, "suggested": "baseline authz and business-logic checks"},
                {"url": "https://app.target.com/api/Users", "suggested": "account collection"},
            ],
            "surface": {
                "p1": [
                    {"url": url, "suggested": "baseline authz and business-logic checks"},
                    {"url": "https://app.target.com/api/Users", "suggested": "account collection"},
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "route-prefix-first parent path; validate concrete child handlers" in ranked_text
    assert "possible route-prefix/container path" in ranked_text
    assert "authz-role-replay" not in ranked_text

    action = _build_next_action_queue([ranked_text], "target.com")[0]
    skeleton = action["metadata"]["ledger_record_skeleton"]
    assert "--variant \"route_prefix_triage\"" in skeleton
    assert "--actor \"anonymous\"" in skeleton
    assert "route prefix triage" in skeleton


def test_ranked_surface_parent_prefix_uses_matrix_child_paths_when_surface_window_truncated():
    url = "https://app.target.com/api"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {"url": url, "suggested": "baseline authz and business-logic checks"},
            ],
            "surface": {
                "p1": [
                    {"url": url, "suggested": "baseline authz and business-logic checks"},
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={
            "endpoints": [
                {"endpoint": "/api", "cells": {}},
                {"endpoint": "/api/Users", "cells": {}},
            ]
        },
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "route-prefix-first parent path; validate concrete child handlers" in ranked_text
    assert "authz-role-replay" not in ranked_text


def test_ranked_surface_generic_api_uses_role_replay_when_case_state_ready():
    url = "https://app.target.com/api/Orders"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "baseline authz and business-logic checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "suggested": "baseline authz and business-logic checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "authz-role-replay" in ranked_text
    assert "--url" in ranked_text
    assert "https://app.target.com/api/Orders" in ranked_text


def test_ranked_surface_placeholder_object_uses_case_state_object():
    url = "https://app.target.com/rest/basket/NaN"
    case_state = {
        "actors": 2,
        "sessions": 2,
        "objects": 1,
        "object_samples": [
            {
                "object_ref": "basket_6",
                "type": "basket",
                "object_id": "6",
                "endpoint": "https://app.target.com/rest/basket/6",
            }
        ],
    }
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "browser_observed": True,
                        "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state=case_state,
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "non-concrete object value NaN" in ranked_text
    assert "do not replay it directly" in ranked_text
    assert "idor-actor-pair" in ranked_text
    assert "basket_6" in ranked_text
    assert "authz-role-replay" not in ranked_text

    action = _build_next_action_queue([ranked_text], "target.com")[0]
    skeleton = action["metadata"]["ledger_record_skeleton"]
    assert "--endpoint \"/rest/basket/6\"" in skeleton
    assert "--object-scope \"basket_6\"" in skeleton
    assert "--variant \"object_replay\"" in skeleton
    assert "/rest/basket/NaN" not in skeleton


def test_ranked_surface_placeholder_object_skips_when_concrete_endpoint_covered():
    url = "https://app.target.com/rest/basket/NaN"
    case_state = {
        "actors": 2,
        "sessions": 2,
        "objects": 1,
        "object_samples": [
            {
                "object_ref": "basket_6",
                "type": "basket",
                "object_id": "6",
                "endpoint": "https://app.target.com/rest/basket/6",
            }
        ],
    }
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [{"url": url, "suggested": "baseline authz"}],
            "surface": {"p1": [{"url": url, "suggested": "baseline authz"}], "workflow_leads": []},
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={
            "recent_entries": [
                {
                    "endpoint": "/rest/basket/6",
                    "vuln_class": "IDOR",
                    "result": "tested_finding",
                }
            ]
        },
        case_state=case_state,
    )

    assert not any(url in item for item in proposals)


def test_ranked_surface_finalized_finding_does_not_hide_raw_endpoint(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    url = "https://target.com/#/search?q=%3Cimg%20src=x%20onerror=marker()%3E"
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "xss_validated",
                        "type": "xss",
                        "url": url,
                        "validation_status": "validated",
                        "report_status": "not_generated",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    proposals = _next_proposals(
        state={
            "has_recon": True,
            "structured_findings": {"findings_dir": str(findings_dir)},
            "recommended_targets": [{"url": url, "suggested": "review scanner candidate"}],
            "surface": {"p1": [{"url": url, "suggested": "review scanner candidate"}], "workflow_leads": []},
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
    )

    assert any("Review surface candidate" in item and url in item for item in proposals)


def test_ranked_surface_spa_page_route_uses_browser_state_first_with_case_state_ready():
    url = "https://app.target.com/orders"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "baseline authz and business-logic checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "suggested": "baseline authz and business-logic checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
        case_state={"actors": 2, "sessions": 2, "objects": 1},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "browser-state-first page route" in ranked_text
    assert "underlying API" in ranked_text
    assert "authz-role-replay --target" not in ranked_text
    assert "raw SPA HTML shell" in ranked_text

    action = _build_next_action_queue([ranked_text], "target.com")[0]
    skeleton = action["metadata"]["ledger_record_skeleton"]
    assert "--actor \"owner\"" in skeleton
    assert "--variant \"browser_observed\"" in skeleton
    assert "browser-state-first page route" in skeleton


def test_ranked_surface_defers_repeated_authz_baselines_when_case_state_missing():
    url = "https://app.target.com/api/Cards"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "baseline authz and business-logic checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "suggested": "baseline authz and business-logic checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={
            "recent_entries": [
                {
                    "endpoint": "/api/Addresss",
                    "vuln_class": "Authz",
                    "actor": "anonymous",
                    "object_scope": "none",
                    "result": "tested_clean",
                },
                {
                    "endpoint": "/api/BasketItems",
                    "vuln_class": "Authz",
                    "actor": "anonymous",
                    "object_scope": "none",
                    "result": "tested_clean",
                },
                {
                    "endpoint": "/rest/user/change-password",
                    "vuln_class": "Authz",
                    "actor": "anonymous",
                    "object_scope": "none",
                    "result": "tested_clean",
                },
            ]
        },
        case_state={"actors": 0, "sessions": 0, "objects": 0},
    )

    assert not any(item.startswith("Review surface candidate ") for item in proposals)
    acquisition = next(item for item in proposals if item.startswith("Case-state acquisition lead:"))
    assert "3 recent anonymous Authz baseline(s)" in acquisition
    assert "testing more identical 401 baselines" in acquisition

    action = _build_next_action_queue([acquisition], "target.com")[0]
    assert action["type"] == "case-state-enrichment"
    assert action["priority"] == 66
    assert action["redline_required"] is False
    assert action["metadata"]["clean_authz_baselines"] == 3
    assert action["metadata"]["deferred_role_surfaces"] == 1


def test_coverage_gap_boilerplate_does_not_force_redline_first():
    proposal = (
        "Cover high-value matrix gap: /rest/products/search x XSS "
        "(weight=3.0, relevance=5: reflection/DOM input surface). "
        "Validation path: Capture the exact request or browser flow needed to reproduce the signal. "
        "If concrete side-effect risk appears, mark blocked and use low-risk evidence instead."
    )

    action = _build_next_action_queue([proposal], "target.com")[0]

    assert action["type"] == "coverage-gap"
    assert action["redline_required"] is False


def test_ranked_surface_path_only_authz_uses_baseline_first():
    url = "https://app.target.com/rest/admin/application-version"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "browser_observed": True,
                        "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
    )

    ranked_text = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "baseline GET or observed-method replay" in ranked_text
    assert "Build a two-actor" not in ranked_text

    action = _build_next_action_queue([ranked_text], "target.com")[0]
    skeleton = action["metadata"]["ledger_record_skeleton"]
    assert '--actor "anonymous"' in skeleton
    assert '--object-scope "none"' in skeleton
    assert '--variant "unauth_baseline"' in skeleton


def test_checkpoint_surfaces_context_contradictions_without_queueing_them(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/graphql",
    ])
    target_dir = tmp_path / "memory" / "goals" / "targets"
    target_dir.mkdir(parents=True)
    (target_dir / "target.com.json").write_text(
        json.dumps({
            "target": "target.com",
            "dead_ends": [
                {"text": "GraphQL introspection disabled; no operation names in JS"}
            ],
        }),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert any(
        "Remembered dead end may have new evidence" in item
        for item in checkpoint["context_pack"]["contradictions"]
    )
    assert not any(
        "Review context contradiction" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert not any(item["type"] == "context-review" for item in checkpoint["next_action_queue"])
    assert "Contradictions:" in output


def test_untouched_observation_prevents_false_surface_exhaustion():
    proposals = _dead_end_proposals(
        {
            "has_recon": True,
            "surface": {
                "stats": {
                    "p1": 0,
                    "p2": 0,
                    "review_pool": 0,
                    "observation_untouched": 1,
                },
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
    )

    assert proposals == []


def test_apply_target_memory_appends_checkpoint_entries(tmp_path):
    checkpoint = build_checkpoint(tmp_path, target="target.com", note="end of authz pass")

    result = apply_target_memory(tmp_path, "target.com", checkpoint)
    memory_path = tmp_path / result["target_memory_path"]
    payload = json.loads(memory_path.read_text(encoding="utf-8"))

    assert result["added"]["next"] >= 1
    assert result["added"]["handoff"] == 1
    assert payload["target"] == "target.com"
    assert payload["next_actions"]
    assert payload["session_handoffs"]
    assert (tmp_path / result["session_path"]).is_file()


def test_apply_target_memory_is_deduped(tmp_path):
    checkpoint = build_checkpoint(tmp_path, target="target.com")

    first = apply_target_memory(tmp_path, "target.com", checkpoint)
    second = apply_target_memory(tmp_path, "target.com", checkpoint)

    assert first["added"]["next"] >= 1
    assert second["added"]["next"] == 0
    assert second["added"]["handoff"] == 0
