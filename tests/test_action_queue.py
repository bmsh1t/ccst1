"""Tests for the persistent autopilot action queue."""

from __future__ import annotations

import json
import multiprocessing
import subprocess
import sys
from pathlib import Path

import pytest

import action_queue as action_queue_module
from action_queue import (
    add_manual_action,
    build_action,
    claim_next_action,
    format_action,
    ingest_checkpoint,
    load_queue,
    main,
    resolve_action,
    save_queue,
    select_next_action,
    select_next_action_for_target,
    summarize_queue,
)
from coverage_matrix import load_matrix, mark_cell
from finding_index import write_finding_index
from runtime_state import runtime_phase_lock, update_runtime_state


def _resolve_unsafe_review_worker(repo_root, target, action_id, output):
    try:
        resolve_action(
            repo_root,
            target=target,
            action_id=action_id,
            status="blocked",
            result=f"blocked-{action_id}",
        )
        output.put("ok")
    except Exception as exc:  # pragma: no cover - surfaced through parent assertion
        output.put(str(exc))


def _claim_action_worker(repo_root, target, output):
    try:
        claimed = claim_next_action(repo_root, target)
        output.put((claimed.get("id", ""), claimed.get("claim_status", ""), ""))
    except Exception as exc:  # pragma: no cover - surfaced through parent assertion
        output.put(("", "error", str(exc)))


def _checkpoint() -> dict:
    return {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 75,
                "type": "coverage-gap",
                "status": "ready",
                "action": "Cover high-value matrix gap: /api/admin/users x IDOR.",
                "command_hint": "focused low-risk probe + evidence ledger",
                "redline_required": True,
                "stop_condition": "record tested, blocked, dead-end, or candidate",
                "metadata": {
                    "endpoint": "/api/admin/users",
                    "vuln_class": "Authz",
                    "weight": "5.0",
                    "relevance_score": 13,
                },
            },
            {
                "id": "A2",
                "priority": 90,
                "type": "known-software-intel",
                "status": "ready",
                "action": "Check known advisories for WordPress plugin X 1.2.3.",
                "command_hint": "/intel + cve_hunter",
                "redline_required": False,
            },
        ]
    }


def _snapshot_files(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_ingest_checkpoint_persists_and_prioritizes(tmp_path):
    finding_root = tmp_path / "findings" / "target.com"
    ledger_root = tmp_path / "memory" / "evidence" / "target.com"
    write_finding_index(finding_root, target="target.com")
    ledger_root.mkdir(parents=True)
    (ledger_root / "ledger.jsonl").touch()
    owner_snapshots = {
        root: _snapshot_files(root)
        for root in (finding_root, ledger_root)
    }

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())

    assert result["stats"]["added"] == 2
    assert result["next"]["type"] in {"known-software-intel", "coverage-gap"}
    assert result["next"]["type"] != "generic-follow-up"

    queue = load_queue(tmp_path, "target.com")
    assert summarize_queue(queue)["active"] == 2
    assert (tmp_path / "state" / "target.com" / "action_queue.json").is_file()
    assert {root: _snapshot_files(root) for root in owner_snapshots} == owner_snapshots

    claimed = claim_next_action(tmp_path, "target.com")
    resolve_action(
        tmp_path,
        target="target.com",
        action_id=claimed["id"],
        status="blocked",
        result="Owner review deferred without a Finding or Evidence conclusion.",
    )
    assert {root: _snapshot_files(root) for root in owner_snapshots} == owner_snapshots


def test_claim_is_atomic_and_resumes_running_before_new_queued_work(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())

    first = claim_next_action(tmp_path, "target.com")
    first_id = first["id"]
    queued_id = next(
        item["id"]
        for item in load_queue(tmp_path, "target.com")["actions"]
        if item["id"] != first_id
    )
    resolve_action(
        tmp_path,
        target="target.com",
        action_id=first_id,
        status="running",
        notes="preserve replay context",
    )

    resumed = claim_next_action(tmp_path, "target.com")
    queue = load_queue(tmp_path, "target.com")
    running = next(item for item in queue["actions"] if item["id"] == first_id)

    assert first["claim_status"] == "claimed"
    assert resumed["id"] == first_id
    assert resumed["claim_status"] == "resumed"
    assert running["status"] == "running"
    assert running["attempts"] == 1
    assert running["notes"] == "preserve replay context"
    assert next(item for item in queue["actions"] if item["id"] == queued_id)["status"] == "queued"


def test_concurrent_claims_grant_one_new_execution_permit(tmp_path):
    target = "target.com"
    ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={
            "next_action_queue": [
                {
                    "id": "AQ-ONLY",
                    "priority": 90,
                    "type": "workflow-lead-review",
                    "status": "ready",
                    "action": "Review one durable owner fact.",
                    "metadata": {"category": "asset-scope-review"},
                }
            ]
        },
    )

    context = multiprocessing.get_context("fork")
    output = context.Queue()
    workers = [
        context.Process(target=_claim_action_worker, args=(str(tmp_path), target, output))
        for _ in range(12)
    ]
    for process in workers:
        process.start()
    results = [output.get(timeout=15) for _ in workers]
    for process in workers:
        process.join(timeout=15)

    queue = load_queue(tmp_path, target)
    action = queue["actions"][0]

    assert all(process.exitcode == 0 for process in workers)
    assert all(not error for _, _, error in results)
    assert {action_id for action_id, _, _ in results} == {action["id"]}
    assert [status for _, status, _ in results].count("claimed") == 1
    assert [status for _, status, _ in results].count("resumed") == len(workers) - 1
    assert action["status"] == "running"
    assert action["attempts"] == 1


def test_checkpoint_generated_action_is_idempotent_by_generation(tmp_path):
    item = {
        "id": "JSON-INJECT",
        "priority": 80,
        "type": "json-inject-review",
        "status": "ready",
        "action": "Review JSON injection candidates.",
        "source": "json-inject",
        "source_id": "json-inject-lane",
        "metadata": {"generation": "g1"},
    }

    first = ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [item]})
    second = ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [item]})

    assert first["stats"]["added"] == 1
    assert second["stats"]["added"] == 0
    assert len(load_queue(tmp_path, "target.com")["actions"]) == 1


def test_checkpoint_generated_action_reopens_only_for_a_new_generation(tmp_path):
    item = {
        "id": "ASSET-SCOPE",
        "priority": 88,
        "type": "workflow-lead-review",
        "status": "ready",
        "action": "Review target-linked external asset scope evidence.",
        "source": "workflow-lead",
        "source_id": "asset-scope-review",
        "metadata": {"generation": "g1", "category": "asset-scope-review"},
    }
    ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [item]})
    action = load_queue(tmp_path, "target.com")["actions"][0]
    resolve_action(
        tmp_path,
        target="target.com",
        action_id=action["id"],
        status="tested",
        result="Kept as external chain context.",
    )

    same = ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [item]})
    newer = ingest_checkpoint(
        tmp_path,
        "target.com",
        checkpoint={
            "next_action_queue": [
                {**item, "metadata": {**item["metadata"], "generation": "g2"}}
            ]
        },
    )

    assert same["stats"]["skipped_final"] == 1
    assert newer["stats"]["added"] == 1
    assert summarize_queue(load_queue(tmp_path, "target.com"))["active"] == 1


def test_concurrent_manual_actions_do_not_lose_updates(tmp_path):
    code = """
import sys
from tools.action_queue import add_manual_action

root, evidence = sys.argv[1:]
add_manual_action(
    root,
    target="target.com",
    action_type="manual-check",
    evidence=evidence,
    next_question=f"review {evidence}",
    action=f"run {evidence}",
)
"""
    repo_root = Path(__file__).resolve().parents[1]
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path), evidence],
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for evidence in ("first", "second")
    ]
    for process in processes:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr

    queue = load_queue(tmp_path, "target.com")
    assert {item["evidence"] for item in queue["actions"]} == {"first", "second"}


def test_target_next_honors_scan_wait_marker_without_deleting_queue(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queued_before = select_next_action(load_queue(tmp_path, "target.com"))
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )

    with runtime_phase_lock(tmp_path, "target.com", "scan"):
        selected = select_next_action_for_target(tmp_path, "target.com")
        queue = load_queue(tmp_path, "target.com")

        assert selected["type"] == "wait_scan"
        assert selected["id"] == "runtime-wait"
        assert summarize_queue(queue, repo_root=tmp_path, target="target.com")["next_id"] == "runtime-wait"
        assert select_next_action(queue)["id"] == queued_before["id"]
        assert summarize_queue(queue)["active"] == 2

    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_only",
        last_executed_workflow="run_vuln_scan",
    )
    assert select_next_action_for_target(tmp_path, "target.com")["id"] == queued_before["id"]


def test_target_next_ignores_orphan_scan_marker_and_keeps_queue_selectable(tmp_path):
    """被终止的后台 scanner 释放锁后不能继续掩盖已持久化的下一步。"""
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queued_before = select_next_action(load_queue(tmp_path, "target.com"))
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )

    selected = select_next_action_for_target(tmp_path, "target.com")

    assert selected["id"] == queued_before["id"]
    assert selected["type"] != "wait_scan"


def test_target_next_honors_recon_wait_marker_without_deleting_queue(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queued_before = select_next_action(load_queue(tmp_path, "target.com"))
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="recon_running",
        last_executed_workflow="run_recon_started",
    )

    with runtime_phase_lock(tmp_path, "target.com", "recon"):
        selected = select_next_action_for_target(tmp_path, "target.com")

        assert selected["type"] == "wait_recon"
        assert selected["id"] == "runtime-wait"
        assert select_next_action(load_queue(tmp_path, "target.com"))["id"] == queued_before["id"]

    update_runtime_state(
        tmp_path,
        "target.com",
        mode="recon_only",
        last_executed_workflow="run_recon",
    )
    assert select_next_action_for_target(tmp_path, "target.com")["id"] == queued_before["id"]


def test_action_queue_cli_next_honors_runtime_wait_marker(tmp_path, capsys):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )

    with runtime_phase_lock(tmp_path, "target.com", "scan"):
        code = main([
            "--repo-root", str(tmp_path),
            "next",
            "--target", "target.com",
            "--json",
        ])
        output = json.loads(capsys.readouterr().out)

        assert code == 0
        assert output["type"] == "wait_scan"
        assert output["status"] == "transient"


def test_ingest_checkpoint_runtime_wait_does_not_retire_existing_queue(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queued_before = select_next_action(load_queue(tmp_path, "target.com"))
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )

    with runtime_phase_lock(tmp_path, "target.com", "scan"):
        result = ingest_checkpoint(
            tmp_path,
            "target.com",
            checkpoint={"next_action_queue": []},
        )
        queue = load_queue(tmp_path, "target.com")

        assert result["stats"]["retired_stale"] == 0
        assert result["next"]["type"] == "wait_scan"
        assert summarize_queue(queue)["active"] == 2
        assert select_next_action(queue)["id"] == queued_before["id"]


def test_report_action_does_not_preempt_active_validation_work(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 99,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "V1",
                "priority": 80,
                "type": "ranked-surface",
                "action": "Continue browser-observed API role replay.",
                "command_hint": "python3 tools/validation_runner.py authz-role-replay ...",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    queue = load_queue(tmp_path, "target.com")

    assert select_next_action(queue)["type"] == "ranked-surface"

    validation = next(item for item in queue["actions"] if item["type"] == "ranked-surface")
    resolve_action(
        tmp_path,
        target="target.com",
        action_id=validation["id"],
        status="tested",
        result="Role replay completed; no additional delta.",
    )
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "report"


def test_surface_review_does_not_preempt_report_when_no_substantive_work(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 90,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "S1",
                "priority": 70,
                "type": "surface-review",
                "action": "Review surface candidate https://api.target.com/rest/user.",
                "command_hint": "AI reviews surface evidence, then chooses the exact lane",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "report"


@pytest.mark.parametrize(
    ("other_type", "other_status"),
    [
        ("runtime-recovery", "running"),
        ("validation", "queued"),
        ("candidate-evidence-gap", "candidate"),
        ("report", "queued"),
    ],
)
def test_capability_chain_review_never_preempts_existing_owner_work(other_type, other_status):
    review = build_action(
        target="target.com",
        action_type="capability-chain-review",
        evidence="A persisted capability primitive needs bounded chain review.",
        next_question="Does one evidence-backed chain remain?",
        action="Review one primitive.",
        priority=999,
    )
    review["id"] = "AQ-REVIEW"
    other = build_action(
        target="target.com",
        action_type=other_type,
        evidence="Existing owner work remains open.",
        next_question="Can the existing work be completed?",
        action="Complete the existing owner work.",
        priority=1,
    )
    other.update({"id": "AQ-OWNER", "status": other_status})

    assert select_next_action({"actions": [review, other]})["id"] == other["id"]


def test_surface_review_with_runner_replay_preempts_report(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 90,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "S1",
                "priority": 70,
                "type": "surface-review",
                "action": "Review surface candidate https://api.target.com/rest/user.",
                "command_hint": "AI reviews surface evidence, then chooses the exact lane",
                "redline_required": False,
                "metadata": {
                    "endpoint": "/rest/user",
                    "replay_draft": (
                        "Run authenticated role replay: "
                        "python3 tools/validation_runner.py authz-role-replay "
                        "--target target.com --url https://api.target.com/rest/user"
                    ),
                },
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    selected = select_next_action(load_queue(tmp_path, "target.com"))

    assert selected["type"] == "surface-review"
    assert selected["metadata"]["endpoint"] == "/rest/user"


def test_legacy_ranked_surface_without_runner_is_advisory(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 90,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "OLD1",
                "priority": 92,
                "type": "ranked-surface",
                "action": "Continue top ranked surface https://api.target.com/rest/legacy.",
                "command_hint": "focused hunt on ranked P1/P2 surface",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "report"


def test_current_surface_review_beats_stale_legacy_ranked_surface_when_only_advisory(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "OLD1",
                "priority": 92,
                "type": "ranked-surface",
                "action": "Continue top ranked surface https://api.target.com/rest/legacy.",
                "command_hint": "focused hunt on ranked P1/P2 surface",
                "redline_required": False,
            },
            {
                "id": "S1",
                "priority": 70,
                "type": "surface-review",
                "action": "Review surface candidate https://api.target.com/rest/current.",
                "command_hint": "AI reviews surface evidence, then chooses the exact lane",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    selected = select_next_action(load_queue(tmp_path, "target.com"))
    assert selected["type"] == "surface-review"
    assert "current" in selected["action"]


def test_low_evidence_top_advisory_surface_review_does_not_drive_next(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 70,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": (
                "Review surface candidate https://target.com/address/create: "
                "baseline authz and business-logic checks. Reason: top advisory score. "
                "AI decision required: choose the exact lane."
            ),
            "next_question": "Execute checkpoint action.",
            "action": (
                "Review surface candidate https://target.com/address/create: "
                "baseline authz and business-logic checks. Reason: top advisory score. "
                "AI decision required: choose the exact lane."
            ),
            "command_hint": "AI reviews surface evidence, then chooses the exact lane",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "old-low-evidence",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/address/create",
                "suggested": (
                    "baseline authz and business-logic checks. Reason: top advisory score. "
                    "AI decision required: choose the exact lane"
                ),
                "replay_draft": "browser-state-first page route; extract the real XHR first",
            },
        }
    ]

    assert select_next_action(queue) == {}


def test_low_evidence_surface_review_with_exact_runner_stays_selectable(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 70,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": (
                "Review surface candidate https://target.com/api/users: "
                "baseline authz checks. Reason: top advisory score. "
                "Replay draft: python3 tools/validation_runner.py authz-role-replay "
                "--target target.com --url https://target.com/api/users"
            ),
            "next_question": "Execute checkpoint action.",
            "action": (
                "Review surface candidate https://target.com/api/users: "
                "baseline authz checks. Reason: top advisory score. "
                "Replay draft: python3 tools/validation_runner.py authz-role-replay "
                "--target target.com --url https://target.com/api/users"
            ),
            "command_hint": "AI reviews surface evidence, then chooses the exact lane",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "runner-backed-review",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/api/users",
                "replay_draft": (
                    "python3 tools/validation_runner.py authz-role-replay "
                    "--target target.com --url https://target.com/api/users"
                ),
            },
        }
    ]

    assert select_next_action(queue)["id"] == "AQ-0001"


def test_ingest_checkpoint_preserves_structured_metadata(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())

    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

    assert coverage["metadata"]["endpoint"] == "/api/admin/users"
    assert coverage["metadata"]["vuln_class"] == "Authz"
    assert "Metadata: endpoint=/api/admin/users" in format_action(coverage)


def test_ingest_checkpoint_dedupes_active_actions(tmp_path):
    first = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queue_path = tmp_path / "state" / "target.com" / "action_queue.json"
    first_inode = queue_path.stat().st_ino
    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())

    assert first["stats"]["added"] == 2
    assert second["stats"]["added"] == 0
    assert second["stats"]["updated"] == 0
    assert queue_path.stat().st_ino == first_inode
    assert {item["id"] for item in load_queue(tmp_path, "target.com")["actions"]} == {"AQ-0001", "AQ-0002"}
    assert select_next_action(load_queue(tmp_path, "target.com"))["id"] == "AQ-0002"


def test_checkpoint_metadata_only_update_is_persisted(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    refreshed = _checkpoint()
    refreshed["next_action_queue"][0]["metadata"]["validation_path"] = "focused replay"

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint=refreshed)

    assert result["stats"]["updated"] == 1
    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")
    assert coverage["metadata"]["validation_path"] == "focused replay"


def test_checkpoint_reingest_can_clear_stale_redline_flag(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 80,
                "type": "actor-gap",
                "status": "ready",
                "action": "Cover actor matrix gap: /api/orders/123 x Authz with anonymous/none/unauth_denied expected=deny status=missing.",
                "command_hint": "focused replay + tools/evidence_ledger.py record",
                "redline_required": True,
                "metadata": {
                    "endpoint": "/api/orders/123",
                    "vuln_class": "Authz",
                    "actor": "anonymous",
                },
            }
        ]
    }
    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    checkpoint["next_action_queue"][0]["redline_required"] = False
    checkpoint["next_action_queue"][0]["priority"] = 54

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)

    queue = load_queue(tmp_path, "target.com")
    assert queue["actions"][0]["redline_required"] is False
    assert queue["actions"][0]["priority"] == 54


def test_resolve_final_action_prevents_readding_same_todo(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    next_action = select_next_action(load_queue(tmp_path, "target.com"))

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=next_action["id"],
        status="dead-end",
        result="Version not affected after advisory range check.",
    )
    assert resolved["status"] == "dead-end"

    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    assert second["stats"]["skipped_final"] == 1
    assert summarize_queue(load_queue(tmp_path, "target.com"))["total"] == 2
    assert next_action["type"] == "known-software-intel"
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "coverage-gap"


def test_generated_action_updates_queued_generation_and_reopens_after_final(tmp_path):
    common = {
        "target": "target.com",
        "action_type": "deep-js-review",
        "evidence": "recon/target.com/js/deep_candidates.txt",
        "next_question": "Which high-value bundles need review?",
        "action": "Review bounded deep-JS candidates",
        "source": "recon",
        "source_id": "deep-js-review",
    }

    first = add_manual_action(tmp_path, generation="gen-1", **common)
    updated = add_manual_action(tmp_path, generation="gen-2", **common)
    queue = load_queue(tmp_path, "target.com")

    assert first["stats"]["added"] == 1
    assert updated["stats"]["updated"] == 1
    assert len(queue["actions"]) == 1
    assert queue["actions"][0]["metadata"]["generation"] == "gen-2"

    resolve_action(
        tmp_path,
        target="target.com",
        action_id=queue["actions"][0]["id"],
        status="tested",
        result="Reviewed the selected bundles.",
    )
    same = add_manual_action(tmp_path, generation="gen-2", **common)
    newer = add_manual_action(tmp_path, generation="gen-3", **common)

    assert same["stats"]["skipped_final"] == 1
    assert newer["stats"]["added"] == 1
    assert summarize_queue(load_queue(tmp_path, "target.com"))["active"] == 1


def test_ingest_checkpoint_retires_stale_checkpoint_queued_actions(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    refreshed = {
        "next_action_queue": [
            {
                "id": "A2",
                "priority": 90,
                "type": "known-software-intel",
                "status": "ready",
                "action": "Check known advisories for WordPress plugin X 1.2.3.",
                "command_hint": "/intel + cve_hunter",
                "redline_required": False,
            },
        ]
    }

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint=refreshed)
    queue = load_queue(tmp_path, "target.com")
    stale = next(item for item in queue["actions"] if item["id"] == "AQ-0001")

    assert result["stats"]["retired_stale"] == 1
    assert stale["status"] == "n/a"
    assert "checkpoint refresh" in stale["result"].lower()


def test_ingest_checkpoint_keeps_coverage_identity_across_projection_wording(tmp_path):
    base = (
        "Cover high-value matrix gap: /api/orders/list x Path "
        "(weight=3.5, relevance=14: observed file selector)."
    )
    legacy = {
        "next_action_queue": [{
            "id": "LEGACY-COVERAGE",
            "priority": 80,
            "type": "coverage-gap",
            "status": "ready",
            "action": base + " Family projection: key=route; kind=route-template; size=2; samples=/api/orders/list,/api/orders/export.",
            "command_hint": "focused replay",
            "metadata": {"endpoint": "/api/orders/list", "vuln_class": "Path"},
        }]
    }
    current = {
        "next_action_queue": [{
            "id": "CURRENT-COVERAGE",
            "priority": 80,
            "type": "coverage-gap",
            "status": "ready",
            "action": base + " Queue projection only: this representative is advisory. Family projection: key=route; kind=route-template; size=2; members=/api/orders/list,/api/orders/export.",
            "command_hint": "focused replay",
            "metadata": {"endpoint": "/api/orders/list", "vuln_class": "Path"},
        }]
    }

    first = ingest_checkpoint(tmp_path, "target.com", checkpoint=legacy)
    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=current)

    assert first["stats"]["added"] == 1
    assert second["stats"]["added"] == 0
    assert second["stats"]["updated"] == 1
    assert second["stats"]["retired_stale"] == 0
    assert len(load_queue(tmp_path, "target.com")["actions"]) == 1


def test_ingest_checkpoint_preserves_running_versioned_hypothesis(tmp_path):
    ingest_checkpoint(
        tmp_path,
        "target.com",
        checkpoint={
            "next_action_queue": [
                {
                    "id": "H-ADMIN",
                    "priority": 99,
                    "type": "coverage-gap",
                    "status": "ready",
                    "action": "Replay the admin configuration boundary.",
                    "command_hint": "focused authz replay",
                    "source": "checkpoint",
                    "source_id": "admin-authz",
                    "metadata": {
                        "endpoint": "/rest/admin/application-configuration",
                        "depth_contract_version": 1,
                        "hypothesis_id": "H-admin-config",
                    },
                }
            ]
        },
    )
    queue = load_queue(tmp_path, "target.com")
    queue["actions"][0]["status"] = "running"
    save_queue(tmp_path, "target.com", queue)

    refreshed = ingest_checkpoint(
        tmp_path,
        "target.com",
        checkpoint={
            "next_action_queue": [
                {
                    "id": "NEW-ACTION",
                    "priority": 80,
                    "type": "coverage-gap",
                    "status": "ready",
                    "action": "Review a different evidence-backed lane.",
                    "command_hint": "focused replay",
                }
            ]
        },
    )
    saved = load_queue(tmp_path, "target.com")
    preserved = next(item for item in saved["actions"] if item["id"] == "AQ-0001")

    assert refreshed["stats"]["retired_stale"] == 0
    assert preserved["status"] == "running"
    assert preserved["metadata"]["hypothesis_id"] == "H-admin-config"


def test_ingest_checkpoint_retires_stale_running_versionless_action(tmp_path):
    ingest_checkpoint(
        tmp_path,
        "target.com",
        checkpoint={
            "next_action_queue": [{
                "id": "LEGACY",
                "priority": 80,
                "type": "coverage-gap",
                "status": "ready",
                "action": "Replay the legacy queued check.",
                "command_hint": "focused replay",
            }]
        },
    )
    queue = load_queue(tmp_path, "target.com")
    queue["actions"][0]["status"] = "running"
    save_queue(tmp_path, "target.com", queue)

    refreshed = ingest_checkpoint(
        tmp_path,
        "target.com",
        checkpoint={
            "next_action_queue": [{
                "id": "NEW",
                "priority": 70,
                "type": "coverage-gap",
                "status": "ready",
                "action": "Review current checkpoint work.",
                "command_hint": "focused replay",
            }]
        },
    )
    saved = load_queue(tmp_path, "target.com")
    legacy = next(item for item in saved["actions"] if item["id"] == "AQ-0001")

    assert refreshed["stats"]["retired_stale"] == 1
    assert legacy["status"] == "n/a"


def test_ingest_checkpoint_retires_stale_partial_validation_candidate(tmp_path):
    stale_checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 100,
                "type": "validation",
                "status": "ready",
                "action": "Run /validate for finding F-old on https://target.com/api/feedbacks.",
                "command_hint": "/validate",
                "redline_required": True,
                "metadata": {
                    "endpoint": "/api/feedbacks",
                    "finding_id": "F-old",
                },
            }
        ]
    }
    ingest_checkpoint(tmp_path, "target.com", checkpoint=stale_checkpoint)
    queue = load_queue(tmp_path, "target.com")
    queue["actions"][0]["status"] = "candidate"
    queue["actions"][0]["result"] = "validation-summary=/tmp/feedbacks/validation-summary.json"
    from action_queue import save_queue

    save_queue(tmp_path, "target.com", queue)

    refreshed = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 100,
                "type": "validation",
                "status": "ready",
                "action": "Run /validate for finding F-new on https://target.com/rest/products/search?q=apple.",
                "command_hint": "/validate",
                "redline_required": True,
                "metadata": {
                    "endpoint": "/rest/products/search",
                    "finding_id": "F-new",
                },
            }
        ]
    }

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint=refreshed)
    saved = load_queue(tmp_path, "target.com")
    stale = next(item for item in saved["actions"] if item["metadata"]["finding_id"] == "F-old")

    assert result["stats"]["retired_stale"] == 1
    assert stale["status"] == "n/a"
    assert select_next_action(saved)["metadata"]["finding_id"] == "F-new"


def test_manual_role_replay_is_not_marked_redline_by_keywords(tmp_path):
    added = add_manual_action(
        tmp_path,
        target="api.target.com",
        action_type="browser-api",
        evidence_type="browser-xhr",
        evidence="Dashboard calls /api/internal/export.",
        next_question="Can anonymous or low-role replay access export data?",
        action="Replay with anonymous and low-role sessions, then record role diff.",
        priority=88,
        command_hint="browser capture + role_diff",
    )
    assert added["stats"]["added"] == 1

    queue = load_queue(tmp_path, "api.target.com")
    action = select_next_action(queue)
    assert action["id"] == "AQ-0001"
    assert action["redline_required"] is False

    resolved = resolve_action(
        tmp_path,
        target="api.target.com",
        action_id="AQ-0001",
        status="candidate",
        result="Low-role replay returned another tenant export metadata.",
        notes="Needs exact /validate replay.",
    )
    assert resolved["summary"]["by_status"]["candidate"] == 1
    saved = json.loads((tmp_path / "state" / "api.target.com" / "action_queue.json").read_text())
    assert saved["actions"][0]["status"] == "candidate"


def test_manual_action_cli_accepts_stop_condition_for_high_risk_lane(tmp_path):
    code = main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--type", "ssrf-parser-boundary",
        "--evidence", "URL fetch path accepts user-controlled callback URL.",
        "--next-question", "Does parser normalization change internal host handling?",
        "--action", "python3 tools/context_pack.py --target api.target.com --focus ssrf",
        "--command-hint", "python3 tools/context_pack.py --target api.target.com --focus ssrf",
        "--stop-condition", "Stop after a read-only parser-boundary probe is recorded as tested, blocked, dead-end, signal, or candidate.",
        "--json",
    ])

    assert code == 0
    queue = load_queue(tmp_path, "api.target.com")
    action = queue["actions"][0]
    assert action["type"] == "ssrf-parser-boundary"
    assert action["stop_condition"].startswith("Stop after a read-only parser-boundary probe")
    assert action["stop_condition"] != "record tested, dead-end, blocked, lead, signal, candidate, or validated before moving to the next queued action"


def test_manual_action_cli_writes_metadata_and_preserves_duplicate_queue_behavior(tmp_path):
    metadata = {
        "hypothesis_id": "H-42",
        "family": "custom-template-chain",
        "chain": ["template", "sandbox", "execution"],
        "tested_dimensions": ["sibling endpoint", "low-role actor"],
        "expected_learning": "A role difference should reveal object scoping.",
        "kill_condition": "Responses remain identical across both actors.",
        "next_question": "Does the sibling endpoint enforce the same object check?",
        "attempts": 2,
        "last_outcome": "anonymous baseline returned 403",
    }
    argv = [
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--type", "browser-api",
        "--evidence", "Observed an object endpoint in the browser trace.",
        "--next-question", "Can a low-role actor replay the object request?",
        "--action", "Replay the request with the low-role actor.",
        "--metadata-json", json.dumps(metadata),
        "--json",
    ]

    assert main(argv) == 0
    assert main(argv) == 0
    queue = load_queue(tmp_path, "api.target.com")

    assert len(queue["actions"]) == 1
    assert queue["actions"][0]["metadata"] == metadata


def test_resolve_cli_merges_structured_metadata_idempotently(tmp_path):
    initial_metadata = {
        "hypothesis_id": "H-42",
        "tested_dimensions": ["sibling endpoint"],
        "expected_learning": "A role difference should reveal object scoping.",
        "kill_condition": "Responses remain identical across both actors.",
        "next_question": "Can the sibling endpoint be replayed?",
        "last_outcome": {"status": "running", "evidence_ref": "evidence/trace.json"},
        "pivot_hints": ["try export"],
    }
    assert main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--type", "browser-api",
        "--evidence", "Observed an object endpoint in the browser trace.",
        "--next-question", "Can a low-role actor replay the object request?",
        "--action", "Replay the request with the low-role actor.",
        "--metadata-json", json.dumps(initial_metadata),
        "--json",
    ]) == 0

    update = {
        "tested_dimensions": ["sibling endpoint", "low-role actor"],
        "next_question": "Does the export endpoint enforce the same object check?",
        "expected_learning": "Export responses should preserve object scoping.",
        "kill_condition": "Both export actors receive the same object body.",
        "last_outcome": {"status": "blocked", "notes": "peer session expired"},
        "pivot_hints": ["try export", "try GraphQL"],
    }
    argv = [
        "--repo-root", str(tmp_path),
        "resolve",
        "--target", "api.target.com",
        "--id", "AQ-0001",
        "--status", "blocked",
        "--evidence", "peer session expired",
        "--metadata-json", json.dumps(update),
        "--json",
    ]
    assert main(argv) == 0
    assert main(argv) == 0

    action = load_queue(tmp_path, "api.target.com")["actions"][0]
    assert action["metadata"] == {
        "hypothesis_id": "H-42",
        "tested_dimensions": ["sibling endpoint", "low-role actor"],
        "expected_learning": "Export responses should preserve object scoping.",
        "kill_condition": "Both export actors receive the same object body.",
        "next_question": "Does the export endpoint enforce the same object check?",
        "last_outcome": {
            "status": "blocked",
            "evidence_ref": "evidence/trace.json",
            "notes": "peer session expired",
        },
        "pivot_hints": ["try export", "try GraphQL"],
    }


def test_resolve_negative_hypothesis_generates_idempotent_pivots(tmp_path):
    metadata = {
        "hypothesis_id": "H-7",
        "tested_dimensions": ["baseline"],
        "pivot_hints": ["sibling endpoint", "encoding", "baseline"],
        "expected_learning": "A sibling or encoding variant may differ.",
        "kill_condition": "Both actor and encoding variants preserve the denial.",
    }
    assert add_manual_action(
        tmp_path,
        target="api.target.com",
        action_type="hypothesis",
        evidence="A target-owned object endpoint was observed.",
        next_question="Does the baseline deny a peer actor?",
        action="Replay the baseline object request.",
        metadata=metadata,
    )

    first = resolve_action(
        tmp_path,
        target="api.target.com",
        action_id="AQ-0001",
        status="tested",
        result="baseline denied",
    )
    assert first["hypothesis_continuation"]["added"] == 2
    queue = load_queue(tmp_path, "api.target.com")
    pivots = [item for item in queue["actions"] if item["type"] == "hypothesis-pivot"]
    assert {item["metadata"]["pivot_hint"] for item in pivots} == {"sibling endpoint", "encoding"}

    second = resolve_action(
        tmp_path,
        target="api.target.com",
        action_id="AQ-0001",
        status="tested",
        result="baseline denied",
    )
    assert "hypothesis_continuation" not in second
    assert len([item for item in load_queue(tmp_path, "api.target.com")["actions"] if item["type"] == "hypothesis-pivot"]) == 2


def test_resolve_kill_condition_closes_hypothesis_without_pivots(tmp_path):
    add_manual_action(
        tmp_path,
        target="api.target.com",
        action_type="hypothesis",
        evidence="Observed a baseline denial.",
        next_question="Is the denial stable?",
        action="Replay the baseline request.",
        metadata={
            "hypothesis_id": "H-8",
            "pivot_hints": ["sibling endpoint"],
            "kill_condition": "Stable denial across the complete matrix.",
        },
    )
    resolve_action(
        tmp_path,
        target="api.target.com",
        action_id="AQ-0001",
        status="tested",
        result="matrix complete",
        metadata={"kill_condition_met": True},
    )
    queue = load_queue(tmp_path, "api.target.com")
    assert not any(item["type"] == "hypothesis-pivot" for item in queue["actions"])
    parent = queue["actions"][0]
    assert parent["metadata"]["hypothesis_status"] == "closed"


def test_target_owned_evidence_ref_rejects_resolver_path_outside_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(
        action_queue_module,
        "_locatable_evidence_ref",
        lambda *_args: "/tmp/foreign/evidence.json",
    )
    assert action_queue_module._target_owned_evidence_ref(tmp_path, "api.target.com", "foreign") == ""


@pytest.mark.parametrize("metadata_json", ["not-json", "[]", "null", '"text"'])
def test_resolve_cli_rejects_non_object_metadata_without_writing(tmp_path, capsys, metadata_json):
    assert main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--evidence", "Observed an endpoint.",
        "--next-question", "Can it be replayed?",
        "--action", "Replay the endpoint.",
    ]) == 0
    path = tmp_path / "state" / "api.target.com" / "action_queue.json"
    before = path.read_bytes()

    code = main([
        "--repo-root", str(tmp_path),
        "resolve",
        "--target", "api.target.com",
        "--id", "AQ-0001",
        "--status", "blocked",
        "--metadata-json", metadata_json,
    ])

    assert code == 2
    assert "--metadata-json" in capsys.readouterr().err
    assert path.read_bytes() == before


def test_resolve_cli_rejects_sensitive_metadata_without_writing(tmp_path, capsys):
    assert main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--evidence", "Observed an endpoint.",
        "--next-question", "Can it be replayed?",
        "--action", "Replay the endpoint.",
    ]) == 0
    path = tmp_path / "state" / "api.target.com" / "action_queue.json"
    before = path.read_bytes()

    code = main([
        "--repo-root", str(tmp_path),
        "resolve",
        "--target", "api.target.com",
        "--id", "AQ-0001",
        "--status", "blocked",
        "--metadata-json", json.dumps({"headers": {"Authorization": "secret"}}),
    ])

    assert code == 2
    assert "sensitive field" in capsys.readouterr().err
    assert path.read_bytes() == before


def test_action_queue_rejects_required_skill_route_without_dimensions(tmp_path):
    with pytest.raises(ValueError, match="skill_route"):
        build_action(
            target="api.target.com",
            action_type="hypothesis",
            evidence="Observed an API object path.",
            next_question="Can a peer actor read it?",
            action="Replay the object path with a peer actor.",
            metadata={"route_required": True},
        )


def test_action_queue_accepts_skill_route_with_required_dimensions(tmp_path):
    action = build_action(
        target="api.target.com",
        action_type="hypothesis",
        evidence="Observed an API object path.",
        next_question="Can a peer actor read it?",
        action="Replay the object path with a peer actor.",
        metadata={
            "route_required": True,
            "skill_route": {
                "skill_id": "web2-vuln-classes",
                "skill_path": "skills/web2-vuln-classes/SKILL.md",
                "reason": "API evidence",
                "required_dimensions": ["auth", "object"],
            },
        },
    )
    assert action["metadata"]["skill_route"]["skill_id"] == "web2-vuln-classes"


@pytest.mark.parametrize("metadata_json", ["not-json", "[]", "null", '"text"'])
def test_manual_action_cli_rejects_non_object_metadata_json(tmp_path, capsys, metadata_json):
    code = main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--evidence", "Observed an endpoint.",
        "--next-question", "Can it be replayed?",
        "--action", "Replay the endpoint.",
        "--metadata-json", metadata_json,
    ])

    assert code == 2
    assert "--metadata-json" in capsys.readouterr().err
    assert not (tmp_path / "state" / "api.target.com" / "action_queue.json").exists()


@pytest.mark.parametrize("field", ["authorization", "cookie", "access_token", "private_marker"])
def test_manual_action_cli_rejects_sensitive_metadata_without_writing(tmp_path, capsys, field):
    code = main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--evidence", "Observed an endpoint.",
        "--next-question", "Can it be replayed?",
        "--action", "Replay the endpoint.",
        "--metadata-json", json.dumps({field: "secret-value"}),
    ])

    assert code == 2
    assert "sensitive field" in capsys.readouterr().err
    assert not (tmp_path / "state" / "api.target.com" / "action_queue.json").exists()


def test_resolve_accepts_coverage_status_aliases(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    next_action = select_next_action(load_queue(tmp_path, "target.com"))

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=next_action["id"],
        status="tested_clean",
        result="Low-risk replay showed no diff.",
    )

    assert resolved["status"] == "tested"
    assert resolved["summary"]["by_status"]["tested"] == 1


def test_resolve_coverage_gap_updates_coverage_matrix(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=coverage["id"],
        status="tested_clean",
        result="Low-risk replay showed no role/object difference.",
    )

    matrix = load_matrix("target.com", repo_root=tmp_path)
    endpoint = next(item for item in matrix["endpoints"] if item["endpoint"] == "/api/admin/users")
    cell = endpoint["cells"]["Authz"]

    assert resolved["coverage_update"]["status"] == "updated"
    assert resolved["coverage_update"]["coverage_status"] == "tested_clean"
    assert cell["status"] == "tested_clean"
    assert "Low-risk replay" in cell["reason"]


def test_resolve_folded_coverage_gap_updates_template_from_representative(tmp_path):
    target = "target.com"
    mark_cell(
        target,
        "/api/orders/{id}",
        "IDOR",
        "untested",
        reason="seed folded route",
        repo_root=tmp_path,
    )
    checkpoint = {
        "next_action_queue": [{
            "type": "coverage-gap",
            "status": "ready",
            "priority": 80,
            "action": "Replay /api/orders/123 for the folded route.",
            "command_hint": "focused replay",
            "metadata": {
                "endpoint": "/api/orders/123",
                "coverage_endpoint": "/api/orders/{id}",
                "vuln_class": "IDOR",
            },
        }],
    }
    ingest_checkpoint(tmp_path, target, checkpoint=checkpoint)
    action = load_queue(tmp_path, target)["actions"][0]

    resolved = resolve_action(
        tmp_path,
        target=target,
        action_id=action["id"],
        status="tested_clean",
        result="Representative route replay showed no unauthorized object access.",
    )

    matrix = load_matrix(target, repo_root=tmp_path)
    endpoints = {item["endpoint"]: item for item in matrix["endpoints"]}
    assert resolved["coverage_update"]["endpoint"] == "/api/orders/{id}"
    assert endpoints["/api/orders/{id}"]["cells"]["IDOR"]["status"] == "tested_clean"
    assert "/api/orders/123" not in endpoints


def test_resolve_coverage_gap_candidate_marks_tested_finding(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=coverage["id"],
        status="tested_finding",
        result="Low-role replay returned another tenant's admin user metadata.",
    )

    matrix = load_matrix("target.com", repo_root=tmp_path)
    endpoint = next(item for item in matrix["endpoints"] if item["endpoint"] == "/api/admin/users")

    assert resolved["status"] == "candidate"
    assert resolved["coverage_update"]["coverage_status"] == "tested_finding"
    assert endpoint["cells"]["Authz"]["status"] == "tested_finding"


def test_dead_end_and_blocked_do_not_falsify_coverage_status(tmp_path):
    for status in ("dead-end", "blocked"):
        target = f"{status}.target.com"
        mark_cell(
            target,
            "/api/admin/users",
            "Authz",
            "untested",
            reason="seed",
            repo_root=tmp_path,
            write_finding=False,
        )
        ingest_checkpoint(tmp_path, target, checkpoint=_checkpoint())
        queue = load_queue(tmp_path, target)
        coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

        resolved = resolve_action(
            tmp_path,
            target=target,
            action_id=coverage["id"],
            status=status,
            result=f"{status} for the current evidence path",
        )

        matrix = load_matrix(target, repo_root=tmp_path)
        endpoint = next(item for item in matrix["endpoints"] if item["endpoint"] == "/api/admin/users")
        assert resolved["coverage_update"]["status"] == "skipped"
        assert "does not close a coverage cell" in resolved["coverage_update"]["reason"]
        assert endpoint["cells"]["Authz"]["status"] == "untested"


def test_resolve_unsafe_skipped_review_persists_resolution(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 88,
                "type": "action-gated-review",
                "status": "ready",
                "action": "Review action-gated scanner lane abcdef1234567890: 1 unresolved skipped probe line(s). Artifact=findings/target.com/manual_review/unsafe_skipped.txt. Decide tested, blocked, dead-end, n/a, or candidate; only rerun with ALLOW_UNSAFE_HTTP_TESTS=1 after explicit operator opt-in.",
                "command_hint": "review legacy unsafe_skipped.txt; resolve queue with tested/blocked/dead-end/n/a/candidate",
                "redline_required": True,
                "metadata": {
                    "unsafe_skipped_id": "abcdef1234567890",
                    "artifact": "findings/target.com/manual_review/unsafe_skipped.txt",
                },
            }
        ]
    }
    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id="AQ-0001",
        status="blocked",
        result="Requires explicit operator opt-in for state-changing scanner probes.",
    )

    review_path = tmp_path / "state" / "target.com" / "unsafe_skipped_reviews.json"
    payload = json.loads(review_path.read_text(encoding="utf-8"))

    assert resolved["unsafe_review_update"]["status"] == "updated"
    assert payload["resolved"]["abcdef1234567890"]["status"] == "blocked"
    assert "operator opt-in" in payload["resolved"]["abcdef1234567890"]["result"]


def test_concurrent_unsafe_review_resolutions_preserve_all_ids(tmp_path):
    target = "target.com"
    items = []
    for index in range(12):
        unsafe_id = f"unsafe-{index:02d}"
        items.append(
            {
                "id": f"A{index}",
                "priority": 88,
                "type": "action-gated-review",
                "status": "ready",
                "action": f"Resolve unsafe review {unsafe_id}.",
                "metadata": {
                    "unsafe_skipped_id": unsafe_id,
                    "artifact": f"findings/{target}/manual_review/unsafe_skipped.txt",
                },
            }
        )
    ingest_checkpoint(tmp_path, target, checkpoint={"next_action_queue": items})

    context = multiprocessing.get_context("fork")
    output = context.Queue()
    workers = [
        context.Process(
            target=_resolve_unsafe_review_worker,
            args=(str(tmp_path), target, f"AQ-{index + 1:04d}", output),
        )
        for index in range(len(items))
    ]
    for process in workers:
        process.start()
    results = [output.get(timeout=15) for _ in workers]
    for process in workers:
        process.join(timeout=15)

    review_path = tmp_path / "state" / target / "unsafe_skipped_reviews.json"
    payload = json.loads(review_path.read_text(encoding="utf-8"))

    assert all(process.exitcode == 0 for process in workers)
    assert results.count("ok") == len(workers)
    assert set(payload["resolved"]) == {f"unsafe-{index:02d}" for index in range(len(items))}
    assert all(item["status"] == "blocked" for item in payload["resolved"].values())


def test_resolve_validated_and_reported_require_locatable_evidence(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    action = select_next_action(load_queue(tmp_path, "target.com"))

    with pytest.raises(ValueError, match="locatable evidence"):
        resolve_action(
            tmp_path,
            target="target.com",
            action_id=action["id"],
            status="validated",
        )
    assert next(item for item in load_queue(tmp_path, "target.com")["actions"] if item["id"] == action["id"])["status"] == "queued"

    unrelated_path = tmp_path / "README.md"
    unrelated_path.write_text("not terminal evidence\n", encoding="utf-8")
    with pytest.raises(ValueError, match="locatable evidence"):
        resolve_action(
            tmp_path,
            target="target.com",
            action_id=action["id"],
            status="validated",
            result="evidence=README.md",
        )

    validation_path = tmp_path / "findings" / "target.com" / "validation-summary.json"
    validation_path.parent.mkdir(parents=True)
    validation_path.write_text("{}\n", encoding="utf-8")
    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=action["id"],
        status="validated",
        result="validation-summary=findings/target.com/validation-summary.json",
    )
    assert resolved["status"] == "validated"

    with pytest.raises(ValueError, match="locatable evidence"):
        resolve_action(
            tmp_path,
            target="target.com",
            action_id=action["id"],
            status="reported",
        )

    report_path = tmp_path / "reports" / "target.com" / "report.md"
    report_path.parent.mkdir(parents=True)
    report_path.write_text("# report\n", encoding="utf-8")
    reported = resolve_action(
        tmp_path,
        target="target.com",
        action_id=action["id"],
        status="reported",
        result="report_file=reports/target.com/report.md",
    )
    assert reported["status"] == "reported"


def test_resolve_cli_accepts_evidence_alias(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    next_action = select_next_action(load_queue(tmp_path, "target.com"))

    code = main([
        "--repo-root", str(tmp_path),
        "resolve",
        "--target", "target.com",
        "--id", next_action["id"],
        "--status", "tested_finding",
        "--evidence", "Evidence is strong enough to promote to candidate.",
        "--json",
    ])

    assert code == 0
    saved = load_queue(tmp_path, "target.com")
    resolved = next(item for item in saved["actions"] if item["id"] == next_action["id"])
    assert resolved["status"] == "candidate"
    assert resolved["result"] == "Evidence is strong enough to promote to candidate."


def test_high_value_actions_sort_ahead_of_generic_actions(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 50,
            "type": "generic-follow-up",
            "evidence_type": "generic",
            "evidence": "Review notes.",
            "next_question": "What next?",
            "action": "Check homepage.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "a",
        },
        {
            "id": "AQ-0002",
            "status": "queued",
            "priority": 50,
            "type": "known-software-intel",
            "evidence_type": "known-software",
            "evidence": "WordPress plugin version needs CVE applicability check.",
            "next_question": "Is the path reachable?",
            "action": "Check exact affected version and reachable route.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "b",
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0002"


def test_legacy_active_action_gets_stable_id_on_claim_and_resolve(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [{
        "status": "queued",
        "priority": 70,
        "type": "legacy-follow-up",
        "evidence": "Legacy action without a durable id.",
        "next_question": "Can the evidence be closed?",
        "action": "Review the bounded evidence packet.",
        "created_at": "2026-01-01T00:00:00Z",
        "dedupe_key": "legacy-follow-up",
    }]
    save_queue(tmp_path, "target.com", queue)

    selected = select_next_action(load_queue(tmp_path, "target.com"))
    legacy_id = selected["id"]
    assert legacy_id.startswith("LEGACY-")
    assert select_next_action(load_queue(tmp_path, "target.com"))["id"] == legacy_id
    assert summarize_queue(load_queue(tmp_path, "target.com"))["legacy_missing_id"] == 1

    claimed = claim_next_action(tmp_path, "target.com", action_id=legacy_id)
    assert claimed["id"] == legacy_id
    saved = load_queue(tmp_path, "target.com")
    assert saved["actions"][0]["id"] == legacy_id

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=legacy_id,
        status="blocked",
        result="bounded evidence is insufficient",
    )
    assert resolved["status"] == "blocked"


def test_candidate_evidence_gap_sorts_ahead_of_plain_validation(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 100,
            "type": "validation",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Run /validate for finding F-1.",
            "next_question": "Validate candidate.",
            "action": "Run /validate for finding F-1.",
            "command_hint": "/validate",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "validate",
        },
        {
            "id": "AQ-0002",
            "status": "queued",
            "priority": 105,
            "type": "candidate-evidence-gap",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Candidate evidence gap for SQLi; missing baseline diff.",
            "next_question": "Fill missing rubric evidence.",
            "action": "Replay baseline vs perturbation and capture stable diff.",
            "command_hint": "fill missing rubric evidence, then /validate",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "gap",
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0002"


def test_superseded_candidate_gap_does_not_steer_next_action(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "candidate",
            "priority": 105,
            "type": "candidate-evidence-gap",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Candidate evidence gap for authz-role-replay-api_users.",
            "next_question": "Fill missing policy evidence.",
            "action": "Candidate evidence gap for authz-role-replay-api_users.",
            "command_hint": "fill missing rubric evidence, then /validate",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "candidate",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
        {
            "id": "AQ-0002",
            "status": "validated",
            "priority": 60,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Validated role replay.",
            "next_question": "done",
            "action": "Validated role replay.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "validated",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
        {
            "id": "AQ-0003",
            "status": "queued",
            "priority": 50,
            "type": "case-state-enrichment",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Find object endpoint.",
            "next_question": "Find endpoint.",
            "action": "Find object endpoint.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:02Z",
            "dedupe_key": "next",
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0003"


def test_ingest_checkpoint_retires_superseded_candidate_gap(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "candidate",
            "priority": 105,
            "type": "candidate-evidence-gap",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Candidate evidence gap for authz-role-replay-api_users.",
            "next_question": "Fill missing policy evidence.",
            "action": "Candidate evidence gap for authz-role-replay-api_users.",
            "command_hint": "fill missing rubric evidence, then /validate",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "candidate",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
        {
            "id": "AQ-0002",
            "status": "validated",
            "priority": 60,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Validated role replay.",
            "next_question": "done",
            "action": "Validated role replay.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "validated",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
    ]
    from action_queue import save_queue

    save_queue(tmp_path, "target.com", queue)

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": []})
    saved = load_queue(tmp_path, "target.com")

    assert result["stats"]["retired_superseded"] == 1
    assert saved["actions"][0]["status"] == "n/a"


def test_ingest_checkpoint_reopens_runner_only_validated_action(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 100,
                "type": "validation",
                "status": "ready",
                "action": (
                    "Run /validate for finding AUTHZ-SYNC on https://target.com/api/Feedbacks; "
                    "verify replay, A/B diff, impact, evidence rubric, and red-line safety before report."
                ),
                "command_hint": "/validate",
                "redline_required": True,
                "stop_condition": "run validate gates",
            }
        ]
    }
    first = ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    queue = load_queue(tmp_path, "target.com")
    action = queue["actions"][0]
    action["status"] = "validated"
    action["result"] = "validation-runner-result=tested_finding; summary=evidence/target.com/validation/authz/summary.json"
    from action_queue import save_queue

    save_queue(tmp_path, "target.com", queue)

    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    saved = load_queue(tmp_path, "target.com")

    assert first["stats"]["added"] == 1
    assert second["stats"]["updated"] == 1
    assert second["stats"]["skipped_final"] == 0
    assert saved["actions"][0]["status"] == "queued"
    assert second["next"]["id"] == saved["actions"][0]["id"]
    assert "runner evidence is candidate-only" in saved["actions"][0]["notes"]


def test_relevance_metadata_breaks_same_endpoint_coverage_ties(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    common = {
        "status": "queued",
        "priority": 75,
        "type": "coverage-gap",
        "evidence_type": "checkpoint-next-action",
        "next_question": "Execute checkpoint action.",
        "command_hint": "focused low-risk probe + evidence ledger",
        "created_at": "2026-01-01T00:00:00Z",
    }
    queue["actions"] = [
        {
            **common,
            "id": "AQ-0001",
            "evidence": "Cover high-value matrix gap: /api/v1/admin/users x IDOR.",
            "action": "Cover high-value matrix gap: /api/v1/admin/users x IDOR.",
            "dedupe_key": "idor",
            "metadata": {
                "endpoint": "/api/v1/admin/users",
                "vuln_class": "IDOR",
                "relevance_score": 9,
            },
        },
        {
            **common,
            "id": "AQ-0002",
            "evidence": "Cover high-value matrix gap: /api/v1/admin/users x Authz.",
            "action": "Cover high-value matrix gap: /api/v1/admin/users x Authz.",
            "dedupe_key": "authz",
            "metadata": {
                "endpoint": "/api/v1/admin/users",
                "vuln_class": "Authz",
                "relevance_score": 13,
            },
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0002"


def test_action_identities_keep_vulnerability_and_auth_context_lanes_distinct():
    endpoint = "https://target.com/api/orders/42"
    idor = {
        "metadata": {
            "endpoint": endpoint,
            "vuln_class": "IDOR",
            "method": "GET",
            "semantic_shape_id": "shape-orders-id",
            "auth_context": "authenticated",
            "actor": "user-a",
            "object_scope": "tenant-a",
        }
    }
    authz = {
        "metadata": {
            "endpoint": endpoint,
            "vuln_class": "Authz",
            "method": "GET",
            "semantic_shape_id": "shape-orders-id",
            "auth_context": "authenticated",
            "actor": "user-a",
            "object_scope": "tenant-a",
        }
    }

    assert action_queue_module._action_identities(idor).isdisjoint(
        action_queue_module._action_identities(authz)
    )


def test_legacy_action_identity_keeps_endpoint_compatibility():
    action = {"metadata": {"endpoint": "https://target.com/api/orders/42"}}

    assert action_queue_module._action_identities(action) == {"endpoint:/api/orders/42"}


def test_queue_fingerprint_ignores_container_timestamps():
    first = {
        "schema_version": 1,
        "target": "target.com",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "actions": [],
    }
    second = {
        **first,
        "created_at": "2026-01-02T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
    }

    assert action_queue_module.queue_fingerprint(first) == action_queue_module.queue_fingerprint(second)


def test_load_queue_rejects_corrupt_or_invalid_canonical_state(tmp_path):
    path = tmp_path / "state" / "target.com" / "action_queue.json"
    path.parent.mkdir(parents=True)

    path.write_text('{"actions":', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid action queue JSON"):
        load_queue(tmp_path, "target.com")

    path.write_text(json.dumps([{"id": "AQ-0001"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="must contain one object"):
        load_queue(tmp_path, "target.com")

    path.write_text(json.dumps({"schema_version": 1, "actions": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="actions must be a list"):
        load_queue(tmp_path, "target.com")

    path.write_text(json.dumps({"schema_version": 2, "actions": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version must be 1"):
        load_queue(tmp_path, "target.com")


def test_save_queue_atomic_replace_failure_preserves_previous_bytes(tmp_path, monkeypatch):
    initial = load_queue(tmp_path, "target.com")
    initial["actions"] = [{"id": "AQ-0001", "status": "queued"}]
    path = save_queue(tmp_path, "target.com", initial)
    previous = path.read_bytes()

    replacement = dict(initial)
    replacement["actions"] = [{"id": "AQ-0002", "status": "queued"}]
    original_replace = Path.replace

    def fail_queue_replace(self, target):
        if self.parent == path.parent and self.name.startswith(f".{path.name}."):
            raise OSError("synthetic replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_queue_replace)
    with pytest.raises(OSError, match="synthetic replace failure"):
        save_queue(tmp_path, "target.com", replacement)

    assert path.read_bytes() == previous
    assert list(path.parent.glob(f".{path.name}.*.tmp")) == []


def test_action_queue_cli_reports_corrupt_state(tmp_path, capsys):
    path = tmp_path / "state" / "target.com" / "action_queue.json"
    path.parent.mkdir(parents=True)
    path.write_text("{broken\n", encoding="utf-8")

    rc = main(
        [
            "--repo-root",
            str(tmp_path),
            "summary",
            "--target",
            "target.com",
            "--json",
        ]
    )

    assert rc == 2
    error = capsys.readouterr().err
    assert "invalid action queue JSON" in error
    assert str(path) in error
