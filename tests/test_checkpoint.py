"""Tests for tools/checkpoint.py."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

import checkpoint as checkpoint_module
import finding_index
from action_queue import (
    _checkpoint_item_to_action,
    _dedupe_key,
    add_manual_action,
    build_action,
    claim_next_action,
    ingest_checkpoint,
    load_queue,
    resolve_action,
    save_queue,
)
from checkpoint import (
    _build_next_action_queue,
    _bounded_next_proposals,
    _actor_gap_enrichment_proposal,
    _capability_chain_review_item,
    _checkpoint_coverage_gaps,
    _coverage_gap_validation_path,
    _decision_for_action,
    _dead_end_proposals,
    _dedupe_artifact_category_items,
    _extract_action_metadata,
    _filter_final_action_queue_items,
    _lead_proposals,
    _ledger_candidate_proposals,
    _ledger_covered_cells,
    _ledger_covers_cell,
    _knowledge_signal_review_item,
    _matrix_summary,
    _next_proposals,
    _project_knowledge_effect_trace,
    _sibling_queue_item,
    _workflow_lead_queue_items,
    _ranked_surface_replay_draft,
    _ranked_surface_vuln_hint,
    _select_default_candidate,
    _sql_matrix_queue_items,
    apply_target_memory,
    build_checkpoint,
    begin_round,
    format_checkpoint,
    record_round_closure,
    record_round_lane,
    record_round_lane_result,
    sync_checkpoint_action_queue,
)
from coverage_matrix import mark_cell
from evidence_ledger import record_entry
from identity_contract import build_closure_cell
from runtime_state import runtime_phase_lock, update_runtime_state
from target_case_state import add_actor, add_backlog, add_hypothesis, add_object, add_session


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


def _write_round_evidence(repo_root: Path, evidence_ref: str, content: str = "{}") -> Path:
    path = repo_root / evidence_ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _seed_capability_parent(
    repo_root: Path,
    *,
    target: str = "target.com",
    primitive: dict | None = None,
    continuation_kind: str = "",
    chain_child: bool = False,
) -> dict:
    evidence_ref = f"evidence/{target}/validation/primitive.json"
    evidence_path = repo_root / evidence_ref
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps({"difference": "stable"}), encoding="utf-8")
    metadata = {
        "depth_contract_version": 1,
        "hypothesis_id": "H-primitive",
        "capability_primitives": [
            primitive
            or {
                "capability": "cross-workflow object selector",
                "evidence_ref": evidence_ref,
                "continuation_hint": "compare the linked download workflow",
            }
        ],
    }
    if continuation_kind:
        metadata["continuation"] = {"kind": continuation_kind}
    parent = build_action(
        target=target,
        action_type="validation",
        evidence="Controlled replay recorded one reusable capability.",
        next_question="Can the capability support one bounded chain?",
        action="Preserve the result and review its chain value.",
        metadata=metadata,
    )
    parent.update({"id": "AQ-0001", "status": "tested"})
    queue = load_queue(repo_root, target)
    queue["actions"].append(parent)
    if chain_child:
        child = build_action(
            target=target,
            action_type="hypothesis-continuation",
            evidence="The parent already selected a chain continuation.",
            next_question="Does the linked chain produce a controlled difference?",
            action="Execute the existing chain child.",
            metadata={
                "depth_contract_version": 1,
                "hypothesis_id": "H-primitive",
                "parent_action_id": parent["id"],
                "continuation_kind": "chain",
            },
        )
        child.update({"id": "AQ-0002", "status": "queued"})
        queue["actions"].append(child)
    save_queue(repo_root, target, queue)
    return parent


def _claim_round_lane_worker(repo_root, target, lane, max_lanes, output):
    try:
        result = record_round_lane(repo_root, target, lane=lane, max_lanes=max_lanes)
        output.put((result["status"], result["allowed"], ""))
    except Exception as exc:  # pragma: no cover - surfaced through parent assertion
        output.put(("error", False, str(exc)))


def _finish_round_lane_worker(repo_root, target, lane, output):
    try:
        result = record_round_lane_result(
            repo_root,
            target,
            lane=lane,
            status="completed",
            decision="concurrent replay completed",
            evidence_ref="findings/target.com/poc/concurrent/summary.json",
            next_action="none",
        )
        output.put((result["status"], ""))
    except Exception as exc:  # pragma: no cover - surfaced through parent assertion
        output.put(("error", str(exc)))


def _apply_target_memory_worker(repo_root, target, index, output):
    try:
        result = apply_target_memory(
            repo_root,
            target,
            {
                "decision": "handoff",
                "target_write_back": {
                    "lead": [f"lead-{index}"],
                    "next": [f"next-{index}"],
                    "dead_end": [f"dead-end-{index}"],
                    "handoff": f"handoff-{index}",
                },
            },
        )
        output.put(("ok", result.get("session_path", "")))
    except Exception as exc:  # pragma: no cover - surfaced through parent assertion
        output.put(("error", str(exc)))


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


def test_checkpoint_projects_visible_knowledge_effect_stages(tmp_path):
    checkpoint = {
        "context_pack": {
            "knowledge_cards": ["sqli-hidden-surfaces"],
            "hypothesis_seeds": ["Compare a header, path segment, and sibling parameter."],
        }
    }
    suggestion = _project_knowledge_effect_trace(checkpoint, [])
    assert suggestion == {
        "suggestion": "sqli-hidden-surfaces / Compare a header, path segment, and sibling parameter.",
        "action": "pending",
        "result": "pending",
    }

    action = {
        "id": "AQ-0123",
        "status": "running",
        "attempts": 1,
        "updated_at": "2026-08-11T00:00:01Z",
        "action": "Compare one controlled X-Forwarded-For pair.",
        "metadata": {"selected_knowledge_refs": ["sqli-hidden-surfaces"]},
    }
    selected = _project_knowledge_effect_trace(checkpoint, [action])
    assert selected["action"] == "AQ-0123 / Compare one controlled X-Forwarded-For pair."
    assert selected["result"] == "pending"
    queued_child = {
        **action,
        "id": "AQ-0124",
        "status": "queued",
        "updated_at": "2026-08-11T00:00:02Z",
        "action": "Inherited continuation that has not been selected.",
    }
    assert _project_knowledge_effect_trace(checkpoint, [action, queued_child]) == selected

    action["status"] = "tested"
    action["metadata"]["last_outcome"] = {
        "status": "tested_clean",
        "summary_ref": "evidence/target.test/validation/header/summary.json",
    }
    resolved = _project_knowledge_effect_trace(checkpoint, [action])
    assert resolved["result"] == (
        "tested_clean / evidence/target.test/validation/header/summary.json"
    )

    checkpoint["target"] = "target.test"
    save_queue(tmp_path, "target.test", {"actions": [action]})
    sync_checkpoint_action_queue(tmp_path, checkpoint)
    assert checkpoint["knowledge_effect_trace"] == resolved

    output = format_checkpoint(checkpoint)
    assert output.count("Knowledge effect:") == 1
    assert "sqli-hidden-surfaces" in output
    assert "-> AQ-0123" in output
    assert "-> tested_clean" in output


def test_round_guard_blocks_only_after_three_identical_records(monkeypatch, tmp_path):
    target = "target.com"
    state_dir = tmp_path / "state" / target
    state_dir.mkdir(parents=True)
    witness = state_dir / "checkpoint_latest.json"
    witness.write_text(json.dumps({"schema_version": 1, "target": target}), encoding="utf-8")
    state = {"target": target, "resolved_target": target, "json_inject": {
        "status": "partial", "input_fingerprint": "abc", "request_count": 1,
    }}
    closure = {"verdict": "handoff", "reasons": ["json_evidence_partial"], "next_action": "handoff"}
    monkeypatch.setattr(checkpoint_module, "build_autopilot_state", lambda *_args, **_kwargs: state)
    monkeypatch.setattr(checkpoint_module, "load_closure_projection", lambda *_args, **_kwargs: closure)

    counts = [record_round_closure(tmp_path, target)["round_guard"]["consecutive"] for _ in range(4)]

    assert counts == [1, 2, 3, 3]


def test_round_lane_budget_resumes_and_dedupes_claims_across_invocations(tmp_path):
    target = "target.com"
    first = begin_round(tmp_path, target, max_lanes=2)
    lane_one = record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=2)
    resumed = begin_round(tmp_path, target, max_lanes=2)
    duplicate = record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=2)
    lane_two = record_round_lane(tmp_path, target, lane="authz:/api/orders/:id", max_lanes=2)
    denied = record_round_lane(tmp_path, target, lane="ssrf:/api/fetch", max_lanes=2)

    assert first["round_progress"]["status"] == "active"
    assert lane_one["status"] == "claimed"
    assert resumed["status"] == "resumed"
    assert resumed["round_progress"]["round_id"] == first["round_progress"]["round_id"]
    assert resumed["round_progress"]["lanes"][0]["status"] == "started"
    assert duplicate["status"] == "already_claimed"
    assert duplicate["allowed"] is True
    assert duplicate["round_progress"]["claimed_count"] == 1
    assert lane_two["round_progress"]["budget_reached"] is True
    assert denied["status"] == "budget_exhausted"
    assert denied["allowed"] is False


@pytest.mark.parametrize(
    "lane",
    [
        "idle:wait",
        "monitor:queue",
        "verify:idle-state",
        "verify:no-change-since-checkpoint",
        "idle-no-change",
        "candidate:idle-no-change-r4e2c64d",
    ],
)
def test_new_passive_round_lane_is_rejected_without_budget_mutation(tmp_path, lane):
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=2)
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    before = witness.read_bytes()

    result = record_round_lane(tmp_path, target, lane=lane, max_lanes=2)

    assert result["status"] == "passive_lane_rejected"
    assert result["allowed"] is False
    assert result["reason"] == "passive_lane_not_substantive"
    assert result["round_progress"]["claimed_count"] == 0
    assert result["round_progress"]["remaining_lanes"] == 2
    assert witness.read_bytes() == before


def test_generic_verify_lane_remains_substantive(tmp_path):
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=1)

    result = record_round_lane(
        tmp_path, target, lane="verify:candidate-42", max_lanes=1
    )

    assert result["status"] == "claimed"
    assert result["allowed"] is True


def test_legacy_claimed_passive_lane_remains_recoverable(tmp_path):
    target = "target.com"
    lane = "idle:no-change"
    begin_round(tmp_path, target, max_lanes=1)
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    payload = json.loads(witness.read_text(encoding="utf-8"))
    payload["round_progress"].update({
        "claimed_lanes": [lane],
        "claimed_count": 1,
        "remaining_lanes": 0,
        "budget_reached": True,
    })
    payload["round_progress"].pop("lanes", None)
    witness.write_text(json.dumps(payload), encoding="utf-8")

    resumed = record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="blocked",
        decision="legacy passive lane observed",
        evidence_ref="none",
        next_action="use owner-selected work",
    )
    terminal = record_round_lane(tmp_path, target, lane=lane, max_lanes=1)

    assert resumed["status"] == "already_claimed"
    assert resumed["allowed"] is True
    assert terminal["status"] == "already_blocked"
    assert terminal["allowed"] is False


def test_round_closure_counts_underlying_post_round_next_action(monkeypatch, tmp_path):
    target = "target.com"
    state = {"target": target, "resolved_target": target, "next_action": "hunt_p1"}
    calls = []
    monkeypatch.setattr(checkpoint_module, "build_autopilot_state", lambda *_args, **_kwargs: state)

    def fake_closure(*_args, include_round_projection=True, **_kwargs):
        calls.append(include_round_projection)
        return {
            "verdict": "handoff",
            "reasons": [
                "round_closure_pending" if include_round_projection else "next_action_pending"
            ],
            "next_action": "complete_round_closure" if include_round_projection else "hunt_p1",
        }

    monkeypatch.setattr(checkpoint_module, "load_closure_projection", fake_closure)

    counts = []
    for index in range(3):
        begin_round(tmp_path, target, max_lanes=1)
        lane = f"candidate:{index}"
        evidence_ref = f"findings/{target}/poc/round-{index}.json"
        record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
        _write_round_evidence(tmp_path, evidence_ref)
        record_round_lane_result(
            tmp_path,
            target,
            lane=lane,
            status="completed",
            decision="bounded candidate reviewed",
            evidence_ref=evidence_ref,
            next_action="hunt_p1",
        )
        counts.append(record_round_closure(tmp_path, target)["round_guard"]["consecutive"])

    assert calls == [False, False, False]
    assert counts == [1, 2, 3]


def test_round_lane_requires_explicit_round_begin(tmp_path):
    target = "target.com"
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    evidence_ref = "findings/target.com/poc/sql.json"

    with pytest.raises(ValueError, match="run --round-begin first"):
        record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=1)
    assert not witness.exists()

    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=1)
    _write_round_evidence(tmp_path, evidence_ref)
    record_round_lane_result(
        tmp_path,
        target,
        lane="sqli:/api/search",
        status="completed",
        decision="tested clean",
        evidence_ref=evidence_ref,
        next_action="none",
    )
    record_round_closure(tmp_path, target)

    with pytest.raises(ValueError, match="run --round-begin first"):
        record_round_lane(tmp_path, target, lane="authz:/api/orders", max_lanes=1)


def test_round_lane_result_survives_resume_and_terminal_replay_is_idempotent(tmp_path):
    target = "target.com"
    lane = "sqli:/api/search"
    evidence_ref = "findings/target.com/poc/sql_parameter/summary.json"
    begin_round(tmp_path, target, max_lanes=2)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=2)
    _write_round_evidence(tmp_path, evidence_ref)

    result = record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="tested-clean after boolean pair",
        evidence_ref=evidence_ref,
        next_action="review authz:/api/orders/:id",
    )
    replay = record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="tested-clean after boolean pair",
        evidence_ref=evidence_ref,
        next_action="review authz:/api/orders/:id",
    )
    resumed = begin_round(tmp_path, target, max_lanes=2)
    terminal_claim = record_round_lane(tmp_path, target, lane=lane, max_lanes=2)

    assert result["status"] == "recorded"
    assert result["lane"]["status"] == "completed"
    assert result["lane"]["decision"] == "tested-clean after boolean pair"
    assert result["lane"]["evidence_ref"].endswith("summary.json")
    assert replay["status"] == "already_recorded"
    assert resumed["round_progress"]["lanes"][0] == replay["lane"]
    assert terminal_claim["status"] == "already_completed"
    assert terminal_claim["allowed"] is False

    with pytest.raises(ValueError, match="cannot be rewritten"):
        record_round_lane_result(
            tmp_path,
            target,
            lane=lane,
            status="completed",
            decision="different decision",
            evidence_ref=evidence_ref,
            next_action="none",
        )


def test_round_lane_result_requires_claim_and_completed_evidence(tmp_path):
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=1)

    with pytest.raises(ValueError, match="was not claimed"):
        record_round_lane_result(
            tmp_path,
            target,
            lane="sqli:/api/search",
            status="blocked",
            decision="tool unavailable",
            evidence_ref="none",
            next_action="repair sql runner",
        )

    record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=1)
    with pytest.raises(ValueError, match="target-owned, non-empty evidence_ref"):
        record_round_lane_result(
            tmp_path,
            target,
            lane="sqli:/api/search",
            status="completed",
            decision="tested clean",
            evidence_ref="none",
            next_action="none",
        )


def test_completed_coverage_lane_requires_canonical_owner_evidence(tmp_path):
    target = "target.com"
    lane = "coverage:high-risk-lane-review"
    narrative_ref = f"evidence/{target}/coverage_disposition.md"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    _write_round_evidence(tmp_path, narrative_ref, "TESTED/BLOCKED narrative only")

    with pytest.raises(ValueError, match="canonical Coverage Matrix"):
        record_round_lane_result(
            tmp_path,
            target,
            lane=lane,
            status="completed",
            decision="coverage disposition recorded",
            evidence_ref=narrative_ref,
            next_action="final closure",
        )

    matrix_ref = f"evidence/{target}/coverage_matrix.json"
    mark_cell(
        target,
        "/api/orders/123",
        "IDOR",
        "tested_clean",
        reason="bounded two-actor replay",
        repo_root=tmp_path,
    )
    recorded = record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="canonical coverage updated",
        evidence_ref=matrix_ref,
        next_action="recompute closure",
    )

    assert recorded["lane"]["evidence_ref"] == matrix_ref


@pytest.mark.parametrize("case", ["missing", "empty", "off_target", "outside_repo"])
def test_completed_round_lane_rejects_invalid_evidence_without_mutating_lane(tmp_path, case):
    target = "target.com"
    lane = "sqli:/api/search"
    refs = {
        "missing": "findings/target.com/poc/missing.json",
        "empty": "findings/target.com/poc/empty.json",
        "off_target": "findings/other.example/poc/summary.json",
        "outside_repo": str(tmp_path.parent / "outside-summary.json"),
    }
    evidence_ref = refs[case]
    if case == "empty":
        _write_round_evidence(tmp_path, evidence_ref, "")
    elif case == "off_target":
        _write_round_evidence(tmp_path, evidence_ref)
    elif case == "outside_repo":
        Path(evidence_ref).write_text("{}", encoding="utf-8")

    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)

    with pytest.raises(ValueError, match="target-owned, non-empty evidence_ref"):
        record_round_lane_result(
            tmp_path,
            target,
            lane=lane,
            status="completed",
            decision="tested clean",
            evidence_ref=evidence_ref,
            next_action="none",
        )

    resumed = begin_round(tmp_path, target, max_lanes=1)
    assert resumed["round_progress"]["lanes"][0]["status"] == "started"


def test_round_lane_result_cli_records_bounded_heartbeat(tmp_path, capsys):
    target = "target.com"
    lane = "authz:/api/orders/:id"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)

    exit_code = checkpoint_module.main([
        "--target", target,
        "--repo-root", str(tmp_path),
        "--record-round-lane-result",
        "--lane", lane,
        "--lane-status", "blocked",
        "--decision", "owner session unavailable",
        "--evidence-ref", "none",
        "--next-action", "capture owner session",
        "--json",
    ])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["status"] == "recorded"
    assert payload["lane"]["status"] == "blocked"
    assert payload["lane"]["next_action"] == "capture owner session"


def test_round_lane_heartbeat_is_atomic_under_concurrent_processes(tmp_path):
    target = "target.com"
    max_lanes = 5
    begin_round(tmp_path, target, max_lanes=max_lanes)
    context = multiprocessing.get_context("fork")
    claim_output = context.Queue()
    claimers = [
        context.Process(
            target=_claim_round_lane_worker,
            args=(str(tmp_path), target, f"lane:{index}", max_lanes, claim_output),
        )
        for index in range(24)
    ]
    for process in claimers:
        process.start()
    claim_results = [claim_output.get(timeout=10) for _ in claimers]
    for process in claimers:
        process.join(timeout=10)

    resumed = begin_round(tmp_path, target, max_lanes=max_lanes)
    progress = resumed["round_progress"]
    assert all(process.exitcode == 0 for process in claimers)
    assert all(not error for _, _, error in claim_results)
    assert sum(allowed for _, allowed, _ in claim_results) == max_lanes
    assert progress["claimed_count"] == max_lanes
    assert len(progress["claimed_lanes"]) == max_lanes
    assert len(progress["lanes"]) == max_lanes
    assert all(item["status"] == "started" for item in progress["lanes"])

    lane = progress["claimed_lanes"][0]
    _write_round_evidence(tmp_path, "findings/target.com/poc/concurrent/summary.json")
    finish_output = context.Queue()
    finishers = [
        context.Process(
            target=_finish_round_lane_worker,
            args=(str(tmp_path), target, lane, finish_output),
        )
        for _ in range(12)
    ]
    for process in finishers:
        process.start()
    finish_results = [finish_output.get(timeout=10) for _ in finishers]
    for process in finishers:
        process.join(timeout=10)

    final = begin_round(tmp_path, target, max_lanes=max_lanes)["round_progress"]
    heartbeat = next(item for item in final["lanes"] if item["id"] == lane)
    assert all(process.exitcode == 0 for process in finishers)
    assert all(not error for _, error in finish_results)
    assert [status for status, _ in finish_results].count("recorded") == 1
    assert [status for status, _ in finish_results].count("already_recorded") == 11
    assert heartbeat["status"] == "completed"
    assert heartbeat["decision"] == "concurrent replay completed"


def test_round_lane_heartbeat_survives_repeated_interrupt_cycles(monkeypatch, tmp_path):
    target = "target.com"
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {"verdict": "handoff", "reasons": ["next_action_pending"]},
    )

    previous_round = ""
    for round_index in range(50):
        started = begin_round(tmp_path, target, max_lanes=3)
        round_id = started["round_progress"]["round_id"]
        assert round_id != previous_round
        lane_ids = [f"round-{round_index}:lane-{index}" for index in range(3)]
        record_round_lane(tmp_path, target, lane=lane_ids[0], max_lanes=3)

        resumed = begin_round(tmp_path, target, max_lanes=3)
        assert resumed["status"] == "resumed"
        assert resumed["round_progress"]["round_id"] == round_id
        assert resumed["round_progress"]["lanes"][0]["status"] == "started"

        for index, lane in enumerate(lane_ids):
            if index:
                record_round_lane(tmp_path, target, lane=lane, max_lanes=3)
            evidence_ref = f"findings/target.com/poc/round-{round_index}/lane-{index}.json"
            _write_round_evidence(tmp_path, evidence_ref)
            record_round_lane_result(
                tmp_path,
                target,
                lane=lane,
                status="completed",
                decision=f"round {round_index} lane {index} completed",
                evidence_ref=evidence_ref,
                next_action="none",
            )

        closed = record_round_closure(tmp_path, target)
        assert closed["round_progress"]["status"] == "completed"
        assert closed["round_progress"]["claimed_count"] == 3
        assert all(item["status"] == "completed" for item in closed["round_progress"]["lanes"])
        previous_round = round_id


def test_round_closure_completes_budget_and_next_begin_starts_new_round(monkeypatch, tmp_path):
    target = "target.com"
    evidence_ref = "findings/target.com/poc/sql_parameter/summary.json"
    first = begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=1)
    _write_round_evidence(tmp_path, evidence_ref)
    record_round_lane_result(
        tmp_path,
        target,
        lane="sqli:/api/search",
        status="completed",
        decision="tested clean",
        evidence_ref=evidence_ref,
        next_action="none",
    )
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {"verdict": "handoff", "reasons": ["next_action_pending"]},
    )

    completed = record_round_closure(tmp_path, target)
    second = begin_round(tmp_path, target, max_lanes=1)

    assert completed["round_progress"]["status"] == "completed"
    assert completed["round_progress"]["budget_reached"] is True
    assert second["status"] == "started"
    assert second["round_progress"]["round_id"] != first["round_progress"]["round_id"]


def test_round_closure_rejects_completed_lane_after_evidence_disappears(monkeypatch, tmp_path):
    target = "target.com"
    lane = "sqli:/api/search"
    evidence_ref = "findings/target.com/poc/sql_parameter/summary.json"
    evidence_path = _write_round_evidence(tmp_path, evidence_ref)
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="tested clean",
        evidence_ref=evidence_ref,
        next_action="none",
    )
    evidence_path.unlink()
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    previous = witness.read_bytes()
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {"verdict": "handoff", "reasons": ["next_action_pending"]},
    )

    with pytest.raises(ValueError, match="cannot start or resume a round"):
        begin_round(tmp_path, target, max_lanes=1)
    with pytest.raises(ValueError, match="invalid completed lane evidence: sqli:/api/search"):
        record_round_closure(tmp_path, target)

    assert witness.read_bytes() == previous


def test_new_round_does_not_overwrite_closed_round_with_invalid_evidence(tmp_path):
    target = "target.com"
    lane = "sqli:/api/search"
    evidence_ref = "findings/target.com/poc/sql_parameter/summary.json"
    evidence_path = _write_round_evidence(tmp_path, evidence_ref)
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="tested clean",
        evidence_ref=evidence_ref,
        next_action="none",
    )
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    payload = json.loads(witness.read_text(encoding="utf-8"))
    payload["round_progress"]["status"] = "completed"
    payload["round_progress"]["completed_at"] = "2026-08-01T00:02:00Z"
    witness.write_text(json.dumps(payload), encoding="utf-8")
    evidence_path.unlink()
    previous = witness.read_bytes()

    with pytest.raises(ValueError, match="cannot start or resume a round with invalid completed lane evidence"):
        begin_round(tmp_path, target, max_lanes=1)

    assert witness.read_bytes() == previous


def test_round_closure_rejects_unfinished_lane(monkeypatch, tmp_path):
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=1)
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {"verdict": "handoff", "reasons": ["lane_pending"]},
    )

    with pytest.raises(ValueError, match="unfinished lanes: sqli:/api/search"):
        record_round_closure(tmp_path, target)


def test_evidence_before_terminal_heartbeat_remains_an_unfinished_lane(monkeypatch, tmp_path):
    target = "target.com"
    evidence_ref = "findings/target.com/poc/sql/summary.json"
    evidence_path = tmp_path / evidence_ref
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(json.dumps({"result": "tested_clean"}), encoding="utf-8")

    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=1)
    resumed = begin_round(tmp_path, target, max_lanes=1)
    lane = resumed["round_progress"]["lanes"][0]

    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {"verdict": "handoff", "reasons": ["lane_pending"]},
    )

    assert evidence_path.is_file()
    assert resumed["status"] == "resumed"
    assert lane["status"] == "started"
    assert lane["evidence_ref"] == ""
    with pytest.raises(ValueError, match="unfinished lanes: sqli:/api/search"):
        record_round_closure(tmp_path, target)


def test_checkpoint_witness_atomic_replace_failure_preserves_previous_bytes(tmp_path, monkeypatch):
    target = "target.com"
    first = checkpoint_module.write_checkpoint_witness(
        tmp_path,
        target,
        {"context_pack": {"selected_skill": "skills/web2-recon/SKILL.md"}},
    )
    path = Path(first["path"])
    previous = path.read_bytes()
    original_replace = Path.replace

    def fail_witness_replace(self, destination):
        if self.parent == path.parent and self.name.startswith(f".{path.name}."):
            raise OSError("synthetic checkpoint replace failure")
        return original_replace(self, destination)

    monkeypatch.setattr(Path, "replace", fail_witness_replace)

    with pytest.raises(OSError, match="synthetic checkpoint replace failure"):
        checkpoint_module.write_checkpoint_witness(
            tmp_path,
            target,
            {"context_pack": {"selected_skill": "skills/web2-vuln-classes/SKILL.md"}},
        )

    assert path.read_bytes() == previous
    assert json.loads(path.read_text(encoding="utf-8"))["kind"] == "autopilot_checkpoint_witness"
    assert not list(path.parent.glob(f".{path.name}.*.tmp"))


def test_checkpoint_witness_validates_preserved_round_before_rewrite(tmp_path):
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=2)
    claimed = record_round_lane(
        tmp_path,
        target,
        lane="sqli:/api/search",
        max_lanes=2,
    )["round_progress"]

    written = checkpoint_module.write_checkpoint_witness(
        tmp_path,
        target,
        {"context_pack": {"selected_skill": "skills/web2-recon/SKILL.md"}},
    )
    path = Path(written["path"])

    assert written["payload"]["round_progress"] == claimed

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["round_progress"]["claimed_count"] = 2
    path.write_text(json.dumps(payload), encoding="utf-8")
    previous = path.read_bytes()

    with pytest.raises(ValueError, match="round_progress budget fields are invalid"):
        checkpoint_module.write_checkpoint_witness(
            tmp_path,
            target,
            {"context_pack": {"selected_skill": "skills/web2-vuln-classes/SKILL.md"}},
        )

    assert path.read_bytes() == previous


def test_round_begin_normalizes_legacy_claimed_lanes_as_unfinished(tmp_path):
    target = "target.com"
    first = begin_round(tmp_path, target, max_lanes=1)
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    payload = json.loads(witness.read_text(encoding="utf-8"))
    payload["round_progress"].update({
        "claimed_lanes": ["sqli:/api/search"],
        "claimed_count": 1,
        "remaining_lanes": 0,
        "budget_reached": True,
    })
    payload["round_progress"].pop("lanes")
    witness.write_text(json.dumps(payload), encoding="utf-8")

    resumed = begin_round(tmp_path, target, max_lanes=1)

    assert resumed["status"] == "resumed"
    assert resumed["round_progress"]["round_id"] == first["round_progress"]["round_id"]
    assert resumed["round_progress"]["lanes"][0]["id"] == "sqli:/api/search"
    assert resumed["round_progress"]["lanes"][0]["status"] == "started"


def test_round_begin_rejects_corrupt_checkpoint_witness(tmp_path):
    witness = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True)
    witness.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid checkpoint witness JSON"):
        begin_round(tmp_path, "target.com", max_lanes=2)


def test_round_begin_rejects_inconsistent_persisted_budget(tmp_path):
    witness = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True)
    witness.write_text(json.dumps({
        "schema_version": 1,
        "target": "target.com",
        "round_progress": {
            "schema_version": 1,
            "status": "active",
            "max_lanes": 1,
            "claimed_lanes": ["lane-one", "lane-two"],
            "claimed_count": 2,
            "remaining_lanes": 0,
            "budget_reached": True,
        },
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="round_progress budget fields are invalid"):
        begin_round(tmp_path, "target.com", max_lanes=2)


def test_checkpoint_reuses_surface_state_for_context_pack(tmp_path, monkeypatch):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/users/1"])
    context_globals = checkpoint_module.build_context_pack.__globals__
    load_registry = context_globals["_load_capability_registry"]
    load_runner_candidates = checkpoint_module.build_autopilot_state.__globals__[
        "load_validation_runner_candidate_pool"
    ]
    registry_loads = 0
    candidate_loads = 0

    def fail_on_second_surface_load(*_args, **_kwargs):
        raise AssertionError("checkpoint rebuilt surface state for context pack")

    def fail_on_candidate_reload(*_args, **_kwargs):
        raise AssertionError("context pack reloaded validation runner candidates")

    def count_registry_loads(*args, **kwargs):
        nonlocal registry_loads
        registry_loads += 1
        return load_registry(*args, **kwargs)

    def count_candidate_loads(*args, **kwargs):
        nonlocal candidate_loads
        candidate_loads += 1
        return load_runner_candidates(*args, **kwargs)

    monkeypatch.setitem(
        context_globals,
        "_surface_state",
        fail_on_second_surface_load,
    )
    monkeypatch.setitem(
        context_globals,
        "load_validation_runner_candidate_pool",
        fail_on_candidate_reload,
    )
    monkeypatch.setitem(
        checkpoint_module.build_autopilot_state.__globals__,
        "load_validation_runner_candidate_pool",
        count_candidate_loads,
    )
    monkeypatch.setitem(context_globals, "_load_capability_registry", count_registry_loads)

    checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)

    assert checkpoint["evidence_reviewed"]["surface"] is True
    assert registry_loads == 1
    assert candidate_loads == 1


def test_checkpoint_reuses_action_queue_snapshot(tmp_path, monkeypatch):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/users/1"])
    _seed_capability_parent(tmp_path)
    load_queue = checkpoint_module.load_action_queue
    queue_loads = 0

    def count_queue_loads(*args, **kwargs):
        nonlocal queue_loads
        queue_loads += 1
        return load_queue(*args, **kwargs)

    def fail_on_state_queue_reload(*_args, **_kwargs):
        raise AssertionError("autopilot state reloaded the checkpoint Queue snapshot")

    monkeypatch.setattr(checkpoint_module, "load_action_queue", count_queue_loads)
    monkeypatch.setitem(
        checkpoint_module.build_autopilot_state.__globals__,
        "load_queue",
        fail_on_state_queue_reload,
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)

    assert queue_loads == 1
    assert any(item["type"] == "capability-chain-review" for item in checkpoint["next_action_queue"])


def test_checkpoint_reuses_case_state_owner_snapshot(tmp_path, monkeypatch):
    add_object(
        tmp_path,
        "target.com",
        object_ref="order_123",
        object_type="order",
        object_id="123",
        endpoint="https://api.target.com/orders/123",
    )
    case_state_globals = checkpoint_module.build_case_state_summary.__globals__
    load_case_state = case_state_globals["load_case_state"]
    state_loads = 0

    def count_state_loads(*args, **kwargs):
        nonlocal state_loads
        state_loads += 1
        return load_case_state(*args, **kwargs)

    monkeypatch.setitem(case_state_globals, "load_case_state", count_state_loads)

    checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)

    assert state_loads == 1
    assert checkpoint["case_state"]["objects"] == 1


def test_checkpoint_owner_read_budget_is_bounded(tmp_path, monkeypatch):
    target = "target.com"
    _seed_recon(tmp_path, target, ["https://api.target.com/users/1"])
    _seed_capability_parent(tmp_path, target=target)

    counts = {
        "queue": 0,
        "case": 0,
        "validation_candidates": 0,
        "coverage_projection": 0,
        "surface_fallback": 0,
        "coverage_fallback": 0,
    }

    original_queue = checkpoint_module.load_action_queue

    def count_queue(*args, **kwargs):
        counts["queue"] += 1
        return original_queue(*args, **kwargs)

    monkeypatch.setattr(checkpoint_module, "load_action_queue", count_queue)

    case_globals = checkpoint_module.build_case_state_summary.__globals__
    original_case = case_globals["load_case_state"]

    def count_case(*args, **kwargs):
        counts["case"] += 1
        return original_case(*args, **kwargs)

    monkeypatch.setitem(case_globals, "load_case_state", count_case)

    state_globals = checkpoint_module.build_autopilot_state.__globals__
    original_candidates = state_globals["load_validation_runner_candidate_pool"]

    def count_candidates(*args, **kwargs):
        counts["validation_candidates"] += 1
        return original_candidates(*args, **kwargs)

    monkeypatch.setitem(state_globals, "load_validation_runner_candidate_pool", count_candidates)

    original_matrix_projection = checkpoint_module.load_matrix_projection

    def count_matrix_projection(*args, **kwargs):
        counts["coverage_projection"] += 1
        return original_matrix_projection(*args, **kwargs)

    monkeypatch.setattr(checkpoint_module, "load_matrix_projection", count_matrix_projection)

    context_globals = checkpoint_module.build_context_pack.__globals__

    def fail_surface_fallback(*_args, **_kwargs):
        counts["surface_fallback"] += 1
        raise AssertionError("Context Pack reloaded Surface after State projection")

    def fail_coverage_fallback(*_args, **_kwargs):
        counts["coverage_fallback"] += 1
        raise AssertionError("Context Pack reloaded Coverage after Checkpoint projection")

    monkeypatch.setitem(context_globals, "_surface_state", fail_surface_fallback)
    monkeypatch.setitem(context_globals, "_safe_find_gaps", fail_coverage_fallback)

    checkpoint = build_checkpoint(tmp_path, target=target, refresh_coverage=False)

    assert checkpoint["target"] == target
    assert counts == {
        "queue": 1,
        "case": 1,
        "validation_candidates": 1,
        "coverage_projection": 1,
        "surface_fallback": 0,
        "coverage_fallback": 0,
    }


def test_checkpoint_owner_snapshots_preserve_state_projection(tmp_path):
    target = "target.com"
    _seed_recon(tmp_path, target, ["https://api.target.com/users/1"])
    _seed_capability_parent(tmp_path, target=target)
    add_object(
        tmp_path,
        target,
        object_ref="order_123",
        object_type="order",
        object_id="123",
        endpoint="https://api.target.com/orders/123",
    )
    checkpoint_module.build_autopilot_state(str(tmp_path), target)
    baseline = checkpoint_module.build_autopilot_state(str(tmp_path), target)
    reused = checkpoint_module.build_autopilot_state(
        str(tmp_path),
        target,
        queue_snapshot=checkpoint_module.load_action_queue(tmp_path, target),
        case_state_summary=checkpoint_module._case_state_summary(tmp_path, target),
    )

    for key in (
        "next_action",
        "action_queue_next",
        "case_state",
        "structured_findings",
        "validation_runner_candidates",
        "priority_frontier",
        "surface",
    ):
        assert reused[key] == baseline[key], key


def test_autopilot_state_rejects_cross_target_owner_snapshots(tmp_path):
    add_object(
        tmp_path,
        "target.com",
        object_ref="order_123",
        object_type="order",
        object_id="123",
        endpoint="https://target.com/orders/123",
    )

    with pytest.raises(ValueError, match="action queue snapshot target"):
        checkpoint_module.build_autopilot_state(
            str(tmp_path),
            "target.com",
            queue_snapshot={"target": "other.test", "actions": []},
        )
    with pytest.raises(ValueError, match="case state snapshot target"):
        checkpoint_module.build_autopilot_state(
            str(tmp_path),
            "target.com",
            case_state_summary={"target": "other.test"},
        )


def test_checkpoint_reuses_fresh_coverage_matrix(tmp_path, monkeypatch):
    _seed_recon(tmp_path, "target.com", ["https://target.com/api/users/1"])
    first = build_checkpoint(tmp_path, target="target.com")
    assert first["evidence_reviewed"]["coverage_rebuilt"] is True

    monkeypatch.setattr(
        checkpoint_module,
        "rebuild_matrix",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("fresh coverage matrix was rebuilt")
        ),
    )
    second = build_checkpoint(tmp_path, target="target.com")
    assert second["evidence_reviewed"]["coverage_rebuilt"] is False


def test_checkpoint_no_refresh_is_read_only_for_coverage(tmp_path, monkeypatch):
    _seed_recon(tmp_path, "target.com", ["https://target.com/api/users/1"])
    monkeypatch.setattr(
        checkpoint_module,
        "rebuild_matrix",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("no-refresh rebuilt coverage")
        ),
    )
    checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)
    assert checkpoint["evidence_reviewed"]["coverage_rebuilt"] is False


def test_bounded_proposals_preserve_lane_types_before_duplicate_fill():
    proposals = [
        f"Candidate evidence gap for finding F-{index} on /items/{index}: fill evidence."
        for index in range(8)
    ] + [
        "Cover high-value matrix gap: /admin x Authz (weight=5).",
        "Cover actor matrix gap: /orders/1 x IDOR with peer/other/id_swap expected=deny status=missing.",
        "Review surface candidate https://target.com/payments: inspect workflow.",
    ]

    bounded = _bounded_next_proposals(proposals, "target.com")

    assert len(bounded) == 8
    assert any(item.startswith("Cover high-value matrix gap:") for item in bounded)
    assert any(item.startswith("Cover actor matrix gap:") for item in bounded)
    assert any(item.startswith("Review surface candidate ") for item in bounded)


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


def test_repeated_auth_prerequisite_handoff_keeps_one_queue_action(tmp_path):
    proposal = _actor_gap_enrichment_proposal(
        {
            "actor_matrix": {
                "gaps": [{
                    "endpoint": "/api/orders/123",
                    "vuln_class": "IDOR",
                    "actor": "peer",
                    "object_scope": "other_object_same_org",
                    "variant": "id_swap",
                    "status": "missing",
                }]
            }
        },
        {"actors": 0, "sessions": 0, "objects": 0},
    )
    checkpoint = {
        "target": "target.com",
        "context_pack": {},
        "next_action_queue": _build_next_action_queue([proposal], "target.com"),
    }

    first = sync_checkpoint_action_queue(tmp_path, checkpoint)
    queue_path = tmp_path / "state" / "target.com" / "action_queue.json"
    first_bytes = queue_path.read_bytes()
    first_queue = load_queue(tmp_path, "target.com")
    second = sync_checkpoint_action_queue(tmp_path, checkpoint)
    second_queue = load_queue(tmp_path, "target.com")

    assert first["stats"]["added"] == 1
    assert second["stats"]["added"] == 0
    assert queue_path.read_bytes() == first_bytes
    assert len(second_queue["actions"]) == len(first_queue["actions"]) == 1
    assert second_queue["actions"][0]["type"] == "case-state-enrichment"
    assert second_queue["actions"][0]["metadata"]["missing_evidence"] == [
        "second actor",
        "peer/second session",
        "business object",
    ]


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


def test_checkpoint_keeps_every_reconciled_root_claim_in_the_durable_queue(tmp_path, capsys):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    for name, endpoint, vuln_class in (
        ("claim-sqli.json", "/rest/products/search", "SQLi"),
        ("claim-authz.json", "/rest/admin/config", "Authz"),
        ("claim-upload.json", "/file-upload", "Upload"),
    ):
        (findings_dir / name).write_text(
            json.dumps(
                {
                    "title": name,
                    "endpoint": endpoint,
                    "vuln_class": vuln_class,
                    "poc": "candidate replay",
                }
            ),
            encoding="utf-8",
        )

    first_exit = checkpoint_module.main([
        "--repo-root", str(tmp_path), "--target", "target.com", "--no-refresh-coverage", "--json",
    ])
    capsys.readouterr()
    findings = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    expected_ids = {item["id"] for item in findings}
    first_queue = load_queue(tmp_path, "target.com")
    first_ids = {
        str((item.get("metadata") or {}).get("finding_id") or "")
        for item in first_queue["actions"]
    }

    second_exit = checkpoint_module.main([
        "--repo-root", str(tmp_path), "--target", "target.com", "--no-refresh-coverage", "--json",
    ])
    capsys.readouterr()
    second_queue = load_queue(tmp_path, "target.com")
    second_ids = {
        str((item.get("metadata") or {}).get("finding_id") or "")
        for item in second_queue["actions"]
    }

    assert first_exit == second_exit == 0
    assert expected_ids <= first_ids
    assert expected_ids <= second_ids
    assert len(second_queue["actions"]) == len(first_queue["actions"])


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

    assert checkpoint["decision"] == "refresh-recon"
    assert checkpoint["structured_findings"]["pending_validation"] == 0
    assert checkpoint["structured_findings"]["validated_pending_report"] == 1
    assert checkpoint["structured_findings"]["next_report"]["id"] == "TARGET-AUTHZ"
    assert any(item["type"] == "report" for item in checkpoint["next_action_queue"])
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


@pytest.mark.parametrize(
    ("action", "decision"),
    [
        ("wait_recon", "wait_recon"),
        ("validation", "validate"),
        ("candidate-evidence-gap", "validate"),
        ("recon", "refresh-recon"),
        ("ranked-surface", "hunt"),
        ("source-enrichment", "enrich"),
        ("action-gated-review", "checkpoint"),
        ("report", "report"),
        ("recon_no_live_hosts", "handoff"),
        ("unknown-action", "handoff"),
    ],
)
def test_checkpoint_decision_is_pure_projection_of_effective_action(action, decision):
    assert _decision_for_action(action) == decision


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


def test_checkpoint_default_preserves_explicitly_claimed_priority_override(tmp_path):
    target = "target.com"
    high = add_manual_action(
        tmp_path,
        target=target,
        action_type="high-default",
        evidence="High default candidate.",
        next_question="Should the default candidate run first?",
        action="Run the default candidate.",
        priority=100,
    )["queue"]["actions"][0]
    added = add_manual_action(
        tmp_path,
        target=target,
        action_type="ai-priority-override",
        evidence="AI selected a lower mechanical priority for higher information gain.",
        next_question="Does the AI-selected workflow expose the stronger signal?",
        action="Run the AI-selected workflow first.",
        priority=1,
        source="ai",
        source_id="priority-override",
    )
    selected = next(
        item for item in added["queue"]["actions"]
        if item["type"] == "ai-priority-override"
    )

    assert high["priority"] > selected["priority"]
    claimed = claim_next_action(tmp_path, target, action_id=selected["id"])
    state = checkpoint_module.build_autopilot_state(str(tmp_path), target)
    checkpoint = build_checkpoint(tmp_path, target=target, refresh_coverage=False)
    sync_checkpoint_action_queue(tmp_path, checkpoint)

    assert claimed["status"] == "running"
    assert state["action_queue_next"]["id"] == selected["id"]
    assert checkpoint["default_candidate"]["id"] == selected["id"]
    assert checkpoint["recommended_executable_action"]["id"] == selected["id"]
    assert checkpoint["action_queue_sync"]["next"]["id"] == selected["id"]


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


def test_hypothesis_seed_is_only_a_fallback_without_owner_hypothesis():
    state = {"has_recon": True, "surface": {"p1": [], "workflow_leads": []}}
    context = {"hypothesis_seeds": ["try a card-derived route"]}

    assert _lead_proposals(state, context) != []
    assert _lead_proposals(state, context, case_state={"open_hypotheses": 1}) == []


def test_checkpoint_v2_closure_compares_the_complete_identity():
    closed = build_closure_cell(
        "/api/search",
        "SQLi",
        {"method": "GET", "parameter": "q"},
    ).key.to_dict()
    other = build_closure_cell(
        "/api/search",
        "SQLi",
        {"method": "GET", "parameter": "term"},
    ).key.to_dict()
    resolver = _ledger_covered_cells({
        "closed_cells_v2": [{"identity_v2": closed, "result": "tested_clean"}],
    })

    assert _ledger_covers_cell(resolver, "/api/search", "SQLi", closed)
    assert not _ledger_covers_cell(resolver, "/api/search", "SQLi", other)
    assert not _ledger_covers_cell(resolver, "/other", "SQLi", closed)


def test_checkpoint_surfaces_identity_follow_up_action():
    proposals = _ledger_candidate_proposals({
        "identity_v2_follow_up_actions": [{
            "kind": "identity_follow_up",
            "endpoint": "/api/search",
            "family": "SQLi",
            "missing_fields": [],
            "conflicts": ["method_mismatch"],
            "evidence_refs": ["evidence/search.json"],
        }],
    })

    assert len(proposals) == 1
    assert "Resolve closure identity for /api/search x SQLi" in proposals[0]
    assert "method_mismatch" in proposals[0]


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


def test_high_risk_review_groups_techniques_without_truncating_canonical_families():
    lane_order = (
        "SQLi", "SSRF", "XXE", "RCE", "Path", "Upload", "IDOR", "Authz",
        "GraphQL", "OAuth", "JWT", "CSRF", "Race", "Webhook", "XSS",
    )
    lanes = {name: {"disposition": "unassessed"} for name in lane_order}
    lanes["SQLi"]["techniques"] = ["NoSQLi"]
    lanes["RCE"]["techniques"] = ["SSTI", "CommandInjection", "Deserialization"]
    lanes["Path"]["techniques"] = ["LFI", "RFI"]

    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": [], "surface": {}},
        coverage_gaps=[],
        matrix={"endpoints": [{"endpoint": "/api"}], "high_risk_lanes": lanes},
        target="target.com",
        context_pack={},
        evidence_summary={},
    )

    review = next(item for item in proposals if item.startswith("High-risk lane review:"))
    assert "SQLi[NoSQLi]=unassessed" in review
    assert "RCE[SSTI,CommandInjection,Deserialization]=unassessed" in review
    assert "Path[LFI,RFI]=unassessed" in review
    assert all(
        f"{name}=" in review
        for name in ("Authz", "GraphQL", "OAuth", "JWT", "CSRF", "Race", "Webhook", "XSS")
    )
    assert "NoSQLi=unassessed" not in review


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


def test_checkpoint_keeps_folded_coverage_and_replay_identities_separate():
    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": []},
        coverage_gaps=[{
            "endpoint": "/api/orders/{id}",
            "representative_endpoint": "/api/orders/123",
            "vuln_class": "IDOR",
            "weight": 3.0,
            "relevance_score": 3,
            "relevance_reason": "object reference path/parameter",
        }],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={},
        evidence_summary={},
    )

    action = next(
        item
        for item in _build_next_action_queue(proposals, "target.com")
        if item["type"] == "coverage-gap"
    )

    assert action["metadata"]["endpoint"] == "/api/orders/123"
    assert action["metadata"]["coverage_endpoint"] == "/api/orders/{id}"


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


def test_checkpoint_does_not_default_actor_matrix_without_owner_family(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://target.com/about/company"])

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["evidence_ledger"]["actor_matrix"] == {
        "gap_count": 0,
        "covered_count": 0,
        "gaps": [],
    }
    assert not any(item["type"] == "actor-gap" for item in checkpoint["next_action_queue"])


def test_checkpoint_actor_matrix_reads_only_active_queue_metadata_family():
    assert checkpoint_module._evidence_vuln_classes(
        [],
        queue_snapshot={"actions": [
            {"status": "queued", "metadata": {"vuln_class": "IDOR"}},
            {"status": "tested", "metadata": {"vuln_class": "Authz"}},
            {"status": "queued", "metadata": {"family": "custom-family"}},
        ]},
    ) == ["IDOR"]


def test_checkpoint_projects_free_hypothesis_metadata_into_case_queue(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://target.com/render"])
    hypothesis = add_hypothesis(
        tmp_path,
        "target.com",
        vuln_class="SSTI",
        endpoint="/render",
        why_now="template syntax changes the response",
        next_action="validate the renderer boundary",
        metadata={
            "family": "RCE",
            "primitive": "SSTI",
            "chain": ["template", "sandbox", "execution"],
            "evidence_refs": ["evidence/target.com/render-response.json"],
        },
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    action = next(
        item for item in checkpoint["next_action_queue"]
        if item["type"] == "case-state-backlog-create"
    )

    assert action["metadata"]["hypothesis_id"] == hypothesis["id"]
    assert action["metadata"]["family"] == "RCE"
    assert action["metadata"]["primitive"] == "SSTI"
    assert action["metadata"]["chain"] == ["template", "sandbox", "execution"]


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


def test_case_state_recovery_projection_keeps_hypothesis_metadata_in_action_queue():
    proposal = checkpoint_module._case_state_proposal({
        "top_next_action": {
            "next_action": "recover_hypothesis",
            "backlog_id": "val_001",
            "hypothesis_id": "hyp_001",
            "hypothesis": "peer access may differ on export",
            "why_now": "previous replay is blocked; recover with: capture export route",
            "recovery_next_action": "capture export route",
            "write_back": "preserve the blocked outcome before a fresh backlog",
            "chain_extensions_if_blocked": ["capture export route"],
        },
    })

    action = _build_next_action_queue([proposal], "target.com")[0]

    assert action["type"] == "case-state-enrichment"
    assert action["metadata"]["backlog_id"] == "val_001"
    assert action["metadata"]["hypothesis_id"] == "hyp_001"
    assert action["metadata"]["hypothesis"] == "peer access may differ on export"
    assert action["metadata"]["why_now"] == "previous replay is blocked; recover with: capture export route"
    assert action["metadata"]["chain_extensions_if_blocked"] == ["capture export route"]
    assert action["metadata"]["recovery_next_action"] == "capture export route"


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


def test_checkpoint_does_not_promote_low_confidence_historical_object_shape(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text("https://target.com\n")
    historical = "https://target.com/?option=com_demo&Itemid=0\n"
    (recon_dir / "urls" / "with_params.txt").write_text(historical)
    (recon_dir / "urls" / "all.txt").write_text(historical)

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["case_state_seed"]["suggested_objects"][0]["confidence"] == "low"
    assert not any(
        item.get("type") in {"case-state-seed", "case-state-enrichment"}
        for item in checkpoint["next_action_queue"]
    )


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
    convergence = next(
        item for item in checkpoint["next_action_queue"] if item["type"] == "evidence-convergence"
    )
    assert convergence["metadata"]["activation_required"] is True
    assert len(convergence["metadata"]["evidence_refs"]) >= 2


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
            "closed_cells": [
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


def test_next_proposals_emit_bounded_viewstate_integrity_review():
    proposals = _next_proposals(
        state={"has_recon": True, "surface": {}, "recommended_targets": []},
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={
            "hypothesis_seeds": [
                "ViewState 表单先保存同页新鲜 GET 基线及 __VIEWSTATEGENERATOR/__EVENTVALIDATION 字段名；"
                "仅对 __VIEWSTATE 做一次格式 control 与单字节 tamper replay。"
            ],
            "contradictions": [],
        },
        evidence_summary={},
    )

    review = next(item for item in proposals if item.startswith("ViewState integrity review:"))
    assert "tools/aspnet_viewstate_knownkey.py" in review
    assert "single-byte __VIEWSTATE tamper" in review
    assert "without submitting a business action" in review
    assert "cannot make ViewState/deserialization N/A" in review
    action_type, priority, hint = checkpoint_module._classify_next_action(review, "target.com")
    assert action_type == "viewstate-integrity-review"
    assert priority == 93
    assert "machineKey" in hint
    assert "Telerik absence is not N/A" in hint


def test_capability_chain_review_projection_has_stable_identity_and_bounded_lineage(tmp_path):
    parent = _seed_capability_parent(tmp_path)

    first = _capability_chain_review_item(tmp_path, "target.com")
    second = _capability_chain_review_item(tmp_path, "target.com")

    assert first == second
    assert first["type"] == "capability-chain-review"
    assert first["source_id"] == parent["id"]
    assert len(first["metadata"]["generation"]) == 64
    assert first["metadata"]["generation"] == first["metadata"]["primitive_fingerprint"]
    assert first["metadata"]["parent_action_id"] == parent["id"]
    assert first["metadata"]["parent_hypothesis_id"] == "H-primitive"
    assert first["metadata"]["primitive_lineage"] == {
        "capability": "cross-workflow object selector",
        "evidence_ref": "evidence/target.com/validation/primitive.json",
        "continuation_hint": "compare the linked download workflow",
    }
    assert "activation_required" not in first
    assert "depth_contract_version" not in first["metadata"]
    assert "hypothesis_id" not in first["metadata"]
    assert _decision_for_action(first["type"]) == "continue"


@pytest.mark.parametrize("case", ["no-hint", "off-target", "immediate-chain", "existing-child"])
def test_capability_chain_review_projection_rejects_ineligible_primitives(tmp_path, case):
    primitive = None
    continuation_kind = ""
    chain_child = False
    if case == "no-hint":
        primitive = {
            "capability": "cross-workflow object selector",
            "evidence_ref": "evidence/target.com/validation/primitive.json",
        }
    elif case == "off-target":
        foreign = tmp_path / "evidence" / "other.test" / "validation" / "primitive.json"
        foreign.parent.mkdir(parents=True)
        foreign.write_text("{}", encoding="utf-8")
        primitive = {
            "capability": "cross-workflow object selector",
            "evidence_ref": "evidence/other.test/validation/primitive.json",
            "continuation_hint": "compare the linked download workflow",
        }
    elif case == "immediate-chain":
        continuation_kind = "chain"
    else:
        chain_child = True
    _seed_capability_parent(
        tmp_path,
        primitive=primitive,
        continuation_kind=continuation_kind,
        chain_child=chain_child,
    )

    assert _capability_chain_review_item(tmp_path, "target.com") == {}


def test_capability_chain_review_checkpoint_ingest_is_idempotent_and_final_suppresses_replay(tmp_path):
    _seed_capability_parent(tmp_path)
    review = _capability_chain_review_item(tmp_path, "target.com")

    ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [review]})
    assert _capability_chain_review_item(tmp_path, "target.com") == {}
    ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": []})
    queue = load_queue(tmp_path, "target.com")
    reviews = [item for item in queue["actions"] if item["type"] == "capability-chain-review"]
    assert len(reviews) == 1

    resolve_action(
        tmp_path,
        target="target.com",
        action_id=reviews[0]["id"],
        status="dead-end",
        result="No bounded in-scope chain remained.",
    )
    assert _capability_chain_review_item(tmp_path, "target.com") == {}
    ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": []})
    reviews = [
        item for item in load_queue(tmp_path, "target.com")["actions"]
        if item["type"] == "capability-chain-review"
    ]
    assert len(reviews) == 1
    assert reviews[0]["status"] == "dead-end"


def test_capability_chain_review_serializes_distinct_primitives_and_dedupes_equivalents(tmp_path):
    parent = _seed_capability_parent(tmp_path)
    second_ref = "evidence/target.com/validation/second-primitive.json"
    second_path = tmp_path / second_ref
    second_path.parent.mkdir(parents=True, exist_ok=True)
    second_path.write_text(json.dumps({"difference": "stable second"}), encoding="utf-8")
    queue = load_queue(tmp_path, "target.com")
    parent_metadata = queue["actions"][0]["metadata"]
    parent_metadata["capability_primitives"].extend([
        {
            "capability": "  CROSS-WORKFLOW   OBJECT SELECTOR ",
            "evidence_ref": "evidence/target.com/validation/primitive.json",
            "continuation_hint": " Compare   the linked DOWNLOAD workflow ",
        },
        {
            "capability": "parser-controlled export format",
            "evidence_ref": second_ref,
            "continuation_hint": "compare one alternate export parser",
        },
    ])
    save_queue(tmp_path, "target.com", queue)

    fingerprints = []
    capabilities = []
    for _ in range(2):
        review = _capability_chain_review_item(tmp_path, "target.com")
        assert review == _capability_chain_review_item(tmp_path, "target.com")
        assert review["source_id"] == parent["id"]
        fingerprints.append(review["metadata"]["primitive_fingerprint"])
        capabilities.append(review["metadata"]["primitive_lineage"]["capability"])
        ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [review]})
        durable = next(
            item for item in load_queue(tmp_path, "target.com")["actions"]
            if item["type"] == "capability-chain-review" and item["status"] == "queued"
        )
        resolve_action(
            tmp_path,
            target="target.com",
            action_id=durable["id"],
            status="dead-end",
            result="No bounded in-scope chain remained for this primitive.",
        )

    assert len(set(fingerprints)) == 2
    assert set(capabilities) == {
        "cross-workflow object selector",
        "parser-controlled export format",
    }
    assert _capability_chain_review_item(tmp_path, "target.com") == {}
    reviews = [
        item for item in load_queue(tmp_path, "target.com")["actions"]
        if item["type"] == "capability-chain-review"
    ]
    assert len(reviews) == 2
    assert all(item["status"] == "dead-end" for item in reviews)


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
            "closed_cells": [
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


@pytest.mark.parametrize(
    ("card_id", "card_file"),
    [
        ("nosql-query-injection", "knowledge/cards/nosql-query-injection.md"),
        ("server-side-template-injection", "knowledge/cards/server-side-template-injection.md"),
        ("insecure-deserialization", "knowledge/cards/insecure-deserialization.md"),
        ("path-traversal-file-read", "knowledge/cards/path-traversal-file-read.md"),
        ("ssrf-url-fetch", "knowledge/cards/ssrf-url-fetch.md"),
        ("sqli-hidden-surfaces", "knowledge/cards/sqli-hidden-surfaces.md"),
    ],
)
def test_specific_knowledge_recalls_use_one_generic_review_path(card_id, card_file):
    item = _knowledge_signal_review_item(
        {
            "knowledge_card_recall": [{
                "file": card_file,
                "id": card_id,
                "status": "selected",
                "rank": 1,
                "reason": "specific routing signal matched; selected within card budget",
            }],
            "evidence_anchors": ["Observed a parser-specific input boundary."],
            "hypothesis_seeds": ["Compare one controlled parser variant."],
        },
        [],
        "target.com",
    )

    assert item["type"] == "knowledge-signal-review"
    assert item["source"] == "knowledge-recall"
    assert item["metadata"]["knowledge_refs"] == [card_file]
    assert _decision_for_action(item["type"]) == "continue"


def test_knowledge_signal_review_is_grouped_stable_and_excludes_fallbacks():
    recalls = [
        {
            "file": "knowledge/cards/fourth.md",
            "id": "fourth",
            "status": "deferred",
            "rank": 4,
            "reason": "context evidence signal matched; deferred by card budget",
        },
        {
            "file": "knowledge/cards/first.md",
            "id": "first",
            "status": "selected",
            "rank": 1,
            "reason": "explicit focus matched; selected within card budget",
        },
        {
            "file": "knowledge/cards/coverage-prompts.md",
            "id": "coverage-prompts",
            "status": "selected",
            "rank": 2,
            "reason": "coverage or routing fallback; selected within card budget",
        },
        {
            "file": "knowledge/cards/already-carried.md",
            "id": "already-carried",
            "status": "selected",
            "rank": 3,
            "reason": "specific routing signal matched; selected within card budget",
        },
        {
            "file": "knowledge/cards/carried-by-file.md",
            "id": "carried-by-file",
            "status": "selected",
            "rank": 3,
            "reason": "specific routing signal matched; selected within card budget",
        },
        *[
            {
                "file": f"knowledge/cards/extra-{rank}.md",
                "id": f"extra-{rank}",
                "status": "deferred",
                "rank": rank,
                "reason": "context evidence signal matched; deferred by card budget",
            }
            for rank in range(5, 9)
        ],
    ]
    context = {
        "knowledge_card_recall": list(reversed(recalls)),
        "evidence_anchors": ["anchor"],
        "hypothesis_seeds": ["seed"],
    }
    actions = [{"metadata": {
        "knowledge_refs": ["knowledge/cards/carried-by-file.md"],
        "selected_knowledge_refs": ["already-carried"],
    }}]

    first = _knowledge_signal_review_item(context, actions, "target.com")
    second = _knowledge_signal_review_item(context, actions, "target.com")

    assert first == second
    assert first["metadata"]["knowledge_refs"] == [
        "knowledge/cards/first.md",
        "knowledge/cards/fourth.md",
        "knowledge/cards/extra-5.md",
        "knowledge/cards/extra-6.md",
        "knowledge/cards/extra-7.md",
        "knowledge/cards/extra-8.md",
    ]
    assert len(first["metadata"]["knowledge_card_recall"]) == 6
    assert "2 more in metadata" in first["action"]
    assert "explicit focus matched" in first["action"]
    assert "coverage-prompts" not in first["action"]
    assert _knowledge_signal_review_item(
        {"knowledge_card_recall": [recalls[2]]},
        [],
        "target.com",
    ) == {}


def test_knowledge_signal_review_terminal_generation_suppression_and_reopen(tmp_path):
    context = {
        "knowledge_card_recall": [{
            "file": "knowledge/cards/server-side-template-injection.md",
            "id": "server-side-template-injection",
            "status": "selected",
            "rank": 1,
            "reason": "specific routing signal matched; selected within card budget",
        }],
        "evidence_anchors": ["template parameter observed"],
        "hypothesis_seeds": ["compare one template expression"],
    }
    first = _knowledge_signal_review_item(context, [], "target.com")
    ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [first]})
    action = next(
        item for item in load_queue(tmp_path, "target.com")["actions"]
        if item["type"] == "knowledge-signal-review"
    )
    resolve_action(
        tmp_path,
        target="target.com",
        action_id=action["id"],
        status="dead-end",
        result="No bounded hypothesis remained for the current evidence.",
    )

    assert _filter_final_action_queue_items(tmp_path, "target.com", [first]) == []

    changed = {**context, "evidence_anchors": ["new template engine marker observed"]}
    reopened = _knowledge_signal_review_item(changed, [], "target.com")
    assert reopened["metadata"]["generation"] != first["metadata"]["generation"]
    assert _filter_final_action_queue_items(tmp_path, "target.com", [reopened]) == [reopened]


def test_knowledge_signal_volatile_projection_changes_do_not_reopen(tmp_path):
    context = {
        "knowledge_card_recall": [{
            "file": "knowledge/cards/api-testing-workflow.md",
            "id": "api-testing-workflow",
            "status": "selected",
            "rank": 1,
            "reason": "specific routing signal matched; selected within card budget",
        }],
        "evidence_anchors": [
            "Surface review https://TARGET/job/a score_hint=2",
            "Coverage gap: /job/a x Path weight=3.0",
        ],
        "hypothesis_seeds": ["compare the observed request shape"],
    }
    first = _knowledge_signal_review_item(context, [], "target.com")
    ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [first]})
    action = next(
        item for item in load_queue(tmp_path, "target.com")["actions"]
        if item["type"] == "knowledge-signal-review"
    )
    resolve_action(
        tmp_path,
        target="target.com",
        action_id=action["id"],
        status="dead-end",
        result="The recalled signal was already dispositioned.",
    )

    changed = {
        **context,
        "knowledge_card_recall": [{
            **context["knowledge_card_recall"][0],
            "rank": 7,
            "reason": "context evidence signal matched; deferred by card budget",
        }],
        "evidence_anchors": [
            "Surface review https://TARGET/job/b score_hint=1",
            "Coverage gap: /job/b x Path weight=3.0",
        ],
    }
    reopened = _knowledge_signal_review_item(changed, [], "target.com")

    assert reopened["metadata"]["signal_identity"] == first["metadata"]["signal_identity"]
    assert reopened["metadata"]["generation"] != first["metadata"]["generation"]
    assert _filter_final_action_queue_items(tmp_path, "target.com", [reopened]) == []
    ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": [reopened]})
    assert len(load_queue(tmp_path, "target.com")["actions"]) == 1


def test_checkpoint_coverage_projection_bounds_large_family_without_closing_siblings():
    family_gaps = [
        {
            "endpoint": f"/en/job/us/role-{index}/23251/{1000 + index}",
            "vuln_class": "Path",
            "weight": 3.5,
            "relevance_score": 14,
            "relevance_reason": "file/path selector; file download/read path",
        }
        for index in range(3)
    ]
    other = {
        "endpoint": "/download/export-report",
        "vuln_class": "Path",
        "weight": 3.5,
        "relevance_score": 12,
        "relevance_reason": "file/path selector; file download/read path",
    }
    matrix = {
        "endpoints": [
            {
                "endpoint": item["endpoint"],
                "cells": {"Path": {"status": "untested"}},
            }
            for item in [*family_gaps, other]
        ]
    }

    selected = _checkpoint_coverage_gaps([*family_gaps, other], matrix, limit=8)

    assert len(selected) == 2
    family_selected = [item for item in selected if "/en/job/" in item["endpoint"]]
    assert len(family_selected) == 1
    assert family_selected[0]["_projection_family"]["size"] == 3
    assert any(item["endpoint"] == other["endpoint"] for item in selected)
    assert all(
        endpoint["cells"]["Path"]["status"] == "untested"
        for endpoint in matrix["endpoints"]
    )

    proposal = (
        "Cover high-value matrix gap: {endpoint} x Path (weight=3.5, relevance=14: "
        "file/path selector; file download/read path). Family projection: "
        "key=structural:path:file/path selector; kind=structural; size=3; "
        "samples={members}."
    ).format(
        endpoint=family_selected[0]["endpoint"],
        members=",".join(family_selected[0]["_projection_family"]["members"]),
    )
    metadata = _extract_action_metadata(proposal)
    assert metadata["family_projection"] == "structural"
    assert metadata["family_size"] == 3
    assert len(metadata["family_members"]) == 3


def test_checkpoint_family_projection_keeps_all_members_and_leaves_ai_override_visible():
    family_gaps = [
        {
            "endpoint": f"/en/job/us/role-{index}/23251/{1000 + index}",
            "vuln_class": "Path",
            "weight": 3.5,
            "relevance_score": 14,
            "relevance_reason": "file/path selector; file download/read path",
        }
        for index in range(7)
    ]
    endpoints = [item["endpoint"] for item in family_gaps]
    matrix = {
        "endpoints": [
            {"endpoint": endpoint, "cells": {"Path": {"status": "untested"}}}
            for endpoint in endpoints
        ]
    }

    selected = _checkpoint_coverage_gaps(family_gaps, matrix, limit=8)
    projection = selected[0]["_projection_family"]

    assert projection["size"] == len(endpoints)
    assert projection["members"] == endpoints

    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": []},
        coverage_gaps=family_gaps,
        matrix=matrix,
        target="target.com",
        context_pack={},
        evidence_summary={},
    )
    proposal = next(item for item in proposals if item.startswith("Cover high-value matrix gap:"))
    assert "Queue projection only" in proposal
    assert "does not assert family equivalence" in proposal
    assert "AI remains the judgment owner and may choose or expand any listed member" in proposal
    assert "sibling Matrix cells stay unclosed" in proposal

    action = next(
        item
        for item in _build_next_action_queue(proposals, "target.com")
        if item["type"] == "coverage-gap"
    )
    assert action["metadata"]["family_size"] == len(endpoints)
    assert action["metadata"]["family_members"] == endpoints
    assert all(
        endpoint["cells"]["Path"]["status"] == "untested"
        for endpoint in matrix["endpoints"]
    )


def test_checkpoint_family_projection_bounds_preview_without_hiding_family_size():
    gaps = [
        {
            "endpoint": f"/api/orders/role-{index}/23251/{1000 + index}",
            "vuln_class": "Path",
            "weight": 3.5,
            "relevance_score": 14,
            "relevance_reason": "file/path selector; file download/read path",
        }
        for index in range(20)
    ]
    matrix = {
        "endpoints": [
            {"endpoint": item["endpoint"], "cells": {"Path": {"status": "untested"}}}
            for item in gaps
        ]
    }

    selected = _checkpoint_coverage_gaps(gaps, matrix, limit=8)
    projection = selected[0]["_projection_family"]

    assert projection["size"] == 20
    assert len(projection["members"]) == 12

    proposals = _next_proposals(
        state={"has_recon": True, "recommended_targets": []},
        coverage_gaps=gaps,
        matrix=matrix,
        target="target.com",
        context_pack={},
        evidence_summary={},
    )
    proposal = next(item for item in proposals if item.startswith("Cover high-value matrix gap:"))
    assert "preview is incomplete" in proposal
    assert "raw Coverage gap window" in proposal


def test_checkpoint_does_not_merge_distinct_dynamic_resources():
    gaps = [
        {
            "endpoint": f"/api/v1/{resource}/{index}",
            "vuln_class": "Path",
            "weight": 3.5,
            "relevance_score": 14,
            "relevance_reason": "file/path selector; file download/read path",
        }
        for resource, index in (("users", 101), ("orders", 202), ("admin", 303))
    ]
    matrix = {
        "endpoints": [
            {
                "endpoint": item["endpoint"],
                "cells": {"Path": {"status": "untested"}},
            }
            for item in gaps
        ]
    }

    selected = _checkpoint_coverage_gaps(gaps, matrix, limit=8)

    assert [item["endpoint"] for item in selected] == [item["endpoint"] for item in gaps]
    assert all("_projection_family" not in item for item in selected)


def test_checkpoint_family_metadata_preserves_delimiters_in_reason_and_paths():
    proposal = (
        "Cover high-value matrix gap: /api/orders/list.json x Path "
        "(weight=3.5, relevance=14: file/path selector; file download/read path). "
        "Validation path: Capture the exact request. If concrete side-effect risk "
        "appears, mark blocked and use low-risk evidence instead. "
        "Family projection: key=structural:path:file/path selector; file download/read "
        "path:{static}/{static}/{static}:/api/orders; kind=structural; size=3; "
        "samples=/api/orders/list.json,/api/orders/search.json,/api/orders/export.json."
    )

    action = _build_next_action_queue([proposal], "target.com")[0]

    assert action["metadata"]["family_key"] == (
        "structural:path:file/path selector; file download/read path:"
        "{static}/{static}/{static}:/api/orders"
    )
    assert action["metadata"]["family_members"] == [
        "/api/orders/list.json",
        "/api/orders/search.json",
        "/api/orders/export.json",
    ]
    assert action["metadata"]["validation_path"] == "Capture the exact request."


def test_checkpoint_family_projection_refreshes_queued_action_without_duplicate(tmp_path):
    def checkpoint_for(size):
        members = ",".join(
            f"/api/orders/{name}.json"
            for name in ("list", "search", "export", "archive")[:size]
        )
        action = (
            "Cover high-value matrix gap: /api/orders/list.json x Path "
            "(weight=3.5, relevance=14: file/path selector). Validation path: "
            "Capture the exact request. If concrete side-effect risk appears, "
            "mark blocked and use low-risk evidence instead. Family projection: "
            f"key=route-template:path:file/path selector:/api/orders/{{id}}; "
            f"kind=route-template; size={size}; samples={members}."
        )
        return {"next_action_queue": _build_next_action_queue([action], "target.com")}

    first = ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint_for(3))
    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint_for(4))
    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

    assert first["stats"]["added"] == 1
    assert second["stats"]["added"] == 0
    assert second["stats"]["updated"] == 1
    assert len(queue["actions"]) == 1
    assert coverage["metadata"]["family_size"] == 4
    assert coverage["metadata"]["family_members"][-1] == "/api/orders/archive.json"
    assert "size=4" in coverage["action"]


@pytest.mark.parametrize("family_status", ["tested", "not_applicable"])
def test_checkpoint_preserves_ssti_recall_after_rce_family_closure(
    tmp_path,
    monkeypatch,
    family_status,
):
    card = "knowledge/cards/server-side-template-injection.md"
    cell_status = "tested_clean" if family_status == "tested" else "n_a"
    monkeypatch.setattr(
        checkpoint_module,
        "load_matrix_projection",
        lambda *_args, **_kwargs: {
            "endpoints": [{
                "endpoint": "/render",
                "cells": {"RCE": {"status": cell_status, "reason": "bounded family closure"}},
            }],
        },
    )
    monkeypatch.setattr(
        checkpoint_module,
        "build_context_pack",
        lambda *_args, **_kwargs: {
            "phase": "hunt",
            "selected_skill": "skills/web2-vuln-classes/SKILL.md",
            "skill_route": {},
            "knowledge_cards": [card],
            "knowledge_card_recall": [{
                "file": card,
                "id": "server-side-template-injection",
                "status": "selected",
                "rank": 1,
                "reason": "specific routing signal matched; selected within card budget",
            }],
            "evidence_anchors": ["POST /render accepts a template-shaped field"],
            "hypothesis_seeds": ["compare one inert expression"],
            "reference_hints": [],
            "required_checks": [],
            "contradictions": [],
        },
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)
    review = next(
        item for item in checkpoint["next_action_queue"]
        if item["type"] == "knowledge-signal-review"
    )
    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    durable = [
        item for item in load_queue(tmp_path, "target.com")["actions"]
        if item["type"] == "knowledge-signal-review"
    ]

    assert checkpoint["coverage"]["high_risk_lanes"]["RCE"]["disposition"] == family_status
    assert review["metadata"]["knowledge_refs"] == [card]
    assert len(durable) == 1


def test_artifact_backed_high_workflow_leads_become_durable_queue_items(tmp_path):
    artifact = tmp_path / "recon" / "target.com" / "exposure" / "openapi.jsonl"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"path":"/api/admin/export"}\n', encoding="utf-8")

    items = _workflow_lead_queue_items(
        {
            "surface": {
                "workflow_leads": [
                    {
                        "title": "OpenAPI auth boundary",
                        "category": "openapi-semantics",
                        "priority": "high",
                        "artifact": str(artifact),
                        "next_action": "replay the declared operation",
                    },
                    {
                        "title": "ordinary metadata",
                        "category": "public-metadata",
                        "priority": "medium",
                        "artifact": str(artifact),
                    },
                ]
            }
        },
        repo_root=tmp_path,
        target="target.com",
    )

    assert len(items) == 1
    item = items[0]
    assert item["type"] == "workflow-lead-review"
    assert item["source"] == "workflow-lead"
    assert item["metadata"]["artifact"] == str(artifact)
    assert item["metadata"]["generation"]

    save_queue(tmp_path, "target.com", {"actions": []})
    assert load_queue(tmp_path, "target.com")["actions"] == []
    checkpoint = {"target": "target.com", "next_action_queue": items}
    sync_checkpoint_action_queue(tmp_path, checkpoint)
    persisted = load_queue(tmp_path, "target.com")
    assert len(persisted["actions"]) == 1
    assert persisted["actions"][0]["source"] == "workflow-lead"


def test_checkpoint_prefers_structured_workflow_lead_for_same_artifact_category():
    artifact = "findings/target.com/manual_review/openapi.jsonl"
    natural = _build_next_action_queue(
        [
            "Evidence: Workflow lead: OpenAPI auth boundary. Why it matters: API. "
            "Category=openapi-semantics. Artifact=findings/target.com/manual_review/openapi.jsonl. "
            "Next action: replay the declared operation."
        ],
        "target.com",
    )[0]
    structured = {
        "source": "workflow-lead",
        "type": "workflow-lead-review",
        "metadata": {"artifact": artifact, "category": "openapi-semantics"},
    }

    deduped = _dedupe_artifact_category_items([natural, structured])

    assert len(deduped) == 1
    assert deduped[0]["source"] == "workflow-lead"


def test_sql_matrix_candidates_become_generation_aware_durable_actions(tmp_path):
    state = {
        "sql_matrix": {
            "query": {
                "status": "candidate_pending",
                "path": "findings/target.com/poc/sql_matrix/query/summary.json",
                "input_fingerprint": "a" * 64,
                "candidate_count": 1,
                "source_paths": ["recon/target.com/urls/with_params.txt"],
                "candidates": [{
                    "endpoint": "/search",
                    "field": "q",
                    "class": "sqli_error",
                    "signal": "database error",
                }],
            },
            "form": {"status": "complete_no_hit"},
        }
    }

    items = _sql_matrix_queue_items(state, "target.com")
    assert len(items) == 1
    assert items[0]["type"] == "sql-matrix-review"
    assert items[0]["source"] == "sql-matrix"
    assert items[0]["source_id"] == "sql-matrix-query"
    assert items[0]["metadata"]["generation"] == "a" * 64
    assert "--urls-file" in items[0]["command_hint"]

    save_queue(tmp_path, "target.com", {"actions": []})
    checkpoint = {"target": "target.com", "next_action_queue": items}
    sync_checkpoint_action_queue(tmp_path, checkpoint)
    persisted = load_queue(tmp_path, "target.com")
    assert len(persisted["actions"]) == 1
    assert persisted["actions"][0]["source_id"] == "sql-matrix-query"

    sync_checkpoint_action_queue(tmp_path, {"target": "target.com", "next_action_queue": items})
    assert len(load_queue(tmp_path, "target.com")["actions"]) == 1


def test_candidate_finding_creates_one_scoped_sibling_action(tmp_path):
    evidence = tmp_path / "findings" / "target.com" / "validation" / "F-1.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"id":"F-1"}\n', encoding="utf-8")
    item = _sibling_queue_item(
        {
            "structured_findings": {
                "next_validation": {
                    "id": "F-1",
                    "url": "https://target.com/api/orders/123",
                    "validation_status": "candidate",
                    "source_file": str(evidence),
                }
            }
        },
        repo_root=tmp_path,
        target="target.com",
    )
    assert item["type"] == "sibling-chain-review"
    assert item["source"] == "primary-finding-sibling"
    assert "sibling_generator.py" in item["command_hint"]
    assert item["metadata"]["finding_id"] == "F-1"


def test_candidate_sibling_action_rejects_off_target_endpoint(tmp_path):
    assert _sibling_queue_item(
        {
            "structured_findings": {
                "next_validation": {
                    "id": "F-1",
                    "url": "https://other.example/api/orders/123",
                    "validation_status": "candidate",
                    "source_file": "findings/target.com/F-1.json",
                }
            }
        },
        repo_root=tmp_path,
        target="target.com",
    ) == {}


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
    assert "--variant \"baseline\"" in skeleton
    assert "--browser-observed" in skeleton
    assert "--state-changing" not in skeleton
    assert "--redline-checked" not in skeleton


@pytest.mark.parametrize(
    "url",
    [
        "https://target.com/urldom/jsonp?callback=foo",
        "https://target.com/reflected/url/css_import?q=a",
        "https://target.com/dom/toxicdom/external/sessionStorage/array/eval",
    ],
)
def test_ranked_dom_surfaces_prefer_xss_over_server_side_or_auth_noise(url):
    entry = {"url": url}
    state = {"surface": {"p1": [entry], "p2": []}, "recommended_targets": [entry]}

    assert _ranked_surface_vuln_hint(entry, url) == "XSS"
    draft = _ranked_surface_replay_draft(state, entry, target="target.com")
    assert "focus XSS evidence" in draft
    assert "parameter-behavior-first" not in draft
    assert "browser-state-first page route" not in draft


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
    assert "--variant \"baseline\"" in skeleton
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
    assert "Ledger skeleton:" not in ranked_text
    assert "ledger_record_skeleton" not in action["metadata"]


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
    assert "Ledger skeleton:" not in ranked_text
    assert "ledger_record_skeleton" not in action["metadata"]


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
    assert "Ledger skeleton:" not in ranked_text
    assert "ledger_record_skeleton" not in action["metadata"]


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
            "closed_cells": [
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

    ranked = next(item for item in proposals if item.startswith("Review surface candidate "))
    assert "Ledger skeleton:" not in ranked
    assert not any(item.startswith("Case-state acquisition lead:") for item in proposals)


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
    assert '--variant "baseline"' in skeleton


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


def test_apply_target_memory_preserves_concurrent_entries_and_handoffs(tmp_path):
    target = "target.com"
    context = multiprocessing.get_context("fork")
    output = context.Queue()
    workers = [
        context.Process(
            target=_apply_target_memory_worker,
            args=(str(tmp_path), target, index, output),
        )
        for index in range(12)
    ]
    for process in workers:
        process.start()
    results = [output.get(timeout=15) for _ in workers]
    for process in workers:
        process.join(timeout=15)

    memory_path = tmp_path / "memory" / "goals" / "targets" / target / "target.com.json"
    if not memory_path.is_file():
        memory_path = tmp_path / "memory" / "goals" / "targets" / "target.com.json"
    payload = json.loads(memory_path.read_text(encoding="utf-8"))

    assert all(process.exitcode == 0 for process in workers)
    assert all(status == "ok" for status, _ in results)
    assert {item["text"] for item in payload["next_actions"]} == {
        f"next-{index}" for index in range(12)
    }
    assert {item["summary"] for item in payload["session_handoffs"]} == {
        f"handoff-{index}" for index in range(12)
    }
    session_paths = [item["path"] for item in payload["session_handoffs"]]
    assert len(session_paths) == len(set(session_paths))
    assert all((tmp_path / path).is_file() for path in session_paths)
