"""Tests for tools/checkpoint.py."""

from __future__ import annotations

import json
import fcntl
import multiprocessing
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

import checkpoint as checkpoint_module
from action_queue import (
    add_manual_action,
    claim_next_action,
    load_queue,
)
from checkpoint import (
    _decision_for_action,
    _matrix_summary,
    _project_knowledge_effect_trace,
    apply_target_memory,
    build_checkpoint,
    begin_round,
    format_checkpoint,
    record_round_closure,
    record_global_review,
    record_round_lane,
    record_round_lane_result,
)
from coverage_matrix import mark_cell, rebuild_matrix
from runtime_state import runtime_phase_lock, update_runtime_state
from target_case_state import add_actor, add_hypothesis, add_object, add_session
from target_store import TargetStore


def test_checkpoint_witness_lock_is_reentrant_and_keeps_outer_lock(tmp_path, monkeypatch):
    original_open = checkpoint_module.open_target_lock_file
    opened = []

    def open_once(*args, **kwargs):
        assert not opened, "nested checkpoint lock must reuse its outer handle"
        handle = original_open(*args, **kwargs)
        opened.append(handle)
        return handle

    monkeypatch.setattr(checkpoint_module, "open_target_lock_file", open_once)
    with checkpoint_module.checkpoint_witness_lock(tmp_path, "target.com"):
        with checkpoint_module.checkpoint_witness_lock(tmp_path, "https://TARGET.com/path"):
            assert len(opened) == 1
        with original_open(tmp_path, "target.com", "checkpoint.lock", create=False) as observer:
            with pytest.raises(BlockingIOError):
                fcntl.flock(observer.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert opened[0].closed
    with original_open(tmp_path, "target.com", "checkpoint.lock", create=False) as observer:
        fcntl.flock(observer.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.fixture
def store(tmp_path):
    result = TargetStore(tmp_path, "target.com")
    result.initialize()
    return result


def _seed_work(repo_root, target="target.com"):
    return add_manual_action(
        repo_root, target=target, action_id="WORK-1", action_type="context-review",
        evidence="Recorded target context", next_question="What is known?", action="Inspect target context",
    )["action"]


def _record_observation(store, *, endpoint, family, result, actor="owner", method="GET", state_changing=False):
    attempt = f"attempt-{store.page('attempts')['total']}"
    path = store.root / "evidence" / store.key / f"{attempt}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Recorded response", encoding="utf-8")
    store.start_attempt(attempt_id=attempt, source="native", started_at="2026-09-24T00:00:00Z", actor="operator")
    return store.record_execution(attempt_id=attempt, outcome="complete", actor="operator", observations=[{
        "endpoint": endpoint, "family": family, "method": method, "actor": actor,
        "object_scope": "own_object", "variant": "baseline", "result": result,
        "description": "Recorded fixture response", "observed_at": "2026-09-24T00:00:00Z",
        "artifacts": {"response": path.relative_to(store.root).as_posix()},
        "state_changing": state_changing, "redline_checked": True,
    }])


def _seed_recon(repo_root: Path, target: str, urls: list[str]) -> None:
    recon_dir = repo_root / "recon" / target
    (recon_dir / "live").mkdir(parents=True, exist_ok=True)
    (recon_dir / "urls").mkdir(parents=True, exist_ok=True)
    (recon_dir / "js").mkdir(parents=True, exist_ok=True)
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


def test_checkpoint_without_recon_is_read_only_and_does_not_choose_work(tmp_path, store):
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    output = format_checkpoint(checkpoint)

    assert checkpoint["decision"] == "continue"
    assert checkpoint["target"] == store.target
    assert checkpoint["next_action_queue"] == []
    assert checkpoint["recommended_executable_action"] == {}
    assert checkpoint["default_candidate"] == {}
    assert checkpoint["target_write_back"]["lead"] == []
    assert checkpoint["target_write_back"]["next"] == []
    assert checkpoint["target_write_back"]["dead_end"] == []
    assert "CHECKPOINT DECISION" in output
    assert "Apply status: read-only Store view" in output
    assert "skill_route" not in checkpoint["context_pack"]
    assert checkpoint["runtime_witness"]["status"] == "not_published"
    assert not (tmp_path / "state" / store.key / "checkpoint_latest.json").exists()
    assert not (tmp_path / "evidence" / store.key / "coverage_matrix.json").exists()
    assert store.binding() == before


def test_primary_checkpoint_projects_store_actions_without_legacy_queue(tmp_path, capsys):
    target = "primary-checkpoint.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(
        command_id="create-work",
        action_id="WORK-1",
        intent="Review the recorded target context",
        execution_key="work:context-review",
        actor="ai",
        kind="work",
        subject={"target": target},
    )
    queue_path = tmp_path / "state" / target / "action_queue.json"
    queue_path.write_text("{not-json", encoding="utf-8")
    before_revision = store.page("actions")["revision"]

    result = checkpoint_module.main([
        "--repo-root", str(tmp_path), "--target", target,
        "--no-refresh-coverage", "--no-apply-target-memory", "--json",
    ])

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert "root_finding_claim_sync" not in output
    assert output["action_queue_sync"]["status"] == "skipped"
    assert output["action_queue_sync"]["reason"].startswith("primary store")
    assert queue_path.read_text(encoding="utf-8") == "{not-json"
    assert store.page("actions")["revision"] == before_revision
    assert output["runtime_witness"]["status"] == "not_published"
    assert [item["id"] for item in output["next_action_queue"]] == ["WORK-1"]
    assert not (tmp_path / "state" / target / "checkpoint_latest.json").exists()


def test_primary_checkpoint_restores_pending_actions_without_generated_routes(tmp_path, monkeypatch):
    import tools.resume as resume_tool

    root = tmp_path / "isolated root"
    target = "checkpoint-actions.test"
    store = TargetStore(root, target)
    store.initialize()
    for index in range(12):
        store.create_action(command_id=f"create-{index:02}", action_id=f"WORK-{index:02}",
                            intent=f"Review context {index}", execution_key=f"context:{index}",
                            actor="operator", kind="work", subject={"target": target},
                            priority=index * 10,
                            metadata={"conditions": "same tenant", "action_context": {
                                "type": "context-review", "command_hint": f"Inspect material {index}",
                            }})

    before = store.binding()
    checkpoint = build_checkpoint(root, target=target, refresh_coverage=False)
    assert [item["id"] for item in checkpoint["next_action_queue"]] == [f"WORK-{i:02}" for i in range(5)]
    assert checkpoint["next_action_queue"][0]["metadata"]["conditions"] == "same tenant"
    assert checkpoint["next_action_queue"][0]["command_hint"] == "Inspect material 0"
    assert checkpoint["default_candidate"] == {}
    assert checkpoint["recommended_executable_action"] == {}
    assert checkpoint["target_write_back"]["next"] == []
    window = checkpoint["action_queue_window"]
    assert (window["total"], window["returned"], window["remaining"]) == (12, 5, 7)
    expanded = subprocess.run(shlex.split(window["expand_command"]), text=True, capture_output=True, check=True)
    assert {item["id"] for item in json.loads(expanded.stdout)} == {f"WORK-{i:02}" for i in range(12)}
    rendered = checkpoint_module.format_checkpoint(checkpoint)
    assert "remaining=7" in rendered
    assert window["expand_command"] in rendered
    followup = resume_tool.load_checkpoint_followup(root, target)
    assert followup["current_action"] == {}
    assert followup["action_queue_window"] == window
    assert store.binding() == before
    assert not (root / "state" / target / "action_queue.json").exists()

    store.transition_action(command_id="claim-last", action_id="WORK-11", expected_version=1,
                            status="claimed", actor="operator")
    store.transition_action(command_id="cancel-first", action_id="WORK-00", expected_version=1,
                            status="cancelled", actor="operator", reason="No longer needed")
    store.transition_action(command_id="block-second", action_id="WORK-01", expected_version=1,
                            status="blocked", actor="operator", reason="Missing comparison context")
    before = store.binding()
    checkpoint = build_checkpoint(root, target=target, refresh_coverage=False)
    assert checkpoint["default_candidate"]["id"] == "WORK-11"
    assert checkpoint["action_queue_window"]["total"] == 11
    assert checkpoint["next_action_queue"][0]["id"] == "WORK-01"
    assert checkpoint["next_action_queue"][0]["status"] == "blocked"
    text = checkpoint_module.format_checkpoint(checkpoint)
    assert "status: blocked" in text and "Missing comparison context" in text
    assert resume_tool.load_checkpoint_followup(root, target)["current_action"]["id"] == "WORK-11"
    assert store.binding() == before


@pytest.mark.parametrize("entry_count", [0, 7])
def test_primary_checkpoint_cli_preserves_goal_and_conditional_memory(tmp_path, entry_count):
    repo = tmp_path / "isolated root"
    target = "target.com"
    store = TargetStore(repo, target)
    store.initialize()
    goal = "Review saved object access evidence"
    store.set_active_goal(
        command_id="goal", goal=goal, actor="operator", expected_revision=store.binding()["revision"],
    )
    operation_id = ""
    if entry_count:
        evidence_ref = f"evidence/{target}/response.txt"
        _write_round_evidence(repo, evidence_ref, "Recorded object response")
        store.start_attempt(
            attempt_id="replay", source="native", started_at="2026-09-24T00:00:00Z", actor="operator",
        )
        store.record_execution(
            attempt_id="replay", outcome="complete", actor="operator",
            observations=[{
                "endpoint": f"https://{target}/object", "method": "GET", "family": "Authz",
                "observed_at": "2026-09-24T00:00:00Z", "description": "Recorded object response",
                "artifacts": {"response": evidence_ref}, "result": "tested_clean", "state_changing": False,
            }],
        )
        operation_id = store.page("operations")["items"][0]["id"]
    for index in range(entry_count):
        store.remember(
            command_id=f"memory-{index}", kind="negative" if index == 6 else "note",
            statement=f"Saved observation {index}", conditions=f"tenant {index}",
            reopen_when=f"peer session {index}", next_intent=f"compare object {index}",
            evidence=[{"operation_id": operation_id, "step": 0}] if index == 6 else [],
            actor="operator",
        )
    legacy_path = repo / "memory" / "goals" / "targets" / f"{target}.json"
    legacy_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_path.write_text("{not-json", encoding="utf-8")
    before = store.binding()
    checkout = Path(__file__).resolve().parents[1]
    command = [
        sys.executable, "-B", str(checkout / "tools" / "checkpoint.py"),
        "--repo-root", str(repo), "--target", target,
    ]
    result = subprocess.run(command + ["--json"], capture_output=True, text=True, check=True)
    checkpoint = json.loads(result.stdout)
    context = checkpoint["context_pack"]
    memory = context["target_experiences"]
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout

    assert context["active_goal"] == goal
    assert goal in output
    assert memory["total"] == entry_count
    assert len(memory["items"]) == min(entry_count, 5)
    assert memory["remaining"] == max(0, entry_count - 5)
    assert f"Showing {min(entry_count, 5)} of {entry_count}" in output
    if entry_count:
        negative = memory["items"][0]
        assert negative["entry_id"] == "memory-6"
        assert negative["kind"] == "negative"
        assert negative["structured"] == {
            "conditions": "tenant 6", "reopen_when": "peer session 6", "next_intent": "compare object 6",
        }
        assert negative["evidence_refs"] == [f"{operation_id}:0"]
        for text in ('conditions="tenant 6"', 'reopen_when="peer session 6"',
                     'next_intent="compare object 6"', f"evidence={operation_id}:0"):
            assert text in output
        for key, extra in (("next_command", []), ("expand_command", ["memory-6"])):
            assert memory[key] in output
            args = shlex.split(memory[key])
            if extra:
                args[-1:] = extra
            page = subprocess.run(args + ["--json"], cwd=checkout, capture_output=True, text=True, check=True)
            assert [item["entry_id"] for item in json.loads(page.stdout)["target_entries"]] == (
                ["memory-6"] if extra else ["memory-1", "memory-0"]
            )
    else:
        assert memory["has_more"] is False
        assert memory["next_command"] == ""
        assert "Next page:" not in output
    assert store.binding() == before
    assert legacy_path.read_text(encoding="utf-8") == "{not-json"
    assert not (repo / "state" / target / "checkpoint_latest.json").exists()
    assert not (repo / "state" / target / "action_queue.json").exists()


def test_record_global_review_persists_checkpoint_witness(tmp_path, monkeypatch, store):
    target = "target.com"
    digest = "c" * 64
    evidence_ref = "evidence/target.com/review/summary.json"
    evidence = tmp_path / evidence_ref
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("review\n", encoding="utf-8")
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(
        json.dumps({
            "schema_version": 1,
            "kind": "autopilot_checkpoint_witness",
            "target": target,
            "round_guard": {"fingerprint": "x"},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {"snapshot_digest": digest},
    )

    result = record_global_review(
        tmp_path,
        target,
        status="complete",
        snapshot_digest=digest,
        evidence_refs=[evidence_ref],
        decision="reconciled all owner views",
    )
    payload = json.loads(witness.read_text(encoding="utf-8"))
    assert result["global_review"]["status"] == "complete"
    assert payload["global_review"]["snapshot_digest"] == digest
    assert payload["round_guard"]["fingerprint"] == "x"


def test_record_global_review_persists_claim_basis(tmp_path, monkeypatch, store):
    """The recorded witness keeps the claim basis next to the digest, so a
    later validation scopes to queue/coverage/closure components instead of
    the whole snapshot."""

    target = "target.com"
    digest = "c" * 64
    evidence_ref = "evidence/target.com/review/summary.json"
    evidence = tmp_path / evidence_ref
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("review\n", encoding="utf-8")
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(
        json.dumps({
            "schema_version": 1,
            "kind": "autopilot_checkpoint_witness",
            "target": target,
            "round_guard": {"fingerprint": "x"},
        }),
        encoding="utf-8",
    )
    components = {
        "queue_fingerprint": "1" * 64,
        "coverage_fingerprint": "2" * 64,
        "closure_state_fingerprint": "3" * 64,
        "ledger_status": "valid",
    }
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {
            "snapshot_digest": digest,
            "snapshot_components": components,
        },
    )

    record_global_review(
        tmp_path,
        target,
        status="complete",
        snapshot_digest=digest,
        evidence_refs=[evidence_ref],
        decision="reconciled all owner views",
    )
    payload = json.loads(witness.read_text(encoding="utf-8"))
    assert payload["global_review"]["snapshot_digest"] == digest
    assert payload["global_review"]["basis"] == {
        "queue_fingerprint": "1" * 64,
        "coverage_fingerprint": "2" * 64,
        "closure_state_fingerprint": "3" * 64,
    }


def test_record_global_review_propagates_stale_recovery_diagnostics(tmp_path, monkeypatch, store):
    target = "target.com"
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(
        json.dumps({"schema_version": 1, "kind": "autopilot_checkpoint_witness", "target": target}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        checkpoint_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: {"target": target, "resolved_target": target},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {"snapshot_digest": "b" * 64},
    )

    with pytest.raises(ValueError) as exc:
        record_global_review(
            tmp_path,
            target,
            status="complete",
            snapshot_digest="a" * 64,
            evidence_refs=[],
            decision="reviewed",
        )

    diagnostics = json.loads(str(exc.value).split(": ", 1)[1])
    assert diagnostics["reason"] == "global_review_stale"
    assert diagnostics["state_changes"][0]["current"] == "b" * 64
    assert "Re-run closure check" in diagnostics["action_required"]


def test_checkpoint_projects_visible_knowledge_effect_stages(tmp_path, store):
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
    checkpoint["knowledge_effect_trace"] = resolved

    output = format_checkpoint(checkpoint)
    assert output.count("Knowledge effect:") == 1
    assert "sqli-hidden-surfaces" in output
    assert "-> AQ-0123" in output
    assert "-> tested_clean" in output


def test_round_guard_blocks_only_after_three_identical_records(monkeypatch, tmp_path, store):
    target = "target.com"
    state_dir = tmp_path / "state" / target
    state_dir.mkdir(parents=True, exist_ok=True)
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


def test_round_lane_budget_resumes_and_dedupes_claims_across_invocations(tmp_path, store):
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
def test_new_passive_round_lane_is_rejected_without_budget_mutation(tmp_path, lane, store):
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


def test_generic_verify_lane_remains_substantive(tmp_path, store):
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=1)

    result = record_round_lane(
        tmp_path, target, lane="verify:candidate-42", max_lanes=1
    )

    assert result["status"] == "claimed"
    assert result["allowed"] is True


def test_legacy_claimed_passive_lane_remains_recoverable(tmp_path, store):
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


def test_round_closure_counts_underlying_post_round_next_action(monkeypatch, tmp_path, store):
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


def test_round_lane_requires_explicit_round_begin(tmp_path, store):
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


def test_round_lane_result_survives_resume_and_terminal_replay_is_idempotent(tmp_path, store):
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


def test_round_lane_result_requires_claim_and_completed_evidence(tmp_path, store):
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


def test_completed_coverage_lane_requires_canonical_owner_evidence(tmp_path, store):
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

    for retired_ref in (f"state/{target}/action_queue.json", f"memory/evidence/{target}/ledger.jsonl"):
        _write_round_evidence(tmp_path, retired_ref, "legacy closure claim")
        with pytest.raises(ValueError, match="canonical Coverage Matrix|target-owned, non-empty evidence_ref"):
            record_round_lane_result(
                tmp_path, target, lane=lane, status="completed", decision="legacy state",
                evidence_ref=retired_ref, next_action="final closure",
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
    rebuild_matrix(target, repo_root=tmp_path)
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
def test_completed_round_lane_rejects_invalid_evidence_without_mutating_lane(tmp_path, case, store):
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


def test_round_lane_result_cli_records_bounded_heartbeat(tmp_path, capsys, store):
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


def test_round_lane_heartbeat_is_atomic_under_concurrent_processes(tmp_path, store):
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


def test_round_lane_heartbeat_survives_repeated_interrupt_cycles(monkeypatch, tmp_path, store):
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


def test_round_closure_completes_budget_and_next_begin_starts_new_round(monkeypatch, tmp_path, store):
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


def test_round_closure_rejects_completed_lane_after_evidence_disappears(monkeypatch, tmp_path, store):
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


def test_new_round_does_not_overwrite_closed_round_with_invalid_evidence(tmp_path, store):
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


def test_round_closure_rejects_unfinished_lane(monkeypatch, tmp_path, store):
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


def test_evidence_before_terminal_heartbeat_remains_an_unfinished_lane(monkeypatch, tmp_path, store):
    target = "target.com"
    evidence_ref = "findings/target.com/poc/sql/summary.json"
    evidence_path = tmp_path / evidence_ref
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
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


def test_checkpoint_witness_atomic_replace_failure_preserves_previous_bytes(tmp_path, monkeypatch, store):
    target = "target.com"
    first = checkpoint_module.write_checkpoint_witness(
        tmp_path,
        target,
        {"context_pack": {"knowledge_cards": []}},
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
            {"context_pack": {"knowledge_cards": []}},
        )

    assert path.read_bytes() == previous
    assert json.loads(path.read_text(encoding="utf-8"))["kind"] == "autopilot_checkpoint_witness"
    assert not list(path.parent.glob(f".{path.name}.*.tmp"))


def test_checkpoint_witness_validates_preserved_round_before_rewrite(tmp_path, store):
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
        {"context_pack": {"knowledge_cards": []}},
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
            {"context_pack": {"knowledge_cards": []}},
        )

    assert path.read_bytes() == previous


def test_round_begin_normalizes_legacy_claimed_lanes_as_unfinished(tmp_path, store):
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


def test_round_begin_rejects_corrupt_checkpoint_witness(tmp_path, store):
    witness = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid checkpoint witness JSON"):
        begin_round(tmp_path, "target.com", max_lanes=2)


def test_round_begin_rejects_inconsistent_persisted_budget(tmp_path, store):
    witness = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
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


@pytest.mark.parametrize("recon", ["absent", "partial", "ready"])
def test_shared_coverage_is_built_once_per_checkpoint_or_pack(tmp_path, monkeypatch, store, recon):
    from tools import coverage_matrix
    from tools.context_pack import build_context_pack

    if recon == "ready":
        _seed_recon(tmp_path, store.target, ["https://api.target.com/users/1"])
    elif recon == "partial":
        (tmp_path / "recon" / store.key).mkdir(parents=True)
    _seed_work(tmp_path, target=store.target)
    store.create_finding(command_id="finding", finding_id="finding", endpoint="https://target.com/item",
                         method="GET", family="custom", title="Claim", claim="Unassessed", actor="operator")
    rebuild = coverage_matrix._rebuild_matrix_unlocked
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[0])
        return rebuild(*args, **kwargs)

    monkeypatch.setattr(coverage_matrix, "_rebuild_matrix_unlocked", counted)
    monkeypatch.setattr(TargetStore, "_finding_projections", lambda *args: pytest.fail("expanded unused Finding history"))
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    assert calls == [store.target]
    calls.clear()
    pack = build_context_pack(tmp_path, target=store.target)
    assert calls == [store.target]
    assert checkpoint["coverage"]["summary"]["total_cells"] >= 0
    assert pack["source_summary"]["findings"] == 1
    assert store.binding() == before
    from tools.resume import load_pickup_summary
    calls.clear()
    pickup = load_pickup_summary(tmp_path / "memory", store.target, repo_root=tmp_path)
    assert pickup["checkpoint"]["available"] is True
    assert calls == [store.target]


@pytest.mark.parametrize("consumer", ["checkpoint", "pack", "surface", "closure"])
def test_shared_coverage_rejects_raw_damage_during_assembly(tmp_path, monkeypatch, store, consumer):
    from tools import autopilot_state, checkpoint as checkpoint_module, context_pack, surface

    _seed_recon(tmp_path, store.target, ["https://api.target.com/users/1"])
    _record_observation(store, endpoint="https://target.com/item", family="Authz", result="tested_clean")
    raw = next((tmp_path / "evidence" / store.key).glob("attempt-*.txt"))
    module = {"checkpoint": checkpoint_module, "pack": context_pack,
              "surface": surface, "closure": autopilot_state}[consumer]
    read_truth = module.current_cell_projection

    def damage(*args, **kwargs):
        raw.write_text("Changed after Coverage acquisition")
        return read_truth(*args, **kwargs)

    monkeypatch.setattr(module, "current_cell_projection", damage)
    with pytest.raises(ValueError, match="coverage evidence changed"):
        if consumer == "closure":
            autopilot_state.load_closure_projection(str(tmp_path), {"target": store.target})
        else:
            build = {"checkpoint": checkpoint_module.build_checkpoint,
                     "pack": context_pack.build_context_pack, "surface": surface.load_surface_context}[consumer]
            build(tmp_path, target=store.target)


def test_checkpoint_owner_read_budget_is_bounded(tmp_path, monkeypatch, store):
    target = "target.com"
    _seed_recon(tmp_path, target, ["https://api.target.com/users/1"])
    _seed_work(tmp_path, target=target)

    counts = {
        "queue": 0,
        "case": 0,
        "validation_candidates": 0,
        "coverage_projection": 0,
        "surface_fallback": 0,
        "coverage_fallback": 0,
    }

    original_queue = checkpoint_module.load_queue_summary

    def count_queue(*args, **kwargs):
        counts["queue"] += 1
        return original_queue(*args, **kwargs)

    monkeypatch.setattr(checkpoint_module, "load_queue_summary", count_queue)

    case_globals = checkpoint_module._build_autopilot_state.__globals__["_load_case_state_projection"].__globals__
    original_case = checkpoint_module.build_case_state_summary

    def count_case(*args, **kwargs):
        counts["case"] += 1
        return original_case(*args, **kwargs)

    monkeypatch.setattr(checkpoint_module, "build_case_state_summary", count_case)
    monkeypatch.setitem(case_globals, "build_case_state_summary", count_case)

    state_globals = checkpoint_module.build_autopilot_state.__globals__
    original_candidates = state_globals["load_validation_runner_candidate_pool"]

    def count_candidates(*args, **kwargs):
        counts["validation_candidates"] += 1
        return original_candidates(*args, **kwargs)

    monkeypatch.setitem(state_globals, "load_validation_runner_candidate_pool", count_candidates)

    original_matrix_projection = checkpoint_module.read_matrix

    def count_matrix_projection(*args, **kwargs):
        counts["coverage_projection"] += 1
        return original_matrix_projection(*args, **kwargs)

    monkeypatch.setattr(checkpoint_module, "read_matrix", count_matrix_projection)

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


def test_checkpoint_owner_snapshots_preserve_state_projection(tmp_path, store):
    target = "target.com"
    _seed_recon(tmp_path, target, ["https://api.target.com/users/1"])
    _seed_work(tmp_path, target=target)
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


@pytest.mark.parametrize("snapshot", ["queue", "case"])
def test_autopilot_state_ignores_caller_supplied_owner_snapshots(tmp_path, store, snapshot):
    add_object(tmp_path, store.target, object_ref="order_123", object_type="order",
               object_id="123", endpoint="https://target.com/orders/123")
    kwargs = ({"queue_snapshot": {"target": "other.test", "actions": [{"id": "FORGED"}]}}
              if snapshot == "queue" else {"case_state_summary": {"target": "other.test", "objects": 999}})
    state = checkpoint_module.build_autopilot_state(str(tmp_path), store.target, **kwargs)
    assert state["case_state"]["objects"] == 1
    assert state["action_queue_next"] == {}
    assert "FORGED" not in json.dumps(state)


@pytest.mark.parametrize("refresh", [False, True])
def test_checkpoint_coverage_is_current_without_publishing_cache(tmp_path, store, refresh):
    _seed_recon(tmp_path, store.target, ["https://target.com/api/users/1"])
    cache = tmp_path / "evidence" / store.key / "coverage_matrix.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("{stale-cache", encoding="utf-8")
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target, refresh_coverage=refresh)
    assert checkpoint["coverage"]["summary"]["endpoints"] == 1
    assert checkpoint["evidence_reviewed"]["coverage_rebuilt"] is False
    assert cache.read_text(encoding="utf-8") == "{stale-cache"
    assert store.binding() == before


def test_checkpoint_ignores_corrupt_legacy_case_state(tmp_path, store):
    path = tmp_path / "state" / store.key / "case_state.json"
    path.write_text("{broken", encoding="utf-8")
    add_object(tmp_path, store.target, object_ref="saved", object_type="order", object_id="1")
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    assert checkpoint["case_state"]["objects"] == 1
    assert path.read_text(encoding="utf-8") == "{broken"


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_checkpoint_cli_fails_fast_on_unavailable_store(tmp_path, store, capsys, damage):
    queue_path = tmp_path / "state" / store.key / "action_queue.json"
    queue_path.write_text('{"actions": [{"id": "LEGACY"}]}', encoding="utf-8")
    if damage == "missing":
        store.path.unlink()
    else:
        store.path.write_bytes(b"corrupt database")
    before = queue_path.read_bytes()
    exit_code = checkpoint_module.main([
        "--repo-root", str(tmp_path), "--target", store.target, "--json",
    ])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "checkpoint state build failed" in captured.err
    assert captured.out == ""
    assert queue_path.read_bytes() == before
    assert not (tmp_path / "state" / store.key / "checkpoint_latest.json").exists()


def test_checkpoint_keeps_pending_claim_without_choosing_validation(tmp_path, store):
    store.create_finding(command_id="F-1", finding_id="F-1", endpoint="https://target.com/api/users",
                         method="GET", family="Authz", title="Unassessed claim",
                         claim="Requires validation", actor="operator")
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    assert checkpoint["structured_findings"]["pending_validation"] == 1
    assert checkpoint["structured_findings"]["next_validation"]["id"] == "F-1"
    assert checkpoint["decision"] == "continue"
    assert checkpoint["next_action_queue"] == []
    assert checkpoint["recommended_executable_action"] == {}
    assert checkpoint["target_write_back"]["next"] == []
    assert store.binding() == before


def test_checkpoint_runtime_wait_marker_preempts_pending_validation(tmp_path, store):
    _seed_recon(tmp_path, "target.com", ["https://target.com/api/orders/1"])
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True, exist_ok=True)
    store.create_finding(command_id='F-wait-scan', finding_id='F-wait-scan', endpoint='https://target.com/api/orders/1', method="GET",
                         family='idor', title="Unassessed claim", claim="Requires validation", actor="operator")
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


def test_checkpoint_orphan_scan_marker_releases_pending_validation(tmp_path, store):
    """进程退出后遗留 marker 不能让 checkpoint 继续返回 wait_scan。"""
    _seed_recon(tmp_path, "target.com", ["https://target.com/api/orders/1"])
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True, exist_ok=True)
    store.create_finding(command_id='F-orphan-scan', finding_id='F-orphan-scan', endpoint='https://target.com/api/orders/1', method="GET",
                         family='idor', title="Unassessed claim", claim="Requires validation", actor="operator")
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com", refresh_coverage=False)

    assert checkpoint["decision"] == "continue"
    assert checkpoint["next_action"] != "wait_scan"
    assert checkpoint["recommended_executable_action"] == {}


def test_checkpoint_runtime_recon_wait_marker_preempts_pending_validation(tmp_path, store):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True, exist_ok=True)
    store.create_finding(command_id='F-wait-recon', finding_id='F-wait-recon', endpoint='https://target.com/api/orders/1', method="GET",
                         family='idor', title="Unassessed claim", claim="Requires validation", actor="operator")
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


def test_checkpoint_displays_runner_candidates_as_advisory_evidence(tmp_path, store):
    _seed_recon(tmp_path, "target.com", ["https://target.com/rest/basket/6"])
    validation_dir = tmp_path / "evidence" / "target.com" / "validation" / "idor-basket"
    validation_dir.mkdir(parents=True, exist_ok=True)
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
    assert checkpoint["next_action_queue"] == []
    assert checkpoint["recommended_executable_action"] == {}
    assert "Validation runner candidates (advisory; require /validate before report):" in output
    assert "idor-basket [idor_actor_pair/tested_finding]" in output
    assert checkpoint["decision"] != "report"


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
        ("high-risk-lane-review", "validate"),
        ("viewstate-integrity-review", "validate"),
        ("report", "report"),
        ("recon_no_live_hosts", "handoff"),
        ("unknown-action", "handoff"),
    ],
)
def test_checkpoint_decision_is_pure_projection_of_effective_action(action, decision):
    assert _decision_for_action(action) == decision


def test_checkpoint_handoff_next_action_does_not_reuse_stale_runtime_state(tmp_path, monkeypatch, store):
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
        lambda *args, **kwargs: {"phase": "recon", "knowledge_cards": [], "active_goal": "", "target_experiences": {}},
    )
    monkeypatch.setattr(
        checkpoint_module,
        "build_evidence_summary",
        lambda *args, **kwargs: {"actor_matrix": {"gap_count": 0, "gaps": []}},
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "continue"
    assert checkpoint["next_action"] == "continue"
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
            # grid enumeration artifact: no observed fact behind this cell
            "endpoint": "/rest/admin/application-configuration",
            "vuln_class": "RCE",
            "weight": 5.0,
            "relevance_score": 0,
            "observed_params": [],
            "source_count": 0,
        },
        {
            # evidence-backed: the search endpoint was observed with a query
            "endpoint": "/api/search",
            "vuln_class": "SQLi",
            "weight": 5.0,
            "relevance_score": 7,
            "observed_params": ["q"],
            "source_count": 1,
        },
    ]

    summary = _matrix_summary(matrix, gaps)

    assert summary["high_value_gaps_count"] == 2
    assert summary["actionable_high_value_gaps_count"] == 1


def test_checkpoint_default_preserves_explicitly_claimed_priority_override(tmp_path, store):
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

    assert claimed["status"] == "claimed"
    assert state["action_queue_next"]["id"] == selected["id"]
    assert checkpoint["default_candidate"]["id"] == selected["id"]
    assert checkpoint["recommended_executable_action"]["id"] == selected["id"]
    assert selected["id"] in [item["id"] for item in checkpoint["next_action_queue"]]


def test_checkpoint_ignores_contradictory_legacy_rubric(tmp_path, store):
    store.create_finding(command_id="F-1", finding_id="F-1", endpoint="https://target.com/orders/1",
                         method="GET", family="Authz", title="Unassessed claim",
                         claim="Requires validation", actor="operator")
    path = tmp_path / "findings" / store.key / "findings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([{"id": "F-1", "status": "confirmed", "evidence_rubric": {"ready": True}}]))
    before = path.read_bytes()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    assert checkpoint["structured_findings"]["pending_validation"] == 1
    assert checkpoint["structured_findings"].get("validated_pending_report", 0) == 0
    assert checkpoint["next_action_queue"] == []
    assert checkpoint["recommended_executable_action"] == {}
    assert path.read_bytes() == before


def test_checkpoint_surfaces_coverage_gaps_without_creating_actions(tmp_path, store):
    _seed_recon(tmp_path, store.target, ["https://api.target.com/api/v1/admin/users?isAdmin=true&userId=1001"])
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    coverage = checkpoint["coverage"]
    assert coverage["summary"]["high_value_gaps_count"] > 0
    assert coverage["window"]["total"] == len(coverage["high_value_gaps"]) + coverage["window"]["remaining"]
    expanded = subprocess.run(shlex.split(coverage["window"]["expand_command"]),
                              capture_output=True, text=True, check=True)
    gaps = json.loads(expanded.stdout)
    assert len(gaps) == coverage["window"]["total"]
    assert ("/api/v1/admin/users", "Authz") in {(item["endpoint"], item["vuln_class"]) for item in gaps}
    assert checkpoint["decision"] == "continue"
    assert checkpoint["target_write_back"]["next"] == []
    assert checkpoint["next_action_queue"] == []
    assert checkpoint["recommended_executable_action"] == {}
    assert store.binding() == before
    assert not (tmp_path / "evidence" / store.key / "coverage_matrix.json").exists()


def test_checkpoint_surfaces_actor_matrix_gaps_without_creating_actions(tmp_path, store):
    endpoint = "https://api.target.com/api/accounts/42/export"
    _seed_recon(tmp_path, store.target, [endpoint + "?account_id=42"])
    _record_observation(store, endpoint=endpoint, family="IDOR", result="tested_clean")
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    output = format_checkpoint(checkpoint)
    assert checkpoint["evidence_ledger"]["entry_count"] == 1
    assert checkpoint["evidence_ledger"]["actor_matrix"]["gap_count"] > 0
    assert checkpoint["target_write_back"]["next"] == []
    assert checkpoint["next_action_queue"] == []
    assert "Evidence ledger:" in output
    assert "actor matrix gaps:" in output


def test_checkpoint_does_not_default_actor_matrix_without_owner_family(tmp_path, store):
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


def test_open_hypothesis_creates_no_case_owned_queue_action(tmp_path, store):
    """Case 只提供上下文：假设写得再细，也不会自己长出一条 checkpoint 行动。"""
    _seed_recon(tmp_path, "target.com", ["https://target.com/render"])
    hypothesis = add_hypothesis(
        tmp_path,
        "target.com",
        vuln_class="SSTI",
        endpoint="https://target.com/render",
        why_now="template syntax changes the response",
        metadata={
            "family": "RCE",
            "primitive": "SSTI",
            "chain": ["template", "sandbox", "execution"],
            "evidence_refs": ["evidence/target.com/render-response.json"],
        },
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert hypothesis["id"] == "hyp_001"
    assert checkpoint["case_state"]["open_hypotheses"] == 1
    assert "next_action" not in checkpoint["case_state"]
    assert "pending_validation_backlog" not in checkpoint["case_state"]
    assert all(
        str(item.get("type") or "") not in {"case-state-validation", "case-state-backlog-create"}
        for item in checkpoint["next_action_queue"]
    )
    assert "pending backlog" not in output
    assert "top next action" not in output


def test_checkpoint_surfaces_open_evidence_candidate_without_creating_actions(tmp_path, store):
    endpoint = "https://target.com/profile/image/url"
    _seed_recon(tmp_path, store.target, [endpoint])
    _record_observation(store, endpoint=endpoint, family="SSRF", result="candidate",
                        method="POST", state_changing=True)
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    output = format_checkpoint(checkpoint)
    assert checkpoint["evidence_ledger"]["open_candidates"][0]["endpoint"] == "/profile/image/url"
    assert checkpoint["target_write_back"]["next"] == []
    assert checkpoint["next_action_queue"] == []
    assert "open candidates: 1" in output
    assert "POST /profile/image/url x SSRF" in output
    assert store.binding() == before


def test_legacy_case_backlog_is_not_a_checkpoint_action_source(tmp_path, store):
    """旧 validation_backlog 带着原裁决留在 Case 文件里，但不进入行动模型。

    §7.1：旧 Case 待办与 Queue 的关联由迁移报告按明确映射搬运并隔离歧义；
    checkpoint 既不能把旧裁决当成活的行动来源，也不能替它排序或计数。
    """
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
    state_path = tmp_path / "state" / "target.com" / "case_state.json"
    payload = {"target": "target.com"}
    payload["validation_backlog"] = [{
        "id": "val_001",
        "runner": "request-diff",
        "vuln_class": "Authz",
        "endpoint": "https://api.target.com/rest/order-history/123",
        "request_spec_ref": "evidence/target.com/validation/order-idor-pair/spec.json",
        "owner_actor": "user_a",
        "peer_actor": "user_b",
        "object_ref": "order_123",
        "priority": "high",
        "status": "tested_clean",
        "result": "tested_clean",
        "created_at": "2026-07-05T01:18:07Z",
    }]
    state_path.write_text(json.dumps(payload), encoding="utf-8")
    before = state_path.read_bytes()

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert checkpoint["case_state"]["objects"] == 1
    assert checkpoint["case_state"]["open_hypotheses"] == 0
    assert "pending_validation_backlog" not in checkpoint["case_state"]
    assert all(
        str(item.get("type") or "") != "case-state-validation"
        for item in checkpoint["next_action_queue"]
    )
    assert all(
        item.get("metadata", {}).get("backlog_id") is None
        for item in checkpoint["next_action_queue"]
    )
    assert "Case-state validation backlog" not in output
    assert "pending backlog" not in output
    # Case 文件本身不动：旧待办只等迁移报告搬运，checkpoint 不替它写回。
    assert state_path.read_bytes() == before


def test_checkpoint_keeps_object_observations_without_automatic_seed_action(tmp_path, store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/rest/order-history/123",
    ])

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["case_state_seed"]["status"] == "suggestions"
    assert checkpoint["case_state_seed"]["suggested_objects"][0]["object_ref"] == "order_123"
    assert all(item["type"] != "case-state-seed" for item in checkpoint["next_action_queue"])
    assert "suggested_backlog" not in checkpoint["case_state_seed"]
    assert all(
        item.get("metadata", {}).get("object_ref") != "order_123"
        for item in checkpoint["next_action_queue"]
    )


def test_checkpoint_keeps_historical_object_shape_without_automatic_seed_action(tmp_path, store):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True, exist_ok=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text("https://target.com\n")
    historical = "https://target.com/?option=com_demo&Itemid=0\n"
    (recon_dir / "urls" / "with_params.txt").write_text(historical)
    (recon_dir / "urls" / "all.txt").write_text(historical)

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["case_state_seed"]["suggested_objects"][0]["object_ref"] == "item_0"
    assert "confidence" not in checkpoint["case_state_seed"]["suggested_objects"][0]
    assert all(item["type"] != "case-state-seed" for item in checkpoint["next_action_queue"])


def test_checkpoint_keeps_endpointless_object_without_inventing_a_backlog(tmp_path, store):
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
    browser_dir.mkdir(parents=True, exist_ok=True)
    (browser_dir / "object_probe.json").write_text(
        json.dumps({"addressId": 7}),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    assert checkpoint["case_state_seed"]["status"] == "suggestions"
    obj = checkpoint["case_state_seed"]["suggested_objects"][0]
    assert obj["object_ref"] == "address_7" and obj["endpoint"] == ""
    assert "private_marker" not in obj
    assert all(
        item.get("metadata", {}).get("object_ref") != "address_7"
        for item in checkpoint["next_action_queue"]
    )


def test_context_pack_hypothesis_and_catalog_do_not_materialize_queue(tmp_path, store):
    store.remember(command_id="hypothesis", kind="hypothesis", statement="Inspect template rendering",
                   conditions="known input", reopen_when="", next_intent="", evidence=[], actor="operator")
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    context = checkpoint["context_pack"]
    assert context["target_experiences"]["items"][0]["entry_id"] == "hypothesis"
    assert any(item["id"] == "server-side-template-injection" for item in context["card_catalog"])
    assert context["hypothesis_seeds"] == []
    assert checkpoint["next_action_queue"] == []
    assert load_queue(tmp_path, store.target)["actions"] == []
    assert not (tmp_path / "state" / store.key / "checkpoint_latest.json").exists()
    assert store.binding() == before


def test_checkpoint_preserves_conditional_learning_without_deciding_reopen(tmp_path, store):
    endpoint = "https://target.com/graphql"
    _seed_recon(tmp_path, store.target, [endpoint])
    receipt = _record_observation(store, endpoint=endpoint, family="Authz", result="tested_clean")
    store.remember(command_id="negative", kind="negative", statement="Introspection unavailable",
                   conditions="anonymous session", reopen_when="new role or operation names",
                   next_intent="", evidence=[{"operation_id": receipt["entity_id"], "step": 0}], actor="operator")
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    output = format_checkpoint(checkpoint)
    assert 'conditions="anonymous session"' in output
    assert 'reopen_when="new role or operation names"' in output
    assert checkpoint["target_write_back"]["next"] == []
    assert checkpoint["next_action_queue"] == []
    assert store.binding() == before


def test_apply_target_memory_flag_is_an_inactive_compatibility_option():
    parser = checkpoint_module.build_parser()
    assert parser.parse_args(["--target", "target.com"]).apply_target_memory is False
    assert parser.parse_args(["--target", "target.com", "--no-apply-target-memory"]).apply_target_memory is False
    assert parser.parse_args(["--target", "target.com", "--apply-target-memory"]).apply_target_memory is True
    assert "never writes memory" in parser.format_help()


@pytest.mark.parametrize("flags", [[], ["--apply-target-memory"], ["--no-apply-target-memory"]])
def test_checkpoint_cli_never_writes_target_memory(tmp_path, store, capsys, flags):
    store.remember(command_id="note", kind="note", statement="Saved operator note",
                   conditions="operator note; applicability unknown", reopen_when="", next_intent="", evidence=[], actor="operator")
    before = store.binding()
    exit_code = checkpoint_module.main([
        "--repo-root", str(tmp_path), "--target", store.target, "--json", *flags,
    ])
    assert exit_code == 0
    checkpoint = json.loads(capsys.readouterr().out)
    assert checkpoint["apply_status"].startswith("read-only Store view")
    if flags == ["--apply-target-memory"]:
        assert checkpoint["apply_result"]["status"] == "skipped"
    assert store.binding() == before
    assert not (tmp_path / "memory" / "goals" / "targets" / f"{store.key}.json").exists()
    assert not (tmp_path / "state" / store.key / "checkpoint_latest.json").exists()


# ---------------------------------------------------------------------------
# B3: browser lane finish auto-imports its focused MCP capture manifest.
# ---------------------------------------------------------------------------


def _write_browser_manifest(repo_root: Path, evidence_ref: str, url: str = "https://target.com/app") -> Path:
    path = repo_root / evidence_ref
    path.parent.mkdir(parents=True, exist_ok=True)
    network = path.parent / "network.json"
    network.write_text(json.dumps([{"url": url, "method": "GET", "resourceType": "xhr"}]), encoding="utf-8")
    path.write_text(
        json.dumps({"target": "target.com", "captures": [{"url": url, "network": str(network)}]}),
        encoding="utf-8",
    )
    return path


def test_browser_lane_completion_auto_imports_focused_manifest(tmp_path, store):
    """B3: browser lane 完成且 evidence_ref 是 manifest 时自动落 browser evidence。"""
    target = "target.com"
    lane = "browser:target.com-session-1"
    manifest_ref = "evidence/target.com/browser/pending-import-manifest.json"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    _write_browser_manifest(tmp_path, manifest_ref)

    result = record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="browser session captured",
        evidence_ref=manifest_ref,
        next_action="review imported surface delta",
    )

    lane_record = result["lane"]
    assert result["status"] == "recorded"
    assert lane_record["browser_import"]["status"] == "ok"
    assert lane_record["browser_import"]["counts"]["successful"] == 1
    assert store.page("actions")["total"] == 0
    # The importer wrote the durable browser surface + capture summary.
    assert (tmp_path / "recon" / "target.com" / "browser" / "xhr_endpoints.txt").is_file()
    assert (tmp_path / "recon" / "target.com" / "browser" / "context_discovery.json").is_file()
    assert (tmp_path / "recon" / "target.com" / "browser" / "context_discovery").is_dir()


def test_browser_lane_manifest_import_failure_does_not_block_heartbeat(tmp_path, monkeypatch, store):
    """B3: 导入失败只记 warning（browser_import.status=failed），不 raise。"""
    from tools import browser_mcp_import

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(browser_mcp_import, "import_focused_mcp_manifest", boom)

    target = "target.com"
    lane = "browser:target.com-session-2"
    manifest_ref = "evidence/target.com/browser/pending-import-manifest.json"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    _write_browser_manifest(tmp_path, manifest_ref)

    result = record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="browser session captured",
        evidence_ref=manifest_ref,
        next_action="retry import next invocation",
    )

    lane_record = result["lane"]
    assert result["status"] == "recorded"
    assert lane_record["status"] == "completed"
    assert lane_record["browser_import"]["status"] == "failed"
    assert "OSError" in lane_record["browser_import"]["reason"]


def test_browser_lane_replay_does_not_reimport_manifest(tmp_path, store):
    """B3: `already_recorded` 幂等重放不重复导入（不新建 capture 目录）。"""
    target = "target.com"
    lane = "browser:target.com-session-3"
    manifest_ref = "evidence/target.com/browser/pending-import-manifest.json"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    _write_browser_manifest(tmp_path, manifest_ref)

    first = record_round_lane_result(
        tmp_path, target, lane=lane, status="completed",
        decision="browser session captured",
        evidence_ref=manifest_ref, next_action="review",
    )
    replay = record_round_lane_result(
        tmp_path, target, lane=lane, status="completed",
        decision="browser session captured",
        evidence_ref=manifest_ref, next_action="review",
    )
    captures = list((tmp_path / "evidence" / "target.com" / "browser").glob("*/summary.json"))

    assert first["status"] == "recorded"
    assert replay["status"] == "already_recorded"
    # Exactly one capture directory was created by the fresh terminal transition.
    assert len(captures) == 1


def test_non_browser_lane_and_non_manifest_evidence_do_not_trigger_import(tmp_path, store):
    """B3: 非 browser lane 或非 manifest evidence 不触发导入（最小侵入面）。"""
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=2)
    record_round_lane(tmp_path, target, lane="sqli:/api/search", max_lanes=2)
    record_round_lane(tmp_path, target, lane="browser:target.com-session-4", max_lanes=2)
    plain_ref = "findings/target.com/poc/sql.json"
    _write_round_evidence(tmp_path, plain_ref)

    # Non-browser lane: completed evidence is a plain artifact, not a manifest.
    sqli = record_round_lane_result(
        tmp_path, target, lane="sqli:/api/search", status="completed",
        decision="tested clean", evidence_ref=plain_ref, next_action="none",
    )
    assert "browser_import" not in sqli["lane"]

    # Browser lane with non-manifest evidence: no captures list -> no import.
    browser = record_round_lane_result(
        tmp_path, target, lane="browser:target.com-session-4", status="completed",
        decision="browser evidence reviewed", evidence_ref=plain_ref, next_action="none",
    )
    assert "browser_import" not in browser["lane"]
    assert not (tmp_path / "recon" / "target.com" / "browser").exists()


def test_importer_output_reused_as_lane_evidence_does_not_reimport(tmp_path, store):
    """B3: importer 自身产物（context_discovery.json）带 captures 列表，但不能作为
    manifest 触发再导入——否则重复 capture 目录和多余 context snapshot 会被创建。
    只有 evidence/<target_key>/browser/ 下的 pending-import manifest 形态 opt-in。
    """
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane="browser:target.com-session-5", max_lanes=1)
    importer_output_ref = "recon/target.com/browser/context_discovery.json"
    importer_output = tmp_path / importer_output_ref
    importer_output.parent.mkdir(parents=True, exist_ok=True)
    importer_output.write_text(
        json.dumps({
            "target": target,
            "captures": [
                {
                    "url": "https://target.com/app",
                    "status": "ok",
                    "new_surface": {},
                    "actionable": False,
                }
            ],
        }),
        encoding="utf-8",
    )

    result = record_round_lane_result(
        tmp_path, target, lane="browser:target.com-session-5", status="completed",
        decision="reviewed importer context delta",
        evidence_ref=importer_output_ref, next_action="none",
    )

    assert result["status"] == "recorded"
    assert "browser_import" not in result["lane"]
    # No capture directory, no extra context snapshot was created.
    assert not (tmp_path / "evidence" / "target.com" / "browser").exists()
    assert not (tmp_path / "recon" / "target.com" / "browser" / "context_discovery").exists()


def test_target_memory_text_returns_empty_for_polluted():
    """读取端回归：污染文本返回空，干净文本原样保留。"""
    from surface import _target_memory_text

    assert _target_memory_text({"text": "{'schema_version': 1, 'text': 'x'}"}) == ""
    assert _target_memory_text({"text": '{"schema_version": 1, "text": "x"}'}) == ""
    assert _target_memory_text({"text": "clean lead"}) == "clean lead"
    assert _target_memory_text({"text": ""}) == ""


def test_checkpoint_roundtrip_does_not_feed_its_projection_back_to_memory(tmp_path, store):
    store.remember(command_id="lead", kind="note", statement="human lead",
                   conditions="operator note; applicability unknown", reopen_when="", next_intent="", evidence=[], actor="operator")
    _seed_work(tmp_path)
    before = store.binding()
    for _ in range(3):
        checkpoint = build_checkpoint(tmp_path, target=store.target)
        result = apply_target_memory(tmp_path, store.target, checkpoint)
        assert result["status"] == "skipped"
        assert [item["id"] for item in checkpoint["next_action_queue"]] == ["WORK-1"]
        memory = checkpoint["context_pack"]["target_experiences"]
        assert memory["total"] == 1
        assert memory["items"][0]["text"] == "human lead"
        assert store.binding() == before


def test_checkpoint_keeps_discovery_material_visible_without_registering_work(tmp_path, store):
    from tools.surface import build_surface_review

    _seed_recon(tmp_path, store.target, ["https://api.target.com/profile"])
    findings = tmp_path / "findings" / store.key
    manual = findings / "manual_review"
    manual.mkdir(parents=True)
    (manual / "unsafe_skipped.txt").write_text(
        "2026-09-24T00:00:00Z\tmethod=PUT\tlabel=method probe\turl=https://api.target.com/profile\treason=requires opt-in\n")
    (manual / "open_200_api.txt").write_text("[OPEN-200-REVIEW] 200 1200 https://api.target.com/profile\n")
    (findings / "manual-claim.json").write_text(json.dumps({
        "title": "Manual claim", "endpoint": "/profile", "vuln_class": "Authz",
        "severity": "medium", "poc": "Recorded claim; requires independent proof", "impact": "unknown",
    }))
    exposure = findings / "exposure"
    exposure.mkdir()
    (exposure / "repo_source_meta.json").write_text('{"status":"ok","source_kind":"local_path"}')
    build_surface_review(tmp_path, store.target)
    before = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    sources = checkpoint["material_sources"]["sources"]
    assert sources["root_claims"]["total"] == 1
    assert sources["root_claims"]["items"][0]["source_file"].endswith("manual-claim.json")
    categories = {item["category"] for item in sources["workflow_leads"]["items"]}
    assert {"open-200-api-review", "action-gated"} <= categories
    assert sources["repo_source"]["items"] == ["findings/target.com/exposure/repo_source_meta.json"]
    text = format_checkpoint(checkpoint)
    assert "manual-claim.json" in text
    assert "open-200-api-review" in text
    assert "repo_source_meta.json" in text
    expanded = subprocess.run(shlex.split(checkpoint["material_sources"]["expand_command"]),
                              capture_output=True, text=True, check=True)
    assert len(json.loads(expanded.stdout)["root_finding_claims"]) == 1
    assert checkpoint["next_action_queue"] == []
    assert store.page("findings")["total"] == 0
    assert store.binding() == before


@pytest.mark.parametrize("projection_status", ["missing", "stale", "valid"])
def test_checkpoint_distinguishes_unavailable_workflow_material_from_empty(tmp_path, store, projection_status):
    from tools.surface import build_surface_review

    _seed_recon(tmp_path, store.target, ["https://target.com/object"])
    if projection_status != "missing":
        build_surface_review(tmp_path, store.target)
    if projection_status == "stale":
        changed = tmp_path / "findings" / store.key / "manual_review" / "open_200_api.txt"
        changed.parent.mkdir(parents=True, exist_ok=True)
        changed.write_text("[OPEN-200-REVIEW] 200 1200 https://target.com/object\n")
    binding = store.binding()
    checkpoint = build_checkpoint(tmp_path, target=store.target)
    window = checkpoint["material_sources"]["sources"]["workflow_leads"]
    assert window["status"] == projection_status
    assert checkpoint["evidence_reviewed"]["surface"] is (projection_status == "valid")
    assert window["items"] == []
    assert window["total"] == (0 if projection_status == "valid" else None)
    assert window["remaining"] == (0 if projection_status == "valid" else None)
    if projection_status != "valid":
        assert window["reason"]
        assert "workflow_leads: " + projection_status in format_checkpoint(checkpoint)
        assert window["refresh_command"] in format_checkpoint(checkpoint)
    assert store.binding() == binding


def test_checkpoint_rechecks_raw_bytes_between_calls_without_revision_change(tmp_path, store):
    _seed_recon(tmp_path, store.target, ["https://target.com/object"])
    receipt = _record_observation(store, endpoint="https://target.com/object", family="Authz", result="tested_clean")
    before = store.binding()
    first = build_checkpoint(tmp_path, target=store.target)
    assert first["coverage"]["summary"]["tested_clean"] > 0
    observation = store.execution(receipt["entity_id"])["observations"][0]
    (tmp_path / observation["artifacts"][0]["ref"]).write_text("changed response")
    second = build_checkpoint(tmp_path, target=store.target)
    assert second["coverage"]["summary"]["tested_clean"] == 0
    assert store.binding() == before
