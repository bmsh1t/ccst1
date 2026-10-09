"""Focused tests for deterministic round orchestration."""

from __future__ import annotations

import json
import multiprocessing
import time
from copy import deepcopy

import pytest

import tools.autopilot_round as autopilot_round_module
import tools.surface as surface_module
from tools.action_queue import load_queue
from tools.autopilot_round import prepare_round, settle_round
from tools.checkpoint import (
    begin_round,
    record_round_lane,
    record_round_lane_result,
)
from tools.coverage_matrix import CoverageEvidenceChangedError
from tools.surface_projection import load_surface_projection
from tools.target_store import StoreError, TargetStore


def _witness(tmp_path, target: str = "target.com"):
    return tmp_path / "state" / target / "checkpoint_latest.json"


def _write_evidence(tmp_path, target: str = "target.com") -> str:
    evidence_ref = f"findings/{target}/poc/round/summary.json"
    path = tmp_path / evidence_ref
    path.parent.mkdir(parents=True)
    path.write_text('{"result":"tested_clean"}\n', encoding="utf-8")
    return evidence_ref


def _seed_stale_surface(tmp_path, target: str = "target.com") -> None:
    recon_dir = tmp_path / "recon" / target
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text(
        f"https://api.{target} [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )
    urls = recon_dir / "urls" / "with_params.txt"
    urls.write_text(f"https://api.{target}/orders?id=1\n", encoding="utf-8")
    surface_module.build_surface_review(tmp_path, target, refresh=True)
    with urls.open("a", encoding="utf-8") as handle:
        handle.write(f"https://api.{target}/orders?id=2\n")
    assert load_surface_projection(tmp_path, target)["status"] == "stale"


def _claim_lane_after_signal(repo_root, target, start, attempting, output):
    start.wait()
    attempting.set()
    try:
        result = record_round_lane(repo_root, target, lane="late:claim", max_lanes=1)
        output.put(("ok", result["status"]))
    except Exception as exc:
        output.put(("error", str(exc)))


def test_closure_snapshot_reads_current_state_and_closure(monkeypatch, tmp_path):
    TargetStore(tmp_path, "target.com").initialize()
    calls = []
    state = {"target": "target.com", "resolved_target": "target.com"}

    def current_state(*args, **kwargs):
        assert kwargs == {"bounded": True}
        calls.append("state")
        return state

    def current_closure(repo, actual, **kwargs):
        assert actual is state
        assert kwargs == {"max_lanes_reached": False}
        calls.append("closure")
        return {"snapshot_digest": "stable"}

    monkeypatch.setattr(autopilot_round_module, "build_autopilot_state", current_state)
    monkeypatch.setattr(autopilot_round_module, "load_closure_projection", current_closure)
    assert autopilot_round_module._closure_snapshot(tmp_path, "target.com") == (
        state, {"snapshot_digest": "stable"},
    )
    assert calls == ["state", "closure"]


def test_closure_snapshot_retries_one_stale_owner_read(monkeypatch, tmp_path):
    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    reads = []

    def current_state(*args, **kwargs):
        reads.append(store.binding()["revision"])
        if len(reads) == 1:
            store.set_active_goal(command_id="concurrent-goal", goal="Changed during read", actor="test")
        return {"target": "target.com", "resolved_target": "target.com"}

    monkeypatch.setattr(autopilot_round_module, "build_autopilot_state", current_state)
    monkeypatch.setattr(autopilot_round_module, "load_closure_projection",
                        lambda *args, **kwargs: {"snapshot_digest": "stable"})
    _, closure = autopilot_round_module._closure_snapshot(tmp_path, "target.com")
    assert reads == [0, 1]
    assert closure == {"snapshot_digest": "stable"}


@pytest.mark.parametrize("error_type,failures,attempts", [
    (CoverageEvidenceChangedError, 1, 2),
    (CoverageEvidenceChangedError, 2, 2),
    (StoreError, 1, 1),
    (OSError, 1, 1),
], ids=["transient", "persistent", "store-error", "io-error"])
def test_closure_snapshot_retries_only_evidence_changes(
    tmp_path, monkeypatch, error_type, failures, attempts,
):
    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    binding = store.binding()
    calls = []
    failure = error_type("closure read failed")
    build_state = autopilot_round_module.build_autopilot_state
    read_closure = autopilot_round_module.load_closure_projection

    def current_state(*args, **kwargs):
        calls.append("state")
        return build_state(*args, **kwargs)

    def current_closure(*args, **kwargs):
        calls.append("closure")
        if calls.count("closure") <= failures:
            raise failure
        return read_closure(*args, **kwargs)

    monkeypatch.setattr(autopilot_round_module, "build_autopilot_state", current_state)
    monkeypatch.setattr(autopilot_round_module, "load_closure_projection", current_closure)
    if failures < attempts:
        state, closure = autopilot_round_module._closure_snapshot(tmp_path, store.target)
        assert state["target"] == store.target
        assert closure["snapshot_digest"]
        assert not closure.get("snapshot_stale")
    else:
        with pytest.raises(error_type) as caught:
            autopilot_round_module._closure_snapshot(tmp_path, store.target)
        assert caught.value is failure
    assert calls == ["state", "closure"] * attempts
    assert store.binding() == binding


def test_prepare_round_is_idempotent_and_preserves_checkpoint_budget(tmp_path):
    TargetStore(tmp_path, "target.com").initialize()
    first = prepare_round(tmp_path, "target.com", 2)
    second = prepare_round(tmp_path, "target.com", 8)

    assert first["status"] == "started"
    assert second["status"] == "resumed"
    assert second["round_progress"]["round_id"] == first["round_progress"]["round_id"]
    assert second["round_progress"]["max_lanes"] == 2


@pytest.mark.parametrize("reason", [
    "global_review_required",
    "global_review_stale",
    "global_review_invalid",
    "global_review_form_insufficient",
])
def test_prepare_does_not_start_new_round_before_global_review(monkeypatch, tmp_path, reason):
    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    begin_round(tmp_path, "target.com", max_lanes=2)
    closed = autopilot_round_module.record_round_closure(tmp_path, "target.com")
    witness = _witness(tmp_path)
    before = witness.read_bytes()
    binding = store.binding()
    progress = closed["round_progress"]
    closure = {
        "verdict": "handoff",
        "can_claim_exhausted": False,
        "reasons": [reason],
        "next_action": "global-review",
        "round_progress": progress,
        "global_review": {
            "status": "form_insufficient",
            "review_status": "complete",
            "missing_tokens": ["scanner:idor_candidates:remaining=12"],
        },
    }
    expected_closure = deepcopy(closure)
    calls = []
    monkeypatch.setattr(
        autopilot_round_module,
        "_closure_snapshot",
        lambda *_args: ({"resolved_target": "target.com"}, closure),
    )
    monkeypatch.setattr(
        autopilot_round_module,
        "begin_round",
        lambda *_args, **_kwargs: calls.append(True),
    )

    result = autopilot_round_module.prepare_round(tmp_path, "target.com", 8)

    assert result["status"] == "review_required"
    assert result["closure"] == expected_closure
    assert result["round_progress"] == expected_closure["round_progress"]
    assert calls == []
    assert witness.read_bytes() == before
    assert store.binding() == binding


@pytest.mark.parametrize("completed", [False, True], ids=["active", "completed-replay"])
@pytest.mark.parametrize("reason", [
    "global_review_required",
    "global_review_stale",
    "global_review_invalid",
    "global_review_form_insufficient",
])
def test_settle_preserves_global_review_and_owner_boundaries(monkeypatch, tmp_path, completed, reason):
    target = "target.com"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(
        command_id="create-work", action_id="WORK-1", intent="Review context",
        execution_key="context-review", actor="ai", kind="work", subject={"target": target},
    )
    started = begin_round(tmp_path, target, max_lanes=2)
    lane = "sqli:/api/orders"
    record_round_lane(tmp_path, target, lane=lane, max_lanes=2)
    record_round_lane_result(
        tmp_path, target, lane=lane, status="completed", decision="tested clean",
        evidence_ref=_write_evidence(tmp_path, target), next_action="none",
    )
    if completed:
        autopilot_round_module.record_round_closure(tmp_path, target)
    witness = _witness(tmp_path, target)
    before = witness.read_bytes()
    binding = store.binding()
    action = store.action("WORK-1")
    calls = []
    projected = []
    read_snapshot = autopilot_round_module._closure_snapshot
    checkpoint = autopilot_round_module.build_checkpoint
    close_round = autopilot_round_module.record_round_closure

    def current_snapshot(*args, **kwargs):
        calls.append("snapshot")
        state, closure = read_snapshot(*args, **kwargs)
        if closure["round_progress"]["status"] == "completed":
            closure.update({
                "verdict": "handoff",
                "can_claim_exhausted": False,
                "reasons": [reason],
                "next_action": "global-review",
                "global_review": {
                    "status": "form_insufficient",
                    "review_status": "complete",
                    "missing_tokens": ["scanner:idor_candidates:remaining=12"],
                },
            })
        projected.append(deepcopy(closure))
        return state, closure

    def current_checkpoint(*args, **kwargs):
        assert not completed, "completed replay must not construct a checkpoint"
        calls.append("checkpoint")
        return checkpoint(*args, **kwargs)

    def current_close(*args, **kwargs):
        assert not completed, "completed replay must not write round closure"
        calls.append("close")
        return close_round(*args, **kwargs)

    def reject_begin(*args, **kwargs):
        pytest.fail("settle must not begin a new round")

    monkeypatch.setattr(autopilot_round_module, "_closure_snapshot", current_snapshot)
    monkeypatch.setattr(autopilot_round_module, "build_checkpoint", current_checkpoint)
    monkeypatch.setattr(autopilot_round_module, "record_round_closure", current_close)
    monkeypatch.setattr(autopilot_round_module, "begin_round", reject_begin)

    result = settle_round(tmp_path, target, refresh_coverage=False)

    assert result["status"] == "review_required"
    assert result["closure"] == projected[-1]
    assert result["closure"]["reasons"] == [reason]
    assert result["closure"]["verdict"] == "handoff"
    assert result["closure"]["can_claim_exhausted"] is False
    assert result["closure"]["global_review"]["missing_tokens"] == [
        "scanner:idor_candidates:remaining=12",
    ]
    assert result["closure"]["global_review"]["review_status"] == "complete"
    assert result["round_progress"]["status"] == "completed"
    assert result["round_progress"]["round_id"] == started["round_progress"]["round_id"]
    assert result["round_progress"]["max_lanes"] == 2
    assert store.binding() == binding
    assert store.action("WORK-1") == action
    if completed:
        assert calls == ["snapshot"]
        assert witness.read_bytes() == before
        assert "checkpoint" not in result
    else:
        assert calls == ["snapshot", "checkpoint", "snapshot", "close", "snapshot"]
        assert projected[0]["round_progress"]["status"] == "active"
        assert witness.read_bytes() != before
        assert "global_review" not in json.loads(witness.read_text())


@pytest.mark.parametrize("reasons", [
    [],
    ["owner_work_pending", "global_review_form_insufficient"],
    ["global_review_form_insufficient_extra"],
])
def test_round_review_routing_uses_only_exact_first_reason(monkeypatch, tmp_path, reasons):
    TargetStore(tmp_path, "target.com").initialize()
    read_snapshot = autopilot_round_module._closure_snapshot

    def current_snapshot(*args, **kwargs):
        state, closure = read_snapshot(*args, **kwargs)
        closure.update({"verdict": "handoff", "reasons": reasons})
        return state, closure

    monkeypatch.setattr(autopilot_round_module, "_closure_snapshot", current_snapshot)
    assert prepare_round(tmp_path, "target.com", 2)["status"] == "started"
    assert prepare_round(tmp_path, "target.com", 8)["status"] == "resumed"
    assert settle_round(tmp_path, "target.com", refresh_coverage=False)["status"] == "settled"
    assert settle_round(tmp_path, "target.com", refresh_coverage=False)["status"] == "already_settled"


def test_settle_round_refuses_started_lane_without_writing(tmp_path):
    target = "target.com"
    TargetStore(tmp_path, target).initialize()
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane="coverage:/api/orders", max_lanes=1)
    witness = _witness(tmp_path, target)
    before = witness.read_bytes()

    with pytest.raises(ValueError, match="unfinished lanes: coverage:/api/orders"):
        settle_round(tmp_path, target, refresh_coverage=False)

    assert witness.read_bytes() == before


def test_settle_round_closes_terminal_lane_and_replays_idempotently(tmp_path):
    target = "target.com"
    TargetStore(tmp_path, target).initialize()
    begin_round(tmp_path, target, max_lanes=1)
    lane = "sqli:/api/orders"
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    evidence_ref = _write_evidence(tmp_path, target)
    record_round_lane_result(
        tmp_path,
        target,
        lane=lane,
        status="completed",
        decision="tested clean",
        evidence_ref=evidence_ref,
        next_action="none",
    )

    settled = settle_round(tmp_path, target, refresh_coverage=False)
    witness = _witness(tmp_path, target)
    after = witness.read_bytes()
    replay = settle_round(tmp_path, target, refresh_coverage=False)

    assert settled["status"] == "settled"
    assert settled["round_progress"]["status"] == "completed"
    assert replay["status"] == "already_settled"
    assert replay["round_progress"]["round_id"] == settled["round_progress"]["round_id"]
    assert witness.read_bytes() == after


@pytest.mark.parametrize("invalid_evidence", [False, True])
def test_primary_settle_only_closes_runtime_round(monkeypatch, tmp_path, invalid_evidence):
    target = "target.com"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(
        command_id="create-work", action_id="WORK-1", intent="Review context",
        execution_key="context-review", actor="ai", kind="work", subject={"target": target},
    )
    begin_round(tmp_path, target, max_lanes=1)
    lane = "sqli:/api/orders"
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    evidence_ref = _write_evidence(tmp_path, target)
    record_round_lane_result(
        tmp_path, target, lane=lane, status="completed", decision="tested clean",
        evidence_ref=evidence_ref, next_action="none",
    )
    if invalid_evidence:
        (tmp_path / evidence_ref).write_text("", encoding="utf-8")
    queue_path = tmp_path / "state" / target / "action_queue.json"
    queue_path.write_text("{legacy-unreadable", encoding="utf-8")

    def reject_legacy(*_args, **_kwargs):
        pytest.fail("primary settlement called a legacy coordinator or implicit refresh")

    monkeypatch.setattr(surface_module, "build_surface_review", reject_legacy)

    def snapshot():
        return {
            str(path.relative_to(tmp_path)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in tmp_path.rglob("*")
            if path.is_file() and "locks" not in path.parts
            and path.name not in {"metadata.sqlite3-wal", "metadata.sqlite3-shm"}
        }

    before = snapshot()
    revision = store.page("actions")["revision"]
    action_before = store.action("WORK-1")
    if invalid_evidence:
        with pytest.raises(ValueError, match="invalid completed lane evidence"):
            settle_round(tmp_path, target)
        assert snapshot() == before
        return

    settled = settle_round(tmp_path, target)
    assert settled["status"] == "settled"
    assert settled["round_progress"]["status"] == "completed"
    assert settled["checkpoint"]["action_queue_sync"]["status"] == "skipped"
    assert settled["checkpoint"]["runtime_witness"]["status"] == "not_published"
    after = snapshot()
    witness_ref = str(_witness(tmp_path, target).relative_to(tmp_path))
    assert {key: value for key, value in after.items() if key != witness_ref} == {
        key: value for key, value in before.items() if key != witness_ref
    }
    replay = settle_round(tmp_path, target)
    assert replay["status"] == "already_settled"
    assert replay["round_progress"]["round_id"] == settled["round_progress"]["round_id"]
    assert store.page("actions")["revision"] == revision
    assert store.action("WORK-1") == action_before
    assert snapshot() == after


@pytest.mark.parametrize("backend", ["preview", "missing-primary", "corrupt-primary"])
def test_settle_rejects_unavailable_backend_before_legacy_writes(monkeypatch, tmp_path, backend):
    target = "target.com"
    store = TargetStore(tmp_path, target)
    store.initialize(allow_legacy=backend == "preview")
    begin_round(tmp_path, target, max_lanes=1)
    witness = _witness(tmp_path, target)
    before = witness.read_bytes()
    if backend == "missing-primary":
        store.path.unlink()
    elif backend == "corrupt-primary":
        store.path.write_bytes(b"not sqlite")

    with pytest.raises(ValueError, match="not active|missing|target store failure"):
        settle_round(tmp_path, target)
    assert witness.read_bytes() == before
    assert not (tmp_path / "state" / target / "action_queue.json").exists()


@pytest.mark.parametrize("failure_point", ["checkpoint", "snapshot", "before-closure", "after-closure"])
def test_settle_round_replays_each_durable_boundary(monkeypatch, tmp_path, failure_point):
    target = "target.com"
    store = TargetStore(tmp_path, target)
    store.initialize()
    started = begin_round(tmp_path, target, max_lanes=1)
    lane = "sqli:/api/orders"
    record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
    record_round_lane_result(tmp_path, target, lane=lane, status="completed", decision="tested clean",
                             evidence_ref=_write_evidence(tmp_path, target), next_action="none")
    binding = store.binding()
    attribute = {"checkpoint": "build_checkpoint", "snapshot": "_closure_snapshot"}.get(
        failure_point, "record_round_closure")
    original = getattr(autopilot_round_module, attribute)
    calls = 0

    def interrupt(*args, **kwargs):
        nonlocal calls
        calls += 1
        if failure_point == "snapshot" and calls == 1:
            return original(*args, **kwargs)
        if failure_point in {"checkpoint", "after-closure"}:
            original(*args, **kwargs)
        raise OSError("interrupted at " + failure_point)

    monkeypatch.setattr(autopilot_round_module, attribute, interrupt)
    with pytest.raises(OSError, match="interrupted at " + failure_point):
        settle_round(tmp_path, target, refresh_coverage=False)
    interrupted = json.loads(_witness(tmp_path).read_text())
    assert interrupted["round_progress"]["status"] == (
        "completed" if failure_point == "after-closure" else "active")
    monkeypatch.setattr(autopilot_round_module, attribute, original)
    recovered = settle_round(tmp_path, target, refresh_coverage=False)
    after = _witness(tmp_path).read_bytes()
    replay = settle_round(tmp_path, target, refresh_coverage=False)
    assert recovered["status"] in {"settled", "already_settled"}
    assert replay["status"] == "already_settled"
    assert replay["round_progress"]["round_id"] == started["round_progress"]["round_id"]
    assert _witness(tmp_path).read_bytes() == after
    assert store.binding() == binding
    assert load_queue(tmp_path, target)["actions"] == []
    assert not (tmp_path / "state" / target / "action_queue.json").exists()


@pytest.mark.parametrize("projection", ["stale", "missing", "malformed"])
def test_settle_completes_without_surface_refresh(tmp_path, monkeypatch, projection):
    target = "target.com"
    store = TargetStore(tmp_path, target)
    store.initialize()
    _seed_stale_surface(tmp_path, target)
    path = tmp_path / "state" / target / "surface-projection.json"
    if projection == "missing":
        path.unlink()
    elif projection == "malformed":
        path.write_text("{broken")
    begin_round(tmp_path, target, max_lanes=1)
    before = _witness(tmp_path).read_bytes()
    binding = store.binding()
    surface_before = path.read_bytes() if path.exists() else None
    result = settle_round(tmp_path, target, refresh_coverage=False)
    assert result["status"] == "settled"
    assert result["round_progress"]["status"] == "completed"
    assert _witness(tmp_path).read_bytes() != before
    assert (path.read_bytes() if path.exists() else None) == surface_before
    surface_module.build_surface_review(tmp_path, target, refresh=True)
    result = settle_round(tmp_path, target, refresh_coverage=False)
    assert result["round_progress"]["status"] == "completed"
    assert store.binding() == binding


def test_settle_round_blocks_concurrent_lane_claim_until_round_is_closed(monkeypatch, tmp_path):
    target = "target.com"
    TargetStore(tmp_path, target).initialize()
    begin_round(tmp_path, target, max_lanes=1)
    context = multiprocessing.get_context("fork")
    start = context.Event()
    attempting = context.Event()
    output = context.Queue()
    process = context.Process(
        target=_claim_lane_after_signal,
        args=(str(tmp_path), target, start, attempting, output),
    )
    process.start()
    original_checkpoint = autopilot_round_module.build_checkpoint

    def checkpoint_while_claim_waits(*args, **kwargs):
        start.set()
        assert attempting.wait(timeout=2)
        time.sleep(0.1)
        assert process.is_alive()
        return original_checkpoint(*args, **kwargs)

    monkeypatch.setattr(
        autopilot_round_module,
        "build_checkpoint",
        checkpoint_while_claim_waits,
    )
    settled = settle_round(tmp_path, target, refresh_coverage=False)
    outcome, detail = output.get(timeout=5)
    process.join(timeout=5)

    assert settled["status"] == "settled"
    assert outcome == "error"
    assert "active round" in detail
    assert process.exitcode == 0
