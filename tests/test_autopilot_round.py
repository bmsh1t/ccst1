"""Focused tests for deterministic round orchestration."""

from __future__ import annotations

import multiprocessing
import time
from contextlib import nullcontext

import pytest

import tools.autopilot_round as autopilot_round_module
from tools.autopilot_round import prepare_round, settle_round
from tools.checkpoint import (
    begin_round,
    record_round_lane,
    record_round_lane_result,
)


def _witness(tmp_path, target: str = "target.com"):
    return tmp_path / "state" / target / "checkpoint_latest.json"


def _write_evidence(tmp_path, target: str = "target.com") -> str:
    evidence_ref = f"findings/{target}/poc/round/summary.json"
    path = tmp_path / evidence_ref
    path.parent.mkdir(parents=True)
    path.write_text('{"result":"tested_clean"}\n', encoding="utf-8")
    return evidence_ref


def _claim_lane_after_signal(repo_root, target, start, attempting, output):
    start.wait()
    attempting.set()
    try:
        result = record_round_lane(repo_root, target, lane="late:claim", max_lanes=1)
        output.put(("ok", result["status"]))
    except Exception as exc:
        output.put(("error", str(exc)))


def test_prepare_round_is_idempotent_and_preserves_checkpoint_budget(tmp_path):
    first = prepare_round(tmp_path, "target.com", 2)
    second = prepare_round(tmp_path, "target.com", 8)

    assert first["status"] == "started"
    assert second["status"] == "resumed"
    assert second["round_progress"]["round_id"] == first["round_progress"]["round_id"]
    assert second["round_progress"]["max_lanes"] == 2


def test_settle_round_refuses_started_lane_without_writing(tmp_path):
    target = "target.com"
    begin_round(tmp_path, target, max_lanes=1)
    record_round_lane(tmp_path, target, lane="coverage:/api/orders", max_lanes=1)
    witness = _witness(tmp_path, target)
    before = witness.read_bytes()

    with pytest.raises(ValueError, match="unfinished lanes: coverage:/api/orders"):
        settle_round(tmp_path, target, refresh_coverage=False)

    assert witness.read_bytes() == before


def test_settle_round_closes_terminal_lane_and_replays_idempotently(tmp_path):
    target = "target.com"
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


def test_pending_surface_refreshes_before_settle(monkeypatch, tmp_path):
    calls = []
    refreshed = ({"surface_projection": {"status": "valid"}}, {"reasons": []})

    monkeypatch.setattr(
        autopilot_round_module,
        "build_surface_review",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    monkeypatch.setattr(autopilot_round_module, "_closure_snapshot", lambda *args: refreshed)

    state, closure = autopilot_round_module._refresh_surface_if_pending(
        tmp_path,
        "target.com",
        {"surface_projection": {"status": "stale"}},
        {"reasons": ["surface_projection_pending"]},
    )

    assert calls == [((tmp_path, "target.com"), {"refresh": True})]
    assert (state, closure) == refreshed


def test_pending_surface_refresh_failure_preserves_handoff(monkeypatch, tmp_path):
    original = ({"surface_projection": {"status": "stale"}}, {"reasons": ["surface_projection_pending"]})

    def fail_refresh(*_args, **_kwargs):
        raise OSError("surface unavailable")

    monkeypatch.setattr(autopilot_round_module, "build_surface_review", fail_refresh)

    assert autopilot_round_module._refresh_surface_if_pending(
        tmp_path,
        "target.com",
        *original,
    ) == original


def test_settle_refreshes_surface_after_checkpoint_queue_writeback(monkeypatch, tmp_path):
    events = []
    target = "target.com"
    state = {"resolved_target": target}
    closure = {
        "reasons": ["surface_projection_pending"],
        "round_progress": {"status": "active", "unfinished_lanes": []},
    }

    monkeypatch.setattr(
        autopilot_round_module,
        "checkpoint_witness_lock",
        lambda *_args, **_kwargs: nullcontext(),
    )
    monkeypatch.setattr(autopilot_round_module, "_closure_snapshot", lambda *_args: (state, closure))
    monkeypatch.setattr(
        autopilot_round_module,
        "reconcile_root_finding_claims",
        lambda *_args, **_kwargs: events.append("reconcile") or {},
    )
    monkeypatch.setattr(
        autopilot_round_module,
        "build_checkpoint",
        lambda *_args, **kwargs: events.append("checkpoint") or {
            "target": kwargs["target"],
            "next_action_queue": [],
        },
    )
    monkeypatch.setattr(autopilot_round_module, "list_root_finding_claims", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        autopilot_round_module,
        "sync_checkpoint_action_queue",
        lambda *_args, **_kwargs: events.append("sync"),
    )
    monkeypatch.setattr(
        autopilot_round_module,
        "_refresh_surface_if_pending",
        lambda *_args, **_kwargs: events.append("refresh") or (state, closure),
    )
    monkeypatch.setattr(
        autopilot_round_module,
        "record_round_closure",
        lambda *_args, **_kwargs: events.append("close") or {"round_progress": {"status": "completed"}},
    )

    result = settle_round(tmp_path, target, refresh_coverage=False)

    assert result["status"] == "settled"
    assert events == ["reconcile", "checkpoint", "sync", "refresh", "close"]


def test_settle_round_blocks_concurrent_lane_claim_until_round_is_closed(monkeypatch, tmp_path):
    target = "target.com"
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
    original_reconcile = autopilot_round_module.reconcile_root_finding_claims

    def reconcile_while_claim_waits(*args, **kwargs):
        start.set()
        assert attempting.wait(timeout=2)
        time.sleep(0.1)
        assert process.is_alive()
        return original_reconcile(*args, **kwargs)

    monkeypatch.setattr(
        autopilot_round_module,
        "reconcile_root_finding_claims",
        reconcile_while_claim_waits,
    )
    settled = settle_round(tmp_path, target, refresh_coverage=False)
    outcome, detail = output.get(timeout=5)
    process.join(timeout=5)

    assert settled["status"] == "settled"
    assert outcome == "error"
    assert "active round" in detail
    assert process.exitcode == 0
