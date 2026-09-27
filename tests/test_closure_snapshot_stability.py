"""Closure binds current facts independently of read time and output mode."""

from datetime import datetime, timedelta, timezone

import pytest

from tools import autopilot_state, coverage_matrix, surface
from tools.checkpoint import (
    begin_round, record_global_review, record_round_closure,
    record_round_lane, record_round_lane_result,
)
from tools.target_store import TargetStore


TARGET = "closure-stability.test"


def _write(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def store(tmp_path):
    owner = TargetStore(tmp_path, TARGET)
    owner.initialize()
    begin_round(tmp_path, TARGET, max_lanes=1)
    _write(tmp_path, f"evidence/{TARGET}/review.txt", "Target-wide evidence review\n")
    return owner


def _closure(root, bounded):
    return autopilot_state.load_closure_projection(
        str(root), autopilot_state.build_autopilot_state(str(root), TARGET, bounded=bounded),
    )


def _review(root, digest):
    return record_global_review(
        root, TARGET, status="complete", snapshot_digest=digest,
        evidence_refs=[f"evidence/{TARGET}/review.txt"], decision="Reviewed current target facts",
    )


@pytest.fixture
def clock(monkeypatch):
    class Clock(datetime):
        current = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)

        @classmethod
        def now(cls, tz=None):
            return cls.current if tz is None else cls.current.astimezone(tz)

    monkeypatch.setattr(coverage_matrix, "datetime", Clock)
    return Clock


@pytest.mark.parametrize("scenario", ["empty", "urls", "js", "ffuf-empty", "whitespace"])
@pytest.mark.parametrize("projection", ["missing", "valid", "stale"])
def test_closure_review_survives_read_time_and_full_bounded_modes(tmp_path, store, clock, scenario, projection):
    relative, content = {
        "empty": ("urls/all.txt", ""),
        "urls": ("urls/all.txt", f"https://{TARGET}/api/orders?id=1\n"),
        "js": ("urls/js_files.txt", f"https://{TARGET}/app.js\n"),
        "ffuf-empty": ("dirs/ffuf_summary.json", '{"observations": 0}'),
        "whitespace": ("urls/all.txt", "\n"),
    }[scenario]
    path = _write(tmp_path, f"recon/{TARGET}/{relative}", content)
    if projection != "missing":
        surface.build_surface_review(tmp_path, TARGET)
    if projection == "stale":
        path.write_text(content + "\n")
    binding = store.binding()
    digest = None
    for bounded in (False, True, False, True):
        current = _closure(tmp_path, bounded)
        digest = digest or current["snapshot_digest"]
        assert current["snapshot_digest"] == digest
        clock.current += timedelta(seconds=1)
    result = _review(tmp_path, digest)
    assert result["snapshot_digest"] == digest
    for bounded in (True, False):
        clock.current += timedelta(seconds=1)
        current = _closure(tmp_path, bounded)
        assert current["global_review"]["status"] == "complete"
        assert current["snapshot_digest"] == digest
    assert store.binding() == binding


def test_completed_round_review_survives_delayed_full_and_bounded_reads(tmp_path, store, clock):
    _write(tmp_path, f"recon/{TARGET}/urls/all.txt", f"https://{TARGET}/unreviewed\n")
    surface.build_surface_review(tmp_path, TARGET)
    record_round_lane(tmp_path, TARGET, lane="fixture-review", max_lanes=1)
    record_round_lane_result(
        tmp_path, TARGET, lane="fixture-review", status="completed",
        decision="Reviewed one local fixture lane; target coverage remains incomplete",
        evidence_ref=f"evidence/{TARGET}/review.txt", next_action="none",
    )
    result = record_round_closure(tmp_path, TARGET)
    assert result["round_progress"]["status"] == "completed"
    binding = store.binding()
    initial = _closure(tmp_path, False)
    assert not initial["can_claim_exhausted"]
    clock.current += timedelta(seconds=30)
    recorded = _review(tmp_path, initial["snapshot_digest"])
    basis = recorded["global_review"]["basis"]
    for bounded in (True, False, True, False):
        clock.current += timedelta(minutes=1)
        current = _closure(tmp_path, bounded)
        assert current["snapshot_digest"] == initial["snapshot_digest"]
        assert current["global_review"]["status"] == "complete"
        assert current["global_review"]["basis"] == basis
        assert not current["can_claim_exhausted"]
    assert store.binding() == binding


@pytest.mark.parametrize("mutation", ["queue", "coverage", "discovery", "evidence"])
def test_closure_review_still_rejects_changed_owner_facts(tmp_path, store, mutation):
    discovery = _write(tmp_path, f"recon/{TARGET}/urls/all.txt", f"https://{TARGET}/object\n")
    raw = _write(tmp_path, f"evidence/{TARGET}/response.txt", "baseline response")
    store.start_attempt(attempt_id="attempt", source="native", started_at="2026-09-27T00:00:00Z", actor="operator")
    store.record_execution(attempt_id="attempt", outcome="complete", actor="operator", observations=[{
        "endpoint": f"https://{TARGET}/object", "method": "GET", "family": "Authz",
        "actor": "owner", "object_scope": "own_object", "variant": "baseline", "result": "tested_clean",
        "description": "Recorded fixture comparison", "observed_at": "2026-09-27T00:00:00Z",
        "artifacts": {"response": str(raw.relative_to(tmp_path))}, "state_changing": False,
    }])
    surface.build_surface_review(tmp_path, TARGET)
    initial = _closure(tmp_path, False)
    _review(tmp_path, initial["snapshot_digest"])
    binding = store.binding()
    if mutation == "queue":
        store.create_action(command_id="follow-up", action_id="follow-up", kind="work",
                            subject={"target": TARGET}, intent="Review follow-up",
                            execution_key="follow-up", actor="operator")
    elif mutation == "coverage":
        store.record_coverage_review(command_id="triage", endpoint="/object", kind="endpoint_kind",
                                     value="api_endpoint", actor="operator")
    elif mutation == "discovery":
        discovery.write_text(f"https://{TARGET}/object\nhttps://{TARGET}/new\n")
    else:
        raw.write_text("changed response")
    current = _closure(tmp_path, True)
    assert current["snapshot_digest"] != initial["snapshot_digest"]
    assert current["global_review"]["status"] == "stale"
    with pytest.raises(ValueError, match="global_review_stale"):
        _review(tmp_path, initial["snapshot_digest"])
    if mutation in {"discovery", "evidence"}:
        assert store.binding() == binding
