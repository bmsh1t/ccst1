"""Runner review material is retired only by exact Store assessment evidence."""

import json
from pathlib import Path

import pytest

from tools.structured_findings import load_validation_runner_candidate_pool
from tools.target_store import StoreError, TargetStore
from tools.validation_runner import _ensure_primary_finding


def test_candidate_pool_keeps_new_attempts_and_ignores_legacy_closure(tmp_path, monkeypatch):
    target = "candidate.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    refs = []
    raw_paths = []
    summaries = []
    for index in range(2):
        attempt = f"attempt-{index}"
        directory = tmp_path / "evidence" / target / "validation" / "claim" / attempt
        directory.mkdir(parents=True)
        raw = directory / "response.txt"
        raw.write_text(f"Observed comparison {index}")
        raw_paths.append(raw)
        raw_ref = raw.relative_to(tmp_path).as_posix()
        store.start_attempt(attempt_id=attempt, source="native", started_at="2026-09-24T00:00:00Z", actor="test")
        receipt = store.record_execution(attempt_id=attempt, outcome="complete", actor="test", observations=[{
            "endpoint": f"https://{target}/orders?id=1", "method": "GET", "family": "Authz",
            "observed_at": "2026-09-24T00:00:01Z", "description": "Observed comparison",
            "artifacts": {"response": raw_ref}, "result": "tested_finding", "state_changing": False,
        }], candidate={"id": "claim", "endpoint": f"https://{target}/orders?id=1", "method": "GET",
                       "family": "Authz", "title": "Saved claim", "claim": "Boundary requires review"})
        refs.append({"operation_id": receipt["entity_id"], "step": 0})
        summary = directory / "summary.json"
        summary.write_text(json.dumps({
            "finding_id": "claim", "attempt_id": attempt, "lane": "native", "candidate_ready": True,
            "url": f"https://{target}/orders?id=1", "method": "GET", "vuln_class": "Authz",
            "result": "tested_finding", "runs": [{"artifacts": {"response": raw_ref}}],
        }))
        summaries.append(summary)
    legacy_paths = [tmp_path / "findings" / target / "findings.json",
                    tmp_path / "memory" / "evidence" / target / "ledger.jsonl"]
    for path in legacy_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"id":"claim","validation_status":"rejected","result":"not_applicable"}')
    original_read = Path.read_text

    def reject_legacy(path, *args, **kwargs):
        if path in legacy_paths:
            raise AssertionError("current candidate pool read a legacy owner")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", reject_legacy)
    assert {item["attempt_id"] for item in load_validation_runner_candidate_pool(tmp_path, target)} == {
        "attempt-0", "attempt-1",
    }
    store.assess(command_id="review", finding_id="claim", verdict="refuted", reason="Owner response is expected",
                 boundary="same actor", impact="", evidence=[refs[0]], actor="test", expected_assessment=None)
    assert store.finding("claim")["assessment"]["evidence"] == [refs[0]]
    before = store.binding()
    assert [item["attempt_id"] for item in load_validation_runner_candidate_pool(tmp_path, target)] == ["attempt-1"]
    # A summary that names the reviewed attempt but contains new material is still reviewable.
    payload = json.loads(summaries[1].read_text())
    payload["attempt_id"] = "attempt-0"
    summaries[1].write_text(json.dumps(payload))
    assert len(load_validation_runner_candidate_pool(tmp_path, target)) == 1
    raw_paths[0].write_text("changed bytes")
    with pytest.raises(StoreError, match="registered evidence changed"):
        load_validation_runner_candidate_pool(tmp_path, target)
    assert store.binding() == before


def test_runner_creation_only_handles_absent_findings(tmp_path, monkeypatch):
    store = TargetStore(tmp_path, "candidate.test")
    store.initialize()
    args = dict(finding_id="claim", endpoint="https://candidate.test/orders", method="GET", family="Authz")
    _ensure_primary_finding(store, **args)
    before = store.binding()
    _ensure_primary_finding(store, **args)
    assert store.binding() == before

    def damaged(_):
        raise StoreError("unreadable current finding")

    monkeypatch.setattr(store, "finding", damaged)
    with pytest.raises(StoreError, match="unreadable current finding"):
        _ensure_primary_finding(store, **args)
    assert store.binding() == before
