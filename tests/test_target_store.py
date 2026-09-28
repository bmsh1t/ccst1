"""Domain contracts in isolated targets; no network or personal runtime state."""

from concurrent.futures import ThreadPoolExecutor
import ast
import hashlib
import json
import os
import sqlite3
import stat
import threading
from pathlib import Path

import pytest

from tools.target_store import (
    ConflictError,
    StoreError,
    TargetStore,
    runtime_store,
    target_backend,
    target_cutover_lock,
)
from tools.action_queue import add_manual_action
import tools.finding_index as finding_index


URL = "https://target.test/api/objects?owner=peer"
FAMILY = "custom-state-transition"
AT = "2026-09-20T01:00:00Z"


def make_store(root):
    store = TargetStore(root, "target.test")
    store.initialize()
    return store


def test_case_context_batches_links_without_losing_hypothesis_context(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    for actor_id in ("owner", "peer"):
        store.upsert_case_actor(command_id=actor_id, actor_id=actor_id, role="user", actor="operator")
    store.upsert_case_object(command_id="object", object_ref="object", object_type="record",
                             owner_actor="owner", actor="operator")
    for index in range(100):
        store.remember_hypothesis(
            command_id=f"h-{index:03}", hypothesis_id=f"H-{index:03}", vuln_class="custom",
            why_now=f"Saved premise {index}", actor_ids=["peer", "owner"] if index % 2 else [],
            object_ref="object" if index % 3 else "", metadata={"context": index}, actor="operator",
        )
    before = store.binding()
    statements = []
    connect = sqlite3.connect

    def traced_connection(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(sqlite3, "connect", traced_connection)
    context = store.case_context()
    assert len(statements) < 25
    assert context["revision"] == before["revision"]
    assert [item["id"] for item in context["hypotheses"]] == [f"H-{index:03}" for index in range(100)]
    for index, item in enumerate(context["hypotheses"]):
        assert item["actors"] == (["owner", "peer"] if index % 2 else [])
        assert item["object_ref"] == ("object" if index % 3 else "")
        assert item["why_now"] == f"Saved premise {index}"
        assert item["metadata"] == {"context": index}
    assert context["authz_coverage"]["status"] == "missing"
    assert store.binding() == before


def create_action(store, action_id="a1"):
    return store.create_action(command_id="create:" + action_id, action_id=action_id,
                               intent="Compare observed business state", endpoint=URL,
                               family=FAMILY, execution_key=action_id, actor="operator")


def observation(root):
    path = root / ".private" / "validation" / "target.test" / "response.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('HTTP/1.1 200 OK\r\n\r\n{"owner":"peer"}')
    return {"endpoint": URL, "method": "GET", "family": FAMILY, "observed_at": AT,
            "description": "Peer object visible in the recorded response",
            "artifacts": {"response": path.relative_to(root).as_posix()}, "state_changing": False}


def candidate():
    return {"id": "f1", "endpoint": URL, "method": "GET", "family": FAMILY,
            "title": "Peer object visibility", "claim": "Peer object crossed the actor boundary"}


def record(store, root, attempt_id="try1", **kwargs):
    store.start_attempt(attempt_id=attempt_id, source="native", started_at=AT, actor="operator")
    return store.record_execution(attempt_id=attempt_id, outcome="complete",
                                  observations=[observation(root)], candidate=candidate(), actor="operator", **kwargs)


def assessment(store, *, command_id="assess1", verdict="confirmed", expected=None):
    return store.assess(command_id=command_id, finding_id="f1", verdict=verdict,
                        reason="Explicit operator assessment using the recorded control and actor context",
                        boundary="Actor A must not read actor B's object", impact="Peer data disclosure",
                        evidence=store.finding("f1")["evidence"], actor="operator", expected_assessment=expected)


def test_finding_page_batches_relations_and_preserves_complete_paging(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    assert store.finding_page()["items"] == []
    for i in range(61):
        store.create_finding(command_id=f"claim-{i}", finding_id=f"F-{i:02}",
                             endpoint=URL, method="GET", family=FAMILY,
                             title=f"Claim {i}", claim=f"Unverified claim {i}", actor="operator")
    before = store.binding()
    statements, connections = [], []
    connect = sqlite3.connect

    def traced(*args, **kwargs):
        conn = connect(*args, **kwargs)
        connections.append(conn)
        conn.set_trace_callback(statements.append)
        return conn

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", traced)
        page = store.finding_page(limit=60)
    assert len(connections) == 1 and len(statements) < 25
    assert page["revision"] == before["revision"]
    assert (page["total"], page["remaining"], page["has_more"]) == (61, 1, True)
    tail = store.finding_page(limit=60, cursor=page["next_cursor"])
    assert (tail["remaining"], tail["has_more"], tail["next_cursor"]) == (0, False, None)
    rows = page["items"] + tail["items"]
    assert [row["id"] for row in rows] == [f"F-{i:02}" for i in range(61)]
    for i, row in enumerate(rows):
        assert (row["title"], row["claim"], row["endpoint"], row["family"]) == (
            f"Claim {i}", f"Unverified claim {i}", URL, FAMILY)
        assert row["assessment"] is None
        assert row["evidence"] == row["deliveries"] == row["reports"] == []
    assert store.binding() == before
    store.set_active_goal(command_id="new-revision", goal="Changed premise", actor="operator")
    with pytest.raises(ConflictError, match="snapshot"):
        store.finding_page(cursor=page["next_cursor"])


def test_finding_summary_is_bounded_exact_and_not_delivery_authority(tmp_path, monkeypatch):
    from tools.resume_read import _structured_finding_followup
    from tools.structured_findings import summarize_structured_findings

    store = make_store(tmp_path)
    assert store.finding_summary()["counts"] == dict(
        total=0, confirmed=0, pending_validation=0, validated_pending_report=0, reported=0)
    record(store, tmp_path)
    evidence_by_finding = {}
    for i in range(12):
        store.create_finding(command_id=f"claim-{i}", finding_id=f"F-{i:02}", endpoint=URL,
                             method="GET", family=FAMILY, title=f"Claim {i}", claim=f"Claim {i}", actor="operator")
        if i == 11:
            continue
        store.start_attempt(attempt_id=f"attempt-{i}", source="native", started_at=AT, actor="operator")
        receipt = store.record_execution(attempt_id=f"attempt-{i}", outcome="complete", actor="operator",
            candidate={**candidate(), "id": f"F-{i:02}", "title": f"Claim {i}", "claim": f"Claim {i}"},
            observations=[observation(tmp_path)])
        evidence = [{"operation_id": receipt["entity_id"], "step": 0}]
        evidence_by_finding[i] = evidence
        store.assess(command_id=f"assess-{i}", finding_id=f"F-{i:02}",
                     verdict="confirmed" if i < 10 else "inconclusive", reason="Recorded review",
                     boundary="Actor boundary", impact="Data disclosure", evidence=evidence,
                     actor="operator", expected_assessment=None)
        if i >= 8:
            continue
        store.decide_delivery(command_id=f"delivery-{i}", finding_id=f"F-{i:02}", assessment_id=f"assess-{i}",
                              destination="internal", status="eligible", reason="Review", actor="operator", expected_decision=None)
        report = tmp_path / "reports" / "target.test" / f"report-{i}.md"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(f"Report {i}")
        store.register_report(command_id=f"report-{i}", report_id=f"report-{i}", finding_id=f"F-{i:02}",
                              assessment_id=f"assess-{i}", delivery_id=f"delivery-{i}", artifact=str(report), actor="operator")
    store.assess(command_id="reassessment", finding_id="F-00", verdict="refuted", reason="New review",
                 boundary="Actor boundary", impact="No disclosure", evidence=evidence_by_finding[0],
                 actor="operator", expected_assessment="assess-0")
    before = store.binding()
    original = store.finding_page()["items"]
    expected = summarize_structured_findings([{
        "id": row["id"], "type": row["family"], "severity": "medium",
        "confidence": (row["assessment"] or {}).get("verdict", ""), "url": row["endpoint"],
        "validation_status": {"confirmed": "validated", "refuted": "rejected"}.get(
            (row["assessment"] or {}).get("verdict"), "candidate"),
        "report_status": "generated" if row["reports"] else "not_generated",
    } for row in original], tmp_path / "findings" / store.key)
    states = store._finding_states
    materialized = []

    def limited(conn, rows):
        materialized.extend(row["id"] for row in rows)
        return states(conn, rows)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_finding_states", limited)
        patch.setattr(store, "_finding_projections", lambda *args: pytest.fail("summary expanded history"))
        summary = store.finding_summary()
    assert len(materialized) == 7
    assert summary["counts"] == dict(total=13, confirmed=9, pending_validation=3, validated_pending_report=2, reported=8)
    assert summary["next_validation"]["id"] == "F-10"
    assert summary["next_report"]["id"] == "F-08"
    assert _structured_finding_followup(summary, tmp_path, store.target) == expected
    assert [row["id"] for row in summary["items"]] == [f"F-{i:02}" for i in range(5)]
    tail = store.finding_state_page(limit=1000, cursor=summary["next_cursor"])
    assert len(tail["items"]) == summary["remaining"] == 8
    assert all(not {"reports", "deliveries", "evidence"} & row.keys() for row in tail["items"])
    assert store.binding() == before

    # Registered history is preserved, but the full authority path still checks current bytes.
    (tmp_path / "reports/target.test/report-1.md").write_text("Changed")
    (tmp_path / ".private/validation/target.test/response.txt").write_text("Changed")
    assert store.finding_summary() == summary
    report = store.finding("F-01")["reports"][0]
    assert report["stale"] is True and report["artifact_authorized"] is False
    with pytest.raises(StoreError):
        store.finding_summary(limit=0)
    with pytest.raises(StoreError, match="cursor"):
        store.finding_state_page(cursor="malformed")
    store.set_active_goal(command_id="new-revision", goal="New premise", actor="operator")
    with pytest.raises(ConflictError, match="snapshot"):
        store.finding_state_page(cursor=summary["next_cursor"])


def test_finding_summary_pins_counts_preview_and_followup_to_one_revision(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    for index in range(2):
        store.create_finding(command_id=f"claim-{index}", finding_id=f"f{index}", endpoint=URL,
                             method="GET", family=FAMILY, title="Claim", claim="Unassessed", actor="operator")
    before = store.binding()
    states = store._finding_states

    def concurrent_write(conn, rows):
        store.create_finding(command_id="new-claim", finding_id="a-new", endpoint=URL,
                             method="GET", family=FAMILY, title="New claim", claim="Unassessed", actor="operator")
        return states(conn, rows)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_finding_states", concurrent_write)
        snapshot = store.finding_summary(limit=1)
    assert snapshot["revision"] == before["revision"]
    assert snapshot["counts"]["total"] == snapshot["total"] == 2
    assert snapshot["items"][0]["id"] == snapshot["next_validation"]["id"] == "f0"
    fresh = store.finding_summary(limit=1)
    assert fresh["counts"]["total"] == fresh["total"] == 3
    assert fresh["next_validation"]["id"] == "a-new"
    with pytest.raises(ConflictError, match="snapshot"):
        store.finding_state_page(cursor=snapshot["next_cursor"])


def test_finding_authorization_reuses_one_snapshot_but_rechecks_next_read(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    first = record(store, tmp_path)
    second = record(store, tmp_path, attempt_id="try2")
    selected = [{"operation_id": second["entity_id"], "step": 0}]
    store.assess(command_id="selected", finding_id="f1", verdict="confirmed", reason="Selected evidence",
                 boundary="Actor boundary", impact="Peer data", evidence=selected,
                 actor="operator", expected_assessment=None)
    store.decide_delivery(command_id="eligible", finding_id="f1", assessment_id="selected",
                          destination="internal", status="eligible", reason="Review complete",
                          actor="operator", expected_decision=None)
    report = tmp_path / "reports" / "target.test" / "report.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Report\n")
    store.register_report(command_id="report", report_id="report", finding_id="f1",
                          assessment_id="selected", delivery_id="eligible", artifact=str(report), actor="operator")
    before = store.binding()
    checked, connections = [], []
    verify, connect = store._verify_operation, sqlite3.connect

    def verified(conn, operation_id):
        checked.append(operation_id)
        return verify(conn, operation_id)

    def connected(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    with monkeypatch.context() as patch:
        patch.setattr(store, "_verify_operation", verified)
        patch.setattr(sqlite3, "connect", connected)
        page = store.finding_page()
    assert len(connections) == 1 and checked == [second["entity_id"]]
    row = page["items"][0]
    assert {ref["operation_id"] for ref in row["evidence"]} == {first["entity_id"], second["entity_id"]}
    assert row["assessment"]["id"] == "selected"
    assert row["deliveries"][0]["stale"] is row["reports"][0]["stale"] is False
    assert store.finding("f1")["assessment"]["evidence"] == selected
    assert store.binding() == before

    # Same metadata revision does not make previously checked files trustworthy.
    report.write_text("Changed report")
    row = store.finding_page()["items"][0]
    assert row["reports"][0]["stale"] is True
    assert row["reports"][0]["artifact_authorized"] is False
    assert row["deliveries"][0]["stale"] is False
    report.write_text("# Report\n")
    raw = tmp_path / ".private/validation/target.test/response.txt"
    original = raw.read_bytes()
    raw.write_bytes(b"Changed evidence")
    row = store.finding_page()["items"][0]
    assert row["assessment"]["verdict"] == "confirmed"
    assert row["deliveries"][0]["stale"] is row["reports"][0]["stale"] is True
    assert store.binding() == before
    raw.write_bytes(original)

    # A concurrent invalidation belongs to the next metadata snapshot, not this page.
    events = store._artifact_events
    changed = False

    def invalidate(conn, artifact_id):
        nonlocal changed
        if not changed:
            changed = True
            store.record_artifact_event(command_id="revoke", artifact_id=artifact_id,
                                        dimension="provenance", state="revoked", reason="New review", actor="operator")
        return events(conn, artifact_id)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_artifact_events", invalidate)
        pinned = store.finding_page()
    assert changed and pinned["revision"] == before["revision"]
    assert pinned["items"][0]["deliveries"][0]["stale"] is False
    assert pinned["items"][0]["reports"][0]["stale"] is False
    fresh = store.finding_page()
    assert fresh["revision"] == before["revision"] + 1
    assert fresh["items"][0]["deliveries"][0]["stale"] is True
    assert fresh["items"][0]["reports"][0]["stale"] is True


def test_finding_page_keeps_judgments_and_destinations_scoped_to_each_claim(tmp_path):
    store = make_store(tmp_path)
    for i in range(3):
        raw = tmp_path / "evidence/target.test" / f"response-{i}.txt"
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(f"Response {i}")
        store.start_attempt(attempt_id=f"try-{i}", source="native", started_at=AT, actor="operator")
        receipt = store.record_execution(attempt_id=f"try-{i}", outcome="complete", actor="operator",
            candidate={**candidate(), "id": f"f{i}"}, observations=[{
                **observation(tmp_path), "artifacts": {"response": raw.relative_to(tmp_path).as_posix()},
            }])
        evidence = [{"operation_id": receipt["entity_id"], "step": 0}]
        store.assess(command_id=f"old-{i}", finding_id=f"f{i}", verdict="confirmed", reason="Initial review",
                     boundary="Actor boundary", impact="Data disclosure", evidence=evidence,
                     actor="operator", expected_assessment=None)
        store.decide_delivery(command_id=f"old-delivery-{i}", finding_id=f"f{i}", assessment_id=f"old-{i}",
                              destination="old-destination", status="eligible", reason="Old review",
                              actor="operator", expected_decision=None)
        store.assess(command_id=f"new-{i}", finding_id=f"f{i}", verdict="confirmed" if i % 2 else "refuted",
                     reason="Reassessment", boundary="Actor boundary", impact="Data disclosure", evidence=evidence,
                     actor="operator", expected_assessment=f"old-{i}")
        store.decide_delivery(command_id=f"current-delivery-{i}", finding_id=f"f{i}", assessment_id=f"new-{i}",
                              destination="current-destination", status="ineligible", reason="Not delivered",
                              actor="operator", expected_decision=None)
    before = store.binding()
    page = store.finding_page()
    for i, row in enumerate(page["items"]):
        assert row["id"] == f"f{i}"
        assert row["assessment"]["id"] == f"new-{i}"
        assert row["assessment"]["verdict"] == ("confirmed" if i % 2 else "refuted")
        assert [d["id"] for d in row["deliveries"]] == [f"current-delivery-{i}", f"old-delivery-{i}"]
        assert [d["stale"] for d in row["deliveries"]] == [False, True]
        assert len(row["evidence"]) == 1 and row["reports"] == []
        assert store.execution(row["evidence"][0]["operation_id"])["attempt"]["id"] == f"try-{i}"
    (tmp_path / "evidence/target.test/response-1.txt").unlink()
    damaged = store.finding_page()["items"]
    assert [row["deliveries"][0]["stale"] for row in damaged] == [False, True, False]
    assert store.binding() == before


def test_execution_identity_atomic_facts_and_separate_decisions(tmp_path):
    store = make_store(tmp_path)
    create_action(store)
    claimed = store.transition_action(command_id="claim1", action_id="a1", expected_version=1,
                                      status="claimed", actor="operator")
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator",
                        action_id="a1", claim_token=claimed["command_id"])
    obs = observation(tmp_path)
    kwargs = dict(attempt_id="try1", outcome="complete", observations=[obs], candidate=candidate(), actor="operator")
    first = store.record_execution(**kwargs)
    repeated = store.record_execution(**kwargs)
    assert repeated["replayed"] and repeated["revision"] == first["revision"]
    assert store.page("actions")["items"][0]["status"] == "claimed"
    assert store.finding("f1")["assessment"] is None
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT family,coverage_class FROM observations").fetchone() == (FAMILY, None)
        assert conn.execute("SELECT count(*) FROM audit").fetchone()[0] == first["revision"]
        assert conn.execute("SELECT count(*) FROM operations").fetchone()[0] == 1
    # A real re-execution has a distinct attempt even if all observed bytes match.
    second = record(store, tmp_path, attempt_id="try2")
    assert second["entity_id"] != first["entity_id"]
    assert store.page("attempts")["total"] == 2
    assessment(store)
    store.decide_delivery(command_id="delivery1", finding_id="f1", assessment_id="assess1",
                          destination="internal-review", status="ineligible", reason="Already known",
                          actor="operator", expected_decision=None)
    finding = store.finding("f1")
    assert finding["assessment"]["verdict"] == "confirmed"
    assert finding["deliveries"][0]["status"] == "ineligible"
    store.transition_action(command_id="finish1", action_id="a1", expected_version=2, status="completed",
                             actor="operator", claim_token="claim1", reason="Requested comparison recorded",
                             completion={"operation_id": first["entity_id"]})
    assert store.page("actions")["items"][0]["status"] == "completed"
    assert store.verify_operation(first["entity_id"])["semantic_verification"] is False
    repeat = dict(command_id="repeat1", action_id="a2", intent="Recheck after conditions changed", endpoint=URL,
                  family=FAMILY, execution_key="a1", actor="operator")
    with pytest.raises(ConflictError, match="explicitly link"):
        store.create_action(**repeat)
    store.create_action(**repeat, repeat_of="a1", repeat_reason="Object policy was updated")
    assert store.page("actions")["total"] == 2


def test_action_metadata_is_bounded_and_hypothesis_claims_are_capped(tmp_path):
    store = make_store(tmp_path)
    metadata = {"hypothesis_id": "h-cap", "max_hypothesis_actions": 1,
                "expected_learning": "one bounded comparison"}
    store.create_action(command_id="create:cap-1", action_id="cap-1", intent="bounded work",
                        execution_key="cap-1", actor="operator", kind="work",
                        subject={"target": "target.test"}, metadata=metadata)
    first = store.transition_action(command_id="claim:cap-1", action_id="cap-1", expected_version=1,
                                    status="claimed", actor="operator", metadata={"active_dimension": "role"})
    assert store.action("cap-1")["metadata"] == {**metadata, "active_dimension": "role"}

    store.create_action(command_id="create:cap-2", action_id="cap-2", intent="second bounded work",
                        execution_key="cap-2", actor="operator", kind="work",
                        subject={"target": "target.test"}, metadata=metadata)
    with pytest.raises(ConflictError, match="hypothesis action budget"):
        store.transition_action(command_id="claim:cap-2", action_id="cap-2", expected_version=1,
                                status="claimed", actor="operator")


def test_action_metadata_rejects_runner_fields_and_foreign_evidence(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(StoreError, match="Runner-owned"):
        store.create_action(command_id="create:runner-field", action_id="runner-field", intent="work",
                            execution_key="runner-field", actor="operator", kind="work",
                            subject={"target": "target.test"}, metadata={"runner_operation_id": "op-1"})
    foreign = tmp_path.parent / "foreign-evidence.txt"
    foreign.write_text("not target-owned", encoding="utf-8")
    with pytest.raises(StoreError, match="raw evidence directories"):
        store.create_action(command_id="create:foreign-ref", action_id="foreign-ref", intent="work",
                            execution_key="foreign-ref", actor="operator", kind="work",
                            subject={"target": "target.test"}, metadata={"evidence_ref": str(foreign)})


def test_primary_action_metadata_keeps_queue_mechanical_boundaries(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(StoreError, match="missing card directory"):
        store.create_action(command_id="create:missing-card", action_id="missing-card", intent="work",
                            execution_key="missing-card", actor="operator", kind="work",
                            subject={"target": "target.test"},
                            metadata={"selected_knowledge_refs": ["knowledge/cards/nope.md"]})

    cards = tmp_path / "knowledge" / "cards"
    cards.mkdir(parents=True)
    (cards / "known.md").write_text("# card\n", encoding="utf-8")
    store.create_action(command_id="create:bounded", action_id="bounded", intent="work",
                        execution_key="bounded", actor="operator", kind="work",
                        subject={"target": "target.test"}, metadata={
                            "hypothesis_id": "h1", "max_hypothesis_actions_cap": 1,
                            "max_hypothesis_actions": 1,
                            "selected_knowledge_refs": ["knowledge/cards/known.md"],
                        })
    with pytest.raises(StoreError, match="single-dimension"):
        store.transition_action(command_id="claim:bad-dimension", action_id="bounded", expected_version=1,
                                status="claimed", actor="operator", metadata={"active_dimension": "two words"})
    with pytest.raises(ConflictError, match="immutable"):
        store.transition_action(command_id="claim:bad-cap", action_id="bounded", expected_version=1,
                                status="claimed", actor="operator", metadata={"max_hypothesis_actions_cap": 2})
    with pytest.raises(ConflictError, match="re-identify"):
        store.transition_action(command_id="claim:bad-identity", action_id="bounded", expected_version=1,
                                status="claimed", actor="operator", metadata={"hypothesis_id": "h2"})
    with pytest.raises(StoreError, match="sensitive field"):
        store.create_action(command_id="create:secret", action_id="secret", intent="work",
                            execution_key="secret", actor="operator", kind="work",
                            subject={"target": "target.test"}, metadata={"nested": {"token": "secret"}})


def test_primary_store_has_no_legacy_finding_writer(tmp_path):
    store = make_store(tmp_path)
    findings_dir = tmp_path / "findings" / "target.test"
    assert not hasattr(finding_index, "upsert_finding")
    assert store.finding_page()["total"] == 0
    assert not (findings_dir / "findings.json").exists()


def test_report_registration_binds_current_delivery_and_artifact(tmp_path):
    store = make_store(tmp_path)
    receipt = record(store, tmp_path)
    assessment(store)
    store.decide_delivery(command_id="delivery1", finding_id="f1", assessment_id="assess1",
                          destination="internal-review", status="eligible", reason="Ready",
                          actor="operator", expected_decision=None)
    report = tmp_path / "reports" / "target.test" / "idor_001.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Peer object visibility\n")

    registered = store.register_report(
        command_id="report1", report_id="idor_001", finding_id="f1", assessment_id="assess1",
        delivery_id="delivery1", artifact=str(report), actor="operator",
    )
    assert registered["entity_id"] == "idor_001"
    row = store.finding("f1")["reports"][0]
    assert row["destination"] == "internal-review"
    assert row["artifact_id"].startswith("artifact:")
    assert store.register_report(
        command_id="report1", report_id="idor_001", finding_id="f1", assessment_id="assess1",
        delivery_id="delivery1", artifact=str(report), actor="operator",
    )["replayed"] is True
    assert receipt["entity_id"] != registered["entity_id"]


def test_report_registration_rejects_ineligible_or_stale_delivery(tmp_path):
    store = make_store(tmp_path)
    record(store, tmp_path)
    assessment(store)
    store.decide_delivery(command_id="delivery1", finding_id="f1", assessment_id="assess1",
                          destination="internal-review", status="ineligible", reason="Known",
                          actor="operator", expected_decision=None)
    report = tmp_path / "reports" / "target.test" / "idor_001.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Report\n")
    with pytest.raises(StoreError, match="eligible delivery"):
        store.register_report(command_id="report1", report_id="idor_001", finding_id="f1",
                              assessment_id="assess1", delivery_id="delivery1", artifact=str(report),
                              actor="operator")


def test_report_and_delivery_become_stale_after_assessment_supersession(tmp_path):
    store = make_store(tmp_path)
    record(store, tmp_path)
    assessment(store)
    store.decide_delivery(command_id="delivery1", finding_id="f1", assessment_id="assess1",
                          destination="internal-review", status="eligible", reason="Ready",
                          actor="operator", expected_decision=None)
    report = tmp_path / "reports" / "target.test" / "idor_001.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Peer object visibility\n")
    store.register_report(command_id="report1", report_id="idor_001", finding_id="f1",
                          assessment_id="assess1", delivery_id="delivery1", artifact=str(report),
                          actor="operator")

    assessment(store, command_id="assess2", verdict="inconclusive", expected="assess1")
    finding = store.finding("f1")
    assert finding["deliveries"][0]["stale"] is True
    assert finding["reports"][0]["stale"] is True
    with pytest.raises(StoreError, match="current eligible delivery"):
        store.register_report(command_id="report2", report_id="idor_002", finding_id="f1",
                              assessment_id="assess1", delivery_id="delivery1", artifact=str(report),
                              actor="operator")


def test_delivery_event_is_explicit_history_not_report_generation_state(tmp_path):
    store = make_store(tmp_path)
    record(store, tmp_path)
    assessment(store)
    store.decide_delivery(command_id="delivery1", finding_id="f1", assessment_id="assess1",
                          destination="internal-review", status="eligible", reason="Ready",
                          actor="operator", expected_decision=None)
    report = tmp_path / "reports" / "target.test" / "idor_001.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Peer object visibility\n")
    store.register_report(command_id="report1", report_id="idor_001", finding_id="f1",
                          assessment_id="assess1", delivery_id="delivery1", artifact=str(report),
                          actor="operator")
    assert store.finding("f1")["delivery_events"] == []

    receipt = tmp_path / "reports" / "target.test" / "idor_001.receipt.json"
    receipt.write_text('{"submission":"EXT-42"}\n')
    event = store.record_delivery_event(
        command_id="submit1", event_id="submission1", report_id="idor_001",
        external_ref="EXT-42", submitted_at=AT, actor="operator", receipt_artifact=str(receipt),
    )
    assert event["entity_id"] == "submission1"
    recorded = store.finding("f1")["delivery_events"][0]
    assert recorded["report_id"] == "idor_001"
    assert recorded["external_ref"] == "EXT-42"
    assert recorded["receipt_available"] is True
    assert recorded["current_binding"] is True

    assessment(store, command_id="assess2", verdict="inconclusive", expected="assess1")
    historical = store.finding("f1")["delivery_events"][0]
    assert historical["external_ref"] == "EXT-42"
    assert historical["current_binding"] is False


def test_registration_rolls_back_all_metadata_and_audit_but_keeps_raw_files(tmp_path):
    store = make_store(tmp_path)
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator")
    obs = observation(tmp_path)
    raw = tmp_path / obs["artifacts"]["response"]
    original = raw.read_bytes()
    with sqlite3.connect(store.path) as conn:
        conn.execute("""CREATE TRIGGER fail_audit BEFORE INSERT ON audit
            WHEN NEW.command='record_execution' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END""")
    kwargs = dict(attempt_id="try1", outcome="complete", observations=[obs], candidate=candidate(), actor="operator")
    with pytest.raises(StoreError, match="injected audit failure"):
        store.record_execution(**kwargs)
    with sqlite3.connect(store.path) as conn:
        for table in ("operations", "observations", "artifacts", "observation_artifacts", "findings", "finding_observations"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        assert conn.execute("SELECT revision FROM store").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM audit").fetchone()[0] == 1
        conn.execute("DROP TRIGGER fail_audit")
    assert raw.read_bytes() == original
    assert store.record_execution(**kwargs)["replayed"] is False
    assert store.record_execution(**kwargs)["replayed"] is True


def test_claims_are_compare_and_swap_and_concurrent_registration_is_idempotent(tmp_path):
    store = make_store(tmp_path)
    create_action(store)
    barrier = threading.Barrier(2)

    def claim(number):
        barrier.wait()
        try:
            return store.transition_action(command_id=f"claim{number}", action_id="a1", expected_version=1,
                                           status="claimed", actor=f"operator{number}")
        except ConflictError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, [1, 2]))
    assert sum(result is not None for result in results) == 1
    store.start_attempt(attempt_id="native1", source="native", started_at=AT, actor="operator")
    obs = observation(tmp_path)
    barrier = threading.Barrier(2)

    def register(_):
        barrier.wait()
        return store.record_execution(attempt_id="native1", outcome="complete", observations=[obs],
                                      candidate=candidate(), actor="operator")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(register, [1, 2]))
    assert sorted(result["replayed"] for result in results) == [False, True]
    assert results[0]["revision"] == results[1]["revision"]


def test_unknown_external_effect_can_be_supplemented_without_reexecution(tmp_path):
    store = make_store(tmp_path)
    create_action(store)
    store.transition_action(command_id="claim1", action_id="a1", expected_version=1, status="claimed", actor="operator")
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator", action_id="a1", claim_token="claim1")
    with pytest.raises(ConflictError, match="unknown"):
        store.transition_action(command_id="release1", action_id="a1", expected_version=2, status="ready",
                                 actor="operator", claim_token="claim1", reason="Interrupted")
    unknown = store.record_execution(attempt_id="try1", outcome="unknown", observations=[], actor="operator")
    with pytest.raises(ConflictError, match="complete observation"):
        store.transition_action(command_id="finish1", action_id="a1", expected_version=2, status="completed",
                                 actor="operator", claim_token="claim1", reason="No returned output",
                                 completion={"operation_id": unknown["entity_id"]})
    obs = observation(tmp_path)
    with pytest.raises(ConflictError, match="explicitly reference"):
        store.record_execution(attempt_id="try1", outcome="complete", observations=[obs], actor="operator")
    recovered = store.record_execution(attempt_id="try1", outcome="complete", observations=[obs], actor="operator",
                                       expected_operation=unknown["entity_id"])
    assert recovered["entity_id"] != unknown["entity_id"]
    assert store.page("attempts")["total"] == 1
    assert store.verify_operation(unknown["entity_id"])["outcome"] == "unknown"


def test_read_only_snapshot_paging_and_conditional_experience(tmp_path):
    store = make_store(tmp_path)
    for number in range(5):
        create_action(store, f"a{number}")
    page = store.page("actions", limit=2, status="ready")
    assert (page["total"], page["remaining"], page["has_more"]) == (5, 3, True)
    second = store.page("actions", limit=2, status="ready", cursor=page["next_cursor"])
    third = store.page("actions", limit=2, status="ready", cursor=second["next_cursor"])
    assert [row["id"] for p in (page, second, third) for row in p["items"]] == [f"a{i}" for i in range(5)]
    assert third["remaining"] == 0 and third["next_cursor"] is None
    assert third["revision"] == page["revision"]
    with store._connection() as conn:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM actions")
        create_action(store, "a5")
        assert conn.execute("SELECT count(*) FROM actions").fetchone()[0] == 5
    with pytest.raises(ConflictError, match="snapshot"):
        store.page("actions", status="ready", cursor=page["next_cursor"])
    for bad in ("", "!", "e30=", "null", [], 42):
        with pytest.raises(StoreError):
            store.page("actions", cursor=bad)
    receipt = record(store, tmp_path)
    count = store.page("actions")["total"]
    store.remember(command_id="primitive1", kind="primitive", statement="Observed peer object read",
                    conditions="Same tenant, peer account, recorded session", reopen_when="", next_intent="",
                    evidence=[{"operation_id": receipt["entity_id"], "step": 0}], actor="operator", finding_id="f1")
    assert store.page("experiences")["items"][0]["conditions"] == "Same tenant, peer account, recorded session"
    assert store.page("actions")["total"] == count  # No task manufactured from a primitive.
    refs = store.experience("primitive1")["evidence"]
    expanded = store.execution(refs[0]["operation_id"])
    assert expanded["attempt"]["id"] == "try1"
    assert expanded["observations"][0]["artifacts"][0]["ref"].endswith("response.txt")
    assert store.page("operations")["items"][0]["id"] == receipt["entity_id"]


def test_assessment_and_destination_conflicts_preserve_history(tmp_path):
    store = make_store(tmp_path)
    record(store, tmp_path)
    assessment(store)
    store.decide_delivery(command_id="d1", finding_id="f1", assessment_id="assess1", destination="review",
                          status="eligible", reason="Meets destination requirements", actor="operator", expected_decision=None)
    assessment(store, command_id="assess2", verdict="inconclusive", expected="assess1")
    result = store.finding("f1")
    assert result["assessment"]["verdict"] == "inconclusive"
    assert result["deliveries"][0]["stale"] is True
    with pytest.raises(ConflictError):
        assessment(store, command_id="stale", expected="assess1")
    with pytest.raises(StoreError, match="confirmed"):
        store.decide_delivery(command_id="d2", finding_id="f1", assessment_id="assess2", destination="review",
                              status="eligible", reason="Still want to submit", actor="operator", expected_decision="d1")
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM assessments").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM delivery_decisions").fetchone()[0] == 1


@pytest.mark.parametrize("damage", ["change", "remove"])
def test_registered_artifact_damage_is_not_empty_or_valid(tmp_path, damage):
    store = make_store(tmp_path)
    receipt = record(store, tmp_path)
    path = tmp_path / ".private" / "validation" / "target.test" / "response.txt"
    if damage == "change":
        path.write_text("different bytes")
    else:
        path.unlink()
    with pytest.raises(StoreError, match="registered evidence"):
        store.verify_operation(receipt["entity_id"])
    with pytest.raises(StoreError, match="registered evidence"):
        assessment(store)
    assert store.finding("f1")["assessment"] is None


def test_operation_verification_checks_all_material_in_one_snapshot(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    base = observation(tmp_path)
    observations = []
    for index in range(10):
        path = tmp_path / ".private" / "validation" / "target.test" / f"response-{index}.txt"
        path.write_text(f"Recorded response {index}")
        observations.append({**base, "artifacts": {"response": path.relative_to(tmp_path).as_posix()}})
    store.start_attempt(attempt_id="many-artifacts", source="native", started_at=AT, actor="operator")
    receipt = store.record_execution(attempt_id="many-artifacts", outcome="complete",
                                     observations=observations, actor="operator")
    before = store.binding()
    connections = []
    connect = sqlite3.connect

    def traced_connection(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", traced_connection)
        result = store.verify_operation(receipt["entity_id"])
    assert len(connections) == 1
    assert result["artifact_count"] == 10
    assert result["integrity"] == "valid"
    assert result["semantic_verification"] is False
    path.write_text("Changed final response")
    with pytest.raises(StoreError, match="registered evidence changed"):
        store.verify_operation(receipt["entity_id"])
    assert store.binding() == before


def test_artifact_invalidations_are_append_only_and_authorization_is_derived(tmp_path):
    store = make_store(tmp_path)
    receipt = record(store, tmp_path)
    with sqlite3.connect(store.path) as conn:
        artifact_id = conn.execute("SELECT artifact_id FROM observation_artifacts LIMIT 1").fetchone()[0]
        original = conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()

    unavailable = store.record_artifact_event(
        command_id="artifact-unavailable", artifact_id=artifact_id,
        dimension="availability", state="unavailable", reason="raw file was removed", actor="operator")
    assert not unavailable["replayed"]
    with pytest.raises(StoreError, match="explicitly unavailable"):
        store.verify_operation(receipt["entity_id"])
    status = store.artifact_status(artifact_id)
    assert status["availability"] == "unavailable" and not status["authorized"]

    path = tmp_path / ".private" / "validation" / "target.test" / "response.txt"
    path.write_text('HTTP/1.1 200 OK\r\n\r\n{"owner":"peer"}')
    restored = store.record_artifact_event(
        command_id="artifact-available", artifact_id=artifact_id,
        dimension="availability", state="available", reason="raw file revalidated", actor="operator")
    assert not restored["replayed"]
    store.record_artifact_event(
        command_id="artifact-revoked", artifact_id=artifact_id,
        dimension="provenance", state="revoked", reason="source attribution withdrawn", actor="operator")
    with pytest.raises(StoreError, match="provenance is revoked"):
        store.verify_operation(receipt["entity_id"])
    store.record_artifact_event(
        command_id="artifact-trusted", artifact_id=artifact_id,
        dimension="provenance", state="trusted", reason="source attribution rechecked", actor="operator")
    assert store.verify_operation(receipt["entity_id"])["integrity"] == "valid"
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone() == original
        assert conn.execute("SELECT count(*) FROM artifact_events WHERE artifact_id=?", (artifact_id,)).fetchone()[0] == 4


@pytest.mark.parametrize("field,value", [
    ("endpoint", "https://foreign.test/x"), ("endpoint", "/api/objects"),
    ("endpoint", "https://user:secret@target.test/x"), ("family", ""), ("family", {}),
    ("family", "abc\nxyz"), ("truncated", "false"), ("state_changing", 1),
    ("method", "GET\nInjected"), ("observed_at", "2026-09-20T01:00:00"),
    ("observed_at", "2026-09-19T01:00:00Z"), ("artifacts", {}), ("artifacts", {1: "x"}),
    ("unknown_field", "must not be silently discarded"),
])
def test_malformed_observation_has_no_metadata_side_effects(tmp_path, field, value):
    store = make_store(tmp_path)
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator")
    obs = observation(tmp_path)
    obs[field] = value
    with pytest.raises(ValueError):
        store.record_execution(attempt_id="try1", outcome="complete", observations=[obs], actor="operator")
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM operations").fetchone()[0] == 0
        assert conn.execute("SELECT revision FROM store").fetchone()[0] == 1


def test_partial_and_foreign_evidence_never_confirms(tmp_path):
    store = make_store(tmp_path)
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator")
    obs = observation(tmp_path)
    obs["truncated"] = True
    with pytest.raises(StoreError, match="incomplete"):
        store.record_execution(attempt_id="try1", outcome="complete", observations=[obs], actor="operator")
    store.record_execution(attempt_id="try1", outcome="partial", observations=[obs], candidate=candidate(), actor="operator")
    with pytest.raises(StoreError, match="partial"):
        assessment(store)
    assert store.finding("f1")["assessment"] is None
    foreign = tmp_path / "evidence" / "foreign.test" / "target.test" / "raw.txt"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("not owned by target.test")
    store.start_attempt(attempt_id="try2", source="native", started_at=AT, actor="operator")
    obs["artifacts"]["response"] = str(foreign)
    with pytest.raises(StoreError, match="belong"):
        store.record_execution(attempt_id="try2", outcome="partial", observations=[obs], actor="operator")


def test_store_missing_corrupt_wrong_target_permissions_backup_and_legacy_refusal(tmp_path):
    missing = TargetStore(tmp_path / "missing", "target.test")
    with pytest.raises(StoreError, match="missing"):
        missing.page("actions")
    assert not missing.path.parent.exists()
    store = make_store(tmp_path)
    create_action(store)
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    with store._connection() as snapshot:
        create_action(store, "a2")
        backup = store.backup(tmp_path / "backup.sqlite3")
        assert snapshot.execute("SELECT count(*) FROM actions").fetchone()[0] == 1
    with sqlite3.connect(backup) as conn:
        assert conn.execute("SELECT count(*) FROM actions").fetchone()[0] == 2
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with pytest.raises(FileExistsError):
        store.backup(backup)
    with pytest.raises(FileExistsError):
        store.initialize()
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE store SET target='foreign.test'")
    with pytest.raises(StoreError, match="mismatch"):
        store.page("actions")
    store.path.write_bytes(b"invalid sqlite")
    with pytest.raises(StoreError, match="failure"):
        store.page("actions")
    legacy = TargetStore(tmp_path / "legacy", "target.test")
    legacy.path.parent.mkdir(parents=True)
    (legacy.path.parent / "case_state.json").write_text('{"sessions":[]}')
    with pytest.raises(StoreError, match="legacy"):
        legacy.initialize()
    assert not legacy.path.exists()


def test_store_role_is_recorded_and_never_guessed(tmp_path):
    """One writable backend per target: exclusive creation is primary, a copy is preview."""
    fresh = make_store(tmp_path / "fresh")
    assert fresh.backend() == "primary"

    copied = tmp_path / "copy"
    preview = TargetStore(copied, "target.test", allow_preview=True)
    preview.path.parent.mkdir(parents=True)
    (preview.path.parent / "case_state.json").write_text('{"sessions":[]}')
    preview.initialize(allow_legacy=True)
    assert preview.backend() == "preview"

    # A third role cannot be written at all: the column is a closed set.
    with pytest.raises(StoreError, match="CHECK constraint failed"):
        with preview._connection(write=True) as conn:
            conn.execute("UPDATE store SET backend='shadow'")
    assert preview.backend() == "preview"


def test_read_only_views_answer_facts_on_one_snapshot_without_side_effects(tmp_path):
    store = make_store(tmp_path)
    for number in range(3):
        create_action(store, f"a{number}")
    record(store, tmp_path)
    store.remember(command_id="prim1", kind="primitive", statement="Peer object read works",
                   conditions="Same tenant", reopen_when="", next_intent="",
                   evidence=[{"operation_id": store.finding("f1")["evidence"][0]["operation_id"], "step": 0}],
                   actor="operator")
    store.remember(command_id="neg1", kind="negative", statement="No rate limit on /objects",
                   conditions="Single request; concurrency not tested", reopen_when="When concurrency is exercised",
                   next_intent="", evidence=[{"operation_id": store.finding("f1")["evidence"][0]["operation_id"], "step": 0}],
                   actor="operator")

    with store._connection() as conn:
        before = conn.execute("SELECT revision FROM store").fetchone()[0]
    context = store.context(limit=2)
    assert context["revision"] == before
    assert context["counts"]["actions"] == 3
    assert context["actions"]["total"] == 3 and context["actions"]["remaining"] == 1
    assert [row["kind"] for row in context["primitives"]["items"]] == ["primitive"]
    assert [row["id"] for row in context["failures"]["items"]] == ["neg1"]
    assert context["failures"]["items"][0]["reopen_when"] == "When concurrency is exercised"

    # No ROI/path-word ordering: rows are presented in stable ID order only.
    assert context["actions"]["order"] == "id"
    assert [row["id"] for row in store.failures()["items"]] == ["neg1"]
    assert [row["id"] for row in store.primitives()["items"]] == ["prim1"]

    # Queries never manufacture actions from stored experience and never mutate.
    assert store.page("actions")["total"] == 3
    with store._connection() as conn:
        assert conn.execute("SELECT revision FROM store").fetchone()[0] == before

    # Cursor is bound to the snapshot: a later write invalidates an old cursor.
    cursor = store.context(limit=1)["actions"]["next_cursor"]
    create_action(store, "a9")
    with pytest.raises(ConflictError, match="snapshot"):
        store.page("actions", limit=1, cursor=cursor)


def test_candidates_report_current_posture_without_ranking(tmp_path):
    store = make_store(tmp_path)
    record(store, tmp_path)
    store.remember(command_id="prim1", kind="primitive", statement="Peer object read works",
                   conditions="Same tenant", reopen_when="", next_intent="",
                   evidence=[{"operation_id": store.finding("f1")["evidence"][0]["operation_id"], "step": 0}],
                   actor="operator")
    page = store.candidates(limit=1)
    assert page["order"] == "id" and page["total"] == 1
    assert page["items"][0]["id"] == "f1" and page["items"][0]["assessment"] is None
    assessment(store)
    assert store.candidates()["items"][0]["assessment"]["verdict"] == "confirmed"
    with pytest.raises(StoreError, match="limit"):
        store.candidates(limit=0)
    with pytest.raises(StoreError, match="limit"):
        store.context(limit="all")


def test_observation_result_and_identity_dimensions_are_facts(tmp_path):
    """The store admits authored cell facts without judging the taxonomy itself."""
    store = make_store(tmp_path)
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator")
    obs = observation(tmp_path)
    obs["result"] = "tested-clean"          # normalised, same vocabulary as the ledger
    obs["identity_dimensions"] = {"parameter": "owner", "method": "GET", "future_field": "kept"}
    store.record_execution(attempt_id="try1", outcome="complete", observations=[obs], actor="operator")

    records = store.closure_records()
    assert records["total"] == 1 and records["truncated"] is False
    record = records["records"][0]
    assert record["result"] == "tested_clean"
    # Unknown dimension keys and unknown families are admitted as facts: the
    # identity contract, not admission, decides what completes a cell.
    assert record["identity_dimensions"] == {"future_field": "kept", "method": "GET", "parameter": "owner"}
    assert record["raw_endpoint"] == URL and record["endpoint"] == "/api/objects?owner=peer"
    assert record["evidence_ref"].endswith("response.txt")
    assert record["outcome"] == "complete"

    # A query never derives identity status: that stays the projection's job.
    assert "identity_status" not in record

    # Structure is still checked, and no partial write reaches the store.
    store.start_attempt(attempt_id="try2", source="native", started_at=AT, actor="operator")
    for field, value in (
        ("result", "looks-fine-to-me"),
        ("identity_dimensions", {"method": ["GET"]}),
        ("identity_dimensions", {"method": True}),
        ("identity_dimensions", {f"k{index}": "v" for index in range(17)}),
    ):
        bad = observation(tmp_path)
        bad[field] = value
        with pytest.raises(StoreError):
            store.record_execution(attempt_id="try2", outcome="complete", observations=[bad], actor="operator")
    assert store.closure_records()["total"] == 1


def test_observation_detail_is_open_payload_but_not_a_relationship_key(tmp_path):
    store = make_store(tmp_path)
    store.start_attempt(attempt_id="detail-attempt", source="native", started_at=AT, actor="operator")
    obs = observation(tmp_path)
    obs["detail"] = {"response_status": 200, "signals": ["peer-object"], "future_field": {"enabled": True}}
    receipt = store.record_execution(attempt_id="detail-attempt", outcome="complete",
                                     observations=[obs], actor="operator")
    expanded = store.execution(receipt["entity_id"])
    assert expanded["observations"][0]["detail"] == obs["detail"]
    with sqlite3.connect(store.path) as conn:
        raw = conn.execute("SELECT detail_json FROM observations").fetchone()[0]
    assert raw == '{"future_field":{"enabled":true},"response_status":200,"signals":["peer-object"]}'
    assert store.closure_records()["records"][0]["identity_dimensions"] == {}


def test_closure_records_feed_the_one_shared_projection(tmp_path):
    """Store facts and file-side entries must close exactly the same cells."""
    from tools.closure_projection import build_current_cell_projection

    store = make_store(tmp_path)
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator")
    obs = observation(tmp_path)
    obs["family"] = "Authz"
    obs["result"] = "tested_clean"
    obs["actor"] = "user_a"
    obs["object_scope"] = "admin_object"
    obs["identity_dimensions"] = {"method": "GET", "actor_role": "admin", "object_scope": "admin_object"}
    store.record_execution(attempt_id="try1", outcome="complete", observations=[obs], actor="operator")

    store.start_attempt(attempt_id="try2", source="native", started_at=AT, actor="operator")
    partial = observation(tmp_path)
    partial["family"] = "IDOR"
    partial["result"] = "tested_clean"
    partial["identity_dimensions"] = {"method": "GET", "path_template": "/api/objects"}   # actor_relation/object_scope missing
    store.record_execution(attempt_id="try2", outcome="complete", observations=[partial], actor="operator")

    records = store.closure_records()["records"]
    projection = build_current_cell_projection(records)
    # Only the complete identity closes; the incomplete one stays fail-open.
    assert [cell["vuln_class"] for cell in projection["closed_cells_v2"]] == ["Authz"]
    closed = projection["closed_cells_v2"][0]
    assert closed["identity_v2"]["dimensions"] == {"actor_role": "admin", "method": "GET", "object_scope": "admin_object"}
    assert projection["identity_v2_diagnostics"]["incomplete_count"] == 1

    file_side = [{
        "event_id": "ledger:1", "raw_endpoint": URL, "endpoint": "/api/objects?owner=peer", "method": "GET",
        "vuln_class": "Authz", "result": "tested_clean", "ts": AT, "actor": "user_a", "object_scope": "admin_object",
        "variant": "", "evidence_ref": "evidence/target.test/response.txt",
        "identity_dimensions": {"method": "GET", "actor_role": "admin", "object_scope": "admin_object"},
    }]
    from_store = build_current_cell_projection([dict(record) for record in records])["closed_cells_v2"]
    from_file = build_current_cell_projection(file_side)["closed_cells_v2"]
    assert [cell["identity_v2"] for cell in from_store] == [cell["identity_v2"] for cell in from_file]


def test_closure_records_stay_honest_about_truncation(tmp_path):
    store = make_store(tmp_path)
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator")
    store.record_execution(attempt_id="try1", outcome="complete",
                           observations=[observation(tmp_path), observation(tmp_path)], actor="operator")
    page = store.closure_records(limit=1)
    assert page["total"] == 2 and page["returned"] == 1 and page["truncated"] is True
    with pytest.raises(StoreError, match="limit"):
        store.closure_records(limit=0)


def test_domain_imports_do_not_depend_on_views_executors_or_old_owners():
    tools = Path(__file__).resolve().parents[1] / "tools"
    allowed = {"evidence_identity", "target_paths", "scope_context"}
    for name in ("target_store.py", "evidence_identity.py", "scope_context.py"):
        for node in ast.walk(ast.parse((tools / name).read_text())):
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module.removeprefix("tools.")
                assert not node.module.startswith("memory."), f"legacy owner dependency: {name}"
                if (tools / (module + ".py")).exists():
                    assert module in allowed, f"reverse dependency: {name} imports {module}"


def test_finding_can_exist_before_evidence_and_attach_without_recreation(tmp_path):
    store = make_store(tmp_path)
    claim = candidate()
    kwargs = {"command_id": "create:f1", "finding_id": claim["id"], "actor": "operator",
              **{key: value for key, value in claim.items() if key != "id"}}
    receipt = store.create_finding(**kwargs)
    assert store.create_finding(**kwargs) == {**receipt, "replayed": True}
    original = store.finding("f1")
    assert original["assessment"] is None and original["deliveries"] == [] and original["evidence"] == []
    assert store.page("attempts")["total"] == store.page("operations")["total"] == 0
    assert store.candidates()["items"][0]["id"] == "f1"

    operation = record(store, tmp_path)
    attached = store.finding("f1")
    assert attached["created_at"] == original["created_at"]
    assert attached["evidence"] == [{"operation_id": operation["entity_id"], "step": 0}]
    assert attached["assessment"] is None and store.page("findings")["total"] == 1
    with pytest.raises(ConflictError, match="different claim"):
        store.create_finding(**{**kwargs, "command_id": "create:changed", "claim": "Different claim"})
    assert store.finding("f1")["revision"] == attached["revision"]


def test_unassessed_finding_admission_and_audit_are_atomic(tmp_path):
    store = make_store(tmp_path)
    kwargs = dict(command_id="create:f1", finding_id="f1", endpoint=URL, method="GET",
                  family=FAMILY, title="Unassessed observation", claim="Boundary needs testing", actor="operator")
    with pytest.raises(StoreError, match="belonging"):
        store.create_finding(**{**kwargs, "endpoint": "https://foreign.test/object"})
    with sqlite3.connect(store.path) as conn:
        conn.execute("""CREATE TRIGGER fail_claim_audit BEFORE INSERT ON audit
            WHEN NEW.command='create_finding' BEGIN SELECT RAISE(ABORT, 'claim audit failed'); END""")
    with pytest.raises(StoreError, match="claim audit failed"):
        store.create_finding(**kwargs)
    assert store.page("findings")["total"] == 0
    assert store.context()["revision"] == 0
    with sqlite3.connect(store.path) as conn:
        conn.execute("DROP TRIGGER fail_claim_audit")
    assert store.create_finding(**kwargs)["revision"] == 1


def test_preview_writes_require_explicit_isolated_import(tmp_path):
    normal = TargetStore(tmp_path, "target.test")
    normal.initialize(allow_legacy=True)
    assert target_backend(tmp_path, "target.test") == "preview"
    with pytest.raises(StoreError, match="explicit isolated migration"):
        create_action(normal)
    assert normal.page("actions")["total"] == 0
    importer = TargetStore(tmp_path, "target.test", allow_preview=True)
    create_action(importer)
    assert normal.page("actions")["total"] == 1
    assert not normal.fence_path.exists()
    with pytest.raises(StoreError, match="boolean"):
        TargetStore(tmp_path, "target.test", allow_preview="yes")


def test_runtime_store_hides_migration_role_and_rejects_preview(tmp_path):
    untouched = tmp_path / "untouched"
    with pytest.raises(StoreError, match="not initialized.*explicit init or legacy import"):
        runtime_store(untouched, "target.test")
    assert not untouched.exists()

    preview = TargetStore(tmp_path, "preview.test", allow_preview=True)
    preview.initialize(allow_legacy=True)
    with pytest.raises(StoreError, match="runtime store is not active"):
        runtime_store(tmp_path, "preview.test")

    active = make_store(tmp_path)
    assert runtime_store(tmp_path, active.target).path == active.path

    active.path.unlink()
    with pytest.raises(StoreError, match="fenced target store missing"):
        runtime_store(tmp_path, active.target)


def test_concurrent_explicit_initialization_is_idempotent(tmp_path):
    from tools.target_store import initialize_target_store

    target = "concurrent-init.test"

    def initialize_and_read(_):
        backend = initialize_target_store(tmp_path, target)
        return backend, TargetStore(tmp_path, target).binding()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(initialize_and_read, range(8)))

    assert {backend for backend, _ in results} == {"primary"}
    assert {binding["store_id"] for _, binding in results} == {results[0][1]["store_id"]}
    assert {binding["revision"] for _, binding in results} == {0}


def test_explicit_initialization_rejects_legacy_target_profile(tmp_path, monkeypatch):
    from memory.target_profile import target_profile_path
    from tools.target_store import initialize_target_store

    memory_dir = tmp_path / "external-hunt-memory"
    monkeypatch.setenv("HUNT_MEMORY_DIR", str(memory_dir))
    profile = target_profile_path(memory_dir, "profiled.test")
    profile.parent.mkdir(parents=True)
    profile.write_text('{"target":"profiled.test"}', encoding="utf-8")

    with pytest.raises(StoreError, match="legacy target state exists"):
        initialize_target_store(tmp_path, "profiled.test")

    store = TargetStore(tmp_path, "profiled.test")
    assert not store.path.exists()
    assert not store.fence_path.exists()


@pytest.mark.parametrize("mask", [0o022, 0o077], ids=["umask022", "umask077"])
@pytest.mark.parametrize("lock_name", ["switch", "phase", "session", "checkpoint"])
def test_lock_before_initialization_creates_private_target_directory(tmp_path, monkeypatch, mask, lock_name):
    from tools.checkpoint import checkpoint_witness_lock
    from tools.runtime_state import runtime_phase_lock, runtime_state_mutation_lock
    from tools.target_store import initialize_target_store, target_switch_lock

    monkeypatch.setenv("HUNT_MEMORY_DIR", str(tmp_path / "hunt-memory"))
    target = "https://Lock-First.test:8443/path"
    store = TargetStore(tmp_path, target)
    lock, args = {
        "switch": (target_switch_lock, ()),
        "phase": (runtime_phase_lock, ("recon",)),
        "session": (runtime_state_mutation_lock, ()),
        "checkpoint": (checkpoint_witness_lock, ()),
    }[lock_name]
    previous_mask = os.umask(mask)
    try:
        with lock(tmp_path, target, *args):
            assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
            assert not store.path.exists() and not store.fence_path.exists()
        assert store.path.parent == tmp_path / "state" / "lock-first.test:8443"
        assert not store.path.exists() and not store.fence_path.exists()
        assert initialize_target_store(tmp_path, target) == "primary"
        assert store.binding()["revision"] == 0
        assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    finally:
        os.umask(previous_mask)


def test_explicit_initialization_does_not_repair_unsafe_target_directory(tmp_path):
    from tools.target_store import initialize_target_store

    store = TargetStore(tmp_path, "unsafe-dir.test")
    store.path.parent.mkdir(parents=True)
    store.path.parent.chmod(0o755)

    with pytest.raises(StoreError, match="requires mode 0700"):
        initialize_target_store(tmp_path, store.target)
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o755
    assert not store.path.exists() and not store.fence_path.exists()

    store.path.parent.chmod(0o700)
    initialize_target_store(tmp_path, store.target)
    store.path.parent.chmod(0o755)
    with pytest.raises(StoreError, match="requires mode 0700"):
        initialize_target_store(tmp_path, store.target)
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o755


@pytest.mark.parametrize("lock_name", ["switch", "mutation", "phase", "session", "checkpoint"])
@pytest.mark.parametrize("obstacle", [
    "state_symlink", "target_symlink", "locks_symlink", "leaf_symlink", "fifo", "hardlink",
])
def test_target_locks_reject_unsafe_paths_without_external_mutation(tmp_path, monkeypatch, lock_name, obstacle):
    from tools.checkpoint import checkpoint_witness_lock
    from tools.runtime_state import runtime_phase_lock, runtime_state_mutation_lock
    from tools.target_store import target_mutation_lock, target_switch_lock

    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"external bytes must survive\n")
    sentinel.chmod(0o644)
    target = "lock-path.test"
    lock, args, filename = {
        "switch": (target_switch_lock, (), "target-switch.lock"),
        "mutation": (target_mutation_lock, (), "target.lock"),
        "phase": (runtime_phase_lock, ("recon",), "recon.lock"),
        "session": (runtime_state_mutation_lock, (), "session.lock"),
        "checkpoint": (checkpoint_witness_lock, (), "checkpoint.lock"),
    }[lock_name]
    lock_path = root / "state" / target / "locks" / filename
    if obstacle.endswith("symlink"):
        blocked_path = {
            "state_symlink": root / "state",
            "target_symlink": root / "state" / target,
            "locks_symlink": lock_path.parent,
            "leaf_symlink": lock_path,
        }[obstacle]
        blocked_path.parent.mkdir(parents=True)
        blocked_path.symlink_to(sentinel if obstacle == "leaf_symlink" else outside)
    else:
        lock_path.parent.mkdir(parents=True)
        blocked_path = lock_path
        if obstacle == "hardlink":
            os.link(sentinel, lock_path)
        else:
            os.mkfifo(lock_path)
            original_open = os.open

            def nonblocking_open(path, flags, *args, **kwargs):
                if path == filename:
                    assert flags & os.O_NONBLOCK, "FIFO must never be opened in blocking mode"
                return original_open(path, flags, *args, **kwargs)

            monkeypatch.setattr(os, "open", nonblocking_open)

    def outside_snapshot():
        return {
            path.relative_to(outside): (path.stat(), path.read_bytes() if path.is_file() else None)
            for path in [outside, *outside.rglob("*")]
        }

    before = outside_snapshot()
    blocked_inode = blocked_path.lstat().st_ino
    with pytest.raises(OSError):
        with lock(root, target, *args):
            pytest.fail("unsafe lock acquired")
    # Reading may update atime; compare inode, mode, links, content and entries.
    after = outside_snapshot()
    assert after.keys() == before.keys()
    for path, (info, content) in before.items():
        current_info, current_content = after[path]
        assert (current_info.st_ino, current_info.st_mode, current_info.st_nlink, current_content) == (
            info.st_ino, info.st_mode, info.st_nlink, content,
        )
    assert blocked_path.lstat().st_ino == blocked_inode
    assert not (root / "state" / target / "metadata.sqlite3").exists()
    assert not (root / "state" / target / "legacy-frozen.json").exists()


def test_cutover_lock_preserves_existing_legacy_directory_modes_and_inode(tmp_path):
    lock_path = tmp_path / "state" / "legacy.test" / "locks" / "target-switch.lock"
    lock_path.parent.mkdir(parents=True)
    for path in (lock_path.parent.parent, lock_path.parent):
        path.chmod(0o755)
    lock_path.write_bytes(b"existing lock inode\n")
    lock_path.chmod(0o644)
    inode = lock_path.stat().st_ino
    with target_cutover_lock(tmp_path, "legacy.test"):
        assert lock_path.stat().st_ino == inode
        assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600
    assert lock_path.read_bytes() == b"existing lock inode\n"
    assert stat.S_IMODE(lock_path.parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(lock_path.parent.parent.stat().st_mode) == 0o755
    assert not (lock_path.parent.parent / "metadata.sqlite3").exists()
    assert not (lock_path.parent.parent / "legacy-frozen.json").exists()


@pytest.mark.parametrize("filename", ["", ".", "..", "../escape.lock", "/escape.lock", "nested/lock", "bad\x00lock"])
def test_target_lock_filename_rejected_before_directory_creation(tmp_path, filename):
    from tools.target_paths import open_target_lock_file

    root = tmp_path / "absent"
    with pytest.raises(ValueError, match="single basename"):
        open_target_lock_file(root, "target.test", filename)
    assert not root.exists()


def test_target_store_init_cli_reports_success_and_rejects_legacy(tmp_path):
    import subprocess
    import sys

    script = Path(__file__).resolve().parents[1] / "tools" / "target_store.py"
    fresh = subprocess.run(
        [sys.executable, str(script), "init", "--store", "--target", "cli-init.test",
         "--repo-root", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    replay = subprocess.run(
        [sys.executable, str(script), "init", "--store", "--target", "cli-init.test",
         "--repo-root", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )

    assert fresh.returncode == replay.returncode == 0
    assert json.loads(fresh.stdout) == {"backend": "primary", "target": "cli-init.test"}
    assert json.loads(replay.stdout) == json.loads(fresh.stdout)

    legacy = tmp_path / "state" / "cli-legacy.test" / "case_state.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"sessions":[]}', encoding="utf-8")
    refused = subprocess.run(
        [sys.executable, str(script), "init", "--store", "--target", "cli-legacy.test",
         "--repo-root", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert refused.returncode == 2
    assert "legacy target state exists" in refused.stderr
    assert not (legacy.parent / "metadata.sqlite3").exists()
    assert legacy.read_text(encoding="utf-8") == '{"sessions":[]}'


def test_target_store_init_cli_help_has_no_target_side_effects(tmp_path):
    import subprocess
    import sys

    script = Path(__file__).resolve().parents[1] / "tools" / "target_store.py"
    result = subprocess.run(
        [sys.executable, str(script), "init", "--help", "--repo-root", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert not (tmp_path / "state").exists()


def _make_v8_store(root, monkeypatch):
    import tools.target_store as module

    v8_schema = module._SCHEMA.replace(module._COVERAGE_REVIEW_SCHEMA, "").replace(
        "    created_at TEXT NOT NULL,\n    active_goal TEXT NOT NULL DEFAULT ''\n",
        "    created_at TEXT NOT NULL\n",
        1,
    ).replace(
        "'primitive','negative','hypothesis','handoff','note'",
        "'primitive','negative','hypothesis','handoff'",
        1,
    )
    assert v8_schema != module._SCHEMA
    store = TargetStore(root, "v8-memory.test")
    with monkeypatch.context() as patch:
        patch.setattr(module, "_SCHEMA", v8_schema)
        patch.setattr(module, "SCHEMA_VERSION", 8)
        store.initialize()
    store.remember(command_id="v8-hypothesis", kind="hypothesis", statement="Compare peer object",
                   conditions="Both actors have sessions", reopen_when="", next_intent="Compare response",
                   evidence=[], actor="operator")
    store.create_action(command_id="v8-work", action_id="v8-work", kind="work",
                        subject={"experience_id": "v8-hypothesis"}, intent="Review hypothesis",
                        execution_key="v8-work", actor="operator")
    return store


def test_memory_schema_upgrade_preserves_v8_facts_and_requires_explicit_backup(tmp_path, monkeypatch):
    import subprocess
    import sys

    store = _make_v8_store(tmp_path, monkeypatch)
    old_revision = store.binding()["revision"]
    assert store.page("experiences")["total"] == 1
    with pytest.raises(StoreError, match="upgrade required"):
        store.active_goal()
    with pytest.raises(StoreError, match="upgrade required"):
        store.remember(command_id="v8-note", kind="note", statement="Unverified note",
                       conditions="unknown", reopen_when="", next_intent="", evidence=[], actor="operator")

    backup = tmp_path / "memory-v8-backup.sqlite3"
    script = Path(__file__).resolve().parents[1] / "tools" / "target_store.py"
    upgraded = subprocess.run(
        [sys.executable, str(script), "upgrade-memory", "--target", store.target,
         "--repo-root", str(tmp_path), "--backup", str(backup)],
        capture_output=True, text=True, check=False,
    )
    assert upgraded.returncode == 0, upgraded.stderr
    result = json.loads(upgraded.stdout)
    assert result["status"] == "upgraded" and result["revision"] == old_revision + 1
    assert backup.is_file() and stat.S_IMODE(backup.stat().st_mode) == 0o600
    with sqlite3.connect(backup) as conn:
        assert conn.execute("SELECT schema_version,revision FROM store").fetchone() == (8, old_revision)
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("SELECT count(*) FROM experiences").fetchone()[0] == 1
    assert store.action("v8-work")["subject_experience_id"] == "v8-hypothesis"
    assert store.active_goal() == ""
    receipt = store.set_active_goal(command_id="set-goal", goal="Map authorization boundary",
                                    actor="operator", expected_revision=old_revision + 1)
    assert receipt["revision"] == old_revision + 2
    assert store.active_goal() == "Map authorization boundary"
    assert store.set_active_goal(command_id="set-goal", goal="Map authorization boundary",
                                 actor="operator", expected_revision=old_revision + 1)["replayed"]
    with pytest.raises(ConflictError, match="revision changed"):
        store.set_active_goal(command_id="stale-goal", goal="Stale intent", actor="operator",
                              expected_revision=old_revision + 1)
    assert store.active_goal() == "Map authorization boundary"
    store.remember(command_id="new-note", kind="note", statement="Header may affect routing",
                   conditions="unknown", reopen_when="", next_intent="Inspect response",
                   evidence=[], actor="operator")
    assert store.experience("new-note")["kind"] == "note"
    assert store.upgrade_memory_schema(tmp_path / "unused-backup.sqlite3")["status"] == "already_current"
    assert not (tmp_path / "unused-backup.sqlite3").exists()


def test_memory_schema_upgrade_failure_rolls_back_and_keeps_verified_backup(tmp_path, monkeypatch):
    import tools.target_store as module

    store = _make_v8_store(tmp_path, monkeypatch)
    before = store.binding()
    backup = tmp_path / "memory-v8-failed-backup.sqlite3"
    with monkeypatch.context() as patch:
        patch.setattr(module, "_digest", lambda value: (_ for _ in ()).throw(RuntimeError("injected failure")))
        with pytest.raises(RuntimeError, match="injected failure"):
            store.upgrade_memory_schema(backup)

    assert backup.is_file()
    with sqlite3.connect(backup) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == 8
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == 8
        assert not any(row[1] == "active_goal" for row in conn.execute("PRAGMA table_info(store)"))
        assert not any(row[0] == "experiences_next" for row in conn.execute("SELECT name FROM sqlite_master"))
    assert store.binding() == before
    assert store.page("experiences")["total"] == 1


def test_experience_page_filters_before_limit_and_binds_cursor(tmp_path):
    store = make_store(tmp_path)
    for index in range(7):
        store.remember(command_id=f"note-{index}", kind="note",
                       statement=f"Candidate {index}",
                       conditions="basket flow" if index < 6 else "unrelated flow",
                       reopen_when="", next_intent="Compare peer response",
                       evidence=[], actor="operator")

    first = store.experience_page(kinds=["note"], query="basket", limit=5)
    assert first["total"] == 6 and first["remaining"] == 1 and first["has_more"]
    assert len(first["items"]) == 5
    assert all(item["conditions"] == "basket flow" and item["evidence"] == []
               for item in first["items"])
    second = store.experience_page(kinds=["note"], query="basket", limit=5,
                                   cursor=first["next_cursor"])
    assert len(second["items"]) == 1 and second["remaining"] == 0
    assert set(item["id"] for item in first["items"] + second["items"]) == {
        f"note-{index}" for index in range(6)
    }
    with pytest.raises(ConflictError, match="filter or snapshot"):
        store.experience_page(kinds=["hypothesis"], query="basket", cursor=first["next_cursor"])
    with pytest.raises(StoreError, match="malformed experience cursor"):
        store.experience_page(cursor="not-base64")
    store.remember(command_id="later-note", kind="note", statement="Later candidate",
                   conditions="basket flow", reopen_when="", next_intent="",
                   evidence=[], actor="operator")
    with pytest.raises(ConflictError, match="filter or snapshot"):
        store.experience_page(kinds=["note"], query="basket", cursor=first["next_cursor"])


def test_memory_context_uses_one_snapshot_during_concurrent_write(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store.set_active_goal(command_id="initial-goal", goal="Original", actor="operator", expected_revision=0)
    before = store.binding()
    original_page = store._experience_page_conn

    def write_between_reads(conn, meta, **kwargs):
        store.set_active_goal(command_id="new-goal", goal="Changed", actor="operator",
                              expected_revision=before["revision"])
        store.remember(command_id="new-note", kind="note", statement="Changed context",
                       conditions="new session", reopen_when="", next_intent="", evidence=[], actor="operator")
        return original_page(conn, meta, **kwargs)

    monkeypatch.setattr(store, "_experience_page_conn", write_between_reads)
    view = store.memory_context(limit=5)
    assert view["revision"] == view["experiences"]["revision"] == before["revision"]
    assert view["active_goal"] == "Original"
    assert view["experiences"]["total"] == 0
    assert view["experiences"]["items"] == []
    assert store.active_goal() == "Changed"
    assert store.experience_page(limit=5)["total"] == 1


def test_primary_fence_survives_database_loss_and_blocks_reinitialization(tmp_path):
    untouched = tmp_path / "untouched"
    assert target_backend(untouched, "target.test") == "legacy"
    assert not untouched.exists()
    store = make_store(tmp_path)
    assert target_backend(tmp_path, "target.test") == "primary"
    assert stat.S_IMODE(store.fence_path.stat().st_mode) == 0o600
    fence = store.fence_path.read_bytes()
    store.path.unlink()
    with pytest.raises(StoreError, match="fenced target store missing"):
        target_backend(tmp_path, "target.test")
    with pytest.raises(StoreError, match="explicit recovery"):
        store.initialize()
    assert store.fence_path.read_bytes() == fence and not store.path.exists()


@pytest.mark.parametrize("damage", ["missing", "invalid-json", "foreign-target", "foreign-store", "permissions", "symlink", "fifo"])
def test_primary_fence_damage_is_never_a_legacy_fallback(tmp_path, damage):
    import os

    store = make_store(tmp_path)
    if damage in {"missing", "symlink", "fifo"}:
        store.fence_path.unlink()
        if damage == "symlink":
            store.fence_path.symlink_to(tmp_path / "absent")
        elif damage == "fifo":
            os.mkfifo(store.fence_path, 0o600)
    elif damage == "permissions":
        store.fence_path.chmod(0o644)
    elif damage == "invalid-json":
        store.fence_path.write_text("{")
    else:
        fence = json.loads(store.fence_path.read_text())
        fence["target" if damage == "foreign-target" else "store_id"] = "foreign.test" if damage == "foreign-target" else "0" * 32
        store.fence_path.write_text(json.dumps(fence))
    with pytest.raises(StoreError, match="fence"):
        target_backend(tmp_path, "target.test")
    with pytest.raises(StoreError, match="fence"):
        create_action(store)


def test_initialization_failure_retains_recovery_fence(tmp_path, monkeypatch):
    import tools.target_store as module

    store = TargetStore(tmp_path, "target.test")
    monkeypatch.setattr(module, "_SCHEMA", "invalid SQL")
    with pytest.raises(StoreError):
        store.initialize()
    assert store.fence_path.is_file() and not store.path.exists()
    with pytest.raises(StoreError, match="restore the current store"):
        target_backend(tmp_path, "target.test")


def create_work(store, action_id="read1", **kwargs):
    return store.create_action(command_id="create:" + action_id, action_id=action_id,
                               intent="Read source and record the relevant preconditions", kind="work",
                               execution_key=action_id, actor="operator", **kwargs)


def claim_work(store, action_id="read1"):
    store.transition_action(command_id="claim:" + action_id, action_id=action_id, expected_version=1,
                             status="claimed", actor="operator")


def test_non_execution_work_records_artifact_without_fabricating_http_evidence(tmp_path):
    store = make_store(tmp_path)
    source = tmp_path / "recon" / "target.test" / "source.txt"
    source.parent.mkdir(parents=True)
    source.write_text("Resource access requires a tenant context.")
    created = create_work(store, subject={"artifact": str(source)})
    assert create_work(store, subject={"artifact": str(source)}) == {**created, "replayed": True}
    action = store.action("read1")
    assert action["kind"] == "work" and action["endpoint"] is None and action["family"] is None
    assert action["subject_artifact"]["ref"] == "recon/target.test/source.txt"
    claim_work(store)
    with pytest.raises(StoreError, match="only execution"):
        store.start_attempt(attempt_id="fake-http", source="reader", started_at=AT, actor="operator",
                            action_id="read1", claim_token="claim:read1")
    output = tmp_path / "evidence" / "target.test" / "source-review.md"
    output.parent.mkdir(parents=True)
    output.write_text("The source requires a tenant context; the live behavior has not been exercised.")
    kwargs = dict(command_id="finish:read1", action_id="read1", expected_version=2, status="completed",
                  actor="operator", claim_token="claim:read1", reason="Source review saved",
                  completion={"artifact": str(output)})
    receipt = store.transition_action(**kwargs)
    assert store.transition_action(**kwargs) == {**receipt, "replayed": True}
    action = store.action("read1")
    assert action["status"] == "completed" and action["version"] == 3
    assert action["completion"]["claim_token"] == "claim:read1"
    assert action["completion"]["action_version"] == 2
    assert action["completion"]["artifact"]["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert store.page("attempts")["total"] == store.page("operations")["total"] == store.page("findings")["total"] == 0
    assert store.closure_records()["total"] == 0


def test_work_receipt_must_belong_to_current_action_claim(tmp_path):
    store = make_store(tmp_path)
    create_work(store, subject={"target": "target.test"})
    create_work(store, "read2", subject={"url": URL})
    claim_work(store)
    remember = dict(kind="handoff", statement="Source review identified a tenant precondition",
                    conditions="Static source only, no execution", reopen_when="", next_intent="",
                    evidence=[], actor="operator", action_id="read1")
    receipt = store.remember(command_id="notes:read1", **remember)
    assert store.action("read1")["status"] == "claimed"  # Recording work never resolves it.
    finish = dict(command_id="finish:read1", action_id="read1", expected_version=2, status="completed",
                  actor="operator", claim_token="claim:read1", reason="Preconditions recorded")
    store.remember(command_id="notes:read2", **{**remember, "action_id": "read2"})
    store.remember(command_id="notes:other-actor", **{**remember, "actor": "other-operator"})
    for wrong in ("missing", "claim:read1", "create:read1", "notes:read2", "notes:other-actor"):
        with pytest.raises(ConflictError, match="current claim"):
            store.transition_action(**finish, completion={"command_id": wrong})
    store.transition_action(command_id="release:read1", action_id="read1", expected_version=2, status="ready",
                             actor="operator", claim_token="claim:read1", reason="Pause before completion")
    store.transition_action(command_id="reclaim:read1", action_id="read1", expected_version=3,
                             status="claimed", actor="operator")
    finish.update(expected_version=4, claim_token="reclaim:read1")
    with pytest.raises(ConflictError, match="current claim"):
        store.transition_action(**finish, completion={"command_id": receipt["command_id"]})
    store.remember(command_id="notes:current", **remember)
    store.transition_action(**finish, completion={"command_id": "notes:current"})
    assert store.action("read1")["completion"]["command_id"] == "notes:current"
    assert store.page("operations")["total"] == 0


@pytest.mark.parametrize("subject", [None, {}, {"url": URL, "target": "target.test"},
    {"unknown": "x"}, {"target": "foreign.test"}, {"url": "https://foreign.test/x"},
    {"finding_id": "missing"}, {"experience_id": "missing"}, {"artifact": "evidence/foreign.test/raw"}])
def test_work_subject_rejects_missing_malformed_or_foreign_references(tmp_path, subject):
    store = make_store(tmp_path)
    with pytest.raises(StoreError):
        create_work(store, subject=subject)
    assert store.context()["revision"] == 0
    assert store.page("actions")["total"] == 0


def test_action_kind_is_explicit_and_context_entity_references_are_real(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(StoreError):
        store.create_action(command_id="bad", action_id="bad", intent="Read source",
                            execution_key="bad", actor="operator")
    with pytest.raises(StoreError, match="not execution endpoint"):
        create_work(store, subject={"target": "target.test"}, endpoint=URL, family=FAMILY)
    store.create_finding(command_id="create:f1", finding_id="f1", actor="operator",
                         **{k: v for k, v in candidate().items() if k != "id"})
    create_work(store, subject={"finding_id": "f1"})
    store.remember(command_id="context1", kind="hypothesis", statement="Tenant is a prerequisite",
                    conditions="Unverified source reading", reopen_when="", next_intent="", evidence=[], actor="operator")
    create_work(store, "read2", subject={"experience_id": "context1"})
    assert store.action("read1")["subject_finding_id"] == "f1"
    assert store.action("read2")["subject_experience_id"] == "context1"
    assert store.finding("f1")["assessment"] is None
    assert store.page("actions")["total"] == 2


def test_completion_proof_and_audit_roll_back_together(tmp_path):
    store = make_store(tmp_path)
    create_work(store, subject={"target": "target.test"})
    claim_work(store)
    artifact = tmp_path / "reports" / "target.test" / "review.md"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("A bounded review result, not an external submission.")
    finish = dict(command_id="finish", action_id="read1", expected_version=2, status="completed",
                  actor="operator", claim_token="claim:read1", reason="Review saved")
    for invalid in (None, {}, {"artifact": str(artifact), "command_id": "claim:read1"}, {"unknown": "value"}):
        with pytest.raises(StoreError):
            store.transition_action(**finish, completion=invalid)
    before = store.context()["revision"]
    with sqlite3.connect(store.path) as conn:
        conn.execute("""CREATE TRIGGER fail_complete_audit BEFORE INSERT ON audit
            WHEN NEW.command_id='finish' BEGIN SELECT RAISE(ABORT, 'completion audit failed'); END""")
    with pytest.raises(StoreError, match="completion audit failed"):
        store.transition_action(**finish, completion={"artifact": str(artifact)})
    assert store.action("read1")["completion"] is None
    assert store.action("read1")["status"] == "claimed" and store.context()["revision"] == before
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 0
        conn.execute("DROP TRIGGER fail_complete_audit")
    assert artifact.read_text() == "A bounded review result, not an external submission."
    store.transition_action(**finish, completion={"artifact": str(artifact)})


def test_execution_completion_rejects_unbound_stale_and_damaged_evidence(tmp_path):
    store = make_store(tmp_path)
    create_action(store)
    store.transition_action(command_id="claim1", action_id="a1", expected_version=1, status="claimed", actor="operator")
    other = record(store, tmp_path, attempt_id="unbound")
    obs = observation(tmp_path)
    finish = dict(command_id="finish", action_id="a1", expected_version=2, status="completed", actor="operator",
                  claim_token="claim1", reason="Comparison recorded")
    for proof in ({"operation_id": other["entity_id"]}, {"artifact": obs["artifacts"]["response"]}):
        with pytest.raises(ConflictError, match="complete observation"):
            store.transition_action(**finish, completion=proof)
    store.start_attempt(attempt_id="bound", source="native", started_at=AT, actor="operator",
                        action_id="a1", claim_token="claim1")
    original = store.record_execution(attempt_id="bound", outcome="complete", observations=[obs], actor="operator")
    current = store.record_execution(attempt_id="bound", outcome="complete", observations=[obs], actor="operator",
                                     expected_operation=original["entity_id"])
    with pytest.raises(ConflictError, match="complete observation"):
        store.transition_action(**finish, completion={"operation_id": original["entity_id"]})
    raw = tmp_path / obs["artifacts"]["response"]
    before = raw.read_bytes()
    raw.write_text("changed after registration")
    with pytest.raises(StoreError, match="registered evidence changed"):
        store.transition_action(**finish, completion={"operation_id": current["entity_id"]})
    assert store.action("a1")["status"] == "claimed"
    raw.write_bytes(before)
    store.transition_action(**finish, completion={"operation_id": current["entity_id"]})
    assert store.action("a1")["completion"]["operation_id"] == current["entity_id"]


def test_unsupported_schema_never_auto_upgrades_or_reinitializes(tmp_path):
    store = make_store(tmp_path)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE store SET schema_version=3")
    before = store.fence_path.read_bytes()
    with pytest.raises(StoreError, match="schema mismatch"):
        store.action("missing")
    with pytest.raises(FileExistsError):
        store.initialize()
    assert store.fence_path.read_bytes() == before
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == 3


@pytest.mark.parametrize("field,value", [("command_id", " padded-id "), ("actor", " operator ")])
@pytest.mark.parametrize("command", ["create_action", "transition_action", "remember"])
def test_command_identity_cannot_diverge_between_facts_and_audit(tmp_path, field, value, command):
    store = make_store(tmp_path)
    create_work(store, subject={"target": "target.test"})
    kwargs = {
        "create_action": dict(action_id="a2", intent="Read context", execution_key="a2", kind="work",
                              subject={"target": "target.test"}),
        "transition_action": dict(action_id="read1", expected_version=1, status="claimed"),
        "remember": dict(kind="handoff", statement="Recorded preconditions", conditions="Source only",
                         reopen_when="", next_intent="", evidence=[], action_id="read1"),
    }[command]
    before = store.context()
    with pytest.raises(StoreError, match="surrounding whitespace"):
        getattr(store, command)(**{**kwargs, "command_id": "new-command", "actor": "operator", field: value})
    assert store.context() == before
    assert store.action("read1")["status"] == "ready"


@pytest.mark.parametrize("writer", ["store", "queue_adapter"])
def test_exclusive_cutover_lock_blocks_target_mutations(tmp_path, writer):
    store = make_store(tmp_path)
    entered = threading.Event()

    def mutate():
        entered.set()
        if writer == "store":
            create_action(store)
        else:
            add_manual_action(
                tmp_path,
                target=store.target,
                action_type="manual-review",
                evidence="Explicit operator request",
                next_question="What does the stored material show?",
                action="Review the target-owned material.",
            )

    target = store.target
    with target_cutover_lock(tmp_path, target):
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(mutate)
        assert entered.wait(timeout=1)
        assert not future.done()
    try:
        future.result(timeout=1)
    finally:
        pool.shutdown(wait=True)
    assert store.page("actions")["total"] == 1
    assert not (tmp_path / "state" / store.target / "action_queue.json").exists()
