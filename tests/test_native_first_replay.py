"""Offline request-pair → Store → exact closure replay; never opens a socket."""
from copy import deepcopy
from pathlib import Path
import sys
import sqlite3
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]

from tools import validation_runner as runner
from tools.autopilot_state import _coverage_terminal_evidence
from tools.closure_projection import build_current_cell_projection
from tools.closure_resolver import ClosureResolver
from tools.coverage_matrix import _empty_cells, read_matrix
from tools.current_truth import current_cell_projection
from tools.identity_contract import ClosureCellKey, EndpointKey, FAMILY_POLICIES
from tools import target_store
from tools.target_store import TargetStore
from tools.target_migration import _ledger_observation


def response(**kw):
    body = '{"id":1}' if kw["url"].endswith("/1") else '{"id":2}'
    return {"url": kw["url"], "method": "GET", "status": 200, "reason": "OK",
            "headers": {"Content-Type": "application/json"}, "body": body,
            "request_text": f"GET {urlsplit(kw['url']).path} HTTP/1.1\nHost: fixture.test\n",
            "response_text": f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{body}"}


def test_family_isolation():
    for family, fields in FAMILY_POLICIES.items():
        dimensions = {field: "GET" if field == "method" else f"{field}_a" for field in fields}
        dimensions["method"] = "GET"
        key = ClosureCellKey(EndpointKey("https://fixture.test/fixture"), family, dimensions, "explicit_check")
        entry = {"event_id": "fixture:0", "endpoint": "https://fixture.test/fixture", "method": "GET", "vuln_class": family,
                 "identity_status": "complete", "evidence_role": "subject",
                 "identity_v2": key.to_dict(), "identity_technique": "explicit_check",
                 "result": "tested_clean", "outcome": "complete"}
        projection = build_current_cell_projection([entry])
        resolver = ClosureResolver(projection)
        assert resolver.is_closure_closed(key), family
        assert not resolver.is_cell_closed("/fixture", family), family
        for field in fields:
            other = ClosureCellKey(key.endpoint_key, family, {**dimensions, field: "POST" if field == "method" else "different"}, "explicit_check")
            assert not resolver.is_closure_closed(other), (family, field)
        assert build_current_cell_projection([entry]) == projection


def test_upgrade_and_import():
    with TemporaryDirectory() as temp:
        root = Path(temp)
        store = TargetStore(root, "legacy.test")
        schema = "\n".join(line for line in target_store._SCHEMA.splitlines()
                           if not line.strip().startswith(("identity_status TEXT", "identity_technique TEXT", "identity_v2 TEXT")))
        with patch.object(target_store, "_SCHEMA", schema), patch.object(target_store, "SCHEMA_VERSION", 10):
            store.initialize()
        raw = root / "evidence/legacy.test/raw.txt"
        raw.parent.mkdir(parents=True)
        raw.write_text("HTTP/1.1 200 OK\n\nlegacy evidence")
        entry = {"endpoint": "/objects/1", "method": "GET", "vuln_class": "IDOR",
                 "ts": "2026-09-29T00:00:00Z", "result": "tested_clean",
                 "evidence_ref": raw.relative_to(root).as_posix(), "state_changing": False}
        observation, reason = _ledger_observation(entry, "https://legacy.test")
        assert not reason
        store.start_attempt(attempt_id="legacy", source="native", started_at=entry["ts"], actor="operator")
        receipt = store.record_execution(attempt_id="legacy", outcome="complete",
                                         observations=[observation], actor="operator")
        before = store.execution(receipt["entity_id"])
        assert not current_cell_projection(root, store.target)["projection"]["closed_cells_v2"]
        with sqlite3.connect(store.path) as conn:
            original = conn.execute("SELECT * FROM observations").fetchall()
            columns = [r[1] for r in conn.execute("PRAGMA table_info(observations)")]
        backup = root / "schema10.sqlite3"
        assert store.upgrade_schema(backup)["status"] == "upgraded"
        assert store.upgrade_schema(root / "unused.sqlite3")["status"] == "already_current"
        with sqlite3.connect(store.path) as conn:
            assert conn.execute("SELECT " + ",".join(columns) + " FROM observations").fetchall() == original
            assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == 11
        with sqlite3.connect(backup) as conn:
            assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == 10
        assert store.execution(receipt["entity_id"])["id"] == before["id"]
        assert not current_cell_projection(root, store.target)["projection"]["closed_cells_v2"]
        assert raw.read_text() == "HTTP/1.1 200 OK\n\nlegacy evidence"
        # Missing provenance is retained for audit, never promoted on import.
        incomplete, reason = _ledger_observation({**entry, "identity_status": "complete"}, "https://legacy.test")
        assert not reason and incomplete["identity_status"] == "incomplete"


def test_native_publication():
    with TemporaryDirectory() as temp:
        root = Path(temp)
        store = TargetStore(root, "native.test")
        store.initialize()
        url = "https://native.test/objects/1"
        store.create_finding(command_id="finding", finding_id="native", endpoint=url, method="GET",
                             family="Authz", title="Native comparison", claim="Peer read", actor="operator")
        runs = []
        for index, actor in enumerate(("owner", "peer")):
            refs = {}
            for kind, body in (("request", "GET /objects/1 HTTP/1.1\nHost: native.test\n"),
                               ("response", "HTTP/1.1 200 OK\n\nrecorded body")):
                raw = root / f"evidence/native.test/{index}-{kind}.txt"
                raw.parent.mkdir(parents=True, exist_ok=True)
                raw.write_text(body)
                refs[kind] = raw.relative_to(root).as_posix()
            runs.append({"url": url, "method": "GET", "actor": actor,
                         "object_scope": "other_object_same_org", "artifacts": refs})
        identity = ClosureCellKey(EndpointKey(url), "Authz", {"method": "GET", "actor_role": "peer",
                                  "object_scope": "other_object_same_org"}, "native_comparison").to_dict()
        evidence = {"schema_version": 1, "source": "browser", "attempt_id": "native-attempt",
                    "generated_at": "2026-09-29T00:00:00Z", "result": "tested_finding",
                    "observed_difference": "Peer read the recorded owner object despite the access boundary.", "runs": runs, "subject_step": 1}
        summary = runner.record_native_evidence(repo_root=root, target=store.target, finding_id="native",
                                                evidence=evidence, identity_v2=identity, state_changing=False)
        assert runner.sync_runner_artifacts(summary, repo_root=root)["status"] == "updated"
        truth = current_cell_projection(root, store.target)
        assert [r["identity_status"] for r in truth["records"]] == ["none", "complete"]
        assert [r["evidence_role"] for r in truth["records"]] == ["control", "subject"]
        assert len(truth["projection"]["closed_cells_v2"]) == 1
        assert ClosureResolver(truth["projection"]).is_cell_closed(url, "Authz", identity_v2=identity)
        assert runner.sync_runner_artifacts(summary, repo_root=root)["status"] == "deduplicated"

        assert store.finding("native")["evidence_integrity"]["status"] == "unassessed"
        reference = {"operation_id": summary["store_operation_id"], "step": 1}
        store.assess(command_id="assessment", finding_id="native", verdict="confirmed",
                     reason="Recorded owner/peer comparison", boundary="Object ownership",
                     impact="Peer reads owner object", evidence=[reference], actor="operator",
                     expected_assessment=None)
        for destination, status in (("internal", "eligible"), ("external", "ineligible"), ("pending", "deferred")):
            store.decide_delivery(command_id=destination, finding_id="native", assessment_id="assessment",
                                  destination=destination, status=status, reason="Fixture destination policy",
                                  actor="operator", expected_decision=None)
        before = store.binding()
        finding = store.finding("native")
        assert finding["technical_conclusion"]["verdict"] == "confirmed"
        assert finding["evidence_integrity"]["status"] == "valid"
        assert {d["decision"] for d in finding["destination_decision"]} == {"accept", "reject", "defer"}
        refs = finding["evidence_integrity"]["references"]
        assert {r["kind"] for r in refs} >= {"request", "response"}
        assert all(r["event_id"] == f"{summary['store_operation_id']}:1" and r["sha256"] for r in refs)
        paged = store.finding_page()["items"][0]
        for field in ("technical_conclusion", "evidence_integrity", "destination_decision"):
            assert paged[field] == finding[field]
        assert store.binding() == before
        (root / next(r["ref"] for r in refs if r["kind"] == "response")).write_text("damaged")
        damaged = store.finding("native")
        assert damaged["technical_conclusion"] == finding["technical_conclusion"]
        assert damaged["evidence_integrity"]["status"] == "invalid"
        assert all(d["stale"] for d in damaged["destination_decision"])


def test_request_pair_replay():
    with TemporaryDirectory() as temp:
        root = Path(temp)
        store = TargetStore(root, "fixture.test")
        store.initialize()
        endpoint = "/api/objects/2"
        identity = ClosureCellKey(EndpointKey(f"https://fixture.test{endpoint}"), "IDOR", {
            "path_template": endpoint, "method": "GET", "actor_relation": "peer",
            "object_scope": "other_object_same_org"}, "peer_object_swap").to_dict()
        spec = {"schema_version": 1, "classifier": "authz", "vuln_class": "IDOR",
                "subject_side": "variant", "active_dimension": f"path:{endpoint}",
                "expected": ["distinct_bodies"],
                "baseline_request": {"method": "GET", "url": "https://fixture.test/api/objects/1",
                                     "actor": "peer", "object_scope": "own_object", "variant": "baseline"},
                "variant_request": {"method": "GET", "url": f"https://fixture.test{endpoint}",
                                    "actor": "peer", "object_scope": "other", "variant": "id_swap"}}
        with patch.object(runner, "request_once", response):
            summary = runner.run_request_diff(repo_root=root, target="fixture.test",
                                              request_spec=spec, identity_v2=identity)
        assert summary["result"] == "tested_finding", summary["result"]
        assert runner.sync_runner_artifacts(summary, repo_root=root)["status"] == "updated"
        truth = current_cell_projection(root, "fixture.test")
        before = store.binding()
        assert runner.sync_runner_artifacts(summary, repo_root=root)["status"] == "deduplicated"
        assert store.binding() == before
        assert current_cell_projection(root, "fixture.test") == truth
        records = truth["records"]
        assert len(records) == 2
        subject = next(r for r in records if r["evidence_role"] == "subject")
        control = next(r for r in records if r["evidence_role"] == "control")
        assert subject["identity_status"] == "complete"
        assert control["identity_status"] == "none"
        for row in records:
            assert row["schema_version"] == 3 and row["event_id"]
            assert {r["kind"] for r in row["evidence_refs"]} >= {"request", "response"}
        resolver = ClosureResolver(truth["projection"])
        assert resolver.is_cell_closed(f"https://fixture.test{endpoint}", "IDOR", identity_v2=identity)
        assert not resolver.is_cell_closed(endpoint, "IDOR")
        for field, value in (("method", "POST"), ("actor_relation", "anonymous"),
                             ("object_scope", "own_object"), ("technique", "other_check")):
            other = deepcopy(identity)
            (other if field == "technique" else other["dimensions"])[field] = value
            assert not resolver.is_cell_closed(f"https://fixture.test{endpoint}", "IDOR", identity_v2=other)
        for change in ({"identity_status": "none"}, {"identity_technique": ""},
                       {"evidence_role": "control"}, {"identity_status": "incomplete"}):
            assert not build_current_cell_projection([{**subject, **change}])["closed_cells_v2"]
        legacy = {k: v for k, v in subject.items() if k != "identity_status"}
        assert not build_current_cell_projection([legacy])["closed_cells_v2"]
        matrix = read_matrix("fixture.test", root)
        assert all(cell["status"] != "tested_finding" for ep in matrix["endpoints"]
                   for cell in ep["cells"].values())
        widened = {"endpoints": [{"endpoint": endpoint, "cells": {"IDOR": {"status": "tested_finding"}}}]}
        assert _coverage_terminal_evidence(widened, truth["projection"])["status"] == "missing"
        widened["endpoints"][0]["cells"]["IDOR"]["identity_v2"] = identity
        widened["endpoints"][0]["endpoint"] = f"https://fixture.test{endpoint}"
        assert _coverage_terminal_evidence(widened, truth["projection"])["status"] == "valid"
        structural = {"endpoints": [{"endpoint": "/api", "cells": _empty_cells("/api", endpoint_kind="route_prefix")}]}
        assert ClosureResolver({}, structural).is_cell_closed("/api", "IDOR")
        cell = structural["endpoints"][0]["cells"]["IDOR"]
        cell.pop("structural_source")
        assert not ClosureResolver({}, structural).is_cell_closed("/api", "IDOR")
        response_ref = next(r["ref"] for r in subject["evidence_refs"] if r["kind"] == "response")
        (root / response_ref).write_text("changed raw evidence")
        damaged = current_cell_projection(root, "fixture.test")
        assert damaged["health"]["status"] == "partial"
        assert not damaged["projection"]["closed_cells_v2"]
    print("PASS: Store replay, subject/control, identity isolation, coverage, structural N/A, raw integrity")
