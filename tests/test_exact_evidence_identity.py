"""Exact conditions, subject selection and restart through the public Store seam."""
from copy import deepcopy
import json
import sqlite3

import pytest

from tools.closure_projection import build_current_cell_projection
from tools.closure_resolver import ClosureResolver
from tools.current_truth import current_cell_projection
from tools.evidence_identity import canonical_endpoint_identity, exact_endpoint_identity
from tools.identity_contract import ClosureCellKey, EndpointKey, build_closure_cell
from tools.target_store import TargetStore
from tools.validation_runner import record_native_evidence, sync_runner_artifacts


def identity(url="https://fixture.test/objects/1", family="UnregisteredBoundary", **conditions):
    return build_closure_cell(url, family, {"method": "GET", "business_state": "pending", **conditions},
                              technique="explicit_check").key


def fixture(tmp_path, family="UnregisteredBoundary"):
    store = TargetStore(tmp_path, "fixture.test")
    store.initialize()
    key = identity(family=family)
    store.create_finding(command_id="finding", finding_id="F", endpoint=key.endpoint, method="GET",
                         family=family, title="Condition check", claim="Explicit claim", actor="operator")
    runs = []
    for i, actor in enumerate(("owner", "peer")):
        refs = {}
        for kind in ("request", "response"):
            path = tmp_path / "evidence/fixture.test" / f"{i}-{kind}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{kind} raw evidence {i}")
            refs[kind] = path.relative_to(tmp_path).as_posix()
        runs.append({"url": key.endpoint, "method": "GET", "actor": actor, "artifacts": refs})
    return store, key, {"schema_version": 1, "source": "browser", "attempt_id": "attempt-1",
                        "generated_at": "2026-09-29T00:00:00Z", "result": "tested_clean",
                        "observed_difference": "Recorded behavior stayed within the declared boundary.",
                        "runs": runs}


@pytest.mark.parametrize("url", ["http://fixture.test/objects/1", "https://other.test/objects/1",
    "https://fixture.test:8443/objects/1", "https://fixture.test/objects/1/",
    "https://fixture.test/objects/1?", "https://fixture.test/objects/%31",
    "https://fixture.test/objects/1#/route"])
def test_exact_assets_do_not_merge(url):
    key = identity()
    other = identity(url)
    resolver = ClosureResolver({"closed_cells_v2": [{"identity_v2": key.to_dict(), "result": "tested_clean"}]})
    assert resolver.is_closure_closed(key)
    assert not resolver.is_closure_closed(other)
    assert not resolver.is_cell_closed(url, key.family, identity_v2=key)


@pytest.mark.parametrize("url", ["/objects/1", "//fixture.test/objects/1", "https://user:secret@fixture.test/",
                                   "https://fixture.test:99999/", "https://fixture.test/a\n"])
def test_missing_or_unsafe_origin_is_not_guessed(url):
    with pytest.raises(ValueError):
        exact_endpoint_identity(url)
    assert not build_closure_cell(url, "NewFamily", {"method": "GET"}, technique="check").complete
    assert canonical_endpoint_identity("https://fixture.test/a/") == "/a"


def test_conditions_are_exact_and_not_family_completeness_claims():
    key = identity(family="SQLi", parameter="q")
    assert key and key.schema_version == 3
    assert identity(family="SQLi", parameter="q", encoding="utf8") != key
    assert identity(family="SQLi", parameter="q", method="POST") != key
    assert identity(family="SQLi", parameter="q", business_state="paid") != key
    assert not build_closure_cell(key.endpoint, "NewFamily", {}, technique="check").complete
    assert not build_closure_cell(key.endpoint, "NewFamily", {"method": "GET", "nested": {}}, technique="check").complete
    # No family-specific schema decides whether an author supplied enough semantic conditions.
    assert build_closure_cell(key.endpoint, "SQLi", {"method": "GET"}, technique="check").complete


def test_historical_identity_remains_readable_without_authorization():
    key = ClosureCellKey(EndpointKey("/objects/1", 2), "SQLi", {"method": "GET", "parameter": "q"}, "check", 2)
    assert ClosureCellKey.from_dict(key.to_dict()) == key
    row = {"identity_v2": key.to_dict(), "identity_status": "complete", "evidence_role": "subject",
           "identity_technique": "check", "endpoint": "/objects/1", "vuln_class": "SQLi", "method": "GET",
           "result": "tested_clean", "event_id": "old:0"}
    before = deepcopy(row)
    projection = build_current_cell_projection([row])
    assert not projection["closed_cells_v2"] and row == before
    assert not ClosureResolver({"closed_cells_v2": [row]}).is_closure_closed(key)


@pytest.mark.parametrize("subject", [None, -1, 2, True, "1"])
def test_native_ambiguous_or_invalid_subject_rejects_before_writes(tmp_path, subject):
    store, key, evidence = fixture(tmp_path)
    if subject is not None:
        evidence["subject_step"] = subject
    before = store.binding()
    with pytest.raises(ValueError, match="subject_step"):
        record_native_evidence(repo_root=tmp_path, target=store.target, finding_id="F",
                               evidence=evidence, identity_v2=key.to_dict())
    assert store.binding() == before
    assert not (tmp_path / ".private").exists()


@pytest.mark.parametrize("family", ["UnregisteredBoundary", "SQLi"])
def test_explicit_subject_conditions_restart_and_distinct_attempts(tmp_path, family):
    store, key, evidence = fixture(tmp_path, family)
    evidence["subject_step"] = 0
    summary = record_native_evidence(repo_root=tmp_path, target=store.target, finding_id="F",
                                    evidence=evidence, identity_v2=key.to_dict())
    assert sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    truth = current_cell_projection(tmp_path, store.target)
    assert [r["evidence_role"] for r in truth["records"]] == ["subject", "control"]
    assert ClosureResolver(truth["projection"]).is_closure_closed(key)
    reopened = TargetStore(tmp_path, store.target)
    operation = reopened.execution(summary["store_operation_id"])
    assert json.loads(operation["observations"][0]["identity_dimensions"]) == dict(key.dimensions)
    assert not ClosureResolver(truth["projection"]).is_cell_closed("/objects/1", "SQLi", identity_v2=key)
    evidence["attempt_id"] = "attempt-2"
    second = record_native_evidence(repo_root=tmp_path, target=store.target, finding_id="F",
                                   evidence=evidence, identity_v2=key.to_dict())
    assert sync_runner_artifacts(second, repo_root=tmp_path)["status"] == "updated"
    assert summary["store_operation_id"] != second["store_operation_id"]
    assert len(current_cell_projection(tmp_path, store.target)["records"]) == 4


def test_projection_does_not_borrow_another_assets_identity():
    key = identity(family="SQLi")
    entry = {"event_id": "attempt:0", "endpoint": "/objects/1", "raw_endpoint": key.endpoint,
             "method": "GET", "vuln_class": key.family, "identity_v2": key.to_dict(),
             "identity_dimensions": key.dimension_map, "identity_status": "complete",
             "identity_technique": key.technique, "evidence_role": "subject", "result": "tested_clean"}
    assert build_current_cell_projection([entry])["closed_cells_v2"]
    for change in ({"raw_endpoint": "https://other.test/objects/1"},
                   {"raw_endpoint": "http://fixture.test/objects/1"},
                   {"raw_endpoint": "https://fixture.test:8443/objects/1"},
                   {"method": "POST"}, {"method": ""},
                   {"identity_dimensions": {**key.dimension_map, "new_condition": "yes"}}):
        assert not build_current_cell_projection([{**entry, **change}])["closed_cells_v2"]


def test_native_subject_must_match_finding_and_unique_legacy_run_is_accepted(tmp_path):
    store, key, evidence = fixture(tmp_path)
    evidence["runs"][0]["url"] = "https://fixture.test/control"
    evidence["subject_step"] = 0
    before = store.binding()
    with pytest.raises(ValueError, match="subject_step must match"):
        record_native_evidence(repo_root=tmp_path, target=store.target, finding_id="F", evidence=evidence)
    assert store.binding() == before
    del evidence["subject_step"]
    summary = record_native_evidence(repo_root=tmp_path, target=store.target, finding_id="F", evidence=evidence)
    assert summary["subject_step"] == 1


def test_v3_conditions_survive_a_new_process(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    store, key, evidence = fixture(tmp_path)
    evidence["subject_step"] = 1
    summary = record_native_evidence(repo_root=tmp_path, target=store.target, finding_id="F",
                                    evidence=evidence, identity_v2=key.to_dict())
    sync_runner_artifacts(summary, repo_root=tmp_path)
    before = store.binding()
    result = subprocess.run([sys.executable, "-c",
        "import json,sys; from tools.current_truth import current_cell_projection; "
        "print(json.dumps(current_cell_projection(sys.argv[1],sys.argv[2])))", str(tmp_path), store.target],
        cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, check=True, timeout=20)
    truth = json.loads(result.stdout)
    assert ClosureResolver(truth["projection"]).is_closure_closed(key)
    assert truth["records"][1]["identity_dimensions"] == key.dimension_map
    assert store.binding() == before


def test_explicit_identity_replacement_keeps_historical_store_rows(tmp_path):
    store, key, evidence = fixture(tmp_path, "SQLi")
    legacy = ClosureCellKey(EndpointKey("/objects/1", 2), "SQLi", {"method": "GET", "parameter": "q"}, "check", 2)
    observation = {"endpoint": key.endpoint, "method": "GET", "family": "SQLi",
                   "observed_at": evidence["generated_at"], "description": "Historical declaration",
                   "artifacts": evidence["runs"][0]["artifacts"], "result": "tested_clean",
                   "identity_status": "complete", "identity_technique": legacy.technique,
                   "identity_v2": legacy.to_dict(), "identity_dimensions": legacy.dimension_map,
                   "detail": {"evidence_role": "subject"}}
    store.start_attempt(attempt_id="history", source="browser", started_at=evidence["generated_at"], actor="operator")
    old = store.record_execution(attempt_id="history", outcome="complete", observations=[observation], actor="operator")
    old_row = store.execution(old["entity_id"])
    before = store.binding()
    assert not current_cell_projection(tmp_path, store.target)["projection"]["closed_cells_v2"]
    assert store.binding() == before
    replacement = {**observation, "identity_v2": key.to_dict(), "identity_technique": key.technique,
                   "identity_dimensions": key.dimension_map}
    new = store.record_execution(attempt_id="history", outcome="complete", observations=[replacement],
                                 actor="operator", expected_operation=old["entity_id"])
    assert new["entity_id"] != old["entity_id"]
    assert store.execution(old["entity_id"]) == old_row
    assert ClosureResolver(current_cell_projection(tmp_path, store.target)["projection"]).is_closure_closed(key)
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == 11
