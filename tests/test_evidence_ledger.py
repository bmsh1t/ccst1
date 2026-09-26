"""Store evidence summaries and explicit historical JSONL diagnostics."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import evidence_ledger
from closure_resolver import ClosureResolver
from evidence_ledger import (
    actor_requirements, build_summary, ledger_path, load_entries, load_entries_diagnostic,
    normalize_actor, normalize_object_scope, normalize_variant, normalize_ledger_vuln_class,
)
from tools.target_store import StoreError, TargetStore


@pytest.fixture
def store(tmp_path):
    value = TargetStore(tmp_path, "target.com")
    value.initialize()
    return value


def record_observation(store, *, attempt="first", **facts):
    """Publish fixture bytes, then use the real attempt and registration commands."""
    raw = store.root / "evidence/target.com" / f"{attempt}.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(f"HTTP/1.1 200 OK\n\nfixture {attempt}", encoding="utf-8")
    observed_at = (datetime(2026, 9, 24, tzinfo=timezone.utc)
                   + timedelta(seconds=store.page("operations")["total"])).isoformat()
    store.start_attempt(attempt_id=attempt, source="fixture", started_at=observed_at, actor="operator")
    observation = {
        "endpoint": "https://target.com/api/search", "method": "GET", "family": "SQLi",
        "actor": "owner", "object_scope": "own_object", "variant": "baseline",
        "observed_at": observed_at, "description": "Recorded fixture response",
        "result": "tested_clean", "state_changing": False, "redline_checked": False,
        "identity_dimensions": {"method": "GET", "parameter": "q"},
        "artifacts": {"response": raw.relative_to(store.root).as_posix()},
        **facts,
    }
    receipt = store.record_execution(attempt_id=attempt, outcome="complete", observations=[observation], actor="operator")
    return receipt, raw


@pytest.mark.parametrize("normalizer,value,expected", [
    (normalize_actor, "self", "owner"), (normalize_actor, "user_b", "peer"),
    (normalize_object_scope, "own", "own_object"),
    (normalize_object_scope, "same_org_other", "other_object_same_org"),
    (normalize_object_scope, "other_object_same_org", "other_object_same_org"),
    (normalize_variant, "object_swap", "id_swap"),
    (normalize_ledger_vuln_class, "file-upload", "Upload"),
    (normalize_ledger_vuln_class, "custom-state-transition", "custom-state-transition"),
])
def test_evidence_vocabulary_normalization(normalizer, value, expected):
    assert normalizer(value) == expected


def test_invalid_alias_error_lists_accepted_input_tokens():
    with pytest.raises(ValueError) as exc:
        normalize_actor("same_org_other")
    assert "Accepted inputs:" in str(exc.value)
    assert "owner (input:" in str(exc.value)
    assert "self" in str(exc.value) and "user_a" in str(exc.value)


@pytest.mark.parametrize("target", ["target.com", "new.test"])
def test_legacy_writer_and_cli_are_retired(tmp_path, target):
    assert not hasattr(evidence_ledger, "record_entry")
    with pytest.raises(SystemExit) as exc:
        evidence_ledger.main(["record", "--target", target])
    assert exc.value.code == 2
    assert not ledger_path(tmp_path, target).exists()


def test_summary_reads_store_and_ignores_conflicting_legacy_files(store):
    receipt, _ = record_observation(store)
    old = ledger_path(store.root, store.target)
    old.parent.mkdir(parents=True)
    old.write_text('{broken legacy input\n', encoding="utf-8")
    binding = store.binding()
    summary = build_summary(store.root, target=store.target)
    assert summary["entry_count"] == 1
    assert summary["ledger_status"] == "ready"
    assert summary["evidence_source"]["kind"] == "store"
    assert summary["recent_entries"][0]["event_id"] == receipt["entity_id"] + ":0"
    assert summary["record_commands"] == []
    assert store.binding() == binding
    assert old.read_text() == '{broken legacy input\n'


@pytest.mark.parametrize("fault", ["uninitialized", "preview", "missing", "corrupt"])
def test_summary_cli_reports_store_failure_without_recovery_writes(tmp_path, capsys, fault):
    store = TargetStore(tmp_path, "target.com", allow_preview=fault == "preview")
    if fault != "uninitialized":
        store.initialize(allow_legacy=fault == "preview")
        store.binding()
    if fault == "missing":
        store.path.unlink()
    elif fault == "corrupt":
        store.path.write_bytes(b"damaged store")
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert evidence_ledger.main(["summary", "--repo-root", str(tmp_path), "--target", store.target, "--json"]) == 2
    output = capsys.readouterr()
    assert not output.out and "evidence-ledger:" in output.err and "Traceback" not in output.err
    assert {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


def test_parent_summary_does_not_aggregate_another_target_store(store):
    child = TargetStore(store.root, "api.target.com")
    child.initialize()
    child.remember(command_id="child-note", kind="note", statement="Child-only context", conditions="unknown",
                   reopen_when="", next_intent="", evidence=[], actor="operator")
    summary = build_summary(store.root, target=store.target)
    assert summary["entry_count"] == 0
    assert "aggregate_closure" not in summary
    assert not ledger_path(store.root, store.target).exists()


def test_v2_projection_preserves_sql_parameter_identity(store):
    record_observation(store)
    record_observation(store, attempt="other", result="candidate",
                       identity_dimensions={"method": "GET", "parameter": "term"})
    summary = build_summary(store.root, target=store.target)
    assert len(summary["closed_cells_v2"]) == 1
    cell = summary["closed_cells_v2"][0]
    assert cell["dimensions"] == {"method": "GET", "parameter": "q"}
    resolver = ClosureResolver(summary)
    assert resolver.is_closure_closed(cell["identity_v2"])
    assert not resolver.is_closure_closed({**cell["identity_v2"], "dimensions": {"method": "GET", "parameter": "term"}})
    assert summary["open_candidates_v2"][0]["identity_dimensions"]["parameter"] == "term"


def test_incomplete_identity_is_preserved_without_authorizing_v2_closure(store):
    record_observation(store, identity_dimensions={"method": "GET"})
    summary = build_summary(store.root, target=store.target)
    assert summary["entry_count"] == 1
    assert summary["closed_cells_v2"] == []
    assert summary["identity_v2_diagnostics"]["incomplete_count"] == 1
    assert summary["recent_entries"][0]["identity_dimensions"] == {"method": "GET"}


def test_open_family_remains_recorded_without_canonical_actor_requirements(store):
    record_observation(store, family="Workflow", endpoint="https://target.com/checkout",
                       identity_dimensions={"workflow": "checkout", "transition": "pay", "actor": "owner"})
    summary = build_summary(store.root, target=store.target, vuln_classes=["Workflow"])
    assert summary["closed_cells_v2"][0]["vuln_class"] == "Workflow"
    assert summary["actor_matrix"]["rows"] == []


@pytest.mark.parametrize("result,closed,candidate", [
    ("candidate", False, True), ("signal", False, False), ("tested_clean", True, False),
])
def test_latest_observation_controls_cell_without_rewriting_history(store, result, closed, candidate):
    record_observation(store)
    record_observation(store, attempt="latest", result=result)
    summary = build_summary(store.root, target=store.target)
    assert bool(summary["closed_cells_v2"]) is closed
    assert bool(summary["open_candidates_v2"]) is candidate
    assert store.page("operations")["total"] == 2
    assert summary["entry_count"] == 2


def test_summary_retains_cells_and_candidates_outside_recent_window(store):
    record_observation(store)
    record_observation(store, attempt="candidate", endpoint="https://target.com/api/pending", result="candidate")
    for index in range(6):
        record_observation(store, attempt=f"noise-{index}", endpoint=f"https://target.com/api/noise/{index}")
    summary = build_summary(store.root, target=store.target)
    assert len(summary["recent_entries"]) == 5
    assert all(row["endpoint"] not in {"/api/search", "/api/pending"} for row in summary["recent_entries"])
    assert any(row["endpoint"] == "/api/search" for row in summary["closed_cells_v2"])
    assert any(row["endpoint"] == "/api/pending" for row in summary["open_candidates_v2"])


def test_damaged_evidence_is_visible_and_suppresses_closure(store):
    _, raw = record_observation(store)
    raw.write_text("changed fixture")
    summary = build_summary(store.root, target=store.target)
    assert summary["entry_count"] == 1
    assert summary["ledger_status"] == "partial"
    assert summary["ledger_diagnostics"]["invalid_count"] == 1
    assert summary["closed_cells"] == summary["closed_cells_v2"] == []
    assert not ClosureResolver(summary).is_cell_closed("/api/search", "SQLi")


@pytest.mark.parametrize("method,state_changing,redline_checked,closed", [
    ("POST", None, False, True), ("POST", False, False, True), ("PATCH", False, False, True),
    ("PATCH", True, True, True), ("DELETE", True, False, False),
])
def test_summary_uses_recorded_side_effect_facts(store, method, state_changing, redline_checked, closed):
    record_observation(store, method=method, state_changing=state_changing, redline_checked=redline_checked,
                       identity_dimensions={"method": method, "parameter": "q"})
    summary = build_summary(store.root, target=store.target)
    assert summary["recent_entries"][0]["result"] == "tested_clean"
    assert summary["recent_entries"][0]["state_changing"] is state_changing
    assert summary["redline_unchecked_count"] == int(bool(state_changing and not redline_checked))
    assert bool(summary["closed_cells_v2"]) is closed


def test_actor_matrix_requires_matching_method_and_actor(store):
    endpoint = "/api/accounts/42/export"
    before = build_summary(store.root, target=store.target, focus_endpoints=[endpoint], vuln_classes=["IDOR"])
    record_observation(store, endpoint="https://target.com" + endpoint, family="IDOR", actor="peer",
                       object_scope="other_object_same_org", variant="id_swap", identity_dimensions={})
    after = build_summary(store.root, target=store.target, focus_endpoints=[endpoint], vuln_classes=["IDOR"])
    assert after["actor_matrix"]["gap_count"] < before["actor_matrix"]["gap_count"]
    peer = next(row for row in after["actor_matrix"]["rows"] if row["actor"] == "peer")
    assert peer["status"] == "covered"
    different = build_summary(store.root, target=store.target, focus_endpoints=[endpoint], vuln_classes=["IDOR"], method="POST")
    peer = next(row for row in different["actor_matrix"]["rows"] if row["actor"] == "peer")
    assert peer["status"] == "missing"


@pytest.mark.parametrize("endpoint,classes", [
    ("/api/accounts/42/export", []), ("/rest/admin/application-configuration", ["Upload"]),
    ("/profile/image/url", ["IDOR", "Authz"]), ("/rest/admin/application-configuration", ["IDOR"]),
])
def test_summary_keeps_irrelevant_actor_requirements_empty(store, endpoint, classes):
    summary = build_summary(store.root, target=store.target, focus_endpoints=[endpoint], vuln_classes=classes)
    assert summary["actor_matrix"]["gap_count"] == 0
    assert summary["record_commands"] == []


def test_explicit_vuln_classes_keep_bounded_actor_matrix(store):
    summary = build_summary(store.root, target=store.target, focus_endpoints=["/api/accounts/42/export"],
                            vuln_classes=["IDOR", "Authz", "GraphQL", "CSRF"])
    assert summary["actor_matrix"]["vuln_classes"] == ["IDOR", "Authz", "GraphQL", "CSRF"]
    assert {row["vuln_class"] for row in summary["actor_matrix"]["rows"]} == {"IDOR", "Authz", "GraphQL"}


def test_actor_requirements_ignore_non_authz_classes():
    assert actor_requirements("/status", "SSRF") == []
    assert actor_requirements("/rest/admin/application-configuration", "Upload") == []


@pytest.mark.parametrize("damage", [b"{broken\n", b"\xff\n"])
def test_explicit_legacy_diagnostic_preserves_valid_prefix(tmp_path, capsys, damage):
    path = ledger_path(tmp_path, "target.com")
    path.parent.mkdir(parents=True)
    first = json.dumps({"endpoint": "/api/orders/1", "vuln_class": "IDOR", "result": "tested_clean"}).encode() + b"\n"
    tail = json.dumps({"endpoint": "/api/orders/2", "vuln_class": "IDOR", "result": "tested_clean"}).encode() + b"\n"
    raw = first + damage + tail
    path.write_bytes(raw)
    diagnostic = load_entries_diagnostic(tmp_path, "target.com")
    assert diagnostic["status"] == "partial"
    assert diagnostic["last_valid_offset"] == len(first)
    assert diagnostic["invalid_count"] == 1
    assert diagnostic["invalid_rows"][0]["line"] == 2
    assert [row["endpoint"] for row in diagnostic["entries"]] == ["/api/orders/1"]
    assert load_entries(tmp_path, "target.com") == diagnostic["entries"]
    assert f"{path}:2" in capsys.readouterr().err
    assert path.read_bytes() == raw
    with pytest.raises(StoreError, match="initialized"):
        build_summary(tmp_path, target="target.com")


def test_explicit_legacy_missing_is_diagnostic_without_creation(tmp_path):
    diagnostic = load_entries_diagnostic(tmp_path, "target.com")
    assert diagnostic["status"] == "missing" and diagnostic["entries"] == []
    assert not ledger_path(tmp_path, "target.com").exists()
