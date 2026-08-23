"""Tests for tools/evidence_ledger.py."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from evidence_ledger import (
    actor_requirements,
    build_current_cell_projection,
    build_summary,
    ledger_path,
    load_entries,
    load_entries_diagnostic,
    record_entry,
)
from closure_resolver import ClosureResolver


def test_record_entry_writes_normalized_ledger_row(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="https://api.target.com/api/accounts/42/export?account_id=42",
        method="get",
        vuln_class="idor",
        actor="self",
        object_scope="own",
        variant="baseline",
        result="tested_clean",
        browser_observed=True,
        replayed=True,
        evidence_ref="recon/target.com/browser/xhr_endpoints.txt:1",
    )

    path = ledger_path(tmp_path, "target.com")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    assert entry["endpoint"] == "/api/accounts/42/export?account_id=42"
    assert entry["method"] == "GET"
    assert entry["vuln_class"] == "IDOR"
    assert entry["actor"] == "owner"
    assert entry["object_scope"] == "own_object"
    assert entry["variant"] == "baseline"
    assert rows[0]["browser_observed"] is True
    assert rows[0]["replayed"] is True


def test_parent_summary_aggregates_child_ledger_without_copying_events(tmp_path):
    record_entry(
        tmp_path,
        target="api.target.com",
        endpoint="/api/users",
        method="GET",
        vuln_class="Authz",
        result="tested_clean",
    )

    summary = build_summary(tmp_path, target="target.com")
    aggregate = summary["aggregate_closure"]

    assert aggregate["child_count"] == 1
    assert aggregate["children"][0]["target"] == "api.target.com"
    assert aggregate["children"][0]["entry_count"] == 1
    assert aggregate["entry_count"] == 1
    assert not ledger_path(tmp_path, "target.com").exists()


def test_v2_projection_preserves_sql_parameter_identity(tmp_path):
    first = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="tested_clean",
        identity_dimensions={"method": "GET", "parameter": "q"},
    )
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="candidate",
        identity_dimensions={"method": "GET", "parameter": "term"},
    )
    summary = build_summary(tmp_path, target="target.com")

    assert first["identity_status"] == "complete"
    assert len(summary["closed_cells_v2"]) == 1
    cell = summary["closed_cells_v2"][0]
    assert cell["dimensions"] == {"method": "GET", "parameter": "q"}
    resolver = ClosureResolver(summary)
    assert resolver.is_closure_closed(cell["identity_v2"])
    other = {
        **cell["identity_v2"],
        "dimensions": {"method": "GET", "parameter": "term"},
    }
    assert resolver.is_closure_closed(other) is False
    assert summary["identity_v2_shadow"]["different"] is True
    assert summary["identity_v2_shadow"]["v2_only"] == [cell]


def test_workflow_identity_family_is_recordable_without_expanding_legacy_matrix(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/checkout",
        vuln_class="Workflow",
        result="tested_clean",
        identity_dimensions={
            "workflow": "checkout",
            "transition": "pay",
            "actor": "owner",
        },
    )

    assert entry["vuln_class"] == "Workflow"
    assert entry["identity_status"] == "complete"
    assert build_summary(tmp_path, target="target.com")["closed_cells_v2"][0]["vuln_class"] == "Workflow"
    assert build_summary(
        tmp_path,
        target="target.com",
        vuln_classes=["Workflow"],
    )["actor_matrix"]["rows"] == []


def test_explicit_empty_vuln_classes_disables_actor_matrix(tmp_path):
    endpoint = "/api/accounts/42/export"

    legacy = build_summary(tmp_path, target="target.com", focus_endpoints=[endpoint])
    explicit_empty = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=[endpoint],
        vuln_classes=[],
    )

    assert legacy["actor_matrix"]["vuln_classes"] == ["IDOR", "Authz"]
    assert legacy["actor_matrix"]["rows"]
    assert explicit_empty["actor_matrix"] == {
        "endpoint_count": 1,
        "vuln_classes": [],
        "rows": [],
        "gaps": [],
        "gap_count": 0,
        "covered_count": 0,
    }
    assert explicit_empty["record_commands"] == []


def test_explicit_nonempty_vuln_classes_keeps_three_class_matrix_cap(tmp_path):
    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=["/api/accounts/42/export"],
        vuln_classes=["IDOR", "Authz", "GraphQL", "CSRF"],
    )

    assert summary["actor_matrix"]["vuln_classes"] == ["IDOR", "Authz", "GraphQL", "CSRF"]
    assert {row["vuln_class"] for row in summary["actor_matrix"]["rows"]} == {
        "IDOR", "Authz", "GraphQL",
    }


def test_v2_incomplete_identity_is_recorded_but_not_closeable(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="tested_clean",
        identity_dimensions={"method": "GET"},
    )
    summary = build_summary(tmp_path, target="target.com")

    assert entry["identity_status"] == "incomplete"
    assert "parameter" in entry["identity_missing_fields"]
    assert summary["closed_cells_v2"] == []


def test_v2_event_id_replay_is_idempotent_and_latest_result_controls_cell(tmp_path):
    kwargs = {
        "target": "target.com",
        "endpoint": "/api/search",
        "method": "GET",
        "vuln_class": "SQLi",
        "result": "tested_clean",
        "event_id": "identity-v2:event-1",
        "identity_dimensions": {"method": "GET", "parameter": "q"},
    }
    first = record_entry(tmp_path, **kwargs)
    duplicate = record_entry(tmp_path, **kwargs)
    assert first["write_status"] == "updated"
    assert duplicate["write_status"] == "deduplicated"
    summary = build_summary(tmp_path, target="target.com")
    assert len(summary["closed_cells_v2"]) == 1

    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="candidate",
        identity_dimensions={"method": "GET", "parameter": "q"},
    )
    reopened = build_summary(tmp_path, target="target.com")
    assert reopened["closed_cells_v2"] == []
    assert len(reopened["open_candidates_v2"]) == 1

    record_entry(tmp_path, **{**kwargs, "event_id": "identity-v2:event-2"})
    reclosed = build_summary(tmp_path, target="target.com")
    assert len(reclosed["closed_cells_v2"]) == 1
    assert reclosed["open_candidates_v2"] == []


def test_legacy_terminal_is_not_a_v2_closure(tmp_path):
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        vuln_class="SQLi",
        result="tested_clean",
    )
    summary = build_summary(tmp_path, target="target.com")
    legacy = next(cell for cell in summary["closed_cells"] if cell["endpoint"] == "/api/search")

    assert summary["closed_cells_v2"] == []
    assert ClosureResolver(summary).is_closure_closed(legacy) is False


def test_ai_identity_candidate_persists_follow_up_without_closing(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        vuln_class="SQLi",
        result="candidate",
        identity_candidate={
            "family": "SQLi",
            "endpoint": "/api/search",
            "dimensions": {"method": "GET"},
            "confidence": 0.6,
            "provenance": ["evidence/response.json"],
            "evidence_refs": ["evidence/response.json"],
        },
    )

    assert entry["identity_status"] == "follow_up_required"
    assert entry["identity_candidate"]["kind"] == "ai_identity_candidate"
    assert "parameter" in entry["identity_candidate"]["missing_fields"]
    assert entry["identity_follow_up_action"]["kind"] == "identity_follow_up"
    summary = build_summary(tmp_path, target="target.com")
    assert summary["closed_cells_v2"] == []
    assert summary["identity_v2_follow_up_actions"][0]["kind"] == "identity_follow_up"


def test_identity_candidate_fact_disagreement_creates_follow_up(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="tested_clean",
        identity_candidate={
            "family": "SQLi",
            "endpoint": "/api/search",
            "dimensions": {"method": "POST", "parameter": "q"},
            "confidence": 0.95,
            "provenance": ["ai:planner"],
            "evidence_refs": ["evidence/search.json"],
        },
    )

    assert entry["identity_status"] == "conflict"
    assert "method_mismatch" in entry["identity_conflicts"]
    assert entry["identity_follow_up_action"]["conflicts"] == ["method_mismatch"]
    assert build_summary(tmp_path, target="target.com")["closed_cells_v2"] == []


def test_v2_projection_requires_complete_identity_status(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="tested_clean",
        identity_dimensions={"method": "GET", "parameter": "q"},
    )
    conflicting = {
        **entry,
        "identity_status": "conflict",
        "identity_conflicts": ["evidence_disagreement"],
    }

    assert build_current_cell_projection([conflicting])["closed_cells_v2"] == []


def test_complete_identity_links_and_resolves_incomplete_event(tmp_path):
    original = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="candidate",
        event_id="identity:incomplete",
        evidence_ref="evidence/search-original.json",
        identity_dimensions={"method": "GET"},
    )
    replacement = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="tested_clean",
        event_id="identity:complete",
        evidence_ref="evidence/search-follow-up.json",
        identity_dimensions={"method": "GET", "parameter": "q"},
        identity_replaces_event_id="identity:incomplete",
    )
    summary = build_summary(tmp_path, target="target.com")
    rows = load_entries(tmp_path, "target.com")

    assert original["identity_status"] == "incomplete"
    assert "identity_replacement" not in rows[0]
    assert replacement["identity_replacement"] == {
        "event_id": "identity:incomplete",
        "evidence_ref": "evidence/search-original.json",
        "identity_v2": None,
    }
    assert summary["identity_v2_diagnostics"]["incomplete_count"] == 0
    assert summary["identity_v2_diagnostics"]["replacement_count"] == 1
    assert len(summary["closed_cells_v2"]) == 1
    assert summary["identity_v2_shadow"]["scope_mismatches"][0]["legacy_scope"] == "endpoint_family"


def test_identity_replacement_requires_existing_event_and_complete_key(tmp_path):
    with pytest.raises(ValueError, match="complete new identity"):
        record_entry(
            tmp_path,
            target="target.com",
            endpoint="/api/search",
            vuln_class="SQLi",
            result="candidate",
            identity_dimensions={"method": "GET"},
            identity_replaces_event_id="missing",
        )


def test_identity_replacement_cannot_suppress_another_endpoint_or_family(tmp_path):
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/orders/1",
        vuln_class="IDOR",
        actor="peer",
        object_scope="other",
        result="candidate",
        event_id="identity:idor",
        identity_dimensions={
            "path_template": "/api/orders/{id}",
            "method": "GET",
            "actor_relation": "peer",
            "object_scope": "other_object_same_org",
        },
    )

    with pytest.raises(ValueError, match="same endpoint and vulnerability family"):
        record_entry(
            tmp_path,
            target="target.com",
            endpoint="/api/search",
            vuln_class="SQLi",
            result="tested_clean",
            identity_dimensions={"method": "GET", "parameter": "q"},
            identity_replaces_event_id="identity:idor",
        )

    summary = build_summary(tmp_path, target="target.com")
    assert summary["open_candidates_v2"][0]["event_id"] == "identity:idor"
    with pytest.raises(ValueError, match="replacement event not found"):
        record_entry(
            tmp_path,
            target="target.com",
            endpoint="/api/search",
            vuln_class="SQLi",
            result="tested_clean",
            identity_dimensions={"method": "GET", "parameter": "q"},
            identity_replaces_event_id="missing",
        )


def test_identity_replacement_supersedes_projection_without_mutating_old_event(tmp_path):
    original = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="tested_clean",
        event_id="identity:old-key",
        evidence_ref="evidence/search-old.json",
        identity_dimensions={"method": "GET", "parameter": "q"},
    )
    replacement = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="GET",
        vuln_class="SQLi",
        result="tested_clean",
        event_id="identity:new-key",
        evidence_ref="evidence/search-new.json",
        identity_dimensions={"method": "GET", "parameter": "term"},
        identity_replaces_event_id="identity:old-key",
    )
    summary = build_summary(tmp_path, target="target.com")
    resolver = ClosureResolver(summary)
    rows = load_entries(tmp_path, "target.com")

    assert rows[0]["identity_v2"] == original["identity_v2"]
    assert "identity_replacement" not in rows[0]
    assert replacement["identity_replacement"]["identity_v2"] == original["identity_v2"]
    assert not resolver.is_closure_closed(original["identity_v2"])
    assert resolver.is_closure_closed(replacement["identity_v2"])


def test_record_entry_normalizes_file_upload_alias(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="https://target.com/my-account/avatar",
        method="POST",
        vuln_class="file-upload",
        result="tested_finding",
        evidence_ref="evidence/target.com/validation/upload/summary.json",
    )

    assert entry["vuln_class"] == "Upload"


def test_record_entry_preserves_spa_hash_route_endpoint(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint='https://target.com/#/search?q=<img src=x onerror=console.log("marker")>',
        method="GET",
        vuln_class="XSS",
        actor="anonymous",
        object_scope="none",
        variant="browser_observed",
        result="tested_finding",
        browser_observed=True,
        replayed=True,
    )

    assert entry["endpoint"].startswith("/#/search?q=")
    assert entry["raw_endpoint"].startswith("https://target.com/#/search")


def test_actor_matrix_reports_missing_then_covered_checks(tmp_path):
    endpoint = "/api/accounts/42/export"

    first = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=[endpoint],
        vuln_classes=["IDOR"],
    )

    assert first["actor_matrix"]["gap_count"] >= 5
    assert any(row["actor"] == "peer" for row in first["actor_matrix"]["gaps"])

    record_entry(
        tmp_path,
        target="target.com",
        endpoint=endpoint,
        vuln_class="IDOR",
        actor="peer",
        object_scope="same_org_other",
        variant="id_swap",
        result="tested_clean",
    )
    second = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=[endpoint],
        vuln_classes=["IDOR"],
    )

    peer_rows = [
        row for row in second["actor_matrix"]["rows"]
        if row["actor"] == "peer" and row["variant"] == "id_swap"
    ]
    assert peer_rows[0]["status"] == "covered"
    assert second["actor_matrix"]["gap_count"] < first["actor_matrix"]["gap_count"]


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_state_changing_record_without_redline_check_is_flagged(tmp_path, method):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42/role",
        method=method,
        vuln_class="Authz",
        actor="low_role",
        object_scope="own",
        variant="role_diff",
        result="tested_clean",
        state_changing=True,
    )

    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=["/api/accounts/42/role"],
        vuln_classes=["Authz"],
        method=method,
    )

    assert entry["result"] == "blocked_redline"
    assert entry["requested_result"] == "tested_clean"
    assert entry["redline_decision"] == "blocked"
    assert summary["redline_unchecked_count"] == 1
    assert "redline_check_missing_for_state_changing_test" in summary["recent_entries"][0]["warnings"]
    assert any(row["redline_required"] for row in summary["actor_matrix"]["gaps"])


def test_state_changing_patch_with_redline_remains_covering(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42/role",
        method="PATCH",
        vuln_class="Authz",
        result="tested_clean",
        state_changing=True,
        redline_checked=True,
    )

    assert entry["result"] == "tested_clean"
    assert entry["redline_decision"] == "allowed"


def test_patch_preview_is_not_redline_blocked_by_method_alone(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42/role/preview",
        method="PATCH",
        vuln_class="Authz",
        result="tested_clean",
        state_changing=False,
    )

    assert entry["state_changing"] is False
    assert entry["result"] == "tested_clean"
    assert entry["warnings"] == []


def test_concurrent_appends_remain_parseable_jsonl(tmp_path):
    def append(index):
        return record_entry(
            tmp_path,
            target="target.com",
            endpoint=f"/api/orders/{index}",
            vuln_class="IDOR",
            result="tested_clean",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(24)))

    rows = [
        json.loads(line)
        for line in ledger_path(tmp_path, "target.com").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 24
    assert {row["endpoint"] for row in rows} == {f"/api/orders/{index}" for index in range(24)}


def test_event_id_append_is_idempotent(tmp_path):
    kwargs = {
        "target": "target.com",
        "endpoint": "/api/orders/42",
        "vuln_class": "IDOR",
        "result": "tested_clean",
        "operation_id": "runner:operation-1",
        "event_id": "ledger:event-1",
    }

    first = record_entry(tmp_path, **kwargs)
    second = record_entry(tmp_path, **kwargs)
    rows = ledger_path(tmp_path, "target.com").read_text(encoding="utf-8").splitlines()

    assert first["write_status"] == "updated"
    assert second["write_status"] == "deduplicated"
    assert len(rows) == 1


def test_corrupt_row_is_diagnostic_and_withholds_closure(tmp_path, capsys):
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/orders/42",
        vuln_class="IDOR",
        result="tested_clean",
    )
    path = ledger_path(tmp_path, "target.com")
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{broken\n")

    summary = build_summary(tmp_path, target="target.com")
    entries = load_entries(tmp_path, "target.com")
    warning = capsys.readouterr().err

    assert len(entries) == 1
    assert summary["ledger_status"] == "partial"
    assert summary["ledger_diagnostics"]["invalid_count"] == 1
    assert summary["ledger_diagnostics"]["invalid_rows"][0]["line"] == 2
    assert summary["closed_cells"] == []
    assert ClosureResolver(summary).is_cell_closed("/api/orders/42", "IDOR") is False
    assert f"{path}:2" in warning


def test_last_valid_offset_stops_before_first_corrupt_row(tmp_path):
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/orders/1",
        vuln_class="IDOR",
        result="tested_clean",
    )
    path = ledger_path(tmp_path, "target.com")
    first_row_size = path.stat().st_size
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{broken\n")
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/orders/2",
        vuln_class="IDOR",
        result="tested_clean",
    )

    diagnostic = load_entries_diagnostic(tmp_path, "target.com")

    assert [entry["endpoint"] for entry in diagnostic["entries"]] == ["/api/orders/1"]
    assert diagnostic["last_valid_offset"] == first_row_size


def test_post_record_is_not_state_changing_by_method_alone(tmp_path):
    entry = record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/search",
        method="POST",
        vuln_class="IDOR",
        actor="owner",
        object_scope="own",
        variant="baseline",
        result="signal",
    )

    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=["/api/search"],
        vuln_classes=["IDOR"],
        method="POST",
    )

    assert entry["state_changing"] is False
    assert entry["warnings"] == []
    assert summary["redline_unchecked_count"] == 0
    assert not any(row["redline_required"] for row in summary["actor_matrix"]["gaps"])


def test_summary_closed_cells_include_older_non_recent_entries(tmp_path):
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42",
        vuln_class="IDOR",
        actor="peer",
        object_scope="other",
        variant="id_swap",
        result="tested_finding",
    )
    for index in range(6):
        record_entry(
            tmp_path,
            target="target.com",
            endpoint=f"/api/noise/{index}",
            vuln_class="Authz",
            result="tested_clean",
        )

    summary = build_summary(tmp_path, target="target.com")

    assert not any(entry.get("endpoint") == "/api/accounts/42" for entry in summary["recent_entries"])
    closed = next(cell for cell in summary["closed_cells"] if cell["endpoint"] == "/api/accounts/42")
    assert closed["vuln_class"] == "IDOR"
    assert closed["result"] == "tested_finding"


def test_summary_closed_cells_include_blocked_redline_terminal_rows(tmp_path):
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/profile/image/url",
        method="POST",
        vuln_class="SSRF",
        result="blocked_redline",
        evidence_ref="evidence/target/ssrf_redline.txt",
    )

    summary = build_summary(tmp_path, target="target.com")

    closed = next(cell for cell in summary["closed_cells"] if cell["endpoint"] == "/profile/image/url")
    assert closed["vuln_class"] == "SSRF"
    assert closed["result"] == "blocked_redline"


def test_summary_open_candidates_survive_recency_but_close_on_final_result(tmp_path):
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
        evidence_ref="evidence/target/ssrf.json",
    )
    for index in range(6):
        record_entry(
            tmp_path,
            target="target.com",
            endpoint=f"/api/noise/{index}",
            vuln_class="Authz",
            result="tested_clean",
        )

    summary = build_summary(tmp_path, target="target.com")

    assert not any(entry.get("endpoint") == "/profile/image/url" for entry in summary["recent_entries"])
    assert any(entry.get("endpoint") == "/profile/image/url" for entry in summary["open_candidates"])

    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/profile/image/url",
        method="POST",
        vuln_class="SSRF",
        actor="owner",
        object_scope="own",
        variant="replay",
        result="dead_end",
    )

    closed = build_summary(tmp_path, target="target.com")

    assert not any(entry.get("endpoint") == "/profile/image/url" for entry in closed["open_candidates"])


def test_summary_latest_open_result_reopens_terminal_cell(tmp_path):
    endpoint = "/api/orders/42"
    record_entry(
        tmp_path,
        target="target.com",
        endpoint=endpoint,
        vuln_class="IDOR",
        actor="peer",
        object_scope="other",
        variant="id_swap",
        result="tested_clean",
    )
    record_entry(
        tmp_path,
        target="target.com",
        endpoint=endpoint,
        vuln_class="IDOR",
        actor="owner",
        object_scope="own",
        result="candidate",
    )

    reopened = build_summary(tmp_path, target="target.com")

    assert not any(cell["endpoint"] == endpoint for cell in reopened["closed_cells"])
    assert [item["endpoint"] for item in reopened["open_candidates"]] == [endpoint]

    record_entry(
        tmp_path,
        target="target.com",
        endpoint=endpoint,
        vuln_class="IDOR",
        actor="owner",
        object_scope="own",
        result="tested_finding",
    )
    closed = build_summary(tmp_path, target="target.com")

    assert not any(item["endpoint"] == endpoint for item in closed["open_candidates"])
    terminal = next(cell for cell in closed["closed_cells"] if cell["endpoint"] == endpoint)
    assert terminal["result"] == "tested_finding"


def test_current_projection_keeps_case_dimensions_independent(tmp_path):
    endpoint = "/api/orders/42?view=summary"
    record_entry(
        tmp_path,
        target="target.com",
        endpoint=endpoint,
        method="GET",
        vuln_class="IDOR",
        actor="owner",
        object_scope="own",
        variant="baseline",
        result="tested_clean",
    )
    record_entry(
        tmp_path,
        target="target.com",
        endpoint=endpoint,
        method="POST",
        vuln_class="IDOR",
        actor="peer",
        object_scope="other",
        variant="id_swap",
        result="candidate",
    )

    summary = build_summary(tmp_path, target="target.com")

    assert not any(cell["endpoint"] == endpoint for cell in summary["closed_cells"])
    candidate = next(item for item in summary["open_candidates"] if item["endpoint"] == endpoint)
    assert candidate["method"] == "POST"
    assert candidate["actor"] == "peer"


def test_actor_matrix_matches_method_as_evidence_identity(tmp_path):
    endpoint = "/api/orders/42"
    record_entry(
        tmp_path,
        target="target.com",
        endpoint=endpoint,
        method="GET",
        vuln_class="IDOR",
        actor="peer",
        object_scope="other",
        variant="id_swap",
        result="tested_clean",
    )

    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=[endpoint],
        vuln_classes=["IDOR"],
        method="POST",
    )

    peer = next(
        row for row in summary["actor_matrix"]["rows"]
        if row["actor"] == "peer" and row["variant"] == "id_swap"
    )
    assert peer["status"] == "missing"


def test_summary_signal_reopens_terminal_cell_without_becoming_candidate(tmp_path):
    endpoint = "/api/orders/42"
    for result in ("dead_end", "signal"):
        record_entry(
            tmp_path,
            target="target.com",
            endpoint=endpoint,
            vuln_class="IDOR",
            result=result,
        )

    summary = build_summary(tmp_path, target="target.com")

    assert not any(cell["endpoint"] == endpoint for cell in summary["closed_cells"])
    assert not any(item["endpoint"] == endpoint for item in summary["open_candidates"])


def test_invalid_alias_error_lists_accepted_input_tokens(tmp_path):
    with pytest.raises(ValueError) as exc:
        record_entry(
            tmp_path,
            target="target.com",
            endpoint="/api/accounts/42",
            vuln_class="IDOR",
            actor="same_org_other",
        )

    message = str(exc.value)
    assert "Accepted inputs:" in message
    assert "owner (input:" in message
    assert "self" in message
    assert "user_a" in message


def test_actor_requirements_are_empty_for_low_signal_non_authz_class():
    assert actor_requirements("/status", "SSRF") == []


def test_actor_requirements_ignore_non_authz_classes_even_on_admin_paths():
    assert actor_requirements("/rest/admin/application-configuration", "Upload") == []


def test_build_summary_does_not_emit_actor_gaps_for_upload_lane_on_admin_path(tmp_path):
    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=["/rest/admin/application-configuration"],
        vuln_classes=["Upload"],
    )

    assert summary["actor_matrix"]["gap_count"] == 0
    assert summary["record_commands"] == []


def test_build_summary_does_not_emit_actor_gaps_for_profile_image_url_action(tmp_path):
    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=["/profile/image/url"],
        vuln_classes=["IDOR", "Authz"],
    )

    assert summary["actor_matrix"]["gap_count"] == 0
    assert summary["record_commands"] == []


def test_build_summary_does_not_emit_idor_actor_gaps_for_non_object_admin_config(tmp_path):
    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=["/rest/admin/application-configuration"],
        vuln_classes=["IDOR"],
    )

    assert summary["actor_matrix"]["gap_count"] == 0
