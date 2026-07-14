"""Tests for tools/evidence_ledger.py."""

from __future__ import annotations

import json

import pytest

from evidence_ledger import (
    actor_requirements,
    build_summary,
    ledger_path,
    record_entry,
)


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

    assert entry["endpoint"] == "/api/accounts/42/export"
    assert entry["method"] == "GET"
    assert entry["vuln_class"] == "IDOR"
    assert entry["actor"] == "owner"
    assert entry["object_scope"] == "own_object"
    assert entry["variant"] == "baseline"
    assert rows[0]["browser_observed"] is True
    assert rows[0]["replayed"] is True


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

    assert entry["endpoint"] == "/#/search"
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


def test_state_changing_record_without_redline_check_is_flagged(tmp_path):
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42/role",
        method="PATCH",
        vuln_class="Authz",
        actor="low_role",
        object_scope="own",
        variant="role_diff",
        result="tested_clean",
    )

    summary = build_summary(
        tmp_path,
        target="target.com",
        focus_endpoints=["/api/accounts/42/role"],
        vuln_classes=["Authz"],
        method="PATCH",
    )

    assert summary["redline_unchecked_count"] == 1
    assert "redline_check_missing_for_state_changing_test" in summary["recent_entries"][0]["warnings"]
    assert any(row["redline_required"] for row in summary["actor_matrix"]["gaps"])


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
