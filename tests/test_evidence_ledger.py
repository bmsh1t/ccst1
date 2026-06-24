"""Tests for tools/evidence_ledger.py."""

from __future__ import annotations

import json

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


def test_actor_requirements_are_empty_for_low_signal_non_authz_class():
    assert actor_requirements("/status", "SSRF") == []
