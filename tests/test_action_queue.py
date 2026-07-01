"""Tests for the persistent autopilot action queue."""

from __future__ import annotations

import json

from action_queue import (
    add_manual_action,
    format_action,
    ingest_checkpoint,
    load_queue,
    main,
    resolve_action,
    select_next_action,
    summarize_queue,
)
from coverage_matrix import load_matrix


def _checkpoint() -> dict:
    return {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 75,
                "type": "coverage-gap",
                "status": "ready",
                "action": "Cover high-value matrix gap: /api/admin/users x IDOR.",
                "command_hint": "focused low-risk probe + evidence ledger",
                "redline_required": True,
                "stop_condition": "record tested, blocked, dead-end, or candidate",
                "metadata": {
                    "endpoint": "/api/admin/users",
                    "vuln_class": "Authz",
                    "weight": "5.0",
                    "relevance_score": 13,
                },
            },
            {
                "id": "A2",
                "priority": 90,
                "type": "known-software-intel",
                "status": "ready",
                "action": "Check known advisories for WordPress plugin X 1.2.3.",
                "command_hint": "/intel + cve_hunter",
                "redline_required": False,
            },
        ]
    }


def test_ingest_checkpoint_persists_and_prioritizes(tmp_path):
    result = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())

    assert result["stats"]["added"] == 2
    assert result["next"]["type"] in {"known-software-intel", "coverage-gap"}
    assert result["next"]["type"] != "generic-follow-up"

    queue = load_queue(tmp_path, "target.com")
    assert summarize_queue(queue)["active"] == 2
    assert (tmp_path / "state" / "target.com" / "action_queue.json").is_file()


def test_ingest_checkpoint_preserves_structured_metadata(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())

    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

    assert coverage["metadata"]["endpoint"] == "/api/admin/users"
    assert coverage["metadata"]["vuln_class"] == "Authz"
    assert "Metadata: endpoint=/api/admin/users" in format_action(coverage)


def test_ingest_checkpoint_dedupes_active_actions(tmp_path):
    first = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())

    assert first["stats"]["added"] == 2
    assert second["stats"]["added"] == 0
    assert second["stats"]["updated"] == 2
    assert load_queue(tmp_path, "target.com")["actions"][0]["id"] == "AQ-0001"


def test_resolve_final_action_prevents_readding_same_todo(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    next_action = select_next_action(load_queue(tmp_path, "target.com"))

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=next_action["id"],
        status="dead-end",
        result="Version not affected after advisory range check.",
    )
    assert resolved["status"] == "dead-end"

    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    assert second["stats"]["skipped_final"] == 1
    assert summarize_queue(load_queue(tmp_path, "target.com"))["total"] == 2
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "known-software-intel"


def test_manual_action_add_and_resolve_to_candidate(tmp_path):
    added = add_manual_action(
        tmp_path,
        target="api.target.com",
        action_type="browser-api",
        evidence_type="browser-xhr",
        evidence="Dashboard calls /api/internal/export.",
        next_question="Can anonymous or low-role replay access export data?",
        action="Replay with anonymous and low-role sessions, then record role diff.",
        priority=88,
        command_hint="browser capture + role_diff",
    )
    assert added["stats"]["added"] == 1

    queue = load_queue(tmp_path, "api.target.com")
    action = select_next_action(queue)
    assert action["id"] == "AQ-0001"
    assert action["redline_required"] is True

    resolved = resolve_action(
        tmp_path,
        target="api.target.com",
        action_id="AQ-0001",
        status="candidate",
        result="Low-role replay returned another tenant export metadata.",
        notes="Needs exact /validate replay.",
    )
    assert resolved["summary"]["by_status"]["candidate"] == 1
    saved = json.loads((tmp_path / "state" / "api.target.com" / "action_queue.json").read_text())
    assert saved["actions"][0]["status"] == "candidate"


def test_manual_action_cli_accepts_stop_condition_for_high_risk_lane(tmp_path):
    code = main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--type", "ssrf-parser-boundary",
        "--evidence", "URL fetch path accepts user-controlled callback URL.",
        "--next-question", "Does parser normalization change internal host handling?",
        "--action", "python3 tools/context_pack.py --target api.target.com --focus ssrf",
        "--command-hint", "python3 tools/context_pack.py --target api.target.com --focus ssrf",
        "--stop-condition", "Stop after a read-only parser-boundary probe is recorded as tested, blocked, dead-end, signal, or candidate.",
        "--json",
    ])

    assert code == 0
    queue = load_queue(tmp_path, "api.target.com")
    action = queue["actions"][0]
    assert action["type"] == "ssrf-parser-boundary"
    assert action["stop_condition"].startswith("Stop after a read-only parser-boundary probe")
    assert action["stop_condition"] != "record tested, dead-end, blocked, lead, signal, candidate, or validated before moving to the next queued action"


def test_resolve_accepts_coverage_status_aliases(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    next_action = select_next_action(load_queue(tmp_path, "target.com"))

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=next_action["id"],
        status="tested_clean",
        result="Low-risk replay showed no diff.",
    )

    assert resolved["status"] == "tested"
    assert resolved["summary"]["by_status"]["tested"] == 1


def test_resolve_coverage_gap_updates_coverage_matrix(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=coverage["id"],
        status="tested_clean",
        result="Low-risk replay showed no role/object difference.",
    )

    matrix = load_matrix("target.com", repo_root=tmp_path)
    endpoint = next(item for item in matrix["endpoints"] if item["endpoint"] == "/api/admin/users")
    cell = endpoint["cells"]["Authz"]

    assert resolved["coverage_update"]["status"] == "updated"
    assert resolved["coverage_update"]["coverage_status"] == "tested_clean"
    assert cell["status"] == "tested_clean"
    assert "Low-risk replay" in cell["reason"]


def test_resolve_coverage_gap_candidate_marks_tested_finding(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    queue = load_queue(tmp_path, "target.com")
    coverage = next(item for item in queue["actions"] if item["type"] == "coverage-gap")

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id=coverage["id"],
        status="tested_finding",
        result="Low-role replay returned another tenant's admin user metadata.",
    )

    matrix = load_matrix("target.com", repo_root=tmp_path)
    endpoint = next(item for item in matrix["endpoints"] if item["endpoint"] == "/api/admin/users")

    assert resolved["status"] == "candidate"
    assert resolved["coverage_update"]["coverage_status"] == "tested_finding"
    assert endpoint["cells"]["Authz"]["status"] == "tested_finding"


def test_resolve_unsafe_skipped_review_persists_resolution(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 88,
                "type": "unsafe-skipped-review",
                "status": "ready",
                "action": "Review unsafe-skipped scanner lane abcdef1234567890: 1 unresolved skipped probe line(s). Artifact=findings/target.com/manual_review/unsafe_skipped.txt. Decide tested, blocked, dead-end, n/a, or candidate; only rerun with ALLOW_UNSAFE_HTTP_TESTS=1 after explicit operator opt-in.",
                "command_hint": "review unsafe_skipped.txt; resolve queue with tested/blocked/dead-end/n/a/candidate",
                "redline_required": True,
                "metadata": {
                    "unsafe_skipped_id": "abcdef1234567890",
                    "artifact": "findings/target.com/manual_review/unsafe_skipped.txt",
                },
            }
        ]
    }
    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)

    resolved = resolve_action(
        tmp_path,
        target="target.com",
        action_id="AQ-0001",
        status="blocked",
        result="Requires explicit operator opt-in for state-changing scanner probes.",
    )

    review_path = tmp_path / "state" / "target.com" / "unsafe_skipped_reviews.json"
    payload = json.loads(review_path.read_text(encoding="utf-8"))

    assert resolved["unsafe_review_update"]["status"] == "updated"
    assert payload["resolved"]["abcdef1234567890"]["status"] == "blocked"
    assert "operator opt-in" in payload["resolved"]["abcdef1234567890"]["result"]


def test_resolve_cli_accepts_evidence_alias(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    next_action = select_next_action(load_queue(tmp_path, "target.com"))

    code = main([
        "--repo-root", str(tmp_path),
        "resolve",
        "--target", "target.com",
        "--id", next_action["id"],
        "--status", "tested_finding",
        "--evidence", "Evidence is strong enough to promote to candidate.",
        "--json",
    ])

    assert code == 0
    saved = load_queue(tmp_path, "target.com")
    resolved = next(item for item in saved["actions"] if item["id"] == next_action["id"])
    assert resolved["status"] == "candidate"
    assert resolved["result"] == "Evidence is strong enough to promote to candidate."


def test_high_value_actions_sort_ahead_of_generic_actions(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 50,
            "type": "generic-follow-up",
            "evidence_type": "generic",
            "evidence": "Review notes.",
            "next_question": "What next?",
            "action": "Check homepage.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "a",
        },
        {
            "id": "AQ-0002",
            "status": "queued",
            "priority": 50,
            "type": "known-software-intel",
            "evidence_type": "known-software",
            "evidence": "WordPress plugin version needs CVE applicability check.",
            "next_question": "Is the path reachable?",
            "action": "Check exact affected version and reachable route.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "b",
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0002"


def test_candidate_evidence_gap_sorts_ahead_of_plain_validation(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 100,
            "type": "validation",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Run /validate for finding F-1.",
            "next_question": "Validate candidate.",
            "action": "Run /validate for finding F-1.",
            "command_hint": "/validate",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "validate",
        },
        {
            "id": "AQ-0002",
            "status": "queued",
            "priority": 105,
            "type": "candidate-evidence-gap",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Candidate evidence gap for SQLi; missing baseline diff.",
            "next_question": "Fill missing rubric evidence.",
            "action": "Replay baseline vs perturbation and capture stable diff.",
            "command_hint": "fill missing rubric evidence, then /validate",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "gap",
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0002"


def test_relevance_metadata_breaks_same_endpoint_coverage_ties(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    common = {
        "status": "queued",
        "priority": 75,
        "type": "coverage-gap",
        "evidence_type": "checkpoint-next-action",
        "next_question": "Execute checkpoint action.",
        "command_hint": "focused low-risk probe + evidence ledger",
        "created_at": "2026-01-01T00:00:00Z",
    }
    queue["actions"] = [
        {
            **common,
            "id": "AQ-0001",
            "evidence": "Cover high-value matrix gap: /api/v1/admin/users x IDOR.",
            "action": "Cover high-value matrix gap: /api/v1/admin/users x IDOR.",
            "dedupe_key": "idor",
            "metadata": {
                "endpoint": "/api/v1/admin/users",
                "vuln_class": "IDOR",
                "relevance_score": 9,
            },
        },
        {
            **common,
            "id": "AQ-0002",
            "evidence": "Cover high-value matrix gap: /api/v1/admin/users x Authz.",
            "action": "Cover high-value matrix gap: /api/v1/admin/users x Authz.",
            "dedupe_key": "authz",
            "metadata": {
                "endpoint": "/api/v1/admin/users",
                "vuln_class": "Authz",
                "relevance_score": 13,
            },
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0002"
