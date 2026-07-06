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


def test_report_action_does_not_preempt_active_validation_work(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 99,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "V1",
                "priority": 80,
                "type": "ranked-surface",
                "action": "Continue browser-observed API role replay.",
                "command_hint": "python3 tools/validation_runner.py authz-role-replay ...",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    queue = load_queue(tmp_path, "target.com")

    assert select_next_action(queue)["type"] == "ranked-surface"

    validation = next(item for item in queue["actions"] if item["type"] == "ranked-surface")
    resolve_action(
        tmp_path,
        target="target.com",
        action_id=validation["id"],
        status="tested",
        result="Role replay completed; no additional delta.",
    )
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "report"


def test_surface_review_does_not_preempt_report_when_no_substantive_work(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 90,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "S1",
                "priority": 70,
                "type": "surface-review",
                "action": "Review surface candidate https://api.target.com/rest/user.",
                "command_hint": "AI reviews surface evidence, then chooses the exact lane",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "report"


def test_surface_review_with_runner_replay_preempts_report(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 90,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "S1",
                "priority": 70,
                "type": "surface-review",
                "action": "Review surface candidate https://api.target.com/rest/user.",
                "command_hint": "AI reviews surface evidence, then chooses the exact lane",
                "redline_required": False,
                "metadata": {
                    "endpoint": "/rest/user",
                    "replay_draft": (
                        "Run authenticated role replay: "
                        "python3 tools/validation_runner.py authz-role-replay "
                        "--target target.com --url https://api.target.com/rest/user"
                    ),
                },
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    selected = select_next_action(load_queue(tmp_path, "target.com"))

    assert selected["type"] == "surface-review"
    assert selected["metadata"]["endpoint"] == "/rest/user"


def test_legacy_ranked_surface_without_runner_is_advisory(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "R1",
                "priority": 90,
                "type": "report",
                "action": "Draft report for validated finding.",
                "command_hint": "/report",
                "redline_required": False,
            },
            {
                "id": "OLD1",
                "priority": 92,
                "type": "ranked-surface",
                "action": "Continue top ranked surface https://api.target.com/rest/legacy.",
                "command_hint": "focused hunt on ranked P1/P2 surface",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "report"


def test_current_surface_review_beats_stale_legacy_ranked_surface_when_only_advisory(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "OLD1",
                "priority": 92,
                "type": "ranked-surface",
                "action": "Continue top ranked surface https://api.target.com/rest/legacy.",
                "command_hint": "focused hunt on ranked P1/P2 surface",
                "redline_required": False,
            },
            {
                "id": "S1",
                "priority": 70,
                "type": "surface-review",
                "action": "Review surface candidate https://api.target.com/rest/current.",
                "command_hint": "AI reviews surface evidence, then chooses the exact lane",
                "redline_required": False,
            },
        ]
    }

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    selected = select_next_action(load_queue(tmp_path, "target.com"))
    assert selected["type"] == "surface-review"
    assert "current" in selected["action"]


def test_low_evidence_top_advisory_surface_review_does_not_drive_next(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 70,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": (
                "Review surface candidate https://target.com/address/create: "
                "baseline authz and business-logic checks. Reason: top advisory score. "
                "AI decision required: choose the exact lane."
            ),
            "next_question": "Execute checkpoint action.",
            "action": (
                "Review surface candidate https://target.com/address/create: "
                "baseline authz and business-logic checks. Reason: top advisory score. "
                "AI decision required: choose the exact lane."
            ),
            "command_hint": "AI reviews surface evidence, then chooses the exact lane",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "old-low-evidence",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/address/create",
                "suggested": (
                    "baseline authz and business-logic checks. Reason: top advisory score. "
                    "AI decision required: choose the exact lane"
                ),
                "replay_draft": "browser-state-first page route; extract the real XHR first",
            },
        }
    ]

    assert select_next_action(queue) == {}


def test_low_evidence_surface_review_with_exact_runner_stays_selectable(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "queued",
            "priority": 70,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": (
                "Review surface candidate https://target.com/api/users: "
                "baseline authz checks. Reason: top advisory score. "
                "Replay draft: python3 tools/validation_runner.py authz-role-replay "
                "--target target.com --url https://target.com/api/users"
            ),
            "next_question": "Execute checkpoint action.",
            "action": (
                "Review surface candidate https://target.com/api/users: "
                "baseline authz checks. Reason: top advisory score. "
                "Replay draft: python3 tools/validation_runner.py authz-role-replay "
                "--target target.com --url https://target.com/api/users"
            ),
            "command_hint": "AI reviews surface evidence, then chooses the exact lane",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "runner-backed-review",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/api/users",
                "replay_draft": (
                    "python3 tools/validation_runner.py authz-role-replay "
                    "--target target.com --url https://target.com/api/users"
                ),
            },
        }
    ]

    assert select_next_action(queue)["id"] == "AQ-0001"


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
    assert {item["id"] for item in load_queue(tmp_path, "target.com")["actions"]} == {"AQ-0001", "AQ-0002"}
    assert select_next_action(load_queue(tmp_path, "target.com"))["id"] == "AQ-0002"


def test_checkpoint_reingest_can_clear_stale_redline_flag(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 80,
                "type": "actor-gap",
                "status": "ready",
                "action": "Cover actor matrix gap: /api/orders/123 x Authz with anonymous/none/unauth_denied expected=deny status=missing.",
                "command_hint": "focused replay + tools/evidence_ledger.py record",
                "redline_required": True,
                "metadata": {
                    "endpoint": "/api/orders/123",
                    "vuln_class": "Authz",
                    "actor": "anonymous",
                },
            }
        ]
    }
    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    checkpoint["next_action_queue"][0]["redline_required"] = False
    checkpoint["next_action_queue"][0]["priority"] = 54

    ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)

    queue = load_queue(tmp_path, "target.com")
    assert queue["actions"][0]["redline_required"] is False
    assert queue["actions"][0]["priority"] == 54


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
    assert next_action["type"] == "known-software-intel"
    assert select_next_action(load_queue(tmp_path, "target.com"))["type"] == "coverage-gap"


def test_ingest_checkpoint_retires_stale_checkpoint_queued_actions(tmp_path):
    ingest_checkpoint(tmp_path, "target.com", checkpoint=_checkpoint())
    refreshed = {
        "next_action_queue": [
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

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint=refreshed)
    queue = load_queue(tmp_path, "target.com")
    stale = next(item for item in queue["actions"] if item["id"] == "AQ-0001")

    assert result["stats"]["retired_stale"] == 1
    assert stale["status"] == "n/a"
    assert "checkpoint refresh" in stale["result"].lower()


def test_ingest_checkpoint_retires_stale_partial_validation_candidate(tmp_path):
    stale_checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 100,
                "type": "validation",
                "status": "ready",
                "action": "Run /validate for finding F-old on https://target.com/api/feedbacks.",
                "command_hint": "/validate",
                "redline_required": True,
                "metadata": {
                    "endpoint": "/api/feedbacks",
                    "finding_id": "F-old",
                },
            }
        ]
    }
    ingest_checkpoint(tmp_path, "target.com", checkpoint=stale_checkpoint)
    queue = load_queue(tmp_path, "target.com")
    queue["actions"][0]["status"] = "candidate"
    queue["actions"][0]["result"] = "validation-summary=/tmp/feedbacks/validation-summary.json"
    from action_queue import save_queue

    save_queue(tmp_path, "target.com", queue)

    refreshed = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 100,
                "type": "validation",
                "status": "ready",
                "action": "Run /validate for finding F-new on https://target.com/rest/products/search?q=apple.",
                "command_hint": "/validate",
                "redline_required": True,
                "metadata": {
                    "endpoint": "/rest/products/search",
                    "finding_id": "F-new",
                },
            }
        ]
    }

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint=refreshed)
    saved = load_queue(tmp_path, "target.com")
    stale = next(item for item in saved["actions"] if item["metadata"]["finding_id"] == "F-old")

    assert result["stats"]["retired_stale"] == 1
    assert stale["status"] == "n/a"
    assert select_next_action(saved)["metadata"]["finding_id"] == "F-new"


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
                "type": "action-gated-review",
                "status": "ready",
                "action": "Review action-gated scanner lane abcdef1234567890: 1 unresolved skipped probe line(s). Artifact=findings/target.com/manual_review/unsafe_skipped.txt. Decide tested, blocked, dead-end, n/a, or candidate; only rerun with ALLOW_UNSAFE_HTTP_TESTS=1 after explicit operator opt-in.",
                "command_hint": "review legacy unsafe_skipped.txt; resolve queue with tested/blocked/dead-end/n/a/candidate",
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


def test_superseded_candidate_gap_does_not_steer_next_action(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "candidate",
            "priority": 105,
            "type": "candidate-evidence-gap",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Candidate evidence gap for authz-role-replay-api_users.",
            "next_question": "Fill missing policy evidence.",
            "action": "Candidate evidence gap for authz-role-replay-api_users.",
            "command_hint": "fill missing rubric evidence, then /validate",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "candidate",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
        {
            "id": "AQ-0002",
            "status": "validated",
            "priority": 60,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Validated role replay.",
            "next_question": "done",
            "action": "Validated role replay.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "validated",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
        {
            "id": "AQ-0003",
            "status": "queued",
            "priority": 50,
            "type": "case-state-enrichment",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Find object endpoint.",
            "next_question": "Find endpoint.",
            "action": "Find object endpoint.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:02Z",
            "dedupe_key": "next",
        },
    ]

    assert select_next_action(queue)["id"] == "AQ-0003"


def test_ingest_checkpoint_retires_superseded_candidate_gap(tmp_path):
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [
        {
            "id": "AQ-0001",
            "status": "candidate",
            "priority": 105,
            "type": "candidate-evidence-gap",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Candidate evidence gap for authz-role-replay-api_users.",
            "next_question": "Fill missing policy evidence.",
            "action": "Candidate evidence gap for authz-role-replay-api_users.",
            "command_hint": "fill missing rubric evidence, then /validate",
            "created_at": "2026-01-01T00:00:00Z",
            "dedupe_key": "candidate",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
        {
            "id": "AQ-0002",
            "status": "validated",
            "priority": 60,
            "type": "surface-review",
            "evidence_type": "checkpoint-next-action",
            "evidence": "Validated role replay.",
            "next_question": "done",
            "action": "Validated role replay.",
            "command_hint": "",
            "created_at": "2026-01-01T00:00:01Z",
            "dedupe_key": "validated",
            "source": "checkpoint",
            "metadata": {
                "endpoint": "/api/users",
                "finding_id": "authz-role-replay-api_users",
            },
        },
    ]
    from action_queue import save_queue

    save_queue(tmp_path, "target.com", queue)

    result = ingest_checkpoint(tmp_path, "target.com", checkpoint={"next_action_queue": []})
    saved = load_queue(tmp_path, "target.com")

    assert result["stats"]["retired_superseded"] == 1
    assert saved["actions"][0]["status"] == "n/a"


def test_ingest_checkpoint_reopens_runner_only_validated_action(tmp_path):
    checkpoint = {
        "next_action_queue": [
            {
                "id": "A1",
                "priority": 100,
                "type": "validation",
                "status": "ready",
                "action": (
                    "Run /validate for finding AUTHZ-SYNC on https://target.com/api/Feedbacks; "
                    "verify replay, A/B diff, impact, evidence rubric, and red-line safety before report."
                ),
                "command_hint": "/validate",
                "redline_required": True,
                "stop_condition": "run validate gates",
            }
        ]
    }
    first = ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    queue = load_queue(tmp_path, "target.com")
    action = queue["actions"][0]
    action["status"] = "validated"
    action["result"] = "validation-runner-result=tested_finding; summary=evidence/target.com/validation/authz/summary.json"
    from action_queue import save_queue

    save_queue(tmp_path, "target.com", queue)

    second = ingest_checkpoint(tmp_path, "target.com", checkpoint=checkpoint)
    saved = load_queue(tmp_path, "target.com")

    assert first["stats"]["added"] == 1
    assert second["stats"]["updated"] == 1
    assert second["stats"]["skipped_final"] == 0
    assert saved["actions"][0]["status"] == "queued"
    assert second["next"]["id"] == saved["actions"][0]["id"]
    assert "runner evidence is candidate-only" in saved["actions"][0]["notes"]


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
