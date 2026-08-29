"""Tests for tools/autopilot_state.py."""

import json
import hashlib
import sys
import time

import pytest

import autopilot_state as autopilot_state_module
import finding_index
from action_queue import (
    add_manual_action,
    claim_next_action,
    ingest_checkpoint,
    load_queue,
    queue_path,
    queue_fingerprint,
    resolve_action,
)
from tools import surface as surface_module
from tools.surface_projection import build_surface_input_manifest, write_surface_projection
from memory.hunt_journal import HuntJournal
from memory.pattern_db import PatternDB
from memory.schemas import make_journal_entry, make_pattern_entry
from memory.target_profile import make_target_profile, save_target_profile
from autopilot_state import (
    _build_enrichment_hints,
    _build_priority_frontier,
    _build_ranker_advisory_hint,
    _build_recommended_targets,
    _checkpoint_round_projection,
    _filter_ranked_placeholders,
    _filter_legacy_memory_candidates,
    _filter_stale_finalized_scanner_candidates,
    _is_substantive_queue_action,
    _load_closure_projection,
    _load_loop_guard_projection,
    _load_json_inject_projection,
    _load_js_intel_projection,
    _load_sql_matrix_projection,
    _pick_next_action,
    build_closure_projection,
    build_decision_projection,
    build_loop_guard_projection,
    build_autopilot_state,
    format_autopilot_state,
    load_closure_projection,
    stagnation_fingerprint,
    main as autopilot_state_main,
)
from request_guard import record_request
from runtime_state import runtime_phase_lock, update_runtime_state
from target_paths import target_storage_key


def test_ranker_advisory_requires_valid_long_tail_and_multiple_evidence_groups(tmp_path):
    ranked = {
        "stats": {
            "review_pool": 4,
            "semantic_shape_count": 12,
            "raw_urls": 40,
            "observation_untouched": 3,
            "observation_stale": 1,
        },
        "browser": {"xhr_count": 2, "api_count": 0},
        "source_intel": {"hypothesis_count": 1},
        "review_pool": [{"url": "https://target.test/orders", "tech_stack": ["nginx"]}],
    }

    hint = _build_ranker_advisory_hint(
        surface_projection={"status": "valid"},
        ranked=ranked,
        next_action="handoff",
    )

    assert hint["tool"] == "recon-ranker"
    assert hint["mode"] == "advisory"
    assert hint["executable"] is False
    assert "untouched observations" in hint["reason"]
    assert _build_ranker_advisory_hint(
        surface_projection={"status": "stale"},
        ranked=ranked,
        next_action="handoff",
    ) == {}
    assert _build_ranker_advisory_hint(
        surface_projection={"status": "valid"},
        ranked=ranked,
        next_action="handoff",
        browser_pending=True,
    ) == {}


def test_ranker_advisory_never_becomes_next_tool_hint(tmp_path):
    next_tool, hints = _build_enrichment_hints(
        repo_root=str(tmp_path),
        resolved_target="target.test",
        surface_context={},
        ranked={
            "stats": {
                "review_pool": 1,
                "semantic_shape_count": 3,
                "raw_urls": 8,
                "observation_untouched": 2,
            },
            "browser": {"xhr_count": 1},
            "source_intel": {"hypothesis_count": 1},
            "review_pool": [{"url": "https://target.test/orders", "tech_stack": ["nginx"]}],
        },
        surface_projection={"status": "valid"},
        repo_source_available=False,
        next_action="handoff",
        browser_evidence={"ready": True},
    )

    assert next_tool == ""
    assert [item["tool"] for item in hints] == ["recon-ranker"]


def _record_owner_provenance(findings_dir, finding_id: str) -> None:
    """Turn a fixture's declared finality into a real owner mutation."""
    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item.get("id") == finding_id)
    updated = finding_index.update_finding_status(
        findings_dir,
        finding_id,
        validation_status=finding.get("validation_status", "unvalidated"),
        report_status=finding.get("report_status", "not_generated"),
    )
    assert updated is not None


def test_browser_context_discovery_queue_item_is_substantive():
    assert _is_substantive_queue_action(
        {
            "status": "queued",
            "source": "browser-context-discovery",
            "evidence_type": "browser-context-discovery",
        }
    )
    assert not _is_substantive_queue_action(
        {
            "status": "queued",
            "source": "browser-context-discovery",
            "evidence_type": "generic",
        }
    )


def test_legacy_memory_surface_hints_stay_visible_but_do_not_steer_without_focus():
    ranked = {
        "review_pool": [
            {"url": "https://target.test/old", "review_reason": "target-memory continuation"},
            {"url": "https://target.test/live", "review_reason": "scanner lead requiring AI triage"},
        ],
        "p1": [
            {"url": "https://target.test/old", "review_reason": "target-memory continuation"},
            {"url": "https://target.test/live", "review_reason": "scanner lead requiring AI triage"},
        ],
    }

    filtered = _filter_legacy_memory_candidates(ranked, [])

    assert [item["url"] for item in filtered["review_pool"]] == ["https://target.test/live"]
    assert [item["url"] for item in filtered["p1"]] == ["https://target.test/live"]
    assert ranked["review_pool"][0]["url"] == "https://target.test/old"
    assert _filter_legacy_memory_candidates(ranked, ["/old"]) == ranked


def test_finalized_scanner_candidates_are_deferred_without_hiding_raw_surface():
    ranked = {
        "review_pool": [
            {
                "url": "https://target.test/static/bundle.js",
                "scanner_findings": [
                    {"validation_status": "rejected", "report_status": "not_generated"}
                ],
            },
            {
                "url": "https://target.test/api/orders",
                "scanner_findings": [
                    {"validation_status": "rejected", "report_status": "not_generated"}
                ],
                "new_observation": True,
            },
        ],
        "p1": [],
        "p2": [],
    }

    filtered = _filter_stale_finalized_scanner_candidates(ranked)

    assert filtered["review_pool"] == [ranked["review_pool"][1]]
    assert filtered["deferred_surface_candidates"][0]["url"].endswith("bundle.js")
    assert ranked["review_pool"][0]["url"].endswith("bundle.js")


def test_generic_intel_does_not_activate_finalized_static_candidate():
    generic = {
        "url": "https://target.test/static/bundle.js",
        "scanner_findings": [{"validation_status": "rejected", "report_status": "not_generated"}],
        "intel_signals": [{"id": "CVE-1", "source": "osv", "applicability": "affected"}],
    }
    route_bound = {
        "url": "https://target.test/static/bundle.js",
        "scanner_findings": [{"validation_status": "rejected", "report_status": "not_generated"}],
        "intel_signals": [{"id": "CVE-2", "source": "osv", "route": "/api/orders", "applicability": "affected"}],
    }

    filtered = _filter_stale_finalized_scanner_candidates({
        "review_pool": [generic, route_bound],
        "p1": [],
        "p2": [],
    })

    assert filtered["review_pool"] == [route_bound]
    assert filtered["deferred_surface_candidates"][0]["intel_packet"][0]["id"] == "CVE-1"


def test_deep_js_review_queue_item_is_substantive():
    action = {
        "status": "queued",
        "type": "deep-js-review",
        "evidence_type": "recon-artifact",
        "command_hint": "/js-read target.com",
    }

    assert _is_substantive_queue_action(action)
    assert not _is_substantive_queue_action({**action, "evidence_type": "generic"})


def test_actor_context_enrichment_lead_is_advisory_until_context_exists():
    action = {
        "status": "queued",
        "type": "case-state-enrichment",
        "source": "checkpoint",
        "evidence_type": "checkpoint-next-action",
        "command_hint": "register actor/session/object with tools/target_case_state.py",
        "metadata": {
            "missing_evidence": [
                "second actor",
                "peer/second session",
                "business object",
            ],
        },
    }

    assert not _is_substantive_queue_action(action)
    assert _is_substantive_queue_action({**action, "status": "running"})
    assert _is_substantive_queue_action({
        **action,
        "metadata": {"missing_evidence": ["object endpoint"]},
    })


def test_persisted_actor_context_enrichment_does_not_block_closure(tmp_path):
    target = "target.test"
    matrix_path = tmp_path / "evidence" / target / "coverage_matrix.json"
    matrix_path.parent.mkdir(parents=True)
    matrix_path.write_text(json.dumps(_closure_matrix()), encoding="utf-8")
    ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={
            "target": target,
            "next_action_queue": [{
                "id": "A1",
                "priority": 54,
                "type": "case-state-enrichment",
                "status": "ready",
                "action": (
                    "Case-state enrichment lead: actor matrix has a role gap. "
                    "Missing evidence: second actor, peer/second session, business object."
                ),
                "command_hint": "register actor/session/object with tools/target_case_state.py",
                "metadata": {
                    "endpoint": "/api/orders/1",
                    "vuln_class": "IDOR",
                    "missing_evidence": [
                        "second actor",
                        "peer/second session",
                        "business object",
                    ],
                },
            }],
        },
    )

    closure = load_closure_projection(
        str(tmp_path),
        {
            "target": target,
            "resolved_target": target,
            "has_recon": True,
            "next_action": "handoff",
            "surface_projection": {"status": "valid"},
            "case_state": {
                "status": "valid",
                "authz_coverage": {
                    "status": "missing",
                    "authenticated_actor_count": 0,
                    "authenticated_session_count": 0,
                },
            },
        },
        max_lanes_reached=False,
    )

    assert closure["verdict"] == "finish"
    assert closure["reasons"] == []
    assert closure["actor_context_gap"]["blocking"] is False
    assert "durable_work_pending" not in closure["reasons"]


def test_asset_scope_workflow_review_is_substantive_but_other_advisory_leads_are_not():
    action = {
        "status": "ready",
        "type": "workflow-lead-review",
        "source": "workflow-lead",
        "metadata": {"category": "asset-scope-review"},
    }

    assert _is_substantive_queue_action(action)
    assert not _is_substantive_queue_action(
        {**action, "metadata": {"category": "public-metadata"}}
    )


def test_legacy_checkpoint_coverage_action_rechecks_current_relevance():
    base = {
        "status": "queued",
        "type": "coverage-gap",
        "evidence_type": "checkpoint-next-action",
        "source": "checkpoint",
        "attempts": 0,
    }

    assert not _is_substantive_queue_action({
        **base,
        "metadata": {
            "endpoint": "/api/public/job-alerts/renew",
            "vuln_class": "RCE",
            "relevance_score": 15,
        },
    })
    assert _is_substantive_queue_action({
        **base,
        "metadata": {
            "endpoint": "/api/jobs/123/run",
            "vuln_class": "RCE",
        },
    })


def test_asset_scope_workflow_review_routes_autopilot_to_durable_queue(tmp_path):
    queue_dir = tmp_path / "state" / "target.com"
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "actions": [
                    {
                        "id": "AQ-0001",
                        "status": "queued",
                        "type": "workflow-lead-review",
                        "priority": 88,
                        "source": "workflow-lead",
                        "action": "Review target-linked external asset scope evidence.",
                        "metadata": {"category": "asset-scope-review"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    state = build_autopilot_state(
        str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory")
    )

    assert state["action_queue_next"]["id"] == "AQ-0001"
    assert state["next_action"] == "resume_action_queue"


def test_queue_resolution_rebuilds_state_from_durable_owner_facts(tmp_path):
    target = "target.com"
    memory_dir = tmp_path / "hunt-memory"
    ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={
            "next_action_queue": [
                {
                    "id": "AQ-OWNER",
                    "priority": 90,
                    "type": "workflow-lead-review",
                    "status": "ready",
                    "action": "Review one durable owner fact.",
                    "metadata": {"category": "asset-scope-review"},
                }
            ]
        },
    )
    before = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))
    witness_path = tmp_path / "state" / target / "checkpoint_latest.json"
    witness_path.parent.mkdir(parents=True, exist_ok=True)
    witness_path.write_text(
        json.dumps({
            "schema_version": 1,
            "kind": "autopilot_checkpoint_witness",
            "target": target,
            "action_queue": {"synchronized": True, "next_id": before["action_queue_next"]["id"]},
        }),
        encoding="utf-8",
    )
    claim = claim_next_action(tmp_path, target)
    resolved = resolve_action(
        tmp_path,
        target=target,
        action_id=claim["id"],
        status="blocked",
        result="Bounded owner review is unavailable.",
    )
    after = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))

    assert before["next_action"] == "resume_action_queue"
    assert before["action_queue_next"]["id"] == claim["id"]
    assert resolved["next"] == {}
    assert after["action_queue_next"] == {}
    assert after["next_action"] != "resume_action_queue"
    closure = load_closure_projection(str(tmp_path), after, max_lanes_reached=False)
    assert closure.get("round_progress", {}) == {}
    assert closure.get("checkpoint_health", {}).get("status") == "valid"


def test_ai_action_outside_initial_frontier_uses_queue_owner_and_resumes(tmp_path):
    target = "target.com"
    ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={
            "next_action_queue": [
                {
                    "id": "AQ-INITIAL",
                    "priority": 90,
                    "type": "workflow-lead-review",
                    "status": "ready",
                    "action": "Review the initial owner-backed action.",
                    "metadata": {"category": "asset-scope-review"},
                }
            ]
        },
    )
    initial = build_autopilot_state(
        str(tmp_path), target, memory_dir=str(tmp_path / "hunt-memory")
    )
    initial_frontier_ids = {
        item["id"] for item in initial["priority_frontier"]
    }

    added = add_manual_action(
        tmp_path,
        target=target,
        action_type="ai-created-frontier-extension",
        evidence="AI identified a target-owned workflow dimension not projected initially.",
        next_question="Can the newly selected workflow dimension be replayed safely?",
        action="Replay the newly selected workflow dimension and record its disposition.",
        priority=1,
        source="ai",
        source_id="frontier-extension",
    )
    new_action = next(
        item
        for item in added["queue"]["actions"]
        if item["type"] == "ai-created-frontier-extension"
    )
    registered = build_autopilot_state(
        str(tmp_path), target, memory_dir=str(tmp_path / "hunt-memory")
    )

    assert new_action["id"] not in initial_frontier_ids
    assert new_action["id"] not in {
        item["id"] for item in registered["priority_frontier"]
    }
    assert any(
        item["id"] == new_action["id"]
        for item in load_queue(tmp_path, target)["actions"]
    )
    claimed = claim_next_action(tmp_path, target, action_id=new_action["id"])
    resumed = claim_next_action(tmp_path, target, action_id=new_action["id"])

    assert claimed["claim_status"] == "claimed"
    assert resumed["claim_status"] == "resumed"
    saved = load_queue(tmp_path, target)
    persisted = next(item for item in saved["actions"] if item["id"] == new_action["id"])
    assert persisted["status"] == "running"
    assert persisted["attempts"] == 1


def test_pending_cidr_continuation_routes_back_to_recon():
    assert _pick_next_action(
        True,
        {"p1": [], "p2": []},
        None,
        cidr_continuation={"status": "pending", "next_offset": 4096},
    ) == "run_recon"


def test_priority_frontier_exposes_queue_and_surface_without_cross_owner_score():
    frontier = _build_priority_frontier({
        "target": "target.com",
        "resolved_target": "target.com",
        "action_queue_next": {
            "id": "AQ-1",
            "status": "queued",
            "priority": 100,
            "action": "Replay the historical low-impact response pair.",
            "evidence": "evidence/target.com/queue/raw.json",
            "next_question": "Does the old response difference still reproduce?",
            "stop_condition": "Record one stable replay disposition.",
        },
        "surface_projection": {
            "status": "valid",
            "path": "state/target.com/surface-projection.json",
        },
        "surface_review_candidates": [{
            "url": "https://target.com/admin/export",
            "suggested": "review privileged export authorization",
            "review_reason": "crown-jewel workflow with a new authenticated observation",
            "score": 12,
        }],
    })

    assert [item["owner"] for item in frontier] == ["action_queue", "surface"]
    assert all("priority" not in item for item in frontier)
    assert frontier[0]["closure_blocking"] is True
    assert frontier[1]["closure_blocking"] is False
    assert frontier[1]["runnable"] is True


def test_priority_frontier_keeps_one_head_for_each_present_owner():
    frontier = _build_priority_frontier({
        "target": "target.com",
        "resolved_target": "target.com",
        "action_queue_next": {
            "id": "AQ-1",
            "action": "replay queue evidence",
            "evidence": "evidence/target.com/queue.json",
            "next_question": "does the owner response persist?",
        },
        "structured_findings": {
            "next_validation": {
                "id": "finding-1",
                "required_action": "validate the candidate",
                "evidence_ref": "findings/target.com/finding.json",
            },
        },
        "validation_runner_next": {
            "id": "runner-1",
            "summary_path": "evidence/target.com/validation/summary.json",
            "next_action": "review runner evidence",
        },
        "intel_continuation": {
            "action": "test_advisory_applicability",
            "reason": "version applicability is unresolved",
        },
        "case_state": {
            "status": "valid",
            "top_next_action": {
                "next_action": "compare owner and peer",
                "why_now": "a case obligation remains open",
            },
        },
        "json_inject": {"status": "partial", "path": "findings/target.com/json.json"},
        "surface_review_candidates": [{
            "url": "https://target.com/admin/export",
            "suggested": "review export authorization",
        }],
    })

    owners = {item["owner"] for item in frontier}
    assert owners >= {
        "action_queue",
        "finding",
        "validation-runner",
        "intel",
        "surface",
        "case_state",
        "json-inject",
    }
    assert [item["owner"] for item in frontier[:5]] == [
        "action_queue",
        "finding",
        "validation-runner",
        "intel",
        "surface",
    ]
    assert all("priority" not in item for item in frontier)


def test_text_state_projects_frontier_and_ignores_unprojected_payload():
    output = format_autopilot_state({
        "target": "target.com",
        "target_kind": "domain",
        "has_recon": True,
        "has_memory": False,
        "next_action": "hunt_p1",
        "fallback_action": "hunt_p1",
        "selection_mode": "ai_priority",
        "hard_gate": {},
        "priority_frontier": [{
            "owner": "surface",
            "action": "review privileged export authorization",
            "id": "https://target.com/admin/export",
            "runnable": True,
            "closure_blocking": False,
            "raw": "do-not-project",
        }],
        "tech_stack": [],
    })

    assert "Selection mode: ai_priority" in output
    assert "Priority frontier (AI selects; array order is not priority):" in output
    assert "surface: review privileged export authorization" in output
    assert "non-blocking" in output
    assert "do-not-project" not in output


def test_text_state_projects_hard_gate_without_frontier_payload():
    output = format_autopilot_state({
        "target": "target.com",
        "target_kind": "domain",
        "has_recon": False,
        "has_memory": False,
        "next_action": "wait_recon",
        "fallback_action": "wait_recon",
        "selection_mode": "hard_gate",
        "hard_gate": {
            "action": "wait_recon",
            "reason": "the target recon phase lock is still held",
            "raw": "do-not-project",
        },
        "priority_frontier": [],
    })

    assert "Hard gate: wait_recon (the target recon phase lock is still held)" in output
    assert "Priority frontier" not in output
    assert "do-not-project" not in output


def _closure_matrix(*, status: str = "tested_clean") -> dict:
    return {
        "endpoints": [{
            "endpoint": "/api/orders/1",
            "weight": 3.0,
            "cells": {"IDOR": {"status": status}},
        }],
        "summary": {"total_cells": 1},
    }


def _publish_surface_projection(repo_root, target: str, memory_dir=None) -> None:
    memory_dir = memory_dir or (repo_root / "hunt-memory")
    inventory_path = repo_root / "recon" / target / "live" / "technology_inventory.json"
    had_inventory = inventory_path.is_file()
    context = surface_module.load_surface_context(
        repo_root,
        target,
        memory_dir=memory_dir,
        write_probe_log=False,
    )
    if not had_inventory and inventory_path.is_file():
        inventory_path.unlink()
    manifest = build_surface_input_manifest(repo_root, target, memory_dir=memory_dir)
    write_surface_projection(
        repo_root,
        target,
        surface_module.rank_surface(context),
        manifest=manifest,
        memory_dir=memory_dir,
    )


def test_closure_finishes_only_for_gap_free_handoff_state():
    closure = build_closure_projection({"next_action": "handoff"}, _closure_matrix())

    assert closure["verdict"] == "finish"
    assert closure["can_claim_exhausted"] is True
    assert closure["reasons"] == []


def test_closure_keeps_actor_context_gap_advisory():
    matrix = {
        **_closure_matrix(),
        "high_risk_lanes": {
            "IDOR": {"disposition": "tested"},
            "Authz": {"disposition": "tested"},
            "GraphQL": {"disposition": "not_observed"},
        },
    }
    closure = build_closure_projection(
        {
            "next_action": "handoff",
            "case_state": {
                "status": "valid",
                "authz_coverage": {
                    "status": "missing",
                    "authenticated_actor_count": 0,
                    "authenticated_session_count": 0,
                },
            },
        },
        matrix,
    )

    assert closure["verdict"] == "finish"
    assert closure["can_claim_exhausted"] is True
    assert closure["reasons"] == []
    assert closure["authz_coverage"]["status"] == "missing"
    assert closure["actor_context_gap"] == {
        "status": "missing",
        "reason": "actor_context_missing",
        "lanes": ["IDOR", "Authz"],
        "blocking": False,
        "required_context": "owner/peer actor and session context",
    }
    assert not stagnation_fingerprint(
        {
            "target": "target.test",
            "case_state": {
                "status": "valid",
                "authz_coverage": {"status": "missing"},
            },
        },
        closure,
    )


def test_partial_actor_context_remains_non_blocking():
    matrix = {
        **_closure_matrix(),
        "high_risk_lanes": {
            "IDOR": {"disposition": "tested"},
            "Authz": {"disposition": "tested"},
        },
    }
    closure = build_closure_projection(
        {
            "next_action": "handoff",
            "case_state": {
                "status": "valid",
                "authz_coverage": {
                    "status": "partial",
                    "authenticated_actor_count": 1,
                    "authenticated_session_count": 1,
                },
            },
        },
        matrix,
    )

    assert closure["verdict"] == "finish"
    assert closure["reasons"] == []
    assert closure["actor_context_gap"]["status"] == "partial"
    assert closure["actor_context_gap"]["reason"] == "actor_context_incomplete"
    assert closure["actor_context_gap"]["blocking"] is False


def test_ready_actor_context_has_no_deferred_gap():
    matrix = {
        **_closure_matrix(),
        "high_risk_lanes": {
            "IDOR": {"disposition": "tested"},
            "Authz": {"disposition": "tested"},
        },
    }
    closure = build_closure_projection(
        {
            "next_action": "handoff",
            "case_state": {
                "status": "valid",
                "authz_coverage": {
                    "status": "ready",
                    "authenticated_actor_count": 2,
                    "authenticated_session_count": 2,
                },
            },
        },
        matrix,
    )

    assert closure["verdict"] == "finish"
    assert "actor_context_gap" not in closure


def test_closure_does_not_cross_close_distinct_vulnerability_lanes():
    completion = autopilot_state_module._surface_review_completion(
        {
            "surface_review_candidates": [{
                "url": "https://target.test/api/orders/1",
                "vuln_class": "SQLi",
            }],
        },
        _closure_matrix(),
        {
            "actions": [{
                "status": "tested",
                "metadata": {
                    "endpoint": "https://target.test/api/orders/1",
                    "vuln_class": "IDOR",
                },
            }],
        },
    )

    assert completion["status"] == "unresolved"
    assert completion["unresolved"] == [{
        "url": "https://target.test/api/orders/1",
        "reason": "review_outcome_missing",
    }]


def test_closure_blocks_case_state_canonical_conflict():
    closure = build_closure_projection(
        {
            "target": "target.com",
            "next_action": "handoff",
            "case_state": {
                "status": "valid",
                "canonical_conflict_count": 1,
            },
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["case_state_canonical_conflict"]
    assert closure["actionable_frontier"][0]["owner"] == "case_state"
    assert closure["actionable_frontier"][0]["id"] == "canonical-conflict"
    assert closure["actionable_frontier"][0]["evidence_ref"].endswith(
        "state/target.com/case_state.json"
    )


@pytest.mark.parametrize(
    ("field", "item_id"),
    [
        ("pending_validation_backlog", "validation-backlog"),
        ("open_hypotheses", "open-hypothesis"),
    ],
)
def test_case_state_obligations_without_top_action_still_have_frontier(
    field, item_id
):
    closure = build_closure_projection(
        {
            "target": "target.com",
            "next_action": "handoff",
            "case_state": {"status": "valid", field: 1},
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["actionable_frontier"][0]["owner"] == "case_state"
    assert closure["actionable_frontier"][0]["id"] == item_id
    assert all(
        closure["actionable_frontier"][0][key]
        for key in ("action", "evidence_ref", "expected_information_gain", "stop_condition")
    )


@pytest.mark.parametrize(
    ("next_action", "owner"),
    [("run_recon", "recon"), ("run_intel", "intel"), ("validate_finding", "finding")],
)
def test_pending_next_action_always_has_owner_backed_frontier(next_action, owner):
    closure = build_closure_projection(
        {"target": "target.com", "next_action": next_action},
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["next_action_pending"]
    item = closure["actionable_frontier"][0]
    assert item["owner"] == owner
    assert all(
        item[key]
        for key in ("action", "evidence_ref", "expected_information_gain", "stop_condition")
    )


@pytest.mark.parametrize(
    ("state", "reason", "owner", "next_action"),
    [
        (
            {
                "target": "target.com",
                "next_action": "handoff",
                "has_recon": True,
                "surface_projection": {"status": "stale"},
            },
            "surface_projection_pending",
            "surface",
            "prepare_surface_context",
        ),
        (
            {
                "target": "target.com",
                "next_action": "handoff",
                "action_queue_next": {"id": "AQ-1", "action": "resume queued work"},
            },
            "durable_work_pending",
            "action_queue",
            "resume_action_queue",
        ),
        (
            {
                "target": "target.com",
                "next_action": "handoff",
                "case_state": {"status": "valid", "pending_validation_backlog": 1},
            },
            "case_state_work_pending",
            "case_state",
            "resume_case_state",
        ),
        (
            {
                "target": "target.com",
                "next_action": "handoff",
                "_checkpoint_health": {"status": "stale"},
            },
            "checkpoint_stale",
            "checkpoint",
            "refresh_checkpoint",
        ),
    ],
)
def test_closure_binds_primary_reason_frontier_and_action(
    state, reason, owner, next_action
):
    closure = build_closure_projection(state, _closure_matrix())

    assert closure["reasons"][0] == reason
    assert closure["actionable_frontier"][0]["owner"] == owner
    assert closure["next_action"] == next_action


def test_closure_prefers_durable_owner_over_stale_surface_projection():
    closure = build_closure_projection(
        {
            "target": "target.com",
            "next_action": "handoff",
            "has_recon": True,
            "surface_projection": {"status": "stale"},
            "action_queue_next": {"id": "AQ-1", "action": "resume queued work"},
        },
        _closure_matrix(),
    )

    assert "surface_projection_pending" in closure["reasons"]
    assert closure["reasons"][0] == "durable_work_pending"
    assert closure["actionable_frontier"][0]["owner"] == "action_queue"
    assert closure["next_action"] == "resume_action_queue"


def test_ledger_health_handoff_always_has_owner_backed_frontier():
    closure = build_closure_projection(
        {
            "target": "target.com",
            "next_action": "handoff",
            "_ledger_health": {"status": "partial"},
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["ledger_partial"]
    assert closure["actionable_frontier"][0]["owner"] == "evidence-ledger"


@pytest.mark.parametrize(
    ("state", "owner"),
    [
        (
            {"recon_artifacts": {"run_budget": {"partial": True}}},
            "recon",
        ),
        (
            {"root_finding_claim_next": {"id": "claim-1", "source_file": "findings/target.com/claim.json"}},
            "finding-claim",
        ),
        ({"recon_in_progress": True}, "runtime"),
    ],
)
def test_authoritative_handoff_reasons_have_executable_frontier(state, owner):
    closure = build_closure_projection(
        {"target": "target.com", "next_action": "handoff", **state},
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    item = closure["actionable_frontier"][0]
    assert item["owner"] == owner
    assert all(
        item[key]
        for key in ("action", "evidence_ref", "expected_information_gain", "stop_condition")
    )


def test_closure_handoffs_only_for_partial_recon_budget():
    interrupted = build_closure_projection(
        {
            "next_action": "handoff",
            "recon_artifacts": {"run_budget": {"status": "partial", "partial": True}},
        },
        _closure_matrix(),
    )
    completed_slow = build_closure_projection(
        {
            "next_action": "handoff",
            "recon_artifacts": {
                "run_budget": {"status": "ok", "partial": False, "advisory_exceeded": True}
            },
        },
        _closure_matrix(),
    )

    assert interrupted["verdict"] == "handoff"
    assert interrupted["reasons"] == ["recon_budget_partial"]
    assert interrupted["recon_budget_partial"] is True
    assert completed_slow["verdict"] == "finish"
    assert completed_slow["recon_budget_partial"] is False


@pytest.mark.parametrize(
    "legacy_state",
    [
        {"verdict": "SUBMIT"},
        {"verdict": "CHAIN"},
        {"verdict": "FINISH: Hunt complete."},
        {"finish": True},
    ],
)
def test_legacy_verdict_cannot_author_formal_closure(legacy_state):
    closure = build_closure_projection(
        {"next_action": "handoff", **legacy_state},
        None,
    )

    assert closure["verdict"] == "handoff"
    assert closure["can_claim_exhausted"] is False
    assert closure["reasons"] == ["coverage_missing"]


def test_checkpoint_witness_verdict_cannot_author_formal_closure(tmp_path):
    target = "target.com"
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True)
    witness.write_text(
        json.dumps({
            "schema_version": 1,
            "kind": "autopilot_checkpoint_witness",
            "target": target,
            "verdict": "finish",
            "can_claim_exhausted": True,
        }),
        encoding="utf-8",
    )

    closure = load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
    )

    assert closure["verdict"] == "handoff"
    assert closure["can_claim_exhausted"] is False
    assert closure["reasons"] == ["coverage_missing"]


def test_stale_checkpoint_queue_fingerprint_forces_refresh_handoff(tmp_path):
    target = "target.com"
    ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={
            "next_action_queue": [{
                "id": "AQ-0001",
                "type": "coverage-gap",
                "action": "Review one durable coverage gap.",
                "priority": 80,
            }]
        },
    )
    current = queue_fingerprint(load_queue(tmp_path, target))
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.write_text(
        json.dumps({
            "schema_version": 1,
            "kind": "autopilot_checkpoint_witness",
            "target": target,
            "action_queue": {
                "synchronized": True,
                "next_id": "AQ-0001",
                "fingerprint": "stale-queue-generation",
            },
        }),
        encoding="utf-8",
    )

    closure = load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
    )

    assert closure["checkpoint_health"]["status"] == "stale"
    assert "checkpoint_stale" in closure["reasons"]
    assert closure["verdict"] == "handoff"
    assert current != "stale-queue-generation"


def test_closure_uses_current_queue_next_instead_of_preloaded_pointer(tmp_path):
    target = "target.com"
    path = queue_path(tmp_path, target)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "target": target,
        "actions": [{
            "id": "AQ-CURRENT",
            "status": "queued",
            "type": "coverage-gap",
            "source": "operator",
            "action": "review the current queue item",
            "priority": 80,
        }],
    }), encoding="utf-8")

    closure = load_closure_projection(
        str(tmp_path),
        {
            "target": target,
            "resolved_target": target,
            "next_action": "handoff",
            "action_queue_next": {"id": "AQ-STALE", "action": "old pointer"},
        },
        max_lanes_reached=False,
    )

    queue = load_queue(tmp_path, target)
    assert closure["snapshot_components"]["queue_fingerprint"] == queue_fingerprint(queue)
    assert closure["snapshot_digest"]
    assert closure["actionable_frontier"][0]["id"] == "AQ-CURRENT"
    assert all(item["id"] != "AQ-STALE" for item in closure["actionable_frontier"])


def test_closure_marks_state_snapshot_stale_when_queue_generation_changes(tmp_path):
    target = "target.com"
    path = queue_path(tmp_path, target)
    path.parent.mkdir(parents=True)
    initial = {
        "schema_version": 1,
        "target": target,
        "actions": [{
            "id": "AQ-OLD",
            "status": "queued",
            "type": "coverage-gap",
            "source": "operator",
            "action": "old queue item",
        }],
    }
    path.write_text(json.dumps(initial), encoding="utf-8")
    old_generation = queue_fingerprint(load_queue(tmp_path, target))
    path.write_text(json.dumps({
        **initial,
        "actions": [{
            **initial["actions"][0],
            "id": "AQ-NEW",
            "action": "new queue item",
        }],
    }), encoding="utf-8")

    closure = load_closure_projection(
        str(tmp_path),
        {
            "target": target,
            "resolved_target": target,
            "next_action": "handoff",
            "action_queue_fingerprint": old_generation,
        },
        max_lanes_reached=False,
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["state_snapshot_stale"]
    assert closure["next_action"] == "refresh_state"
    assert closure["snapshot_stale"] is True
    assert closure["snapshot_stale_sources"] == ["action_queue"]


def test_closure_marks_owner_snapshot_stale_when_source_changes_during_read(tmp_path, monkeypatch):
    target = "target.com"
    names = (
        "action_queue",
        "coverage",
        "ledger",
        "surface",
        "checkpoint",
        "target_memory",
    )
    stable = {name: (False,) for name in names}
    changed = {**stable, "ledger": (True, 1, 2, 3, 4)}
    markers = iter((stable, changed))
    monkeypatch.setattr(
        autopilot_state_module,
        "_owner_source_markers",
        lambda *_args, **_kwargs: next(markers),
    )

    closure = load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["state_snapshot_stale"]
    assert closure["snapshot_stale_sources"] == ["ledger"]
    assert closure["next_action"] == "refresh_state"
    assert closure["actionable_frontier"][0]["owner"] == "controller"
    assert closure["actionable_frontier"][0]["id"] == "state_snapshot_stale"


def test_closure_digest_changes_when_decision_state_changes(tmp_path):
    target = "target.com"
    base = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "case_state": {"status": "valid", "open_hypotheses": 0},
        "recon_artifacts": {"run_budget": {"partial": False}},
        "structured_findings": {},
    }

    original = load_closure_projection(str(tmp_path), base, max_lanes_reached=False)
    changed = load_closure_projection(
        str(tmp_path),
        {
            **base,
            "case_state": {"status": "valid", "open_hypotheses": 1},
        },
        max_lanes_reached=False,
    )

    assert original["snapshot_digest"] != changed["snapshot_digest"]
    assert (
        original["snapshot_components"]["closure_state_fingerprint"]
        != changed["snapshot_components"]["closure_state_fingerprint"]
    )


def test_invalid_cidr_continuation_has_recon_frontier(tmp_path):
    target = "target.com"
    closure = build_closure_projection(
        {
            "target": target,
            "resolved_target": target,
            "next_action": "handoff",
            "recon_artifacts": {
                "cidr_continuation": {
                    "status": "invalid",
                    "path": "recon/target.com/live/cidr_continuation.json",
                }
            },
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"][0] == "cidr_continuation_invalid"
    assert closure["next_action"] == "run_recon"
    assert closure["actionable_frontier"][0]["owner"] == "recon"
    assert closure["actionable_frontier"][0]["evidence_ref"].endswith(
        "cidr_continuation.json"
    )


def test_pending_cidr_continuation_has_recon_frontier_and_cannot_finish():
    closure = build_closure_projection(
        {
            "target": "10.0.0.0/19",
            "resolved_target": "10.0.0.0/19",
            "next_action": "handoff",
            "recon_artifacts": {
                "cidr_continuation": {
                    "status": "pending",
                    "next_offset": 4096,
                    "remaining_hosts": 4094,
                    "path": "recon/10.0.0.0_19/live/cidr_continuation.json",
                }
            },
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"][0] == "cidr_continuation_pending"
    assert closure["next_action"] == "run_recon"
    assert closure["actionable_frontier"][0]["owner"] == "recon"
    assert closure["actionable_frontier"][0]["evidence_ref"].endswith(
        "cidr_continuation.json"
    )


def test_checkpoint_cursor_missing_from_queue_is_stale_not_advanced(tmp_path):
    target = "target.com"
    ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={
            "next_action_queue": [{
                "id": "AQ-0001",
                "type": "coverage-gap",
                "action": "Review one durable coverage gap.",
                "priority": 80,
            }]
        },
    )
    queue_path = tmp_path / "state" / target / "action_queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.write_text(
        json.dumps({
            "schema_version": 1,
            "kind": "autopilot_checkpoint_witness",
            "target": target,
            "action_queue": {
                "synchronized": True,
                "next_id": "AQ-0001",
                "fingerprint": queue_fingerprint(queue),
            },
        }),
        encoding="utf-8",
    )
    queue["actions"] = []
    queue_path.write_text(json.dumps(queue), encoding="utf-8")

    closure = load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
    )

    assert closure["checkpoint_health"]["status"] == "stale"
    assert "checkpoint_stale" in closure["reasons"]


def test_corrupt_checkpoint_witness_becomes_recovery_handoff(tmp_path):
    witness_path = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    witness_path.parent.mkdir(parents=True)
    witness_path.write_bytes(b"{broken\n")

    closure = load_closure_projection(
        str(tmp_path),
        {"target": "target.com", "resolved_target": "target.com", "next_action": "handoff"},
        max_lanes_reached=False,
    )

    assert closure["verdict"] == "handoff"
    assert "checkpoint_invalid" in closure["reasons"]
    assert closure["checkpoint_health"]["status"] == "invalid"
    assert witness_path.read_bytes() == b"{broken\n"


def test_closure_projection_exposes_v2_identity_and_blocks_incomplete_candidate():
    identity = {
        "schema_version": 2,
        "kind": "closure_cell",
        "endpoint": {
            "schema_version": 2,
            "kind": "endpoint",
            "endpoint": "/api/search",
        },
        "family": "SQLi",
        "dimensions": {"method": "GET", "parameter": "q"},
    }
    open_candidate = {
        "endpoint": "/api/search",
        "vuln_class": "SQLi",
        "identity_v2": identity,
        "result": "candidate",
    }
    closure = build_closure_projection(
        {
            "next_action": "handoff",
            "_ledger_projection": {
                "closed_cells_v2": [],
                "open_candidates_v2": [open_candidate],
                "identity_v2_diagnostics": {"incomplete_count": 0},
            },
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["identity_v2_candidate_pending"]
    assert closure["identity_v2"]["open_candidates"] == [open_candidate]


def test_closure_projection_exposes_identity_follow_up_and_shadow_diff():
    follow_up = {
        "kind": "identity_follow_up",
        "endpoint": "/api/search",
        "family": "SQLi",
        "conflicts": ["method_mismatch"],
    }
    shadow = {"status": "compared", "different": True}
    closure = build_closure_projection(
        {
            "next_action": "handoff",
            "_ledger_projection": {
                "identity_v2_follow_up_actions": [follow_up],
                "identity_v2_shadow": shadow,
                "identity_v2_diagnostics": {"incomplete_count": 1, "follow_up_count": 1},
            },
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["identity_v2_follow_up_pending"]
    assert closure["identity_v2"]["follow_up_actions"] == [follow_up]
    assert closure["identity_v2"]["shadow"] == shadow


def test_closure_resumes_started_lane_and_requires_round_closure(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    progress = {
        "schema_version": 1,
        "round_id": "round-test",
        "status": "active",
        "max_lanes": 1,
        "claimed_lanes": ["sqli:/api/search"],
        "lanes": [{
            "schema_version": 1,
            "id": "sqli:/api/search",
            "status": "started",
            "decision": "",
            "evidence_ref": "",
            "next_action": "",
            "started_at": "2026-08-01T00:00:00Z",
            "updated_at": "2026-08-01T00:00:00Z",
        }],
        "claimed_count": 1,
        "remaining_lanes": 0,
        "budget_reached": True,
        "started_at": "2026-08-01T00:00:00Z",
        "updated_at": "2026-08-01T00:00:00Z",
    }
    witness.write_text(json.dumps({"round_progress": progress}), encoding="utf-8")
    state = {"target": target, "resolved_target": target, "next_action": "handoff"}

    started = load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    evidence_ref = "findings/target.com/poc/sql_parameter/summary.json"
    evidence_path = tmp_path / evidence_ref
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text("{}", encoding="utf-8")
    progress["lanes"][0].update({
        "status": "completed",
        "decision": "tested clean",
        "evidence_ref": evidence_ref,
        "next_action": "none",
        "finished_at": "2026-08-01T00:01:00Z",
        "updated_at": "2026-08-01T00:01:00Z",
    })
    witness.write_text(json.dumps({"round_progress": progress}), encoding="utf-8")
    terminal = load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    progress["status"] = "completed"
    witness.write_text(json.dumps({"round_progress": progress}), encoding="utf-8")
    closed = load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )

    assert started["verdict"] == "handoff"
    assert started["reasons"] == ["round_lane_unfinished"]
    assert started["next_action"] == "resume_round_lane"
    assert started["round_progress"]["unfinished_lanes"] == ["sqli:/api/search"]
    assert terminal["verdict"] == "handoff"
    assert terminal["reasons"] == ["round_closure_pending"]
    assert terminal["round_progress"]["latest_lane"]["decision"] == "tested clean"
    for item in (started["actionable_frontier"], terminal["actionable_frontier"]):
        assert item[0]["owner"] == "round-progress"
        assert item[0]["evidence_ref"].endswith("checkpoint_latest.json")
        assert item[0]["action"]
        assert item[0]["expected_information_gain"]
        assert item[0]["stop_condition"]
    assert closed["verdict"] == "finish"
    assert closed["can_claim_exhausted"] is True


def test_closure_does_not_finish_an_active_round_before_first_lane_claim(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({
        "round_progress": {
            "schema_version": 1,
            "round_id": "round-empty",
            "status": "active",
            "max_lanes": 2,
            "claimed_lanes": [],
            "lanes": [],
            "claimed_count": 0,
            "remaining_lanes": 2,
            "budget_reached": False,
            "started_at": "2026-08-01T00:00:00Z",
            "updated_at": "2026-08-01T00:00:00Z",
        }
    }), encoding="utf-8")

    closure = load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["round_lane_unclaimed"]
    assert closure["next_action"] == "resume_round_lane"
    assert closure["actionable_frontier"][0]["owner"] == "round-progress"


@pytest.mark.parametrize(
    "evidence_ref",
    ["findings/target.com/poc/missing.json", "none"],
)
def test_closure_handoffs_legacy_completed_lane_with_invalid_evidence(
    tmp_path,
    evidence_ref,
):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({
        "round_progress": {
            "schema_version": 1,
            "round_id": "round-legacy",
            "status": "completed",
            "max_lanes": 1,
            "claimed_lanes": ["sqli:/api/search"],
            "lanes": [{
                "schema_version": 1,
                "id": "sqli:/api/search",
                "status": "completed",
                "decision": "tested clean",
                "evidence_ref": evidence_ref,
                "next_action": "none",
                "started_at": "2026-08-01T00:00:00Z",
                "updated_at": "2026-08-01T00:01:00Z",
                "finished_at": "2026-08-01T00:01:00Z",
            }],
            "claimed_count": 1,
            "remaining_lanes": 0,
            "budget_reached": True,
            "started_at": "2026-08-01T00:00:00Z",
            "updated_at": "2026-08-01T00:01:00Z",
            "completed_at": "2026-08-01T00:01:00Z",
        }
    }), encoding="utf-8")
    previous = witness.read_bytes()

    closure = load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )

    assert closure["verdict"] == "handoff"
    assert closure["can_claim_exhausted"] is False
    assert closure["reasons"] == ["round_lane_evidence_invalid"]
    assert closure["next_action"] == "repair_round_lane_evidence"
    assert closure["round_progress"]["invalid_evidence_lanes"] == ["sqli:/api/search"]
    assert closure["actionable_frontier"][0]["owner"] == "round-progress"
    assert witness.read_bytes() == previous


def test_closure_rejects_legacy_coverage_lane_with_narrative_only_evidence(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    narrative_ref = f"evidence/{target}/coverage_disposition.md"
    narrative_path = tmp_path / narrative_ref
    narrative_path.write_text("TESTED/BLOCKED narrative only", encoding="utf-8")
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({
        "round_progress": {
            "schema_version": 1,
            "round_id": "round-legacy-coverage",
            "status": "completed",
            "max_lanes": 1,
            "claimed_lanes": ["coverage:high-risk-lane-review"],
            "lanes": [{
                "schema_version": 1,
                "id": "coverage:high-risk-lane-review",
                "status": "completed",
                "decision": "coverage disposition recorded",
                "evidence_ref": narrative_ref,
                "next_action": "final closure",
                "started_at": "2026-08-01T00:00:00Z",
                "updated_at": "2026-08-01T00:01:00Z",
                "finished_at": "2026-08-01T00:01:00Z",
            }],
            "claimed_count": 1,
            "remaining_lanes": 0,
            "budget_reached": True,
            "started_at": "2026-08-01T00:00:00Z",
            "updated_at": "2026-08-01T00:01:00Z",
            "completed_at": "2026-08-01T00:01:00Z",
        },
    }), encoding="utf-8")

    closure = _load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )

    assert closure["reasons"] == ["round_lane_evidence_invalid"]
    assert closure["round_progress"]["invalid_evidence_lanes"] == [
        "coverage:high-risk-lane-review"
    ]
    assert closure["actionable_frontier"][0]["owner"] == "round-progress"


def test_round_projection_preserves_budget_after_lane_field_projection(tmp_path):
    target = "target.com"
    evidence_ref = "evidence/target.com/summary.json"
    evidence_path = tmp_path / evidence_ref
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text("{}", encoding="utf-8")
    lane = {
        "schema_version": 1,
        "id": "validate:example",
        "status": "completed",
        "decision": "tested clean",
        "evidence_ref": evidence_ref,
        "next_action": "none",
        "started_at": "2026-08-01T00:00:00Z",
        "updated_at": "2026-08-01T00:01:00Z",
        "finished_at": "2026-08-01T00:01:00Z",
    }
    progress = {
        "schema_version": 1,
        "round_id": "round-test",
        "status": "completed",
        "max_lanes": 3,
        "claimed_lanes": ["validate:example"],
        "lanes": [lane],
        "claimed_count": 1,
        "remaining_lanes": 2,
        "budget_reached": False,
    }
    projection = _checkpoint_round_projection(
        {"round_progress": progress},
        repo_root=tmp_path,
        target=target,
    )

    assert projection["max_lanes"] == 3

    invalid_budget = {**progress, "max_lanes": 33, "remaining_lanes": 32}
    with pytest.raises(ValueError, match="budget fields are invalid"):
        _checkpoint_round_projection(
            {"round_progress": invalid_budget}, repo_root=tmp_path, target=target
        )

    invalid_timestamps = {**progress, "lanes": [{**lane, "started_at": ""}]}
    with pytest.raises(ValueError, match="lane timestamps are invalid"):
        _checkpoint_round_projection(
            {"round_progress": invalid_timestamps}, repo_root=tmp_path, target=target
        )


def test_case_state_work_routes_bootstrap_and_blocks_exhausted_closure(tmp_path):
    target = "target.com"
    case_path = tmp_path / "state" / target / "case_state.json"
    case_path.parent.mkdir(parents=True)
    case_path.write_text(
        json.dumps({
            "schema_version": 1,
            "target": target,
            "target_key": target,
            "actors": {},
            "sessions": {},
            "objects": {},
            "hypotheses": [{
                "status": "open",
                "vuln_class": "Authz",
                "endpoint": "https://target.com/api/orders/1",
                "next_action": "build actor-pair replay",
            }],
            "validation_backlog": [],
        }),
        encoding="utf-8",
    )

    state = build_autopilot_state(
        str(tmp_path), target, memory_dir=str(tmp_path / "memory"), bounded=True
    )
    closure = build_closure_projection(
        {"next_action": "handoff", "case_state": state["case_state"]},
        _closure_matrix(),
    )

    assert state["next_action"] == "resume_case_state"
    assert state["case_state"]["top_next_action"]["next_action"] == "create_validation_backlog"
    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["case_state_work_pending"]


def test_case_state_recovery_keeps_bounded_hypothesis_linkage(tmp_path):
    target = "target.com"
    case_path = tmp_path / "state" / target / "case_state.json"
    case_path.parent.mkdir(parents=True)
    case_path.write_text(
        json.dumps({
            "schema_version": 1,
            "target": target,
            "target_key": target,
            "actors": {},
            "sessions": {},
            "objects": {},
            "hypotheses": [{
                "id": "hyp_001",
                "status": "open",
                "vuln_class": "Authz",
                "next_action": "capture the export route",
            }],
            "validation_backlog": [{
                "id": "val_001",
                "hypothesis_id": "hyp_001",
                "runner": "marker-replay",
                "status": "blocked",
                "chain_extensions_if_blocked": ["capture the export route"],
            }],
        }),
        encoding="utf-8",
    )

    state = build_autopilot_state(str(tmp_path), target, bounded=True)
    top = state["case_state"]["top_next_action"]

    assert top["next_action"] == "recover_hypothesis"
    assert top["hypothesis_id"] == "hyp_001"
    assert top["recovery_next_action"] == "capture the export route"


def test_case_state_metadata_projection_is_bounded_and_secret_free(tmp_path):
    target = "target.com"
    case_path = tmp_path / "state" / target / "case_state.json"
    case_path.parent.mkdir(parents=True)
    case_path.write_text(
        json.dumps({
            "schema_version": 1,
            "target": target,
            "target_key": target,
            "actors": {}, "sessions": {}, "objects": {},
            "hypotheses": [{
                "id": "hyp_001", "status": "open", "vuln_class": "SSTI",
                "next_action": "validate template renderer",
                "metadata": {
                    "family": "RCE", "primitive": "SSTI",
                    "impact": {
                        "kind": "command execution",
                        "headers": {"Cookie": "SECRET"},
                        "accessToken": "SECRET_ACCESS_TOKEN",
                        "authHeader": "SECRET_AUTH_HEADER",
                        "clientSecret": "SECRET_CLIENT_SECRET",
                        "cookieValue": "SECRET_COOKIE",
                        "secretKey": "SECRET_KEY",
                        "sessionId": "SECRET_SESSION",
                        "tokenValue": "SECRET_TOKEN",
                    },
                    "chain": ["template", "shell"], "password": "SECRET_PASSWORD",
                },
            }],
            "validation_backlog": [],
        }),
        encoding="utf-8",
    )

    state = build_autopilot_state(str(tmp_path), target, bounded=True)
    metadata = state["case_state"]["top_next_action"]["metadata"]

    assert metadata["family"] == "RCE"
    assert metadata["primitive"] == "SSTI"
    assert metadata["chain"] == ["template", "shell"]
    assert "password" not in metadata
    assert "headers" not in metadata["impact"]
    assert "accessToken" not in metadata["impact"]
    assert "authHeader" not in metadata["impact"]
    assert "clientSecret" not in metadata["impact"]
    assert "cookieValue" not in metadata["impact"]
    assert "secretKey" not in metadata["impact"]
    assert "sessionId" not in metadata["impact"]
    assert "tokenValue" not in metadata["impact"]


def test_case_state_projection_preserves_descriptive_token_dimension(tmp_path):
    target = "target.com"
    case_path = tmp_path / "state" / target / "case_state.json"
    case_path.parent.mkdir(parents=True)
    case_path.write_text(
        json.dumps({
            "schema_version": 1,
            "target": target,
            "target_key": target,
            "actors": {}, "sessions": {}, "objects": {},
            "hypotheses": [{
                "id": "hyp_001", "status": "open", "vuln_class": "JWT",
                "next_action": "compare token algorithm handling",
                "metadata": {
                    "family": "JWT",
                    "dimensions": {
                        "token_location": "Authorization header",
                        "claim_algorithm": "alg",
                        "cache_key": "Accept-Language",
                    },
                },
            }],
            "validation_backlog": [],
        }),
        encoding="utf-8",
    )

    state = build_autopilot_state(str(tmp_path), target, bounded=True)
    dimensions = state["case_state"]["top_next_action"]["metadata"]["dimensions"]
    assert dimensions["token_location"] == "Authorization header"
    assert dimensions["cache_key"] == "Accept-Language"


def test_malformed_case_state_returns_structured_state_error(tmp_path, monkeypatch, capsys):
    target = "target.com"
    case_path = tmp_path / "state" / target / "case_state.json"
    case_path.parent.mkdir(parents=True)
    case_path.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr("autopilot_state.BASE_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        ["autopilot_state.py", "--target", target, "--bounded", "--closure", "--json"],
    )

    assert autopilot_state_main() == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["closure"]["verdict"] == "error"
    assert payload["closure"]["reasons"] == ["state_read_error"]
    assert "invalid target case state JSON" in payload["closure"]["error"]["message"]


def test_malformed_checkpoint_witness_returns_structured_state_error(tmp_path, monkeypatch, capsys):
    target = "target.com"
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True)
    witness.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr("autopilot_state.BASE_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "autopilot_state.py",
            "--target", target,
            "--bounded",
            "--closure",
            "--projection-only",
            "--json",
        ],
    )

    assert autopilot_state_main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["closure"]["verdict"] == "handoff"
    assert "checkpoint_invalid" in payload["closure"]["reasons"]
    assert payload["closure"]["checkpoint_health"]["status"] == "invalid"
    assert "invalid checkpoint witness JSON" in payload["closure"]["checkpoint_health"]["reason"]


def test_decision_projections_preserve_only_controller_fields():
    state = {
        "resolved_target": "target.com",
        "loop_guard": {"verdict": "rotate", "next_action": "hunt_p2"},
        "closure": {
            "verdict": "handoff",
            "can_claim_exhausted": False,
            "reasons": ["next_action_pending"],
            "next_action": "hunt_p1",
            "rotation_hint": {"action": "rotate_to_adjacent_high_value_lane"},
            "round_progress": {
                "status": "active",
                "unfinished_lanes": ["sqli:/api/search"],
            },
            "surface_review": {"unresolved": [{"url": "https://target.com/large"}]},
        },
        "structured_findings": {"reported": 2, "items": [{"raw": "omitted"}]},
        "browser_evidence": {"present": True, "ready": False, "private": "omitted"},
        "repo_source_available": True,
        "repo_source_summary": {"status": "partial", "routes": ["omitted"]},
        "recon_blocker": "",
        "observation_inventory": {"status": "ready", "reason": "", "items": ["omitted"]},
        "surface_projection": {"status": "valid", "reason": "", "surface": {"p1": ["omitted"]}},
        "surface": {"raw": "omitted"},
    }

    loop = build_decision_projection(state, "loop_check")
    closure = build_decision_projection(state, "closure")

    assert loop == {
        "schema_version": 1,
        "kind": "autopilot_loop_check_projection",
        "target": "target.com",
        "target_storage_key": "target.com",
        "loop_guard": state["loop_guard"],
    }
    assert closure["closure"] == {
        key: state["closure"][key]
        for key in (
            "verdict",
            "can_claim_exhausted",
            "reasons",
            "next_action",
            "rotation_hint",
            "round_progress",
            "surface_review",
        )
    }
    assert closure["structured_findings"] == {"reported": 2}
    assert closure["browser_evidence"] == {"present": True, "ready": False}
    assert closure["repo_source_summary"] == {"status": "partial"}
    assert closure["observation_inventory"] == {"status": "ready", "reason": ""}
    assert closure["surface_projection"] == {"status": "valid", "reason": ""}
    assert "surface" not in closure


def test_surface_continuation_is_omitted_when_no_page_remains():
    state = autopilot_state_module._surface_projection_with_continuation(
        {"status": "valid", "reason": ""},
        {"surface_index": {"continuation": {"available": False}}},
    )

    assert state == {"status": "valid", "reason": ""}


def test_cli_projection_only_keeps_full_json_mode_available(monkeypatch, capsys):
    state = {
        "target": "target.com",
        "resolved_target": "target.com",
        "surface": {"p1": [{"url": "https://target.com/admin"}]},
        "structured_findings": {"reported": 0},
    }
    monkeypatch.setattr(
        autopilot_state_module,
        "build_autopilot_state",
        lambda *_args, **_kwargs: dict(state),
    )
    monkeypatch.setattr(
        autopilot_state_module,
        "load_closure_projection",
        lambda *_args, **_kwargs: {
            "verdict": "finish",
            "can_claim_exhausted": True,
            "reasons": [],
            "next_action": "handoff",
            "rotation_hint": {},
        },
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "autopilot_state.py",
            "--target",
            "target.com",
            "--bounded",
            "--closure",
            "--projection-only",
            "--json",
        ],
    )
    assert autopilot_state_main() == 0
    narrow = json.loads(capsys.readouterr().out)
    assert narrow["closure"]["verdict"] == "finish"
    assert "surface" not in narrow

    monkeypatch.setattr(
        sys,
        "argv",
        ["autopilot_state.py", "--target", "target.com", "--bounded", "--closure", "--json"],
    )
    assert autopilot_state_main() == 0
    full = json.loads(capsys.readouterr().out)
    assert full["surface"] == state["surface"]


def test_json_summary_projection_and_partial_closure(tmp_path):
    target = "target.com"
    source = tmp_path / "recon" / target / "urls" / "json_endpoints.txt"
    source.parent.mkdir(parents=True)
    source.write_text("https://target.com/api/login\n", encoding="utf-8")
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    path = tmp_path / "findings" / target / "poc" / "json_inject" / "summary.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 2,
        "kind": "json_inject_summary",
        "target": target,
        "status": "partial",
        "input_fingerprint": "a" * 64,
        "source_bindings": [{"kind": "endpoints", "path": str(source), "sha256": source_digest}],
        "waf_plan_ref": "findings/target.com/poc/waf-plan.json",
        "waf_plan_sha256": "b" * 64,
        "waf_plan_variant_count": 1,
        "waf_ai_variants_executed": 1,
        "request_count": 2,
        "transport_error_count": 1,
        "skipped": {},
    }), encoding="utf-8")

    projection = _load_json_inject_projection(str(tmp_path), target)
    closure = build_closure_projection(
        {"target": target, "next_action": "handoff", "json_inject": projection},
        _closure_matrix(),
    )

    assert projection["status"] == "partial"
    assert projection["source_paths"] == [str(source)]
    assert projection["source_refs"] == [{"kind": "endpoints", "path": str(source)}]
    assert projection["waf_plan_variant_count"] == 1
    assert projection["waf_ai_variants_executed"] == 1
    assert closure["reasons"] == ["json_evidence_partial"]
    assert stagnation_fingerprint(
        {"target": target, "json_inject": projection}, closure
    )


def _write_closure_owners(tmp_path, target: str, *, status: str, final_review: bool) -> None:
    evidence_dir = tmp_path / "evidence" / target_storage_key(target)
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "coverage_matrix.json").write_text(
        json.dumps(_closure_matrix(status=status)),
        encoding="utf-8",
    )
    if final_review:
        queue_dir = tmp_path / "state" / target_storage_key(target)
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": target,
                "actions": [{
                    "id": "AQ-0001",
                    "status": "tested",
                    "type": "surface-review",
                    "metadata": {"endpoint": "/api/orders/1"},
                }],
            }),
            encoding="utf-8",
        )


def test_matching_third_round_guard_blocks_partial_json_lane(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    state = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "json_inject": {"status": "partial", "input_fingerprint": "abc", "request_count": 1},
    }
    base = _load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    fingerprint = base["stagnation_fingerprint"]
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({
        "round_guard": {
            "fingerprint": fingerprint, "consecutive": 3, "threshold": 3,
        },
        "round_progress": {
            "schema_version": 1,
            "status": "completed",
            "round_id": "round-3",
            "max_lanes": 1,
            "claimed_lanes": [],
            "claimed_count": 0,
            "remaining_lanes": 1,
            "budget_reached": False,
        },
    }), encoding="utf-8")

    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert closure["verdict"] == "blocked"
    assert closure["reasons"] == ["stagnant_prerequisite"]


def test_matching_third_round_guard_does_not_revive_advisory_surface(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=True)
    matrix_path = tmp_path / "evidence" / target / "coverage_matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["endpoints"].append({
        "endpoint": "/profile",
        "weight": 3.0,
        "cells": {"IDOR": {"status": "tested_clean"}},
    })
    matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
    queue_path = tmp_path / "state" / target / "action_queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"].append({
        "id": "AQ-0002",
        "status": "tested",
        "type": "surface-review",
        "metadata": {"endpoint": "/profile"},
    })
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    ledger_dir = tmp_path / "memory" / "evidence" / target
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "ledger.jsonl").write_text(
        "".join(json.dumps({
            "endpoint": f"/api/orders/{value}",
            "vuln_class": "IDOR",
            "result": "tested_clean",
        }) + "\n" for value in ("1", "2", "3")),
        encoding="utf-8",
    )
    state = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "json_inject": {"status": "partial", "input_fingerprint": "abc", "request_count": 1},
        "surface_review_candidates": [{
            "url": "https://target.com/profile",
            "score": 91,
            "new_observation": True,
        }],
    }
    base = _load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({"round_guard": {
        "fingerprint": base["stagnation_fingerprint"], "consecutive": 3, "threshold": 3,
    }}), encoding="utf-8")

    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert closure["verdict"] == "blocked"
    assert closure["reasons"] == ["stagnant_prerequisite"]
    assert "rotation_target" not in closure


def test_matching_third_round_guard_ignores_stale_state_queue_pointer(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    stagnant_state = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "json_inject": {"status": "partial", "input_fingerprint": "abc", "request_count": 1},
    }
    base = _load_closure_projection(
        str(tmp_path), stagnant_state, max_lanes_reached=False, apply_round_guard=False
    )
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({"round_guard": {
        "fingerprint": base["stagnation_fingerprint"], "consecutive": 3, "threshold": 3,
    }}), encoding="utf-8")

    closure = _load_closure_projection(str(tmp_path), {
        **stagnant_state,
        "action_queue_next": {"id": "AQ-1", "next_action": "validate_finding"},
    }, max_lanes_reached=False)

    assert closure["verdict"] == "blocked"
    assert closure["reasons"] == ["stagnant_prerequisite"]
    assert closure["next_action"] == "json-inject-review"
    assert "rotation_target" not in closure


def test_matching_third_round_guard_keeps_blocked_family_terminal(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=True)
    matrix_path = tmp_path / "evidence" / target / "coverage_matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["endpoints"].append({
        "endpoint": "/api/orders/99",
        "weight": 3.0,
        "cells": {"IDOR": {"status": "tested_clean"}},
    })
    matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
    queue_path = tmp_path / "state" / target / "action_queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"].append({
        "id": "AQ-0002",
        "status": "tested",
        "type": "surface-review",
        "metadata": {"endpoint": "/api/orders/99"},
    })
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    ledger_dir = tmp_path / "memory" / "evidence" / target
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "ledger.jsonl").write_text(
        "".join(json.dumps({
            "endpoint": f"/api/orders/{value}",
            "vuln_class": "IDOR",
            "result": "tested_clean",
        }) + "\n" for value in ("1", "2", "3")),
        encoding="utf-8",
    )
    state = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "json_inject": {"status": "partial", "input_fingerprint": "abc", "request_count": 1},
    }
    base = _load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({"round_guard": {
        "fingerprint": base["stagnation_fingerprint"], "consecutive": 3, "threshold": 3,
    }}), encoding="utf-8")

    closure = _load_closure_projection(str(tmp_path), {
        **state,
        "surface_review_candidates": [{
            "url": "https://target.com/api/orders/99",
            "score": 91,
            "new_observation": True,
        }],
    }, max_lanes_reached=False)

    assert closure["verdict"] == "blocked"
    assert closure["reasons"] == ["stagnant_prerequisite"]


def test_round_guard_ignores_coverage_rebuild_timestamp(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    state = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "json_inject": {"status": "partial", "input_fingerprint": "abc", "request_count": 1},
    }
    first = _load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    matrix_path = tmp_path / "evidence" / target / "coverage_matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["last_updated"] = "2099-01-01T00:00:00+00:00"
    matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
    second = _load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )

    assert first["stagnation_fingerprint"] == second["stagnation_fingerprint"]


def test_semantic_coverage_fingerprint_ignores_source_count_only_changes():
    projection = {
        "_coverage_projection": True,
        "_coverage_gaps": [{
            "endpoint": "/api/orders/{id}",
            "vuln_class": "IDOR",
            "relevance_score": 3,
            "source_count": 1,
        }],
    }
    changed = {
        **projection,
        "_coverage_gaps": [{**projection["_coverage_gaps"][0], "source_count": 99}],
    }

    assert (
        autopilot_state_module._semantic_coverage_fingerprint(projection)
        == autopilot_state_module._semantic_coverage_fingerprint(changed)
    )


def test_next_action_pending_round_guard_ignores_candidate_window_churn(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    state = {
        "target": target,
        "resolved_target": target,
        "next_action": "hunt_p1",
        "surface_review_candidates": [{"url": f"https://{target}/profile"}],
    }
    base = _load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    changed = _load_closure_projection(
        str(tmp_path),
        {**state, "surface_review_candidates": [{"url": f"https://{target}/settings"}]},
        max_lanes_reached=False,
        apply_round_guard=False,
    )

    assert base["verdict"] == "finish"
    assert changed["verdict"] == "finish"
    assert "stagnation_fingerprint" not in base
    assert "stagnation_fingerprint" not in changed


def test_coverage_high_value_gap_round_guard_blocks_without_candidate(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="untested", final_review=False)
    state = {"target": target, "resolved_target": target, "next_action": "handoff"}
    base = _load_closure_projection(
        str(tmp_path), state, max_lanes_reached=False, apply_round_guard=False
    )
    witness = tmp_path / "state" / target / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(json.dumps({"round_guard": {
        "fingerprint": base["stagnation_fingerprint"], "consecutive": 3, "threshold": 3,
    }}), encoding="utf-8")

    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert base["reasons"] == ["coverage_high_value_gaps"]
    assert closure["verdict"] == "blocked"
    assert closure["can_claim_exhausted"] is False
    assert closure["reasons"] == ["stagnant_prerequisite"]


def test_stagnation_fingerprint_resets_only_on_current_owner_change():
    closure = {
        "verdict": "handoff",
        "reasons": ["next_action_pending"],
        "next_action": "hunt_p1",
    }
    state = {
        "target": "target.com",
        "resolved_target": "target.com",
        "_stagnation_coverage": "coverage-a",
        "_stagnation_ledger": "ledger-a",
        "action_queue_next": {"id": "AQ-1"},
        "observation_inventory": {
            "status": "valid",
            "inventory_binding": {"sha256": "observation-a"},
        },
        "surface_review_candidates": [{"url": "https://target.com/profile"}],
    }
    base = stagnation_fingerprint(state, closure)

    assert stagnation_fingerprint(
        {**state, "action_queue_next": {"id": "AQ-2"}}, closure
    ) != base
    for update in (
        {"_stagnation_coverage": "coverage-b"},
        {"_stagnation_ledger": "ledger-b"},
        {"observation_inventory": {
            "status": "valid",
            "inventory_binding": {"sha256": "observation-b"},
        }},
        {"surface_review_candidates": [{"url": "https://target.com/settings"}]},
    ):
        assert stagnation_fingerprint({**state, **update}, closure) == base


def test_next_action_stagnation_uses_owner_semantics_not_runtime_noise():
    closure = {
        "verdict": "handoff",
        "reasons": ["next_action_pending"],
        "next_action": "resume_action_queue",
    }
    state = {
        "target": "target.com",
        "resolved_target": "target.com",
        "action_queue_next": {
            "id": "AQ-1",
            "status": "running",
            "action": "replay owner response",
            "evidence": "evidence/target.com/queue/summary.json",
            "next_question": "does the peer response differ?",
            "created_at": "2026-08-22T00:00:00Z",
            "metadata": {
                "tested_dimensions": ["identity"],
                "last_outcome": {
                    "status": "baseline_only",
                    "observed_difference": "no peer difference",
                    "evidence_ref": "evidence/target.com/queue/response.json",
                    "at": "2026-08-22T00:01:00Z",
                    "operation_id": "run-1",
                },
            },
        },
        "structured_findings": {
            "next_validation": {
                "id": "finding-1",
                "status": "candidate",
                "next_question": "is the claim reproducible?",
                "evidence_ref": "findings/target.com/finding-1.json",
                "missing_evidence": ["control replay", "raw response"],
            },
        },
        "case_state": {
            "status": "valid",
            "top_next_action": {
                "next_action": "compare owner and peer",
                "next_question": "does the private marker match?",
                "status": "pending",
            },
        },
    }
    base = stagnation_fingerprint(state, closure)
    noisy = {
        **state,
        "action_queue_next": {
            **state["action_queue_next"],
            "created_at": "2099-01-01T00:00:00Z",
            "updated_at": "2099-01-01T00:00:01Z",
            "rebuild_id": "rebuild-99",
            "metadata": {
                **state["action_queue_next"]["metadata"],
                "last_outcome": {
                    **state["action_queue_next"]["metadata"]["last_outcome"],
                    "at": "2099-01-01T00:00:02Z",
                    "operation_id": "run-99",
                },
            },
        },
    }
    assert stagnation_fingerprint(noisy, closure) == base

    for update in (
        {"action_queue_next": {
            **state["action_queue_next"],
            "metadata": {
                **state["action_queue_next"]["metadata"],
                "tested_dimensions": ["identity", "method"],
            },
        }},
        {"action_queue_next": {
            **state["action_queue_next"],
            "next_question": "does the role response differ?",
        }},
        {"action_queue_next": {
            **state["action_queue_next"],
            "metadata": {
                **state["action_queue_next"]["metadata"],
                "last_outcome": {
                    **state["action_queue_next"]["metadata"]["last_outcome"],
                    "observed_difference": "peer response exposes owner marker",
                },
            },
        }},
        {"structured_findings": {
            "next_validation": {
                **state["structured_findings"]["next_validation"],
                "status": "needs-evidence",
            },
        }},
        {"structured_findings": {
            "next_validation": {
                **state["structured_findings"]["next_validation"],
                "missing_evidence": ["control replay"],
            },
        }},
        {"case_state": {
            **state["case_state"],
            "top_next_action": {
                **state["case_state"]["top_next_action"],
                "next_question": "does the private role marker match?",
            },
        }},
    ):
        assert stagnation_fingerprint({**state, **update}, closure) != base


def test_stagnation_fingerprint_ignores_queue_rebuild_and_round_recovery():
    closure = {
        "verdict": "handoff",
        "reasons": ["next_action_pending"],
        "next_action": "hunt_p1",
    }
    state = {
        "target": "target.com",
        "resolved_target": "target.com",
        "_stagnation_queue": "queue-a",
        "round_progress": {
            "round_id": "round-a",
            "status": "active",
            "max_lanes": 2,
            "claimed_count": 1,
            "budget_reached": False,
            "unfinished_lanes": ["lane-a"],
            "invalid_evidence_lanes": [],
            "latest_lane": {"id": "lane-a", "status": "started"},
        },
    }
    base = stagnation_fingerprint(state, closure)

    assert stagnation_fingerprint({**state, "_stagnation_queue": "queue-b"}, closure) == base
    assert stagnation_fingerprint(
        {**state, "round_progress": {**state["round_progress"], "round_id": "round-b"}},
        closure,
    ) == base


def test_closure_prefers_compact_coverage_projection(tmp_path, monkeypatch):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    projection = {
        "target": target,
        "summary": {"high_value_gaps_count": 0},
        "endpoints": [{
            "endpoint": "/api/orders/1",
            "cells": {"IDOR": {"status": "tested_clean"}},
        }],
        "_coverage_gaps": [],
        "_coverage_projection": True,
    }
    monkeypatch.setattr(autopilot_state_module, "load_matrix_projection", lambda *_args: projection)
    monkeypatch.setattr(
        autopilot_state_module,
        "load_matrix",
        lambda *_args: (_ for _ in ()).throw(AssertionError("full matrix loaded")),
    )

    closure = _load_closure_projection(
        str(tmp_path), {"target": target, "next_action": "handoff"}, max_lanes_reached=False
    )

    assert closure["verdict"] == "finish"


def test_closure_falls_back_when_coverage_projection_is_unavailable(tmp_path, monkeypatch):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    loaded = []
    monkeypatch.setattr(autopilot_state_module, "load_matrix_projection", lambda *_args: None)
    original = autopilot_state_module.load_matrix
    monkeypatch.setattr(
        autopilot_state_module,
        "load_matrix",
        lambda *args: loaded.append(args) or original(*args),
    )

    closure = _load_closure_projection(
        str(tmp_path), {"target": target, "next_action": "handoff"}, max_lanes_reached=False
    )

    assert closure["verdict"] == "finish"
    assert loaded


def test_compact_projection_keeps_default_cells_as_pending_gaps():
    projection = {
        "summary": {"high_value_gaps_count": 1},
        "endpoints": [{"endpoint": "/api/orders/1", "cells": {}}],
        "_coverage_gaps": [{"endpoint": "/api/orders/1", "vuln_class": "IDOR"}],
        "_coverage_projection": True,
    }

    closure = build_closure_projection({"next_action": "handoff"}, projection)

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["coverage_high_value_gaps"]


def test_zero_relevance_coverage_gap_is_advisory_not_closure_work():
    projection = {
        "summary": {"high_value_gaps_count": 1},
        "endpoints": [{"endpoint": "/api/orders/1", "cells": {}}],
        "_coverage_gaps": [{"endpoint": "/api/orders/1", "vuln_class": "RCE", "relevance_score": 0}],
        "_coverage_projection": True,
    }

    closure = build_closure_projection({"next_action": "handoff"}, projection)

    assert closure["verdict"] == "finish"
    assert closure["reasons"] == []
    assert projection["summary"]["high_value_gaps_count"] == 1


def test_zero_relevance_gap_does_not_hide_surface_review_requirement():
    projection = {
        "summary": {"high_value_gaps_count": 1},
        "endpoints": [{"endpoint": "/api/orders/1", "cells": {}}],
        "_coverage_gaps": [{"endpoint": "/api/orders/1", "vuln_class": "RCE", "relevance_score": 0}],
        "_coverage_projection": True,
    }

    completion = autopilot_state_module._surface_review_completion(
        {"surface_review_candidates": [{"url": "https://target.com/api/orders/1"}]},
        projection,
        {"actions": []},
    )

    assert completion["unresolved"] == [{
        "url": "https://target.com/api/orders/1",
        "reason": "review_outcome_missing",
    }]


def test_actionable_coverage_gap_still_blocks_closure_and_frontier():
    projection = {
        "summary": {"high_value_gaps_count": 1},
        "endpoints": [{"endpoint": "/api/orders/1", "cells": {}}],
        "_coverage_gaps": [{"endpoint": "/api/orders/1", "vuln_class": "IDOR", "relevance_score": 3}],
        "_coverage_projection": True,
    }

    closure = build_closure_projection({"target": "target.com", "next_action": "handoff"}, projection)

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["coverage_high_value_gaps"]
    assert closure["actionable_frontier"][0]["owner"] == "coverage"


def _surface_closure_state(target: str, *, next_action: str = "hunt_p1") -> dict:
    return {
        "target": target,
        "resolved_target": target,
        "next_action": next_action,
        "surface_review_candidates": [{"url": f"https://{target}/api/orders/1"}],
        "browser_evidence": {"ready": True},
    }


def test_surface_candidate_blocks_closure_without_durable_review_outcome(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)

    closure = _load_closure_projection(
        str(tmp_path), _surface_closure_state(target), max_lanes_reached=False
    )

    assert closure["verdict"] == "finish"
    assert closure["surface_review"]["status"] == "unresolved"
    assert closure["surface_review"]["unresolved"][0]["reason"] == "review_outcome_missing"


def test_surface_candidate_allows_closure_after_coverage_and_final_review(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=True)

    closure = _load_closure_projection(
        str(tmp_path), _surface_closure_state(target), max_lanes_reached=False
    )

    assert closure["verdict"] == "finish"
    assert closure["can_claim_exhausted"] is True
    assert closure["surface_review"] == {"status": "complete", "unresolved": []}


def test_surface_candidate_stays_unresolved_after_terminal_ledger_outcome(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    ledger_dir = tmp_path / "memory" / "evidence" / target_storage_key(target)
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "ledger.jsonl").write_text(
        json.dumps({
            "endpoint": "/api/orders/1",
            "vuln_class": "IDOR",
            "result": "dead_end",
        }) + "\n",
        encoding="utf-8",
    )

    closure = _load_closure_projection(
        str(tmp_path), _surface_closure_state(target), max_lanes_reached=False
    )

    assert closure["verdict"] == "finish"
    assert closure["can_claim_exhausted"] is True
    assert closure["surface_review"]["status"] == "unresolved"
    assert closure["surface_review"]["unresolved"][0]["reason"] == "review_outcome_missing"


def test_surface_candidate_query_is_not_closed_by_terminal_ledger_identity(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    ledger_dir = tmp_path / "memory" / "evidence" / target_storage_key(target)
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "ledger.jsonl").write_text(
        json.dumps({
            "endpoint": "/api/orders/1?view=summary",
            "vuln_class": "IDOR",
            "result": "dead_end",
        }) + "\n",
        encoding="utf-8",
    )

    state = _surface_closure_state(target)
    state["surface_review_candidates"][0]["url"] += "?view=detail"
    mismatch = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)
    state["surface_review_candidates"][0]["url"] = (
        f"https://{target}/api/orders/1?view=summary"
    )
    exact = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert mismatch["verdict"] == "finish"
    assert (
        mismatch["surface_review"]["unresolved"][0]["reason"]
        == "review_outcome_missing"
    )
    assert exact["verdict"] == "finish"
    assert exact["surface_review"]["unresolved"][0]["reason"] == "review_outcome_missing"


def test_surface_candidate_query_requires_exact_final_queue_identity(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=True)
    state = _surface_closure_state(target)
    state["surface_review_candidates"][0]["url"] += "?view=detail"

    mismatch = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)
    queue_path = tmp_path / "state" / target_storage_key(target) / "action_queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["metadata"]["endpoint"] += "?view=detail"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    exact = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert mismatch["verdict"] == "finish"
    assert mismatch["surface_review"]["status"] == "unresolved"
    assert mismatch["surface_review"]["unresolved"][0]["reason"] == "review_outcome_missing"
    assert exact["verdict"] == "finish"
    assert exact["surface_review"] == {"status": "complete", "unresolved": []}


def test_surface_candidate_uses_folded_coverage_but_requires_exact_queue_identity():
    matrix = {
        "endpoints": [{
            "endpoint": "/api/orders/{id}",
            "cells": {"IDOR": {"status": "tested_clean"}},
        }],
        "summary": {"high_value_gaps_count": 0},
    }
    state = {
        "surface_review_candidates": [{
            "url": "https://target.com/api/orders/123?view=detail",
            "vuln_class": "IDOR",
        }],
    }
    mismatch = autopilot_state_module._surface_review_completion(
        state,
        matrix,
        {"actions": [{
            "status": "tested",
            "metadata": {
                "endpoint": "/api/orders/123?view=summary",
                "vuln_class": "IDOR",
            },
        }]},
    )
    exact = autopilot_state_module._surface_review_completion(
        state,
        matrix,
        {"actions": [{
            "status": "tested",
            "metadata": {
                "endpoint": "/api/orders/123?view=detail",
                "vuln_class": "IDOR",
            },
        }]},
    )

    assert mismatch["unresolved"][0]["reason"] == "review_outcome_missing"
    assert exact == {"status": "complete", "unresolved": []}


def test_surface_candidate_reopens_after_new_ledger_candidate(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=False)
    ledger_dir = tmp_path / "memory" / "evidence" / target_storage_key(target)
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "ledger.jsonl").write_text(
        "\n".join([
            json.dumps({
                "endpoint": "/api/orders/1",
                "vuln_class": "IDOR",
                "result": "dead_end",
            }),
            json.dumps({
                "endpoint": "/api/orders/1",
                "vuln_class": "IDOR",
                "result": "candidate",
            }),
        ]) + "\n",
        encoding="utf-8",
    )

    closure = _load_closure_projection(
        str(tmp_path), _surface_closure_state(target), max_lanes_reached=False
    )

    assert closure["verdict"] == "finish"
    assert closure["surface_review"]["unresolved"][0]["reason"] == "review_outcome_missing"


def test_malformed_surface_candidate_fails_open_at_closure(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=True)
    state = _surface_closure_state(target, next_action="handoff")
    state["surface_review_candidates"] = ["broken-candidate"]

    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert closure["verdict"] == "finish"
    assert closure["surface_review"]["unresolved"] == [{"reason": "invalid_candidate"}]


def test_finalized_finding_filters_only_exact_resume_identity(tmp_path):
    target = "target.com"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "schema_version": 1,
            "target": target,
            "findings": [{
                "id": "idor_summary",
                "type": "idor",
                "url": f"https://{target}/api/orders/1?view=summary",
                "validation_status": "rejected",
                "report_status": "not_generated",
            }],
        }),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "idor_summary")
    targets = ["/api/orders/1?view=summary", "/api/orders/1?view=detail"]
    finalized = autopilot_state_module._finalized_finding_identities(
        str(tmp_path),
        target,
    )

    filtered = autopilot_state_module._filter_resume_targets_for_final_state(
        targets,
        finalized,
    )

    assert finalized == {"/api/orders/1?view=summary"}
    assert filtered == ["/api/orders/1?view=detail"]


def test_final_surface_review_does_not_hide_high_value_coverage_gap(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="untested", final_review=True)

    closure = _load_closure_projection(
        str(tmp_path),
        _surface_closure_state(target, next_action="handoff"),
        max_lanes_reached=False,
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["coverage_high_value_gaps"]
    assert closure["surface_review"]["unresolved"][0]["reason"] == "coverage_gap_pending"


def test_json_closure_returns_structured_error_for_malformed_coverage(
    tmp_path, monkeypatch, capsys
):
    target = "target.com"
    evidence_dir = tmp_path / "evidence" / target_storage_key(target)
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "coverage_matrix.json").write_text("{broken", encoding="utf-8")
    monkeypatch.setattr("autopilot_state.BASE_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "autopilot_state.py",
            "--target",
            target,
            "--bounded",
            "--closure",
            "--projection-only",
            "--json",
        ],
    )

    assert autopilot_state_main() == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["closure"]["verdict"] == "error"
    assert payload["closure"]["reasons"] == ["state_read_error"]
    assert payload["closure"]["error"]["type"] == "ValueError"


def test_closure_handoffs_actionable_work_and_coverage_gaps():
    action_closure = build_closure_projection(
        {"next_action": "validate_finding"}, _closure_matrix()
    )
    gap_closure = build_closure_projection(
        {"next_action": "handoff"}, _closure_matrix(status="untested")
    )

    assert action_closure["verdict"] == "handoff"
    assert action_closure["reasons"] == ["next_action_pending"]
    assert gap_closure["can_claim_exhausted"] is False
    assert gap_closure["reasons"] == ["coverage_high_value_gaps"]


def test_stale_surface_projection_blocks_full_state_and_closure(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "js").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://target.com [200] [API] [Express] [100]\n", encoding="utf-8"
    )
    source = recon_dir / "urls" / "with_params.txt"
    source.write_text("https://target.com/api/orders?id=1\n", encoding="utf-8")
    (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
    _publish_surface_projection(tmp_path, "target.com")

    source.write_text("https://target.com/api/orders?id=2\n", encoding="utf-8")
    state = build_autopilot_state(str(tmp_path), "target.com")

    assert state["surface_projection"]["status"] == "stale"
    assert state["next_action"] == "prepare_surface_context"

    _write_closure_owners(tmp_path, "target.com", status="tested_clean", final_review=False)
    state["next_action"] = "handoff"
    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)
    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["surface_projection_pending"]


def test_surface_round_guard_resets_after_surface_input_changes(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "js").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://target.com [200] [API] [Express] [100]\n", encoding="utf-8"
    )
    source = recon_dir / "urls" / "with_params.txt"
    source.write_text("https://target.com/api/orders?id=1\n", encoding="utf-8")
    (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
    _publish_surface_projection(tmp_path, "target.com")

    source.write_text("https://target.com/api/orders?id=2\n", encoding="utf-8")
    _write_closure_owners(tmp_path, "target.com", status="tested_clean", final_review=False)
    first_state = build_autopilot_state(str(tmp_path), "target.com")
    first_state["next_action"] = "handoff"
    first = _load_closure_projection(
        str(tmp_path), first_state, max_lanes_reached=False, apply_round_guard=False
    )
    witness = tmp_path / "state" / "target.com" / "checkpoint_latest.json"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(
        json.dumps({
            "round_guard": {
                "fingerprint": first["stagnation_fingerprint"],
                "consecutive": 3,
                "threshold": 3,
            }
        }),
        encoding="utf-8",
    )
    blocked = _load_closure_projection(
        str(tmp_path), first_state, max_lanes_reached=False
    )
    assert blocked["verdict"] == "blocked"
    assert blocked["reasons"] == ["stagnant_prerequisite"]

    source.write_text(
        "https://target.com/api/orders?id=2\n"
        "https://target.com/api/orders?id=3\n",
        encoding="utf-8",
    )
    changed_state = build_autopilot_state(str(tmp_path), "target.com")
    changed_state["next_action"] = "handoff"
    changed = _load_closure_projection(
        str(tmp_path), changed_state, max_lanes_reached=False
    )

    assert changed_state["surface_projection"]["input_fingerprint"]
    assert (
        changed_state["surface_projection"]["input_fingerprint"]
        != first_state["surface_projection"]["input_fingerprint"]
    )
    assert changed["verdict"] == "handoff"
    assert changed["reasons"] == ["surface_projection_pending"]


def test_missing_surface_projection_without_recon_does_not_mask_closure_reason():
    closure = build_closure_projection(
        {
            "has_recon": False,
            "next_action": "handoff",
            "surface_projection": {"status": "missing"},
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "finish"
    assert closure["reasons"] == []


def test_closure_never_finishes_for_invalid_coverage_or_explicit_durable_work():
    missing = build_closure_projection({"next_action": "handoff"}, None)
    invalid = build_closure_projection(
        {"next_action": "handoff"},
        _closure_matrix(status="unknown"),
    )
    durable = build_closure_projection(
        {"next_action": "handoff", "action_queue_next": {"id": "pending-1"}},
        _closure_matrix(),
    )

    assert missing["verdict"] == "handoff"
    assert missing["reasons"] == ["coverage_missing"]
    assert invalid["verdict"] == "handoff"
    assert invalid["reasons"] == ["coverage_invalid"]
    assert durable["verdict"] == "handoff"
    assert durable["reasons"] == ["durable_work_pending"]


def test_closure_recomputes_terminal_prerequisites_after_lane_limit():
    blocked = build_closure_projection(
        {"next_action": "recon_no_live_hosts"}, _closure_matrix()
    )
    lane_limited = build_closure_projection(
        {"next_action": "handoff"}, _closure_matrix(), max_lanes_reached=True
    )
    terminal_lane_limited = build_closure_projection(
        {"next_action": "batch_failed"}, _closure_matrix(), max_lanes_reached=True
    )
    gap_lane_limited = build_closure_projection(
        {"next_action": "handoff"},
        _closure_matrix(status="untested"),
        max_lanes_reached=True,
    )

    assert blocked["verdict"] == "blocked"
    assert blocked["reasons"] == ["recon_no_live_hosts"]
    assert lane_limited["verdict"] == "finish"
    assert lane_limited["round_budget_reached"] is True
    assert lane_limited["reasons"] == []
    assert terminal_lane_limited["verdict"] == "blocked"
    assert terminal_lane_limited["reasons"] == ["batch_failed"]
    assert gap_lane_limited["verdict"] == "handoff"
    assert gap_lane_limited["reasons"] == ["coverage_high_value_gaps"]


def test_legacy_resume_preview_is_advisory_without_current_surface_binding():
    state = {
        "target": "target.com",
        "next_action": "resume_untested",
        "resume_targets": ["/legacy-endpoint"],
    }
    advisory = build_closure_projection(state, _closure_matrix())
    assert advisory["verdict"] == "finish"
    assert advisory["reasons"] == []

    bound = build_closure_projection(
        {
            **state,
            "surface_review_candidates": [{
                "url": "https://target.com/legacy-endpoint",
                "new_observation": True,
            }],
            "next_action": "handoff",
        },
        _closure_matrix(),
    )
    assert bound["verdict"] == "handoff"
    assert bound["reasons"] == ["surface_work_pending"]


def test_budget_exhaustion_with_empty_frontier_finishes_without_handoff():
    closure = build_closure_projection(
        {"target": "target.com", "next_action": "handoff"},
        _closure_matrix(),
        max_lanes_reached=True,
    )

    assert closure["verdict"] == "finish"
    assert closure["round_budget_reached"] is True
    assert closure["actionable_frontier"] == []


def test_actionable_frontier_preserves_queue_contract_fields():
    closure = build_closure_projection(
        {
            "target": "target.com",
            "next_action": "handoff",
            "action_queue_next": {
                "id": "AQ-1",
                "type": "validation",
                "action": "Replay the owner-selected validation.",
                "evidence": "findings/target.com/poc/summary.json",
                "next_question": "Does the peer response expose the owner marker?",
                "stop_condition": "Stop after two stable repeats or a denial.",
                "priority": 110,
            },
        },
        _closure_matrix(),
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["durable_work_pending"]
    assert closure["actionable_frontier"] == [{
        "owner": "action_queue",
        "id": "AQ-1",
        "action": "Replay the owner-selected validation.",
        "evidence_ref": "findings/target.com/poc/summary.json",
        "expected_information_gain": "Does the peer response expose the owner marker?",
        "stop_condition": "Stop after two stable repeats or a denial.",
        "priority": 110,
    }]


def test_coverage_frontier_is_derived_without_marking_surface_clean():
    closure = build_closure_projection(
        {"target": "target.com", "next_action": "handoff"},
        _closure_matrix(status="untested"),
        max_lanes_reached=True,
    )

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["coverage_high_value_gaps"]
    assert closure["actionable_frontier"][0]["owner"] == "coverage"
    assert closure["actionable_frontier"][0]["evidence_ref"].endswith(
        "evidence/target.com/coverage_matrix.json"
    )
    assert "tested_clean" not in closure["actionable_frontier"][0]["action"]


def test_closure_rotation_hint_never_changes_the_verdict():
    entries = [
        {
            "endpoint": f"/api/orders/{value}",
            "vuln_class": "IDOR",
            "result": result,
        }
        for value, result in (("1", "tested_clean"), ("2", "dead_end"), ("3", "tested_clean"))
    ]
    closure = build_closure_projection({"next_action": "handoff"}, _closure_matrix(), entries)

    assert closure["verdict"] == "finish"
    assert closure["rotation_hint"] == {
        "reason": "three_homogeneous_clean_outcomes",
        "endpoint_family": "/api/orders/:id",
        "vuln_class": "IDOR",
        "action": "rotate_to_adjacent_high_value_lane",
    }


def test_loop_guard_rotates_only_three_matching_recent_outcomes():
    entries = [
        {
            "endpoint": f"/api/orders/{value}",
            "vuln_class": "IDOR",
            "result": result,
        }
        for value, result in (("1", "tested_clean"), ("2", "dead_end"), ("3", "tested_clean"))
    ]
    rotate = build_loop_guard_projection({"next_action": "hunt_p1"}, entries)
    mixed = build_loop_guard_projection(
        {"next_action": "hunt_p1"},
        [*entries[:2], {**entries[2], "vuln_class": "Authz"}],
    )

    assert rotate == {
        "verdict": "rotate",
        "reason": "three_homogeneous_clean_outcomes",
        "endpoint_family": "/api/orders/:id",
        "vuln_class": "IDOR",
        "next_action": "rotate_to_adjacent_high_value_lane",
        "rotation_target": {},
    }
    assert mixed["verdict"] == "continue"
    assert mixed["reason"] == "insufficient_homogeneous_outcomes"
    assert mixed["rotation_target"] == {}


def test_damaged_ledger_is_visible_and_blocks_closure_and_rotation(tmp_path):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=True)
    ledger_dir = tmp_path / "memory" / "evidence" / target_storage_key(target)
    ledger_dir.mkdir(parents=True)
    rows = [
        {
            "endpoint": f"/api/orders/{value}",
            "vuln_class": "IDOR",
            "result": "tested_clean",
        }
        for value in ("1", "2", "3")
    ]
    rows[0].update({
        "identity_status": "complete",
        "identity_v2": {
            "schema_version": 2,
            "kind": "closure_cell",
            "endpoint": {
                "schema_version": 2,
                "kind": "endpoint",
                "endpoint": "/api/orders/1",
            },
            "family": "IDOR",
            "dimensions": {
                "path_template": "/api/orders/{id}",
                "method": "GET",
                "actor_relation": "peer",
                "object_scope": "other_object_same_org",
            },
        },
    })
    (ledger_dir / "ledger.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows) + "{broken\n",
        encoding="utf-8",
    )
    state = {"target": target, "resolved_target": target, "next_action": "handoff"}

    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)
    loop = _load_loop_guard_projection(str(tmp_path), {**state, "next_action": "hunt_p1"})

    assert closure["ledger_health"]["status"] == "partial"
    assert closure["ledger_health"]["invalid_count"] == 1
    assert closure["ledger_health"]["last_valid_offset"] > 0
    assert closure["verdict"] == "handoff"
    assert "ledger_partial" in closure["reasons"]
    assert closure["identity_v2"]["closed_cells"] == []
    assert closure["identity_v2"]["diagnostics"]["closed_count"] == 0
    assert closure["identity_v2"]["diagnostics"]["suppressed_closed_count"] == 1
    assert closure["identity_v2"]["shadow"] == {
        "status": "unavailable",
        "reason": "ledger_partial",
    }
    assert loop["ledger_health"]["status"] == "partial"
    assert loop["verdict"] == "continue"
    assert loop["reason"] == "ledger_partial"
    assert loop["rotation_target"] == {}


def test_unreadable_ledger_is_visible_and_blocks_closure(tmp_path, monkeypatch):
    target = "target.com"
    _write_closure_owners(tmp_path, target, status="tested_clean", final_review=True)
    monkeypatch.setattr(
        autopilot_state_module,
        "load_entries_diagnostic",
        lambda *_args: {
            "status": "unreadable",
            "entries": [],
            "invalid_rows": [],
            "invalid_count": 0,
            "last_valid_offset": 0,
            "read_error": "permission denied " + ("x" * 1000),
        },
    )

    closure = _load_closure_projection(
        str(tmp_path),
        {"target": target, "resolved_target": target, "next_action": "handoff"},
        max_lanes_reached=False,
    )

    assert closure["ledger_health"]["status"] == "unreadable"
    assert len(closure["ledger_health"]["read_error"]) <= 240
    assert closure["verdict"] == "handoff"
    assert "ledger_unreadable" in closure["reasons"]


def test_loop_guard_rotation_target_excludes_blocked_family_and_prefers_new_observation():
    entries = [
        {"endpoint": f"/api/orders/{value}", "vuln_class": "IDOR", "result": "tested_clean"}
        for value in ("1", "2", "3")
    ]
    guard = build_loop_guard_projection(
        {
            "target": "target.com",
            "next_action": "hunt_p1",
            "surface_review_candidates": [
                {"url": "https://target.com/api/orders/99", "score": 20},
                {"url": "https://target.com/api/settings", "score": 10},
                {
                    "url": "https://target.com/api/profile",
                    "score": 1,
                    "new_observation": True,
                    "review_reason": "new observation representative (neutral)",
                },
            ],
        },
        entries,
    )

    assert guard["verdict"] == "rotate"
    assert guard["rotation_target"] == {
        "url": "https://target.com/api/profile",
        "score": 1,
        "review_reason": "new observation representative (neutral)",
        "new_observation": True,
    }


def test_loop_guard_rotation_target_ignores_off_target_frontier_entries():
    entries = [
        {"endpoint": f"/api/orders/{value}", "vuln_class": "IDOR", "result": "tested_clean"}
        for value in ("1", "2", "3")
    ]
    guard = build_loop_guard_projection(
        {
            "target": "target.com",
            "next_action": "hunt_p1",
            "surface_review_candidates": [
                {"url": "https://external.example/api/profile", "new_observation": True},
                {"url": "https://target.com/api/settings", "score": 10},
            ],
        },
        entries,
    )

    assert guard["rotation_target"] == {
        "url": "https://target.com/api/settings",
        "score": 10,
    }


def test_loop_guard_never_overrides_authoritative_next_actions():
    entries = [
        {"endpoint": f"/api/orders/{value}", "vuln_class": "IDOR", "result": "tested_clean"}
        for value in ("1", "2", "3")
    ]
    for action in ("wait_recon", "wait_scan", "validate_finding", "complete_report_draft", "resume_action_queue"):
        guard = build_loop_guard_projection({"next_action": action}, entries)
        assert guard["verdict"] == "continue"
        assert guard["reason"] == "authoritative_next_action"
        assert guard["next_action"] == action
        assert guard["rotation_target"] == {}


def test_loop_guard_stale_handoff_yields_to_authoritative_control_plane_work():
    entries = [
        {"endpoint": f"/api/orders/{value}", "vuln_class": "IDOR", "result": "tested_clean"}
        for value in ("1", "2", "3")
    ]
    states = [
        {"recon_in_progress": True},
        {"scan_in_progress": True},
        {"active_action_queue_count": 1},
        {"action_queue_next": {"id": "AQ-1"}},
        {"validation_runner_next": {"id": "VR-1"}},
        {"root_finding_claim_next": {"id": "F-1"}},
        {"memory_candidate_next": {"id": "M-1"}},
        {"structured_findings": {"next_owner_revalidation": {"id": "F-1"}}},
        {"structured_findings": {"next_validation": {"id": "F-1"}}},
        {"structured_findings": {"draft_completion_pending": {"id": "F-1"}}},
        {"structured_findings": {"validated_pending_report": {"id": "F-1"}}},
        {"intel_continuation": {"blocked": True}},
    ]

    for state in states:
        guard = build_loop_guard_projection({"next_action": "handoff", **state}, entries)
        assert guard["verdict"] == "continue"
        assert guard["reason"].startswith("authoritative_")
        assert guard["next_action"] == "handoff"
        assert guard["rotation_target"] == {}


def test_closure_ignores_malformed_or_endpointless_rotation_entries():
    malformed = [
        {"endpoint": "/api/orders/1", "vuln_class": "IDOR", "result": "tested_clean"},
        "not a ledger entry",
        {"endpoint": "/api/orders/3", "vuln_class": "IDOR", "result": "dead_end"},
    ]
    endpointless = [
        {"vuln_class": "IDOR", "result": "tested_clean"},
        {"vuln_class": "IDOR", "result": "tested_clean"},
        {"vuln_class": "IDOR", "result": "dead_end"},
    ]

    assert build_closure_projection({"next_action": "handoff"}, _closure_matrix(), malformed)["rotation_hint"] == {}
    assert build_closure_projection({"next_action": "handoff"}, _closure_matrix(), endpointless)["rotation_hint"] == {}


def test_closure_only_handoffs_browser_or_js_when_partial_work_is_explicit():
    missing_browser = build_closure_projection(
        {"next_action": "handoff", "browser_evidence": {"present": False, "ready": False}},
        _closure_matrix(),
    )
    partial_browser = build_closure_projection(
        {"next_action": "handoff", "browser_evidence": {"present": True, "ready": False}},
        _closure_matrix(),
    )
    required_browser = build_closure_projection(
        {
            "next_action": "handoff",
            "browser_required": True,
            "browser_evidence": {"present": False, "ready": False},
        },
        _closure_matrix(),
    )
    pending_js = build_closure_projection(
        {"next_action": "handoff", "enrichment_hints": [{"tool": "run_js_read"}]},
        _closure_matrix(),
    )
    blocked_source = build_closure_projection(
        {"next_action": "handoff", "repo_source_summary": {"status": "confirmation_required"}},
        _closure_matrix(),
    )

    assert missing_browser["verdict"] == "finish"
    assert partial_browser["reasons"] == ["browser_evidence_partial"]
    assert required_browser["reasons"] == ["browser_evidence_required"]
    assert pending_js["reasons"] == ["js_evidence_partial"]
    assert blocked_source["reasons"] == ["source_evidence_partial"]


def test_closure_handoffs_for_high_value_or_invalid_observation_inventory():
    high_value = build_closure_projection(
        {
            "next_action": "handoff",
            "observation_inventory": {
                "status": "valid",
                "by_kind": {"exposure": {"present_untouched": 2}},
            },
        },
        _closure_matrix(),
    )
    invalid = build_closure_projection(
        {"next_action": "handoff", "observation_inventory": {"status": "stale"}},
        _closure_matrix(),
    )
    reviewed = build_closure_projection(
        {
            "next_action": "handoff",
            "observation_inventory": {
                "status": "valid",
                "by_kind": {"exposure": {"present_untouched": 0}},
            },
        },
        _closure_matrix(),
    )

    assert high_value["reasons"] == ["observation_high_value_pending"]
    assert invalid["reasons"] == ["observation_inventory_partial"]
    for closure in (high_value, invalid):
        assert closure["actionable_frontier"][0]["owner"] == "observation"
        assert closure["actionable_frontier"][0]["evidence_ref"].endswith(
            "observations-summary.json"
        )
    assert reviewed["verdict"] == "finish"


def test_default_formatted_state_omits_explicit_closure_line():
    output = format_autopilot_state({
        "target": "target.com",
        "has_recon": False,
        "has_memory": False,
        "next_action": "run_recon",
    })

    assert "Closure:" not in output
    assert "Loop guard:" not in output


def test_normal_bounded_state_never_loads_closure_owners(tmp_path, monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError("closure owner read")

    monkeypatch.setattr("autopilot_state.load_matrix", fail)
    monkeypatch.setattr("autopilot_state.load_entries_diagnostic", fail)

    state = build_autopilot_state(
        str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory"), bounded=True
    )

    assert state["next_action"] == "run_recon"


def test_explicit_closure_defers_non_substantive_active_queue_work(tmp_path):
    target = "target.com"
    evidence_dir = tmp_path / "evidence" / target_storage_key(target)
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "coverage_matrix.json").write_text(
        json.dumps(_closure_matrix()), encoding="utf-8"
    )
    queue_dir = tmp_path / "state" / target_storage_key(target)
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps({
            "schema_version": 1,
            "target": target,
            "actions": [{
                "id": "AQ-0001",
                "status": "queued",
                "type": "surface-review",
                "evidence": "reason: top advisory score",
            }],
        }),
        encoding="utf-8",
    )

    state = build_autopilot_state(
        str(tmp_path), target, memory_dir=str(tmp_path / "hunt-memory"), bounded=True
    )
    assert state["action_queue_next"] == {}
    state["next_action"] = "handoff"
    state["observation_inventory"] = {"status": "valid", "by_kind": {}}
    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert closure["verdict"] == "finish"
    assert closure["reasons"] == []


def test_explicit_closure_keeps_substantive_surface_queue_work(tmp_path):
    target = "target.com"
    evidence_dir = tmp_path / "evidence" / target_storage_key(target)
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "coverage_matrix.json").write_text(
        json.dumps(_closure_matrix()), encoding="utf-8"
    )
    queue_dir = tmp_path / "state" / target_storage_key(target)
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps({
            "schema_version": 1,
            "target": target,
            "actions": [{
                "id": "AQ-0001",
                "status": "queued",
                "type": "surface-review",
                "command_hint": "python3 tools/validation_runner.py marker-replay",
                "evidence": "findings/target.com/poc/candidate.json",
                "stop_condition": "record a terminal replay result",
            }],
        }),
        encoding="utf-8",
    )
    state = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "observation_inventory": {"status": "valid", "by_kind": {}},
    }

    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)

    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["durable_work_pending"]


def test_explicit_closure_checks_pending_source_and_js_artifacts(tmp_path):
    target = "target.com"
    storage_key = target_storage_key(target)
    evidence_dir = tmp_path / "evidence" / storage_key
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "coverage_matrix.json").write_text(
        json.dumps(_closure_matrix()), encoding="utf-8"
    )
    exposure_dir = tmp_path / "findings" / storage_key / "exposure"
    exposure_dir.mkdir(parents=True)
    (exposure_dir / "repo_source_meta.json").write_text('{"status":"ok"}\n', encoding="utf-8")

    state = build_autopilot_state(str(tmp_path), target, bounded=True)
    state["next_action"] = "handoff"
    state["observation_inventory"] = {"status": "valid", "by_kind": {}}
    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)
    assert closure["reasons"] == ["source_evidence_partial"]

    source_intel = tmp_path / "findings" / storage_key / "source_intel"
    source_intel.mkdir()
    (source_intel / "summary.md").write_text("source review complete\n", encoding="utf-8")
    assert _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)["verdict"] == "finish"

    js_dir = tmp_path / "recon" / storage_key / "urls"
    js_dir.mkdir(parents=True)
    (js_dir / "js_files.txt").write_text("https://target.com/app.js\n", encoding="utf-8")
    closure = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)
    assert closure["reasons"] == ["js_evidence_partial"]

    js_intel = tmp_path / "findings" / storage_key / "js_intel"
    js_intel.mkdir()
    (js_intel / "materials.json").write_text("{}\n", encoding="utf-8")
    prepared = _load_closure_projection(str(tmp_path), state, max_lanes_reached=False)
    assert prepared["verdict"] == "handoff"
    assert prepared["reasons"] == ["js_evidence_partial"]


def test_sql_matrix_projection_validates_lane_and_source_freshness(tmp_path):
    target = "target.com"
    source = tmp_path / "urls.txt"
    source.write_text("https://target.com/search?q=1\n", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    summary = tmp_path / "findings" / target / "poc" / "sql_matrix" / "query" / "summary.json"
    summary.parent.mkdir(parents=True)
    summary.write_text(json.dumps({
        "schema_version": 1,
        "kind": "sql_matrix_summary",
        "lane": "query",
        "target": target,
        "status": "candidate_pending",
        "input_fingerprint": "a" * 64,
        "waf_plan_sha256": "b" * 64,
        "waf_plan_variant_count": 2,
        "waf_ai_variants_executed": 2,
        "source_bindings": [{"path": str(source), "sha256": digest}],
        "endpoint_count": 1,
        "hit_count": 1,
        "hits": [{"url": "https://target.com/search", "field": "q", "class": "sqli_error", "signal": "error"}],
    }), encoding="utf-8")
    projection = _load_sql_matrix_projection(str(tmp_path), target, "query")
    assert projection["status"] == "candidate_pending"
    assert projection["waf_plan_variant_count"] == 2
    assert projection["candidates"] == [{"endpoint": "/search", "field": "q", "class": "sqli_error", "signal": "error"}]
    source.write_text("changed\n", encoding="utf-8")
    stale = _load_sql_matrix_projection(str(tmp_path), target, "query")
    assert stale["status"] == "partial"
    assert stale["reason"] == "stale_source_binding"


def test_sql_matrix_partial_blocks_closure(tmp_path):
    target = "target.com"
    summary = tmp_path / "findings" / target / "poc" / "sql_matrix" / "form" / "summary.json"
    summary.parent.mkdir(parents=True)
    summary.write_text(json.dumps({
        "schema_version": 1,
        "kind": "sql_matrix_summary",
        "lane": "form",
        "target": target,
        "status": "partial",
        "input_fingerprint": "b" * 64,
        "source_bindings": [{"path": "missing-input", "sha256": "c" * 64}],
    }), encoding="utf-8")
    projection = _load_sql_matrix_projection(str(tmp_path), target, "form")
    closure = build_closure_projection(
        {"target": target, "next_action": "handoff", "sql_matrix": {"form": projection}},
        _closure_matrix(),
    )
    assert closure["verdict"] == "handoff"
    assert closure["reasons"] == ["sql_evidence_partial"]


def test_js_materials_require_analysis_or_terminal_disposition(tmp_path):
    target = "target.com"
    js_dir = tmp_path / "findings" / target / "js_intel"
    js_dir.mkdir(parents=True)
    (js_dir / "materials.json").write_text("{}\n", encoding="utf-8")
    prepared = _load_js_intel_projection(str(tmp_path), target)
    assert prepared["status"] == "prepared"
    (js_dir / "hypotheses.json").write_text(json.dumps({"hypotheses": [{"id": "h1"}]}), encoding="utf-8")
    assert _load_js_intel_projection(str(tmp_path), target)["status"] == "analyzed"
    (js_dir / "hypotheses.json").write_text("{}\n", encoding="utf-8")
    assert _load_js_intel_projection(str(tmp_path), target)["status"] == "partial"
    (js_dir / "disposition.json").write_text(json.dumps({"status": "blocked", "evidence_ref": "findings/target/js.log"}), encoding="utf-8")
    assert _load_js_intel_projection(str(tmp_path), target)["status"] == "blocked"


def test_js_reader_attack_surface_leads_are_analyzed(tmp_path):
    target = "target.com"
    js_dir = tmp_path / "findings" / target / "js_intel"
    js_dir.mkdir(parents=True)
    (js_dir / "hypotheses.json").write_text(
        json.dumps({
            "hypotheses": [],
            "endpoints": [{"path": "/api/orders"}],
            "attack_surface_leads": [{"title": "order authorization"}],
        }),
        encoding="utf-8",
    )

    projection = _load_js_intel_projection(str(tmp_path), target)

    assert projection["status"] == "analyzed"
    assert projection["analysis_format"] == "attack_surface_leads"
    assert projection["hypothesis_count"] == 1


class TestAutopilotState:
    def test_bounded_recon_counts_render_unknown_without_crashing(self, tmp_path):
        recon_dir = tmp_path / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir()
        (recon_dir / "live" / "httpx_full.txt").write_text("https://target.com\n")
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://target.com/search?q=1\n"
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
            bounded=True,
        )

        assert state["recon_artifacts"]["counts"]["hosts"] is None
        assert "Recon cache: hosts=?, surface=?" in format_autopilot_state(state)


    def test_batch_state_selects_only_completed_domain_handoff(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\nbeta.test\ngamma.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / target_storage_key(str(scope))
        batch_dir.mkdir(parents=True)
        (batch_dir / "batch_manifest.jsonl").write_text(
            '{"target":"alpha.test","status":"ok"}\n'
            '{"target":"beta.test","status":"failed"}\n',
            encoding="utf-8",
        )
        (batch_dir / "failed_targets.txt").write_text("beta.test\n", encoding="utf-8")
        (batch_dir / "pending_targets.txt").write_text(
            "alpha.test\nbeta.test\ngamma.test\n",
            encoding="utf-8",
        )
        (batch_dir / "high_value_targets.json").write_text(
            json.dumps([
                {"target": "alpha.test", "score": "invalid", "top_signals": []},
                {"target": "uncompleted.test", "score": 99, "top_signals": []},
            ]),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))

        assert state["target_kind"] == "list"
        assert state["next_action"] == "select_completed_domain"
        assert state["batch"]["completed"] == ["alpha.test"]
        assert state["batch"]["failed"] == ["beta.test"]
        assert state["batch"]["pending"] == ["gamma.test"]
        assert [item["target"] for item in state["batch"]["candidates"]] == ["alpha.test"]
        assert state["batch"]["candidates"][0]["score"] == 0
        assert state["batch"]["candidates"][0]["parent_scope_ref"] == str(scope.resolve())
        assert state["batch"]["candidates"][0]["parent_scope_hash"] == state["scope"]["scope_hash"]
        assert state["batch"]["candidates"][0]["continuation_create_args"] == [
            "--parent-target",
            str(scope.resolve()),
            "--selected-target",
            "alpha.test",
        ]
        output = format_autopilot_state(state)
        assert "Completed-domain candidates:" in output
        assert "alpha.test" in output
        assert "Do not run surface, scan, or active hunting against the batch index." in output

    def test_empty_batch_is_terminal_instead_of_restarting_recon(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("# no current targets\n\n", encoding="utf-8")

        state = build_autopilot_state(str(tmp_path), str(scope))
        output = format_autopilot_state(state)

        assert state["next_action"] == "invalid_batch_target"
        assert state["batch"]["current_entries"] == []
        assert state["batch"]["pending"] == []
        assert "Stop: add at least one usable primary domain" in output

    def test_same_stem_batch_lists_do_not_share_recon_wait_state(self, tmp_path):
        first = tmp_path / "a" / "scope.txt"
        second = tmp_path / "b" / "scope.txt"
        first.parent.mkdir()
        second.parent.mkdir()
        first.write_text("alpha.test\n", encoding="utf-8")
        second.write_text("beta.test\n", encoding="utf-8")
        update_runtime_state(
            tmp_path,
            str(first),
            mode="recon_only",
            last_executed_workflow="run_recon_started",
        )

        with runtime_phase_lock(tmp_path, str(first), "recon"):
            first_state = build_autopilot_state(str(tmp_path), str(first))
            second_state = build_autopilot_state(str(tmp_path), str(second))

        assert target_storage_key(str(first)) != target_storage_key(str(second))
        assert first_state["next_action"] == "wait_recon"
        assert second_state["next_action"] == "run_batch_recon"

    def test_owned_legacy_batch_state_and_recon_are_migrated(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\n", encoding="utf-8")
        old_state = tmp_path / "state" / "targets"
        old_state.mkdir(parents=True)
        (old_state / "session.json").write_text(json.dumps({
            "schema_version": 2,
            "target": str(scope.resolve()),
            "storage_key": "targets",
            "mode": "recon_only",
            "last_executed_workflow": "run_recon",
            "updated_at": "2026-07-12T00:00:00Z",
        }), encoding="utf-8")
        old_recon = tmp_path / "recon" / "targets"
        old_recon.mkdir(parents=True)
        (old_recon / "completed_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (old_recon / "high_value_targets.json").write_text(
            json.dumps([{"target": "alpha.test", "score": 5}]),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))
        new_key = target_storage_key(str(scope))

        assert state["next_action"] == "select_completed_domain"
        migrated_session = tmp_path / "state" / new_key / "session.json"
        assert migrated_session.is_file()
        assert json.loads(migrated_session.read_text(encoding="utf-8"))["storage_key"] == new_key
        assert (tmp_path / "recon" / new_key / "completed_targets.txt").is_file()
        assert not old_state.exists()
        assert not old_recon.exists()

    def test_all_failed_current_batch_is_terminal(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\nbeta.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / target_storage_key(str(scope))
        batch_dir.mkdir(parents=True)
        (batch_dir / "failed_targets.txt").write_text(
            "alpha.test\nbeta.test\nold.test\n",
            encoding="utf-8",
        )
        (batch_dir / "pending_targets.txt").write_text(
            "old.test\n",
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))
        output = format_autopilot_state(state)

        assert state["next_action"] == "batch_failed"
        assert state["batch"]["failed"] == ["alpha.test", "beta.test"]
        assert state["batch"]["pending"] == []
        assert "do not retry the failed batch automatically" in output

    def test_changed_batch_input_filters_old_candidates_and_adds_current_pending(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("beta.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / target_storage_key(str(scope))
        batch_dir.mkdir(parents=True)
        (batch_dir / "completed_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (batch_dir / "pending_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (batch_dir / "high_value_targets.json").write_text(
            json.dumps([{"target": "alpha.test", "score": 99}]),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))

        assert state["next_action"] == "run_batch_recon"
        assert state["batch"]["current_entries"] == ["beta.test"]
        assert state["batch"]["completed"] == []
        assert state["batch"]["candidates"] == []
        assert state["batch"]["pending"] == ["beta.test"]

    def test_changed_batch_scope_hash_invalidates_completion_projection(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\nbeta.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / target_storage_key(str(scope))
        batch_dir.mkdir(parents=True)
        (batch_dir / "completed_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (batch_dir / "scope_context.json").write_text(
            json.dumps({"scope_hash": "sha256:old"}),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))

        assert state["batch"]["scope_changed"] is True
        assert state["batch"]["completed"] == []
        assert state["batch"]["pending"] == ["alpha.test", "beta.test"]
        assert state["next_action"] == "run_batch_recon"

    def test_partial_batch_keeps_current_pending_when_ranked_json_is_invalid(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\nbeta.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / target_storage_key(str(scope))
        batch_dir.mkdir(parents=True)
        (batch_dir / "completed_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (batch_dir / "pending_targets.txt").write_text("beta.test\nold.test\n", encoding="utf-8")
        (batch_dir / "high_value_targets.json").write_text("{invalid", encoding="utf-8")

        state = build_autopilot_state(str(tmp_path), str(scope))

        assert state["next_action"] == "select_completed_domain"
        assert state["batch"]["pending"] == ["beta.test"]
        assert [item["target"] for item in state["batch"]["candidates"]] == ["alpha.test"]

    def test_ranked_filter_keeps_closed_history_but_removes_object_placeholders(self):
        kept_dead_end = {
            "url": "https://app.target.com/api/orders",
            "suggested": "avoid repeating remembered dead end unless new evidence changed",
        }
        kept_reported = {
            "url": "https://app.target.com/api/users",
            "suggested": "already reported/generated; avoid repeating exact lane",
        }
        placeholder = {"url": "https://app.target.com/rest/basket/NaN"}

        filtered = _filter_ranked_placeholders({
            "review_pool": [kept_dead_end, kept_reported, placeholder],
            "p1": [kept_dead_end, kept_reported, placeholder],
            "p2": [],
        })

        assert filtered["review_pool"] == [kept_dead_end, kept_reported]
        assert filtered["p1"] == [kept_dead_end, kept_reported]

    def test_recommended_targets_frontload_last_focus_within_same_guard_bucket(self):
        recommended = _build_recommended_targets(
            [
                {
                    "url": "https://api.target.com/api/v2/users/123",
                    "host": "api.target.com",
                    "suggested": "idor checks",
                    "score": 18,
                },
                {
                    "url": "https://api.target.com/graphql",
                    "host": "api.target.com",
                    "suggested": "field auth checks",
                    "score": 10,
                },
            ],
            {"hosts": []},
            ["/graphql"],
            prefer_resume_targets=True,
        )

        assert recommended[0]["url"] == "https://api.target.com/graphql"
        assert recommended[0]["matches_resume_target"] is True
        assert recommended[1]["matches_resume_target"] is False

    def test_recommended_targets_preserve_surface_review_order_over_score(self):
        recommended = _build_recommended_targets(
            [
                {
                    "url": "https://app.target.com/rest/languages",
                    "host": "app.target.com",
                    "suggested": "browser-observed workflow checks",
                    "score": 7,
                    "review_reason": "browser-observed API/workflow",
                },
                {
                    "url": "https://app.target.com/rest/continue-code/apply/",
                    "host": "app.target.com",
                    "suggested": "baseline checks",
                    "score": 11,
                    "review_reason": "top advisory score",
                },
            ],
            {"hosts": []},
        )

        assert recommended[0]["url"] == "https://app.target.com/rest/languages"
        assert recommended[0]["review_reason"] == "browser-observed API/workflow"

    def test_requires_recon_when_missing(self, tmp_path):
        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(memory_dir))
        assert state["has_recon"] is False
        assert state["has_memory"] is True
        assert state["next_action"] == "run_recon"

    def test_loads_target_goal_memory_into_state_and_output(self, tmp_path):
        repo_root = tmp_path
        goals_dir = repo_root / "memory" / "goals"
        target_dir = goals_dir / "targets"
        target_dir.mkdir(parents=True)
        (goals_dir / "active.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "active_goal": "test org API authorization",
                    "current_hypothesis": "org_id may be user-controlled",
                }
            ),
            encoding="utf-8",
        )
        (target_dir / "target.com.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "active_leads": [{"text": "/api/org/{id}/users"}],
                    "next_actions": [{"text": "run role_diff with two owned accounts"}],
                    "dead_ends": [{"text": "GraphQL introspection alone is not reportable"}],
                    "session_handoffs": [
                        {
                            "path": "memory/goals/sessions/example.md",
                            "summary": "continue org API role diff",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["target_goal_memory"]["active_matches"] is True
        assert state["target_goal_memory"]["active"]["active_goal"] == "test org API authorization"
        assert "Target memory:" in output
        assert "Goal: test org API authorization" in output
        assert "Hypothesis: org_id may be user-controlled" in output
        assert "/api/org/{id}/users" in output
        assert "run role_diff with two owned accounts" in output
        assert state["memory_action_queue"]
        assert state["memory_action_queue"][0]["command_hint"] == "role/object diff with low-risk replay"
        assert "Memory action queue:" in output
        assert "continue org API role diff" in output

    def test_legacy_raw_corpus_nuclei_action_requires_replan_without_memory_mutation(self, tmp_path):
        repo_root = tmp_path
        target_memory_path = repo_root / "memory" / "goals" / "targets" / "target.com.json"
        target_memory_path.parent.mkdir(parents=True)
        target_memory_path.write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "next_actions": [
                        {"text": "Run /validate after nuclei on 19K wayback URLs"},
                        {"text": "Run nuclei -l all.txt -severity high,critical"},
                        {
                            "text": (
                                "Run nuclei -tags cve -id CVE-2026-1234 against "
                                "https://app.target.com/admin"
                            )
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        original_bytes = target_memory_path.read_bytes()

        state = build_autopilot_state(
            str(repo_root),
            "target.com",
            memory_dir=str(repo_root / "hunt-memory"),
        )
        output = format_autopilot_state(state)

        stale, stale_file, targeted = state["memory_action_queue"]
        assert stale["action"] == "Run /validate after nuclei on 19K wayback URLs"
        for item in (stale, stale_file):
            assert item["status"] == "requires_replan"
            assert item["executable"] is False
            assert "scan-only --quick" in item["command_hint"]
        assert state["memory_candidate_next"] == {}
        assert targeted.get("status") is None
        assert targeted.get("executable", True) is True
        assert target_memory_path.read_bytes() == original_bytes
        assert "status: requires_replan" in output
        assert "executable: false" in output

    def test_target_memory_validate_candidate_preempts_generic_resume_and_requires_artifact(self, tmp_path):
        repo_root = tmp_path
        memory_dir = repo_root / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(
            memory_dir,
            make_target_profile(
                "target.com",
                untested_endpoints=["/historical-resume"],
                hunt_sessions=1,
            ),
        )
        target_memory_path = repo_root / "memory" / "goals" / "targets" / "target.com.json"
        target_memory_path.parent.mkdir(parents=True)
        target_memory_path.write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "next_actions": [
                        {
                            "text": (
                                "Run /validate for SQLi candidate after comparing the raw response pair. "
                                "Evidence=evidence/target.com/validation/sqli/raw-pair.json"
                            )
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        state_without_artifact = build_autopilot_state(
            str(repo_root),
            "target.com",
            memory_dir=str(memory_dir),
        )

        assert state_without_artifact["memory_candidate_next"]["command_hint"] == "/validate"
        assert state_without_artifact["memory_candidate_next"]["evidence_available"] is False
        assert state_without_artifact["next_action"] == "collect_candidate_evidence"
        assert state_without_artifact["next_action"] != "resume_untested"
        assert (
            _pick_next_action(
                True,
                {},
                {"latest_session_summary": {"session_id": "old-session"}},
                resume_targets=["/historical-resume"],
                memory_candidate_next=state_without_artifact["memory_candidate_next"],
            )
            == "collect_candidate_evidence"
        )

        raw_evidence = repo_root / "evidence" / "target.com" / "validation" / "sqli" / "raw-pair.json"
        raw_evidence.parent.mkdir(parents=True)
        raw_evidence.write_text('{"baseline": 1, "probe": 56}\n', encoding="utf-8")

        state_with_artifact = build_autopilot_state(
            str(repo_root),
            "target.com",
            memory_dir=str(memory_dir),
        )

        assert state_with_artifact["memory_candidate_next"]["evidence_ref"].endswith("raw-pair.json")
        assert state_with_artifact["memory_candidate_next"]["evidence_available"] is True
        assert state_with_artifact["next_action"] == "validate_finding"

    def test_target_memory_evidence_requires_target_owned_nonempty_regular_file(self, tmp_path):
        repo_root = tmp_path
        memory_path = repo_root / "memory" / "goals" / "targets" / "target.com.json"
        memory_path.parent.mkdir(parents=True)
        memory_path.write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "next_actions": [
                        {"text": "Run /validate Evidence=evidence/target.com/empty.json"},
                        {"text": "Run /validate Evidence=evidence/other.test/raw.json"},
                        {"text": "Run /validate Evidence=evidence/target.com"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        target_root = repo_root / "evidence" / "target.com"
        target_root.mkdir(parents=True)
        (target_root / "empty.json").write_text("", encoding="utf-8")
        (repo_root / "evidence" / "other.test").mkdir(parents=True)
        (repo_root / "evidence" / "other.test" / "raw.json").write_text("{}", encoding="utf-8")

        state = build_autopilot_state(str(repo_root), "target.com")

        assert len(state["memory_action_queue"]) == 3
        assert all(item["evidence_available"] is False for item in state["memory_action_queue"])

    def test_legacy_memory_narrative_cannot_preempt_report_closure(self, tmp_path):
        target_memory_path = tmp_path / "memory" / "goals" / "targets" / "target.com.json"
        target_memory_path.parent.mkdir(parents=True)
        target_memory_path.write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "next_actions": [
                        {"text": "Please validate the report narrative next session."},
                        {"text": "Validated finding needs report reconciliation."},
                        {"text": "Review validation notes next session."},
                        {"text": "/validated findings are only a handoff summary."},
                        {"text": "/validate-later is not the validation command."},
                    ],
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), "target.com")

        assert state["memory_candidate_next"] == {}
        assert len(state["memory_action_queue"]) == 5
        assert all(item["command_hint"] != "/validate" for item in state["memory_action_queue"])
        assert state["next_action"] == "run_recon"

        legacy_candidate = {"command_hint": "/validate", "evidence_available": False}
        assert (
            _pick_next_action(
                True,
                {},
                None,
                {"draft_completion_pending": 1},
                memory_candidate_next=legacy_candidate,
            )
            == "complete_report_draft"
        )
        assert (
            _pick_next_action(
                True,
                {},
                None,
                {"validated_pending_report": 1},
                memory_candidate_next=legacy_candidate,
            )
            == "report_finding"
        )

    def test_fresh_recon_without_ranked_candidate_prepares_surface_context(self):
        assert (
            _pick_next_action(
                True,
                {"review_pool": [], "p1": []},
                None,
                fresh_recon_ready=True,
            )
            == "prepare_surface_context"
        )

    def test_validated_incomplete_draft_completes_without_revalidating(self):
        assert (
            _pick_next_action(
                True,
                {"review_pool": [], "p1": []},
                None,
                {"draft_completion_pending": 1},
            )
            == "complete_report_draft"
        )

    def test_host_list_relative_target_uses_batch_handoff_not_aggregate_surface(self, tmp_path, monkeypatch):
        repo_root = tmp_path
        list_file = repo_root / "scope.txt"
        list_file.write_text("api.target.com\n", encoding="utf-8")
        monkeypatch.chdir(repo_root)

        recon_dir = repo_root / "recon" / target_storage_key("scope.txt")
        recon_dir.mkdir(parents=True)
        (recon_dir / "completed_targets.txt").write_text("api.target.com\n")
        (recon_dir / "high_value_targets.json").write_text(
            json.dumps([{"target": "api.target.com", "score": 12}]),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "scope.txt")

        assert state["resolved_target"] == str(list_file.resolve())
        assert state["target_kind"] == "list"
        assert state["has_recon"] is True
        assert state["next_action"] == "select_completed_domain"
        assert state["batch"]["candidates"][0]["target"] == "api.target.com"
        assert "surface" not in state
        assert "guard_status" not in state

    def test_all_hosts_tripped_pivots_to_cached_evidence_work(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,Cloudflare] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        record_request(
            memory_dir=memory_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=403,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=time.time(),
        )

        _publish_surface_projection(repo_root, "target.com", memory_dir)
        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["next_action"] == "guard_safe_pivot"
        assert state["guard_status"]["ready_hosts"] == 0
        assert state["next_tool_hint"] == "context_pack"
        assert "cached recon/browser/JS/source evidence" in output
        assert "residential" not in output.lower()

    def test_pending_structured_finding_collects_missing_candidate_evidence(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "sqli_pending",
                            "type": "sqli",
                            "severity": "high",
                            "confidence": "confirmed",
                            "url": "https://api.target.com/search?q=1",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                            "rubric": {
                                "rubric_id": "sqli",
                                "status": "needs-evidence",
                                "ready": False,
                                "score": 50,
                                "satisfied_count": 2,
                                "total": 4,
                                "missing_labels": [
                                    "paired baseline and probe",
                                    "stable response difference",
                                ],
                                "next_actions": [
                                    "capture a paired baseline/probe response diff",
                                ],
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["next_action"] == "collect_candidate_evidence"
        assert "collect candidate evidence for finding sqli_pending" in output
        assert "missing=paired baseline and probe, stable response difference" in output
        assert "Next evidence step: capture a paired baseline/probe response diff" in output
        assert "Structured findings: total=1, pending_validation=1" in output
        assert "Next validation: sqli_pending [high/confirmed] sqli https://api.target.com/search?q=1" in output
        assert state["next_tool_hint"] == ""

    def test_ready_and_legacy_structured_candidates_still_validate(self):
        ready = {
            "next_validation": {
                "id": "ready-candidate",
                "rubric": {"ready": True, "status": "candidate-ready"},
            }
        }
        legacy = {"next_validation": {"id": "legacy-candidate"}}

        assert _pick_next_action(True, {}, None, ready) == "validate_finding"
        assert _pick_next_action(True, {}, None, legacy) == "validate_finding"

    def test_root_json_claim_is_read_only_candidate_evidence_handoff(self, tmp_path):
        findings_dir = tmp_path / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "manual-claim.json").write_text(
            json.dumps(
                {
                    "title": "Manual SQLi claim",
                    "severity": "critical",
                    "endpoint": "/rest/products/search",
                    "vuln_class": "SQLi",
                    "poc": "curl https://target.com/rest/products/search?q=...",
                    "impact": "claimed database access",
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), "target.com")
        output = format_autopilot_state(state)

        assert state["next_action"] == "collect_candidate_evidence"
        assert state["root_finding_claim_next"]["claim_source_file"] == "manual-claim.json"
        assert state["root_finding_claim_next"]["evidence_rubric"]["ready"] is False
        assert not (findings_dir / "findings.json").exists()
        assert "Unreconciled root finding claims (not validated):" in output
        assert "Do not call it validated or report-ready from the claim alone." in output

    def test_wait_marker_preempts_missing_candidate_evidence(self):
        structured = {
            "next_validation": {
                "id": "waiting-candidate",
                "rubric": {"ready": False, "status": "needs-evidence"},
            }
        }

        assert (
            _pick_next_action(
                True,
                {},
                None,
                structured,
                recon_in_progress=True,
            )
            == "wait_recon"
        )

    def test_outputs_validation_runner_candidates_as_advisory_pool(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [API] [Express] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://target.com/rest/basket/6\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        validation_dir = repo_root / "evidence" / "target.com" / "validation" / "idor-basket"
        validation_dir.mkdir(parents=True)
        (validation_dir / "summary.json").write_text(
            json.dumps(
                {
                    "lane": "idor_actor_pair",
                    "finding_id": "idor-basket",
                    "url": "https://target.com/rest/basket/6",
                    "method": "GET",
                    "result": "tested_finding",
                    "candidate_ready": True,
                    "evidence_rubric": {
                        "status": "candidate-ready",
                        "ready": True,
                        "summary": "authz:candidate-ready",
                    },
                }
            ),
            encoding="utf-8",
        )
        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["validation_runner_candidates"][0]["id"] == "idor-basket"
        assert state["validation_runner_next"]["id"] == "idor-basket"
        assert state["next_action"] == "review_validation_candidate"
        assert "review validation-runner candidate idor-basket" in output
        assert "Validation runner candidates (advisory; require /validate before report):" in output
        assert "idor-basket [idor_actor_pair/tested_finding]" in output

    def test_substantive_durable_queue_preempts_fresh_recon(self, tmp_path):
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "actions": [
                    {
                        "id": "AQ-0001",
                        "target": "target.com",
                        "status": "candidate",
                        "type": "candidate-evidence-gap",
                        "priority": 95,
                        "action": "Review the exact owner/peer response diff.",
                        "command_hint": "/validate idor-orders",
                        "evidence": "runner summary is candidate-ready",
                    }
                ],
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )
        output = format_autopilot_state(state)

        assert state["has_recon"] is False
        assert state["action_queue_next"]["id"] == "AQ-0001"
        assert state["next_action"] == "resume_action_queue"
        assert "resume durable action AQ-0001" in output

    def test_queued_evidence_actions_reach_action_queue_next(self, tmp_path):
        for index, action_type in enumerate((
            "candidate-evidence-gap",
            "actor-gap",
            "coverage-gap",
            "action-gated-review",
            "browser-enrichment",
            "case-state-enrichment",
        ), 1):
            target = f"case{index}.target"
            queue_dir = tmp_path / "state" / target
            queue_dir.mkdir(parents=True)
            (queue_dir / "action_queue.json").write_text(json.dumps({
                "schema_version": 1,
                "target": target,
                "actions": [{
                    "id": "AQ-0001",
                    "status": "queued",
                    "type": action_type,
                    "priority": 90,
                    "action": f"Execute {action_type} from existing evidence.",
                    "command_hint": "review the linked evidence",
                }],
            }))

            state = build_autopilot_state(
                str(tmp_path), target, memory_dir=str(tmp_path / "hunt-memory")
            )

            assert state["action_queue_next"]["type"] == action_type
            assert state["next_action"] == "resume_action_queue"

    def test_advisory_queue_item_does_not_preempt_fresh_recon(self, tmp_path):
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "actions": [
                    {
                        "id": "AQ-0001",
                        "target": "target.com",
                        "status": "queued",
                        "type": "surface-review",
                        "priority": 92,
                        "action": "Review a score-only surface hint.",
                        "command_hint": "choose a route",
                        "evidence": "Reason: top advisory score",
                    }
                ],
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )

        assert state["action_queue_next"] == {}
        assert state["next_action"] == "run_recon"

    def test_generic_surface_command_does_not_preempt_fresh_recon(self, tmp_path):
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(json.dumps({
            "schema_version": 1,
            "target": "target.com",
            "actions": [{
                "id": "AQ-0001",
                "status": "queued",
                "type": "surface-review",
                "priority": 99,
                "action": "Refresh the generic surface review.",
                "command_hint": "python3 tools/surface.py --target target.com",
            }],
        }))

        state = build_autopilot_state(
            str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory")
        )

        assert state["action_queue_next"] == {}
        assert state["next_action"] == "run_recon"

    def test_advisory_item_does_not_hide_lower_priority_substantive_action(
        self, tmp_path
    ):
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "actions": [
                        {
                            "id": "AQ-0001",
                            "target": "target.com",
                            "status": "queued",
                            "type": "manual-review",
                            "priority": 90,
                            "action": "Review a generic advisory.",
                            "command_hint": "choose a route",
                        },
                        {
                            "id": "AQ-0002",
                            "target": "target.com",
                            "status": "queued",
                            "type": "browser-context-discovery",
                            "priority": 78,
                            "source": "browser-context-discovery",
                            "evidence_type": "browser-context-discovery",
                            "action": "Review the captured browser delta.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )

        assert state["action_queue_next"]["id"] == "AQ-0002"
        assert state["next_action"] == "resume_action_queue"

    def test_completed_recon_without_live_hosts_is_terminal(self, tmp_path):
        recon_dir = tmp_path / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text("", encoding="utf-8")
        (recon_dir / "exposure").mkdir()
        (recon_dir / "exposure" / "config_files.txt").write_text(
            "https://target.com/.env\n",
            encoding="utf-8",
        )
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_only",
            last_executed_workflow="run_recon",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )
        output = format_autopilot_state(state)

        assert state["has_recon"] is False
        assert state["recon_completed_no_live_hosts"] is True
        assert state["next_action"] == "recon_no_live_hosts"
        assert "do not rerun recon automatically" in output
        assert "completed with no live host inventory" in state["recon_blocker"]
        inventory = state["observation_inventory"]
        assert inventory["total"] >= 1
        assert inventory["untouched"] >= 1
        assert "Observation inventory: total=" in output

    def test_incomplete_http_probing_is_not_no_live_terminal(self, tmp_path):
        for index, (status, note) in enumerate((
            ("skipped", "httpx missing"),
            ("partial", "httpx timed out"),
            ("failed", "httpx failed"),
        ), 1):
            target = f"probe{index}.target"
            recon_dir = tmp_path / "recon" / target
            (recon_dir / "live").mkdir(parents=True)
            (recon_dir / "live" / "httpx_full.txt").write_text("")
            (recon_dir / "recon_manifest.jsonl").write_text(json.dumps({
                "record_type": "recon_phase",
                "phase": "http_probing",
                "status": status,
                "count": 0,
                "note": note,
            }) + "\n")
            update_runtime_state(
                tmp_path, target, mode="recon_only", last_executed_workflow="run_recon"
            )

            state = build_autopilot_state(
                str(tmp_path), target, memory_dir=str(tmp_path / "hunt-memory")
            )

            assert state["recon_completed_no_live_hosts"] is False
            assert state["next_action"] == "run_recon"

    def test_zero_live_hosts_with_historical_surface_is_not_terminal(self, tmp_path):
        recon_dir = tmp_path / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir()
        (recon_dir / "live" / "httpx_full.txt").write_text("")
        (recon_dir / "urls" / "all.txt").write_text("https://target.com/api/history\n")
        (recon_dir / "recon_manifest.jsonl").write_text(json.dumps({
            "record_type": "recon_phase",
            "phase": "http_probing",
            "status": "ok",
            "count": 0,
        }) + "\n")
        update_runtime_state(
            tmp_path, "target.com", mode="recon_only", last_executed_workflow="run_recon"
        )

        state = build_autopilot_state(
            str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory")
        )

        assert state["has_recon"] is True
        assert state["recon_completed_no_live_hosts"] is False
        assert state["next_action"] != "recon_no_live_hosts"

    def test_missing_recon_precedes_validated_structured_finding_report(self, tmp_path):
        repo_root = tmp_path
        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "mfa_report",
                            "type": "mfa",
                            "severity": "medium",
                            "confidence": "high",
                            "url": "https://api.target.com/mfa",
                            "validation_status": "validated",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        _record_owner_provenance(findings_dir, "mfa_report")

        state = build_autopilot_state(
            str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory")
        )
        output = format_autopilot_state(state)

        assert state["next_action"] == "run_recon"
        assert "Next: run /recon target.com first." in output
        assert "Next report: mfa_report [medium/high] mfa https://api.target.com/mfa" in output

    def test_weak_generic_pending_does_not_mask_validated_report(self, tmp_path):
        repo_root = tmp_path
        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "metrics",
                            "type": "exposure",
                            "severity": "medium",
                            "confidence": "medium",
                            "title": "prometheus-metrics on https://target.com/metrics",
                            "summary": "[prometheus-metrics] [http] [medium] https://target.com/metrics",
                            "url": "https://target.com/metrics",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                        },
                        {
                            "id": "admin_config",
                            "type": "auth_bypass",
                            "severity": "high",
                            "confidence": "confirmed",
                            "url": "https://target.com/rest/admin/application-configuration",
                            "validation_status": "validated",
                            "report_status": "not_generated",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        _record_owner_provenance(findings_dir, "admin_config")

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["structured_findings"]["pending_validation"] == 1
        assert "next_validation" not in state["structured_findings"]
        assert state["next_action"] == "run_recon"
        assert "Next: run /recon target.com first." in output
        assert "Next report: admin_config [high/confirmed] auth_bypass" in output
        assert "Next validation:" not in output

    def test_validated_report_does_not_preempt_live_surface_review(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/orders?id=42\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "mfa_report",
                            "type": "mfa",
                            "severity": "medium",
                            "confidence": "high",
                            "url": "https://api.target.com/mfa",
                            "validation_status": "validated",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        _record_owner_provenance(findings_dir, "mfa_report")

        memory_dir = tmp_path / "hunt-memory"
        _publish_surface_projection(repo_root, "target.com", memory_dir)
        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["has_recon"] is True
        assert state["surface_review_candidates"]
        assert state["next_action"] == "hunt_p1"
        assert "Next step: review the top surface candidate" in output
        assert "Next report: mfa_report [medium/high] mfa https://api.target.com/mfa" in output
        assert "Next: generate a report for validated finding mfa_report." not in output

    def test_prefers_p1_targets_when_recon_ready(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/v2/report?id=123\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/api/v2/users/123"],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=2,
        ))
        PatternDB(memory_dir / "patterns.jsonl").save(make_pattern_entry(
            target="alpha.com",
            vuln_class="idor",
            technique="id_swap",
            tech_stack=["graphql"],
            payout=900,
        ))

        _publish_surface_projection(repo_root, "target.com", memory_dir)
        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["has_recon"] is True
        assert state["has_memory"] is True
        assert state["next_action"] == "hunt_p1"
        assert state["recommended_targets"]
        assert "graphql" in state["recommended_targets"][0]["url"]

    def test_build_autopilot_state_does_not_rewrite_surface_probe_log(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/search?q=%27%20or%20%271%27=%271\n"
            "https://api.target.com/api/org/123/users\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        probe_log = recon_dir / "urls" / "_filtered_attack_probes.txt"
        probe_log.write_text("sentinel\n", encoding="utf-8")

        build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert probe_log.read_text(encoding="utf-8") == "sentinel\n"

    def test_prefers_continue_last_focus_when_recent_session_exists(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/graphql"],
            untested_endpoints=["/api/v2/users/123"],
            hunt_sessions=2,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/graphql"],
            vuln_classes_tried=["recon", "idor"],
            findings_count=1,
            session_id="sess-focus",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["next_action"] == "continue_last_focus"
        assert state["resume_targets"] == ["/graphql"]
        assert state["recommended_targets"][0]["url"] == "https://api.target.com/graphql"

    def test_finalized_findings_do_not_drive_resume_but_do_not_hide_surface(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [API] [Express] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://target.com/api/Feedbacks\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "auth_bypass_feedbacks",
                            "type": "auth_bypass",
                            "url": "https://target.com/api/Feedbacks",
                            "validation_status": "rejected",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        _record_owner_provenance(findings_dir, "auth_bypass_feedbacks")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tested_endpoints=["/api/Feedbacks"],
            untested_endpoints=[],
            hunt_sessions=1,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/api/Feedbacks"],
            vuln_classes_tried=["authz"],
            findings_count=0,
            session_id="sess-closed",
        )

        _publish_surface_projection(repo_root, "target.com", memory_dir)
        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["resume_targets"] == []
        assert state["surface_review_candidates"]
        assert state["surface_review_candidates"][0]["url"] == "https://target.com/api/Feedbacks"
        assert state["next_action"] == "hunt_p1"

    def test_build_autopilot_state_emits_enrichment_tool_hints(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [Admin Portal] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://app.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "urls" / "js_files.txt").write_text(
            "https://app.target.com/static/app.js\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("/api/v2/users\n")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["next.js", "graphql"],
            tested_endpoints=[],
            untested_endpoints=["/graphql"],
            hunt_sessions=1,
        ))

        _publish_surface_projection(repo_root, "target.com", memory_dir)
        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["next_tool_hint"] == "collect_browser_mcp_evidence"
        assert state["browser_required"] is True
        assert [item["tool"] for item in state["enrichment_hints"]] == [
            "collect_browser_mcp_evidence",
            "run_source_intel",
            "run_js_read",
        ]

    def test_format_autopilot_state_shows_enrichment_hints(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js", "graphql"],
            "next_action": "hunt_p1",
            "next_tool_hint": "collect_browser_mcp_evidence",
            "enrichment_hints": [
                {
                    "tool": "collect_browser_mcp_evidence",
                    "reason": "app-like or GraphQL surface signals were detected; use Chrome DevTools or Playwright MCP, then import the observed artifacts",
                },
                {
                    "tool": "run_js_read",
                    "reason": "cached JS artifacts exist, but js_intel materials have not been prepared yet",
                },
            ],
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": [],
            "recommended_targets": [],
        })

        assert "Next tool hint: collect_browser_mcp_evidence" in output
        assert "Enrichment hints:" in output
        assert "- collect_browser_mcp_evidence: app-like or GraphQL surface signals were detected" in output
        assert "- run_js_read: cached JS artifacts exist" in output

    def test_format_autopilot_state_shows_workflow_leads(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js", "graphql"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {
                "stats": {"p1": 1, "p2": 0},
                "workflow_leads": [
                    json.dumps(
                        {
                            "source": "js_intel",
                            "title": "Admin export IDOR",
                            "category": "idor",
                            "priority": "high",
                            "next_action": "swap order_id under a lower-privileged session",
                        }
                    )
                ],
            },
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": [],
            "recommended_targets": [],
        })

        assert "Workflow leads:" in output
        assert "[high] idor: Admin export IDOR" in output
        assert "Next: swap order_id under a lower-privileged session" in output

    def test_legacy_untested_inventory_does_not_reactivate_autopilot(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=2,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=[],
            vuln_classes_tried=["recon"],
            findings_count=0,
            session_id="sess-resume",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["next_action"] != "resume_untested"
        assert state["resume_targets"] == []
        assert state["resume_summary"]["untested_endpoints"] == [
            "/graphql",
            "/api/v2/report?id=123",
        ]

    def test_formats_state(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js", "graphql"],
            "next_action": "hunt_p1",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql", "/api/users"],
                "latest_session_summary": {
                    "findings_count": 1,
                    "vuln_classes": ["recon", "idor"],
                    "endpoints_preview": ["/graphql"],
                },
            },
            "surface": {"stats": {"p1": 2, "p2": 1}},
            "guard_status": {"tracked_hosts": 1, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql"],
            "recommended_targets": [
                {
                    "url": "https://api.target.com/graphql",
                    "suggested": "field-level auth checks",
                    "score": 14,
                    "tripped": False,
                    "remaining_seconds": 0.0,
                }
            ],
        })
        assert "AUTOPILOT STATE: target.com" in output
        assert "Next action: hunt_p1" in output
        assert "Next step: review the top surface candidate, then choose the next evidence step: https://api.target.com/graphql." in output
        assert "https://api.target.com/graphql" in output
        assert "Last session: 1 finding(s), tried recon, idor" in output
        assert "Last endpoints: /graphql" in output
        assert "Resume targets: /graphql" in output

    def test_formats_continue_last_focus_with_human_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["graphql"],
            "next_action": "continue_last_focus",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql"],
                "latest_session_summary": {
                    "findings_count": 1,
                    "vuln_classes": ["recon", "idor"],
                    "endpoints_preview": ["/graphql"],
                },
            },
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql"],
            "recommended_targets": [],
        })

        assert "Next action: continue_last_focus" in output
        assert "Next step: continue testing the last focus first: /graphql." in output

    def test_formats_resume_untested_with_human_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["graphql"],
            "next_action": "resume_untested",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql", "/api/v2/report?id=123"],
                "latest_session_summary": {
                    "findings_count": 0,
                    "vuln_classes": ["recon"],
                    "endpoints_preview": [],
                },
            },
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql", "/api/v2/report?id=123"],
            "recommended_targets": [],
        })

        assert "Next action: resume_untested" in output
        assert "Next step: resume the cached untested surface first: /graphql, /api/v2/report?id=123." in output

    def test_includes_guard_state_and_marks_tripped_hosts(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "\n".join([
                "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]",
                "https://files.target.com [200] [Files] [nginx] [1000]",
            ]) + "\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://files.target.com/download?id=1\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/download?id=1"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=2,
        ))
        now_ts = time.time()
        record_request(
            memory_dir=memory_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=now_ts,
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["guard_status"]["tracked_hosts"] == 1
        assert len(state["guard_status"]["tripped_hosts"]) == 1
        assert state["guard_status"]["tripped_hosts"][0]["host"] == "api.target.com"
        assert "cooling hosts" in state["guard_hint"]
        assert state["recommended_targets"][0]["host"] == "files.target.com"
        assert state["recommended_targets"][0]["tripped"] is False
        assert any(item["tripped"] for item in state["recommended_targets"])
        output = format_autopilot_state(state)
        assert "Guard hint:" in output
        assert "files.target.com" in output

    def test_build_autopilot_state_includes_recent_guard_advisories(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql"],
            tested_endpoints=[],
            untested_endpoints=["/graphql"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=1,
        ))
        HuntJournal(memory_dir / "journal.jsonl").append(make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="guard_advisory",
            endpoint="https://api.target.com/graphql",
            result="informational",
            severity="none",
            technique="request_guard",
            notes=(
                "request_guard advisory for GET https://api.target.com/graphql. "
                "Host: api.target.com. Action: breaker_advisory. "
                "Reason: circuit breaker active."
            ),
            tags=["guard_advisory", "auto_logged", "breaker_advisory"],
        ))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert len(state["recent_guard_advisories"]) == 1
        assert state["recent_guard_advisories"][0]["endpoint"] == "https://api.target.com/graphql"
        assert "breaker_advisory" in state["recent_guard_advisories"][0]["notes"]
        assert state["pivot_hint"] == ""

    def test_includes_repo_source_hint_when_artifacts_exist(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok"}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 1\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["repo_source_available"] is True
        assert state["repo_source_artifacts"] == ["repo_source_meta.json", "repo_summary.md"]
        assert "Repo source: available" in output
        assert "read_repo_source_summary" in output

    def test_build_autopilot_state_includes_repo_source_summary(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 1\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["repo_source_summary"]["source_kind"] == "local_path"
        assert state["repo_source_summary"]["secret_findings"] == 2
        assert state["repo_source_summary"]["ci_findings"] == 1
        assert state["repo_source_summary"]["summary_hint"] == "local_path, secrets=2, ci=1"

    def test_build_autopilot_state_includes_runtime_state_and_recon_cache_summary(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "exposure" / "api_leaks").mkdir(parents=True)
        (recon_dir / "exposure" / "identity_intel").mkdir(parents=True)
        (recon_dir / "exposure" / "cloud").mkdir(parents=True)
        (recon_dir / "api_specs").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "exposure" / "api_doc_candidates.txt").write_text(
            "[urls] https://api.target.com/openapi.json\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leak_candidates.txt").write_text(
            "https://www.postman.com/target/workspace/collection\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leak_trufflehog_verified.jsonl").write_text(
            '{"Verified":true}\n',
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leaks" / "swagger_leaks.txt").write_text(
            "https://api.target.com/swagger.json\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leaks" / "postman_leaks.txt").write_text(
            "postman collection: target\n",
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "spec_urls.txt").write_text(
            "https://api.target.com/openapi.json\n",
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "operations.jsonl").write_text(
            '{"method":"GET","url":"https://api.target.com/users"}\n',
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "public_operations.txt").write_text(
            "GET\thttps://api.target.com/health\texplicit_public\n",
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "auth_boundary_candidates.jsonl").write_text(
            '{"method":"GET","url":"https://api.target.com/users"}\n',
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "platform_metadata.jsonl").write_text(
            '{"kind":"oauth_authorization_server"}\n',
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "cloud_storage_candidates.txt").write_text(
            "https://target.s3.amazonaws.com/private/\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "identity_intel" / "emails.txt").write_text(
            "admin@target.com\nops@target.com\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "identity_intel" / "leaksearch.txt").write_text(
            "target leak hit\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "cloud" / "cloud_enum.txt").write_text(
            "target-backup\n",
            encoding="utf-8",
        )
        update_runtime_state(repo_root, "target.com", mode="agent", last_executed_workflow="run_vuln_scan")

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["runtime_state"]["last_executed_workflow"] == "run_vuln_scan"
        assert state["runtime_state"]["mode"] == "agent"
        assert state["recon_artifacts"]["ready"] is True
        assert "Last Workflow: run_vuln_scan" in output
        assert "Recon cache: hosts=1, surface=1" in output
        assert state["recon_artifacts"]["exposure_ready"] is True
        assert state["recon_artifacts"]["counts"]["api_doc_candidates"] == 1
        assert state["recon_artifacts"]["counts"]["identity_emails"] == 2
        assert "Exposure signals:" in output
        assert "- API docs: 1" in output
        assert "- OpenAPI semantics: specs=1, operations=1, public_or_optional=1, auth_boundaries=1, platform_metadata=1" in output
        assert "- API leaks: candidates=1, swagger=1, postman=1, postleaks=0, verified_secrets=1" in output
        assert "- Identity/cloud intel: emails=2, LeakSearch=1, cloud_enum=1" in output
        assert "Next exposure review:" in output
        assert "recon/target.com/api_specs/summary.md" in output
        assert "recon/target.com/exposure/api_doc_candidates.txt" in output
        assert "recon/target.com/exposure/api_leak_trufflehog_verified.jsonl" in output
        assert "recon/target.com/exposure/identity_intel/summary.md" in output

    def test_format_autopilot_state_surfaces_incomplete_cached_recon(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": False,
            "has_memory": False,
            "next_action": "run_recon",
            "resume_summary": {},
            "runtime_state": {"last_executed_workflow": "run_recon", "mode": "recon_only"},
            "recon_artifacts": {
                "available": True,
                "missing": ["live/httpx_full.txt"],
                "warnings": [],
            },
            "repo_source_available": False,
            "structured_findings": {},
            "recent_guard_advisories": [],
        })

        assert "Last Workflow: run_recon" in output
        assert "Recon cache issue: live/httpx_full.txt" in output
        assert "rerun /recon target.com; cached recon is incomplete" in output

    def test_recon_running_runtime_state_waits_instead_of_restart_loop(self, tmp_path):
        repo_root = tmp_path
        update_runtime_state(
            repo_root,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon_started",
        )

        with runtime_phase_lock(repo_root, "target.com", "recon"):
            state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
            output = format_autopilot_state(state)

            assert state["has_recon"] is False
            assert state["recon_in_progress"] is True
            assert state["next_action"] == "wait_recon"
            assert state["hard_gate"]["action"] == "wait_recon"
            assert state["selection_mode"] == "hard_gate"
            assert state["priority_frontier"] == []
            assert "Recon: in progress" in output
            assert "wait/poll the existing /recon target.com run; do not launch another recon" in output

        # 宿主直接终止后台任务时 flock 会释放，但 session marker 仍可能很新。
        # 这时必须立即恢复 recon，而不是等待 marker 的两小时超时。
        orphaned = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        assert orphaned["recon_in_progress"] is False
        assert orphaned["next_action"] == "run_recon"

    def test_active_recon_lock_preempts_surface_when_partial_artifacts_are_ready(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [Home] [Apache] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://target.com/search?q=sample\n",
            encoding="utf-8",
        )
        update_runtime_state(
            repo_root,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon_started",
        )

        with runtime_phase_lock(repo_root, "target.com", "recon"):
            state = build_autopilot_state(
                str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory")
            )

        assert state["recon_artifacts"]["ready"] is True
        assert state["recon_in_progress"] is True
        assert state["next_action"] == "wait_recon"

    def test_recon_running_marker_preempts_validation_followup(self, tmp_path):
        findings_dir = tmp_path / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "idor_wait_recon",
                        "type": "idor",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": "https://target.com/api/orders/1",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                ],
            }),
            encoding="utf-8",
        )
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon_started",
        )

        with runtime_phase_lock(tmp_path, "target.com", "recon"):
            state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["structured_findings"]["next_validation"]["id"] == "idor_wait_recon"
        assert state["next_action"] == "wait_recon"

    def test_recon_running_marker_preempts_runner_and_durable_queue(self, tmp_path):
        validation_dir = tmp_path / "evidence" / "target.com" / "validation" / "runner-wait"
        validation_dir.mkdir(parents=True)
        (validation_dir / "summary.json").write_text(
            json.dumps({
                "lane": "authz_role_replay",
                "finding_id": "runner-wait",
                "url": "https://target.com/api/admin",
                "method": "GET",
                "result": "tested_finding",
                "candidate_ready": True,
                "evidence_rubric": {"status": "candidate-ready", "ready": True},
            }),
            encoding="utf-8",
        )
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "actions": [{
                    "id": "AQ-0001",
                    "status": "candidate",
                    "type": "candidate-evidence-gap",
                    "priority": 99,
                    "action": "review candidate evidence",
                    "command_hint": "/validate runner-wait",
                }],
            }),
            encoding="utf-8",
        )
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon_started",
        )

        with runtime_phase_lock(tmp_path, "target.com", "recon"):
            state = build_autopilot_state(
                str(tmp_path),
                "target.com",
                memory_dir=str(tmp_path / "hunt-memory"),
            )

        assert state["validation_runner_next"]["id"] == "runner-wait"
        assert state["action_queue_next"]["id"] == "AQ-0001"
        assert state["next_action"] == "wait_recon"

    def test_stale_recon_running_marker_allows_single_rerun(self, tmp_path):
        state_dir = tmp_path / "state" / "target.com"
        state_dir.mkdir(parents=True)
        (state_dir / "session.json").write_text(
            json.dumps({
                "schema_version": 2,
                "target": "target.com",
                "storage_key": "target.com",
                "mode": "recon_running",
                "last_executed_workflow": "run_recon_started",
                "updated_at": "2000-01-01T00:00:00Z",
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["recon_in_progress"] is False
        assert state["next_action"] == "run_recon"

    def test_completed_recon_workflow_overrides_stale_running_mode(self, tmp_path):
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon",
        )

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["recon_in_progress"] is False
        assert state["next_action"] != "wait_recon"

    def test_scan_running_runtime_state_waits_instead_of_restart_loop(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        update_runtime_state(
            repo_root,
            "target.com",
            mode="scan_running",
            last_executed_workflow="run_scan_started",
        )

        with runtime_phase_lock(repo_root, "target.com", "scan"):
            state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
            output = format_autopilot_state(state)

            assert state["has_recon"] is True
            assert state["scan_in_progress"] is True
            assert state["next_action"] == "wait_scan"
            assert "Scan: in progress" in output
            assert "do not launch another scan-only quick" in output

        orphaned = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        assert orphaned["scan_in_progress"] is False
        assert orphaned["next_action"] != "wait_scan"

    def test_scan_running_marker_preempts_validation_followup(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [HTML] [OK] [100]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://target.com/api/orders/1\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "idor_wait_scan",
                        "type": "idor",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": "https://target.com/api/orders/1",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                ],
            }),
            encoding="utf-8",
        )
        update_runtime_state(
            repo_root,
            "target.com",
            mode="scan_running",
            last_executed_workflow="run_scan_started",
        )

        with runtime_phase_lock(repo_root, "target.com", "scan"):
            state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["structured_findings"]["next_validation"]["id"] == "idor_wait_scan"
        assert state["scan_in_progress"] is True
        assert state["next_action"] == "wait_scan"

    def test_stale_scan_running_marker_allows_single_rerun(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        state_dir = repo_root / "state" / "target.com"
        state_dir.mkdir(parents=True)
        (state_dir / "session.json").write_text(
            json.dumps({
                "schema_version": 2,
                "target": "target.com",
                "storage_key": "target.com",
                "mode": "scan_running",
                "last_executed_workflow": "run_scan_started",
                "updated_at": "2000-01-01T00:00:00Z",
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["has_recon"] is True
        assert state["scan_in_progress"] is False
        assert state["next_action"] != "wait_scan"

    def test_completed_scan_workflow_overrides_stale_running_mode(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        update_runtime_state(
            repo_root,
            "target.com",
            mode="scan_running",
            last_executed_workflow="run_vuln_scan",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["has_recon"] is True
        assert state["scan_in_progress"] is False
        assert state["next_action"] != "wait_scan"

    def test_formats_recent_guard_advisories_section(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 1, "tripped_hosts": [], "settings": {}},
            "guard_hint": "prefer the ready host files.target.com via https://files.target.com/download?id=1",
            "repo_source_available": False,
            "resume_targets": [],
            "recommended_targets": [
                {
                    "url": "https://files.target.com/download?id=1",
                    "suggested": "idor checks",
                    "score": 9,
                    "tripped": False,
                    "remaining_seconds": 0.0,
                }
            ],
            "recent_guard_advisories": [
                {
                    "action": "hunt",
                    "endpoint": "https://api.target.com/graphql",
                    "notes": (
                        "request_guard advisory for GET https://api.target.com/graphql. "
                        "Host: api.target.com. Action: breaker_advisory. "
                        "Reason: circuit breaker active."
                    ),
                }
            ],
        })

        assert "Recent guard advisories:" in output
        assert "https://api.target.com/graphql" in output
        assert "breaker_advisory" in output

    def test_format_autopilot_state_shows_repo_source_summary(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "guard_hint": "",
            "repo_source_available": True,
            "repo_source_summary": {
                "summary_hint": "local_path, secrets=2, ci=1",
                "source_kind": "local_path",
                "secret_findings": 2,
                "ci_findings": 1,
            },
            "resume_targets": [],
            "recommended_targets": [],
            "recent_guard_advisories": [],
        })

        assert "Repo source: local_path, secrets=2, ci=1" in output

    def test_build_autopilot_state_includes_repo_first_pivot_hint_when_guard_advisories_and_repo_findings_exist(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
            "https://files.target.com [200] [Files] [nginx] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://files.target.com/download?id=1\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 0\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/download?id=1"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=1,
        ))
        now_ts = time.time()
        record_request(
            memory_dir=memory_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=now_ts,
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["pivot_hint"] == "live API has guard advisories; inspect repo source findings first."

    def test_build_autopilot_state_uses_cidr_storage_key_for_recon_findings_and_repo_source(self, tmp_path):
        repo_root = tmp_path
        stored_key = "1.2.3.0_24"
        recon_dir = repo_root / "recon" / stored_key
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://1.2.3.25 [200] [API] [nginx] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://1.2.3.25/api/v1/orders?id=42\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        findings_dir = repo_root / "findings" / stored_key
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "1.2.3.0/24",
                    "findings": [
                        {
                            "id": "idor_cidr",
                            "type": "idor",
                            "severity": "high",
                            "confidence": "confirmed",
                            "url": "https://1.2.3.25/api/v1/orders?id=42",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        exposure_dir = findings_dir / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 1\n- CI findings: 0\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "1.2.3.0/24",
            tech_stack=["nginx"],
            tested_endpoints=[],
            untested_endpoints=["/api/v1/orders?id=42"],
            scope_snapshot={"in_scope": ["1.2.3.0/24"]},
            hunt_sessions=1,
        ))

        state = build_autopilot_state(str(repo_root), "1.2.3.0/24", memory_dir=str(memory_dir))

        assert state["has_recon"] is True
        assert state["structured_findings"]["total"] == 1
        assert state["structured_findings"]["next_validation"]["id"] == "idor_cidr"
        assert state["repo_source_available"] is True
        assert state["repo_source_summary"]["secret_findings"] == 1

    def test_format_autopilot_state_shows_pivot_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {
                "tracked_hosts": 1,
                "tripped_hosts": [{"host": "api.target.com", "remaining_seconds": 20.0}],
                "settings": {},
            },
            "guard_hint": (
                "cooling hosts: api.target.com (20.0s); prefer the ready host "
                "files.target.com via https://files.target.com/download?id=1"
            ),
            "repo_source_available": True,
            "repo_source_summary": {
                "summary_hint": "local_path, secrets=2, ci=0",
                "secret_findings": 2,
                "ci_findings": 0,
            },
            "resume_targets": [],
            "recommended_targets": [],
            "recent_guard_advisories": [],
            "pivot_hint": "live API has guard advisories; inspect repo source findings first.",
        })

        assert "Pivot hint: live API has guard advisories; inspect repo source findings first." in output
