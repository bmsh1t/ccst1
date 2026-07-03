"""Tests for tools/checkpoint.py."""

from __future__ import annotations

import json
from pathlib import Path

from checkpoint import _build_next_action_queue, _next_proposals, apply_target_memory, build_checkpoint, format_checkpoint
from evidence_ledger import record_entry


def _seed_recon(repo_root: Path, target: str, urls: list[str]) -> None:
    recon_dir = repo_root / "recon" / target
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [FastAPI,React] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "\n".join(urls) + "\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
    (recon_dir / "urls" / "all.txt").write_text(
        "\n".join(urls) + "\n",
        encoding="utf-8",
    )
    (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")


def test_checkpoint_without_recon_recommends_refresh_recon(tmp_path):
    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert checkpoint["decision"] == "refresh-recon"
    assert checkpoint["target"] == "target.com"
    assert any("/recon target.com" in item for item in checkpoint["target_write_back"]["next"])
    assert checkpoint["recommended_executable_action"]["type"] == "recon"
    assert (
        checkpoint["recommended_executable_action"]["command_hint"]
        == 'python3 tools/hunt.py --target "target.com" --recon-only && '
        'python3 tools/surface.py --target "target.com" && '
        'python3 tools/checkpoint.py --target "target.com"'
    )
    assert "CHECKPOINT DECISION" in output
    assert "Apply status: not applied" in output


def test_checkpoint_prioritizes_pending_validation(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "F-1",
                    "type": "idor",
                    "severity": "high",
                    "confidence": "confirmed",
                    "url": "https://api.target.com/api/org/123/users",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                }
            ]
        }),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "validate"
    assert checkpoint["structured_findings"]["pending_validation"] == 1
    assert any("F-1" in item for item in checkpoint["target_write_back"]["next"])
    assert checkpoint["recommended_executable_action"]["type"] == "candidate-evidence-gap"
    assert checkpoint["recommended_executable_action"]["command_hint"] == "fill missing rubric evidence, then /validate"
    assert any(
        item["type"] == "validation"
        for item in checkpoint["next_action_queue"]
    )


def test_checkpoint_queues_candidate_evidence_gap_before_validate(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "findings": [
                {
                    "id": "SQLI-1",
                    "type": "sqli",
                    "severity": "high",
                    "confidence": "medium",
                    "url": "https://api.target.com/search?q=1",
                    "summary": "possible SQL injection",
                    "validation_status": "unvalidated",
                    "report_status": "not_generated",
                }
            ]
        }),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Candidate evidence gap for finding SQLI-1" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert checkpoint["recommended_executable_action"]["type"] == "candidate-evidence-gap"


def test_checkpoint_queues_secret_verification_lane_from_repo_source_summary(tmp_path):
    exposure_dir = tmp_path / "findings" / "target.com" / "exposure"
    exposure_dir.mkdir(parents=True)
    (exposure_dir / "repo_source_meta.json").write_text(
        json.dumps({"status": "ok", "source_kind": "local", "clone_performed": False}),
        encoding="utf-8",
    )
    (exposure_dir / "repo_summary.md").write_text(
        "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 0\n",
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Secret verification lane" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert any(
        item["type"] == "secret-verification"
        for item in checkpoint["next_action_queue"]
    )


def test_checkpoint_queues_unsafe_skipped_review_from_manual_review_artifact(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/profile"])
    manual_dir = tmp_path / "findings" / "target.com" / "manual_review"
    manual_dir.mkdir(parents=True)
    (manual_dir / "unsafe_skipped.txt").write_text(
        "2026-06-07T00:00:00Z\tmethod=PUT\tlabel=HTTP method tampering probes\turl=https://api.target.com/profile\treason=requires opt-in\n",
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Review action-gated scanner lane" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    review_action = next(item for item in checkpoint["next_action_queue"] if item["type"] == "action-gated-review")
    assert review_action["redline_required"] is True
    assert review_action["metadata"]["unsafe_skipped_id"]
    assert review_action["metadata"]["artifact"] == "findings/target.com/manual_review/unsafe_skipped.txt"


def test_checkpoint_surfaces_high_value_coverage_gaps(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/v1/admin/users?isAdmin=true&userId=1001",
    ])

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert checkpoint["decision"] == "continue"
    assert checkpoint["coverage"]["summary"]["high_value_gaps_count"] > 0
    assert any(
        "Cover high-value matrix gap" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert checkpoint["next_action_queue"]
    assert any(item["type"] == "coverage-gap" for item in checkpoint["next_action_queue"])
    assert checkpoint["recommended_executable_action"]["status"] == "ready"
    assert checkpoint["coverage"]["high_value_gaps"][0]["vuln_class"] == "Authz"
    coverage_action = next(item for item in checkpoint["next_action_queue"] if item["type"] == "coverage-gap")
    assert coverage_action["metadata"]["endpoint"] == "/api/v1/admin/users"
    assert coverage_action["metadata"]["vuln_class"] == "Authz"
    assert coverage_action["metadata"]["relevance_score"] > 0
    assert "Validation path:" in coverage_action["action"]
    assert coverage_action["metadata"]["validation_path"]
    assert "Capture the exact method, URL, headers, body" in coverage_action["metadata"]["validation_path"]
    assert (tmp_path / "evidence" / "target.com" / "coverage_matrix.json").is_file()


def test_checkpoint_surfaces_actor_matrix_gaps(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/accounts/42/export?account_id=42",
    ])
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42/export",
        vuln_class="IDOR",
        actor="owner",
        object_scope="own",
        variant="baseline",
        result="tested_clean",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert checkpoint["evidence_ledger"]["entry_count"] == 1
    assert checkpoint["evidence_ledger"]["actor_matrix"]["gap_count"] > 0
    assert any(
        "Cover actor matrix gap" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert any(item["type"] == "actor-gap" for item in checkpoint["next_action_queue"])
    assert "Evidence ledger:" in output
    assert "actor matrix gaps:" in output
    assert "Next action queue:" in output
    assert "Recommended executable action:" in output


def test_checkpoint_queues_cross_evidence_convergence(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/admin/export?order_id=42",
    ])
    recon_dir = tmp_path / "recon" / "target.com"
    browser_dir = recon_dir / "browser"
    js_intel_dir = tmp_path / "findings" / "target.com" / "js_intel"
    source_intel_dir = tmp_path / "findings" / "target.com" / "source_intel"
    browser_dir.mkdir(parents=True)
    js_intel_dir.mkdir(parents=True)
    source_intel_dir.mkdir(parents=True)

    converged_url = "https://api.target.com/api/admin/export?order_id=42"
    (browser_dir / "xhr_endpoints.txt").write_text(converged_url + "\n", encoding="utf-8")
    (browser_dir / "api_endpoints.txt").write_text(converged_url + "\n", encoding="utf-8")
    (js_intel_dir / "hypotheses.json").write_text(
        json.dumps({
            "endpoints": [
                {"method": "POST", "path": "/api/admin/export?order_id=42", "auth_required": "true"}
            ],
            "attack_surface_leads": [],
            "graphql_operations": [],
        }),
        encoding="utf-8",
    )
    (source_intel_dir / "routes.json").write_text(
        json.dumps({"routes": [{"route": "/api/admin/export?order_id=42", "method": "POST"}]}),
        encoding="utf-8",
    )
    (source_intel_dir / "hypotheses.jsonl").write_text(
        json.dumps({
            "type": "idor",
            "candidate": "/api/admin/export?order_id=42",
            "reason": "admin export route uses order_id",
            "source": "routes/export.py",
        }) + "\n",
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")

    assert any(
        "Cross-evidence high-value surface" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    assert any(item["type"] == "evidence-convergence" for item in checkpoint["next_action_queue"])
    assert any(
        item["command_hint"] == "focused replay with browser/JS/source evidence"
        for item in checkpoint["next_action_queue"]
    )


def test_next_proposals_skip_ranked_surface_when_endpoint_already_has_tested_finding():
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": "https://api.target.com/api/admin/users?isAdmin=true",
                    "suggested": "prioritize authz checks",
                }
            ],
            "surface": {},
        },
        coverage_gaps=[],
        matrix={
            "endpoints": [
                {
                    "endpoint": "/api/admin/users",
                    "cells": {"Authz": {"status": "tested_finding"}},
                }
            ]
        },
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
    )

    assert not any(
        "Continue top ranked surface https://api.target.com/api/admin/users" in item
        for item in proposals
    )


def test_ranked_surface_proposal_includes_replay_draft_and_metadata():
    url = "https://app.target.com/api/admin/export?order_id=42"
    proposals = _next_proposals(
        state={
            "has_recon": True,
            "recommended_targets": [
                {
                    "url": url,
                    "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                }
            ],
            "surface": {
                "p1": [
                    {
                        "url": url,
                        "browser_observed": True,
                        "js_intel_endpoints": [{"method": "POST", "auth_required": "true"}],
                        "source_intel_hypotheses": [{"type": "idor", "reason": "admin export route uses order_id"}],
                        "suggested": "prioritize authenticated/browser-observed authz and workflow checks",
                    }
                ],
                "workflow_leads": [],
            },
        },
        coverage_gaps=[],
        matrix={"endpoints": []},
        target="target.com",
        context_pack={"contradictions": []},
        evidence_summary={},
    )

    ranked_text = next(item for item in proposals if item.startswith("Continue top ranked surface "))
    assert "Replay draft:" in ranked_text
    assert "Ledger skeleton:" in ranked_text
    assert "browser-observed request/response baseline first" in ranked_text
    assert "prefer POST replay" in ranked_text

    queue = _build_next_action_queue([ranked_text], "target.com")
    ranked_action = queue[0]
    assert ranked_action["type"] == "ranked-surface"
    assert ranked_action["metadata"]["url"] == url
    assert ranked_action["metadata"]["endpoint"] == "/api/admin/export"
    assert "browser-observed request/response baseline first" in ranked_action["metadata"]["replay_draft"]
    assert "Ledger skeleton:" not in ranked_action["metadata"]["replay_draft"]
    skeleton = ranked_action["metadata"]["ledger_record_skeleton"]
    assert "python3 tools/evidence_ledger.py record" in skeleton
    assert "--endpoint \"/api/admin/export\"" in skeleton
    assert "--method \"POST\"" in skeleton
    assert "--vuln-class \"IDOR\"" in skeleton
    assert "--browser-observed" in skeleton
    assert "--state-changing" not in skeleton
    assert "--redline-checked" not in skeleton


def test_checkpoint_surfaces_context_contradictions(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/graphql",
    ])
    target_dir = tmp_path / "memory" / "goals" / "targets"
    target_dir.mkdir(parents=True)
    (target_dir / "target.com.json").write_text(
        json.dumps({
            "target": "target.com",
            "dead_ends": [
                {"text": "GraphQL introspection disabled; no operation names in JS"}
            ],
        }),
        encoding="utf-8",
    )

    checkpoint = build_checkpoint(tmp_path, target="target.com")
    output = format_checkpoint(checkpoint)

    assert any(
        "Remembered dead end may have new evidence" in item
        for item in checkpoint["context_pack"]["contradictions"]
    )
    assert any(
        "Review context contradiction" in item
        for item in checkpoint["target_write_back"]["next"]
    )
    context_action = next(item for item in checkpoint["next_action_queue"] if item["type"] == "context-review")
    assert context_action["command_hint"] == 'python3 tools/context_pack.py --target "target.com"'
    assert "Contradictions:" in output


def test_apply_target_memory_appends_checkpoint_entries(tmp_path):
    checkpoint = build_checkpoint(tmp_path, target="target.com", note="end of authz pass")

    result = apply_target_memory(tmp_path, "target.com", checkpoint)
    memory_path = tmp_path / result["target_memory_path"]
    payload = json.loads(memory_path.read_text(encoding="utf-8"))

    assert result["added"]["next"] >= 1
    assert result["added"]["handoff"] == 1
    assert payload["target"] == "target.com"
    assert payload["next_actions"]
    assert payload["session_handoffs"]
    assert (tmp_path / result["session_path"]).is_file()


def test_apply_target_memory_is_deduped(tmp_path):
    checkpoint = build_checkpoint(tmp_path, target="target.com")

    first = apply_target_memory(tmp_path, "target.com", checkpoint)
    second = apply_target_memory(tmp_path, "target.com", checkpoint)

    assert first["added"]["next"] >= 1
    assert second["added"]["next"] == 0
    assert second["added"]["handoff"] == 0
