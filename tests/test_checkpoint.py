"""Tests for tools/checkpoint.py."""

from __future__ import annotations

import json
from pathlib import Path

from checkpoint import apply_target_memory, build_checkpoint, format_checkpoint
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
    assert checkpoint["recommended_executable_action"]["type"] == "validation"
    assert checkpoint["recommended_executable_action"]["command_hint"] == "/validate"


def test_checkpoint_surfaces_high_value_coverage_gaps(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/v1/admin/users",
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
