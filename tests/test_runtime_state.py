"""Tests for lightweight runtime state + recon artifact inspection."""

import json

from runtime_state import (
    DEPRECATED_FIELDS,
    PERSISTED_FIELDS,
    SCHEMA_VERSION,
    derive_state_view,
    inspect_recon_artifacts,
    load_runtime_state,
    update_runtime_state,
)


def test_update_and_load_runtime_state(tmp_path):
    """Schema v2: only whitelisted fields persist; legacy kwargs are dropped/renamed."""
    payload = update_runtime_state(
        tmp_path,
        "target.com",
        mode="agent",
        # legacy kwargs — auto-renamed
        last_completed_step="run_vuln_scan",
        # deprecated kwargs — silently dropped
        current_stage="scan",
        pending_validation=2,
        recon_completed=True,
        # whitelisted field
        enrichment_tools=["browser", "js-reader"],
    )

    loaded = load_runtime_state(tmp_path, "target.com")

    assert payload["target"] == "target.com"
    assert payload["schema_version"] == SCHEMA_VERSION
    # legacy `last_completed_step` was renamed to last_executed_workflow
    assert loaded["last_executed_workflow"] == "run_vuln_scan"
    assert loaded["mode"] == "agent"
    assert loaded["enrichment_tools"] == ["browser", "js-reader"]
    # deprecated fields must NOT survive write
    for field in ("current_stage", "pending_validation", "recon_completed"):
        assert field not in loaded, f"deprecated field leaked into v2 file: {field}"
    assert loaded["updated_at"]


def test_persisted_fields_whitelist_is_explicit():
    """The persisted field set is intentionally small to avoid stage-locking."""
    assert PERSISTED_FIELDS == frozenset({
        "mode",
        "last_executed_workflow",
        "enrichment_tools",
        "ctf_mode",
        "last_validation_result",
        "last_validated_finding_id",
    })


def test_load_v1_schema_maps_legacy_field(tmp_path):
    """v1 schema files are migrated transparently on read."""
    state_dir = tmp_path / "state" / "target.com"
    state_dir.mkdir(parents=True)
    (state_dir / "session.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "storage_key": "target.com",
                "mode": "hunt",
                "last_completed_step": "run_recon",
                "current_stage": "recon",
                "recon_completed": True,
                "surface_ready": False,
                "enrichment_tools": ["browser"],
                "ctf_mode": True,
            }
        ),
        encoding="utf-8",
    )

    loaded = load_runtime_state(tmp_path, "target.com")

    assert loaded["schema_version"] == SCHEMA_VERSION
    assert loaded["last_executed_workflow"] == "run_recon"
    assert "last_completed_step" not in loaded
    for field in DEPRECATED_FIELDS:
        assert field not in loaded, f"deprecated field {field} survived v1 migration"
    # whitelisted fields preserved
    assert loaded["mode"] == "hunt"
    assert loaded["enrichment_tools"] == ["browser"]
    assert loaded["ctf_mode"] is True


def test_write_v2_excludes_deprecated_fields(tmp_path):
    """Even legacy-style callers cannot leak deprecated fields into the v2 file."""
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="agent",
        recon_completed=True,
        surface_ready=True,
        scan_completed=False,
        pending_validation=5,
        validated_pending_report=2,
        reports_generated=1,
        cve_hunt=True,
        zero_day=False,
        browser_evidence_ready=True,
    )

    on_disk = json.loads(
        (tmp_path / "state" / "target.com" / "session.json").read_text()
    )
    for field in DEPRECATED_FIELDS:
        assert field not in on_disk, f"deprecated field {field} persisted"
    assert on_disk["schema_version"] == SCHEMA_VERSION


def test_derive_state_view_returns_all_layers(tmp_path):
    """derive_state_view exposes persisted + recon + findings + evidence layers."""
    update_runtime_state(tmp_path, "target.com", mode="agent",
                        last_executed_workflow="run_recon")
    view = derive_state_view(tmp_path, "target.com")
    assert set(view.keys()) == {"persisted", "recon", "findings", "evidence"}
    assert view["persisted"]["mode"] == "agent"
    # recon dir doesn't exist → unavailable
    assert view["recon"]["available"] is False
    # finding counts default to 0
    assert view["findings"]["structured_total"] == 0
    assert view["evidence"]["browser_evidence_present"] is False


def test_inspect_recon_artifacts_reports_ready_cache(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    findings_dir = tmp_path / "findings" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    findings_dir.mkdir(parents=True)

    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\n",
        encoding="utf-8",
    )

    payload = inspect_recon_artifacts(tmp_path, "target.com")

    assert payload["available"] is True
    assert payload["ready"] is True
    assert payload["host_inventory_ready"] is True
    assert payload["surface_inputs_ready"] is True
    assert payload["counts"]["hosts"] == 1
    assert payload["counts"]["api_urls"] == 1


def test_inspect_recon_artifacts_counts_exposure_signals(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "exposure" / "api_leaks").mkdir(parents=True)
    (recon_dir / "exposure" / "identity_intel").mkdir(parents=True)
    (recon_dir / "exposure" / "cloud").mkdir(parents=True)

    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\n",
        encoding="utf-8",
    )
    (recon_dir / "exposure" / "api_doc_candidates.txt").write_text(
        "[urls] https://api.target.com/swagger.json\n"
        "[urls] https://api.target.com/openapi.json\n",
        encoding="utf-8",
    )
    (recon_dir / "exposure" / "api_leak_candidates.txt").write_text(
        "https://www.postman.com/target/workspace/collection\n",
        encoding="utf-8",
    )
    (recon_dir / "exposure" / "api_leak_trufflehog_verified.jsonl").write_text(
        '{"SourceName":"api_leaks","Verified":true}\n',
        encoding="utf-8",
    )
    (recon_dir / "exposure" / "api_leaks" / "swagger_leaks.txt").write_text(
        "https://api.target.com/admin/openapi.yaml\n",
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
        "target.com: hit\n",
        encoding="utf-8",
    )
    (recon_dir / "exposure" / "cloud" / "cloud_enum.txt").write_text(
        "target-backup\n",
        encoding="utf-8",
    )

    payload = inspect_recon_artifacts(tmp_path, "target.com")

    assert payload["exposure_ready"] is True
    assert payload["counts"]["api_doc_candidates"] == 2
    assert payload["counts"]["api_leak_candidates"] == 1
    assert payload["counts"]["verified_secrets"] == 1
    assert payload["counts"]["swagger_leaks"] == 1
    assert payload["counts"]["cloud_storage_candidates"] == 1
    assert payload["counts"]["identity_emails"] == 2
    assert payload["counts"]["leaksearch_hits"] == 1
    assert payload["counts"]["cloud_enum_hits"] == 1
    assert payload["exposure_paths"]["api_doc_candidates"] == "exposure/api_doc_candidates.txt"
    assert payload["exposure_paths"]["verified_secrets"] == "exposure/api_leak_trufflehog_verified.jsonl"


def test_inspect_recon_artifacts_warns_on_surface_gaps(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js] [1000]\n",
        encoding="utf-8",
    )

    payload = inspect_recon_artifacts(tmp_path, "target.com")

    assert payload["available"] is True
    assert payload["ready"] is True
    assert payload["surface_inputs_ready"] is False
    assert payload["warnings"] == ["no URL, JS, browser, or structured finding surface artifacts found yet"]
