"""Tests for lightweight runtime state + recon artifact inspection."""

import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import runtime_phase_exec

from tools.recon_adapter import ReconAdapter

from runtime_state import (
    DEPRECATED_FIELDS,
    PERSISTED_FIELDS,
    RuntimePhaseBusy,
    SCHEMA_VERSION,
    derive_state_view,
    inspect_recon_artifacts,
    inspect_recon_artifacts_fast,
    load_runtime_state,
    runtime_phase_in_progress,
    runtime_phase_is_active,
    runtime_phase_lock,
    runtime_recon_in_progress,
    runtime_scan_in_progress,
    runtime_wait_action,
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


def test_update_runtime_state_preserves_existing_file_when_atomic_replace_fails(tmp_path, monkeypatch):
    """写入失败时不能暴露半截 session.json，也不能破坏旧的可读状态。"""
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )
    state_file = tmp_path / "state" / "target.com" / "session.json"
    original_text = state_file.read_text(encoding="utf-8")
    original_replace = type(state_file).replace

    def fail_session_replace(self, target):
        if self.name.startswith(".session.json."):
            raise OSError("simulated replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(type(state_file), "replace", fail_session_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="scan_only",
            last_executed_workflow="run_vuln_scan",
        )

    assert state_file.read_text(encoding="utf-8") == original_text
    loaded = load_runtime_state(tmp_path, "target.com")
    assert loaded["mode"] == "scan_running"
    assert loaded["last_executed_workflow"] == "run_scan_started"
    assert not list(state_file.parent.glob(".session.json.*.tmp"))


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


def test_runtime_phase_lock_blocks_same_target_phase_only(tmp_path):
    with runtime_phase_lock(tmp_path, "target.com", "recon") as lock_path:
        assert lock_path == tmp_path / "state" / "target.com" / "locks" / "recon.lock"
        with pytest.raises(RuntimePhaseBusy, match="recon is already running"):
            with runtime_phase_lock(tmp_path, "target.com", "recon"):
                pass

        with runtime_phase_lock(tmp_path, "target.com", "scan"):
            pass
        with runtime_phase_lock(tmp_path, "other.test", "recon"):
            pass

    with runtime_phase_lock(tmp_path, "target.com", "recon"):
        pass


def test_runtime_phase_lock_rejects_unknown_phase(tmp_path):
    with pytest.raises(ValueError, match="unsupported runtime phase"):
        with runtime_phase_lock(tmp_path, "target.com", "report"):
            pass


def test_direct_phase_runner_returns_busy_without_starting_child(tmp_path, monkeypatch):
    monkeypatch.setattr(
        runtime_phase_exec.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("child must not start")),
    )

    with runtime_phase_lock(tmp_path, "target.com", "recon"):
        assert runtime_phase_exec.run_phase_command(
            tmp_path,
            "target.com",
            "recon",
            ["ignored"],
        ) == 75


def test_direct_phase_runner_marks_child_lock_ownership(tmp_path, monkeypatch):
    captured = {}

    def fake_run(command, *, env, check):
        captured.update({"command": command, "env": env, "check": check})
        return SimpleNamespace(returncode=17)

    monkeypatch.setattr(runtime_phase_exec.subprocess, "run", fake_run)
    code = runtime_phase_exec.run_phase_command(
        tmp_path,
        "target.com",
        "scan",
        ["scanner", "--quick"],
    )

    assert code == 17
    assert captured["command"] == ["scanner", "--quick"]
    assert captured["env"]["BBHUNT_RUNTIME_PHASE_LOCKED"] == "scan"
    assert captured["env"]["BBHUNT_RUNTIME_LOCK_TARGET"] == "target.com"
    state = load_runtime_state(tmp_path, "target.com")
    assert state["mode"] == "scan_failed"
    assert state["last_executed_workflow"] == "run_vuln_scan_failed"


def test_runtime_phase_liveness_requires_running_marker_and_held_lock(tmp_path):
    """孤儿 marker 不能伪装成仍在运行的长 phase。"""
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )
    scan_state = load_runtime_state(tmp_path, "target.com")

    assert runtime_phase_is_active(tmp_path, "target.com", "scan") is False
    assert runtime_phase_in_progress(tmp_path, "target.com", "scan", scan_state) is False
    assert runtime_scan_in_progress(scan_state) is True

    with runtime_phase_lock(tmp_path, "target.com", "scan"):
        assert runtime_phase_is_active(tmp_path, "target.com", "scan") is True
        assert runtime_phase_in_progress(tmp_path, "target.com", "scan", scan_state) is True
        assert runtime_scan_in_progress(scan_state) is True
        stale_scan_state = {**scan_state, "updated_at": "2000-01-01T00:00:00Z"}
        assert runtime_phase_in_progress(tmp_path, "target.com", "scan", stale_scan_state) is True

    update_runtime_state(
        tmp_path,
        "target.com",
        mode="recon_running",
        last_executed_workflow="run_recon_started",
    )
    recon_state = load_runtime_state(tmp_path, "target.com")
    assert runtime_recon_in_progress(recon_state) is True
    assert runtime_phase_in_progress(tmp_path, "target.com", "recon", recon_state) is False
    with runtime_phase_lock(tmp_path, "target.com", "recon"):
        assert runtime_phase_in_progress(tmp_path, "target.com", "recon", recon_state) is True


def test_runtime_phase_liveness_recovers_after_terminated_owner_process(tmp_path):
    """模拟 Claude 杀掉后台 scanner 后，flock 释放应立即取消 wait_scan。"""
    repo_root = Path(__file__).resolve().parents[1]
    child_code = """
import sys
import time
from tools.runtime_state import runtime_phase_lock, update_runtime_state

runtime_root, target = sys.argv[1:]
with runtime_phase_lock(runtime_root, target, 'scan'):
    update_runtime_state(
        runtime_root,
        target,
        mode='scan_running',
        last_executed_workflow='run_scan_started',
    )
    time.sleep(60)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", child_code, str(tmp_path), "target.com"],
        cwd=repo_root,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = load_runtime_state(tmp_path, "target.com")
            if runtime_phase_in_progress(tmp_path, "target.com", "scan", state):
                break
            time.sleep(0.05)
        else:
            pytest.fail("child scanner owner never acquired the scan phase lock")

        assert runtime_wait_action(tmp_path, "target.com") == "wait_scan"
        process.terminate()
        process.wait(timeout=5)

        state = load_runtime_state(tmp_path, "target.com")
        assert state["last_executed_workflow"] == "run_scan_started"
        assert runtime_scan_in_progress(state) is True
        assert runtime_phase_in_progress(tmp_path, "target.com", "scan", state) is False
        assert runtime_wait_action(tmp_path, "target.com") == ""
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


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


def test_fast_recon_inspection_uses_stat_presence_without_line_counts(tmp_path, monkeypatch):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text("https://target.com\n")
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://target.com/search?q=1\n"
    )

    monkeypatch.setattr(
        "runtime_state._line_count",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("fast inspection must not count lines")
        ),
    )

    payload = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert payload["ready"] is True
    assert payload["surface_inputs_ready"] is True
    assert payload["counts_exact"] is False
    assert payload["counts"]["hosts"] is None
    assert payload["counts"]["param_urls"] is None


def test_inspect_recon_artifacts_counts_exposure_signals(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
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
    assert payload["counts"]["openapi_specs"] == 1
    assert payload["counts"]["openapi_operations"] == 1
    assert payload["counts"]["openapi_public_operations"] == 1
    assert payload["counts"]["openapi_auth_boundary_candidates"] == 1
    assert payload["counts"]["platform_metadata"] == 1
    assert payload["counts"]["cloud_storage_candidates"] == 1
    assert payload["counts"]["identity_emails"] == 2
    assert payload["counts"]["leaksearch_hits"] == 1
    assert payload["counts"]["cloud_enum_hits"] == 1
    assert payload["exposure_paths"]["api_doc_candidates"] == "exposure/api_doc_candidates.txt"
    assert payload["exposure_paths"]["verified_secrets"] == "exposure/api_leak_trufflehog_verified.jsonl"
    assert payload["exposure_paths"]["openapi_operations"] == "api_specs/operations.jsonl"


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


def test_inspect_recon_artifacts_accepts_compact_ffuf_surface(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "dirs").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://target.com [200] [Site]\n",
        encoding="utf-8",
    )
    (recon_dir / "dirs" / "ffuf_results.jsonl").write_text(
        json.dumps({
            "url": "https://target.com/admin",
            "status": 403,
            "length": 123,
            "words": 10,
            "lines": 2,
            "content-type": "text/html",
            "input": {"FUZZ": "admin"},
        }) + "\n",
        encoding="utf-8",
    )
    ReconAdapter(recon_dir).summarize_ffuf_results()

    payload = inspect_recon_artifacts(tmp_path, "target.com")

    assert payload["counts"]["ffuf_observations"] == 1
    assert payload["surface_inputs_ready"] is True
    assert payload["ffuf_needs_summary"] is False


def test_inspect_recon_artifacts_reports_legacy_ffuf_without_parsing_it(tmp_path):
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "dirs").mkdir(parents=True)
    (recon_dir / "dirs" / "ffuf_target.com.json").write_text(
        "{this intentionally does not parse",
        encoding="utf-8",
    )

    payload = inspect_recon_artifacts(tmp_path, "target.com")

    assert payload["counts"]["ffuf_observations"] == 0
    assert payload["counts"]["ffuf_legacy_raw_files"] == 1
    assert payload["ffuf_needs_summary"] is True
    assert payload["warnings"] == ["FFUF artifacts found but compact summary is missing or stale"]
