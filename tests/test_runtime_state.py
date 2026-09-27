"""Tests for lightweight runtime state + recon artifact inspection."""

import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import hunt
import pytest
import resume as resume_module
import runtime_state as runtime_state_module
import runtime_phase_exec

from tools.recon_adapter import ReconAdapter

from runtime_state import (
    DEPRECATED_FIELDS,
    PERSISTED_FIELDS,
    RuntimePhaseBusy,
    SCHEMA_VERSION,
    derive_state_view,
    derive_owner_projection,
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
from tools.target_store import TargetStore


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


@pytest.mark.parametrize("write_fails", [False, True])
def test_hunt_breadcrumb_write_does_not_query_derived_state(tmp_path, monkeypatch, write_fails):
    before = update_runtime_state(
        tmp_path, "target.com", mode="scan_running",
        last_executed_workflow="run_scan_started",
        last_validation_result="validated", last_validated_finding_id="finding-1",
    )
    state_file = tmp_path / "state" / "target.com" / "session.json"
    original_bytes = state_file.read_bytes()
    recon = Mock(side_effect=OSError("recon unavailable"))
    findings = Mock(side_effect=ValueError("findings unavailable"))
    log = Mock()
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "log", log)
    monkeypatch.setattr(runtime_state_module, "inspect_recon_artifacts", recon)
    monkeypatch.setattr(resume_module, "load_structured_finding_followup", findings)
    if write_fails:
        monkeypatch.setattr(Path, "replace", Mock(side_effect=OSError("replace failed")))

    hunt._persist_runtime_state(
        "target.com", mode="scan_only", last_executed_workflow="run_vuln_scan",
        ctf_mode=True, enrichment_tools=("run_js_read",),
    )

    recon.assert_not_called()
    findings.assert_not_called()
    if write_fails:
        assert state_file.read_bytes() == original_bytes
        assert not list(state_file.parent.glob(".session.json.*.tmp"))
        log.assert_called_once_with("warn", "Runtime state update failed (non-fatal): replace failed")
    else:
        saved = json.loads(state_file.read_text(encoding="utf-8"))
        assert saved == {
            **before, "mode": "scan_only", "last_executed_workflow": "run_vuln_scan",
            "ctf_mode": True, "enrichment_tools": ["run_js_read"],
            "updated_at": saved["updated_at"],
        }
        log.assert_not_called()


@pytest.mark.parametrize("phase", ["recon", "scan"])
@pytest.mark.parametrize("outcome", [True, False, "interrupt", "busy"])
def test_hunt_phase_breadcrumbs_survive_exit(tmp_path, monkeypatch, phase, outcome):
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)
    before = update_runtime_state(tmp_path, "target.com", mode="previous")

    def run_phase(*args, **kwargs):
        state = load_runtime_state(tmp_path, "target.com")
        assert state["mode"] == f"{phase}_running"
        assert runtime_phase_in_progress(tmp_path, "target.com", phase, state)
        if outcome == "interrupt":
            raise KeyboardInterrupt
        return outcome

    runner = Mock(side_effect=run_phase)
    monkeypatch.setattr(hunt, "run_recon" if phase == "recon" else "run_vuln_scan", runner)
    options = {f"{phase}_only": True}
    if outcome == "busy":
        with hunt.runtime_phase_lock(tmp_path, "target.com", phase):
            with pytest.raises(hunt.RuntimePhaseBusy):
                hunt._hunt_target_impl("target.com", **options)
        runner.assert_not_called()
        assert load_runtime_state(tmp_path, "target.com") == before
    else:
        if outcome == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                hunt._hunt_target_impl("target.com", **options)
        else:
            result = hunt._hunt_target_impl("target.com", **options)
            assert result[phase] is outcome
        state = load_runtime_state(tmp_path, "target.com")
        scan_failed = phase == "scan" and outcome is not True
        assert state["mode"] == ("scan_failed" if scan_failed else f"{phase}_only")
        assert state["last_executed_workflow"] == (
            "run_recon" if phase == "recon" else
            "run_vuln_scan_failed" if scan_failed else "run_vuln_scan"
        )
        assert state["ctf_mode"] is False
        assert state["enrichment_tools"] == []
    assert runtime_wait_action(tmp_path, "target.com") == ""


def test_hunt_batch_completion_persists_breadcrumb_without_a_store(tmp_path, monkeypatch):
    target_list = tmp_path / "targets.txt"
    target_list.write_text("target.com\n", encoding="utf-8")
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)

    result = hunt._batch_recon_result(str(target_list), True, time.monotonic())

    state = load_runtime_state(tmp_path, str(target_list))
    assert result["batch"] is True
    assert state["mode"] == "batch_recon"
    assert state["last_executed_workflow"] == "run_recon_batch"


def test_corrupt_runtime_state_is_not_treated_as_empty_or_overwritten(tmp_path):
    state_file = tmp_path / "state" / "target.com" / "session.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid runtime state JSON"):
        load_runtime_state(tmp_path, "target.com")
    with pytest.raises(ValueError, match="invalid runtime state JSON"):
        update_runtime_state(tmp_path, "target.com", mode="agent")

    assert state_file.read_text(encoding="utf-8") == "{broken"


def test_concurrent_runtime_updates_preserve_disjoint_fields(tmp_path, monkeypatch):
    original_load = runtime_state_module.load_runtime_state
    first_read = threading.Event()
    release_first = threading.Event()
    second_read = threading.Event()
    read_count = 0
    read_count_lock = threading.Lock()

    def coordinated_load(repo_root, target):
        nonlocal read_count
        payload = original_load(repo_root, target)
        with read_count_lock:
            read_count += 1
            current_read = read_count
        if current_read == 1:
            first_read.set()
            assert release_first.wait(timeout=5)
        elif current_read == 2:
            second_read.set()
        return payload

    monkeypatch.setattr(runtime_state_module, "load_runtime_state", coordinated_load)
    workers = [threading.Thread(
        target=update_runtime_state,
        args=(tmp_path, "target.com"),
        kwargs={"mode": "agent"},
    )]
    workers[0].start()
    assert first_read.wait(timeout=5)

    workers.append(threading.Thread(
        target=update_runtime_state,
        args=(tmp_path, "target.com"),
        kwargs={"enrichment_tools": ["browser"]},
    ))
    workers[1].start()
    assert not second_read.wait(timeout=0.1)
    release_first.set()

    for worker in workers:
        worker.join(timeout=5)

    assert all(not worker.is_alive() for worker in workers)
    assert second_read.is_set()
    loaded = original_load(tmp_path, "target.com")
    assert loaded["mode"] == "agent"
    assert loaded["enrichment_tools"] == ["browser"]


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


def test_runtime_phase_lock_status_never_creates_or_chmods(tmp_path):
    root = tmp_path / "absent"
    assert runtime_state_module._runtime_phase_lock_status(root, "target.com", "recon") is False
    assert not root.exists()
    lock_path = root / "state" / "target.com" / "locks" / "recon.lock"
    for directory in (root, root / "state", lock_path.parent.parent, lock_path.parent):
        directory.mkdir()
        assert runtime_state_module._runtime_phase_lock_status(root, "target.com", "recon") is False
        assert list(directory.iterdir()) == []
    lock_path.write_bytes(b"existing metadata\n")
    lock_path.chmod(0o644)
    assert runtime_state_module._runtime_phase_lock_status(root, "target.com", "recon") is False
    assert lock_path.read_bytes() == b"existing metadata\n"
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o644


@pytest.mark.parametrize("obstacle", ["symlink", "dangling_symlink", "fifo", "hardlink", "directory", "parent_symlink"])
def test_runtime_phase_lock_status_reports_unsafe_path_as_unknown(tmp_path, obstacle):
    lock_path = tmp_path / "state" / "target.com" / "locks" / "recon.lock"
    lock_path.parent.mkdir(parents=True)
    sentinel = tmp_path / "external"
    sentinel.write_bytes(b"external lock metadata\n")
    sentinel.chmod(0o644)
    if obstacle in {"symlink", "dangling_symlink"}:
        lock_path.symlink_to(sentinel if obstacle == "symlink" else tmp_path / "missing")
    elif obstacle == "fifo":
        os.mkfifo(lock_path)
    elif obstacle == "hardlink":
        os.link(sentinel, lock_path)
    elif obstacle == "directory":
        lock_path.mkdir()
    else:
        lock_path.parent.rmdir()
        lock_path.parent.symlink_to(tmp_path)
    assert runtime_state_module._runtime_phase_lock_status(tmp_path, "target.com", "recon") is None
    assert sentinel.read_bytes() == b"external lock metadata\n"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o644


def test_runtime_phase_lock_remains_held_by_inheriting_child(tmp_path):
    """父调用方释放上下文后，实际长任务继承的 fd 仍必须维持 flock。"""
    child = None
    try:
        with runtime_phase_lock(
            tmp_path,
            "target.com",
            "recon",
            include_fd=True,
        ) as (_lock_path, lock_fd):
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                pass_fds=(lock_fd,),
            )

        assert runtime_phase_is_active(tmp_path, "target.com", "recon") is True
    finally:
        if child is not None:
            child.terminate()
            child.wait(timeout=5)

    assert runtime_phase_is_active(tmp_path, "target.com", "recon") is False


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

    class FakeProc:
        returncode = 17
        pid = 1234

        def wait(self):
            return self.returncode

    def fake_popen(command, *, env, start_new_session):
        captured.update({"command": command, "env": env, "start_new_session": start_new_session})
        return FakeProc()

    monkeypatch.setattr(runtime_phase_exec.subprocess, "Popen", fake_popen)
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
    assert captured["start_new_session"] is True
    state = load_runtime_state(tmp_path, "target.com")
    assert state["mode"] == "scan_failed"
    assert state["last_executed_workflow"] == "run_vuln_scan_failed"


def test_direct_phase_runner_terminates_child_on_interrupt(tmp_path, monkeypatch):
    captured = []

    class FakeProc:
        returncode = None
        pid = 1235

        def wait(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(
        runtime_phase_exec.subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProc(),
    )
    monkeypatch.setattr(
        runtime_phase_exec,
        "_terminate_process_group",
        lambda proc: captured.append(proc),
    )

    with pytest.raises(KeyboardInterrupt):
        runtime_phase_exec.run_phase_command(
            tmp_path,
            "target.com",
            "scan",
            ["scanner", "--deep"],
        )

    assert captured
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
    TargetStore(tmp_path, 'target.com').initialize()
    update_runtime_state(tmp_path, "target.com", mode="agent",
                        last_executed_workflow="run_recon")
    view = derive_state_view(tmp_path, "target.com")
    assert set(view.keys()) == {"persisted", "recon", "findings", "evidence", "derived"}
    assert view["persisted"]["mode"] == "agent"
    # recon dir doesn't exist → unavailable
    assert view["recon"]["available"] is False
    # finding counts default to 0
    assert view["findings"]["structured_total"] == 0
    assert view["evidence"]["browser_evidence_present"] is False
    assert view["derived"]["status"] == "unavailable"


def test_primary_runtime_queue_projection_ignores_corrupt_legacy_queue(tmp_path):
    target = "primary-runtime.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(
        command_id="create-runtime-work",
        action_id="WORK-1",
        intent="Review target context",
        execution_key="work:runtime-review",
        actor="ai",
        kind="work",
        subject={"target": target},
    )
    queue_path = tmp_path / "state" / target / "action_queue.json"
    queue_path.write_text("{not-json", encoding="utf-8")

    queue = runtime_state_module._derive_queue_state(tmp_path, target)

    assert queue["status"] == "valid"
    assert queue["backend"] == "primary"
    assert queue["active"] == 1
    assert queue["total"] == 1


def test_owner_projection_uses_registered_observations_and_current_surface(tmp_path):
    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    store.create_finding(
        command_id="claim", finding_id="F-1", endpoint="https://target.com/api/orders?id=7",
        method="GET", family="sqli", title="SQLi candidate", claim="Unassessed claim", actor="operator",
    )
    raw = tmp_path / "evidence" / "target.com" / "response.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("Recorded response", encoding="utf-8")
    store.start_attempt(attempt_id="read", source="native", started_at="2026-09-24T00:00:00Z", actor="operator")
    store.record_execution(attempt_id="read", outcome="complete", actor="operator", observations=[{
        "endpoint": "https://target.com/api/orders", "method": "GET", "family": "sqli",
        "observed_at": "2026-09-24T00:00:00Z", "description": "Recorded response",
        "result": "tested_clean", "artifacts": {"response": raw.relative_to(tmp_path).as_posix()},
        "state_changing": False,
    }])
    urls = tmp_path / "recon" / "target.com" / "urls" / "all.txt"
    urls.parent.mkdir(parents=True)
    urls.write_text("https://target.com/api/orders?id=7\nhttps://target.com/api/export\n", encoding="utf-8")
    before = store.binding()

    projection = derive_owner_projection(tmp_path, "target.com")

    assert projection["findings_authoritative"] is True
    assert projection["tested_authoritative"] is True
    assert projection["untested_authoritative"] is True
    assert "/api/orders" in projection["tested_endpoints"]
    assert "/api/export" in projection["untested_endpoints"]
    assert projection["findings"][0]["vuln_class"] == "SQLi"
    assert store.binding() == before


def test_primary_owner_projection_ignores_retired_coverage(tmp_path):
    target = "target.com"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="finding-1", finding_id="finding-1",
        endpoint=f"https://{target}/current", method="GET", family="Authz",
        title="Current claim", claim="Review current boundary", actor="ai",
    )
    matrix_path = tmp_path / "evidence" / target / "coverage_matrix.json"
    matrix_path.parent.mkdir(parents=True)
    matrix_path.write_text(json.dumps({"target": target, "endpoints": [
        {"endpoint": "/retired-tested", "cells": {"Authz": {"status": "tested_clean"}}},
        {"endpoint": "/retired-untested", "cells": {"Authz": {"status": "untested"}}},
    ]}), encoding="utf-8")
    recon_urls = tmp_path / "recon" / target / "urls" / "all.txt"
    recon_urls.parent.mkdir(parents=True)
    recon_urls.write_text(f"https://{target}/current-open\n", encoding="utf-8")

    projection = derive_owner_projection(tmp_path, target)

    assert projection["backend"] == "primary"
    assert projection["tested_authoritative"] is True
    assert projection["untested_authoritative"] is True
    assert projection["tested_endpoints"] == []
    assert "/current-open" in projection["untested_endpoints"]
    assert "/retired-untested" not in projection["untested_endpoints"]
    matrix_path.write_text("{broken", encoding="utf-8")
    assert derive_owner_projection(tmp_path, target)["tested_endpoints"] == []


def test_derived_status_preserves_scan_failure_over_ready_artifacts(tmp_path, monkeypatch):
    TargetStore(tmp_path, 'target.com').initialize()
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="scan_failed",
        last_executed_workflow="run_vuln_scan_failed",
    )
    monkeypatch.setattr(
        runtime_state_module,
        "inspect_recon_artifacts",
        lambda *_args, **_kwargs: {"ready": True},
    )

    view = derive_state_view(tmp_path, "target.com")

    assert view["derived"]["status"] == "partial"
    assert "scanner phase failed" in view["derived"]["reason"]
    assert view["derived"]["failure_breadcrumb"]["mode"] == "scan_failed"


def test_derived_status_exposes_partial_recon_budget(tmp_path, monkeypatch):
    TargetStore(tmp_path, 'target.com').initialize()
    update_runtime_state(tmp_path, "target.com", mode="recon", last_executed_workflow="run_recon")
    monkeypatch.setattr(
        runtime_state_module,
        "inspect_recon_artifacts",
        lambda *_args, **_kwargs: {
            "ready": True,
            "run_budget": {"partial": True, "stopped_phase": "url_collection"},
        },
    )

    view = derive_state_view(tmp_path, "target.com")

    assert view["derived"]["status"] == "partial"
    assert "recon run exceeded" in view["derived"]["reason"]


def test_inspect_recon_artifacts_reports_ready_cache(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
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


def test_recon_inspection_projects_pending_cidr_continuation(tmp_path):
    TargetStore(tmp_path, '10.0.0.0/19').initialize()
    live_dir = tmp_path / "recon" / "10.0.0.0_19" / "live"
    live_dir.mkdir(parents=True)
    (live_dir / "cidr_continuation.json").write_text(
        json.dumps({
            "target": "10.0.0.0/19",
            "status": "partial",
            "next_offset": 4096,
            "remaining_hosts": 4094,
        }),
        encoding="utf-8",
    )

    exact = inspect_recon_artifacts(tmp_path, "10.0.0.0/19")
    fast = inspect_recon_artifacts_fast(tmp_path, "10.0.0.0/19")

    expected = {
        "status": "pending",
        "path": str(live_dir / "cidr_continuation.json"),
        "next_offset": 4096,
        "remaining_hosts": 4094,
    }
    assert exact["cidr_continuation"] == expected
    assert fast["cidr_continuation"] == expected

    (live_dir / "cidr_continuation.json").write_text(
        json.dumps({
            "target": "10.0.0.0/19",
            "status": "partial",
            "next_offset": 0,
            "remaining_hosts": 4094,
        }),
        encoding="utf-8",
    )
    assert inspect_recon_artifacts(tmp_path, "10.0.0.0/19")["cidr_continuation"]["status"] == "invalid"


def test_recon_inspection_rejects_inconsistent_complete_cidr_continuation(tmp_path):
    TargetStore(tmp_path, '10.0.0.0/19').initialize()
    live_dir = tmp_path / "recon" / "10.0.0.0_19" / "live"
    live_dir.mkdir(parents=True)
    (live_dir / "cidr_continuation.json").write_text(
        json.dumps({
            "target": "10.0.0.0/19",
            "status": "ok",
            "next_offset": 4096,
            "remaining_hosts": 1,
        }),
        encoding="utf-8",
    )

    state = inspect_recon_artifacts(tmp_path, "10.0.0.0/19")

    assert state["cidr_continuation"]["status"] == "invalid"
    assert state["cidr_continuation"]["reason"] == "complete-with-remaining-hosts"


@pytest.mark.parametrize("content", [b"{broken", b"\xff"])
def test_recon_inspection_warns_on_invalid_cidr_continuation(tmp_path, content):
    TargetStore(tmp_path, '10.0.0.0/19').initialize()
    live_dir = tmp_path / "recon" / "10.0.0.0_19" / "live"
    live_dir.mkdir(parents=True)
    (live_dir / "cidr_continuation.json").write_bytes(content)

    payload = inspect_recon_artifacts(tmp_path, "10.0.0.0/19")

    assert payload["cidr_continuation"]["status"] == "invalid"
    assert any("CIDR continuation is invalid" in item for item in payload["warnings"])


@pytest.mark.parametrize(
    ("status", "note", "outcome"),
    [
        ("ok", "completed", "success_zero"),
        ("skipped", "httpx missing", "skipped"),
        ("partial", "httpx timed out", "timeout"),
        ("error", "httpx failed", "failure"),
    ],
)
def test_http_probe_outcome_distinguishes_success_zero_from_incomplete(
    tmp_path, status, note, outcome
):
    TargetStore(tmp_path, 'target.com').initialize()
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text("")
    (recon_dir / "recon_manifest.jsonl").write_text(
        json.dumps({
            "record_type": "recon_phase",
            "phase": "http_probing",
            "status": status,
            "count": 0,
            "note": note,
        }) + "\n"
    )

    exact = inspect_recon_artifacts(tmp_path, "target.com")
    fast = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert exact["http_probe"]["outcome"] == outcome
    assert fast["http_probe"]["outcome"] == outcome
    assert (exact["missing"] == []) is (outcome == "success_zero")


def test_zero_live_hosts_keeps_historical_surface_ready(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text("")
    (recon_dir / "urls" / "all.txt").write_text("https://target.com/old-api\n")

    exact = inspect_recon_artifacts(tmp_path, "target.com")
    fast = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert exact["host_inventory_ready"] is False
    assert exact["surface_inputs_ready"] is True
    assert exact["ready"] is True
    assert fast["ready"] is True


def test_normal_recon_js_inventory_is_a_surface_input(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text("https://target.com\n")
    (recon_dir / "urls" / "js_files.txt").write_text(
        "https://target.com/static/app.js\n"
    )

    exact = inspect_recon_artifacts(tmp_path, "target.com")
    fast = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert exact["counts"]["js_files"] == 1
    assert exact["surface_inputs_ready"] is True
    assert fast["counts"]["js_files"] is None
    assert fast["surface_inputs_ready"] is True


def test_fast_recon_inspection_uses_stat_presence_without_line_counts(tmp_path, monkeypatch):
    TargetStore(tmp_path, 'target.com').initialize()
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
    TargetStore(tmp_path, 'target.com').initialize()
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
    (recon_dir / "exposure" / "host_ranking.jsonl").write_text(
        '{"kind":"host-ranking-candidate","host":"api.target.com"}\n',
        encoding="utf-8",
    )
    payload = inspect_recon_artifacts(tmp_path, "target.com")
    assert payload["counts"]["host_ranking"] == 1
    assert payload["exposure_paths"]["host_ranking"] == "exposure/host_ranking.jsonl"
    assert payload["exposure_paths"]["api_doc_candidates"] == "exposure/api_doc_candidates.txt"
    assert payload["exposure_paths"]["verified_secrets"] == "exposure/api_leak_trufflehog_verified.jsonl"
    assert payload["exposure_paths"]["openapi_operations"] == "api_specs/operations.jsonl"


def test_inspect_recon_artifacts_warns_on_surface_gaps(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
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
    assert payload["warnings"] == ["no URL, JS, browser, or source-intel surface artifacts found yet"]


def test_inspect_recon_prefers_host_aware_ports_with_legacy_fallback(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "ports").mkdir(parents=True)
    legacy = recon_dir / "ports" / "open_ports_all.txt"
    legacy.write_text("443/open\n", encoding="utf-8")

    fallback = inspect_recon_artifacts(tmp_path, "target.com")
    assert fallback["counts"]["open_ports"] == 1
    assert fallback["infra_paths"]["open_ports"] == "ports/open_ports_all.txt"

    (recon_dir / "ports" / "open_host_ports.txt").write_text(
        "api.target.com:443\nadmin.target.com:8443\n",
        encoding="utf-8",
    )
    preferred = inspect_recon_artifacts(tmp_path, "target.com")
    assert preferred["counts"]["open_ports"] == 2
    assert preferred["infra_paths"]["open_ports"] == "ports/open_host_ports.txt"


def test_inspect_recon_exposes_structured_waf_context(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
    recon_dir = tmp_path / "recon" / "target.com" / "live"
    recon_dir.mkdir(parents=True)
    (recon_dir / "waf_context.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "waf_context",
                "target": "target.com",
                "status": "ok",
                "detected_count": 1,
                "vendors": ["cloudflare"],
            }
        ),
        encoding="utf-8",
    )

    payload = inspect_recon_artifacts(tmp_path, "target.com")

    assert payload["counts"]["waf_context"] == 1
    assert payload["infra_paths"]["waf_context"] == "live/waf_context.json"


def test_inspect_recon_artifacts_accepts_compact_ffuf_surface(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
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


def test_recon_budget_projection_uses_latest_record_and_preserves_advisory_status(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
    recon_dir = tmp_path / "recon" / "target.com"
    recon_dir.mkdir(parents=True)
    manifest = recon_dir / "recon_manifest.jsonl"
    partial = {
        "record_type": "recon_phase",
        "phase": "run_budget",
        "status": "partial",
        "note": "stopped_during_phase=url_collection; elapsed_seconds=37; soft_budget_seconds=30; soft_budget_status=advisory_exceeded",
        "recorded_at": "2026-08-20T00:00:00Z",
    }
    completed = {
        "record_type": "recon_phase",
        "phase": "run_budget",
        "status": "ok",
        "note": "elapsed_seconds=45; soft_budget_seconds=30; soft_budget_status=advisory_exceeded",
        "recorded_at": "2026-08-20T00:01:00Z",
    }
    manifest.write_text(
        "{not-json}\n" + json.dumps(partial) + "\n" + json.dumps(completed) + "\n",
        encoding="utf-8",
    )

    full = inspect_recon_artifacts(tmp_path, "target.com")["run_budget"]
    fast = inspect_recon_artifacts_fast(tmp_path, "target.com")["run_budget"]

    assert full == fast
    assert full["status"] == "ok"
    assert full["partial"] is False
    assert full["elapsed_seconds"] == 45
    assert full["soft_budget_seconds"] == 30
    assert full["advisory_exceeded"] is True

    manifest.write_text(json.dumps(partial) + "\n", encoding="utf-8")
    interrupted = inspect_recon_artifacts(tmp_path, "target.com")["run_budget"]

    assert interrupted["partial"] is True
    assert interrupted["stopped_phase"] == "url_collection"


def test_recon_phase_gates_are_projected_from_latest_manifest_rows(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
    recon_dir = tmp_path / "recon" / "target.com"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://target.com [200]\n", encoding="utf-8"
    )
    (recon_dir / "urls" / "all.txt").write_text(
        "https://target.com/\n", encoding="utf-8"
    )
    manifest = recon_dir / "recon_manifest.jsonl"
    manifest.write_text(
        "\n".join(
            json.dumps(row)
            for row in (
                {
                    "record_type": "recon_phase",
                    "phase": "url_collection",
                    "status": "ok",
                    "artifact": "recon/target.com/urls/all.txt",
                    "gate": {
                        "status": "complete",
                        "evidence_refs": ["recon/target.com/urls/all.txt"],
                        "coverage_gaps": [],
                        "next_focus": "choose next evidence",
                    },
                },
                {
                    "record_type": "recon_phase",
                    "phase": "js_analysis",
                    "status": "partial",
                    "artifact": "recon/target.com/js/endpoints.txt",
                    "gate": {
                        "status": "partial",
                        "evidence_refs": [],
                        "coverage_gaps": ["phase_status:partial"],
                        "next_focus": "resume JS",
                    },
                },
            )
        )
        + "\n",
        encoding="utf-8",
    )

    full = inspect_recon_artifacts(tmp_path, "target.com")
    fast = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert full["phase_gates"] == fast["phase_gates"]
    gates = full["phase_gates"]
    assert gates["complete_count"] == 1
    assert gates["incomplete"] == ["js_analysis"]
    assert gates["latest"]["url_collection"]["evidence_refs"] == [
        "recon/target.com/urls/all.txt"
    ]
    assert gates["latest"]["js_analysis"]["coverage_gaps"] == [
        "missing_artifact:recon/target.com/js/endpoints.txt",
        "phase_status:partial",
    ]


def test_inspect_recon_artifacts_reports_legacy_ffuf_without_parsing_it(tmp_path):
    TargetStore(tmp_path, 'target.com').initialize()
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
