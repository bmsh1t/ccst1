"""Hook results and durable bindings agree across waits, errors and completion."""

import io
import json

import pytest

from tools import autopilot_host as host, autopilot_state as state_api


@pytest.fixture
def session(tmp_path, monkeypatch):
    state, closure = {}, {}
    monkeypatch.setattr(state_api, "build_autopilot_state", lambda *a, **kw: state)
    monkeypatch.setattr(state_api, "load_closure_projection", lambda *a, **kw: closure)
    with host.session_binding(tmp_path, "test-session") as (binding, path):
        binding.update(status="active", invocation_id="invocation", prompt_id="prompt",
                       target="fixture.test", repo_root=str(host.REPO_ROOT), source_sha256="a" * 64,
                       round_mode=False, needs_refresh=False, last_stop_basis="")
        host.write_json_atomic(path, binding)

    def event(name="Stop", **extra):
        return host.hook(tmp_path, {"hook_event_name": name, "session_id": "test-session",
                                   "cwd": str(host.REPO_ROOT), **extra},
                         part=None, contract_sha256="fixture")

    return tmp_path, path, state, closure, event


@pytest.mark.parametrize("execution", ["recon_in_progress", "scan_in_progress", "background"])
def test_running_execution_waits_without_suspending_and_restarts_rejection_count(session, execution):
    _, path, state, closure, event = session
    closure["round_progress"] = {"status": "active"}
    assert event()["decision"] == "block"
    assert json.loads(path.read_text())["last_stop_basis"]
    extra = {}
    if execution == "background":
        extra["background_tasks"] = [{"id": "job", "status": "running"}]
    else:
        state[execution] = True
    for _ in range(3):
        assert event(stop_hook_active=True, **extra)["decision"] == "block"
        binding = json.loads(path.read_text())
        assert binding["status"] == "active" and not binding["last_stop_basis"]
    state.clear()
    # The Round remains unfinished even though its real execution has returned.
    assert event(stop_hook_active=True)["decision"] == "block"
    assert json.loads(path.read_text())["status"] == "active"
    assert event(stop_hook_active=True)["continue"] is False
    assert json.loads(path.read_text())["status"] == "suspended"


@pytest.mark.parametrize("case", ["missing_review", "foreign_review", "needs_refresh", "round_only"])
def test_repeated_non_waiting_rejections_still_suspend(session, case):
    _, path, state, closure, event = session
    if case == "needs_refresh":
        binding = json.loads(path.read_text())
        binding["needs_refresh"] = True
        host.write_json_atomic(path, binding)
        state["recon_in_progress"] = True
    elif case == "round_only":
        closure["round_progress"] = {"status": "active"}
    elif case == "foreign_review":
        closure["global_review"] = {"status": "complete", "termination": {
            "reason": "no_worthwhile_work", "session_id": "other", "invocation_id": "invocation"}}
    assert event()["decision"] == "block"
    assert event(stop_hook_active=True)["continue"] is False
    assert json.loads(path.read_text())["status"] == "suspended"


def test_current_review_completes_only_after_execution_returns(session):
    _, path, state, closure, event = session
    closure["global_review"] = {"status": "complete", "termination": {
        "reason": "no_worthwhile_work", "session_id": "test-session", "invocation_id": "invocation"}}
    state["recon_in_progress"] = True
    assert event()["decision"] == "block"
    state.clear()
    assert event(stop_hook_active=True) == {}
    assert json.loads(path.read_text())["status"] == "completed"


def test_failed_batch_still_suspends_immediately(session):
    _, path, state, _, event = session
    state.update(target_kind="list", next_action="invalid_batch_target", recon_in_progress=True)
    assert event()["continue"] is False
    assert json.loads(path.read_text())["status"] == "suspended"


@pytest.mark.parametrize("reader", ["build_autopilot_state", "load_closure_projection"])
def test_stop_read_error_returns_incomplete_and_persists_recovery(session, monkeypatch, capsys, reader):
    runtime, path, _, _, _ = session

    def fail(*args, **kwargs):
        raise ValueError("fixture owner read failed")

    monkeypatch.setattr(state_api, reader, fail)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({
        "hook_event_name": "Stop", "session_id": "test-session", "cwd": str(host.REPO_ROOT)})))
    assert host.main(["--runtime-root", str(runtime), "hook"]) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["continue"] is False and "fixture owner read failed" in response["stopReason"]
    binding = json.loads(path.read_text())
    assert binding["status"] == "suspended" and binding["needs_refresh"] is True


def test_notifications_and_child_events_preserve_binding_but_user_cancel_suspends(session):
    _, path, _, _, event = session
    previous = path.read_bytes()
    notification = ("<task-notification><task-id>job</task-id><output-file>/tmp/result</output-file>"
                    "<status>completed</status><summary>done</summary></task-notification>")
    assert event("UserPromptSubmit", prompt=notification) == {}
    assert event(agent_id="child") == {}
    assert path.read_bytes() == previous
    event("UserPromptSubmit", prompt="停止")
    assert json.loads(path.read_text())["status"] == "suspended"
    assert event() == {}
