"""Offline regression: python3 -I research/verify_autopilot_continuity.py.

Uses real temporary Store, host bindings and source snapshots. Scope/state acquisition
is injected; network, subprocesses and personal/real-target reads are forbidden.
"""

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import os
import sys

SOURCE = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(SOURCE))


def isolated_reads(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "subprocess.Popen"}:
        raise AssertionError(f"unexpected external operation: {event}")
    if event == "open" and isinstance(args[0], (str, bytes)):
        path = Path(args[0].decode() if isinstance(args[0], bytes) else args[0]).absolute()
        blocked = [SOURCE / name for name in (
            "tests", ".trellis/workspace", ".claude", "state", "evidence", "reports",
            "findings", "recon", "hunt-memory", "memory/goals",
        )] + [Path.home() / name for name in (".claude", ".codex", ".grok")]
        if path.name in {"connection.py", "config.json"} or any(path.is_relative_to(root) for root in blocked):
            raise AssertionError(f"unexpected private/target read: {path}")


sys.addaudithook(isolated_reads)

from tools import autopilot_bootstrap as bootstrap, autopilot_host as host, autopilot_state as state_owner
from tools import autopilot_loop_guard, runtime_config
from tools.target_memory import load_goal_memory
from tools.target_paths import target_storage_key
from tools.target_store import initialize_target_store, runtime_store

TARGET = "continuity-fixture.test"
SESSION = "offline-session"


def refused(call, error=ValueError):
    try:
        call()
    except error:
        return
    raise AssertionError("stale or invalid operation was accepted")


def verify(project, runtime):
    initialize_target_store(project, TARGET)
    store = runtime_store(project, TARGET)
    store.set_active_goal(command_id="goal:initial", goal="Review the local fixture", actor="selfcheck")

    def remember(key, kind="note", statement="Local fixture note"):
        store.remember(command_id=key, kind=kind, statement=statement,
                       conditions="fixture-reader", reopen_when="fixture revision changes",
                       next_intent="Compare the pending fixture revision" if kind == "handoff" else "",
                       evidence=[], actor="selfcheck")

    remember("handoff:initial", "handoff", "Local comparison recorded; pending revision remains")
    for index in range(7):
        remember(f"note:{index}")

    def current_state():
        memory = load_goal_memory(project, TARGET, experience_limit=5)
        current = memory["target"]
        return {"target": TARGET, "target_kind": "domain", "repo_root": str(project),
                "next_action": "continue_investigation", "owner_continuations": [],
                "resume_summary": {"source_binding": store.binding(), "target_memory": {
                    "active_goal": current["active_goal"],
                    "recent_entries": memory["recent_entries"],
                    "current_handoff": current["current_handoff"], "next_actions": current["next_actions"],
                    "experience_window": memory["source"]["experience_window"],
                }}}

    state = current_state()
    memory = state["resume_summary"]["target_memory"]
    assert len(memory["recent_entries"]) == 5 and memory["experience_window"]["remaining"] == 3
    assert memory["current_handoff"]["entry_id"] == "handoff:initial"
    assert all(row["entry_id"] != "handoff:initial" for row in memory["recent_entries"])
    assert memory["next_actions"][0]["text"] == "Compare the pending fixture revision"
    compact = bootstrap.compact_autopilot_state(state)
    assert compact["target_memory"] == {**memory, "source_binding": store.binding()}
    for kind in ("loop_check", "closure"):
        assert state_owner.build_decision_projection(state, kind)["active_goal"] == memory["active_goal"]

    queue = {"target": TARGET, "store_id": store.binding()["store_id"], "actions": []}

    def snapshot(value):
        return state_owner._closure_snapshot_digest(TARGET, value, queue, None, {}, {}, {}, {})

    digest, components = snapshot(state)
    evidence_ref = f"evidence/{target_storage_key(TARGET)}/local-review.txt"
    evidence = project / evidence_ref
    evidence.parent.mkdir(parents=True)
    evidence.write_text("Local fixture review evidence\n")
    review = {"status": "complete", "snapshot_digest": digest,
              "basis": state_owner._global_review_basis(components), "evidence_refs": [evidence_ref],
              "decision": "Local fixture reviewed", "residual_unknowns": []}

    def checked(value, saved=review):
        expected_digest, expected_components = snapshot(value)
        return state_owner.validate_global_review(project, TARGET, saved, queue,
            expected_digest=expected_digest, expected_components=expected_components)

    assert checked(state)["status"] == "valid"
    remember("handoff:updated", "handoff", "Same goal, updated local handoff")
    changed = current_state()
    assert snapshot(changed)[0] != digest and checked(changed)["status"] == "valid"
    store.set_active_goal(command_id="goal:changed", goal="Review a different fixture", actor="selfcheck")
    stale = checked(current_state())
    assert stale["status"] == "stale"
    assert any(item["field"] == "basis.closure_state_fingerprint" for item in stale["state_changes"])
    store.set_active_goal(command_id="goal:clear", goal="", actor="selfcheck")
    assert checked(current_state())["status"] == "stale"
    for kind in ("loop_check", "closure"):
        assert state_owner.build_decision_projection(current_state(), kind)["active_goal"] == ""
    legacy = deepcopy(review)
    legacy["basis"]["version"] = 2
    assert checked(state, legacy)["status"] == "stale"
    legacy.pop("basis")
    assert checked(state, legacy)["status"] == "valid"
    current = current_state()
    assert not state_owner.load_closure_projection(str(project), current).get("snapshot_stale")
    store.set_active_goal(command_id="goal:read-race", goal="Concurrent local revision", actor="selfcheck")
    stale_closure = state_owner.load_closure_projection(str(project), current)
    assert stale_closure["snapshot_stale"] and "target_memory" in stale_closure["snapshot_stale_sources"]
    store.set_active_goal(command_id="goal:restore", goal="", actor="selfcheck")

    # Real files/locks/source integrity; only external owner acquisition is injected below.
    source = host.capture_context(SOURCE)
    contract = host.host_source_digest(SOURCE, context=source)
    path = runtime / ".ccst-autopilot" / SESSION / "binding.json"
    context_path = path.with_name("context.json")
    initial = {"session_id": SESSION, "invocation_id": "completed-invocation", "prompt_id": "old-prompt",
        "repo_root": str(SOURCE), "target": TARGET, "status": "completed", "round_mode": False,
        "source_sha256": source["sha256"], "content_sha256": source["content_sha256"],
        "contract_sha256": contract, "started_at": 100, "max_seconds": 60,
        "round_limit": {"max_lanes": 2, "round_id": "current-round", "previous_round_id": ""},
        "last_stop_basis": "previous-rejection", "needs_refresh": False,
        "arguments": {"action": "continue", "target": TARGET, "target_kind": "domain", "invocation_batch": {}},
    }

    def seed(**updates):
        host.write_json_atomic(path, initial | updates)
        host.write_json_atomic(context_path, {key: source[key] for key in ("sha256", "sources", "sections")})

    def saved():
        return json.loads(path.read_text())

    def event(name, **fields):
        part = fields.pop("part", None)
        return host.hook(runtime, {"hook_event_name": name, "session_id": SESSION,
            "cwd": str(SOURCE), **fields}, part=part, contract_sha256=contract)

    def refresh(value=None):
        value = saved() if value is None else value
        return json.loads(host.refresh_state(runtime, SESSION, value["invocation_id"], value["prompt_id"], value["target"]))

    with patch.object(bootstrap, "load_autopilot_context", return_value={"scope": {}, "continuation": {}}), \
         patch.object(bootstrap, "load_autopilot_target_state", side_effect=lambda *args: deepcopy(state)), \
         patch.object(bootstrap, "build_autopilot_bootstrap", side_effect=AssertionError("unexpected Bootstrap")), \
         patch.object(autopilot_loop_guard, "_load_loop_guard_projection", return_value={}), \
         patch.object(runtime_config, "is_ctf_mode_enabled", return_value=False), \
         patch.object(host.time, "time", return_value=200):
        seed()
        refused(refresh)
        before = path.read_bytes()
        notification = "<task-notification><task-id>fixture</task-id><output-file>/unused</output-file><status>completed</status><summary>done</summary></task-notification>"
        assert event("UserPromptSubmit", prompt=notification) == {} and path.read_bytes() == before
        restored = event("SessionStart", source="compact")
        assert "INACTIVE" in restored["hookSpecificOutput"]["additionalContext"]
        assert "INACTIVE" in event("SessionStart", source="compact", part=0)["hookSpecificOutput"]["additionalContext"]
        assert saved()["status"] == "completed" and "reopen_prompt_id" not in saved()
        refused(refresh)
        event("UserPromptSubmit", prompt="What was recorded?")
        assert saved()["status"] == "completed"
        event("Stop")
        refused(refresh)

        event("UserPromptSubmit", prompt="Continue the same fixture review")
        pending = saved()
        for key, wrong in (("prompt_id", "stale-prompt"), ("invocation_id", "foreign-invocation"), ("target", "foreign.test")):
            refused(lambda: refresh(pending | {key: wrong}))
        event("SessionStart", source="compact")
        assert saved()["reopen_prompt_id"] == pending["prompt_id"]
        recovered = refresh()
        resumed = saved()
        assert resumed["status"] == "active" and resumed["invocation_id"] != initial["invocation_id"]
        assert "reopen_prompt_id" not in resumed and resumed["last_stop_basis"] == ""
        for key in ("started_at", "max_seconds", "round_limit", "arguments", "target"):
            assert resumed[key] == initial[key], key
        assert recovered["recovery"]["state"]["target_memory"] == compact["target_memory"]
        assert recovered["host"]["invocation_id"] == resumed["invocation_id"]
        assert recovered["active_goal"] == memory["active_goal"]
        refused(lambda: refresh(pending))

        closure = {"can_claim_exhausted": False, "global_review": {"status": "complete", "termination": {
            "reason": "no_worthwhile_work", "session_id": SESSION, "invocation_id": initial["invocation_id"]}}}
        assert not host.stop_check(resumed, state, closure, {})["allow"]
        closure["global_review"]["termination"]["invocation_id"] = resumed["invocation_id"]
        assert host.stop_check(resumed, state, closure, {}) == {"allow": True, "reason": "no_worthwhile_work", "exhausted": False}
        assert host._explicit_limit_reached(resumed, {"limit": {"elapsed_seconds": 60}}, {})
        assert not host._explicit_limit_reached(resumed, {"limit": {"elapsed_seconds": 1}}, {})
        round_state = {"round_id": "current-round", "max_lanes": 2, "budget_reached": True}
        assert host._explicit_limit_reached(resumed, {"limit": {"round_id": "current-round"}}, round_state)
        assert not host._explicit_limit_reached(resumed, {"limit": {"round_id": "previous-round"}}, round_state)
        host.write_json_atomic(path, resumed | {"last_stop_basis": "unchanged-rejection"})
        assert "recovery" not in refresh()
        assert saved()["invocation_id"] == resumed["invocation_id"] and saved()["last_stop_basis"] == "unchanged-rejection"

        for boundary in ("SessionEnd", "StopFailure", "Stop", "restart"):
            seed()
            event("UserPromptSubmit", prompt="Continue the fixture review")
            if boundary == "restart":
                event("SessionStart", source="resume")
            else:
                event(boundary)
            assert saved()["status"] == "completed" and "reopen_prompt_id" not in saved()
            refused(refresh)

        seed()
        event("UserPromptSubmit", prompt="Continue the fixture review")
        context_path.write_text("{}")
        refused(refresh, KeyError)
        assert saved()["status"] == "completed" and saved()["invocation_id"] == initial["invocation_id"]
        seed(contract_sha256="wrong-source")
        # SessionStart verifies the persisted contract; no current user event replaces it here.
        refused(lambda: event("SessionStart", source="compact"))
        assert saved()["status"] == "completed"
        seed()
        event("UserPromptSubmit", prompt="Continue the fixture review")
        pending = saved()
        context_path.write_text("{}")
        refused(lambda: event("SessionStart", source="resume"), KeyError)
        assert "reopen_prompt_id" not in saved()
        host.write_json_atomic(context_path, {key: source[key] for key in ("sha256", "sources", "sections")})
        refused(lambda: refresh(pending))
        seed()
        event("UserPromptSubmit", prompt="Continue the fixture review")
        with patch.object(bootstrap, "load_autopilot_context", side_effect=ValueError("scope changed")):
            refused(refresh)
        assert saved()["status"] == "completed"

        seed(status="suspended")
        assert refresh()["host"]["invocation_id"] == initial["invocation_id"]
        assert saved()["last_stop_basis"] == initial["last_stop_basis"]
        with patch.object(state_owner, "build_autopilot_state", return_value=deepcopy(state)), \
             patch.object(state_owner, "load_closure_projection", return_value={}):
            assert event("Stop")["decision"] == "block"
            refresh()
            assert event("Stop", stop_hook_active=True)["continue"] is False
            assert saved()["status"] == "suspended"
        seed()
        event("UserPromptSubmit", prompt="Continue the fixture review")
        event("SessionEnd", reason="clear")
        assert saved()["status"] == "idle" and "reopen_prompt_id" not in saved()
        assert event("SessionStart", source="resume") == {}
        assert event("UserPromptSubmit", prompt="Continue the fixture review") == {}
        refused(refresh)
        seed()
        event("SessionStart", source="clear")
        assert saved()["status"] == "idle" and "invocation_id" not in saved()

    assert store.active_goal() == "", "host lifecycle changed target memory"


if __name__ == "__main__":
    original_cwd = Path.cwd()
    try:
        with TemporaryDirectory(prefix="ccst-continuity-") as temporary:
            root = Path(temporary)
            os.chdir(root)
            verify(root / "project", root / "runtime")
    finally:
        os.chdir(original_cwd)
    print("PASS: goal/review binding, five-entry memory recovery, prompt-bound reopen, unchanged limits and Stop guard")
