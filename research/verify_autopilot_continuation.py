"""Offline continuation checks: synthetic Store/runtime, no model or target requests."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch


def stage(source, root):
    for directory in ("tools", "memory"):
        for path in (source / directory).glob("*.py"):
            if path.name == "connection.py" or path.is_symlink():
                continue
            destination = root / directory / path.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
    for name in ("commands/autopilot.md", "commands/autopilot-round.md",
                 "skills/runtime-protocol.md", "skills/src-hunter/SKILL.md", "agents/autopilot.md"):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, destination)
    registry = root / "knowledge/capabilities.yaml"
    registry.parent.mkdir()
    registry.write_text("schema_version: 1\ncapabilities: []\ncontracts: {}\n")


def check(root, runtime):
    os.chdir(root)
    sys.path.insert(0, str(root))
    from tools import autopilot_host as host, autopilot_bootstrap as boot
    from tools import autopilot_state as state_api
    from tools.action_queue import load_queue, resolve_action
    from tools.autopilot_args import parse_autopilot_args
    from tools.checkpoint import build_checkpoint
    from tools.claude_hook_contract import capture_context, RECOVERY_PARTS
    from tools.target_memory import load_goal_memory
    from tools.target_store import initialize_target_store, runtime_store, ConflictError

    target, actor, sid = "continuation.test", "offline-check", "offline-session"
    results = []

    def cli(*args):
        reply = subprocess.run([sys.executable, *args], cwd=root, text=True,
                               capture_output=True, timeout=15)
        assert reply.returncode == 0, reply.stderr
        return json.loads(reply.stdout)

    def reject(operation, reason):
        try:
            operation()
        except ConflictError as error:
            assert reason in str(error), str(error)
        else:
            raise AssertionError("expected owner rejection: " + reason)

    def remember(command, *, kind="note", action=None, next_intent="", statement="Synthetic saved result"):
        return store.remember(command_id=command, kind=kind, statement=statement,
                              conditions="fixture source revision 1", reopen_when="source revision changes",
                              next_intent=next_intent, evidence=[], actor=actor, action_id=action)

    def transition(action, command, status, **extra):
        current = store.action(action)
        return store.transition_action(command_id=command, action_id=action,
            expected_version=current["version"], expected_store_id=store.binding()["store_id"],
            status=status, actor=actor, reason=command,
            claim_token=current["claim_token"] if current["status"] == "claimed" else None, **extra)

    initialize_target_store(root, target)
    store = runtime_store(root, target)
    store.set_active_goal(command_id="goal", goal="Review synthetic saved documents", actor=actor)
    for index in range(7):
        action = f"review-{index}"
        store.create_action(command_id="add-" + action, action_id=action, intent="Review synthetic document",
                            execution_key=action, actor=actor, kind="work", subject={"target": target})
        transition(action, "block-" + action, "blocked",
                   metadata={"conditions": "source missing", "reopen_when": "source arrives"})
    remember("handoff-old", kind="handoff", next_intent="Earlier proposed work")
    remember("handoff-current", kind="handoff", action="review-6", next_intent="Review document six")
    for index in range(6):
        remember(f"note-{index}")
    before = store.binding()
    checkpoint = build_checkpoint(root, target=target, refresh_coverage=False)
    window = checkpoint["action_queue_window"]
    assert window["returned"] == 5 and window["remaining"] == 2, window
    expanded = cli(*shlex.split(window["expand_command"])[1:])
    assert len(expanded) == 7 and expanded[-1]["id"] == "review-6"
    assert all(item["status"] == "blocked" for item in expanded)
    memory = load_goal_memory(root, target, experience_limit=5)
    assert memory["target"]["current_handoff"]["entry_id"] == "handoff-current"
    assert all(item["entry_id"] != "handoff-current" for item in memory["recent_entries"])
    assert store.binding() == before
    results.append("five-entry window expands all seven blocked actions; current handoff survives history window; reads do not write")

    selected = expanded[-1]
    reopened = resolve_action(root, target=target, action_id=selected["id"], status="queued",
                              result="Synthetic source arrived", actor=actor,
                              expected_store_id=selected["store_id"], expected_version=selected["version"])
    assert store.action("review-6")["status"] == "ready"
    assert reopened["version"] == selected["version"] + 1 == store.action("review-6")["version"]
    assert all(store.action(f"review-{index}")["status"] == "blocked" for index in range(6))
    transition("review-6", "claim-review", "claimed")
    remember("result-review", action="review-6")
    transition("review-6", "finish-review", "completed", completion={"command_id": "result-review"})
    reject(lambda: transition("review-6", "reopen-terminal", "ready"), "terminal actions are immutable")
    assert load_goal_memory(root, target)["target"]["current_handoff"]["entry_id"] == "handoff-current"
    assert store.action("review-6")["status"] == "completed"
    remember("handoff-empty", kind="handoff")
    assert load_goal_memory(root, target)["target"]["next_actions"] == []
    results.append("explicit blocked-to-ready uses original CAS; other blockers untouched; stale handoff cannot mutate terminal work; empty current intent stays empty")

    store.create_action(command_id="add-effect", action_id="unknown-effect", intent="Synthetic unreturned attempt",
                        execution_key="unknown-effect", actor=actor, endpoint=f"https://{target}/fixture",
                        family="synthetic-check")
    transition("unknown-effect", "claim-effect", "claimed")
    store.start_attempt(attempt_id="fixture-attempt", source="offline simulation",
                        started_at="2026-01-01T00:00:00Z", actor=actor, action_id="unknown-effect",
                        claim_token=store.action("unknown-effect")["claim_token"])
    reject(lambda: transition("unknown-effect", "release-effect", "ready"), "execution outcome unknown")
    results.append("unregistered attempt retains its original claim instead of replay")

    arguments = parse_autopilot_args([target, "--deep", "--normal", "--max-seconds=600"], cwd=root)
    assert arguments["action"] == "continue"
    context = capture_context(root)
    with host.session_binding(runtime, sid) as (binding, path):
        binding.update(status="active", repo_root=str(root), invocation_id="offline-invocation",
                       prompt_id="offline-prompt", target=target, round_mode=False,
                       arguments=arguments, source_sha256=context["sha256"], needs_refresh=False,
                       started_at=time.time(), max_seconds=600, round_limit={"max_lanes": None, "round_id": ""},
                       invocation_prompt="/autopilot continuation.test --deep --normal")
        host.write_json_atomic(path, binding)
    binding_path = runtime / ".ccst-autopilot" / sid / "binding.json"

    def binding():
        return json.loads(binding_path.read_text())

    def event(name, **extra):
        return host.hook(runtime, {"hook_event_name": name, "session_id": sid, "cwd": str(root), **extra},
                         part=None, contract_sha256="offline-contract")

    def refresh():
        current = binding()
        return json.loads(host.refresh_state(runtime, sid, current["invocation_id"],
                                             current["prompt_id"], target))

    original = binding()
    with patch.object(boot, "initialize_target_store", side_effect=AssertionError("refresh initialized Store")), \
         patch.object(boot, "compare_runtime", side_effect=AssertionError("refresh inspected personal runtime")), \
         patch.object(boot, "load_autopilot_target_state", wraps=boot.load_autopilot_target_state) as read:
        live = refresh()
        assert read.call_count == 1
    assert live["action"] == "continue"
    assert any(item["id"] == "unknown-effect" for item in live["control"]["owner_continuations"])
    task = {"id": "fixture-task", "status": "running"}
    state = {"target_kind": "domain", "owner_continuations": live["control"]["owner_continuations"]}
    closure = {"snapshot_components": {"store": store.binding()}, "owner_continuations": []}
    with patch.object(state_api, "build_autopilot_state", return_value=state), \
         patch.object(state_api, "load_closure_projection", return_value=closure):
        wait = event("Stop", background_tasks=[task])
        assert wait["decision"] == "block" and "Collect" in wait["reason"]
        notification = ("<task-notification><task-id>fixture-task</task-id>"
                        "<output-file>/tmp/fixture-result</output-file><status>completed</status>"
                        "<summary>synthetic completion</summary></task-notification>")
        previous = binding()
        assert event("UserPromptSubmit", prompt=notification) == {} and binding() == previous
        baseline = event("Stop", stop_hook_active=True)
        assert baseline["decision"] == "block"
        basis_before = binding()["last_stop_basis"]
        store.record_execution(attempt_id="fixture-attempt", outcome="unknown", observations=[], actor=actor)
        transition("unknown-effect", "recorded-unknown", "blocked")
        remember("received-result", statement="The synthetic task returned; effects remain unknown")
        closure["snapshot_components"] = {"store": store.binding()}
        current = event("Stop", stop_hook_active=True)
        assert current["decision"] == "block" and binding()["status"] == "active"
        assert current["reason"].split("\nHost binding:")[0] == baseline["reason"].split("\nHost binding:")[0]
        assert binding()["last_stop_basis"] != basis_before
        refresh()
        assert event("Stop", stop_hook_active=True)["continue"] is False
        assert binding()["status"] == "suspended"
        before = binding()
        assert event("UserPromptSubmit", prompt=notification) == {} and binding() == before
    results.append("real hook preserves active notifications and changed result basis; identical repeated Stop still suspends; notifications cannot reactivate")

    event("UserPromptSubmit", prompt="继续同一任务")
    refresh()
    event("SessionStart", source="compact")
    restored = refresh()
    expected = load_goal_memory(root, target, experience_limit=5)["target"]
    assert restored["recovery"]["state"]["target_memory"]["current_handoff"] == expected["current_handoff"]
    for key in ("started_at", "max_seconds", "round_limit", "arguments"):
        assert binding()[key] == original[key], key
    assert binding()["invocation_id"] == original["invocation_id"]
    snapshot = store.binding()
    for prompt in ("目前进展如何", "停止", "换个任务"):
        event("UserPromptSubmit", prompt=prompt)
        assert event("Stop") == {} and binding()["status"] == "suspended"
    assert store.binding() == snapshot
    results.append("compact restores current handoff and original allocation; questions/cancel/task changes stay suspended")

    bodies = []
    for round_mode in (False, True):
        source = capture_context(root, round_mode=round_mode)
        parts = [host.body(part, round_mode=round_mode) for part in range(RECOVERY_PARTS)]
        chunks = [part.split("\n", 1)[1].removesuffix("\nCCST_ENTRY_END") for part in parts if part]
        assert "".join(chunks) == source["text"]
        assert all(len(part.encode()) < 24000 for part in parts)
        assert source["text"].count("执行结果（含后台终态、子代理交付）") == 1
        assert "result reassessment in `skills/runtime-protocol.md#5-execution-and-write-back`" in source["text"]
        bodies.append({"round": round_mode, "chunks": len(chunks), "bytes": len(source["text"].encode())})
    assert not any((runtime / ".ccst-autopilot" / sid).glob("context*.json"))
    results.append("normal/round/current-source transport delivers one complete result protocol without body snapshots")
    return {"passed": results, "transport_fixture": bodies,
            "limits": "Current protocol/Skill bodies; synthetic Store/runtime and two mocked Stop owner projections; no model or network execution."}


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--isolated":
        print(json.dumps(check(Path(sys.argv[2]), Path(sys.argv[3])), ensure_ascii=False))
    else:
        source = Path(__file__).resolve().parents[1]
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="ccst-result-continuation-") as directory:
            root, runtime = Path(directory) / "checkout", Path(directory) / "runtime"
            stage(source, root)
            env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                   "PYTHONDONTWRITEBYTECODE": "1", "CCST_RUNTIME_ROOT": str(runtime),
                   "CLAUDE_CONFIG_DIR": str(runtime), "HUNT_MEMORY_DIR": str(root / "hunt-memory")}
            reply = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--isolated", str(root), str(runtime)],
                                   cwd=root, env=env, text=True, capture_output=True, timeout=60)
            if reply.returncode:
                print(reply.stderr, file=sys.stderr)
                raise SystemExit(reply.returncode)
            result = {**json.loads(reply.stdout), "elapsed_seconds": round(time.monotonic() - started, 3)}
            print(json.dumps(result, ensure_ascii=False, indent=2))
