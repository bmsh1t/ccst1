"""Thin Claude lifecycle adapter; investigation and target facts keep their owners."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import re
import shlex
import sys
import time
import uuid

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.artifact_io import publish_bytes_create_only, write_json_atomic
from tools.claude_hook_contract import DYNAMIC_OUTPUT_LIMIT, capture_context, dynamic_output, hook_context, json_digest
from tools.runtime_config import claude_runtime_root


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("missing or invalid Claude session/invocation identity")
    return value


@contextmanager
def session_binding(runtime: Path, session_id: str):
    directory = runtime / ".ccst-autopilot" / _identifier(session_id)
    for path in (directory, *directory.parents):
        if path.is_symlink():
            raise ValueError("Claude host binding path must not be linked")
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    state_path, lock_path = (directory / name for name in ("binding.json", "lock"))
    if any(p.is_symlink() or (p.exists() and not p.is_file()) for p in (state_path, lock_path)):
        raise ValueError("Claude host binding must use regular private files")
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(state_path.read_text()) if state_path.exists() else {"session_id": session_id, "status": "idle"}
        if not isinstance(state, dict) or state.get("session_id") != session_id:
            raise ValueError("invalid Claude host binding")
        yield state, state_path


def _state_command(runtime: Path, binding: dict) -> str:
    return shlex.join(["python3", str(REPO_ROOT / "tools/autopilot_host.py"),
                       "--runtime-root", str(runtime), "state", "--session-id", binding["session_id"],
                       "--invocation-id", binding["invocation_id"], "--prompt-id", binding["prompt_id"],
                       "--target", binding["target"]])


def _host_view(runtime: Path, binding: dict) -> dict:
    started = binding.get("started_at")
    return {key: binding[key] for key in ("session_id", "invocation_id", "target", "status")} | {
        "state_command": _state_command(runtime, binding),
        "source_sha256": binding["source_sha256"],
        "round_mode": binding["round_mode"],
        "invocation_prompt": binding.get("invocation_prompt", ""),
        "started_at": started,
        "elapsed_seconds": round(time.time() - started, 3) if type(started) in (int, float) else None,
        "max_seconds": binding.get("max_seconds"),
        "round_limit": binding.get("round_limit", {}),
    }


def _entry_output(text: str, directory: Path) -> str:
    raw = text.encode("utf-8")
    if len(raw) < DYNAMIC_OUTPUT_LIMIT:
        return dynamic_output(text)
    snapshot = directory / f"bootstrap-{uuid.uuid4().hex}.json"
    publish_bytes_create_only(snapshot, raw)
    return dynamic_output(json.dumps({"action": "read_bootstrap", "bootstrap_path": str(snapshot)}, ensure_ascii=False))


def start(runtime: Path, session_id: str, argv: list[str], *, round_mode: bool) -> str:
    from tools.autopilot_bootstrap import build_autopilot_bootstrap, render_autopilot_bootstrap_json
    started = time.time()
    with session_binding(runtime, session_id) as (binding, path):
        if binding.get("repo_root") not in {None, str(REPO_ROOT)}:
            raise ValueError("Claude session is bound to another checkout")
        binding["status"] = "suspended" if binding.get("invocation_id") else "idle"
        write_json_atomic(path, binding)
        if not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("contract_sha256") or "")):
            raise ValueError(f"Autopilot entry has no lifecycle event record at {path}; "
                             f"check that Claude hooks use checkout {REPO_ROOT} and runtime {runtime}. "
                             "Run sync-check and restart Claude after fixing the configuration")
        context = capture_context(REPO_ROOT, round_mode=round_mode)
        payload = build_autopilot_bootstrap(argv, repo_root=REPO_ROOT, runtime_root=runtime, round_defaults=round_mode)
        if payload["action"] != "continue":
            return _entry_output(render_autopilot_bootstrap_json(payload), path.parent)
        progress = (payload.get("state") or {}).get("round_progress") or {}
        inherited = progress.get("status") == "active"
        binding.update(status="active", invocation_id=uuid.uuid4().hex, arguments=payload["arguments"],
                       started_at=started,
                       max_seconds=payload["arguments"].get("max_seconds"),
                       round_limit={"max_lanes": progress.get("max_lanes") if inherited else payload["arguments"].get("max_lanes"),
                                    "round_id": progress.get("round_id", "") if inherited else "",
                                    "previous_round_id": "" if inherited else progress.get("round_id", "")},
                       round_mode=round_mode, repo_root=str(REPO_ROOT),
                       target=payload["arguments"]["target"], source_sha256=context["sha256"],
                       last_stop_basis="", needs_refresh=False,
                       prompt_id=binding.get("prompt_id") or uuid.uuid4().hex)
        binding.pop("reopen_prompt_id", None)
        payload["host"] = _host_view(runtime, binding)
        output = _entry_output(render_autopilot_bootstrap_json(payload), path.parent)
        write_json_atomic(path, binding)
        return output


def body(part: int, *, round_mode: bool) -> str:
    if part < 0:
        raise ValueError("invalid entry body part")
    context = capture_context(REPO_ROOT, round_mode=round_mode)
    chunks = context["chunks"]
    if part >= len(chunks):
        return ""
    return dynamic_output(f"CCST_ENTRY {context['sha256']} "
                          f"PART {part + 1}/{len(chunks)}\n" + chunks[part] + "\nCCST_ENTRY_END")


def refresh_state(runtime: Path, session_id: str, invocation_id: str, prompt_id: str, target: str) -> str:
    from tools.autopilot_bootstrap import compact_autopilot_state, load_autopilot_context, load_autopilot_target_state
    from tools.autopilot_loop_guard import _load_loop_guard_projection
    from tools.autopilot_state import build_decision_projection
    from tools.runtime_config import is_ctf_mode_enabled
    with session_binding(runtime, session_id) as (binding, path):
        reopening = binding.get("status") == "completed"
        if (binding.get("status") not in {"active", "suspended", "completed"}
                or (reopening and binding.get("reopen_prompt_id") != prompt_id)
                or binding.get("repo_root") != str(REPO_ROOT)
                or binding.get("invocation_id") != _identifier(invocation_id)
                or binding.get("prompt_id") != _identifier(prompt_id)
                or binding.get("target") != target):
            raise ValueError("stale Autopilot state binding; use the command from the current host event")
        recovering = reopening or bool(binding.get("needs_refresh"))
        check_source = recovering or binding["status"] == "suspended"
        binding["status"] = "completed" if reopening else "suspended"
        write_json_atomic(path, binding)
        source = None
        if check_source:
            current = capture_context(REPO_ROOT, round_mode=binding["round_mode"])
            if current["sha256"] != binding["source_sha256"]:
                source, recovering = current, True
        arguments = dict(binding["arguments"])
        if arguments["action"] != "continue" or arguments["target"] != target:
            raise ValueError("saved Autopilot arguments do not match the admitted target")
        context = load_autopilot_context(REPO_ROOT, arguments)
        state = load_autopilot_target_state(REPO_ROOT, arguments, context)
        if state.get("target_kind") != "list":
            state["loop_guard"] = _load_loop_guard_projection(str(REPO_ROOT), state)
        payload = build_decision_projection(state, "loop_check")
        if state.get("target_kind") == "list":
            payload["batch"] = compact_autopilot_state(state)["batch"]
        if recovering:
            payload["recovery"] = {"repo_root": str(REPO_ROOT), "repo_root_shell": shlex.quote(str(REPO_ROOT)),
                "arguments": arguments, "invocation_batch": arguments["invocation_batch"],
                "ctf_mode": is_ctf_mode_enabled(REPO_ROOT), **context, "state": compact_autopilot_state(state)}
            if source:
                payload["recovery"]["source_context"] = {"sha256": source["sha256"], "commands": [
                    shlex.join(["python3", str(REPO_ROOT / "tools/autopilot_host.py"), "body", "--part", str(part),
                                *(["--round-defaults"] if binding["round_mode"] else [])])
                    for part in range(len(source["chunks"]))]}
                binding["source_sha256"] = source["sha256"]
        if reopening or source:
            # Retain the original allocation; only the old Stop attestation expires.
            binding.update(invocation_id=uuid.uuid4().hex, last_stop_basis="")
            binding.pop("reopen_prompt_id", None)
        binding.update(status="active", needs_refresh=False)
        payload.update(action="continue", host=_host_view(runtime, binding))
        output = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        write_json_atomic(path, binding)
        return output


def _explicit_limit_reached(binding: dict, termination: dict, round_progress: dict) -> bool:
    limit = termination.get("limit") or {}
    if set(limit) == {"elapsed_seconds"}:
        started, seconds = binding.get("started_at"), limit["elapsed_seconds"]
        return (type(started) in (int, float) and started > 0
                and type(seconds) is int and seconds > 0 and seconds == binding.get("max_seconds")
                and time.time() - started >= seconds)
    if set(limit) == {"round_id"}:
        admitted = binding.get("round_limit") or {}
        round_id = limit["round_id"]
        return (bool(limit["round_id"]) and limit["round_id"] == round_progress.get("round_id")
                and type(admitted.get("max_lanes")) is int and admitted["max_lanes"] > 0
                and admitted["max_lanes"] == round_progress.get("max_lanes")
                and (round_id == admitted["round_id"] if admitted.get("round_id")
                     else round_id != admitted.get("previous_round_id"))
                and round_progress.get("budget_reached") is True)
    return False


def stop_check(binding: dict, state: dict, closure: dict, event: dict) -> dict:
    """Read existing owner/review facts; never judge investigation value."""
    review = closure.get("global_review") or {}
    termination = review.get("termination") or {}
    reviewed_stop = (review.get("status") == "complete" or (
        review.get("status") == "form_insufficient" and review.get("review_status") == "complete"
        and termination.get("reason") in {"scope_boundary", "explicit_limit", "global_blocker"}))
    bound_review = (not closure.get("snapshot_stale") and reviewed_stop
                    and termination.get("session_id") == binding["session_id"]
                    and termination.get("invocation_id") == binding["invocation_id"])
    active_phase = state.get("recon_in_progress") or state.get("scan_in_progress")
    round_progress = closure.get("round_progress") or state.get("round_progress") or {}
    unfinished = active_phase or round_progress.get("unfinished_lanes") or round_progress.get("status") == "active"
    pending = [item for item in [*state.get("owner_continuations", []), *closure.get("owner_continuations", [])]
               if item.get("runnable", True) and item.get("closure_blocking", True)]
    host_tasks = [item for item in event.get("background_tasks", [])
                  if item.get("status") in {"running", "pending"}]
    if binding.get("needs_refresh"):
        reason = "Context recovered. Run the current host state command before target work or completion."
    elif unfinished or host_tasks:
        reason = ("Collect the existing execution result and finish owner write-back before stopping; "
                  "independent evidence-backed work may continue while it runs.")
    elif state.get("target_kind") == "list":
        from tools.autopilot_gate import describe_next_step
        reason = describe_next_step(state)
    elif not bound_review:
        reason = ("Continue worthwhile investigation. Before a justified stop, read fresh Closure and record an existing "
                  "Checkpoint global review with termination bound to this session/invocation; a handoff or report is not a stop reason.")
    elif termination["reason"] == "explicit_limit" and not _explicit_limit_reached(binding, termination, round_progress):
        reason = ("The submitted explicit limit has not been reached or does not match this invocation's admitted time/Round limit. "
                  "Keep the actual user/host threshold and continue useful work; estimated usage or a saved handoff cannot end it.")
    elif termination["reason"] == "no_worthwhile_work" and pending:
        reason = "Known runnable owner work remains. Resolve it before claiming no worthwhile work: " + str(pending[0].get("action", ""))[:350]
    elif (pending or closure.get("owner_continuations")) and not review.get("residual_unknowns"):
        reason = "The stop review must preserve current unfinished owner work and reopening conditions in residual_unknowns."
    else:
        return {"allow": True, "reason": termination["reason"], "exhausted": bool(closure.get("can_claim_exhausted"))}
    return {"allow": False, "reason": reason, "basis": json_digest({
        "components": closure.get("snapshot_components"), "reason": reason,
        "tasks": host_tasks, "termination": termination,
    })}


def hook(runtime: Path, data: dict, *, part: int | None, contract_sha256: str) -> dict:
    event = data.get("hook_event_name")
    if data.get("agent_id") or event not in {"SessionStart", "UserPromptSubmit", "Stop", "StopFailure", "SessionEnd"}:
        return {}
    session_id = _identifier(data.get("session_id", ""))
    checkout_cwd = Path(data.get("cwd") or ".").resolve().is_relative_to(REPO_ROOT)
    if not checkout_cwd and not (runtime / ".ccst-autopilot" / session_id / "binding.json").exists():
        return {}
    if part is not None and (part < 0 or event != "SessionStart"):
        raise ValueError("invalid Claude recovery part")
    with session_binding(runtime, session_id) as (binding, path):
        if not checkout_cwd and binding.get("repo_root") != str(REPO_ROOT):
            return {}
        if binding.get("repo_root") not in {None, str(REPO_ROOT)}:
            raise ValueError("Claude session is bound to another checkout")
        active = binding.get("status") in {"active", "suspended"} and bool(binding.get("invocation_id"))
        completed = binding.get("status") == "completed" and bool(binding.get("invocation_id"))
        if event == "UserPromptSubmit":
            prompt = str(data.get("prompt") or "").strip()
            # Claude also emits this hook for its reserved background-result envelope.
            if re.fullmatch(
                r"<task-notification>\s*<task-id>[A-Za-z0-9_-]+</task-id>\s*"
                r"(?:<tool-use-id>[A-Za-z0-9_-]+</tool-use-id>\s*)?"
                r"<output-file>[^<>\r\n]+</output-file>\s*"
                r"<status>(?:completed|failed|killed)</status>\s*"
                r"<summary>[\s\S]*</summary>\s*</task-notification>", prompt
            ):
                return {}
            binding.update(contract_sha256=contract_sha256, prompt_id=uuid.uuid4().hex)
            if prompt.split(maxsplit=1)[0:1] in (["/autopilot"], ["/autopilot-round"]):
                binding["invocation_prompt"] = prompt
            if active:
                binding["status"] = "suspended"
            if completed:
                binding["reopen_prompt_id"] = binding["prompt_id"]
            write_json_atomic(path, binding)
            if active or completed:
                return hook_context(event, f"Autopilot {binding['status']}. Answer questions directly; cancellation/task changes stay inactive. "
                    "Only if the current user request explicitly continues this investigation, enter Refresh with: "
                    + _state_command(runtime, binding) + ". Retain the original limits and use the returned host identity. "
                    "Run recovery.source_context.commands and read every part before work; each CCST_ENTRY hash "
                    "must match source_context.sha256. These bodies supersede prior source instructions. "
                    "No separate resume or Bootstrap; never replay effects to recover registration.")
            return {}
        if event == "SessionStart":
            if data.get("source") == "clear":
                if part is None:
                    write_json_atomic(path, {"session_id": binding["session_id"], "status": "idle", "contract_sha256": contract_sha256})
                return {}
            if not (active or completed):
                if part is None:
                    binding["contract_sha256"] = contract_sha256
                    write_json_atomic(path, binding)
                return {}
            if completed and data.get("source") != "compact" and "reopen_prompt_id" in binding:
                binding.pop("reopen_prompt_id")
                write_json_atomic(path, binding)
            try:
                context = capture_context(REPO_ROOT, round_mode=binding["round_mode"])
            except (OSError, ValueError, KeyError, TypeError):
                binding.update(status="completed" if completed else "suspended", needs_refresh=True)
                write_json_atomic(path, binding)
                raise
            activation = ("Current Autopilot instructions. Automation is INACTIVE; do not apply these instructions "
                          "or resume unless the current user request continues this investigation.\n"
                          if binding["status"] != "active" or data.get("source") != "compact" else "")
            if part is not None:
                chunks = context["chunks"]
                if part >= len(chunks):
                    return {}
                return hook_context(event, activation + f"CCST_RECOVERY {binding['invocation_id']} {context['sha256']} "
                                    f"PART {part + 1}/{len(chunks)}\n" + chunks[part])
            binding["needs_refresh"] = True
            if not completed:
                binding["prompt_id"] = uuid.uuid4().hex
            if not completed and data.get("source") != "compact":
                binding["status"] = "suspended"
            write_json_atomic(path, binding)
            return hook_context(event, activation + "Current complete CCST source bodies follow in numbered parts and supersede prior bodies. "
                "For active/same-task continuation, state_command restores Scope/Auth, owners and memory. "
                "Retain limits and use the returned host identity; incomplete transport is an error. "
                + json.dumps(_host_view(runtime, binding) | {"source_sha256": context["sha256"]}, ensure_ascii=False))
        if event in {"SessionEnd", "StopFailure"}:
            if active and part is None:
                binding["status"] = "idle" if data.get("reason") == "clear" else "suspended"
                write_json_atomic(path, binding)
            elif completed:
                binding.pop("reopen_prompt_id", None)
                if data.get("reason") == "clear":
                    binding["status"] = "idle"
                write_json_atomic(path, binding)
            return {}
        if event == "Stop" and completed:
            binding.pop("reopen_prompt_id", None)
            write_json_atomic(path, binding)
            return {}
        if event != "Stop" or binding.get("status") != "active":
            return {}
        from tools.autopilot_state import build_autopilot_state, load_closure_projection
        state = build_autopilot_state(str(REPO_ROOT), binding["target"], bounded=True, include_goal_memory=False)
        # A batch selects a real target; its list file has no Finding/Checkpoint Store.
        closure = {} if state.get("target_kind") == "list" else load_closure_projection(str(REPO_ROOT), state)
        decision = stop_check(binding, state, closure, data)
        if decision["allow"]:
            binding["status"] = "completed"
            write_json_atomic(path, binding)
            return {}
        batch_blocked = state.get("target_kind") == "list" and state.get("next_action") in {"invalid_batch_target", "batch_failed"}
        if batch_blocked or (data.get("stop_hook_active") and binding.get("last_stop_basis") == decision["basis"]):
            binding["status"] = "suspended"
            write_json_atomic(path, binding)
            return {"continue": False, "stopReason": "CCST_AUTOPILOT_INCOMPLETE: "
                    + (decision["reason"] if batch_blocked else "repeated normal stop without owner progress.")
                    + " Automation is suspended; retained evidence is not completion. " + _state_command(runtime, binding)}
        binding["last_stop_basis"] = decision["basis"]
        write_json_atomic(path, binding)
        return {"decision": "block", "reason": decision["reason"] + "\nHost binding: "
                + json.dumps(_host_view(runtime, binding), ensure_ascii=False)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--contract-sha256", default="")
    parser.add_argument("--ccst-autopilot-host", action="store_true")
    actions = parser.add_subparsers(dest="action", required=True)
    entry = actions.add_parser("entry")
    entry.add_argument("--session-id", required=True)
    entry.add_argument("--round-defaults", action="store_true")
    entry.add_argument("arguments", nargs=argparse.REMAINDER)
    material = actions.add_parser("body")
    material.add_argument("--session-id", help="Accepted for installed commands; body reads are session-independent")
    material.add_argument("--part", type=int, required=True)
    material.add_argument("--round-defaults", action="store_true")
    state = actions.add_parser("state", help="Refresh the bound investigation and rearm its stop check")
    for name in ("session-id", "invocation-id", "prompt-id", "target"):
        state.add_argument("--" + name, required=True)
    hooks = actions.add_parser("hook")
    hooks.add_argument("--part", type=int)
    args = parser.parse_args(argv)
    try:
        if args.action == "body":
            print(body(args.part, round_mode=args.round_defaults))
            return 0
        runtime = claude_runtime_root(args.runtime_root)
        if args.action == "entry":
            arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
            print(start(runtime, args.session_id, arguments, round_mode=args.round_defaults))
        elif args.action == "state":
            print(refresh_state(runtime, args.session_id, args.invocation_id, args.prompt_id, args.target))
        else:
            data = json.load(sys.stdin)
            if not isinstance(data, dict):
                raise ValueError("Claude hook input must be an object")
            print(json.dumps(hook(runtime, data, part=args.part, contract_sha256=args.contract_sha256), ensure_ascii=False))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        message = "CCST_AUTOPILOT_INCOMPLETE: " + " ".join(str(exc).split())[:700]
        if args.action == "hook":
            print(json.dumps({"continue": False, "stopReason": message, "systemMessage": message}))
            return 0
        print(message, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
