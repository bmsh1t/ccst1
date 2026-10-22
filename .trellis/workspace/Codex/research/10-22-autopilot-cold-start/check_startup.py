"""Exercise real Autopilot startup in a disposable, offline source/runtime copy."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parents[5]
BASELINE = "f98398a"
PREEXISTING = ("tools/autopilot_state.py", "tools/surface_projection.py")


def isolated(root: Path) -> None:
    denied = []

    def audit(event, args):
        if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn"}:
            denied.append(event)
            raise RuntimeError(f"offline check forbids {event}")
        if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0])).resolve()
            if ("tests" in path.parts or path.is_relative_to(REPO)
                    or any(path.is_relative_to(Path(value)) for value in ("/root/.claude", "/root/.codex"))):
                denied.append(str(path))
                raise RuntimeError(f"isolated check forbids opening {path}")

    sys.addaudithook(audit)
    sys.path.insert(0, str(root))
    from tools.autopilot_bootstrap import build_autopilot_bootstrap, render_autopilot_bootstrap_json
    from tools.autopilot_continuation import create_continuation
    from tools.autopilot_round import prepare_round
    from tools.autopilot_state import build_autopilot_bootstrap_state, build_autopilot_state
    from tools.autopilot_loop_guard import _load_loop_guard_projection
    from tools.runtime_doctor import RUNTIME_SUBDIRS
    from tools.target_store import StoreError, TargetStore, initialize_target_store

    runtime = root / "runtime"
    receipt = {}
    for kind, destination in RUNTIME_SUBDIRS.items():
        shutil.copytree(root / kind, runtime / destination)
        for path in (runtime / destination).rglob("*"):
            if path.is_file():
                receipt[path.relative_to(runtime).as_posix()] = {
                    "kind":kind, "sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                }
    (runtime / ".ccst-installed.json").write_text(json.dumps(receipt))

    results = []

    def boot(argv, *, round_defaults=False):
        return build_autopilot_bootstrap(
            argv, cwd=root, repo_root=root, runtime_root=runtime, round_defaults=round_defaults,
        )

    def accepted(payload):
        assert payload["action"] == "continue", payload
        assert payload["runtime"]["critical_clean"] is True, payload["runtime"]

    def no_store(target):
        assert not TargetStore(root, target).path.exists(), target

    assert boot([])["action"] == "ask_target"
    invalid = boot(["invalid-args.invalid", "--max-lanes", "0"])
    assert invalid["action"] != "continue"
    no_store("invalid-args.invalid")
    assert not (root / "state").exists()
    results.append("missing/invalid arguments stop before target writes")

    query_target = "query-only.invalid"
    try:
        build_autopilot_bootstrap_state(str(root), query_target)
    except StoreError as exc:
        assert "not initialized" in str(exc)
    else:
        raise AssertionError("ordinary state reader initialized an absent Store")
    no_store(query_target)
    results.append("ordinary state query remains read-only and requires initialization")

    (root / "bad-context.json").write_text("{}\n")
    invalid_context = boot(["bad-context.invalid", "--context-file=bad-context.json"])
    assert invalid_context["action"] == "stop_invalid_context", invalid_context
    no_store("bad-context.invalid")
    for target, content in (
        ("bad-json.invalid", '{"headers":'),
        ("bad-shape.invalid", '{"allowed_origins": 7}'),
        ("wrong-auth.invalid", '{"target":"another.invalid","bearer":"fixture-secret"}'),
        ("bad-header.invalid", json.dumps({"headers":["Authorization: fixture-secret\r\nX-Injected: x"]})),
    ):
        (root / "auth.json").write_text(content)
        payload = boot([target, "--auth-file", "auth.json"])
        assert payload["action"] == "stop_invalid_context", payload
        assert "fixture-secret" not in render_autopilot_bootstrap_json(payload)
        no_store(target)
    results.append("invalid context, malformed credentials and target mismatch stop before initialization")

    scope_store = TargetStore(root, "bad-scope.invalid")
    scope_store.path.parent.mkdir(parents=True, mode=0o700)
    (scope_store.path.parent / "scope.json").write_text('{"schema_version":1,"root_target":"other.invalid"}')
    assert boot([scope_store.target])["action"] == "stop_invalid_scope"
    no_store(scope_store.target)
    results.append("invalid explicit Scope cannot create a Store")

    seed = "https://fresh.invalid/app?seed=1"
    fresh = boot([seed, "--quick"])
    accepted(fresh)
    store = TargetStore(root, "fresh.invalid")
    assert store.backend() == "primary"
    assert fresh["arguments"]["seed_url"] == seed
    assert "--quick" in fresh["arguments"]["recon_flags"]
    assert fresh["state"]["next_action"] == "handoff"
    assert "commands/autopilot.md#shared-automation" in fresh["state"]["next_step"]
    assert "no Recon or checkpoint prerequisite" not in fresh["state"]["next_step"]
    state = build_autopilot_state(str(root), store.target, bounded=True)
    assert isinstance(_load_loop_guard_projection(root, state), dict)
    results.append("fresh ordinary startup initializes the real Store; seed/quick flags and loop-check work")

    store.set_active_goal(command_id="goal", goal="preserve the investigation", actor="check")
    store.remember(command_id="note", kind="note", statement="retained context", conditions="same target",
                   reopen_when="", next_intent="continue the pending question", evidence=[], actor="check")
    store.create_action(command_id="action", action_id="pending-work", intent="review supplied material",
                        execution_key="review-material", actor="check", kind="work", subject={"target":store.target})
    before = (store.binding(), store.active_goal(), store.experience_page(), store.action_page())
    protected = {path: path.read_bytes() for path in (store.fence_path, store.path.parent / "scope.json")}
    resumed = boot([store.target])
    accepted(resumed)
    assert before == (store.binding(), store.active_goal(), store.experience_page(), store.action_page())
    assert all(path.read_bytes() == data for path, data in protected.items())
    assert resumed["state"]["next_action"] != "run_recon"
    assert "preserve the investigation" in render_autopilot_bootstrap_json(resumed)
    results.append("repeat startup preserves Store identity/revision, goal, experience, Action, Scope and fence")

    round_target = "round-fresh.invalid"
    accepted(boot([round_target], round_defaults=True))
    started = prepare_round(root, round_target, 16)
    assert started["status"] == "started", started
    resumed_round = prepare_round(root, round_target, 16)
    assert resumed_round["status"] == "resumed", resumed_round
    assert started["round_progress"] == resumed_round["round_progress"]
    results.append("fresh Round prepare starts after Bootstrap; replay preserves its round and budget")

    batch = root / "targets.txt"
    batch.write_text("child-auth.invalid\nchild-anonymous.invalid\nchild-wrong-auth.invalid\n")
    accepted(boot([str(batch)]))
    no_store("child-auth.invalid")
    no_store("child-anonymous.invalid")
    results.append("list Bootstrap reads batch state without initializing unselected targets")

    (root / "auth.json").write_text('{"target":"child-auth.invalid","bearer":"fixture-secret"}')
    accepted(boot([str(batch), "--auth-file", "auth.json"]))
    no_store("child-auth.invalid")
    continuation = create_continuation(root, parent_target=str(batch), selected_target="child-auth.invalid",
                                       auth_file=root / "auth.json")
    bound = boot(["child-auth.invalid", f"--context-file={continuation['path']}"])
    accepted(bound)
    assert bound["continuation"]["selected_target"] == "child-auth.invalid"
    assert "--auth-file" in bound["arguments"]["hunt_auth_flags"]
    assert "--context-file" in bound["arguments"]["hunt_auth_flags"]
    assert "fixture-secret" not in render_autopilot_bootstrap_json(bound)
    wrong_child = create_continuation(root, parent_target=str(batch), selected_target="child-wrong-auth.invalid",
                                     auth_file=root / "auth.json")
    rejected_child = boot(["child-wrong-auth.invalid", f"--context-file={wrong_child['path']}"])
    assert rejected_child["action"] == "stop_invalid_context", rejected_child
    no_store("child-wrong-auth.invalid")
    results.append("list accepts child-bound auth; selected child validates binding and rejects a mismatch before init")
    anonymous = create_continuation(root, parent_target=str(batch), selected_target="child-anonymous.invalid")
    os.environ["BBHUNT_BEARER"] = "ambient-secret"
    env_before = dict(os.environ)
    anon = boot(["child-anonymous.invalid", f"--context-file={anonymous['path']}"])
    accepted(anon)
    assert not anon["arguments"]["auth_file"]
    assert "ambient-secret" not in render_autopilot_bootstrap_json(anon)
    assert dict(os.environ) == env_before
    results.append("bound/anonymous child startup retains parent Scope/context without publishing or inheriting auth")

    legacy = TargetStore(root, "legacy.invalid")
    legacy.path.parent.mkdir(parents=True, mode=0o700)
    legacy_file = legacy.path.parent / "action_queue.json"
    legacy_file.write_text("{}\n")
    assert boot([legacy.target])["action"] == "stop_state_error"
    no_store(legacy.target)
    assert legacy_file.read_text() == "{}\n"
    preview = TargetStore(root, "preview.invalid", allow_preview=True)
    preview.initialize(allow_legacy=True)
    preview_bytes = preview.path.read_bytes()
    assert boot([preview.target])["action"] == "stop_invalid_context"
    assert preview.path.read_bytes() == preview_bytes
    assert preview.backend() == "preview"
    for target, damaged in (("fenced-missing.invalid", False), ("damaged.invalid", True)):
        initialize_target_store(root, target)
        rejected = TargetStore(root, target)
        fence = rejected.fence_path.read_bytes()
        if damaged:
            rejected.path.write_bytes(b"damaged database")
        else:
            rejected.path.unlink()
        assert boot([target])["action"] == "stop_invalid_context"
        assert rejected.fence_path.read_bytes() == fence
        if damaged:
            assert rejected.path.read_bytes() == b"damaged database"
        else:
            no_store(target)
    results.append("legacy, preview, missing-fenced and damaged Stores are refused without migration/replacement")

    installed_command = runtime / "commands/autopilot.md"
    original = installed_command.read_bytes()
    installed_command.write_bytes(original + b"\nruntime drift\n")
    assert boot(["drift.invalid"])["action"] == "stop_runtime_drift"
    no_store("drift.invalid")
    installed_command.write_bytes(original)
    results.append("real critical runtime drift stops before initialization")

    command = (root / "commands/autopilot.md").read_text()
    round_command = (root / "commands/autopilot-round.md").read_text()
    assert "A new/empty target with no prior work or usable supplied request/source/browser" in command
    assert "evidence starts with `/recon`" in command
    assert "Supplied usable evidence may start the investigation directly" in command
    assert "Existing-target gaps mandate neither Recon nor Checkpoint" in command
    assert "Recon default applies after the round starts and its selected lane is claimed" in round_command
    for name, current in (("autopilot.md", command), ("autopilot-round.md", round_command)):
        previous = (root / "baseline" / name).read_text()
        assert current.split("---", 2)[1] == previous.split("---", 2)[1]
        assert [line for line in current.splitlines() if "!`python3" in line] == [
            line for line in previous.splitlines() if "!`python3" in line]
    start, end = "<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST", "AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->"
    assert command.split(start, 1)[1].split(end, 1)[0] == (root / "baseline/autopilot.md").read_text().split(start, 1)[1].split(end, 1)[0]
    assert "Native fixed-loop prompt identity (do not reinterpret): `/autopilot-round $ARGUMENTS`" in round_command
    results.append("Claude entry contracts retain fresh Recon/evidence exception, claim ordering and runtime identities")

    for name, module in list(sys.modules.items()):
        if name.split(".")[0] in {"tools", "memory", "contracts"} and getattr(module, "__file__", None):
            assert Path(module.__file__).resolve().is_relative_to(root), name
    assert not denied, denied
    print(json.dumps({"status":"passed", "baseline_readers":BASELINE, "checks":results,
                      "network_or_private_runtime_attempts":0, "claude_host_tested":False}, ensure_ascii=False, indent=2))


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--isolated":
        isolated(Path(sys.argv[2]).resolve())
        return
    protected = {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in PREEXISTING}
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "tools", "memory", "contracts", "knowledge/capabilities.yaml",
         "commands", "agents", "skills"], cwd=REPO,
    ).decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="ccst-autopilot-cold-start-") as directory:
        root = Path(directory)
        for relative in filter(None, tracked):
            path = Path(relative)
            assert "tests" not in path.parts
            if path.parts[0] in {"tools", "memory", "contracts"} and path.suffix not in {".py", ".sh"}:
                continue
            source = REPO / relative
            assert source.is_file() and not source.is_symlink() and source.resolve().is_relative_to(REPO), relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        for relative in PREEXISTING:
            (root / relative).write_bytes(subprocess.check_output(["git", "show", f"{BASELINE}:{relative}"], cwd=REPO))
        (root / "baseline").mkdir()
        for name in ("autopilot.md", "autopilot-round.md"):
            (root / "baseline" / name).write_bytes(subprocess.check_output(["git", "show", f"{BASELINE}:commands/{name}"], cwd=REPO))
        env = {key:value for key, value in os.environ.items() if not key.startswith(("BBHUNT_", "HUNT_", "CCST_", "CLAUDE_"))}
        env.update(HUNT_MEMORY_DIR=str(root / "hunt-memory"), CCST_RUNTIME_ROOT=str(root / "runtime"),
                   PYTHONPATH=str(root), PYTHONDONTWRITEBYTECODE="1")
        run = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--isolated", str(root)],
                             cwd=root, env=env, capture_output=True, text=True, timeout=60)
        assert run.returncode == 0, run.stderr + run.stdout
        print(run.stdout, end="")
    assert protected == {name:hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in PREEXISTING}


if __name__ == "__main__":
    main()
