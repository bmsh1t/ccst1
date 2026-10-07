"""Target-memory commands must work across real processes and isolated roots."""

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tools import target_memory
from tools.target_store import TargetStore


def _command(root, *args, exit_code=0):
    result = subprocess.run(
        [sys.executable, "-B", str(Path(target_memory.__file__)),
         "--repo-root", str(root), "--json", *args],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == exit_code, result.stderr
    return json.loads(result.stdout)


def test_daily_memory_commands_survive_process_exit_without_global_root_mutation(tmp_path):
    root = tmp_path / "isolated root"
    target = "memory-cli.test"
    store = TargetStore(root, target)
    store.initialize()
    artifact = root / "evidence" / target / "response.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("Recorded object response", encoding="utf-8")
    store.start_attempt(attempt_id="read", source="native", actor="operator",
                        started_at="2026-09-24T00:00:00Z")
    store.record_execution(attempt_id="read", outcome="complete", actor="operator", observations=[{
        "endpoint": f"https://{target}/object", "method": "GET", "family": "Authz",
        "observed_at": "2026-09-24T00:00:00Z", "description": "Recorded response",
        "artifacts": {"response": artifact.relative_to(root).as_posix()},
        "result": "tested_clean", "state_changing": False,
    }])
    operation_id = store.page("operations")["items"][0]["id"]
    selected = _command(root, "set", target, "--goal", "Review ownership boundary",
                        "--command-id", "goal", "--expected-revision", str(store.binding()["revision"]))
    assert selected["target"] == target
    assert selected["receipt"]["entity_id"]
    assert store.active_goal() == "Review ownership boundary"

    commands = [
        ("note", ["Unverified routing note"], "note"),
        ("lead", ["Compare peer session", "--conditions", "same tenant"], "hypothesis"),
        ("next", ["Review saved response"], "handoff"),
        ("fact", ["--key", "routing", "Header changes route"], "note"),
        ("dead-end", ["No peer read", "--conditions", "same tenant", "--reopen-when", "new role",
                      "--operation-ref", f"{operation_id}:0"], "negative"),
        ("pattern", ["Control comparison", "--operation-ref", f"{operation_id}:0"], "primitive"),
        ("handoff", ["Resume comparison", "--next-intent", "Review object ID"], "handoff"),
    ]
    for command, arguments, kind in commands:
        args = [command, *arguments, "--command-id", command]
        saved = _command(root, *args)
        assert saved["target"] == target
        assert saved["receipt"]["entity_id"] == command
        assert store.experience(command)["kind"] == kind
        before = store.binding()
        replayed = _command(root, *args)["receipt"]
        assert replayed == {**saved["receipt"], "replayed": True}
        assert store.binding() == before

    view = _command(root, "show")
    assert view["target"]["active_goal"] == "Review ownership boundary"
    assert {item["entry_id"] for item in view["recent_entries"]} == {row[0] for row in commands}
    assert view["source"]["experience_window"]["total"] == len(commands)
    assert set(json.loads((root / "memory/goals/active.json").read_text())) == {
        "schema_version", "target", "updated_at",
    }
    assert not (root / "memory/goals/targets" / f"{target}.json").exists()
    assert not (root / "memory/goals/sessions").exists()

    other = tmp_path / "other root"
    TargetStore(other, target).initialize()
    assert _command(other, "show", target)["source"]["experience_window"]["total"] == 0
    assert _command(other, "set", "uninitialized.test", exit_code=2)["error"]
    assert not (other / "state/uninitialized.test/metadata.sqlite3").exists()


@pytest.mark.parametrize("arguments", [
    ["note"],
    ["lead", "--structured-json", "{"],
    ["dead-end", "No read", "--conditions", "same tenant", "--reopen-when", "new role",
     "--operation-ref", "not-an-operation"],
    ["set", "memory-cli.test", "--phase", "legacy-phase"],
    ["fact", "--key", "Bad Key!", "invalid"],
    ["handoff"],
    ["note", "--not-a-flag"],
])
def test_memory_cli_bad_input_is_structured_and_does_not_write(tmp_path, arguments):
    store = TargetStore(tmp_path, "memory-cli.test")
    store.initialize()
    before = store.binding()
    if arguments[0] != "set":
        arguments = [*arguments, "--target", store.target]
    result = _command(tmp_path, *arguments, exit_code=2)
    assert result["error"]
    assert store.binding() == before
    assert not (tmp_path / "memory/goals/active.json").exists()


def test_memory_cli_explains_failed_negative_and_recovers_as_advisory_note(tmp_path):
    store = TargetStore(tmp_path, "memory-cli.test")
    store.initialize()
    before = store.binding()
    error = _command(tmp_path, "set", "--goal", "Review peer read", exit_code=2)["error"]
    assert "usage:" in error and "target" in error and "set --help" in error
    error = _command(tmp_path, "dead-end", "--target", store.target, "Peer read denied", exit_code=2)["error"]
    assert all(flag in error for flag in ("--conditions", "--reopen-when", "--operation-ref OPERATION_ID:STEP"))
    assert "note --target TARGET" in error
    assert store.binding() == before
    help_result = subprocess.run(
        [sys.executable, "-B", str(Path(target_memory.__file__)), "dead-end", "--help"],
        capture_output=True, text=True, timeout=20,
    )
    assert help_result.returncode == 0
    assert "OPERATION_ID:0" in help_result.stdout and "zero-based" in help_result.stdout
    assert "--evidence-ref" not in help_result.stdout and "--kind" not in help_result.stdout
    _command(tmp_path, "note", "--target", store.target, "Unverified peer denial",
             "--command-id", "unverified-denial")
    restored = _command(tmp_path, "show", store.target)
    entry = next(e for e in restored["recent_entries"] if e["entry_id"] == "unverified-denial")
    assert entry["kind"] == "note" and entry["evidence_refs"] == []
    assert restored["target"]["current_handoff"] is None
    assert restored["target"]["next_actions"] == []
    assert not (tmp_path / "memory/goals/active.json").exists()


@pytest.mark.parametrize("revision_args", [[], ["--expected-revision", "0"]])
def test_memory_cli_json_reports_committed_goal_when_pointer_publish_fails(tmp_path, monkeypatch, capsys, revision_args):
    store = TargetStore(tmp_path, "memory-cli.test")
    store.initialize()
    original_write = target_memory.write_json

    def fail_pointer(path, payload):
        if path == tmp_path / "memory/goals/active.json":
            raise OSError("pointer publication interrupted")
        original_write(path, payload)

    monkeypatch.setattr(target_memory, "write_json", fail_pointer)
    arguments = [
        "set", store.target, "--goal", "Keep committed intent", "--command-id", "goal",
        "--repo-root", str(tmp_path), "--json", *revision_args,
    ]
    result = target_memory.main(arguments)
    payload = json.loads(capsys.readouterr().out)
    assert result == 2
    assert payload["selection_status"] == "failed"
    assert payload["receipt"]["entity_id"]
    assert store.active_goal() == "Keep committed intent"
    assert not (tmp_path / "memory/goals/active.json").exists()
    monkeypatch.setattr(target_memory, "write_json", original_write)
    before = store.binding()
    assert target_memory.main(arguments) == 0
    assert store.binding() == before


def test_goal_cli_retry_without_revision_preserves_later_intent(tmp_path):
    store = TargetStore(tmp_path, "memory-cli.test")
    store.initialize()
    arguments = ["set", store.target, "--goal", "Original intent", "--command-id", "original"]
    saved = _command(tmp_path, *arguments)
    _command(tmp_path, "set", store.target, "--goal", "Later intent", "--command-id", "later")
    before = store.binding()
    assert _command(tmp_path, *arguments)["receipt"] == {**saved["receipt"], "replayed": True}
    assert store.active_goal() == "Later intent"
    assert _command(tmp_path, "set", store.target, "--goal", "Different content",
                    "--command-id", "original", exit_code=2)["error"]
    assert store.binding() == before


def test_handoff_operation_refs_are_bound_atomic_and_idempotent_across_processes(tmp_path):
    store = TargetStore(tmp_path, "memory-cli.test")
    store.initialize()
    operations = []
    for index in range(2):
        artifact = tmp_path / "evidence" / store.target / f"response-{index}.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(f"Recorded response {index}")
        store.start_attempt(attempt_id=f"read-{index}", source="native", actor="test",
                            started_at="2026-09-30T00:00:00Z")
        receipt = store.record_execution(
            attempt_id=f"read-{index}", outcome="complete", actor="test", observations=[{
                "endpoint": f"https://{store.target}/object", "method": "GET", "family": "Authz",
                "observed_at": "2026-09-30T00:00:00Z", "description": "Recorded response",
                "artifacts": {"response": artifact.relative_to(tmp_path).as_posix()},
                "state_changing": False,
            }],
        )
        operations.append(receipt["entity_id"])
    arguments = ["handoff", "Candidate; impact not established", "--target", store.target,
                 "--command-id", "handoff-bound", "--conditions", "saved response only",
                 "--next-intent", "Compare existing control", "--actor", "session-a"]
    for operation in operations:
        arguments.extend(["--operation-ref", f"{operation}:0"])
    saved = _command(tmp_path, *arguments)
    before = store.binding()
    assert _command(tmp_path, *arguments)["receipt"] == {**saved["receipt"], "replayed": True}
    assert _command(tmp_path, *["Changed statement" if a == "Candidate; impact not established" else a
                                for a in arguments], exit_code=2)["error"]
    assert store.binding() == before
    current = _command(tmp_path, "show", store.target)["target"]["current_handoff"]
    assert current["entry_id"] == "handoff-bound"
    assert current["evidence_refs"] == sorted(f"{operation}:0" for operation in operations)
    assert current["recorded_by"] == "session-a"
    assert current["structured"]["conditions"] == "saved response only"

    for ref in ["bad-ref", f"{operations[0]}:-1", f"{operations[0]}:1", "missing-operation:0"]:
        result = _command(tmp_path, "handoff", "Rejected", "--target", store.target,
                          "--command-id", "rejected", "--operation-ref", ref, exit_code=2)
        assert result["error"]
        assert store.binding() == before
    other = TargetStore(tmp_path, "other.test")
    other.initialize()
    other_before = other.binding()
    assert _command(tmp_path, "handoff", "Foreign reference", "--target", other.target,
                    "--operation-ref", f"{operations[0]}:0", exit_code=2)["error"]
    assert other.binding() == other_before
    assert other.experience_page()["total"] == 0
    assert store.experience_page()["total"] == 1


def test_memory_preserves_raw_url_values_across_processes_and_projections(tmp_path):
    from tools import experience_recall
    from tools.context_pack import build_context_pack, format_context_pack
    from tools.resume import format_resume_output
    from tools.resume_read import load_resume_summary

    root = tmp_path / "isolated root"
    store = TargetStore(root, "raw-memory.test")
    store.initialize()
    baseline = "https://raw-memory.test/search?q=apple"
    variant = "https://raw-memory.test/search?q=apple%27"
    signed = (
        "https://raw-memory.test/search?q=apple&q=apple%27&empty="
        "&encoded=%2527%2f%2F+%20&token=eyJhbGciOiJub25lIn0.eyJmaXh0dXJlIjp0cnVlfQ.fake"
        "&X-Amz-Signature=0123456789abcdef&label=%E8%8B%B9%E6%9E%9C#fixture"
    )
    conditions = f"Synthetic input only: {signed}; 苹果"
    next_intent = f"Compare saved inputs {baseline} versus {variant}; retain {signed}"
    statements = {
        "raw-note": f"Note: {baseline} differs from {variant}; {signed}",
        "raw-handoff": f"Handoff: {variant} is not {baseline}; {signed}",
    }
    for entry_id, statement in statements.items():
        _command(root, entry_id.removeprefix("raw-"), statement,
                 "--target", store.target, "--command-id", entry_id,
                 "--conditions", conditions, "--next-intent", next_intent)
        saved = store.experience(entry_id)
        assert saved["statement"] == statement
        assert saved["conditions"] == conditions
        assert saved["next_intent"] == next_intent

    before = store.binding()
    shown = _command(root, "show", store.target)
    assert {entry["entry_id"]: entry["text"] for entry in shown["recent_entries"]} == statements
    for entry in shown["recent_entries"]:
        assert entry["structured"]["conditions"] == conditions
        assert entry["structured"]["next_intent"] == next_intent

    recall_args = [sys.executable, "-B", str(Path(experience_recall.__file__)),
                   "--repo-root", str(root), "--target", store.target]
    for json_mode in (True, False):
        result = subprocess.run(recall_args + (["--json"] if json_mode else []),
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        if json_mode:
            entries = json.loads(result.stdout)["target_entries"]
            assert {entry["entry_id"]: entry["text"] for entry in entries} == statements
            for entry in entries:
                assert entry["conditions"] == conditions
                assert entry["next_intent"] == next_intent
        else:
            for value in [*statements.values(), conditions, next_intent]:
                assert value in result.stdout

    pack = build_context_pack(root, target=store.target)
    resume = load_resume_summary(root / "hunt-memory", store.target, repo_root=root)
    for memory in (shown["target"], pack["target_experiences"], resume["target_memory"]):
        current = memory["current_handoff"]
        assert current["entry_id"] == "raw-handoff"
        assert current["text"] == statements["raw-handoff"]
        assert current["structured"]["conditions"] == conditions
        assert current["structured"]["next_intent"] == next_intent
        assert [entry["text"] for entry in memory["next_actions"]] == [next_intent]
    for output in (format_context_pack(pack), format_resume_output(resume, store.target)):
        for value in (statements["raw-handoff"], conditions, next_intent):
            assert value in output
    assert store.binding() == before


REPO = Path(__file__).resolve().parents[1]
GUIDANCE_COMMANDS = [
    (document, shlex.split(line, comments=True))
    for document in ("agents/validator.md", "rules/retrospective.md", "commands/retrospect.md")
    for block in re.findall(r"```bash\n(.*?)```", (REPO / document).read_text(), re.S)
    for line in block.replace("\\\n", " ").splitlines()
    if line.startswith(("python3 tools/target_memory.py", "python3 tools/target_store.py",
                        "python3 tools/experience_recall.py"))
]


def _guidance_command(root, command, *, operation_id="", exit_code=0):
    replacements = {"TARGET": "guidance.test", "FINDING_ID": "selected",
                    "OPERATION_ID:0": f"{operation_id}:0"}
    arguments = [replacements.get(token, token) for token in command[2:]]
    if command[1] == "tools/target_memory.py":
        return _command(root, *arguments, exit_code=exit_code)
    result = subprocess.run(
        [sys.executable, "-B", str(REPO / command[1]), *arguments,
         "--repo-root", str(root),
         *(["--json"] if command[1] == "tools/experience_recall.py" else [])],
        cwd=root, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == exit_code, result.stderr
    if exit_code:
        assert result.stderr or json.loads(result.stdout)["error"]
        return None
    return json.loads(result.stdout)


def _guidance_files(root):
    # SQLite read bookkeeping is not a domain write; binding is checked separately.
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*")
            if path.is_file() and not path.name.startswith("metadata.sqlite3")}


def _guidance_observation(store):
    raw = store.root / "evidence" / store.target / "response.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("Recorded peer response", encoding="utf-8")
    store.start_attempt(attempt_id="read", source="native", actor="operator",
                        started_at="2026-10-07T00:00:00Z")
    receipt = store.record_execution(
        attempt_id="read", outcome="complete", actor="operator",
        candidate={"id": "selected", "endpoint": f"https://{store.target}/object",
                   "method": "GET", "family": "Authz", "title": "Current claim",
                   "claim": "Compare recorded peer response"},
        observations=[{
            "endpoint": f"https://{store.target}/object", "method": "GET", "family": "Authz",
            "observed_at": "2026-10-07T00:00:00Z", "description": "Recorded peer response",
            "artifacts": {"response": raw.relative_to(store.root).as_posix()},
            "state_changing": False,
        }],
    )
    return receipt["entity_id"]


@pytest.mark.parametrize("mode", ["current", "empty", "missing"])
def test_documented_guidance_reads_current_store_without_mutation(tmp_path, mode):
    commands = [(document, command) for document, command in GUIDANCE_COMMANDS
                if command[1] != "tools/target_memory.py" or command[2] == "show"]
    assert len(commands) == 11
    store = TargetStore(tmp_path, "guidance.test")
    if mode != "missing":
        store.initialize()
    if mode == "current":
        operation_id = _guidance_observation(store)
        store.assess(command_id="assessment", finding_id="selected", verdict="confirmed",
                     reason="Reviewed response", boundary="Peer boundary", impact="Peer read",
                     evidence=[{"operation_id": operation_id, "step": 0}],
                     actor="operator", expected_assessment=None)
        store.decide_delivery(command_id="delivery", finding_id="selected", assessment_id="assessment",
                              destination="internal-review", status="eligible", reason="Reviewed",
                              actor="operator", expected_decision=None)
        report = tmp_path / "reports" / store.target / "selected.md"
        report.parent.mkdir(parents=True)
        report.write_text("Recorded peer comparison", encoding="utf-8")
        store.register_report(command_id="report", report_id="report", finding_id="selected",
                              assessment_id="assessment", delivery_id="delivery",
                              artifact=str(report), actor="operator")
        store.create_finding(command_id="other", finding_id="other",
                             endpoint=f"https://{store.target}/other", method="GET", family="Authz",
                             title="Other claim", claim="Unassessed", actor="operator")
        store.remember(command_id="current-note", kind="note", statement="Current note",
                       conditions="saved response", reopen_when="", next_intent="",
                       evidence=[], actor="operator")
    for relative in (f"memory/goals/targets/{store.target}.json",
                     f"hunt-memory/targets/{store.target}.json",
                     f"findings/{store.target}/findings.json", "findings/last-validate.json"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"finding_id":"other","statement":"LEGACY_ONLY"}\n')
    pointer = tmp_path / "memory/goals/active.json"
    pointer.write_text('{"schema_version":1,"target":"other.test","updated_at":"2026-10-07T00:00:00Z"}')
    before = _guidance_files(tmp_path)
    binding = store.binding() if mode != "missing" else None
    for document, command in commands:
        selected = "--id" in command
        fails = mode == "missing" or (selected and mode == "empty")
        result = _guidance_command(tmp_path, command, exit_code=2 if fails else 0)
        assert "LEGACY_ONLY" not in json.dumps(result), document
        if fails:
            continue
        if command[1] == "tools/target_store.py":
            if selected:
                assert result["id"] == "selected"
                assert result["assessment"]["id"] == "assessment"
                assert result["assessment"]["evidence"] == [{"operation_id": operation_id, "step": 0}]
                assert result["evidence"] == result["assessment"]["evidence"]
                assert result["deliveries"][0]["id"] == "delivery"
                assert result["reports"][0]["artifact_ref"] == report.relative_to(tmp_path).as_posix()
            else:
                assert {item["id"] for item in result["items"]} == (
                    {"selected", "other"} if mode == "current" else set())
        else:
            entries = result["recent_entries"] if command[1] == "tools/target_memory.py" else result["target_entries"]
            assert [item["text"] for item in entries] == (["Current note"] if mode == "current" else [])
    assert _guidance_files(tmp_path) == before
    if mode == "missing":
        assert not store.path.exists()
    else:
        assert store.binding() == binding


def test_documented_memory_writes_preserve_conditions_and_reject_incomplete_negative(tmp_path):
    store = TargetStore(tmp_path, "guidance.test")
    store.initialize()
    writes = [command for _, command in GUIDANCE_COMMANDS
              if command[1] == "tools/target_memory.py" and command[2] != "show"]
    assert {command[2] for command in writes} == {"lead", "next", "dead-end", "handoff", "note"}
    # The documented no-evidence alternative must work before any execution exists.
    note = next(command for command in writes if command[2] == "note")
    saved = _guidance_command(tmp_path, note)
    entry = store.experience(saved["receipt"]["entity_id"])
    assert entry["kind"] == "note" and entry["evidence"] == []
    restored = _command(tmp_path, "show", store.target)
    assert restored["recent_entries"][0]["text"] == note[-1]
    assert restored["recent_entries"][0]["evidence_refs"] == []
    assert restored["target"]["current_handoff"] is None
    assert store.page("operations")["total"] == 0
    operation_id = _guidance_observation(store)
    for command in writes:
        if command[2] == "note":
            continue
        saved = _guidance_command(tmp_path, command, operation_id=operation_id)
        entry_id = saved["receipt"]["entity_id"]
        entry = store.experience(entry_id)
        assert entry["kind"] == {"lead": "hypothesis", "next": "handoff",
                                 "handoff": "handoff", "dead-end": "negative"}[command[2]]
        assert entry["statement"] == command[-1]
        for flag, field in (("--conditions", "conditions"), ("--reopen-when", "reopen_when"),
                            ("--next-intent", "next_intent")):
            if flag in command:
                assert entry[field] == command[command.index(flag) + 1]
        if command[2] == "next":
            assert entry["next_intent"] == command[-1]
        expected_refs = [{"operation_id": operation_id, "step": 0}] if "--operation-ref" in command else []
        assert entry["evidence"] == expected_refs
        restored = _command(tmp_path, "show", store.target)
        recovered = next(item for item in restored["recent_entries"] if item["entry_id"] == entry_id)
        assert recovered["text"] == entry["statement"]
        assert recovered["evidence_refs"] == ([f"{operation_id}:0"] if expected_refs else [])
        for field in ("conditions", "reopen_when", "next_intent"):
            assert recovered["structured"].get(field, "") == entry[field]
    before, files = store.binding(), _guidance_files(tmp_path)
    negative = next(command for command in writes if command[2] == "dead-end")
    for flag in ("--conditions", "--reopen-when", "--operation-ref"):
        command = negative.copy()
        index = command.index(flag)
        del command[index:index + 2]
        assert _guidance_command(tmp_path, command, operation_id=operation_id, exit_code=2)["error"]
        assert store.binding() == before
        assert _guidance_files(tmp_path) == files
    assert store.page("actions")["total"] == 0
    assert not (tmp_path / "memory/goals/active.json").exists()
