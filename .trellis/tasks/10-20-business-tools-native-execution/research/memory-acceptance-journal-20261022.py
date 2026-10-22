"""Focused synthetic remember/journal recovery acceptance, outside project tests/."""
from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
ORIGIN = Path(__file__).resolve().parents[4]
BASELINE = "fb1704076e477cc67e24611f6b563089d5fa45c1"
OVERLAY = ()
START = time.monotonic()
CHECKS = 0


def check(condition, description):
    global CHECKS
    if not condition:
        raise AssertionError(description)
    CHECKS += 1


def raises(exception, call):
    try:
        call()
    except exception as exc:
        check(True, f"expected {exception.__name__}")
        return exc
    raise AssertionError(f"expected {exception.__name__}")


GUARD = '''import os, runpy, sys
from pathlib import Path
sys.dont_write_bytecode = True
def guard(event, args):
    if event in {'socket.connect', 'socket.connect_ex', 'socket.getaddrinfo'}:
        raise RuntimeError('fixture forbids network')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        path = Path(os.fsdecode(args[0])).absolute()
        roots = [Path(os.environ['CCST_CHECK_ORIGIN']), Path('/root/.claude'), Path('/root/.codex')]
        if any(root == path or root in path.parents for root in roots) or 'tests' in path.parts:
            raise RuntimeError('fixture forbids private/original/project-test reads')
sys.addaudithook(guard)
'''
CLI_GUARD = GUARD + '''
mode, script = sys.argv[1], Path(sys.argv[2])
sys.path[:0] = [str(script.parent.parent), str(script.parent)]
if mode == 'fail':
    from memory.hunt_journal import HuntJournal
    def fail(self, entry):
        raise OSError('synthetic journal unavailable')
    HuntJournal._append_locked = fail
sys.argv = [str(script), *sys.argv[3:]]
runpy.run_path(str(script), run_name='__main__')
'''


with tempfile.TemporaryDirectory(prefix="ccst-remember-journal-") as temporary:
    fixture = Path(temporary)
    runtime = fixture / "checkout"
    runtime.mkdir(mode=0o700)
    names = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", BASELINE, "--", "tools", "memory"],
        cwd=ORIGIN, text=True).splitlines()
    selected = [name for name in names if Path(name).suffix in {".py", ".sh"}
                and "tests" not in Path(name).parts]
    archive = subprocess.check_output(["git", "archive", BASELINE, "--", *selected], cwd=ORIGIN)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        for member in bundle.getmembers():
            if member.isfile():
                destination = runtime / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(bundle.extractfile(member).read())
    for name in OVERLAY:
        (runtime / name).write_bytes((ORIGIN / name).read_bytes())
    (runtime / "knowledge").mkdir()
    (runtime / "knowledge/capabilities.yaml").write_text("capabilities: []\ncontracts: {}\n")
    host = fixture / "host"
    host.mkdir()
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ}
    environment.update(PYTHONPATH=str(runtime), PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                       HUNT_MEMORY_DIR=str(fixture / "memory"), CCST_RUNTIME_ROOT=str(host),
                       CCST_CHECK_ORIGIN=str(ORIGIN))
    wrapper = fixture / "cli-guard.py"
    wrapper.write_text(CLI_GUARD)
    os.environ.clear()
    os.environ.update(environment)
    os.chdir(runtime)
    sys.path[:0] = [str(runtime), str(runtime / "tools")]
    exec(GUARD, {"__name__": "fixture_guard"})

    from memory.hunt_journal import HuntJournal, JournalConflictError, JournalIntegrityError
    from memory.schemas import SchemaError, make_journal_entry, validate_journal_entry
    from tools.memory_gc import do_purge, do_rotate
    from tools.remember import RememberJournalError, remember_finding
    from tools.target_store import StoreError, initialize_target_store, runtime_store

    target = "journal-fixture.invalid"
    initialize_target_store(runtime, target)
    store = runtime_store(runtime, target)
    memory = fixture / "memory"
    path = memory / "journal.jsonl"

    def arguments(command_id, **overrides):
        return dict(memory_dir=memory, repo_root=runtime, target=target,
                    vuln_class="idor", endpoint="/synthetic", result="informational",
                    notes="synthetic recovery note", actor="fixture", command_id=command_id, **overrides)

    def rows(directory=memory):
        output = []
        for candidate in directory.glob("journal.jsonl*"):
            if candidate.is_file():
                output.extend(json.loads(line) for line in candidate.read_bytes().splitlines() if line.strip())
        return output

    def count(command_id, directory=memory):
        return sum(row.get("command_id") == command_id for row in rows(directory))

    # Normal replay preserves both owners, including original session metadata.
    with patch.dict(os.environ, BBHUNT_SESSION_ID="original-session"):
        first = remember_finding(**arguments("remember:normal"))
    binding, original = store.binding(), path.read_bytes()
    with patch.dict(os.environ, BBHUNT_SESSION_ID="retry-session"):
        replay = remember_finding(**arguments("remember:normal"))
    check(first["journal_saved"] and not replay["journal_saved"] and replay["journal_replayed"], "one journal row")
    check(store.binding() == binding and path.read_bytes() == original, "replay preserves Store and original journal")
    check(first["store_id"] == binding["store_id"] and count("remember:normal") == 1, "Store-bound journal key")

    # Failed append after commit: retry fills the gap without another Store revision.
    with patch.object(HuntJournal, "_append_locked", side_effect=OSError("synthetic unavailable")):
        failure = raises(RememberJournalError, lambda: remember_finding(**arguments("remember:recover")))
    committed = store.binding()
    check(failure.summary["status"] == "partial" and failure.summary["experience_saved"], "partial keeps committed receipt")
    check(failure.summary["command_id"] == "remember:recover" and failure.summary["journal_status"] == "unconfirmed", "retry ID and unconfirmed log")
    recovered = remember_finding(**arguments("remember:recover"))
    check(recovered["experience_replayed"] and recovered["journal_saved"], "Store replay repairs journal")
    check(store.binding() == committed and count("remember:recover") == 1, "repair creates no duplicate experience")

    # Short writes undo only their own incomplete tail, preserving previous bytes.
    before = path.read_bytes()
    real_write = os.write
    def short_write(fd, data):
        return real_write(fd, data[:len(data) // 2])
    with patch("memory.hunt_journal.os.write", side_effect=short_write):
        raises(RememberJournalError, lambda: remember_finding(**arguments("remember:short")))
    committed = store.binding()
    check(path.read_bytes() == before, "short-write rollback preserves prior bytes")
    check(remember_finding(**arguments("remember:short"))["journal_saved"], "short-write retry completes")
    check(store.binding() == committed and count("remember:short") == 1, "short-write recovery is idempotent")

    # Complete writes followed by failed acknowledgement or fsync must not duplicate.
    append_locked = HuntJournal._append_locked
    def failed_ack(self, entry):
        append_locked(self, entry)
        raise OSError("synthetic acknowledgement lost")
    for command_id, fault in (("remember:ack", patch.object(HuntJournal, "_append_locked", failed_ack)),
                              ("remember:sync", patch("memory.hunt_journal.os.fsync", side_effect=OSError("synthetic sync failure")))):
        with fault:
            raises(RememberJournalError, lambda: remember_finding(**arguments(command_id)))
        committed = store.binding()
        check(not remember_finding(**arguments(command_id))["journal_saved"], "complete row survives failure")
        check(store.binding() == committed and count(command_id) == 1, "complete-write retry never duplicates")

    # Journal-only payload changes are conflicts even when Store content replays.
    before, committed = path.read_bytes(), store.binding()
    conflict_args = arguments("remember:normal", severity="high")
    conflict = raises(RememberJournalError, lambda: remember_finding(**conflict_args))
    check(conflict.summary["error_type"] == "JournalConflictError", "severity conflict is explicit")
    check(path.read_bytes() == before and store.binding() == committed, "conflict changes neither owner")
    changed = arguments("remember:normal")
    changed["notes"] = "different synthetic note"
    raises(StoreError, lambda: remember_finding(**changed))

    # All existing numeric backups participate, independent of default retention.
    path.rename(memory / "journal.jsonl.7")
    check(not remember_finding(**arguments("remember:normal"))["journal_saved"], "custom backup prevents duplicate")
    check(not path.exists(), "backup-only replay does not recreate live file")
    with contextlib.redirect_stdout(io.StringIO()):
        check(do_purge(memory, keep=7) == 1, "GC purges explicitly retained backup")
    check(remember_finding(**arguments("remember:normal"))["journal_saved"], "purged binding can restore a row")
    check(store.binding() == committed, "retention recovery leaves Store unchanged")

    # Old schema bytes stay readable; an old replay cannot infer unbound ownership.
    legacy_memory = fixture / "legacy"
    legacy = make_journal_entry(target, "remember", "idor", "/synthetic", "informational",
                                notes="synthetic recovery note", tags=[])
    legacy_journal = HuntJournal(legacy_memory / "journal.jsonl")
    legacy_journal.append(legacy)
    legacy_bytes = legacy_journal.path.read_bytes()
    legacy_args = arguments("remember:normal")
    legacy_args["memory_dir"] = legacy_memory
    repaired = remember_finding(**legacy_args)
    check(repaired["journal_saved"] and repaired.get("journal_recovery_note"), "unbound replay boundary is visible")
    check(legacy_journal.path.read_bytes().startswith(legacy_bytes), "legacy bytes are preserved")
    check(not remember_finding(**legacy_args)["journal_saved"] and count("remember:normal", legacy_memory) == 1, "new binding is idempotent")
    for field, value in (("command_id", ""), ("store_id", None), ("command_id", 3)):
        invalid = dict(legacy, command_id="c", store_id="s")
        invalid[field] = value
        raises(SchemaError, lambda: validate_journal_entry(invalid))
    raises(SchemaError, lambda: validate_journal_entry(dict(legacy, command_id="only-one-binding")))
    roundtrip = dict(legacy, command_id="tuple-roundtrip", store_id="synthetic-store", notes=("a",))
    check(legacy_journal.append_once(roundtrip), "JSON representation is accepted")
    check(not legacy_journal.append_once(roundtrip), "same JSON representation replays without a false conflict")

    # Same command ID in distinct target/Store namespaces never aliases.
    other_target = "other-journal-fixture.invalid"
    initialize_target_store(runtime, other_target)
    other_args = arguments("remember:normal")
    other_args["target"] = other_target
    other = remember_finding(**other_args)
    check(other["journal_saved"] and count("remember:normal") == 2, "cross-target commands are separate")
    foreign_entry = dict(rows()[0], store_id="synthetic-other-store")
    check(HuntJournal(path).append_once(foreign_entry), "same target command in different Store is separate")

    # Corruption fails visibly and preserves old bytes, rather than claiming a gap is repaired.
    for index, bad in enumerate((b'{broken}\n', b'{}\n', b'{"unfinished":', b'\xff\n')):
        bad_memory = fixture / f"bad-{index}"
        bad_memory.mkdir()
        bad_path = bad_memory / "journal.jsonl"
        bad_path.write_bytes(bad)
        bad_args = arguments(f"remember:bad-{index}")
        bad_args["memory_dir"] = bad_memory
        failed = raises(RememberJournalError, lambda: remember_finding(**bad_args))
        check(failed.summary["error_type"] == "JournalIntegrityError" and bad_path.read_bytes() == bad, "corruption is explicit and unchanged")

    # Real competing processes: command replay, ordinary append and GC rotation share a lock.
    race_memory = fixture / "race"
    race_memory.mkdir()
    race_args = arguments("remember:race")
    race_args["memory_dir"] = race_memory
    context = multiprocessing.get_context("fork")
    ready, outputs = context.Event(), context.Queue()
    def racer(kind):
        ready.wait(5)
        try:
            if kind == "remember":
                for _ in range(3):
                    remember_finding(**race_args)
            elif kind == "append":
                for index in range(4):
                    HuntJournal(race_memory / "journal.jsonl").append(dict(legacy, notes=f"ordinary-{index}"))
            else:
                with contextlib.redirect_stdout(io.StringIO()):
                    for _ in range(4):
                        do_rotate(race_memory, max_bytes=1, keep=20)
            outputs.put(None)
        except Exception as exc:
            outputs.put(f"{type(exc).__name__}: {exc}")
    processes = [context.Process(target=racer, args=(kind,)) for kind in ("remember", "remember", "append", "rotate")]
    for process in processes:
        process.start()
    ready.set()
    for process in processes:
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
        check(process.exitcode == 0, "concurrent process completed")
    check([outputs.get(timeout=2) for _ in processes] == [None] * len(processes), "concurrent owners succeeded")
    check(count("remember:race", race_memory) == 1 and len(rows(race_memory)) == 5, "one command row plus every ordinary append")

    # Real CLI JSON: generated IDs survive a partial and make recovery practical.
    def cli(mode, *extra, expected=0):
        result = subprocess.run([sys.executable, "-B", str(wrapper), mode, str(runtime / "tools/remember.py"),
                                 "--repo-root", str(runtime), "--memory-dir", str(fixture / "cli-memory"),
                                 "--target", target, "--vuln-class", "idor", "--endpoint", "/cli",
                                 "--result", "informational", "--notes", "synthetic CLI note", "--json", *extra],
                                cwd=runtime, env=environment, capture_output=True, text=True, timeout=10)
        check(result.returncode == expected and "Traceback" not in result.stderr, "CLI exit without traceback")
        return json.loads(result.stdout)
    partial = cli("fail", expected=2)
    check(partial["status"] == "partial" and partial["store_receipt"]["entity_id"] == partial["experience_id"], "CLI preserves receipt")
    check(partial["command_id"] and partial["recovery"]["command_id"] == partial["command_id"], "generated ID is recoverable")
    committed = store.binding()
    complete = cli("normal", "--command-id", partial["command_id"])
    replay = cli("normal", "--command-id", partial["command_id"])
    check(complete["journal_saved"] and replay["journal_replayed"] and store.binding() == committed, "CLI retry repairs only journal")

    # Execute only reset's journal-filter block on synthetic rows, never reset_target.sh.
    reset_source = (runtime / "tools/reset_target.sh").read_text()
    block = reset_source.split('FILTERED=$(python3 - ', 1)[1].split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
    reset_path = fixture / "reset-journal.jsonl"
    reset_journal = HuntJournal(reset_path)
    reset_journal.append(dict(legacy, vuln_class="session_summary"))
    reset_journal.append(dict(legacy, command_id="reset-retained", store_id="synthetic-store"))
    saved_argv = sys.argv
    try:
        sys.argv = ["synthetic-filter", str(reset_path), target, str(runtime)]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            exec(compile(block, "synthetic-reset-filter", "exec"), {"__name__": "filter_fixture"})
        check(output.getvalue().strip() == "1", "reset journal block remains callable")
        check(len(reset_journal.read_all()) == 1 and reset_journal.read_all()[0]["command_id"] == "reset-retained", "reset retains remember rows")
    finally:
        sys.argv = saved_argv
    shell = subprocess.run(["bash", "-n", str(runtime / "tools/reset_target.sh")], capture_output=True, text=True)
    check(shell.returncode == 0, "changed shell parses")
    # Leave the source copy before TemporaryDirectory deletes cwd; the I/O
    # guard resolves relative descriptors during recursive cleanup as well.
    os.chdir(fixture.parent)

print(json.dumps({"status": "passed", "baseline": BASELINE, "overlay": OVERLAY,
                  "assertions": CHECKS, "seconds": round(time.monotonic() - START, 3),
                  "scope": "synthetic Store/journal; no project tests, private data, network or host execution"}, ensure_ascii=False))
