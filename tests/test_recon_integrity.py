"""Local regressions for Recon process ownership and lossless evidence publication."""

import gzip
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from test_ffuf_control_contract import _env, _functions
from tools import recon_artifact_gc, recon_target_selector as selector
from tools.recon_adapter import ReconAdapter
from tools.autopilot_state import build_autopilot_state
from tools.scope_source import load_scope_source, publish_scope_source
from tools.target_paths import target_storage_key
from tools.target_store import TargetStore


REPO = Path(__file__).resolve().parents[1]


def _run_shell(root, names, body):
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-c",
         "set -euo pipefail\n" + _functions(names) + "\n" + body],
        cwd=root, env=_env(root), text=True, capture_output=True, timeout=10,
    )


@pytest.mark.parametrize("failure", ["none", "read", "publish"])
def test_raw_union_preserves_old_archive_and_staging_on_failure(tmp_path, failure):
    old = tmp_path / "all.txt.gz"
    old.write_bytes(gzip.compress(b"https://old.test/a\n"))
    original = old.read_bytes()
    staging = tmp_path / "current.txt"
    staging.write_text("https://new.test/b\n")
    injected = {
        "none": "",
        "read": 'gzip() { echo "read interrupted" >&2; return 1; }\n',
        "publish": 'mv() { echo "publication interrupted" >&2; return 1; }\n',
    }[failure]
    result = _run_shell(
        tmp_path, ["append_artifact", "publish_raw_url_archive"],
        injected + 'RAW_URLS_ARCHIVE="$PWD/all.txt"\nRAW_URLS_STAGING="$PWD/current.txt"\n'
        "publish_raw_url_archive",
    )
    assert result.returncode == (0 if failure == "none" else 1), result.stderr
    if failure == "none":
        assert (tmp_path / "all.txt").read_text().splitlines() == [
            "https://old.test/a", "https://new.test/b",
        ]
        assert not old.exists() and not staging.exists()
    else:
        assert old.read_bytes() == original
        assert staging.read_text() == "https://new.test/b\n"
        assert not (tmp_path / "all.txt").exists()


@pytest.mark.parametrize("collector_exit", [0, 1, 124])
@pytest.mark.parametrize("failure", ["none", "read", "publish", "archive"])
def test_collector_merge_failure_preserves_both_generations(tmp_path, collector_exit, failure):
    urls = tmp_path / "urls"
    urls.mkdir()
    old = urls / "katana.txt.gz"
    old.write_bytes(gzip.compress(b"https://old.test/a\n"))
    original = old.read_bytes()
    injected = {
        "none": "",
        "read": 'gzip() { echo "read interrupted" >&2; return 1; }\n',
        "publish": 'mv() { echo "publication interrupted" >&2; return 1; }\n',
        "archive": 'cp() { echo "archive interrupted" >&2; return 1; }\n',
    }[failure]
    result = _run_shell(
        tmp_path, ["append_artifact", "archive_collector_artifact", "run_collector_task"],
        injected + 'RECON_DIR="$PWD"\n'
        f'collect() {{ printf "https://new.test/b\\n" > "$1"; return {collector_exit}; }}\n'
        'run_collector_task "$PWD/urls/katana.txt" "$PWD/status.tsv" collect',
    )
    assert result.returncode == 0, result.stderr
    failed = failure in {"read", "publish"} or failure == "archive" and collector_exit == 0
    status = (tmp_path / "status.tsv").read_text().split("\t")[0]
    assert status == ("error" if failed else "ok" if collector_exit == 0 else "partial")
    if failed:
        assert old.read_bytes() == original
        assert not (urls / "katana.txt").exists()
        assert any(p.read_text() == "https://new.test/b\n"
                   for p in urls.glob(".katana.txt.collector.*"))
        assert "preserved at" in (tmp_path / "status.tsv").read_text()
    else:
        assert set((urls / "katana.txt").read_text().splitlines()) == {
            "https://old.test/a", "https://new.test/b",
        }
        assert not old.exists()


@pytest.mark.parametrize("reference_kind", ["json", "jsonl", "md"])
def test_gc_protects_logical_references_to_compressed_raw(tmp_path, monkeypatch, reference_kind):
    target = "gc.test"
    logical = Path("recon") / target / "urls/raw/all.txt"
    actual = tmp_path / (str(logical) + ".gz")
    actual.parent.mkdir(parents=True)
    actual.write_bytes(gzip.compress(b"https://gc.test/a\n"))
    evidence = tmp_path / "evidence" / target
    evidence.mkdir(parents=True)
    reference = str(logical)
    (evidence / f"record.{reference_kind}").write_text(
        json.dumps({"source": reference}) + "\n" if reference_kind != "md"
        else f"[raw evidence]({reference})\n"
    )
    monkeypatch.setattr(recon_artifact_gc, "build_autopilot_state", lambda *a, **k: {})
    monkeypatch.setattr(recon_artifact_gc, "load_closure_projection",
                        lambda *a, **k: {"verdict": "complete", "can_claim_exhausted": True})
    plan = recon_artifact_gc.collect_gc_plan(tmp_path, target)
    assert plan["referenced_count"] == 1 and plan["removable"] == []
    assert recon_artifact_gc.apply_gc_plan(tmp_path, plan) == 0
    assert actual.exists()
    with pytest.raises(RuntimeError, match="not exhausted"):
        recon_artifact_gc.apply_gc_plan(tmp_path, {
            **plan, "closure": {"can_claim_exhausted": False},
        })


@pytest.mark.parametrize("contents", ["{broken\n", "{}\n", "", None])
def test_ffuf_invalid_main_cannot_complete(tmp_path, contents):
    path = tmp_path / "main.jsonl"
    if contents is not None:
        path.write_text(contents)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("found\nabsent")
    with pytest.raises(ValueError):
        ReconAdapter(tmp_path).check_ffuf_run(path, wordlist)


@pytest.mark.parametrize("outer", [False, True])
@pytest.mark.parametrize("form", ["foreground", "background", "pipeline"])
def test_timeout_reclaims_grandchild_and_inherited_lock(tmp_path, outer, form):
    # Run the assertion process as a subreaper so this regression leaves no zombies.
    child = tmp_path / "collector.py"
    child.write_text(
        "import os, signal, subprocess, sys, time\nfrom pathlib import Path\n"
        "root = Path(sys.argv[1]); fd = int(sys.argv[2])\n"
        "code = \"import os, signal, sys, time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "Path(sys.argv[1], 'grandchild.pid').write_text(str(os.getpid())); time.sleep(30)\"\n"
        "subprocess.Popen([sys.executable, '-c', code, str(root)], pass_fds=(fd,))\n"
        "time.sleep(30)\n"
    )
    quoted = shlex.quote
    command = (
        f"run_with_timeout {'30' if outer else '.4'} {quoted(sys.executable)} "
        f"{quoted(str(child))} {quoted(str(tmp_path))} \"$1\""
    )
    command = {
        "foreground": command,
        "background": f"{command} &\nwait $!",
        "pipeline": f"printf input | {command}",
    }[form]
    shell = tmp_path / "run.sh"
    shell.write_text("set -euo pipefail\n" + _functions(["timeout_bin", "run_with_timeout"]) + "\n" + command)
    driver = r'''
import ctypes, fcntl, os, signal, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from tools.runtime_exec import run_live_argv_command
root = Path(sys.argv[2]); outer = sys.argv[3] == "True"
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(36, 1, 0, 0, 0) == 0
fd = os.open(root / "phase.lock", os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
try:
    try:
        rc = run_live_argv_command(
            ["bash", str(root / "run.sh"), str(fd)], pass_fds=(fd,),
            timeout=.7 if outer else 8,
        )
        assert not outer and rc == 124, rc
    except subprocess.TimeoutExpired:
        assert outer
    pid = int((root / "grandchild.pid").read_text())
    stat = Path(f"/proc/{pid}/stat")
    assert not stat.exists() or stat.read_text().split(") ", 1)[1].startswith("Z")
    os.close(fd); fd = -1
    with (root / "phase.lock").open() as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
finally:
    if fd >= 0:
        os.close(fd)
    for raw in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split():
        try:
            os.kill(int(raw), signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            time.sleep(.01)
'''
    result = subprocess.run(
        [sys.executable, "-c", driver, str(REPO), str(tmp_path), str(outer)],
        cwd=tmp_path, env=_env(tmp_path), text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_timeout_preserves_stdin_status_and_outer_trap(tmp_path):
    result = _run_shell(
        tmp_path, ["timeout_bin", "run_with_timeout"],
        """trap 'printf outer > "$PWD/trap.txt"' EXIT
printf 'input bytes' | run_with_timeout 2 cat
run_with_timeout 2 bash -c 'exit 7'""",
    )
    assert (result.returncode, result.stdout) == (7, "input bytes")
    assert (tmp_path / "trap.txt").read_text() == "outer"


def test_parameter_inventory_keeps_all_raw_query_keys(tmp_path):
    params = tmp_path / "params"
    params.mkdir()
    (tmp_path / "urls.txt").write_text(
        "https://params.test/?a=1&b=2&a=3\n"
        "https://params.test/?empty=&flag&=x&&redirect=/next&file=one=two\n"
        "https://params.test/?%61=1&next%5B%5D=&q=a+b&plus+key=value\n"
        "https://params.test/?a=1#fragment&fake=2\n"
        "https://params.test/#fragment?fake=1\n"
        "https://[invalid/?odd=1\nhttps://params.test/no-query\n"
    )
    source = (REPO / "tools/recon_engine.sh").read_text()
    phase = source.split('if [ -s "$PARAM_URLS_FOR_DISCOVERY" ]; then\n', 1)[1]
    phase = 'if [ -s "$PARAM_URLS_FOR_DISCOVERY" ]; then\n' + phase.split('\nUNIQUE_PARAMS=', 1)[0]
    result = _run_shell(tmp_path, [],
        'RECON_DIR="$PWD"\nPARAM_URLS_FOR_DISCOVERY="$PWD/urls.txt"\n'
        'log_step() { :; }; log_done() { :; }; log_warn() { :; }\n' + phase)
    assert result.returncode == 0, result.stdout + result.stderr
    frequency = {key: int(count) for count, key in
                 (line.split() for line in (params / "param_frequency.txt").read_text().splitlines())}
    assert frequency == {"a": 3, "b": 1, "empty": 1, "flag": 1, "redirect": 1,
                         "file": 1, "%61": 1, "next%5B%5D": 1, "q": 1, "plus+key": 1, "odd": 1}
    assert set((params / "unique_params.txt").read_text().splitlines()) == set(frequency)
    assert set((params / "interesting_params.txt").read_text().splitlines()) == {
        "redirect", "file", "next%5B%5D",
    }


@pytest.fixture
def collection(tmp_path):
    target = "collection.test"
    kwargs = dict(target=target, repo_root=tmp_path, identity="katana:depth=3", limit=1,
                  state_path=tmp_path / "collection.json", plan_path=tmp_path / "plan.json",
                  targets_path=tmp_path / "selected.txt")

    def select(urls, **overrides):
        return selector.select_collection(**(kwargs | overrides), urls=urls)

    def record(url, status="ok"):
        path = tmp_path / "results.tsv"
        path.write_text(f"{url}\t{status}\n")
        return selector.record_results(target=target, repo_root=tmp_path,
                                       state_path=kwargs["state_path"], results_path=path)

    return select, record, kwargs


def test_collection_inventory_changes_preserve_completed_and_rotate_failures(collection):
    select, record, kwargs = collection
    a, b, c = [f"https://collection.test/{name}" for name in "abc"]
    assert select([a, b])["selected"] == [{"url": a}]
    record(a)
    before = json.loads(kwargs["state_path"].read_text())
    plan = select([c, b, a])
    after = json.loads(kwargs["state_path"].read_text())
    assert plan["completed_count"] == 1 and plan["selected"] == [{"url": b}]
    assert after["collection_fingerprint"] == before["collection_fingerprint"]
    assert after["inventory_fingerprint"] != before["inventory_fingerprint"]
    record(b, "partial")
    assert select([a, b, c])["selected"] == [{"url": c}]
    record(c)
    plan = select([b, c])
    assert plan["completed_count"] == 1 and plan["selected"] == [{"url": b}]
    assert set(json.loads(kwargs["state_path"].read_text())["completed"]) == {c}
    record(b)
    assert select([b, c])["exhausted"] is True


@pytest.mark.parametrize("change", ["config", "origins", "scope", "legacy"])
def test_collection_identity_changes_reset_progress(tmp_path, collection, change):
    select, record, kwargs = collection
    url = "https://collection.test"
    select([url])
    record(url)
    overrides = {}
    if change == "config":
        overrides["identity"] = "katana:depth=4"
    elif change == "origins":
        overrides["origins_only"] = True
    elif change == "scope":
        TargetStore(tmp_path, kwargs["target"]).initialize()
        current = load_scope_source(tmp_path, kwargs["target"])
        publish_scope_source(tmp_path, kwargs["target"], {
            "schema_version": 1, "root_target": kwargs["target"],
            "in_scope": [kwargs["target"]], "out_of_scope": ["excluded.collection.test"],
        }, expected_sha256=current["sha256"])
    else:
        state = json.loads(kwargs["state_path"].read_text())
        state["collection_fingerprint"] = hashlib.sha256(
            "\n".join(sorted([kwargs["identity"], url])).encode()).hexdigest()
        kwargs["state_path"].write_text(json.dumps(state))
    plan = select([url], **overrides)
    assert plan["completed_count"] == 0 and plan["selected"] == [{"url": url}]
    record(url)
    assert select([url], **overrides)["exhausted"] is True


@pytest.fixture
def batch_runner(tmp_path):
    # Run the production batch function; replace only child collection with local receipts.
    (tmp_path / "tools").symlink_to(REPO / "tools", target_is_directory=True)
    scope = tmp_path / "targets.txt"
    scope.write_text("alpha.test\nbeta.test\n")
    child = tmp_path / "child.sh"
    child.write_text('printf "%s\\n" "$1" >> "$PWD/calls.txt"\n'
                     '[ -f "$PWD/always-fail" ] && exit 75\n'
                     'if [ "$1" = alpha.test ] && [ ! -f "$PWD/once" ]; then\n'
                     '    touch "$PWD/once"; exit 75\nfi\nexit 0\n')
    source = (REPO / "tools/recon_engine.sh").read_text()
    functions = source.split("refresh_batch_progress() {", 1)[1]
    functions = "refresh_batch_progress() {" + functions.split('\nif [ -f "$TARGET" ]', 1)[0]
    shell = ('set -euo pipefail\n' + functions + '\nBASE_DIR="$PWD"\nSCRIPT_PATH="$PWD/child.sh"\n'
             'log_info() { :; }; log_warn() { :; }; log_err() { :; }; emit_claude_hint() { :; }\n'
             'run_domain_list_batch "$PWD/targets.txt" --quick\n')
    batch_dir = tmp_path / "recon" / target_storage_key(str(scope))

    def run(size=1, reset=False):
        env = _env(tmp_path) | {"BBHUNT_BATCH_SIZE": str(size), "BBHUNT_BATCH_RESET": str(int(reset))}
        return subprocess.run(["bash", "--noprofile", "--norc", "-c", shell], cwd=tmp_path,
                              env=env, capture_output=True, text=True, timeout=10)

    return run, scope, batch_dir


def test_batch_retry_advances_tail_then_clears_failure(tmp_path, batch_runner):
    run, scope, batch_dir = batch_runner
    for expected_rc, completed, failed, pending in [
        (1, [], ["alpha.test"], ["beta.test", "alpha.test"]),
        (0, ["beta.test"], ["alpha.test"], ["alpha.test"]),
        (0, ["beta.test", "alpha.test"], [], []),
    ]:
        result = run()
        assert result.returncode == expected_rc, result.stdout + result.stderr
        state = build_autopilot_state(str(tmp_path), str(scope))
        for name, values in [("completed", completed), ("failed", failed), ("pending", pending)]:
            assert (batch_dir / f"{name}_targets.txt").read_text().splitlines() == values
            assert state["batch"][name] == values
        assert f"- Remaining: {len(pending)}\n" in (batch_dir / "batch_summary.md").read_text()
    calls = (tmp_path / "calls.txt").read_text().splitlines()
    assert calls == ["alpha.test", "beta.test", "alpha.test"]
    manifest = [json.loads(row) for row in (batch_dir / "batch_manifest.jsonl").read_text().splitlines()]
    assert [row["exit_code"] for row in manifest] == [75, 0, 0]
    assert run().returncode == 0
    assert (tmp_path / "calls.txt").read_text().splitlines() == calls


def test_batch_persistent_failures_rotate_and_keep_each_call_bounded(tmp_path, batch_runner):
    run, scope, batch_dir = batch_runner
    (tmp_path / "always-fail").touch()
    for _ in range(3):
        assert run().returncode == 1
    assert (tmp_path / "calls.txt").read_text().splitlines() == ["alpha.test", "beta.test", "alpha.test"]
    assert (batch_dir / "failed_targets.txt").read_text().splitlines() == ["beta.test", "alpha.test"]
    state = build_autopilot_state(str(tmp_path), str(scope))
    assert state["next_action"] == "run_batch_recon"
    assert state["batch"]["pending"] == ["beta.test", "alpha.test"]
    assert "- Remaining: 2\n" in (batch_dir / "batch_summary.md").read_text()
    # The reader can run before the shell compacts the just-appended receipt.
    failed = batch_dir / "failed_targets.txt"
    failed.write_text("alpha.test\nbeta.test\nold.test\nalpha.test\n")
    state = build_autopilot_state(str(tmp_path), str(scope))
    assert state["next_action"] == "run_batch_recon"
    assert state["batch"]["failed"] == state["batch"]["pending"] == ["beta.test", "alpha.test"]
    assert failed.read_text() == "alpha.test\nbeta.test\nold.test\nalpha.test\n"


@pytest.mark.parametrize("mode", ["reset", "full", "scope"])
def test_batch_explicit_reset_and_scope_change_still_invalidate(tmp_path, batch_runner, mode):
    run, scope, batch_dir = batch_runner
    (tmp_path / "once").touch()
    assert run().returncode == 0
    if mode == "scope":
        scope.write_text("alpha.test\nbeta.test\ngamma.test\n")
    result = run(size=0 if mode == "full" else 1, reset=mode == "reset")
    assert result.returncode == 0, result.stdout + result.stderr
    calls = (tmp_path / "calls.txt").read_text().splitlines()
    assert calls[:2] == ["alpha.test", "alpha.test"]
    assert len(calls) == (3 if mode == "full" else 2)
    assert len((batch_dir / "batch_manifest.jsonl").read_text().splitlines()) == len(calls) - 1


def _recon_finish_script(event):
    source = (REPO / "tools/recon_engine.sh").read_text()
    finish = source[source.index("sync_observation_inventory final\n"):]
    return ("set -euo pipefail\n" + _functions([
        "record_recon_phase", "record_recon_collector", "aggregate_optional_status",
        "recon_record_budget_on_exit",
    ]) + '''
BASE_DIR="$PWD"; TARGET="${1:-exit.test}"; RECON_TARGET_KEY="$TARGET"; RECON_PROFILE=quick
RECON_DIR="$PWD/recon/$TARGET"; RECON_MANIFEST="$RECON_DIR/recon_manifest.jsonl"
mkdir -p "$RECON_DIR/subdomains" "$RECON_DIR/live"
touch "$RECON_DIR/subdomains/all.txt" "$RECON_DIR/live/httpx_full.txt"
RECON_STARTED_EPOCH=$(date +%s); RECON_SOFT_BUDGET_SECONDS=1800
RECON_BUDGET_ADVISORY_EXCEEDED=0; RECON_BUDGET_RECORD_WRITTEN=0; RECON_PHASE_PARTIAL=0
log_warn() { :; }; log_done() { :; }; emit_claude_hint() { :; }
sync_observation_inventory() { record_recon_phase observation_index "${FINAL_SYNC_STATUS:-ok}"; }
python3() {
    if [[ "$1" == */surface_finalizer.py ]]; then return "${FINALIZER_EXIT:-0}"; fi
    command python3 "$@"
}
trap 'exit_code=$?; recon_record_budget_on_exit "$exit_code"; exit "$exit_code"' EXIT
''' + event + "\n" + finish)


@pytest.mark.parametrize("event,expected", [
    ('record_recon_phase http_probe partial', 75),
    ('record_recon_collector katana error "" 0 0', 75),
    ('record_recon_phase api_leak_detection "$(aggregate_optional_status ok partial missing)"', 75),
    ('record_recon_phase port_scan "$(aggregate_optional_status ok unavailable)"', 0),
    ('record_recon_phase api_leak_detection "$(aggregate_optional_status missing skipped)"', 0),
    ('record_recon_phase route_kind_observation partial; FINALIZER_EXIT=1', 0),
    ('FINAL_SYNC_STATUS=partial', 75),
    ('RECON_BUDGET_ADVISORY_EXCEEDED=1', 0),
    ('record_recon_phase config_exposure ok "" 0 "input_total=2; selected=1; remaining=1; closure_blocking=false"', 0),
    ('exit 143', 143),
])
def test_recon_finish_distinguishes_execution_failure_from_advisory(tmp_path, event, expected):
    (tmp_path / "tools").symlink_to(REPO / "tools", target_is_directory=True)
    result = subprocess.run(["bash", "--noprofile", "--norc", "-c", _recon_finish_script(event)],
                            cwd=tmp_path, env=_env(tmp_path), capture_output=True, text=True, timeout=10)
    assert result.returncode == expected, result.stdout + result.stderr
    records = [json.loads(row) for row in (tmp_path / "recon/exit.test/recon_manifest.jsonl").read_text().splitlines()]
    assert records[-1]["phase"] == "run_budget"
    assert records[-1]["status"] == ("partial" if expected else "ok")
    assert (tmp_path / "recon/exit.test/live/httpx_full.txt").exists()


def test_batch_partial_child_finish_is_pending_until_success(tmp_path, batch_runner):
    run, scope, batch_dir = batch_runner
    (tmp_path / "child.sh").write_text(_recon_finish_script('''
if [ "$TARGET" = alpha.test ] && [ ! -f "$PWD/recovered" ]; then
    record_recon_phase http_probe partial
else
    record_recon_phase http_probe ok
fi
'''))
    assert run().returncode == 1
    record = json.loads((batch_dir / "batch_manifest.jsonl").read_text())
    assert record["exit_code"] == 75 and record["status"] == "failed"
    state = build_autopilot_state(str(tmp_path), str(scope))
    assert state["batch"]["completed"] == []
    assert state["batch"]["pending"] == ["beta.test", "alpha.test"]
    (tmp_path / "recovered").touch()
    assert run().returncode == 0
    assert run().returncode == 0
    state = build_autopilot_state(str(tmp_path), str(scope))
    assert state["batch"]["completed"] == ["beta.test", "alpha.test"]
    assert state["batch"]["pending"] == state["batch"]["failed"] == []


@pytest.mark.parametrize("child,seed_response,expected", [
    ({}, True, "ok"),
    ({}, False, "partial"),
    ({"error": "EOF"}, True, "partial"),
    ({"response": {"status_code": 429}}, True, "partial"),
    ({"response": {"status_code": 503}}, True, "partial"),
    ({"response": None}, True, "partial"),
    ({"response": {"status_code": "200"}}, True, "partial"),
])
def test_katana_discovery_only_rows_do_not_impersonate_response_receipts(tmp_path, child, seed_response, expected):
    origin = "https://katana.test"
    seeds, capture, output, results = [tmp_path / name for name in ["seeds", "capture", "urls", "results"]]
    seeds.write_text(origin + "\n")
    rows = [{"request": {"endpoint": origin}}]
    if seed_response:
        rows[0]["response"] = {"status_code": 200}
    rows.append({"request": {"endpoint": origin + "/same"}, **child})
    capture.write_text("".join(json.dumps(row) + "\n" for row in rows))
    ReconAdapter(tmp_path).publish_katana_receipts(capture, seeds, output, results, 0)
    assert results.read_text() == f"{origin}\t{expected}\n"
    assert output.read_text().splitlines() == [origin, origin + "/same"]


def test_cidr_next_page_is_pending_without_failing_the_current_page(tmp_path):
    (tmp_path / "tools").symlink_to(REPO / "tools", target_is_directory=True)
    source = (REPO / "tools/recon_engine.sh").read_text()
    page = source[source.index("    CIDR_LIMIT=4096\n"):source.index("\nfi\n\nSUBDOMAIN_ARTIFACT=")]
    result = _run_shell(tmp_path, ["record_recon_phase"], '''
BASE_DIR="$PWD"; TARGET=198.18.0.0/19; RECON_TARGET_KEY=198.18.0.0_19; RECON_PROFILE=quick
RECON_DIR="$PWD/recon/$RECON_TARGET_KEY"; RECON_MANIFEST="$RECON_DIR/recon_manifest.jsonl"
mkdir -p "$RECON_DIR/live/cidr_pages"
DISCOVERY_HOSTS_FILE="$RECON_DIR/live/discovery_hosts.txt"; CIDR_OFFSET=0; RECON_PHASE_PARTIAL=0
RECON_MODE_FLAG=--quick; SCRIPT_PATH="$BASE_DIR/tools/recon_engine.sh"
log_warn() { :; }; log_ok() { :; }; emit_claude_hint() { :; }
''' + page + '\ntest "$RECON_PHASE_PARTIAL" = 0\n')
    assert result.returncode == 0, result.stdout + result.stderr
    recon = tmp_path / "recon/198.18.0.0_19"
    continuation = json.loads((recon / "live/cidr_continuation.json").read_text())
    assert continuation["status"] == "partial" and continuation["next_offset"] == 4096
    assert continuation["remaining_hosts"] == 4094
    assert len((recon / "live/discovery_hosts.txt").read_text().splitlines()) == 4096
    phase = json.loads((recon / "recon_manifest.jsonl").read_text())
    assert phase["status"] == "ok"
