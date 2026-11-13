"""Local regressions for Recon process ownership and lossless evidence publication."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


def _stub(root, name, body):
    path = root.parent / "home/go/bin" / name
    path.write_text(f"#!{sys.executable}\n" + body)
    path.chmod(0o700)


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
        tmp_path, ["append_artifact", "publish_artifact_union", "publish_raw_url_archive"],
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


@pytest.mark.parametrize("origins_only", [False, True])
def test_selected_collection_keeps_unselected_inventory_and_progress(collection, origins_only):
    select, record, kwargs = collection
    a, b, c = [f"https://{name}.collection.test" for name in "abc"]
    preferred = [c + "/path" if origins_only else c]
    kwargs["origins_only"] = origins_only
    assert select([a, b, c], preferred=preferred)["selected"] == [{"url": c}]
    record(c)
    plan = select([a, b, c], preferred=preferred)
    assert plan["selected"] == [] and plan["exhausted"] is False
    assert plan["eligible_count"] == 3 and plan["pending_count"] == 2
    assert select([a, b, c])["selected"] == [{"url": a}]
    assert c in json.loads(kwargs["state_path"].read_text())["completed"]


def test_preferred_collection_rotates_failed_prefix_past_completed_anchor(collection):
    select, record, kwargs = collection
    a, b, c = [f"https://collection.test/{name}.js" for name in "abc"]
    preferred = [c, a, c, b]
    assert select([a, b, c], preferred=preferred)["selected"] == [{"url": c}]
    record(c, "partial")
    assert select([a, b, c], preferred=preferred)["selected"] == [{"url": a}]
    record(a)
    # a is completed, but remains the position from which explicit ordering resumes.
    assert select([a, b, c], preferred=preferred)["selected"] == [{"url": b}]
    record(b)
    assert select([a, b, c], preferred=preferred)["selected"] == [{"url": c}]
    record(c)
    assert select([a, b, c], preferred=preferred)["exhausted"] is True


@pytest.fixture
def probe_checkout(tmp_path):
    root = tmp_path / "source"
    tools = root / "tools"
    tools.mkdir(parents=True)
    for source in (REPO / "tools").glob("*.py"):
        shutil.copy2(source, tools / source.name)
    for name in ("recon_engine.sh", "_auth_helper.sh"):
        shutil.copy2(REPO / "tools" / name, tools / name)
    memory = root / "memory"
    memory.mkdir()
    for source in (REPO / "memory").glob("*.py"):
        shutil.copy2(source, memory / source.name)
    target = "probe.test"
    TargetStore(root, target).initialize()
    home = tmp_path / "home"
    binaries = home / "go/bin"
    binaries.mkdir(parents=True)
    script = f"#!{sys.executable}\n" + r'''
import json, os, sys
from pathlib import Path
root = Path(os.environ['RECON_TEST_ROOT'])
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if '-version' in args:
    print('projectdiscovery httpx'); raise SystemExit(0)
if name == 'puredns':
    source = Path(args[1]); output = Path(args[args.index('--write') + 1])
else:
    source = Path(args[args.index('-l') + 1]); output = Path(args[args.index('-o') + 1])
values = source.read_text().splitlines()
with (root / 'calls.jsonl').open('a') as handle:
    handle.write(json.dumps({'tool': name, 'inputs': values}) + '\n')
if (root / ('fail-' + name)).exists():
    raise SystemExit(124)
if name == 'puredns':
    output.write_text(''.join(value + '\n' for value in values if not value.startswith('wild.')))
else:
    output.write_text(''.join((value if '://' in value else 'https://' + value) + ' [200] [10] [test]\n' for value in values))
'''
    for name in ("puredns", "httpx"):
        path = binaries / name
        path.write_text(script)
        path.chmod(0o700)
    # Fail visibly if a supposedly local probe accidentally executes another collector.
    for name in ("subfinder", "assetfinder", "gau", "waymore", "katana", "ffuf", "naabu", "nmap", "curl",
                 "porch-pirate", "postleaksNg", "trufflehog", "emailfinder", "cloud_enum"):
        path = binaries / name
        path.write_text(f"#!{sys.executable}\nfrom pathlib import Path\n"
                        f"Path({str(root / 'unexpected-tool')!r}).write_text({name!r})\nraise SystemExit(99)\n")
        path.chmod(0o700)
    env = _env(home) | {"RECON_TEST_ROOT": str(root), "BBHUNT_RECON_POST_COMPRESS": "0"}

    def run(stage="probe", input_file=None, expected=0, background=False, target_value=None, **extra_env):
        command = ["bash", str(tools / "recon_engine.sh"), target_value or target, "--deep", "--collect", stage]
        if input_file:
            command += ["--input", str(input_file)]
        if background:
            with (root / "run.log").open("w") as log:
                return subprocess.Popen(command, cwd=root, env=env | extra_env, text=True,
                                        stdout=log, stderr=subprocess.STDOUT)
        result = subprocess.run(command, cwd=root, env=env | extra_env, text=True, capture_output=True, timeout=25)
        assert result.returncode == expected, result.stdout + result.stderr
        assert not (root / "unexpected-tool").exists()
        return result

    return root, target, run


def test_probe_entry_merges_actual_live_and_retries_only_pending_inputs(probe_checkout):
    root, target, run = probe_checkout
    recon = root / "recon" / target
    live = recon / "live"
    candidates = root / "fofa candidates.txt"
    candidates.write_text("https://probe.test:8443/login?next=%2Fhome\na.probe.test\nhttps://outside.test/\n")
    run(input_file=candidates)
    first = set((live / "urls.txt").read_text().splitlines())
    assert first == {"https://probe.test", "https://a.probe.test", "https://probe.test:8443/login?next=%2Fhome"}
    first_calls = (root / "calls.jsonl").read_text()
    assert any(path.stat().st_size for path in (live / "httpx_runs").glob("*.txt"))
    run(input_file=candidates)
    assert (root / "calls.jsonl").read_text() == first_calls
    candidates.write_text(candidates.read_text() + "b.probe.test\n")
    (root / "fail-httpx").touch()
    run(input_file=candidates, expected=75)
    assert set((live / "urls.txt").read_text().splitlines()) == first
    (root / "fail-httpx").unlink()
    run(input_file=candidates)
    assert set((live / "urls.txt").read_text().splitlines()) == first | {"https://b.probe.test"}
    calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
    assert calls[-1] == {"tool": "httpx", "inputs": ["b.probe.test"]}
    candidates.write_text(candidates.read_text() + "wild.probe.test\n")
    run(input_file=candidates)
    assert [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()][-1] == {
        "tool": "puredns", "inputs": ["wild.probe.test"]}
    progress = json.loads((live / "probe_state.json").read_text())
    assert "wild.probe.test" not in progress["completed"]
    rows = [json.loads(line) for line in (recon / "recon_manifest.jsonl").read_text().splitlines()]
    latest = {row.get("phase"): row for row in rows if row["record_type"] == "recon_phase"}
    assert latest["run_budget"]["status"] == "ok"
    assert latest["dir_fuzz"]["status"] == latest["url_collection"]["status"] == "not_run"
    assert latest["http_probing"]["gate"]["bounded"]["remaining"] == 1


def test_httpx_receipts_do_not_promote_search_or_unselected_urls(tmp_path):
    (tmp_path / "live").mkdir()
    canonical = tmp_path / "live/httpx_full.txt"
    canonical.write_text("https://old.test [200]\n")
    capture, seeds, results = (tmp_path / name for name in ("raw.txt", "seeds.txt", "results.tsv"))
    seeds.write_text("https://selected.test:8443/path\n")
    for value in ("https://selected.test:8443/path", "https://outside.test [200]",
                  "https://selected.test/path [200]", "https://selected.test:8443/path/ [200]"):
        capture.write_text(value + "\n")
        with pytest.raises(ValueError):
            ReconAdapter(tmp_path).publish_httpx_receipts(capture, seeds, results, 0)
        assert canonical.read_text() == "https://old.test [200]\n"
        assert not results.exists()


def test_httpx_receipts_accept_ipv6_without_parsing_host_as_status(tmp_path):
    capture, seeds, results = (tmp_path / name for name in ("raw", "seeds", "results"))
    url = "http://[::1]:8080/path?x=1"
    capture.write_text(url + " [200] [8] [Page]\n")
    seeds.write_text(url + "\n")
    ReconAdapter(tmp_path).publish_httpx_receipts(capture, seeds, results, 0)
    assert results.read_text() == url + "\tok\n"
    assert (tmp_path / "live/urls.txt").read_text() == url + "\n"


def test_discover_publishes_live_before_slow_source_finishes(probe_checkout):
    root, target, run = probe_checkout
    script = r'''
import json, os, sys, time
from pathlib import Path
root = Path(os.environ['RECON_TEST_ROOT'])
name, args = Path(sys.argv[0]).name, sys.argv[1:]
if name == 'assetfinder':
    (root / 'slow.started').touch()
    deadline = time.monotonic() + 20
    while not (root / 'release').exists() and time.monotonic() < deadline:
        time.sleep(.02)
    print('slow.probe.test')
elif name == 'subfinder':
    Path(args[args.index('-o') + 1]).write_text('fast.probe.test\n')
elif name == 'gau':
    Path(args[args.index('--o') + 1]).write_text('https://fast.probe.test/old?k=v\n')
elif name == 'waymore':
    Path(args[args.index('-oU') + 1]).write_text('')
elif name == 'curl':
    print('[]' if any('crt.sh' in arg for arg in args) else '')
'''
    for name in ("subfinder", "assetfinder", "gau", "waymore", "curl"):
        _stub(root, name, script)
    proc = run("discover", background=True)
    live = root / "recon" / target / "live/urls.txt"
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and proc.poll() is None:
            if live.is_file() and "https://fast.probe.test" in live.read_text():
                break
            time.sleep(.02)
        assert (root / "slow.started").exists()
        assert proc.poll() is None, (root / "run.log").read_text()
        assert "https://fast.probe.test" in live.read_text()
        assert "https://slow.probe.test" not in live.read_text()
    finally:
        (root / "release").touch()
        proc.wait(timeout=25)
    assert proc.returncode == 0, (root / "run.log").read_text()
    assert "https://slow.probe.test" in live.read_text()
    assert not (root / "unexpected-tool").exists()


def test_discover_probe_failure_stops_collector_tree(tmp_path):
    result = _run_shell(tmp_path, ["append_artifact", "archive_collector_artifact", "run_collector_task",
                                  "start_collector", "wait_collector_group", "cleanup_collectors", "artifact_line_count"], r'''
RECON_DIR="$PWD"
RECON_COLLECT=discover
TARGET_KIND=domain
COLLECTOR_PIDS=(); COLLECTOR_NAMES=(); COLLECTOR_ARTIFACTS=()
COLLECTOR_ARTIFACT_LABELS=(); COLLECTOR_META_FILES=()
log_step() { :; }; log_done() { :; }; log_warn() { :; }
record_recon_collector() { printf '%s:%s\n' "$1" "$2" >> "$PWD/receipts"; }
mkdir -p subdomains
: > subdomains/all.txt
merge_discovery_candidates() { printf 'fast.test\n' > subdomains/all.txt; }
run_http_probe() { return 42; }
fast() { echo fast > "$1"; }
slow() { echo raw > "$1"; sleep .5; echo orphan > "$PWD/late-write"; }
trap 'code=$?; cleanup_collectors; exit "$code"' EXIT
start_collector fast "$PWD/fast.txt" fast.txt fast
start_collector slow "$PWD/slow.txt" slow.txt slow
wait_collector_group
''')
    assert result.returncode == 42, result.stdout + result.stderr
    time.sleep(.6)
    assert not (tmp_path / "late-write").exists()
    assert "slow:partial" in (tmp_path / "receipts").read_text()
    assert any(path.read_text() == "raw\n" for path in tmp_path.glob(".slow.txt.collector.*"))


def test_ports_fallback_candidates_reenter_probe_and_keep_progress(probe_checkout):
    root, target, run = probe_checkout
    script = r'''
import json, os, sys
from pathlib import Path
root = Path(os.environ['RECON_TEST_ROOT'])
name, args = Path(sys.argv[0]).name, sys.argv[1:]
flag = '-list' if name == 'naabu' else '-iL'
inputs = Path(args[args.index(flag) + 1]).read_text().splitlines()
with (root / 'ports_calls.jsonl').open('a') as log:
    log.write(json.dumps({'tool': name, 'inputs': inputs}) + '\n')
inputs = [host for host in inputs if not host.startswith('silent.')]
if name == 'naabu':
    if (root / 'naabu-ok').exists():
        Path(args[args.index('-o') + 1]).write_text(''.join(host + ':8443\n' for host in inputs))
        raise SystemExit(0)
    raise SystemExit(124)
if (root / 'fail-nmap').exists():
    raise SystemExit(124)
for flag in ('-oN', '-oG'):
    Path(args[args.index(flag) + 1]).write_text(''.join(
        'Host: 192.0.2.10 ()\tPorts: 8443/open/tcp//https///\n' for host in inputs))
Path(args[args.index('-oX') + 1]).write_text('<nmaprun>' + ''.join(
    f'<host><address addr="192.0.2.10"/><hostnames><hostname name="{host}" type="user"/></hostnames><ports><port protocol="tcp" portid="8443"/></ports></host>'
    for host in inputs) + '</nmaprun>')
'''
    for name in ("naabu", "nmap"):
        _stub(root, name, script)
    recon = root / "recon" / target
    (recon / "subdomains").mkdir(parents=True)
    (recon / "subdomains/all.txt").write_text("later.probe.test\n")
    preferred = root / "selected.txt"
    preferred.write_text("https://probe.test\n")
    run("ports", input_file=preferred)
    calls = [json.loads(line) for line in (root / "ports_calls.jsonl").read_text().splitlines()]
    assert calls == [{"tool": tool, "inputs": [target]} for tool in ("naabu", "nmap")]
    assert "https://probe.test:8443/" in (recon / "urls/port_candidates.txt").read_text()
    run("probe")
    assert "https://probe.test:8443/" in (recon / "live/urls.txt").read_text()
    original = (recon / "ports/open_host_ports.txt").read_text()
    (root / "fail-nmap").touch()
    run("ports", expected=75)
    assert (recon / "ports/open_host_ports.txt").read_text() == original
    assert "later.probe.test" not in json.loads((recon / "ports/scan_state.json").read_text())["completed"]
    (root / "fail-nmap").unlink()
    (root / "naabu-ok").touch()
    run("ports")
    assert json.loads((root / "ports_calls.jsonl").read_text().splitlines()[-1]) == {
        "tool": "naabu", "inputs": ["later.probe.test"]}
    assert set(json.loads((recon / "ports/scan_state.json").read_text())["completed"]) == {target, "later.probe.test"}
    assert "later.probe.test:8443" in (recon / "ports/open_host_ports.txt").read_text()
    previous = (root / "ports_calls.jsonl").read_text()
    run("ports")
    assert (root / "ports_calls.jsonl").read_text() == previous
    with (recon / "subdomains/all.txt").open("a") as handle:
        handle.write("silent.probe.test\n")
    run("ports")
    assert "silent.probe.test" not in json.loads((recon / "ports/scan_state.json").read_text())["completed"]
    (root / "naabu-ok").unlink()
    run("ports")
    assert "silent.probe.test" not in json.loads((recon / "ports/scan_state.json").read_text())["completed"]


def test_js_input_and_failed_retry_preserve_endpoints_and_raw_candidates(probe_checkout):
    root, target, run = probe_checkout
    script = r'''
import os, sys
from pathlib import Path
root = Path(os.environ['RECON_TEST_ROOT'])
if (root / 'fail-curl').exists():
    raise SystemExit(28)
Path(sys.argv[sys.argv.index('-o') + 1]).write_text('const path = "/api/retained";')
print('200', end='')
'''
    _stub(root, "curl", script)
    _stub(root, "linkfinder", "print('/api/retained')\n")
    supplied = root / "js.txt"
    supplied.write_text("https://probe.test/app.js\n")
    raw = root / "recon" / target / "urls/raw"
    raw.mkdir(parents=True)
    (raw / "all.txt.gz").write_bytes(gzip.compress(b"https://bucket.s3.amazonaws.com/path\n"))
    run("js", input_file=supplied)
    recon = root / "recon" / target
    endpoints = recon / "js/endpoints.txt"
    assert endpoints.read_text() == "/api/retained\n"
    assert "bucket" in (recon / "exposure/s3_bucket_candidates.txt").read_text().splitlines()
    (root / "fail-curl").touch()
    supplied.write_text(supplied.read_text() + "https://probe.test/new.js\n")
    run("js", input_file=supplied, expected=75)
    assert endpoints.read_text() == "/api/retained\n"
    assert any(path.stat().st_size for path in (recon / "js/runs").glob("*/endpoints_raw.txt"))
    assert "bucket" in (recon / "exposure/s3_bucket_candidates.txt").read_text().splitlines()


def test_js_batches_resume_both_analyses_without_repeating_successful_downloads(probe_checkout):
    root, target, run = probe_checkout
    _stub(root, "curl", r'''
import os, sys
from pathlib import Path
root = Path(os.environ['RECON_TEST_ROOT'])
url = next(value for value in sys.argv if value.startswith('https://'))
with (root / 'js_downloads.txt').open('a') as handle: handle.write(url + '\n')
status = 503 if url.endswith('/00.js') and not (root / 'recovered').exists() else 200
name = url.rsplit('/', 1)[-1].split('.')[0]
Path(sys.argv[sys.argv.index('-o') + 1]).write_text('const route="/api/' + name + '";')
print(status, end='')
''')
    _stub(root, "linkfinder", r'''
import os, re, sys
from pathlib import Path
root = Path(os.environ['RECON_TEST_ROOT'])
body = Path(sys.argv[sys.argv.index('-i') + 1]).read_text()
with (root / 'js_link_calls.txt').open('a') as handle: handle.write(body + '\n')
print('\n'.join(re.findall(r'"(/api/[^" ]+)"', body)))
''')
    supplied = root / "js.txt"
    urls = [f"https://probe.test/{index:02}.js" for index in range(53)]
    supplied.write_text("\n".join(urls) + "\n")
    run("js", input_file=supplied, expected=75)
    recon = root / "recon" / target
    def done(name):
        return set(json.loads((recon / f"js/{name}_state.json").read_text())["completed"])
    assert len(done("extract")) == 49 and len(done("links")) == 24
    (root / "recovered").touch()
    run("js", input_file=supplied)
    assert len(done("extract")) == 53 and len(done("links")) == 49
    run("js", input_file=supplied)
    assert done("links") == done("extract") == set(urls)
    downloads = (root / "js_downloads.txt").read_text().splitlines()
    assert len(downloads) == 54 and downloads.count(urls[0]) == 2
    assert len((root / "js_link_calls.txt").read_text().splitlines()) == 53
    assert all(downloads.count(url) == 1 for url in urls[1:])
    run("js", input_file=supplied)
    assert (root / "js_downloads.txt").read_text().splitlines() == downloads
    assert len((root / "js_link_calls.txt").read_text().splitlines()) == 53
    supplied.write_text("https://probe.test/new.js\n")
    run("js", input_file=supplied)
    assert done("links") == done("extract") == set(urls) | {"https://probe.test/new.js"}
    assert "/api/52" in (recon / "js/endpoints.txt").read_text()
    rows = [json.loads(line) for line in (recon / "recon_manifest.jsonl").read_text().splitlines()]
    last = [row for row in rows if row.get("phase") == "js_analysis"][-1]
    assert "selected=54; remaining=0" in last["note"]


@pytest.mark.parametrize("fault", ["none", "unfinished", "nonzero"])
def test_js_xn_terminal_receipts_and_legacy_fallback(probe_checkout, fault):
    root, target, run = probe_checkout
    _stub(root, "xnLinkFinder", r'''
import os, sys
from pathlib import Path
args = sys.argv[1:]
assert not sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty()
assert '-i' not in args and all(flag in args for flag in ('-sf', '-all', '-vv', '-ow'))
assert args[args.index('-d') + 1] == '1'
assert args[args.index('-mrs') + 1] == '20' and int(args[args.index('-rl') + 1]) > 0
assert Path(args[args.index('-sf') + 1]).read_text().splitlines() == ['probe.test']
assert sys.stdin.read() == 'https://probe.test/a.js\nhttps://probe.test/b.js\n'
raw = Path(args[args.index('-o') + 1])
raw.write_text('/api/xn\nhttps://probe.test.evil.invalid/ignored\n')
print('Response 200: https://probe.test/a.js')
print('Response 503: https://probe.test/b.js')
if os.environ['XN_FAULT'] != 'unfinished':
    print('Potential unique links found for <stdin>: 2')
    print('Links successfully written to file ' + str(raw))
raise SystemExit(1 if os.environ['XN_FAULT'] == 'nonzero' else 0)
''')
    _stub(root, "curl", r'''
import sys
from pathlib import Path
url = next(arg for arg in sys.argv if arg.startswith('https://'))
Path(sys.argv[sys.argv.index('-o') + 1]).write_text(url)
print('200', end='')
''')
    _stub(root, "linkfinder", r'''
import os, sys
from pathlib import Path
body = Path(sys.argv[sys.argv.index('-i') + 1]).read_text()
with Path(os.environ['RECON_TEST_ROOT'], 'legacy_calls.txt').open('a') as log:
    log.write(body + '\n')
print('/api/legacy/' + body.rsplit('/', 1)[-1])
''')
    seeds = root / "js.txt"
    urls = ["https://probe.test/a.js", "https://probe.test/b.js"]
    seeds.write_text("\n".join(urls) + "\n")
    run("js", input_file=seeds, XN_FAULT=fault, expected=75)
    js = root / "recon" / target / "js"
    capture = next((js / "runs").iterdir())
    assert (capture / "linkfinder_raw.txt.upstream").read_text().endswith("evil.invalid/ignored\n")
    assert "Response 200:" in (capture / "linkfinder_raw.txt.log").read_text()
    expected = urls[1:] if fault == "none" else urls
    assert (root / "legacy_calls.txt").read_text().splitlines() == expected
    assert set((js / "linkfinder_endpoints.txt").read_text().splitlines()) == {
        "/api/xn", *("/api/legacy/" + url.rsplit("/", 1)[-1] for url in expected),
    }
    assert set(json.loads((js / "links_state.json").read_text())["completed"]) == set(urls)
    rows = [json.loads(line) for line in (js.parent / "recon_manifest.jsonl").read_text().splitlines()]
    assert [row for row in rows if row.get("phase") == "js_analysis"][-1]["status"] == "partial"


def test_js_auth_change_does_not_reuse_previous_identity_response(probe_checkout):
    root, target, run = probe_checkout
    _stub(root, "curl", r'''
import os, sys
from pathlib import Path
identity = os.environ['BBHUNT_SESSION_ID']
assert 'X-Fixture-Actor: ' + identity in sys.argv
Path(sys.argv[sys.argv.index('-o') + 1]).write_text('"/api/' + identity + '"')
with Path(os.environ['RECON_TEST_ROOT'], 'identities.txt').open('a') as log:
    log.write(identity + '\n')
print('200', end='')
''')
    _stub(root, "linkfinder", "import sys\nfrom pathlib import Path\n"
          "print(Path(sys.argv[sys.argv.index('-i') + 1]).read_text().strip(chr(34)))\n")
    seeds = root / "js.txt"
    seeds.write_text("https://probe.test/a.js\n")
    for identity in ("one", "one", "two"):
        run("js", input_file=seeds, BBHUNT_SESSION_ID=identity,
            BBHUNT_AUTH_HEADERS="X-Fixture-Actor: " + identity,
            BBHUNT_AUTH_ORIGINS="https://probe.test")
    assert (root / "identities.txt").read_text().splitlines() == ["one", "two"]
    js = root / "recon" / target / "js"
    assert set((js / "linkfinder_endpoints.txt").read_text().splitlines()) == {"/api/one", "/api/two"}
    cached = list((js / "responses").glob("*.js"))
    assert {path.read_text() for path in cached} == {'"/api/one"', '"/api/two"'}
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in cached)


def test_js_publication_failure_keeps_raw_without_completing_batch(probe_checkout):
    root, target, run = probe_checkout
    _stub(root, "curl", "import sys\nfrom pathlib import Path\n"
          "Path(sys.argv[sys.argv.index('-o') + 1]).write_text('\"/api/new\"')\nprint('200', end='')\n")
    _stub(root, "linkfinder", "print('/api/new')\n")
    _stub(root, "mv", r'''
import os, sys
if sys.argv[-1].endswith('/js/endpoints.txt'):
    raise SystemExit(42)
os.execv('/bin/mv', ['/bin/mv', *sys.argv[1:]])
''')
    seeds = root / "js.txt"
    seeds.write_text("https://probe.test/a.js\n")
    js = root / "recon" / target / "js"
    js.mkdir(parents=True)
    (js / "endpoints.txt").write_text("/api/retained\n")
    run("js", input_file=seeds, expected=1)
    assert (js / "endpoints.txt").read_text() == "/api/retained\n"
    assert any("/api/new" in path.read_text() for path in (js / "runs").glob("*/endpoints_raw.txt"))
    for name in ("extract", "links"):
        assert not json.loads((js / f"{name}_state.json").read_text())["completed"]


@pytest.mark.parametrize("fault", ["none", "empty", "no_log", "no_finish", "analysis_error", "timeout"])
def test_xnlinkfinder_receipts_require_response_and_finished_analysis(tmp_path, fault):
    seeds, raw, capture, output, results = [tmp_path / name for name in ("seeds", "raw", "log", "links", "results")]
    a, b = "https://xn.test/a.js", "https://xn.test/b.js"
    seeds.write_text(a + "\n" + b + "\n")
    raw.write_text("" if fault == "empty" else "/api/items\nhttps://other.test/ignored\n")
    log = f"\x1b[32mResponse 200: {a}\x1b[0m\nResponse 503: {b}\n"
    if fault != "no_finish":
        log += "Potential unique links found for <stdin>: 1\n"
        log += ("No links were found so nothing written to file.\n" if fault == "empty"
                else f"Links successfully written to file {raw}\n")
    if fault == "analysis_error": log += "ERROR getResponseLinks: incomplete parsing\n"
    capture.write_text("" if fault == "no_log" else log)
    assert ReconAdapter(tmp_path).publish_xnlinkfinder_receipts(
        capture, seeds, raw, output, results, 124 if fault == "timeout" else 0, "xn.test") is False
    expected = "ok" if fault in {"none", "empty"} else "partial"
    assert results.read_text() == f"{a}\t{expected}\n{b}\tpartial\n"
    assert output.read_text() == ("" if fault == "empty" else "/api/items\n")


@pytest.mark.parametrize("stage", ["", "history"])
def test_url_view_keeps_explicit_js_inventory_and_progress(tmp_path, collection, stage):
    select, record, _ = collection
    supplied, new = "https://collection.test/supplied.js", "https://collection.test/new.js"
    urls = tmp_path / "urls"
    urls.mkdir()
    (urls / "all.txt").write_text(new + "\nhttps://collection.test/\n")
    (urls / "js_files.txt").write_text(supplied + "\n")
    select([supplied])
    record(supplied)
    result = _run_shell(tmp_path, ["append_artifact", "publish_artifact_union", "publish_url_view"],
                        f'RECON_COLLECT={shlex.quote(stage)}\nRECON_DIR="$PWD"\n'
                        'publish_url_view "$PWD/urls/all.txt" "$PWD/urls/js_files.txt" "\\.js$"')
    assert result.returncode == 0, result.stderr
    inventory = (urls / "js_files.txt").read_text().splitlines()
    assert inventory == [supplied, new]
    plan = select(inventory)
    assert plan["completed_count"] == 1 and plan["selected"] == [{"url": new}]


@pytest.mark.parametrize("stage,files,tools", [
    ("identity", ("identity_intel/emails.txt", "identity_intel/leaksearch.txt", "cloud/cloud_enum.txt"),
     ("emailfinder", "cloud_enum")),
    ("api", ("api_leak_candidates.txt", "api_leak_trufflehog_verified.jsonl", "api_leaks/postman_leaks.txt"),
     ("porch-pirate", "postleaksNg", "trufflehog")),
])
def test_optional_collection_failure_retains_prior_artifacts(probe_checkout, stage, files, tools):
    root, target, run = probe_checkout
    for name in tools:
        _stub(root, name, "raise SystemExit(124)\n")
    for name in files:
        path = root / "recon" / target / "exposure" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("prior evidence\n")
    run(stage, expected=75)
    for name in files:
        assert (root / "recon" / target / "exposure" / name).read_text() == "prior evidence\n"


def test_real_httpx_loopback_preserves_path_port_and_redirect(probe_checkout):
    candidates = [Path("/root/go/bin/httpx"), Path("/usr/local/bin/httpx")]
    binary = next((path for path in candidates if path.is_file() and os.access(path, os.X_OK)), None)
    if binary is None:
        pytest.skip("ProjectDiscovery httpx binary unavailable")
    root, _, run = probe_checkout
    stub = root.parent / "home/go/bin/httpx"
    stub.unlink()
    stub.symlink_to(binary)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/must-not-follow")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<title>Local Redirect</title>")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/login?next=%2Fhome"
    TargetStore(root, target).initialize()
    try:
        run(target_value=target)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    live = root / "recon" / target_storage_key(target) / "live"
    assert set(requests) == {"/login?next=%2Fhome"}
    assert live.joinpath("urls.txt").read_text().splitlines() == [target]
    assert "[302]" in live.joinpath("httpx_full.txt").read_text()
    assert set(json.loads(live.joinpath("probe_state.json").read_text())["completed"]) == {target}


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
