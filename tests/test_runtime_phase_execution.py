"""Local process-tree regressions for both runtime phase entry points."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
from unittest.mock import patch

import pytest

import hunt
import runtime_phase_exec
from runtime_state import (
    load_runtime_state, runtime_phase_lock,
    runtime_wait_action, update_runtime_state,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = "phase.test"
URL = "https://phase.test/a?next=https://other.test/x&name=one"

CHILD = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
root = Path(os.environ['PHASE_TEST_ROOT'])
mode = os.environ.get('PHASE_TEST_MODE', 'exit')
(root / 'child.pid').write_text(str(os.getpid()))
grandchild = None
if mode not in ('exit', 'hold'):
    code = "import os, signal, time; from pathlib import Path; "
    if mode == 'leader-exits':
        code += "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
    code += "Path(os.environ['PHASE_TEST_ROOT'], 'grandchild-ready').touch(); time.sleep(60)"
    grandchild = subprocess.Popen([sys.executable, '-c', code])
    (root / 'grandchild.pid').write_text(str(grandchild.pid))
    deadline = time.monotonic() + 5
    while not (root / 'grandchild-ready').exists():
        if time.monotonic() > deadline:
            raise RuntimeError('grandchild readiness timeout')
        time.sleep(.01)
locks = []
for fd in Path('/proc/self/fd').iterdir():
    try:
        name = os.readlink(fd)
        if name.endswith('.lock'):
            os.fstat(int(fd.name))
            locks.append(name)
    except OSError:
        pass
record = {'pid': os.getpid(), 'grandchild': grandchild.pid if grandchild else None,
          'argv': sys.argv[1:], 'cwd': os.getcwd(), 'locks': locks,
          'env': {key: os.environ.get(key) for key in
                  ('CHAOS_API_KEY', 'H1_API_TOKEN', 'RESIN_PROXY_TOKEN',
                   'BBHUNT_RUNTIME_PHASE_LOCKED', 'BBHUNT_RUNTIME_LOCK_TARGET')}}
(root / 'candidate').write_text('flushed candidate')
(root / 'ready.tmp').write_text(json.dumps(record))
(root / 'ready.tmp').replace(root / 'ready.json')
print('phase stdout', flush=True)
print('phase stderr', file=sys.stderr, flush=True)
if mode != 'exit':
    time.sleep(60)
sys.exit(int(os.environ.get('PHASE_TEST_EXIT', '0')))
'''


def _prepare(root):
    scripts = root / "tools with spaces"
    scripts.mkdir()
    (root / "recon" / TARGET).mkdir(parents=True)
    (root / "caller").mkdir()
    child = root / "child.py"
    child.write_text(CHILD)
    shell = f"exec {shlex.quote(sys.executable)} {shlex.quote(str(child))} \"$@\"\n"
    for name in ("recon_engine.sh", "vuln_scanner.sh"):
        (scripts / name).write_text(shell)


def _entry(root, entry, phase, *, timeout=None):
    """Isolate unrelated services, not process execution or state ownership."""
    root = Path(root)
    with ExitStack() as stack:
        for name, value in {
            "BASE_DIR": str(root), "TOOLS_DIR": str(root / "tools with spaces"),
            "RECON_DIR": str(root / "recon"), "FINDINGS_DIR": str(root / "findings"),
            "_AUTH_SESSION": hunt.AuthSession(),
            "_auto_log_session_summary": lambda *a, **k: None,
        }.items():
            stack.enter_context(patch.object(hunt, name, value))
        stack.enter_context(patch("observation_inventory.sync_inventory"))
        stack.enter_context(patch.object(hunt.CredentialStore, "export_to", lambda self, env, keys: None))

        def index_candidates(*args, **kwargs):
            (root / "preserved").write_text((root / "candidate").read_text())
            return {"total": 1}

        stack.enter_context(patch("tools.finding_index.index_scanner_material", index_candidates))
        if timeout is not None:
            live = hunt.run_live_argv_command

            def short_budget(argv, **kwargs):
                assert kwargs["timeout"] > timeout
                return live(argv, **{**kwargs, "timeout": timeout})

            stack.enter_context(patch.object(hunt, "run_live_argv_command", short_budget))
        if entry == "hunt":
            return hunt._hunt_target_impl(
                URL, quick=True, scanner_skip="module with spaces", **{f"{phase}_only": True}
            )[phase]
        return runtime_phase_exec.run_phase_command(
            root, TARGET, phase, [sys.executable, str(root / "child.py"), URL, "arg with spaces"]
        )


def _assert_finished(root, entry, phase, success):
    state = load_runtime_state(root, TARGET)
    failed = not success and (entry == "direct" or phase == "scan")
    workflow = "run_recon" if phase == "recon" else "run_vuln_scan"
    assert state["mode"] == f"{phase}_{'failed' if failed else 'only'}"
    assert state["last_executed_workflow"] == workflow + ("_failed" if failed else "")
    assert runtime_wait_action(root, TARGET) == ""
    with runtime_phase_lock(root, TARGET, phase):
        pass


def _alive(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False


def _wait_for(predicate, process=None, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if process is not None and process.poll() is not None:
            raise AssertionError(f"entry exited before readiness: {process.returncode}")
        time.sleep(.01)
    raise AssertionError("process readiness/exit deadline exceeded")


@pytest.fixture
def phase_root(tmp_path, monkeypatch):
    _prepare(tmp_path)
    monkeypatch.chdir(tmp_path / "caller")
    for key, value in {
        "PHASE_TEST_ROOT": str(tmp_path), "PHASE_TEST_MODE": "exit", "PHASE_TEST_EXIT": "0",
        "CHAOS_API_KEY": "synthetic-chaos", "H1_API_TOKEN": "synthetic-h1",
        "RESIN_PROXY_TOKEN": "synthetic-resin",
    }.items():
        monkeypatch.setenv(key, value)
    return tmp_path


@pytest.mark.parametrize("entry", ["hunt", "direct"])
@pytest.mark.parametrize("phase", ["recon", "scan"])
@pytest.mark.parametrize("code", [0, 17])
def test_phase_real_exit_preserves_argv_environment_fd_and_streams(phase_root, monkeypatch, capfd, entry, phase, code):
    monkeypatch.setenv("PHASE_TEST_EXIT", str(code))
    result = _entry(phase_root, entry, phase)
    assert result == ((code == 0) if entry == "hunt" else code)
    assert type(result) is (bool if entry == "hunt" else int)
    record = json.loads((phase_root / "ready.json").read_text())
    assert record["env"]["BBHUNT_RUNTIME_PHASE_LOCKED"] == phase
    assert record["env"]["BBHUNT_RUNTIME_LOCK_TARGET"] == (URL if entry == "hunt" and phase == "recon" else TARGET)
    assert record["locks"] == [str(phase_root / "state" / TARGET / "locks" / f"{phase}.lock")]
    if entry == "hunt":
        assert record["cwd"] == str(phase_root)
        assert record["env"]["H1_API_TOKEN"] is None
        assert record["env"]["RESIN_PROXY_TOKEN"] is None
        assert record["env"]["CHAOS_API_KEY"] == ("synthetic-chaos" if phase == "recon" else None)
        assert record["argv"] == ([URL, "--quick"] if phase == "recon" else [str(phase_root / "recon" / TARGET), "--quick", "--skip", "module with spaces"])
    else:
        assert record["cwd"] == str(phase_root / "caller")
        assert record["argv"] == [URL, "arg with spaces"]
        assert record["env"]["H1_API_TOKEN"] == "synthetic-h1"
    output = capfd.readouterr()
    assert "phase stdout" in output.out
    assert "phase stderr" in output.err
    _assert_finished(phase_root, entry, phase, code == 0)


@pytest.mark.parametrize("entry", ["hunt", "direct"])
@pytest.mark.parametrize("phase", ["recon", "scan"])
def test_phase_busy_does_not_spawn_or_rewrite_marker(phase_root, entry, phase):
    update_runtime_state(phase_root, TARGET, mode="previous")
    state_file = phase_root / "state" / TARGET / "session.json"
    before = state_file.read_bytes()
    with runtime_phase_lock(phase_root, TARGET, phase):
        if entry == "hunt":
            with pytest.raises(hunt.RuntimePhaseBusy):
                _entry(phase_root, entry, phase)
        else:
            assert _entry(phase_root, entry, phase) == 75
    assert not (phase_root / "ready.json").exists()
    assert state_file.read_bytes() == before


@pytest.mark.parametrize("phase", ["recon", "scan"])
def test_direct_child_exit_124_is_not_a_wrapper_deadline(phase_root, monkeypatch, phase):
    monkeypatch.setenv("PHASE_TEST_EXIT", "124")
    assert _entry(phase_root, "direct", phase) == 124
    _assert_finished(phase_root, "direct", phase, False)


def _check_direct_wrapper_sigkill(root, phase):
    # This helper runs in its own process so orphan reaping never affects pytest.
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "could not enable test child reaping")
    cli = [sys.executable, str(ROOT / "tools" / "runtime_phase_exec.py"),
           "--repo-root", str(root), "--target", TARGET, "--phase", phase, "--"]
    wrapper = subprocess.Popen(
        [*cli, sys.executable, str(root / "child.py")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    def deadline(_signum, _frame):
        raise TimeoutError("direct SIGKILL regression exceeded its deadline")

    try:
        # Leave time for finally to reap children before the outer hard timeout.
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(20)
        _wait_for(lambda: (root / "ready.json").exists(), wrapper)
        record = json.loads((root / "ready.json").read_text())
        child_pid = record["pid"]
        assert record["grandchild"] is None
        assert record["locks"] == [str(root / "state" / TARGET / "locks" / f"{phase}.lock")]
        assert runtime_wait_action(root, TARGET) == f"wait_{phase}"
        state_file = root / "state" / TARGET / "session.json"
        before = state_file.read_bytes()

        wrapper.kill()
        assert wrapper.wait(timeout=5) == -signal.SIGKILL
        assert _alive(child_pid)
        assert runtime_wait_action(root, TARGET) == f"wait_{phase}"
        sentinel = root / "duplicate-started"
        duplicate = subprocess.run(
            [*cli, sys.executable, "-c",
             "import sys; from pathlib import Path; Path(sys.argv[1]).touch()", str(sentinel)],
            capture_output=True, text=True, timeout=5,
        )
        assert duplicate.returncode == 75, duplicate.stderr
        assert not sentinel.exists()
        assert state_file.read_bytes() == before
    finally:
        signal.alarm(0)
        if wrapper.poll() is None:
            wrapper.kill()
        wrapper.wait(timeout=5)
        # After the wrapper is reaped, any surviving test child belongs to us,
        # even if it failed before publishing its readiness/PID files.
        children = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
        for child in children:
            pid = int(child)
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _wait_for(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid, timeout=5)

    with pytest.raises(ChildProcessError):
        os.waitpid(child_pid, os.WNOHANG)
    assert runtime_wait_action(root, TARGET) == ""
    assert state_file.read_bytes() == before
    with runtime_phase_lock(root, TARGET, phase):
        pass


@pytest.mark.parametrize("phase", ["recon", "scan"])
def test_direct_wrapper_sigkill_keeps_child_lock_until_reaped(phase_root, phase):
    code = (
        "import runpy, sys; ns = runpy.run_path(sys.argv[1]); "
        "ns['_check_direct_wrapper_sigkill'](ns['Path'](sys.argv[2]), sys.argv[3])"
    )
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "tools"))),
           "PHASE_TEST_MODE": "hold"}
    result = subprocess.run(
        [sys.executable, "-c", code, str(Path(__file__).resolve()), str(phase_root), phase],
        env=env, capture_output=True, text=True, timeout=35,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _run_interrupted(root, entry, phase, *, signum=None, timeout=None, mode="hang"):
    code = (
        "import runpy; ns = runpy.run_path(" + repr(str(Path(__file__).resolve())) + "); "
        "ns['_entry'](" + repr(str(root)) + ", " + repr(entry) + ", " + repr(phase)
        + ", timeout=" + repr(timeout) + ")"
    )
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "tools"))),
           "PHASE_TEST_MODE": mode}
    process = subprocess.Popen([sys.executable, "-c", code], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    record = None
    try:
        _wait_for(lambda: (root / "ready.json").exists(), process)
        record = json.loads((root / "ready.json").read_text())
        assert runtime_wait_action(root, TARGET) == f"wait_{phase}"
        if signum is not None:
            process.send_signal(signum)
        stdout, stderr = process.communicate(timeout=12)
        assert process.returncode == (0 if timeout is not None else -signal.SIGINT)
        assert "phase stdout" in stdout and "phase stderr" in stderr
        _wait_for(lambda: not _alive(record["pid"]) and not _alive(record["grandchild"]))
        _assert_finished(root, entry, phase, False)
        if entry == "hunt" and phase == "scan":
            assert (root / "preserved").read_text() == "flushed candidate"
    finally:
        if record is None and (root / "ready.json").exists():
            record = json.loads((root / "ready.json").read_text())
        child_pid = root / "child.pid"
        if child_pid.exists():
            try:
                os.killpg(int(child_pid.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


@pytest.mark.parametrize("entry", ["hunt", "direct"])
@pytest.mark.parametrize("phase", ["recon", "scan"])
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_phase_signals_reap_child_and_grandchild_and_release_lock(phase_root, entry, phase, signum):
    _run_interrupted(phase_root, entry, phase, signum=signum)


@pytest.mark.parametrize("phase", ["recon", "scan"])
def test_hunt_outer_timeout_reaps_process_tree(phase_root, phase):
    _run_interrupted(phase_root, "hunt", phase, timeout=.5)


def test_cleanup_kills_term_ignoring_descendant_after_leader_exits(phase_root):
    _run_interrupted(phase_root, "direct", "scan", signum=signal.SIGTERM, mode="leader-exits")


@pytest.mark.parametrize("entry", ["hunt", "direct"])
@pytest.mark.parametrize("phase", ["recon", "scan"])
def test_phase_spawn_failure_keeps_failure_marker_and_releases_lock(phase_root, monkeypatch, entry, phase):
    if entry == "hunt":
        monkeypatch.setenv("PATH", str(phase_root / "absent-bin"))
        with pytest.raises(FileNotFoundError):
            _entry(phase_root, entry, phase)
    else:
        with pytest.raises(FileNotFoundError):
            runtime_phase_exec.run_phase_command(phase_root, TARGET, phase, [str(phase_root / "missing")])
    assert not (phase_root / "ready.json").exists()
    _assert_finished(phase_root, entry, phase, False)
