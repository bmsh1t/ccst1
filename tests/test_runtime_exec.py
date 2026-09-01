"""Regression tests for tools/runtime_exec.py."""

from __future__ import annotations

import shlex
import signal
import subprocess
import sys

import pytest

import runtime_exec
import zero_day_fuzzer


def _timeout_test_command() -> str:
    script = (
        "import sys, time; "
        "print('hello', flush=True); "
        "print('err', file=sys.stderr, flush=True); "
        "time.sleep(30)"
    )
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(script)}"


def test_spawn_uses_session_safe_popen_options_and_cwd(monkeypatch):
    captured = {}

    class FakeProc:
        pass

    def fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", fake_popen)

    proc = runtime_exec._spawn("echo ok", cwd="/tmp/example")

    assert isinstance(proc, FakeProc)
    assert captured["args"] == ("echo ok",)
    assert captured["kwargs"]["shell"] is True
    assert captured["kwargs"]["cwd"] == "/tmp/example"
    assert captured["kwargs"]["stdout"] is subprocess.PIPE
    assert captured["kwargs"]["stderr"] is subprocess.PIPE
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["start_new_session"] is True
    assert "preexec_fn" not in captured["kwargs"]


def test_spawn_passes_explicit_environment(monkeypatch):
    captured = {}

    class FakeProc:
        pass

    monkeypatch.setattr(
        runtime_exec.subprocess,
        "Popen",
        lambda *args, **kwargs: captured.update(kwargs) or FakeProc(),
    )

    runtime_exec._spawn("echo ok", env={"BBHUNT_AUTH_HEADERS": "Authorization: secret"})

    assert captured["env"] == {"BBHUNT_AUTH_HEADERS": "Authorization: secret"}


def test_run_argv_command_split_preserves_arguments_and_spawn_contract(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 7

        def communicate(self, timeout=None):
            captured["timeout"] = timeout
            return "stdout", "stderr"

    def fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", fake_popen)

    success, stdout, stderr = runtime_exec.run_argv_command_split(
        ["tool", "arg with spaces", ";literal"],
        cwd="/tmp/example",
        env={"MODE": "test"},
        timeout=12,
    )

    assert (success, stdout, stderr) == (False, "stdout", "stderr")
    assert captured["args"] == (["tool", "arg with spaces", ";literal"],)
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["cwd"] == "/tmp/example"
    assert captured["kwargs"]["env"] == {"MODE": "test"}
    assert captured["kwargs"]["stdout"] is not subprocess.PIPE
    assert captured["kwargs"]["stderr"] is not subprocess.PIPE
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["start_new_session"] is True
    assert captured["timeout"] == 12


def test_run_argv_command_rejects_invalid_shapes_before_spawn(monkeypatch):
    monkeypatch.setattr(
        runtime_exec.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )

    for argv in ([], "echo ok", 123, ["echo", 1]):
        try:
            runtime_exec.run_argv_command(argv)
        except ValueError:
            continue
        raise AssertionError(f"invalid argv accepted: {argv!r}")


def test_run_argv_command_missing_executable_returns_failure():
    success, stdout, stderr = runtime_exec.run_argv_command_split(
        ["__ccst_missing_executable__"]
    )

    assert success is False
    assert stdout == ""
    assert "__ccst_missing_executable__" in stderr


def test_run_argv_command_timeout_reuses_partial_output_cleanup():
    argv = shlex.split(_timeout_test_command())

    success, stdout, stderr = runtime_exec.run_argv_command_split(argv, timeout=0.1)

    assert success is False
    assert stdout == "hello\n"
    assert stderr.count("err\n") == 1
    assert "command timed out after 0.1s" in stderr.lower()


def test_run_argv_command_idle_timeout_preserves_output_and_kills_group():
    script = "import time; print('ready', flush=True); time.sleep(30)"

    success, stdout, stderr = runtime_exec.run_argv_command_split(
        [sys.executable, "-c", script],
        timeout=5,
        idle_timeout=0.25,
    )

    assert success is False
    assert stdout == "ready\n"
    assert "no output for 0.25s (idle timeout)" in stderr.lower()


def test_run_argv_command_activity_resets_idle_timeout():
    script = (
        "import time; "
        "print('one', flush=True); time.sleep(0.1); "
        "print('two', flush=True); time.sleep(0.1); "
        "print('three', flush=True)"
    )

    success, stdout, stderr = runtime_exec.run_argv_command_split(
        [sys.executable, "-c", script],
        timeout=2,
        idle_timeout=0.5,
    )

    assert success is True
    assert stdout == "one\ntwo\nthree\n"
    assert stderr == ""



def test_run_shell_command_returns_combined_output(monkeypatch):
    class FakeProc:
        pid = 4242
        returncode = 0

        def communicate(self, timeout=None):
            assert timeout == 30
            return ("ok stdout\n", "warn stderr\n")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_args, **_kwargs: FakeProc())

    success, output = runtime_exec.run_shell_command("echo ok", timeout=30)

    assert success is True
    assert output == "ok stdout\nwarn stderr\n"



def test_run_shell_command_kills_process_group_on_timeout(monkeypatch):
    events = []
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9001
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            events.append(("communicate", timeout))
            if calls["communicate"] in (1, 2):
                raise subprocess.TimeoutExpired(cmd="boom", timeout=timeout)
            return ("", "")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda pid, sig: events.append(("killpg", pid, sig)))
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, output = runtime_exec.run_shell_command("sleep 60", timeout=5)

    assert success is False
    assert "timed out after 5s" in output.lower()
    assert ("killpg", 9001, signal.SIGTERM) in events
    assert ("killpg", 9001, signal.SIGKILL) in events



def test_cleanup_communication_error_is_failure_and_reaches_sigkill(monkeypatch):
    events = []

    class FakeProc:
        pid = 9010

        def communicate(self, timeout=None):
            raise RuntimeError("x" * 1000)

    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(
        runtime_exec.os,
        "killpg",
        lambda pid, sig: events.append((pid, sig)),
    )

    stdout, stderr = runtime_exec._terminate_process_group(FakeProc())

    assert stdout == ""
    assert "communicate failed:" in stderr
    assert len(stderr) < 600
    assert (9010, signal.SIGTERM) in events
    assert (9010, signal.SIGKILL) in events


def test_run_shell_command_timeout_preserves_partial_and_cleanup_output(monkeypatch):
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9002
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            if calls["communicate"] == 1:
                raise subprocess.TimeoutExpired(
                    cmd="slow",
                    timeout=2,
                    output="partial stdout\n",
                    stderr="partial stderr\n",
                )
            return ("cleanup stdout\n", "cleanup stderr\n")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda *_a, **_k: None)
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, output = runtime_exec.run_shell_command("slow", timeout=2)

    assert success is False
    assert "partial stdout" in output
    assert "partial stderr" in output
    assert "cleanup stdout" in output
    assert "cleanup stderr" in output
    assert "timed out after 2s" in output.lower()



def test_run_shell_command_split_preserves_stdout_and_stderr(monkeypatch):
    class FakeProc:
        pid = 1337
        returncode = 7

        def communicate(self, timeout=None):
            assert timeout == 10
            return ("out", "err")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())

    success, stdout, stderr = runtime_exec.run_shell_command_split("exit 7", timeout=10)

    assert success is False
    assert stdout == "out"
    assert stderr == "err"


def test_run_argv_command_bounded_projection_preserves_full_artifacts(tmp_path):
    script = "import sys; print('x' * 500); print('e' * 500, file=sys.stderr)"

    success, stdout, stderr = runtime_exec.run_argv_command_split(
        [sys.executable, "-c", script],
        max_output_bytes=100,
        output_artifact_dir=tmp_path / "command-output",
    )

    assert success is True
    assert len(stdout.encode("utf-8")) <= 100
    assert len(stderr.encode("utf-8")) <= 100
    assert "output truncated" in stdout
    assert (tmp_path / "command-output" / "stdout.txt").read_text().startswith("x" * 500)
    assert (tmp_path / "command-output" / "stderr.txt").read_text().startswith("e" * 500)


def test_run_argv_command_rejects_invalid_output_limit():
    with pytest.raises(ValueError, match="max_output_bytes"):
        runtime_exec.run_argv_command([sys.executable, "-c", "pass"], max_output_bytes=0)



def test_run_shell_command_split_kills_process_group_on_timeout(monkeypatch):
    events = []
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9003
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            events.append(("communicate", timeout))
            if calls["communicate"] in (1, 2):
                raise subprocess.TimeoutExpired(cmd="hang", timeout=timeout)
            return ("", "")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda pid, sig: events.append(("killpg", pid, sig)))
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, stdout, stderr = runtime_exec.run_shell_command_split("hang", timeout=4)

    assert success is False
    assert stdout == ""
    assert "timed out after 4s" in stderr.lower()
    assert ("killpg", 9003, signal.SIGTERM) in events
    assert ("killpg", 9003, signal.SIGKILL) in events



def test_run_shell_command_split_timeout_preserves_partial_stdout_and_stderr(monkeypatch):
    calls = {"communicate": 0}

    class FakeProc:
        pid = 9004
        returncode = None

        def communicate(self, timeout=None):
            calls["communicate"] += 1
            if calls["communicate"] == 1:
                raise subprocess.TimeoutExpired(
                    cmd="slow split",
                    timeout=6,
                    output="partial out\n",
                    stderr="partial err\n",
                )
            return ("cleanup out\n", "cleanup err\n")

    monkeypatch.setattr(runtime_exec.subprocess, "Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr(runtime_exec.os, "killpg", lambda *_a, **_k: None)
    monkeypatch.setattr(runtime_exec.os, "getpgid", lambda pid: pid)

    success, stdout, stderr = runtime_exec.run_shell_command_split("slow split", timeout=6)

    assert success is False
    assert stdout == "partial out\ncleanup out\n"
    assert "partial err" in stderr
    assert "cleanup err" in stderr
    assert "timed out after 6s" in stderr.lower()



def test_run_shell_command_timeout_real_subprocess_does_not_duplicate_output():
    success, output = runtime_exec.run_shell_command(_timeout_test_command(), timeout=0.1)

    assert success is False
    assert output.count("hello\n") == 1
    assert output.count("err\n") == 1
    assert "command timed out after 0.1s" in output.lower()



def test_run_shell_command_split_timeout_real_subprocess_does_not_duplicate_output():
    success, stdout, stderr = runtime_exec.run_shell_command_split(_timeout_test_command(), timeout=0.1)

    assert success is False
    assert stdout == "hello\n"
    assert stderr.count("err\n") == 1
    assert "command timed out after 0.1s" in stderr.lower()



def test_concat_streams_keeps_legitimate_repeated_output():
    assert runtime_exec._concat_streams("aa", "aa") == "aaaa"
    assert runtime_exec._concat_streams("hello\n", "hello\n") == "hello\nhello\n"



def test_trim_replayed_prefix_only_strips_confirmed_duplicate_prefix():
    assert runtime_exec._trim_replayed_prefix("hello\n", "hello\nworld\n") == "world\n"
    assert runtime_exec._trim_replayed_prefix("abc", "bcd") == "bcd"
    assert runtime_exec._trim_replayed_prefix("same", "same") == ""


def test_zero_day_fuzzer_run_cmd_delegates_to_split_shared_helper(monkeypatch):
    captured = {}

    def fake_run_shell_command_split(cmd, *, cwd=None, timeout=600, max_output_bytes=None):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        captured["max_output_bytes"] = max_output_bytes
        return False, "out", "err"

    monkeypatch.setattr(
        zero_day_fuzzer,
        "run_shell_command_split",
        fake_run_shell_command_split,
        raising=False,
    )

    success, stdout, stderr = zero_day_fuzzer.run_cmd("echo nope", timeout=9)

    assert (success, stdout, stderr) == (False, "out", "err")
    assert captured == {"cmd": "echo nope", "cwd": None, "timeout": 9, "max_output_bytes": None}


def test_zero_day_fuzzer_run_cmd_preserves_legacy_timeout_contract(monkeypatch):
    captured = {}

    def fake_run_shell_command_split(cmd, *, cwd=None, timeout=600, max_output_bytes=None):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        captured["max_output_bytes"] = max_output_bytes
        return False, "partial out\n", "partial err\nCommand timed out after 9s"

    monkeypatch.setattr(
        zero_day_fuzzer,
        "run_shell_command_split",
        fake_run_shell_command_split,
        raising=False,
    )

    success, stdout, stderr = zero_day_fuzzer.run_cmd("sleep 9", timeout=9)

    assert (success, stdout, stderr) == (False, "", "timeout")
    assert captured == {"cmd": "sleep 9", "cwd": None, "timeout": 9, "max_output_bytes": None}
