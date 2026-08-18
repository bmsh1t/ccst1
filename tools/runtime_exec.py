"""Shared subprocess execution helpers with process-group cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Sequence
from typing import Any

TERMINATION_GRACE_SECONDS = 3


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _bounded_error(error: BaseException, limit: int = 240) -> str:
    message = " ".join(str(error).split())[:limit]
    return message or type(error).__name__


def _append_message(stream: str, message: str) -> str:
    if not stream:
        return message
    if stream.endswith("\n"):
        return stream + message
    return stream + "\n" + message


def _concat_streams(existing: str, new: str) -> str:
    return existing + new


def _trim_replayed_prefix(partial: str, cleanup: str) -> str:
    if partial and cleanup.startswith(partial):
        return cleanup[len(partial) :]
    return cleanup


def _communicate_for(proc: subprocess.Popen[str], timeout: int | float) -> tuple[str, str, bool]:
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return _to_text(stdout), _to_text(stderr), True
    except subprocess.TimeoutExpired as exc:
        return _to_text(exc.output), _to_text(exc.stderr), False
    except Exception as exc:
        return "", f"communicate failed: {_bounded_error(exc)}", False


def _merge_timeout_stream(partial: str, cleanup: str) -> str:
    return _concat_streams(partial, _trim_replayed_prefix(partial, cleanup))


def _terminate_process_group(proc: subprocess.Popen[str]) -> tuple[str, str]:
    try:
        pgid = os.getpgid(proc.pid)
    except Exception as exc:
        return "", f"process-group lookup failed: {_bounded_error(exc)}"

    termination_error = ""
    try:
        os.killpg(pgid, signal.SIGTERM)
    except Exception as exc:
        termination_error = f"SIGTERM failed: {_bounded_error(exc)}"

    stdout, stderr, finished = _communicate_for(proc, TERMINATION_GRACE_SECONDS)
    if termination_error:
        stderr = _append_message(stderr, termination_error)
    if finished:
        return stdout, stderr

    try:
        os.killpg(pgid, signal.SIGKILL)
    except Exception as exc:
        return stdout, _append_message(stderr, f"SIGKILL failed: {_bounded_error(exc)}")

    kill_stdout, kill_stderr, _finished = _communicate_for(proc, TERMINATION_GRACE_SECONDS)
    return _merge_timeout_stream(stdout, kill_stdout), _merge_timeout_stream(stderr, kill_stderr)


def _spawn(
    cmd: str | Sequence[str],
    *,
    shell: bool = True,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        cmd,
        shell=shell,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def _validate_idle_timeout(idle_timeout: int | float | None) -> None:
    if idle_timeout is None:
        return
    if (
        isinstance(idle_timeout, bool)
        or not isinstance(idle_timeout, (int, float))
        or idle_timeout <= 0
    ):
        raise ValueError("idle_timeout must be a positive number or None")


def _communicate_with_idle_timeout(
    proc: subprocess.Popen[str],
    *,
    timeout: int | float,
    idle_timeout: int | float,
) -> tuple[str, str, str | None]:
    started = last_activity = time.monotonic()
    stdout = stderr = ""
    poll_interval = min(1.0, idle_timeout / 4)

    while True:
        now = time.monotonic()
        total_remaining = timeout - (now - started)
        idle_remaining = idle_timeout - (now - last_activity)
        if total_remaining <= 0:
            return stdout, stderr, "total"
        if idle_remaining <= 0:
            return stdout, stderr, "idle"

        try:
            final_stdout, final_stderr = proc.communicate(
                timeout=min(total_remaining, idle_remaining, poll_interval)
            )
            return _to_text(final_stdout), _to_text(final_stderr), None
        except subprocess.TimeoutExpired as exc:
            partial_stdout = _to_text(exc.output)
            partial_stderr = _to_text(exc.stderr)
            if partial_stdout != stdout or partial_stderr != stderr:
                stdout, stderr = partial_stdout, partial_stderr
                last_activity = time.monotonic()


def _run_command_split(
    cmd: str | Sequence[str],
    *,
    shell: bool,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    _validate_idle_timeout(idle_timeout)
    try:
        proc = _spawn(cmd, shell=shell, cwd=cwd, env=env)
    except OSError as exc:
        return False, "", str(exc)
    try:
        if idle_timeout is not None:
            stdout, stderr, timeout_kind = _communicate_with_idle_timeout(
                proc,
                timeout=timeout,
                idle_timeout=idle_timeout,
            )
            if timeout_kind is None:
                return proc.returncode == 0, stdout, stderr

            cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
            stdout = _merge_timeout_stream(stdout, cleanup_stdout)
            stderr = _merge_timeout_stream(stderr, cleanup_stderr)
            message = (
                f"Command timed out after {timeout}s"
                if timeout_kind == "total"
                else f"Command produced no output for {idle_timeout}s (idle timeout)"
            )
            return False, stdout, _append_message(stderr, message)

        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode == 0, _to_text(stdout), _to_text(stderr)
    except subprocess.TimeoutExpired as exc:
        stdout = _to_text(exc.output)
        stderr = _to_text(exc.stderr)
        cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
        stdout = _merge_timeout_stream(stdout, cleanup_stdout)
        stderr = _merge_timeout_stream(stderr, cleanup_stderr)
        stderr = _append_message(stderr, f"Command timed out after {timeout}s")
        return False, stdout, stderr
    except Exception as exc:
        stdout = _to_text(getattr(exc, "output", None))
        stderr = _to_text(getattr(exc, "stderr", None))
        cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
        stdout = _merge_timeout_stream(stdout, cleanup_stdout)
        stderr = _merge_timeout_stream(stderr, cleanup_stderr)
        stderr = _append_message(stderr, f"command failed: {_bounded_error(exc)}")
        return False, stdout, stderr


def _run_shell_command_split(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    return _run_command_split(
        cmd,
        shell=True,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
    )


def _normalize_argv(argv: Sequence[str]) -> list[str]:
    if (
        isinstance(argv, (str, bytes))
        or not isinstance(argv, Sequence)
        or not argv
        or any(not isinstance(value, str) for value in argv)
    ):
        raise ValueError("argv must be a non-empty sequence of strings")
    return list(argv)


def run_shell_command(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
    success, stdout, stderr = _run_shell_command_split(
        cmd,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
    )
    return success, stdout + stderr


def run_shell_command_split(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    return _run_shell_command_split(
        cmd,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
    )


def run_argv_command(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
    success, stdout, stderr = run_argv_command_split(
        argv,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
    )
    return success, stdout + stderr


def run_argv_command_split(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    return _run_command_split(
        _normalize_argv(argv),
        shell=False,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
    )
