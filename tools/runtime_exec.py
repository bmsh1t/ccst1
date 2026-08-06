"""Shared subprocess execution helpers with process-group cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
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


def _run_command_split(
    cmd: str | Sequence[str],
    *,
    shell: bool,
    cwd: str | None = None,
    timeout: int | float = 600,
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    try:
        proc = _spawn(cmd, shell=shell, cwd=cwd, env=env)
    except OSError as exc:
        return False, "", str(exc)
    try:
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
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    return _run_command_split(cmd, shell=True, cwd=cwd, timeout=timeout, env=env)


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
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
    success, stdout, stderr = _run_shell_command_split(cmd, cwd=cwd, timeout=timeout, env=env)
    return success, stdout + stderr


def run_shell_command_split(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    return _run_shell_command_split(cmd, cwd=cwd, timeout=timeout, env=env)


def run_argv_command(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
    success, stdout, stderr = run_argv_command_split(argv, cwd=cwd, timeout=timeout, env=env)
    return success, stdout + stderr


def run_argv_command_split(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    return _run_command_split(
        _normalize_argv(argv),
        shell=False,
        cwd=cwd,
        timeout=timeout,
        env=env,
    )
