"""Shared subprocess execution helpers with process-group cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

TERMINATION_GRACE_SECONDS = 3
DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _bounded_error(error: BaseException, limit: int = 240) -> str:
    message = " ".join(str(error).split())[:limit]
    return message or type(error).__name__


def _validate_output_limit(max_output_bytes: int | None) -> None:
    if max_output_bytes is None:
        return
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes < 1
    ):
        raise ValueError("max_output_bytes must be a positive integer or None")


def _clip_output(value: str, max_output_bytes: int | None) -> str:
    text = _to_text(value)
    if max_output_bytes is None:
        return text
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_output_bytes:
        return text
    marker = f"\n...[output truncated; {len(encoded)} bytes total]...\n".encode("utf-8")
    if len(marker) >= max_output_bytes:
        return marker[:max_output_bytes].decode("utf-8", errors="ignore")
    available = max_output_bytes - len(marker)
    head_bytes = available // 2
    tail_bytes = available - head_bytes
    head = encoded[:head_bytes].decode("utf-8", errors="ignore")
    tail = encoded[-tail_bytes:].decode("utf-8", errors="ignore") if tail_bytes else ""
    return head + marker.decode("utf-8") + tail


def _read_captured_output(path: Path, max_output_bytes: int) -> str:
    """Read a bounded head/tail projection without materializing the stream."""
    total = path.stat().st_size
    if total <= max_output_bytes:
        return path.read_bytes().decode("utf-8", errors="replace")
    marker = f"\n...[output truncated; {total} bytes total]...\n".encode("utf-8")
    if len(marker) >= max_output_bytes:
        return marker[:max_output_bytes].decode("utf-8", errors="ignore")
    available = max_output_bytes - len(marker)
    head_size = available // 2
    tail_size = available - head_size
    with path.open("rb") as handle:
        head = handle.read(head_size)
        handle.seek(-tail_size, os.SEEK_END)
        tail = handle.read(tail_size)
    return (head + marker + tail).decode("utf-8", errors="replace")


def _finalize_output(
    stdout: str,
    stderr: str,
    *,
    max_output_bytes: int | None,
    output_artifact_dir: str | Path | None,
) -> tuple[str, str]:
    """Persist complete streams when requested, then return bounded projections."""
    stdout = _to_text(stdout)
    stderr = _to_text(stderr)
    if output_artifact_dir:
        root = Path(output_artifact_dir)
        root.mkdir(parents=True, exist_ok=True)
        (root / "stdout.txt").write_text(stdout, encoding="utf-8")
        (root / "stderr.txt").write_text(stderr, encoding="utf-8")
    return (
        _clip_output(stdout, max_output_bytes),
        _clip_output(stderr, max_output_bytes),
    )


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
    stdout: Any = subprocess.PIPE,
    stderr: Any = subprocess.PIPE,
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        cmd,
        shell=shell,
        cwd=cwd,
        env=env,
        stdout=stdout,
        stderr=stderr,
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
    max_output_bytes: int | None = DEFAULT_MAX_OUTPUT_BYTES,
    output_artifact_dir: str | Path | None = None,
) -> tuple[bool, str, str]:
    _validate_idle_timeout(idle_timeout)
    _validate_output_limit(max_output_bytes)
    capture_tempdir: tempfile.TemporaryDirectory[str] | None = None
    capture_handles: list[Any] = []
    capture_paths: tuple[Path, Path] | None = None
    capture_streams = max_output_bytes is not None and idle_timeout is None
    try:
        if capture_streams:
            if output_artifact_dir:
                capture_root = Path(output_artifact_dir)
                capture_root.mkdir(parents=True, exist_ok=True)
            else:
                capture_tempdir = tempfile.TemporaryDirectory(prefix="ccst-runtime-output-")
                capture_root = Path(capture_tempdir.name)
            capture_paths = (capture_root / "stdout.txt", capture_root / "stderr.txt")
            capture_handles = [path.open("w+b") for path in capture_paths]
            proc = _spawn(
                cmd,
                shell=shell,
                cwd=cwd,
                env=env,
                stdout=capture_handles[0],
                stderr=capture_handles[1],
            )
        else:
            proc = _spawn(cmd, shell=shell, cwd=cwd, env=env)
    except OSError as exc:
        for handle in capture_handles:
            handle.close()
        if capture_tempdir is not None:
            capture_tempdir.cleanup()
        return False, "", str(exc)

    def read_capture() -> tuple[str, str]:
        if not capture_streams or capture_paths is None:
            return "", ""
        for handle in capture_handles:
            handle.flush()
            handle.close()
        return (
            _read_captured_output(capture_paths[0], max_output_bytes),  # type: ignore[arg-type]
            _read_captured_output(capture_paths[1], max_output_bytes),  # type: ignore[arg-type]
        )

    def finish(success: bool, stdout: str, stderr: str) -> tuple[bool, str, str]:
        try:
            if capture_streams:
                captured_stdout, captured_stderr = read_capture()
                # A fake process or a platform wrapper may still return streams
                # directly; use them only when the capture file is empty.
                stdout = captured_stdout or _to_text(stdout)
                captured_stderr = captured_stderr or _to_text(stderr)
                if stderr and captured_stderr != _to_text(stderr):
                    captured_stderr = _append_message(captured_stderr, _to_text(stderr))
                return success, stdout, captured_stderr
            projected_stdout, projected_stderr = _finalize_output(
                stdout,
                stderr,
                max_output_bytes=max_output_bytes,
                output_artifact_dir=output_artifact_dir,
            )
        except OSError as exc:
            projected_stdout = _clip_output(stdout, max_output_bytes)
            projected_stderr = _append_message(
                _clip_output(stderr, max_output_bytes),
                f"output artifact write failed: {_bounded_error(exc)}",
            )
            success = False
        return success, projected_stdout, projected_stderr

    try:
        if idle_timeout is not None:
            stdout, stderr, timeout_kind = _communicate_with_idle_timeout(
                proc,
                timeout=timeout,
                idle_timeout=idle_timeout,
            )
            if timeout_kind is None:
                return finish(proc.returncode == 0, stdout, stderr)

            cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
            stdout = _merge_timeout_stream(stdout, cleanup_stdout)
            stderr = _merge_timeout_stream(stderr, cleanup_stderr)
            message = (
                f"Command timed out after {timeout}s"
                if timeout_kind == "total"
                else f"Command produced no output for {idle_timeout}s (idle timeout)"
            )
            return finish(False, stdout, _append_message(stderr, message))

        stdout, stderr = proc.communicate(timeout=timeout)
        return finish(proc.returncode == 0, stdout, stderr)
    except subprocess.TimeoutExpired as exc:
        stdout = _to_text(exc.output)
        stderr = _to_text(exc.stderr)
        cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
        stdout = _merge_timeout_stream(stdout, cleanup_stdout)
        stderr = _merge_timeout_stream(stderr, cleanup_stderr)
        stderr = _append_message(stderr, f"Command timed out after {timeout}s")
        return finish(False, stdout, stderr)
    except Exception as exc:
        stdout = _to_text(getattr(exc, "output", None))
        stderr = _to_text(getattr(exc, "stderr", None))
        cleanup_stdout, cleanup_stderr = _terminate_process_group(proc)
        stdout = _merge_timeout_stream(stdout, cleanup_stdout)
        stderr = _merge_timeout_stream(stderr, cleanup_stderr)
        stderr = _append_message(stderr, f"command failed: {_bounded_error(exc)}")
        return finish(False, stdout, stderr)
    finally:
        for handle in capture_handles:
            if not handle.closed:
                handle.close()
        if capture_tempdir is not None:
            capture_tempdir.cleanup()


def _run_shell_command_split(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
    max_output_bytes: int | None = DEFAULT_MAX_OUTPUT_BYTES,
    output_artifact_dir: str | Path | None = None,
) -> tuple[bool, str, str]:
    return _run_command_split(
        cmd,
        shell=True,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
        max_output_bytes=max_output_bytes,
        output_artifact_dir=output_artifact_dir,
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
    max_output_bytes: int | None = DEFAULT_MAX_OUTPUT_BYTES,
    output_artifact_dir: str | Path | None = None,
) -> tuple[bool, str]:
    success, stdout, stderr = _run_shell_command_split(
        cmd,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
        max_output_bytes=max_output_bytes,
        output_artifact_dir=output_artifact_dir,
    )
    return success, stdout + stderr


def run_shell_command_split(
    cmd: str,
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
    max_output_bytes: int | None = DEFAULT_MAX_OUTPUT_BYTES,
    output_artifact_dir: str | Path | None = None,
) -> tuple[bool, str, str]:
    return _run_shell_command_split(
        cmd,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
        max_output_bytes=max_output_bytes,
        output_artifact_dir=output_artifact_dir,
    )


def run_argv_command(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
    max_output_bytes: int | None = DEFAULT_MAX_OUTPUT_BYTES,
    output_artifact_dir: str | Path | None = None,
) -> tuple[bool, str]:
    success, stdout, stderr = run_argv_command_split(
        argv,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
        max_output_bytes=max_output_bytes,
        output_artifact_dir=output_artifact_dir,
    )
    return success, stdout + stderr


def run_argv_command_split(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: int | float = 600,
    idle_timeout: int | float | None = None,
    env: dict[str, str] | None = None,
    max_output_bytes: int | None = DEFAULT_MAX_OUTPUT_BYTES,
    output_artifact_dir: str | Path | None = None,
) -> tuple[bool, str, str]:
    return _run_command_split(
        _normalize_argv(argv),
        shell=False,
        cwd=cwd,
        timeout=timeout,
        idle_timeout=idle_timeout,
        env=env,
        max_output_bytes=max_output_bytes,
        output_artifact_dir=output_artifact_dir,
    )
