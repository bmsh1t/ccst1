#!/usr/bin/env python3
"""在现有 runtime phase lock 内执行 direct Shell 入口。"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

try:
    from tools.runtime_state import RuntimePhaseBusy, runtime_phase_lock, update_runtime_state
except ImportError:  # pragma: no cover - direct tools/ execution
    from runtime_state import RuntimePhaseBusy, runtime_phase_lock, update_runtime_state  # type: ignore


def run_phase_command(
    repo_root: str | Path,
    target: str,
    phase: str,
    command: list[str],
) -> int:
    if not command:
        raise ValueError("phase command is required")
    returncode: int | None = None
    try:
        with runtime_phase_lock(repo_root, target, phase):
            update_runtime_state(
                repo_root,
                target,
                mode=f"{phase}_running",
                last_executed_workflow=f"run_{phase}_started",
            )
            env = os.environ.copy()
            env["BBHUNT_RUNTIME_PHASE_LOCKED"] = phase
            env["BBHUNT_RUNTIME_LOCK_TARGET"] = target
            try:
                returncode = subprocess.run(command, env=env, check=False).returncode
                return returncode
            finally:
                succeeded = returncode == 0
                update_runtime_state(
                    repo_root,
                    target,
                    mode=f"{phase}_only" if succeeded else f"{phase}_failed",
                    last_executed_workflow=(
                        "run_recon" if phase == "recon" else "run_vuln_scan"
                    ) if succeeded else (
                        "run_recon_failed" if phase == "recon" else "run_vuln_scan_failed"
                    ),
                )
    except RuntimePhaseBusy as exc:
        print(f"runtime phase busy: {exc}", file=sys.stderr)
        return 75


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a command under the target runtime phase lock")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--phase", required=True, choices=("recon", "scan"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    return run_phase_command(args.repo_root, args.target, args.phase, command)


if __name__ == "__main__":
    raise SystemExit(main())
