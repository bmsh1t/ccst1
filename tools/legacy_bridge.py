"""Compatibility bridge for legacy hunt/report/memory capabilities."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

from memory.hunt_journal import HuntJournal

try:
    # Support `import tools.legacy_bridge`.
    from .runtime_exec import run_shell_command
except ImportError:
    # Keep legacy top-level `import legacy_bridge` working.
    from runtime_exec import run_shell_command


def open_hunt_journal(memory_dir: str | Path) -> HuntJournal:
    """Return the HuntJournal for the legacy journal file."""
    return HuntJournal(Path(memory_dir) / "journal.jsonl")


def run_legacy_cve_hunt(
    domain: str,
    *,
    base_dir: str,
    recon_dir: str | None = None,
    timeout: int = 600,
) -> tuple[bool, str]:
    """Delegate execution to the legacy CVE hunter script."""
    script = os.path.join(base_dir, "tools", "cve_hunter.py")
    cmd_parts = ["python3", shlex.quote(script), shlex.quote(domain)]
    if recon_dir:
        cmd_parts.extend(["--recon-dir", shlex.quote(recon_dir)])
    return run_shell_command(" ".join(cmd_parts), cwd=base_dir, timeout=timeout)



def generate_legacy_reports(
    findings_dir: str,
    *,
    base_dir: str,
    timeout: int = 600,
) -> tuple[bool, str]:
    """Delegate execution to the legacy report generator script."""
    script = os.path.join(base_dir, "tools", "report_generator.py")
    cmd_parts = ["python3", shlex.quote(script), shlex.quote(findings_dir)]
    return run_shell_command(" ".join(cmd_parts), cwd=base_dir, timeout=timeout)
