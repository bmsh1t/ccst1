#!/usr/bin/env python3
"""Read-only local dependency facts for `/autopilot`, not execution readiness."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable

try:
    from tools.eburst_lane import resolve_eburst
except ImportError:  # pragma: no cover - direct tools/ execution
    from eburst_lane import resolve_eburst  # type: ignore


SCHEMA_VERSION = 2
REPO_ROOT = Path(__file__).resolve().parents[1]
# Fixed startup discovery only; execution owners check their actual dependencies.
LOCAL_TOOLS = (
    "curl", "httpx", "subfinder", "katana", "gau", "waybackurls", "ffuf",
    "nuclei", "alterx", "dnsgen", "puredns", "eburst", "interactsh-client",
    "forge", "cloud_enum", "s3scanner",
)
LOCAL_FILES = (
    "tools/recon_engine.sh", "tools/vuln_scanner.sh", "tools/browser_mcp_import.py",
)
SESSION_MANAGED = ("chrome-devtools-mcp", "playwright-mcp")
Which = Callable[[str], str | None]


def unknown_capability_profile(reason: str = "not-checked") -> dict:
    """Unknown is distinct from a completed check that found no dependencies."""
    return {
        "schema_version": SCHEMA_VERSION,
        "checked": False,
        "status": "unknown",
        "available": [],
        "missing": [],
        "local_files": {},
        "session_managed": list(SESSION_MANAGED),
        "session_status": "unchecked",
        "reason": reason,
    }


def build_capability_profile(
    repo_root: str | Path | None = None,
    *,
    which: Which | None = None,
) -> dict:
    """Discover PATH candidates and local files without executing any tool.

    EBurst reuses its owner's binary/script-and-interpreter resolution. File
    presence (including the browser importer) never proves a working backend.
    """
    resolved_repo = Path(repo_root or REPO_ROOT).resolve()
    resolver = which or shutil.which
    available, missing = [], []
    for tool in LOCAL_TOOLS:
        present = (
            resolve_eburst(which=resolver).get("status") == "ready"
            if tool == "eburst"
            else bool(resolver(tool))
        )
        (available if present else missing).append(tool)
    return {
        "schema_version": SCHEMA_VERSION,
        "checked": True,
        "status": "checked",
        "available": available,
        "missing": missing,
        "local_files": {path: (resolved_repo / path).is_file() for path in LOCAL_FILES},
        "session_managed": list(SESSION_MANAGED),
        "session_status": "unchecked",
    }
