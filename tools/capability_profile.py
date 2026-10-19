#!/usr/bin/env python3
"""Read-only local dependency facts for `/autopilot`, not execution readiness."""

from __future__ import annotations

import shutil
import hashlib
import json
import os
import time
import fcntl
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

try:
    from tools.eburst_lane import resolve_eburst
    from tools.artifact_io import write_json_atomic
except ImportError:  # pragma: no cover - direct tools/ execution
    from eburst_lane import resolve_eburst  # type: ignore
    from artifact_io import write_json_atomic  # type: ignore


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
DEGRADED_MARKER = ".ccst-capability-degraded.json"
DEGRADED_SCHEMA_VERSION = 1
MAX_MARKER_BYTES = 16384


def _marker_payload(value: object) -> dict:
    fields = {"schema_version", "recorded_at", "source", "reason", "missing", "profile_sha256"}
    if not isinstance(value, dict) or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != DEGRADED_SCHEMA_VERSION:
        raise ValueError("invalid capability marker schema")
    for field, limit in (("recorded_at", 32), ("source", 128), ("reason", 500)):
        if not isinstance(value[field], str) or not value[field].strip() or len(value[field]) > limit:
            raise ValueError(f"invalid capability marker {field}")
    time.strptime(value["recorded_at"], "%Y-%m-%dT%H:%M:%SZ")
    missing = value["missing"]
    if not isinstance(missing, list) or len(missing) > 64 or any(
        not isinstance(item, str) or not item.strip() or len(item) > 128 for item in missing
    ) or len(set(missing)) != len(missing):
        raise ValueError("invalid capability marker missing list")
    digest = value["profile_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("invalid capability marker profile digest")
    return value


def _regular_marker_destination(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise ValueError("capability marker must be a regular file, not a link or special file")


@contextmanager
def _marker_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f"{path.name}.lock")
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "w") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("capability marker lock must be a regular file")
        fcntl.flock(lock, fcntl.LOCK_EX)
        _regular_marker_destination(path)
        yield


def capability_marker_path(runtime_root: str | Path | None = None) -> Path:
    """Return the runtime-global capability marker path."""
    root = Path(runtime_root or os.environ.get("CCST_RUNTIME_ROOT") or (Path.home() / ".claude"))
    return root.expanduser().resolve() / DEGRADED_MARKER


def load_capability_degraded_marker(runtime_root: str | Path | None = None) -> dict:
    """Read an explicit degraded marker without probing or repairing it."""
    path = None
    try:
        path = capability_marker_path(runtime_root)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("capability marker must be a regular file")
            content = handle.read(MAX_MARKER_BYTES + 1)
        if len(content) > MAX_MARKER_BYTES:
            raise ValueError("capability marker exceeds size limit")
        payload = _marker_payload(json.loads(content.decode("utf-8")))
    except FileNotFoundError:
        return {"status": "none", "path": str(path), "schema_version": DEGRADED_SCHEMA_VERSION}
    except (OSError, ValueError, RuntimeError) as exc:
        return {
            "status": "invalid",
            "path": str(path),
            "schema_version": DEGRADED_SCHEMA_VERSION,
            "reason": f"{type(exc).__name__}: {exc}"[:500],
        }
    return {**payload, "status": "degraded", "path": str(path)}


def write_capability_degraded_marker(
    runtime_root: str | Path | None = None,
    *,
    reason: str,
    missing: list[str] | None = None,
    source: str = "explicit",
    profile: dict | None = None,
) -> dict:
    """Persist an operator-confirmed capability degradation atomically.

    This is an explicit writer; startup discovery remains read-only.  The
    marker is runtime-global so a later target session can display the same
    known limitation without treating it as target evidence.
    """
    path = capability_marker_path(runtime_root)
    profile_bytes = json.dumps(profile or {}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload = {
        "schema_version": DEGRADED_SCHEMA_VERSION,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": str(source or "explicit"),
        "reason": str(reason or "").strip(),
        "missing": sorted({str(item).strip() for item in (missing or []) if str(item).strip()}),
        "profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
    }
    _marker_payload(payload)
    encoded = (json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_MARKER_BYTES:
        raise ValueError("capability marker exceeds serialized size limit")
    with _marker_lock(path):
        write_json_atomic(path, payload, ensure_ascii=True, sort_keys=True)
    return {**payload, "status": "degraded", "path": str(path)}


def clear_capability_degraded_marker(runtime_root: str | Path | None = None) -> dict:
    """Explicitly acknowledge recovery; discovery never clears the marker."""
    path = capability_marker_path(runtime_root)
    with _marker_lock(path):
        path.unlink(missing_ok=True)
    return {"status": "none", "path": str(path), "schema_version": DEGRADED_SCHEMA_VERSION}


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


def main(argv: list[str] | None = None) -> int:
    """Explicit operator entry point for the runtime-global degradation note."""
    import argparse

    parser = argparse.ArgumentParser(description="Read or record capability degradation state.")
    parser.add_argument("command", choices=("show", "record-degraded", "clear"))
    parser.add_argument("--runtime-root", default=None)
    parser.add_argument("--reason", default="capability unavailable")
    parser.add_argument("--missing", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == "show":
            result = load_capability_degraded_marker(args.runtime_root)
        elif args.command == "clear":
            result = clear_capability_degraded_marker(args.runtime_root)
        else:
            result = write_capability_degraded_marker(
                args.runtime_root, reason=args.reason, missing=args.missing,
                source="capability-profile-cli",
            )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"capability marker: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result["status"] == "invalid" else 0


if __name__ == "__main__":
    raise SystemExit(main())
