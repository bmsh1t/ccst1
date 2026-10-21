#!/usr/bin/env python3
"""
repo_source_artifacts.py — shared helpers for repo-source exposure artifacts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key

KNOWN_REPO_SOURCE_ARTIFACTS = (
    "repo_source_meta.json",
    "repo_secrets.json",
    "repo_ci_findings.json",
    "repo_workflows.json",
    "repo_summary.md",
)

_SECRET_FINDINGS_RE = re.compile(r"^- Secret findings:\s*(\d+)\s*$", re.M)
_CI_FINDINGS_RE = re.compile(r"^- CI findings:\s*(\d+)\s*$", re.M)


def repo_source_exposure_dir(repo_root: str | Path, target: str) -> Path:
    """Return the standard repo-source exposure directory for a target."""
    return Path(repo_root) / "findings" / target_storage_key(target) / "exposure"


def list_repo_source_artifacts(repo_root: str | Path, target: str) -> list[str]:
    """List known repo-source artifact files that already exist for a target."""
    exposure_dir = repo_source_exposure_dir(repo_root, target)
    if not exposure_dir.is_dir():
        return []

    return [
        name
        for name in KNOWN_REPO_SOURCE_ARTIFACTS
        if (exposure_dir / name).is_file()
    ]


def has_repo_source_artifacts(repo_root: str | Path, target: str) -> bool:
    """Check whether any known repo-source artifacts exist for a target."""
    return bool(list_repo_source_artifacts(repo_root, target))


def load_repo_source_summary(repo_root: str | Path, target: str) -> dict:
    """Load a compact repo-source summary from exposure artifacts when present."""
    exposure_dir = repo_source_exposure_dir(repo_root, target)
    meta_path = exposure_dir / "repo_source_meta.json"
    summary_path = exposure_dir / "repo_summary.md"

    summary: dict[str, object] = {}

    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(meta, dict):
                summary["status"] = str(meta.get("status", "") or "")
                summary["source_kind"] = str(meta.get("source_kind", "") or "")
                summary["clone_performed"] = bool(meta.get("clone_performed", False))
                summary["repo_commit"] = str(meta.get("repo_commit") or "")
                if meta.get("execution_mode") == "source-capture":
                    summary["execution_mode"] = "source-capture"
                    capture = meta.get("source_capture")
                    summary["source_capture_status"] = (
                        str(capture.get("status") or "unknown")
                        if isinstance(capture, dict) else "unknown"
                    )
                    summary["secret_scan"] = str(meta.get("secret_scan") or "unknown")
                    summary["ci_scan"] = str(meta.get("ci_scan") or "unknown")
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass

    summary_text = ""
    if summary_path.exists():
        try:
            summary_text = summary_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            summary_text = ""

    if summary_text:
        secret_match = _SECRET_FINDINGS_RE.search(summary_text)
        ci_match = _CI_FINDINGS_RE.search(summary_text)
        confirmation_required = "confirmation required before clone" in summary_text.lower()

        if secret_match and summary.get("execution_mode") != "source-capture":
            summary["secret_findings"] = int(secret_match.group(1))
        if ci_match and summary.get("execution_mode") != "source-capture":
            summary["ci_findings"] = int(ci_match.group(1))
        if confirmation_required and not summary.get("status"):
            summary["status"] = "confirmation_required"

    workflows = exposure_dir / "repo_workflows.json"
    if workflows.exists():
        try:
            payload = json.loads(workflows.read_text(encoding="utf-8"))
            if (not isinstance(payload, dict) or payload.get("status") not in {"complete", "partial", "not_run"}
                    or not isinstance(payload.get("workflows"), list)):
                raise ValueError("invalid workflow inventory")
            rows = payload["workflows"]
            if any(not isinstance(row, dict) or row.get("status") not in {"ok", "invalid", "unavailable", "oversized"}
                   or not isinstance(row.get("file_path"), str) for row in rows):
                raise ValueError("invalid workflow rows")
            remaining = payload.get("remaining_files")
            if payload["status"] != "not_run" and (type(remaining) is not int or remaining < 0):
                raise ValueError("invalid workflow remainder")
            if payload["status"] == "complete" and (remaining or any(row["status"] != "ok" for row in rows)):
                raise ValueError("incomplete workflow inventory claimed complete")
            if payload.get("inventory_kind") == "source-capture" and payload["status"] != "not_run":
                total = payload.get("total_files")
                deferred = payload.get("deferred_paths")
                if (type(total) is not int or total < 0 or not isinstance(deferred, list)
                        or any(not isinstance(name, str) or not name for name in deferred)
                        or len(deferred) != remaining):
                    raise ValueError("invalid workflow totals or deferred paths")
                directory_error = (total == 0 and payload["status"] == "partial"
                                   and len(rows) == 1 and rows[0]["file_path"] == ".github/workflows"
                                   and rows[0]["status"] == "unavailable")
                if not directory_error and total != len(rows) + remaining:
                    raise ValueError("inconsistent workflow inventory counts")
            summary["workflow_status"] = payload["status"]
            summary["workflow_remaining"] = remaining
        except (OSError, UnicodeError, ValueError):
            summary["workflow_status"] = "invalid"

    status = str(summary.get("status", "") or "").strip()
    source_kind = str(summary.get("source_kind", "") or "").strip()

    summary_hint = ""
    if status == "confirmation_required":
        summary_hint = "confirmation required before clone"
    elif summary.get("execution_mode") == "source-capture":
        summary_hint = (
            f"{source_kind or 'source'}, capture={summary['source_capture_status']}, "
            f"workflows={summary.get('workflow_status', 'unknown')}, "
            f"secret scan={summary['secret_scan']}, CI analysis={summary['ci_scan']}"
        )
    elif source_kind:
        summary_hint = source_kind
        if "secret_findings" in summary:
            summary_hint += f", secrets={summary['secret_findings']}"
        if "ci_findings" in summary:
            summary_hint += f", ci={summary['ci_findings']}"
        if summary.get("workflow_status"):
            summary_hint += f", workflows={summary['workflow_status']}"

    if summary_hint:
        summary["summary_hint"] = summary_hint

    return summary
