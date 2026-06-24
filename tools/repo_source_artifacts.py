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
        except (OSError, json.JSONDecodeError):
            pass

    summary_text = ""
    if summary_path.exists():
        try:
            summary_text = summary_path.read_text(encoding="utf-8")
        except OSError:
            summary_text = ""

    if summary_text:
        secret_match = _SECRET_FINDINGS_RE.search(summary_text)
        ci_match = _CI_FINDINGS_RE.search(summary_text)
        confirmation_required = "confirmation required before clone" in summary_text.lower()

        if secret_match:
            summary["secret_findings"] = int(secret_match.group(1))
        if ci_match:
            summary["ci_findings"] = int(ci_match.group(1))
        if confirmation_required and not summary.get("status"):
            summary["status"] = "confirmation_required"

    status = str(summary.get("status", "") or "").strip()
    source_kind = str(summary.get("source_kind", "") or "").strip()
    secret_findings = int(summary.get("secret_findings", 0) or 0)
    ci_findings = int(summary.get("ci_findings", 0) or 0)

    summary_hint = ""
    if status == "confirmation_required":
        summary_hint = "confirmation required before clone"
    elif source_kind:
        summary_hint = f"{source_kind}, secrets={secret_findings}, ci={ci_findings}"

    if summary_hint:
        summary["summary_hint"] = summary_hint

    return summary
