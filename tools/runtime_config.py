#!/usr/bin/env python3
"""Shared runtime config helpers for repo-local execution flags."""

from __future__ import annotations

import json
from pathlib import Path


def load_runtime_config(repo_root: str | Path) -> dict:
    """Load repo-local config.json if present; ignore missing/invalid files."""
    config_path = Path(repo_root) / "config.json"
    if not config_path.exists():
        return {}

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    return data if isinstance(data, dict) else {}


def is_ctf_mode_enabled(repo_root: str | Path, explicit: bool | None = None) -> bool:
    """Resolve repo-local CTF mode, allowing an explicit override."""
    if explicit is not None:
        return bool(explicit)
    return bool(load_runtime_config(repo_root).get("ctf_mode", False))
