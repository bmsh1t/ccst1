"""私有运行产物的最小权限写入工具。"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any


def ensure_private_dir(path: str | Path) -> Path:
    """创建 `.private` 子目录，并强制沿途目录仅 owner 可访问。"""
    resolved = Path(path)
    parts = [resolved]
    parent = resolved.parent
    while parent != parent.parent and parent.name != ".private":
        parts.append(parent)
        parent = parent.parent
    if parent.name != ".private":
        raise ValueError(f"private artifact path must be under .private: {resolved}")
    parts.append(parent)
    for directory in reversed(parts):
        directory.mkdir(exist_ok=True)
        os.chmod(directory, 0o700)
    return resolved


def private_artifact_dir(
    repo_root: str | Path,
    capability: str,
    target_key: str,
    run_id: str = "",
) -> Path:
    path = Path(repo_root) / ".private" / capability / target_key
    if run_id:
        path /= run_id
    return ensure_private_dir(path)


def secure_file(path: str | Path) -> Path:
    resolved = Path(path)
    ensure_private_dir(resolved.parent)
    if resolved.exists():
        os.chmod(resolved, 0o600)
    return resolved


def write_private_text(path: str | Path, text: str) -> Path:
    resolved = secure_file(path)
    resolved.write_text(text, encoding="utf-8")
    os.chmod(resolved, 0o600)
    return resolved


def write_private_json(path: str | Path, payload: Any) -> Path:
    return write_private_text(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )


def copy_private_file(source: str | Path, destination: str | Path) -> Path:
    resolved = secure_file(destination)
    shutil.copyfile(source, resolved)
    os.chmod(resolved, 0o600)
    return resolved
