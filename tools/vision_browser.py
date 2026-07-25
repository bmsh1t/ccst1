#!/usr/bin/env python3
"""读取由 Chrome DevTools/Playwright MCP 导入的浏览器截图。"""

from __future__ import annotations

import json
from pathlib import Path

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key  # type: ignore


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"


def _target_browser_dir(target: str, evidence_root: str | Path | None) -> Path:
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    return root / target_storage_key(target) / "browser"


def find_latest_screenshot(
    target: str,
    *,
    evidence_root: str | Path | None = None,
) -> Path | None:
    """返回目标最近一次导入的 MCP 截图。"""
    rows = list_screenshots(target, evidence_root=evidence_root)
    return Path(rows[-1]["screenshot_path"]) if rows else None


def list_screenshots(target: str, *, evidence_root: str | Path | None = None) -> list[dict]:
    """按捕获顺序列出 summary 引用的私有截图与 snapshot。"""
    target_dir = _target_browser_dir(target, evidence_root)
    if not target_dir.exists():
        return []
    captures: list[tuple[str, float, str, dict]] = []
    for summary_path in target_dir.glob("*/summary.json"):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary_mtime = summary_path.stat().st_mtime
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(summary, dict):
            continue
        artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
        screenshot = Path(str(artifacts.get("screenshot_png") or summary.get("screenshot_path") or ""))
        if not screenshot.is_file():
            continue
        snapshot = Path(str(
            artifacts.get("snapshot_private_txt")
            or artifacts.get("snapshot_txt")
            or summary.get("dom_path")
            or ""
        ))
        captures.append((
            str(summary.get("captured_at") or ""),
            summary_mtime,
            str(summary_path),
            {
                "screenshot_path": str(screenshot),
                "dom_path": str(snapshot) if snapshot.is_file() else "",
                "capture_dir": str(summary.get("evidence_dir") or summary_path.parent),
                "summary_path": str(summary_path),
                "url": str(summary.get("url") or ""),
                "captured_at": str(summary.get("captured_at") or ""),
            },
        ))
    captures.sort(key=lambda item: item[:3])
    return [{"seq": seq, **item[3]} for seq, item in enumerate(captures, 1)]
