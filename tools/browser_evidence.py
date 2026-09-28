#!/usr/bin/env python3
"""浏览器 MCP 证据的公共摘要与最近一次捕获读取辅助函数。"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key  # type: ignore


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
BROWSER_FRESHNESS_SECONDS = 24 * 60 * 60


def _target_key(target: str) -> str:
    """返回浏览器 artifact 使用的项目级目标存储键。"""
    return target_storage_key(target)


def snapshot_shape(raw: str) -> str:
    """公共 snapshot 仅保留哈希、长度与 form 形状。"""
    text = str(raw or "")
    forms = []
    for match in re.finditer(r"<form\b(?P<attrs>[^>]*)>", text, re.I):
        attrs = match.group("attrs")
        action = next(iter(re.findall(r"action=[\"']([^\"']+)[\"']", attrs, re.I)), "")
        method = next(iter(re.findall(r"method=[\"']([^\"']+)[\"']", attrs, re.I)), "GET")
        action_path = re.sub(r"\?.*$", "", action)
        forms.append(f'<form action="{action_path}" method="{method.upper()}">')
    encoded = text.encode("utf-8", errors="replace")
    header = f"snapshot_bytes={len(encoded)}\nsnapshot_sha256={hashlib.sha256(encoded).hexdigest()}\n"
    return header + (("\n".join(forms) + "\n") if forms else "")


def console_shape(payload: object) -> dict:
    """将 MCP console 输出压成不含正文的公共摘要。"""
    items = payload if isinstance(payload, list) else []
    return {
        "count": len(items),
        "types": sorted({str(item.get("type") or "") for item in items if isinstance(item, dict)}),
        "sha256": hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }


def _read_summary_from_path(path: str | Path) -> dict:
    candidate = Path(path)
    summary_path = candidate / "summary.json" if candidate.is_dir() else candidate
    if not summary_path.is_file():
        return {}
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def compact_browser_evidence(summary: dict | str | Path | None) -> dict:
    """仅返回 validation 可安全引用的浏览器证据字段。"""
    if not summary:
        return {}
    payload = _read_summary_from_path(summary) if isinstance(summary, (str, Path)) else summary
    if not isinstance(payload, dict) or not payload:
        return {}

    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    compact = {
        "dir": payload.get("evidence_dir") or payload.get("dir") or "",
        "summary_path": payload.get("summary_path") or payload.get("summary") or "",
        "session": payload.get("session") or "",
        "url": payload.get("url") or "",
        "capture_backend": payload.get("capture_backend") or "",
        "request_count": int(counts.get("requests", payload.get("request_count", 0)) or 0),
        "console_count": int(counts.get("console", payload.get("console_count", 0)) or 0),
        "screenshot_path": artifacts.get("screenshot_png") or payload.get("screenshot_path") or "",
        "captured_at": payload.get("captured_at") or "",
        "error": payload.get("error") or "",
    }
    browser_surface = payload.get("browser_surface") if isinstance(payload.get("browser_surface"), dict) else {}
    browser_counts = browser_surface.get("counts") if isinstance(browser_surface.get("counts"), dict) else {}
    browser_artifacts = browser_surface.get("artifacts") if isinstance(browser_surface.get("artifacts"), dict) else {}
    compact.update({
        "browser_xhr_count": int(browser_counts.get("xhr_endpoints", payload.get("browser_xhr_count", 0)) or 0),
        "browser_api_count": int(browser_counts.get("api_endpoints", payload.get("browser_api_count", 0)) or 0),
        "browser_param_count": int(browser_counts.get("browser_params", payload.get("browser_param_count", 0)) or 0),
        "browser_surface_summary": browser_artifacts.get("summary") or payload.get("browser_surface_summary") or "",
    })
    return {key: value for key, value in compact.items() if value not in ("", None)}


def load_last_browser_evidence(target: str, *, evidence_root: str | Path | None = None) -> dict:
    """读取目标最近一次由 MCP 导入的浏览器证据摘要。"""
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    pointer_path = root / _target_key(target) / "browser" / "last-capture.json"
    if not pointer_path.is_file():
        return {}
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(pointer, dict):
        return {}
    summary_path = pointer.get("summary_path")
    return compact_browser_evidence(summary_path or pointer)


def inspect_mcp_browser_readiness(
    repo_root: str | Path,
    target: str,
    *,
    freshness_seconds: int = BROWSER_FRESHNESS_SECONDS,
) -> dict[str, Any]:
    """Validate the importer-owned latest capture without trusting file presence."""
    root = Path(repo_root)
    key = target_storage_key(target)
    pointer_path = root / "evidence" / key / "browser" / "last-capture.json"
    result: dict[str, Any] = {
        "present": False,
        "ready": False,
        "status": "missing",
        "success": False,
        "core_network": False,
        "fresh": False,
        "fingerprint": "",
        "fingerprint_valid": False,
        "auth_required": False,
        "auth_state": "unknown",
        "summary_path": str(pointer_path),
        "reason": "missing browser capture",
    }
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return result
    if not isinstance(pointer, dict):
        result["reason"] = "invalid browser pointer"
        return result
    summary_path = Path(str(pointer.get("summary_path") or ""))
    if not summary_path.is_absolute():
        summary_path = pointer_path.parent / summary_path
    result["summary_path"] = str(summary_path)
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result["reason"] = "missing or invalid browser summary"
        return result
    if not isinstance(summary, dict):
        result["reason"] = "invalid browser summary"
        return result

    result["present"] = True
    result["status"] = str(summary.get("status") or "unknown").strip().lower()
    result["success"] = bool(summary.get("success"))
    counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
    result["core_network"] = int(counts.get("requests", 0) or 0) > 0
    result["fingerprint"] = str(summary.get("network_fingerprint") or "").strip()
    artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
    requests_path = Path(str(artifacts.get("requests_json") or ""))
    try:
        result["fingerprint_valid"] = bool(
            result["fingerprint"]
            and requests_path.is_file()
            and hashlib.sha256(requests_path.read_bytes()).hexdigest() == result["fingerprint"]
        )
    except OSError:
        pass
    private_artifacts = summary.get("private_artifacts") if isinstance(summary.get("private_artifacts"), dict) else {}
    browser_state = (
        private_artifacts.get("browser_state")
        if isinstance(private_artifacts.get("browser_state"), dict)
        else {}
    )
    state_artifact = Path(str(browser_state.get("path") or ""))
    if state_artifact and not state_artifact.is_absolute():
        state_artifact = summary_path.parent / state_artifact
    state_digest = str(browser_state.get("sha256") or "").strip()
    try:
        state_artifact_valid = bool(
            state_artifact.is_file()
            and (
                not state_digest
                or hashlib.sha256(state_artifact.read_bytes()).hexdigest() == state_digest
            )
        )
    except OSError:
        state_artifact_valid = False
    result["auth_required"] = bool(summary.get("auth_required") or summary.get("authenticated"))
    claimed_auth_state = str(summary.get("auth_state") or "").strip().lower()
    result["auth_state"] = (
        "present"
        if state_artifact_valid and claimed_auth_state in {"", "present"}
        else claimed_auth_state
        if claimed_auth_state and claimed_auth_state != "present"
        else "missing"
    )
    try:
        captured_at = datetime.strptime(
            str(summary.get("captured_at") or ""), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        captured_at = None
    result["fresh"] = bool(
        captured_at is not None
        and (datetime.now(timezone.utc) - captured_at).total_seconds() <= freshness_seconds
    )
    result["ready"] = bool(
        result["status"] == "ok"
        and result["success"]
        and result["core_network"]
        and result["fresh"]
        and result["fingerprint_valid"]
        and (not result["auth_required"] or result["auth_state"] == "present")
    )
    failed = []
    if result["status"] != "ok":
        failed.append("status")
    failed.extend(
        name
        for name in ("success", "core_network", "fresh", "fingerprint_valid")
        if not result[name]
    )
    if result["auth_required"] and result["auth_state"] != "present":
        failed.append("missing_state")
    result["reason"] = "ready" if result["ready"] else "browser capture is " + ", ".join(failed or ["not ready"])
    return result
