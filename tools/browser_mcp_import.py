#!/usr/bin/env python3
"""Import browser MCP artifacts into the existing browser evidence pipeline.

这个工具不直接调用 MCP：MCP 是会话级能力，项目脚本无法稳定地从 Python
内部访问它。这里做的是“桥接层”——把 chrome-devtools / playwright MCP
导出的 network、snapshot、console、screenshot 文件转成本项目已经消费的
evidence/recon 结构，让 /surface、/checkpoint、/validate 继续复用同一套
browser_surface 索引。
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import inspect
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.browser_evidence import compact_browser_evidence, console_shape, snapshot_shape
    from tools.browser_surface import (
        build_page_js_map,
        load_page_js_map,
        public_request_payload,
        public_url_shape,
        write_browser_surface,
    )
    from tools.private_artifacts import copy_private_file, private_artifact_dir, write_private_json, write_private_text
    from tools.target_paths import target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from browser_evidence import compact_browser_evidence, console_shape, snapshot_shape  # type: ignore
    from browser_surface import (  # type: ignore
        build_page_js_map,
        load_page_js_map,
        public_request_payload,
        public_url_shape,
        write_browser_surface,
    )
    from private_artifacts import (  # type: ignore
        copy_private_file,
        private_artifact_dir,
        write_private_json,
        write_private_text,
    )
    from target_paths import target_storage_key, url_belongs_to_target  # type: ignore


DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
DEFAULT_RECON_ROOT = BASE_DIR / "recon"
DEFAULT_FOCUSED_LIMIT = 8
BROWSER_FRESHNESS_SECONDS = 24 * 60 * 60
RAW_REQUEST_RE = re.compile(
    r"""
    ^\s*
    (?:\d+\.\s*)?
    (?:\[(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\]\s*)?
    (?P<url>https?://[^\s]+|/[^\s]+)
    (?:\s*=>\s*\[(?P<status>\d{3})\].*)?
    \s*$
    """,
    re.I | re.X,
)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _safe_label(value: str, default: str = "mcp") -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in (value or "").strip())
    return cleaned.strip("._-")[:80] or default


def _load_network_payload(path: str | Path | None) -> Any:
    """Load MCP network output, accepting both JSON and raw text listings."""
    if not path:
        return []
    candidate = Path(path)
    if not candidate.is_file():
        return []
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}


def _json_items(payload: Any, *, _allow_data_envelope: bool = True) -> list[Any]:
    """Return request/console item arrays from common MCP JSON shapes."""
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in (
        "requests",
        "networkRequests",
        "consoleMessages",
        "items",
        "entries",
        "messages",
        "network",
        "data",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    log = payload.get("log")
    if isinstance(log, dict) and isinstance(log.get("entries"), list):
        return log["entries"]
    # MCP 包装层仅解一层 data，避免递归误读请求 body。
    data = payload.get("data")
    if _allow_data_envelope and isinstance(data, dict):
        nested = _json_items(data, _allow_data_envelope=False)
        if nested:
            return nested
    for key in ("raw", "result"):
        value = payload.get(key)
        if isinstance(value, str):
            return _raw_request_items(value)
    return []


def _raw_request_items(raw: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in raw.splitlines():
        match = RAW_REQUEST_RE.match(line.strip())
        if not match:
            continue
        item: dict[str, Any] = {
            "url": (match.group("url") or "").rstrip(","),
            "method": (match.group("method") or "GET").upper(),
            "resourceType": "",
        }
        if match.group("status"):
            item["status"] = int(match.group("status"))
        items.append(item)
    return items


def _load_console_payload(path: str | Path | None) -> tuple[Any, str]:
    """读取 console 文件，同时保留需要进入私有证据层的原文。"""
    if not path:
        return [], ""
    candidate = Path(path)
    if not candidate.is_file():
        return [], ""
    try:
        raw = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], ""
    try:
        return json.loads(raw), raw
    except json.JSONDecodeError:
        return {"raw": raw}, raw


def _console_items(payload: Any) -> list[dict[str, Any]]:
    raw = payload.get("raw") if isinstance(payload, dict) else ""
    items = [] if isinstance(raw, str) else _json_items(payload)
    if items:
        return [item for item in items if isinstance(item, dict)]
    if not isinstance(raw, str):
        return []
    parsed = []
    for line in raw.splitlines():
        text = line.strip()
        if not text or text.lower().startswith(("total messages:", "returning ", "note:")):
            continue
        match = re.match(r"^\[?(error|warning|warn|info|debug|log)\]?[:\s-]+", text, re.I)
        level = (match.group(1).lower() if match else "log").replace("warn", "warning")
        parsed.append({"type": level, "text": text})
    return parsed


def _private_file_meta(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def _archive_private_artifact(
    source: str | Path | None,
    destination: Path,
) -> dict[str, Any]:
    if not source or not Path(source).is_file():
        return {}
    copied = copy_private_file(source, destination)
    return _private_file_meta(copied)


def _first_string(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _body_from_item(item: dict[str, Any], request: dict[str, Any]) -> Any:
    """Extract request body fields from Chrome DevTools / Playwright MCP shapes."""
    candidates = [
        item.get("postData"),
        item.get("requestPostData"),
        item.get("body"),
        item.get("payload"),
        item.get("data"),
        request.get("postData"),
        request.get("body"),
        request.get("payload"),
        request.get("data"),
    ]
    for value in candidates:
        if value not in ("", None):
            return value
    return ""


def normalize_mcp_network(payload: Any) -> list[dict[str, Any]]:
    """Normalize MCP network exports to the shape consumed by browser_surface.

    Supported inputs include:
    - chrome-devtools MCP `list_network_requests` JSON arrays
    - playwright MCP network request arrays
    - HAR-like `{log:{entries:[...]}}`
    - project-friendly `{requests:[...]}`
    """
    normalized: list[dict[str, Any]] = []
    for item in _json_items(payload):
        if isinstance(item, str):
            text = item.strip()
            if text:
                normalized.append({"url": text, "method": "GET", "resourceType": "", "postData": ""})
            continue
        if not isinstance(item, dict):
            continue

        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        url = _first_string(
            item.get("url"),
            item.get("requestUrl"),
            item.get("href"),
            item.get("documentURL"),
            request.get("url"),
        )
        if not url:
            continue
        method = _first_string(item.get("method"), request.get("method")) or "GET"
        resource_type = _first_string(
            item.get("resourceType"),
            item.get("type"),
            item.get("_resourceType"),
            item.get("initiatorType"),
            request.get("resourceType"),
            request.get("type"),
        )
        status = item.get("status", response.get("status", ""))
        normalized.append(
            {
                "url": url,
                "method": method.upper(),
                "resourceType": resource_type.lower(),
                "status": status,
                "postData": _body_from_item(item, request),
            }
        )
    return normalized


def _network_capture_failed(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("success") is False:
        return True
    return str(payload.get("status") or "").strip().lower() in {
        "error", "failed", "failure", "timeout", "stale",
    }


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


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _rollback_failed_capture(func):
    """Remove only this import's capture directories when publishing fails."""
    signature = inspect.signature(func)

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        target_key = target_storage_key(str(bound.arguments["target"]))
        evidence_root = Path(bound.arguments["evidence_root"])
        public_parent = evidence_root / target_key / "browser"
        private_parent = evidence_root.parent / ".private" / "browser" / target_key
        before_public = set(public_parent.iterdir()) if public_parent.is_dir() else None
        before_private = set(private_parent.iterdir()) if private_parent.is_dir() else None

        def rollback(parent: Path, before: set[Path] | None) -> None:
            def remove(path: Path) -> None:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)

            if not parent.exists():
                return
            if before is None:
                remove(parent)
                return
            for child in list(parent.iterdir()):
                if child not in before:
                    remove(child)

        try:
            return func(*args, **kwargs)
        except BaseException:
            rollback(public_parent, before_public)
            rollback(private_parent, before_private)
            raise

    return wrapped


@_rollback_failed_capture
def import_mcp_browser_evidence(
    *,
    target: str,
    url: str = "",
    network_path: str | Path | None = None,
    snapshot_path: str | Path | None = None,
    console_path: str | Path | None = None,
    screenshot_path: str | Path | None = None,
    cookies_path: str | Path | None = None,
    local_storage_path: str | Path | None = None,
    session_storage_path: str | Path | None = None,
    state_path: str | Path | None = None,
    har_path: str | Path | None = None,
    label: str = "mcp",
    evidence_root: str | Path = DEFAULT_EVIDENCE_ROOT,
    recon_root: str | Path = DEFAULT_RECON_ROOT,
    source: str = "mcp",
    auth_required: bool = False,
    auth_state: str = "",
) -> dict[str, Any]:
    """Create an evidence capture from MCP-exported browser artifacts."""
    target_key = target_storage_key(target)
    safe_label = _safe_label(label, "mcp")
    safe_source = _safe_label(source, "mcp")
    root = Path(evidence_root)
    run_id = f"{_timestamp_slug()}-{safe_label}"
    capture_dir = root / target_key / "browser" / run_id
    capture_dir.mkdir(parents=True, exist_ok=False)
    private_dir = private_artifact_dir(root.parent, "browser", target_key, run_id)

    artifacts: dict[str, str] = {}
    network_payload = _load_network_payload(network_path or har_path)
    requests = normalize_mcp_network(network_payload)
    if (
        (not requests or _network_capture_failed(network_payload))
        and har_path
        and str(har_path) != str(network_path)
    ):
        har_payload = _load_network_payload(har_path)
        har_requests = normalize_mcp_network(har_payload)
        if har_requests and not _network_capture_failed(har_payload):
            network_payload, requests = har_payload, har_requests
    artifacts["network_private_json"] = str(
        write_private_json(private_dir / "network.raw.json", network_payload)
    )
    requests_file = capture_dir / "requests.json"
    _write_json(requests_file, public_request_payload({"requests": requests}, source=safe_source))
    artifacts["requests_json"] = str(requests_file)
    network_fingerprint = hashlib.sha256(requests_file.read_bytes()).hexdigest()

    copied_snapshot = ""
    if snapshot_path and Path(snapshot_path).is_file():
        raw_snapshot = Path(snapshot_path).read_text(encoding="utf-8", errors="replace")
        artifacts["snapshot_private_txt"] = str(
            write_private_text(private_dir / "snapshot.txt", raw_snapshot)
        )
        public_snapshot = capture_dir / "snapshot.txt"
        public_snapshot.write_text(snapshot_shape(raw_snapshot), encoding="utf-8")
        copied_snapshot = str(public_snapshot)
        artifacts["snapshot_txt"] = copied_snapshot

    console_payload, raw_console = _load_console_payload(console_path)
    console_items = _console_items(console_payload)
    if console_path and Path(console_path).is_file():
        artifacts["console_private"] = str(
            write_private_text(private_dir / "console.raw.txt", raw_console)
        )
        console_file = capture_dir / "console.json"
        _write_json(console_file, console_shape(console_items))
        artifacts["console_json"] = str(console_file)

    copied_screenshot = ""
    if screenshot_path and Path(screenshot_path).is_file():
        copied_screenshot = str(copy_private_file(screenshot_path, private_dir / "screenshot.png"))
        artifacts["screenshot_png"] = copied_screenshot

    private_artifacts = {}
    for name, source_path, filename in (
        ("cookies", cookies_path, "cookies.json"),
        ("local_storage", local_storage_path, "local-storage.json"),
        ("session_storage", session_storage_path, "session-storage.json"),
        ("browser_state", state_path, "state.json"),
        ("network_har", har_path, "network.har"),
    ):
        meta = _archive_private_artifact(source_path, private_dir / filename)
        if meta:
            private_artifacts[name] = meta
            artifacts[f"{name}_private"] = str(meta["path"])

    browser_surface = write_browser_surface(
        recon_root=recon_root,
        target_key=target_key,
        requests_path=requests_file,
        snapshot_path=artifacts.get("snapshot_txt", ""),
        capture_dir=str(capture_dir),
        merge_existing=True,
    )
    summary_path = capture_dir / "summary.json"
    pointer_path = root / target_key / "browser" / "last-capture.json"
    browser_counts = browser_surface.get("counts") if isinstance(browser_surface, dict) else {}
    source_failed = _network_capture_failed(network_payload)
    has_core_network = bool(requests) and not source_failed
    has_any_artifact = bool(
        requests or copied_snapshot or console_items or copied_screenshot or private_artifacts
    )
    archived_browser_state = bool(private_artifacts.get("browser_state"))
    requested_auth_state = _safe_label(auth_state, "missing") if auth_state else ""
    auth_state_value = (
        "present"
        if archived_browser_state
        else "missing"
        if requested_auth_state in {"", "present"}
        else requested_auth_state
    )
    capture_success = has_any_artifact and not source_failed
    capture_status = (
        "error"
        if source_failed
        else "ok"
        if has_core_network and (not auth_required or auth_state_value == "present")
        else "partial"
        if has_any_artifact
        else "error"
    )
    summary = {
        "schema_version": 1,
        "target": target,
        "target_key": target_key,
        "url": public_url_shape(url),
        "session": "",
        "label": safe_label,
        "capture_backend": safe_source,
        "captured_at": _now_utc(),
        "evidence_dir": str(capture_dir),
        "summary_path": str(summary_path),
        "pointer_path": str(pointer_path),
        "success": capture_success,
        "status": capture_status,
        "network_fingerprint": network_fingerprint,
        "auth_required": bool(auth_required),
        "auth_state": auth_state_value,
        "counts": {
            "requests": len(requests),
            "console": len(console_items),
            "browser_xhr_endpoints": int(browser_counts.get("xhr_endpoints", 0) or 0),
            "browser_api_endpoints": int(browser_counts.get("api_endpoints", 0) or 0),
            "browser_params": int(browser_counts.get("browser_params", 0) or 0),
        },
        "artifacts": artifacts,
        "private_artifacts": private_artifacts,
        "browser_surface": browser_surface,
    }
    _write_json(summary_path, summary)
    # page→JS builder discovers captures by summary.json, so refresh only after publishing it.
    try:
        build_page_js_map(evidence_root=root, recon_root=recon_root, target_key=target_key)
    except (OSError, json.JSONDecodeError):  # pragma: no cover - 防御损坏的历史 capture
        pass

    pointer = compact_browser_evidence(summary)
    pointer.update(
        {"target": target, "target_key": target_key, "label": safe_label, "capture_backend": safe_source}
    )
    _write_json(pointer_path, pointer)
    return summary


def _read_lines(path: Path) -> set[str]:
    try:
        return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    except OSError:
        return set()


def _browser_surface_sets(recon_root: Path, target_key: str) -> dict[str, set[str]]:
    browser_dir = recon_root / target_key / "browser"
    page_js_map = load_page_js_map(recon_root, target_key)
    js_index = page_js_map.get("js_index") if isinstance(page_js_map, dict) else {}
    return {
        "xhr_endpoints": _read_lines(browser_dir / "xhr_endpoints.txt"),
        "api_endpoints": _read_lines(browser_dir / "api_endpoints.txt"),
        "browser_params": _read_lines(browser_dir / "browser_params.txt"),
        "js_files": set(js_index) if isinstance(js_index, dict) else set(),
    }


def _line_url(value: str) -> str:
    return str(value or "").split(" :: ", 1)[0].strip()


def _target_owned_delta(
    before: dict[str, set[str]],
    after: dict[str, set[str]],
    target: str,
) -> dict[str, list[str]]:
    return {
        kind: sorted(
            line
            for line in after.get(kind, set()) - before.get(kind, set())
            if url_belongs_to_target(_line_url(line), target)
        )
        for kind in before
    }


def _snapshot_digest(path: str | Path | None) -> str:
    if not path:
        return ""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"^snapshot_sha256=([0-9a-f]{64})$", text, re.MULTILINE)
    return match.group(1) if match else ""


def _known_snapshot_hashes(browser_root: Path) -> set[str]:
    return {
        digest
        for path in browser_root.glob("*/snapshot.txt")
        if (digest := _snapshot_digest(path))
    }


def _focused_signal(url: str, delta: dict[str, list[str]]) -> dict[str, Any]:
    try:
        from tools.high_value_signals import classify_high_value_signal
    except ImportError:  # pragma: no cover - direct tools/ execution
        from high_value_signals import classify_high_value_signal  # type: ignore

    candidates = [(url, [])]
    for kind, lines in delta.items():
        for line in lines:
            key = line.split(" :: ", 1)[1] if kind == "browser_params" and " :: " in line else ""
            candidates.append((_line_url(line), [key] if key else []))
    signals = []
    for candidate, extra_keys in candidates:
        parsed = urlparse(candidate)
        signals.append(
            classify_high_value_signal(
                path=parsed.path or "/",
                query_keys=[
                    *[key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)],
                    *extra_keys,
                ],
                evidence="browser context discovery",
            )
        )
    return {
        "score": max((signal.score for signal in signals), default=0),
        "classes": list(dict.fromkeys(value for signal in signals for value in signal.classes)),
        "reasons": list(dict.fromkeys(value for signal in signals for value in signal.reasons)),
    }


def _resolve_manifest_artifact(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    path = Path(value.strip()).expanduser()
    return str(path if path.is_absolute() else BASE_DIR / path)


def _load_focused_manifest(path: str | Path) -> dict[str, Any]:
    candidate = Path(path)
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"focused manifest is unreadable: {candidate}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"focused manifest is invalid JSON: {candidate}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("captures"), list):
        raise ValueError("focused manifest must be an object with a captures array")
    return payload


def _enqueue_focused_action(
    repo_root: Path,
    target: str,
    artifact_path: Path,
    actionable: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        from tools.action_queue import add_manual_action
    except ImportError:  # pragma: no cover - direct tools/ execution
        from action_queue import add_manual_action  # type: ignore

    generation = hashlib.sha256(
        json.dumps(
            [
                {
                    "url": item.get("url", ""),
                    "snapshot_sha256": item.get("snapshot_sha256", ""),
                    "new_surface": item.get("new_surface", {}),
                }
                for item in actionable
            ],
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    result = add_manual_action(
        repo_root,
        target=target,
        action_type="browser-context-discovery",
        evidence=(
            f"{len(actionable)} MCP browser capture(s) exposed high-value, "
            f"target-owned surface; review {artifact_path}."
        ),
        next_question=(
            "Which newly observed route or parameter warrants the smallest independent replay?"
        ),
        action="Review the browser context delta, then replay one evidence-backed endpoint.",
        priority=78,
        evidence_type="browser-context-discovery",
        source="browser-context-discovery",
        source_id="browser-context-discovery",
        generation=generation,
        safety="non_destructive",
        stop_condition=(
            "record tested, dead-end, blocked, lead, signal, candidate, or validated before another lane"
        ),
    )
    return {"path": result["path"], "stats": result["stats"]}


def import_focused_mcp_manifest(
    *,
    target: str,
    manifest_path: str | Path,
    max_urls: int = DEFAULT_FOCUSED_LIMIT,
    evidence_root: str | Path = DEFAULT_EVIDENCE_ROOT,
    recon_root: str | Path = DEFAULT_RECON_ROOT,
    repo_root: str | Path = BASE_DIR,
    enqueue: bool = True,
) -> dict[str, Any]:
    """批量导入 MCP 已落盘的少量同目标证据，并只入队高价值新差分。"""
    if max_urls < 1:
        raise ValueError("max_urls must be at least 1")
    manifest = _load_focused_manifest(manifest_path)
    manifest_target = str(manifest.get("target") or "").strip()
    if manifest_target and target_storage_key(manifest_target) != target_storage_key(target):
        raise ValueError("focused manifest target does not match --target")

    selected = []
    skipped = []
    seen = set()
    for raw in manifest["captures"]:
        if not isinstance(raw, dict):
            skipped.append({"url": "", "reason": "invalid_capture"})
            continue
        url = str(raw.get("url") or "").strip()
        if not url:
            skipped.append({"url": "", "reason": "invalid_url"})
            continue
        if url in seen:
            skipped.append({"url": public_url_shape(url), "reason": "duplicate"})
            continue
        seen.add(url)
        parsed_url = urlparse(url)
        if parsed_url.scheme.lower() not in {"http", "https"} or not parsed_url.netloc:
            skipped.append({"url": public_url_shape(url), "reason": "invalid_url"})
            continue
        if not url_belongs_to_target(url, target):
            skipped.append({"url": public_url_shape(url), "reason": "off_target"})
            continue
        if len(selected) >= max_urls:
            skipped.append({"url": public_url_shape(url), "reason": "budget_exhausted"})
            continue
        selected.append((url, raw))

    evidence = Path(evidence_root)
    recon = Path(recon_root)
    target_key = target_storage_key(target)
    browser_root = evidence / target_key / "browser"
    known_hashes = _known_snapshot_hashes(browser_root)
    known_surface = _browser_surface_sets(recon, target_key)
    captures = []
    actionable = []
    successful = 0
    complete = 0

    for index, (url, item) in enumerate(selected, 1):
        paths = {
            key: _resolve_manifest_artifact(item.get(key))
            for key in (
                "network",
                "snapshot",
                "console",
                "screenshot",
                "cookies",
                "local_storage",
                "session_storage",
                "state",
                "har",
            )
        }
        missing = sorted(key for key, value in paths.items() if value and not Path(value).is_file())
        if not paths["network"] and not paths["har"]:
            missing.insert(0, "network")
        before = {kind: set(values) for kind, values in known_surface.items()}
        try:
            summary = import_mcp_browser_evidence(
                target=target,
                url=url,
                network_path=paths["network"],
                snapshot_path=paths["snapshot"],
                console_path=paths["console"],
                screenshot_path=paths["screenshot"],
                cookies_path=paths["cookies"],
                local_storage_path=paths["local_storage"],
                session_storage_path=paths["session_storage"],
                state_path=paths["state"],
                har_path=paths["har"],
                label=f"focused-{index}",
                evidence_root=evidence,
                recon_root=recon,
                source=str(item.get("source") or "mcp"),
                auth_required=bool(item.get("auth_required") or item.get("authenticated")),
                auth_state=str(item.get("auth_state") or ""),
            )
        except (OSError, ValueError) as exc:
            captures.append(
                {
                    "url": public_url_shape(url),
                    "status": "error",
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                    "new_surface": {},
                    "actionable": False,
                }
            )
            continue

        if summary.get("success"):
            successful += 1
        if summary.get("status") == "ok":
            complete += 1
        after = _browser_surface_sets(recon, target_key)
        delta = _target_owned_delta(before, after, target)
        known_surface = after
        artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
        snapshot_hash = _snapshot_digest(artifacts.get("snapshot_txt"))
        repeated_shape = bool(snapshot_hash and snapshot_hash in known_hashes)
        if snapshot_hash:
            known_hashes.add(snapshot_hash)
        signal = _focused_signal(url, delta)
        is_actionable = bool(
            summary.get("success")
            and signal["score"] > 0
            and (any(delta.values()) or (snapshot_hash and not repeated_shape))
        )
        capture = {
            "url": public_url_shape(url),
            "status": summary.get("status", "error"),
            "capture": compact_browser_evidence(summary),
            "missing_artifacts": missing,
            "snapshot_sha256": snapshot_hash,
            "repeated_shape": repeated_shape if snapshot_hash else None,
            "new_surface": delta,
            "high_value": signal,
            "actionable": is_actionable,
        }
        captures.append(capture)
        if is_actionable:
            actionable.append(capture)

    if not selected:
        status = "skipped"
    elif complete == len(selected) and not skipped:
        status = "ok"
    elif successful:
        status = "partial"
    else:
        status = "error"
    output_dir = recon / target_key / "browser" / "context_discovery"
    output_path = output_dir / f"{_timestamp_slug()}.json"
    latest_path = output_dir.parent / "context_discovery.json"
    result = {
        "schema_version": 1,
        "target": target,
        "target_key": target_key,
        "generated_at": _now_utc(),
        "status": status,
        "budget": max_urls,
        "captures": captures,
        "skipped": skipped,
        "counts": {
            "selected": len(selected),
            "successful": successful,
            "actionable": len(actionable),
            "skipped": len(skipped),
        },
        "artifact": str(output_path),
    }
    _write_json(output_path, result)
    _write_json(latest_path, result)
    if enqueue and actionable:
        result["queue"] = _enqueue_focused_action(
            Path(repo_root), target, output_path, actionable
        )
        _write_json(output_path, result)
        _write_json(latest_path, result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import chrome-devtools/playwright MCP artifacts as browser evidence")
    parser.add_argument("--target", required=True, help="Target name/URL used for canonical evidence storage")
    parser.add_argument("--url", default="", help="Page URL observed by MCP")
    parser.add_argument("--network-json", default="", help="JSON/text file exported from MCP network request list")
    parser.add_argument("--snapshot", default="", help="Optional MCP snapshot/DOM text file")
    parser.add_argument("--console-json", default="", help="Optional MCP console messages JSON/text file")
    parser.add_argument("--screenshot", default="", help="Optional MCP screenshot path")
    parser.add_argument("--cookies", default="", help="Optional cookie artifact kept private")
    parser.add_argument("--local-storage", default="", help="Optional localStorage artifact kept private")
    parser.add_argument("--session-storage", default="", help="Optional sessionStorage artifact kept private")
    parser.add_argument("--state", default="", help="Optional browser state artifact kept private")
    parser.add_argument("--auth-required", action="store_true", help="Require persisted browser state for an authenticated capture")
    parser.add_argument("--auth-state", default="", help="Authenticated state label, e.g. present or missing")
    parser.add_argument("--har", default="", help="Optional HAR artifact kept private; also used as network input when needed")
    parser.add_argument("--focused-manifest", default="", help="Import a bounded file-backed MCP capture manifest")
    parser.add_argument("--max-urls", type=int, default=DEFAULT_FOCUSED_LIMIT, help="Focused manifest URL budget")
    parser.add_argument("--no-enqueue", action="store_true", help="Do not add focused high-value deltas to Action Queue")
    parser.add_argument("--label", default="mcp", help="Capture label suffix")
    parser.add_argument("--source", default="mcp", help="Source label, e.g. chrome-devtools-mcp or playwright-mcp")
    parser.add_argument("--evidence-root", default=str(DEFAULT_EVIDENCE_ROOT), help="Evidence root directory")
    parser.add_argument("--recon-root", default=str(DEFAULT_RECON_ROOT), help="Recon root directory")
    parser.add_argument("--repo-root", default=str(BASE_DIR), help="Repository root used by the existing Action Queue owner")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.focused_manifest:
        result = import_focused_mcp_manifest(
            target=args.target,
            manifest_path=args.focused_manifest,
            max_urls=args.max_urls,
            evidence_root=args.evidence_root,
            recon_root=args.recon_root,
            repo_root=args.repo_root,
            enqueue=not args.no_enqueue,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if not args.network_json and not args.har:
        parser.error("one of --network-json, --har, or --focused-manifest is required")
    summary = import_mcp_browser_evidence(
        target=args.target,
        url=args.url,
        network_path=args.network_json,
        snapshot_path=args.snapshot,
        console_path=args.console_json,
        screenshot_path=args.screenshot,
        cookies_path=args.cookies,
        local_storage_path=args.local_storage,
        session_storage_path=args.session_storage,
        state_path=args.state,
        har_path=args.har,
        label=args.label,
        evidence_root=args.evidence_root,
        recon_root=args.recon_root,
        source=args.source,
        auth_required=args.auth_required,
        auth_state=args.auth_state,
    )
    print(json.dumps(compact_browser_evidence(summary), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
