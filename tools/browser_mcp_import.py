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
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.browser_evidence import compact_browser_evidence, console_shape, snapshot_shape
    from tools.browser_surface import (
        build_page_js_map,
        public_request_payload,
        public_url_shape,
        write_browser_surface,
    )
    from tools.private_artifacts import copy_private_file, private_artifact_dir, write_private_json, write_private_text
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from browser_evidence import compact_browser_evidence, console_shape, snapshot_shape  # type: ignore
    from browser_surface import (  # type: ignore
        build_page_js_map,
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
    from target_paths import target_storage_key  # type: ignore


DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
DEFAULT_RECON_ROOT = BASE_DIR / "recon"
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


def _load_json(path: str | Path | None) -> Any:
    if not path:
        return []
    candidate = Path(path)
    if not candidate.is_file():
        return []
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


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
    for key in ("requests", "items", "entries", "messages", "network", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    log = payload.get("log")
    if isinstance(log, dict) and isinstance(log.get("entries"), list):
        return log["entries"]
    # agent-browser 的 JSON envelope 仅解一层 data，避免递归误读请求 body。
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


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def import_mcp_browser_evidence(
    *,
    target: str,
    url: str = "",
    network_path: str | Path | None = None,
    snapshot_path: str | Path | None = None,
    console_path: str | Path | None = None,
    screenshot_path: str | Path | None = None,
    label: str = "mcp",
    evidence_root: str | Path = DEFAULT_EVIDENCE_ROOT,
    recon_root: str | Path = DEFAULT_RECON_ROOT,
    source: str = "mcp",
) -> dict[str, Any]:
    """Create an evidence capture from MCP-exported browser artifacts."""
    target_key = target_storage_key(target)
    safe_label = _safe_label(label, "mcp")
    root = Path(evidence_root)
    run_id = f"{_timestamp_slug()}-{safe_label}"
    capture_dir = root / target_key / "browser" / run_id
    capture_dir.mkdir(parents=True, exist_ok=False)
    private_dir = private_artifact_dir(root.parent, "browser", target_key, run_id)

    artifacts: dict[str, str] = {}
    network_payload = _load_network_payload(network_path)
    artifacts["network_private_json"] = str(
        write_private_json(private_dir / "network.raw.json", network_payload)
    )
    requests = normalize_mcp_network(network_payload)
    requests_file = capture_dir / "requests.json"
    _write_json(requests_file, public_request_payload({"requests": requests}, source=source))
    artifacts["requests_json"] = str(requests_file)

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

    console_payload = _load_json(console_path)
    console_items = _json_items(console_payload)
    if console_path:
        artifacts["console_private_json"] = str(
            write_private_json(private_dir / "console.raw.json", console_payload)
        )
        console_file = capture_dir / "console.json"
        _write_json(console_file, console_shape(console_items if console_items else console_payload))
        artifacts["console_json"] = str(console_file)

    copied_screenshot = ""
    if screenshot_path and Path(screenshot_path).is_file():
        copied_screenshot = str(copy_private_file(screenshot_path, private_dir / "screenshot.png"))
        artifacts["screenshot_png"] = copied_screenshot

    browser_surface = write_browser_surface(
        recon_root=recon_root,
        target_key=target_key,
        requests_path=requests_file,
        snapshot_path=artifacts.get("snapshot_txt", ""),
        capture_dir=str(capture_dir),
        merge_existing=True,
    )
    # 与 browser_evidence.py 保持同一副作用：每次导入都刷新 page→JS 映射。
    try:
        build_page_js_map(evidence_root=root, recon_root=recon_root, target_key=target_key)
    except (OSError, json.JSONDecodeError):  # pragma: no cover - 防御损坏的历史 capture
        pass

    summary_path = capture_dir / "summary.json"
    pointer_path = root / target_key / "browser" / "last-capture.json"
    browser_counts = browser_surface.get("counts") if isinstance(browser_surface, dict) else {}
    summary = {
        "target": target,
        "target_key": target_key,
        "url": public_url_shape(url),
        "session": "",
        "label": safe_label,
        "capture_backend": source,
        "captured_at": _now_utc(),
        "evidence_dir": str(capture_dir),
        "summary_path": str(summary_path),
        "pointer_path": str(pointer_path),
        "success": bool(requests or copied_snapshot or console_items or copied_screenshot),
        "counts": {
            "requests": len(requests),
            "console": len(console_items),
            "browser_xhr_endpoints": int(browser_counts.get("xhr_endpoints", 0) or 0),
            "browser_api_endpoints": int(browser_counts.get("api_endpoints", 0) or 0),
            "browser_params": int(browser_counts.get("browser_params", 0) or 0),
        },
        "artifacts": artifacts,
        "browser_surface": browser_surface,
    }
    _write_json(summary_path, summary)

    pointer = compact_browser_evidence(summary)
    pointer.update({"target": target, "target_key": target_key, "label": safe_label, "capture_backend": source})
    _write_json(pointer_path, pointer)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import chrome-devtools/playwright MCP artifacts as browser evidence")
    parser.add_argument("--target", required=True, help="Target name/URL used for canonical evidence storage")
    parser.add_argument("--url", default="", help="Page URL observed by MCP")
    parser.add_argument("--network-json", required=True, help="JSON file exported from MCP network request list")
    parser.add_argument("--snapshot", default="", help="Optional MCP snapshot/DOM text file")
    parser.add_argument("--console-json", default="", help="Optional MCP console messages JSON file")
    parser.add_argument("--screenshot", default="", help="Optional MCP screenshot path")
    parser.add_argument("--label", default="mcp", help="Capture label suffix")
    parser.add_argument("--source", default="mcp", help="Source label, e.g. chrome-devtools-mcp or playwright-mcp")
    parser.add_argument("--evidence-root", default=str(DEFAULT_EVIDENCE_ROOT), help="Evidence root directory")
    parser.add_argument("--recon-root", default=str(DEFAULT_RECON_ROOT), help="Recon root directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = import_mcp_browser_evidence(
        target=args.target,
        url=args.url,
        network_path=args.network_json,
        snapshot_path=args.snapshot,
        console_path=args.console_json,
        screenshot_path=args.screenshot,
        label=args.label,
        evidence_root=args.evidence_root,
        recon_root=args.recon_root,
        source=args.source,
    )
    print(json.dumps(compact_browser_evidence(summary), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
