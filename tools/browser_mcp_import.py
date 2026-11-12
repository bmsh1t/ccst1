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
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.artifact_io import write_json_atomic as _write_json, publish_bytes_create_only
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_json_atomic as _write_json, publish_bytes_create_only


try:
    from tools.browser_evidence import (
        compact_browser_evidence, console_shape, snapshot_shape,
    )
    from tools.browser_surface import (
        browser_export_items,
        build_page_js_map,
        load_page_js_map,
        public_request_payload,
        public_url_shape,
        write_browser_surface,
    )
    from tools.private_artifacts import copy_private_file, private_artifact_dir, write_private_json, write_private_text
    from tools.target_paths import target_storage_key
    from tools.scope_context import url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from browser_evidence import (
        compact_browser_evidence, console_shape, snapshot_shape,
    )  # type: ignore
    from browser_surface import (  # type: ignore
        browser_export_items,
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
    from target_paths import target_storage_key  # type: ignore
    from scope_context import url_belongs_to_target  # type: ignore


DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
DEFAULT_RECON_ROOT = BASE_DIR / "recon"
DEFAULT_FOCUSED_LIMIT = 8
DEFAULT_BROWSER_IMPORT_MAX_BYTES = 32 * 1024 * 1024


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _safe_label(value: str, default: str = "mcp") -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in (value or "").strip())
    return cleaned.strip("._-")[:80] or default


def _browser_import_max_bytes() -> int:
    raw = os.environ.get("BBHUNT_BROWSER_IMPORT_MAX_BYTES", "")
    if not raw:
        return DEFAULT_BROWSER_IMPORT_MAX_BYTES
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("BBHUNT_BROWSER_IMPORT_MAX_BYTES must be a positive integer") from exc
    if value <= 0:
        raise ValueError("BBHUNT_BROWSER_IMPORT_MAX_BYTES must be a positive integer")
    return value


def _check_import_input(path: str | Path | None) -> Path | None:
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        return None
    try:
        size = candidate.stat().st_size
    except OSError:
        return None
    limit = _browser_import_max_bytes()
    if size > limit:
        raise ValueError(
            f"browser import input exceeds BBHUNT_BROWSER_IMPORT_MAX_BYTES: "
            f"path={candidate} bytes={size} limit={limit}"
        )
    return candidate


def _capture_network_payload(path: str | Path | None) -> tuple[Any, bytes | None, str]:
    """Capture once: discovery and the original-byte baseline share these bytes."""
    candidate = _check_import_input(path)
    if candidate is None:
        return [], None, "text"
    raw = candidate.read_bytes()
    if len(raw) > _browser_import_max_bytes():
        raise ValueError("browser network input grew beyond the import byte budget")
    text = raw.decode("utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}, raw, "text"
    return payload, raw, "har" if isinstance(payload, dict) and isinstance(payload.get("log"), dict) else "json"


def _load_console_payload(path: str | Path | None) -> tuple[Any, str]:
    """读取 console 文件，同时保留需要进入私有证据层的原文。"""
    if not path:
        return [], ""
    candidate = _check_import_input(path)
    if candidate is None:
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
    raw = payload.get("raw") if isinstance(payload, dict) else None
    items = [] if isinstance(raw, str) else browser_export_items(payload)[0]
    if items:
        return [item for item in items if isinstance(item, dict)]
    if not isinstance(raw, str):
        return []
    parsed = []
    for line in raw.splitlines():
        text = line.strip()
        if not text or text.lower().startswith(("total messages:", "returning ", "note:")):
            continue
        match = re.match(r"^(?:\[\s*\d+(?:\.\d+)?ms\]\s*)?\[?(error|warning|warn|info|debug|verbose|log)\]?[:\s-]+", text, re.I)
        level = match.group(1).lower() if match else "log"
        if level == "warn":
            level = "warning"
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
    source_path = _check_import_input(source)
    if source_path is None:
        return {}
    copied = copy_private_file(source_path, destination)
    return _private_file_meta(copied)


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
    capture_error: str = "",
    run_identity: str = "",
) -> dict[str, Any]:
    """Create an evidence capture from MCP-exported browser artifacts.

    ``run_identity`` makes the capture directory stable across retries: when a
    capture with the same identity was already published (its summary.json is
    intact), it is confirmed by returning that summary instead of publishing a
    duplicate; a leftover partial directory of the same identity is replaced
    (it belongs to this identity alone). Without an identity, every call
    publishes a fresh timestamped capture as before.
    """
    target_key = target_storage_key(target)
    safe_label = _safe_label(label, "mcp")
    safe_source = _safe_label(source, "mcp")
    root = Path(evidence_root)
    run_id = _safe_label(run_identity, "") if run_identity else f"{_timestamp_slug()}-{safe_label}"
    capture_dir = root / target_key / "browser" / run_id
    if run_identity and capture_dir.exists():
        prior_summary = capture_dir / "summary.json"
        if prior_summary.is_file():
            try:
                return json.loads(prior_summary.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        # Interrupted leftover of this same identity: safe to replace because
        # the directory belongs to this identity alone, never to another run.
        shutil.rmtree(capture_dir, ignore_errors=True)
        shutil.rmtree(
            private_artifact_dir(root.parent, "browser", target_key, run_id), ignore_errors=True)
    capture_dir.mkdir(parents=True, exist_ok=False)
    private_dir = private_artifact_dir(root.parent, "browser", target_key, run_id)

    surface_touched = False
    try:
        artifacts: dict[str, str] = {}
        selected_path = network_path or har_path
        network_payload, network_bytes, network_format = _capture_network_payload(selected_path)
        captured_inputs = {str(selected_path): (network_payload, network_bytes, network_format)}
        network_items, source_failed = browser_export_items(network_payload)
        request_payload = public_request_payload(network_items, source=safe_source, from_capture=True)
        requests = request_payload["requests"]
        if (
            (not requests or source_failed)
            and har_path
            and str(har_path) != str(selected_path)
        ):
            har_payload, har_bytes, har_format = _capture_network_payload(har_path)
            captured_inputs[str(har_path)] = (har_payload, har_bytes, har_format)
            har_items, har_failed = browser_export_items(har_payload)
            har_request_payload = public_request_payload(har_items, source=safe_source, from_capture=True)
            har_requests = har_request_payload["requests"]
            if har_requests and not har_failed:
                network_payload, requests = har_payload, har_requests
                request_payload = har_request_payload
                network_bytes, network_format = har_bytes, har_format
                source_failed = har_failed
        network_source = {}
        if network_bytes is not None:
            original_path = private_dir / "network.source"
            publish_bytes_create_only(original_path, network_bytes)
            network_source = {**_private_file_meta(original_path), "format": network_format}
            if network_source["sha256"] != hashlib.sha256(network_bytes).hexdigest() or network_source["bytes"] != len(network_bytes):
                raise ValueError("archived network source does not match captured bytes")
        artifacts["network_private_json"] = str(
            write_private_json(private_dir / "network.raw.json", network_payload)
        )
        requests_file = capture_dir / "requests.json"
        _write_json(requests_file, request_payload)
        artifacts["requests_json"] = str(requests_file)
        network_fingerprint = hashlib.sha256(requests_file.read_bytes()).hexdigest()

        copied_snapshot = ""
        if snapshot_path and Path(snapshot_path).is_file():
            snapshot_file = _check_import_input(snapshot_path)
            raw_snapshot = snapshot_file.read_text(encoding="utf-8", errors="replace") if snapshot_file else ""
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
            screenshot_file = _check_import_input(screenshot_path)
            if screenshot_file is not None:
                copied_screenshot = str(copy_private_file(screenshot_file, private_dir / "screenshot.png"))
            artifacts["screenshot_png"] = copied_screenshot

        private_artifacts = {}
        for name, source_path, filename in (
            ("cookies", cookies_path, "cookies.json"),
            ("local_storage", local_storage_path, "local-storage.json"),
            ("session_storage", session_storage_path, "session-storage.json"),
            ("browser_state", state_path, "state.json"),
            ("network_har", har_path, "network.har"),
        ):
            if name == "network_har":
                # A selected/fallback HAR must not be reread after capture.
                captured = captured_inputs.get(str(source_path))
                if captured is None:
                    captured = _capture_network_payload(source_path)
                raw = captured[1]
                meta = {}
                if raw is not None:
                    saved = private_dir / filename
                    publish_bytes_create_only(saved, raw)
                    meta = _private_file_meta(saved)
            else:
                meta = _archive_private_artifact(source_path, private_dir / filename)
            if meta:
                private_artifacts[name] = meta
                artifacts[f"{name}_private"] = str(meta["path"])

        # Once the shared Recon projection is touched, retain this capture on
        # later publish failure so the projection never points at a deleted
        # directory. A retry with run_identity can replace the partial capture.
        surface_touched = True
        browser_surface = write_browser_surface(
            recon_root=recon_root,
            target_key=target_key,
            requests_path=requests_file,
            requests=requests,
            snapshot_path=artifacts.get("snapshot_private_txt", ""),
            capture_dir=str(capture_dir),
            merge_existing=True,
        )
        summary_path = capture_dir / "summary.json"
        pointer_path = root / target_key / "browser" / "last-capture.json"
        browser_counts = browser_surface.get("counts") if isinstance(browser_surface, dict) else {}
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
        safe_capture_error = " ".join(str(capture_error or "").split())[:400]
        capture_success = has_any_artifact and not source_failed
        capture_status = (
            "error"
            if source_failed
            else "partial"
            if safe_capture_error and has_any_artifact
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
            "error": safe_capture_error,
            "network_fingerprint": network_fingerprint,
            "network_source": network_source,
            "auth_required": bool(auth_required),
            "auth_state": auth_state_value,
            "counts": {
                "requests": len(requests),
                "console": len(console_items),
                "browser_xhr_endpoints": int(browser_counts.get("xhr_endpoints", 0) or 0),
                "browser_api_endpoints": int(browser_counts.get("api_endpoints", 0) or 0),
                "browser_params": int(browser_counts.get("browser_params", 0) or 0),
                "realtime_messages": int(browser_counts.get("realtime_messages", 0) or 0),
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
    except BaseException:
        # Before the shared projection is touched, remove this run's partial
        # directories. Afterward keep them: deleting them would leave Recon
        # pointing at missing evidence, and a stable retry can replace them.
        if not surface_touched:
            shutil.rmtree(capture_dir, ignore_errors=True)
            shutil.rmtree(private_dir, ignore_errors=True)
        raise


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


def _manifest_capture_identity(manifest_path: str | Path, url: str, capture_key: str = "") -> str:
    """Stable capture identity for one manifest item, surviving retries.

    Derived from manifest bytes, URL and any additional same-URL declaration:
    the same lane evidence
    retried after an interrupted terminal commit re-derives the same identity
    and confirms the existing capture instead of publishing a duplicate.
    """
    digest = hashlib.sha256()
    try:
        digest.update(Path(manifest_path).read_bytes())
    except OSError:
        digest.update(str(manifest_path).encode("utf-8", "replace"))
    digest.update(b"|")
    digest.update(str(url or "").encode("utf-8", "replace"))
    if capture_key:
        digest.update(b"|")
        digest.update(capture_key.encode("utf-8"))
    return f"mcp-{digest.hexdigest()[:24]}"


def import_focused_mcp_manifest(
    *,
    target: str,
    manifest_path: str | Path,
    max_urls: int = DEFAULT_FOCUSED_LIMIT,
    evidence_root: str | Path = DEFAULT_EVIDENCE_ROOT,
    recon_root: str | Path = DEFAULT_RECON_ROOT,
    repo_root: str | Path = BASE_DIR,
    enqueue: bool = False,
) -> dict[str, Any]:
    """导入 MCP 已落盘的同目标证据，发布有界差分供 AI 选择。"""
    if enqueue:
        from tools.action_queue import add_material_review
        from tools.target_store import runtime_store
        runtime_store(repo_root, target)
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
        capture_key = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if capture_key in seen:
            skipped.append({"url": public_url_shape(url), "reason": "duplicate"})
            continue
        seen.add(capture_key)
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
        selected.append((url, raw, capture_key))

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

    captured_urls = set()
    for index, (url, item, capture_key) in enumerate(selected, 1):
        # Preserve the existing first-URL receipt; later states need separate captures.
        run_identity = _manifest_capture_identity(
            manifest_path, url, capture_key if url in captured_urls else "")
        captured_urls.add(url)
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
                run_identity=run_identity,
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
        is_actionable = bool(
            summary.get("success")
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
        registered = add_material_review(
            repo_root, target=target, source="browser-context-discovery",
            source_id="browser-context-discovery", action_type="browser-context-discovery",
            summary_path=output_path, material={"captures": actionable},
        )
        result["queue"] = {"receipt": registered["receipt"], "action_id": registered["action"]["id"]}
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
    parser.add_argument("--enqueue", action=argparse.BooleanOptionalAction, default=False,
                        help="Explicitly register review work for new browser material in the active Store")
    parser.add_argument("--label", default="mcp", help="Capture label suffix")
    parser.add_argument("--source", default="mcp", help="Source label, e.g. chrome-devtools-mcp or playwright-mcp")
    parser.add_argument("--evidence-root", default=str(DEFAULT_EVIDENCE_ROOT), help="Evidence root directory")
    parser.add_argument("--recon-root", default=str(DEFAULT_RECON_ROOT), help="Recon root directory")
    parser.add_argument("--repo-root", default=str(BASE_DIR), help="Repository data root")
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
            enqueue=args.enqueue,
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
