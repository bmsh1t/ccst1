#!/usr/bin/env python3
"""Extract reusable lightweight attack surface from browser evidence."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

API_RE = re.compile(r"(/api/|/v\d+(?:/|$)|/graphql\b|/rest/|/rpc/)", re.I)
HIGH_SIGNAL_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,80}$")
RAW_REQUEST_RE = re.compile(
    r"""
    ^\s*
    (?:\d+\.\s*)?
    (?:\[(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\]\s*)?
    (?P<url>https?://[^\s]+|/[^\s]+)
    (?:\s*=>.*)?
    \s*$
    """,
    re.I | re.X,
)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _load_json(path: Path | None) -> object:
    if not path or not path.is_file():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _request_items(payload: object) -> list[object]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("requests", "items", "entries", "messages"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    log = payload.get("log")
    if isinstance(log, dict) and isinstance(log.get("entries"), list):
        return log["entries"]
    for key in ("raw", "result"):
        value = payload.get(key)
        if isinstance(value, str):
            return _raw_request_items(value)
    return []


def _first_string(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _body_from_request(item: dict, request: dict) -> object:
    for source in (item, request):
        for key in ("postData", "body", "payload", "data", "formData"):
            value = source.get(key)
            if value not in ("", None):
                return value
    return ""


def _parse_request_item(item: object) -> dict:
    if isinstance(item, str):
        raw_item = _parse_raw_request_line(item)
        if raw_item:
            return raw_item
        return {"url": item.strip(), "method": "GET", "resource_type": "", "body": ""}
    if not isinstance(item, dict):
        return {"url": "", "method": "GET", "resource_type": "", "body": ""}

    request = item.get("request") if isinstance(item.get("request"), dict) else {}
    url = _first_string(item.get("url"), item.get("requestUrl"), item.get("href"), request.get("url"))
    method = _first_string(item.get("method"), request.get("method")) or "GET"
    resource_type = _first_string(
        item.get("resourceType"),
        item.get("type"),
        item.get("initiatorType"),
        item.get("_resourceType"),
        request.get("resourceType"),
        request.get("type"),
    )
    return {
        "url": url,
        "method": method.upper(),
        "resource_type": resource_type.lower(),
        "body": _body_from_request(item, request),
    }


def _raw_request_items(raw: str) -> list[dict]:
    """Parse playwright-cli --raw/--json requests text output into request dicts."""
    items: list[dict] = []
    for line in raw.splitlines():
        parsed = _parse_raw_request_line(line)
        if parsed:
            items.append(parsed)
    return items


def _parse_raw_request_line(line: str) -> dict:
    """Parse lines like: 2. [POST] https://host/api/me => [200] OK."""
    match = RAW_REQUEST_RE.match((line or "").strip())
    if not match:
        return {}
    method = (match.group("method") or "GET").upper()
    url = (match.group("url") or "").rstrip(",")
    return {"url": url, "method": method, "resource_type": "", "body": ""}


def _body_param_keys(body: object) -> list[str]:
    if isinstance(body, dict):
        keys: list[str] = []
        for key, value in body.items():
            if key in {"text", "raw"} and isinstance(value, str):
                keys.extend(_body_param_keys(value))
            elif key in {"params", "entries"} and isinstance(value, list):
                keys.extend(_body_param_keys(value))
            elif isinstance(value, str) and key in {"query", "graphql"}:
                keys.extend(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", value))
                keys.append(str(key))
            elif HIGH_SIGNAL_PARAM_RE.match(str(key)):
                keys.append(str(key))
        return keys
    if isinstance(body, list):
        keys = []
        for item in body:
            if isinstance(item, dict) and item.get("name"):
                keys.append(str(item["name"]))
            else:
                keys.extend(_body_param_keys(item))
        return keys
    if not isinstance(body, str) or not body.strip():
        return []

    raw = body.strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        return _body_param_keys(parsed)
    keys = [key for key, _ in parse_qsl(raw, keep_blank_values=True)]
    keys.extend(re.findall(r'["\']([A-Za-z_][A-Za-z0-9_.:-]{0,80})["\']\s*:', raw))
    return keys


def _param_lines(url: str, body: object) -> list[str]:
    parsed = urlparse(url)
    keys = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    keys.extend(_body_param_keys(body))
    return [f"{url} :: {key}" for key in _dedupe_keep_order(keys)]


def _is_api_url(url: str) -> bool:
    parsed = urlparse(url)
    value = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    return bool(API_RE.search(value or url))


def _is_xhr_like(request: dict) -> bool:
    resource_type = str(request.get("resource_type", "")).lower()
    method = str(request.get("method", "GET")).upper()
    return resource_type in {"xhr", "fetch", "xmlhttprequest"} or method not in {"", "GET", "HEAD"} or _is_api_url(request["url"])


def _extract_forms(snapshot_path: Path | None) -> dict:
    if not snapshot_path or not snapshot_path.is_file():
        return {"status": "not_available", "forms": [], "note": "No DOM/snapshot artifact was available."}
    text = snapshot_path.read_text(encoding="utf-8", errors="replace")
    forms = []
    for match in re.finditer(r"<form\b(?P<attrs>[^>]*)>", text, re.I):
        attrs = match.group("attrs")
        action = _first_string(*(m.group(1) for m in re.finditer(r'action=["\']([^"\']+)["\']', attrs, re.I)))
        method = _first_string(*(m.group(1) for m in re.finditer(r'method=["\']([^"\']+)["\']', attrs, re.I))) or "GET"
        forms.append({"action": action, "method": method.upper()})
    if forms:
        return {"status": "extracted", "forms": forms, "note": "Extracted from form tags in snapshot text."}
    return {
        "status": "placeholder",
        "forms": [],
        "note": "playwright-cli snapshot is not guaranteed to be DOM HTML; no form tags were parsed.",
    }


def write_browser_surface(
    *,
    recon_root: str | Path,
    target_key: str,
    requests_path: str | Path | None = None,
    snapshot_path: str | Path | None = None,
    capture_dir: str = "",
) -> dict:
    """Write recon/<target>/browser artifacts from captured request data."""
    browser_dir = Path(recon_root) / target_key / "browser"
    browser_dir.mkdir(parents=True, exist_ok=True)
    req_path = Path(requests_path) if requests_path else None
    snap_path = Path(snapshot_path) if snapshot_path else None

    requests = [_parse_request_item(item) for item in _request_items(_load_json(req_path))]
    requests = [item for item in requests if item.get("url")]
    xhr_urls = _dedupe_keep_order([item["url"] for item in requests if _is_xhr_like(item)])
    api_urls = _dedupe_keep_order([item["url"] for item in requests if _is_api_url(item["url"]) or item["url"] in xhr_urls])
    params = _dedupe_keep_order([line for item in requests for line in _param_lines(item["url"], item.get("body", ""))])
    forms = _extract_forms(snap_path)

    artifacts = {
        "xhr_endpoints": str(browser_dir / "xhr_endpoints.txt"),
        "api_endpoints": str(browser_dir / "api_endpoints.txt"),
        "browser_params": str(browser_dir / "browser_params.txt"),
        "forms": str(browser_dir / "forms.json"),
        "summary": str(browser_dir / "summary.json"),
    }
    _write_lines(Path(artifacts["xhr_endpoints"]), xhr_urls)
    _write_lines(Path(artifacts["api_endpoints"]), api_urls)
    _write_lines(Path(artifacts["browser_params"]), params)
    Path(artifacts["forms"]).write_text(json.dumps(forms, indent=2) + "\n", encoding="utf-8")

    summary = {
        "target_key": target_key,
        "generated_at": _now_utc(),
        "source_requests_path": str(req_path or ""),
        "source_snapshot_path": str(snap_path or ""),
        "source_capture_dir": capture_dir,
        "counts": {
            "requests": len(requests),
            "xhr_endpoints": len(xhr_urls),
            "api_endpoints": len(api_urls),
            "browser_params": len(params),
            "forms": len(forms.get("forms", [])),
        },
        "artifacts": artifacts,
        "forms_status": forms.get("status", ""),
    }
    Path(artifacts["summary"]).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


# ─── Per-page JS loading map (PR-19) ────────────────────────────────────────
JS_EXTENSIONS = (".js", ".mjs", ".cjs")


def _is_js_request(item: dict) -> bool:
    """A request loaded a JS asset.

    Primary signal: resource_type == 'script' (Playwright DevTools protocol).
    Fallback (when resource_type is empty — e.g., raw playwright-cli output):
    URL extension matches a known JS extension, OR contains '.js?' (cache
    buster). Excludes everything else even when their URLs happen to contain
    'js' as a substring (e.g., '/api/jspatch/health').
    """
    if not isinstance(item, dict):
        return False
    if str(item.get("resource_type", "")).lower() == "script":
        return True
    url = str(item.get("url", "") or "").split("#", 1)[0]
    if not url:
        return False
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith(JS_EXTENSIONS):
        return True
    # Cache buster: /static/app.js?v=123
    if any(f"{ext}?" in url.lower() for ext in JS_EXTENSIONS):
        return True
    return False


def _capture_summary_dirs(browser_root: Path) -> list[Path]:
    """Iterate timestamp-labelled capture dirs under evidence/<target>/browser/."""
    if not browser_root.is_dir():
        return []
    out = []
    for child in sorted(browser_root.iterdir()):
        if not child.is_dir():
            continue
        if (child / "summary.json").is_file():
            out.append(child)
    return out


def _extract_js_urls(requests_path: Path) -> list[str]:
    """Read a capture's requests.json and return JS-only URLs in order."""
    if not requests_path.is_file():
        return []
    items = [_parse_request_item(item) for item in _request_items(_load_json(requests_path))]
    js_urls = [item["url"] for item in items if item.get("url") and _is_js_request(item)]
    return _dedupe_keep_order(js_urls)


def build_page_js_map(
    *,
    evidence_root: str | Path,
    recon_root: str | Path,
    target_key: str,
) -> dict:
    """Aggregate per-page JS loading observed across all browser captures.

    Walks evidence/<target>/browser/<timestamp>-*/summary.json, groups JS
    requests by the page URL of each capture, and emits both forward
    (page → JS files) and reverse (JS file → pages) lookups so surface
    ranking can answer "which page should I navigate to in order to load
    this JS sink?" without re-visiting.

    Idempotent: re-runs include all captures present at call time.
    Multiple captures of the same page accumulate in `capture_dirs` and
    union their JS sets — never lose history.

    Returns the map dict (also written to
    recon/<target>/browser/page_js_map.json).
    """
    browser_evidence = Path(evidence_root) / target_key / "browser"
    capture_dirs = _capture_summary_dirs(browser_evidence)

    pages: dict[str, dict] = {}
    js_index: dict[str, list[str]] = {}

    for cap_dir in capture_dirs:
        summary = _load_json(cap_dir / "summary.json")
        if not isinstance(summary, dict):
            continue
        page_url = str(summary.get("url", "") or "").strip()
        if not page_url:
            continue
        captured_at = str(summary.get("captured_at", "") or "")
        artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
        requests_path = Path(artifacts.get("requests_json") or (cap_dir / "requests.json"))
        js_urls = _extract_js_urls(requests_path)

        entry = pages.setdefault(
            page_url,
            {"captured_at": captured_at, "capture_dirs": [], "js_files": []},
        )
        # Track lifetime-aggregate dirs (history preserved)
        if str(cap_dir) not in entry["capture_dirs"]:
            entry["capture_dirs"].append(str(cap_dir))
        # Union JS files across re-captures of the same page
        for js in js_urls:
            if js not in entry["js_files"]:
                entry["js_files"].append(js)
        # Latest capture time wins for the page-level captured_at
        if captured_at and (not entry["captured_at"] or captured_at > entry["captured_at"]):
            entry["captured_at"] = captured_at

    # Build reverse index after all pages are populated
    for page_url, entry in pages.items():
        for js in entry["js_files"]:
            pages_for_js = js_index.setdefault(js, [])
            if page_url not in pages_for_js:
                pages_for_js.append(page_url)

    map_obj = {
        "generated_at": _now_utc(),
        "target_key": target_key,
        "pages": pages,
        "js_index": js_index,
    }

    out_path = Path(recon_root) / target_key / "browser" / "page_js_map.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(map_obj, indent=2) + "\n", encoding="utf-8")
    return map_obj


def load_page_js_map(recon_root: str | Path, target_key: str) -> dict:
    """Read the persisted per-page JS map. Empty dict when absent — does
    NOT raise so surface ranking on a fresh target is unaffected."""
    path = Path(recon_root) / target_key / "browser" / "page_js_map.json"
    payload = _load_json(path)
    if not isinstance(payload, dict):
        return {"pages": {}, "js_index": {}}
    payload.setdefault("pages", {})
    payload.setdefault("js_index", {})
    return payload
