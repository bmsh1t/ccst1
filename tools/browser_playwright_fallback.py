#!/usr/bin/env python3
"""Capture one target-owned page with local Python Playwright.

This is a thin fallback for sessions without a usable browser MCP.  It only
collects artifacts and hands them to ``browser_mcp_import``; Surface and
readiness remain owned by the existing importer/runtime pipeline.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.browser_evidence import compact_browser_evidence
    from tools.browser_mcp_import import import_mcp_browser_evidence
    from tools.target_paths import canonical_target_value, url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from browser_evidence import compact_browser_evidence  # type: ignore
    from browser_mcp_import import import_mcp_browser_evidence  # type: ignore
    from target_paths import canonical_target_value, url_belongs_to_target  # type: ignore


DEFAULT_TIMEOUT_MS = 30_000
DEFAULT_WAIT_MS = 1_000


def _safe_error(value: object) -> str:
    return " ".join(str(value or "").split())[:400]


def _default_url(target: str) -> str:
    value = str(target or "").strip()
    if "://" in value:
        return value
    host = value.rsplit("@", 1)[-1]
    host = host.rsplit(":", 1)[0].strip("[]")
    local = host == "localhost" or host.endswith(".local")
    if not local:
        try:
            local = ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
    return f"{'http' if local else 'https'}://{value}"


def _resolve_url(target: str, url: str) -> str:
    candidate = str(url or "").strip() or _default_url(target)
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("fallback URL must be an absolute HTTP(S) URL")
    if not url_belongs_to_target(candidate, target):
        raise ValueError("fallback URL is outside target scope")
    return candidate


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def capture_with_playwright(
    *,
    target: str,
    url: str = "",
    evidence_root: str | Path | None = None,
    recon_root: str | Path | None = None,
    storage_state: str | Path | None = None,
    auth_required: bool = False,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    wait_ms: int = DEFAULT_WAIT_MS,
    headed: bool = False,
    label: str = "playwright-fallback",
) -> dict[str, Any]:
    """Capture and import one page, returning the importer summary/projection."""
    if timeout_ms <= 0 or wait_ms < 0:
        raise ValueError("timeout_ms must be positive and wait_ms must be non-negative")
    resolved_target = canonical_target_value(target)
    page_url = _resolve_url(resolved_target, url)
    state_path = Path(storage_state).expanduser() if storage_state else None
    if state_path is not None and not state_path.is_file():
        raise ValueError(f"storage state does not exist: {state_path}")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {
            "status": "unavailable",
            "success": False,
            "target": resolved_target,
            "url": page_url,
            "error": "Python Playwright is unavailable",
        }

    requests: dict[int, dict[str, Any]] = {}
    console: list[dict[str, str]] = []
    errors: list[str] = []
    snapshot = ""
    screenshot_taken = False

    with tempfile.TemporaryDirectory(prefix="ccst-playwright-") as temp_dir:
        temp = Path(temp_dir)
        network_path = temp / "network.json"
        snapshot_path = temp / "snapshot.html"
        console_path = temp / "console.json"
        screenshot_path = temp / "screenshot.png"

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=not headed)
                context_kwargs: dict[str, Any] = {"service_workers": "block"}
                if state_path is not None:
                    context_kwargs["storage_state"] = str(state_path)
                context = browser.new_context(**context_kwargs)

                def route_request(route: Any, request: Any) -> None:
                    request_url = str(getattr(request, "url", "") or "")
                    scheme = urlparse(request_url).scheme.lower()
                    if scheme in {"http", "https"} and not url_belongs_to_target(
                        request_url, resolved_target
                    ):
                        route.abort()
                        return
                    route.continue_()

                context.route("**/*", route_request)
                page = context.new_page()

                def record_request(request: Any) -> None:
                    request_url = str(getattr(request, "url", "") or "")
                    if not url_belongs_to_target(request_url, resolved_target):
                        return
                    try:
                        body = request.post_data or ""
                    except Exception:
                        body = ""
                    requests[id(request)] = {
                        "url": request_url,
                        "method": str(getattr(request, "method", "GET") or "GET").upper(),
                        "resourceType": str(getattr(request, "resource_type", "") or "").lower(),
                        "postData": body,
                    }

                def record_response(response: Any) -> None:
                    item = requests.get(id(getattr(response, "request", None)))
                    if item is not None:
                        item["status"] = int(getattr(response, "status", 0) or 0)

                def record_console(message: Any) -> None:
                    console.append({
                        "type": str(getattr(message, "type", "log") or "log"),
                        "text": str(getattr(message, "text", "") or ""),
                    })

                page.on("request", record_request)
                page.on("response", record_response)
                page.on("console", record_console)
                try:
                    page.goto(page_url, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception as exc:
                    errors.append(f"navigation failed: {_safe_error(exc)}")
                if wait_ms:
                    try:
                        page.wait_for_timeout(wait_ms)
                    except Exception as exc:
                        errors.append(f"settle failed: {_safe_error(exc)}")
                try:
                    snapshot = page.content()
                except Exception as exc:
                    errors.append(f"snapshot failed: {_safe_error(exc)}")
                try:
                    page.screenshot(path=str(screenshot_path), full_page=False)
                    screenshot_taken = screenshot_path.is_file()
                except Exception as exc:
                    errors.append(f"screenshot failed: {_safe_error(exc)}")
                context.close()
                browser.close()
        except Exception as exc:
            errors.append(f"browser failed: {_safe_error(exc)}")

        _write_json(network_path, list(requests.values()))
        snapshot_path.write_text(snapshot, encoding="utf-8")
        _write_json(console_path, console)
        evidence = Path(evidence_root) if evidence_root else BASE_DIR / "evidence"
        recon = Path(recon_root) if recon_root else BASE_DIR / "recon"
        summary = import_mcp_browser_evidence(
            target=resolved_target,
            url=page_url,
            network_path=network_path,
            snapshot_path=snapshot_path,
            console_path=console_path,
            screenshot_path=screenshot_path if screenshot_taken else None,
            state_path=state_path,
            label=label,
            evidence_root=evidence,
            recon_root=recon,
            source="playwright-fallback",
            auth_required=bool(auth_required or state_path),
            auth_state="present" if state_path else "",
            capture_error="; ".join(errors),
        )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture target-owned browser evidence with Python Playwright")
    parser.add_argument("--target", required=True)
    parser.add_argument("--url", default="")
    parser.add_argument("--storage-state", default="")
    parser.add_argument("--auth-required", action="store_true")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--wait-ms", type=int, default=DEFAULT_WAIT_MS)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--label", default="playwright-fallback")
    parser.add_argument("--evidence-root", default="")
    parser.add_argument("--recon-root", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = capture_with_playwright(
            target=args.target,
            url=args.url,
            evidence_root=args.evidence_root or None,
            recon_root=args.recon_root or None,
            storage_state=args.storage_state or None,
            auth_required=args.auth_required,
            timeout_ms=args.timeout_ms,
            wait_ms=args.wait_ms,
            headed=args.headed,
            label=args.label,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": _safe_error(exc)}, ensure_ascii=False))
        return 1
    if result.get("status") == "unavailable":
        print(json.dumps(result, ensure_ascii=False))
        return 2
    print(json.dumps(compact_browser_evidence(result), ensure_ascii=False, indent=2))
    return 0 if result.get("status") in {"ok", "partial"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
