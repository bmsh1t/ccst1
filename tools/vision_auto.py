#!/usr/bin/env python3
"""
vision_auto.py — heuristic SPA/login detector for auto-vision (P5-VA).

Decides whether to auto-trigger capture_with_screenshot_sequence at a
recon→hunt transition, based on signals already collected by the recon
pipeline.

API:
    should_auto_trigger(recon_signals, url) -> (bool, str)
        Returns (yes_or_no, reason). Reason is a short tag suitable for
        the audit log.

    log_auto_trigger(target, url, reason, screenshot_seq, *, path=None)
        Append one row to hunt-memory/audit/vision_auto.jsonl.

Throttling state:
    should_auto_trigger() is stateless. The CALLER is responsible for
    de-duplicating (target, url_path_prefix) within a session. A small
    helper VisionAutoThrottle is provided for in-memory throttling.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


# URL paths that strongly suggest an app/SPA login surface
_LOGIN_PATH_PATTERNS = (
    re.compile(r"/login\b", re.IGNORECASE),
    re.compile(r"/signin\b", re.IGNORECASE),
    re.compile(r"/sign-in\b", re.IGNORECASE),
    re.compile(r"/account\b", re.IGNORECASE),
    re.compile(r"/dashboard\b", re.IGNORECASE),
    re.compile(r"/app(\b|/)", re.IGNORECASE),
    re.compile(r"/portal\b", re.IGNORECASE),
    re.compile(r"/console\b", re.IGNORECASE),
    re.compile(r"/admin\b", re.IGNORECASE),
)


# SPA-framework fingerprints (looked for in JS file names / titles / bundles)
_SPA_FRAMEWORK_FINGERPRINTS = (
    "react", "vue", "angular", "next", "nuxt", "svelte", "ember",
    "_next", "/static/js", "main.bundle.js", "runtime.js", "vendor.js",
    # Angular CLI / Juice-Shop bundle naming (output of `ng build`)
    "main-es", "runtime-es", "vendor-es", "polyfills-es", "styles-es",
    "main-es2015", "runtime-es2015", "vendor-es2015", "polyfills-es2015",
)


def _is_html_response(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return "text/html" in ct or "application/xhtml" in ct


def _path_matches_login(url: str) -> bool:
    try:
        path = urlparse(url).path or ""
    except Exception:
        return False
    return any(p.search(path) for p in _LOGIN_PATH_PATTERNS)


def _has_spa_fingerprint(js_files: Iterable[str]) -> bool:
    js_list = list(js_files or [])
    if not js_list:
        return False
    joined = " ".join(str(j).lower() for j in js_list)
    return any(fp in joined for fp in _SPA_FRAMEWORK_FINGERPRINTS)


def _has_password_form(html_snippet: str) -> bool:
    """Detect a probable password form anywhere in the snippet."""
    if not html_snippet:
        return False
    s = html_snippet.lower()
    return ('type="password"' in s or "type='password'" in s
            or "input type=password" in s)


def should_auto_trigger(recon_signals: dict, url: str) -> tuple[bool, str]:
    """Decide whether to fire a vision capture for url.

    Multi-signal decision keeps false-positives down (static marketing
    pages with /login link in the footer won't trip it).

    Primary class (any one):
      - login_signal: URL path matches /login, /signin, /dashboard, ...
      - password_signal: HTML snippet contains type="password"
      - spa_app_signal: ≥5 JS files AND a known SPA framework fingerprint
        (covers SPA root paths like Juice Shop "/" that bootstrap login
        modal via JS, so login_signal and password_signal both miss)

    Secondary class (any one): spa_signal, html_signal, spa_bundle_signal.

    Returns (True, reason_tag) or (False, "").
    """
    if not isinstance(recon_signals, dict) or not url:
        return False, ""

    login_signal = _path_matches_login(url)
    password_signal = _has_password_form(recon_signals.get("html_snippet", ""))

    spa_signal = _has_spa_fingerprint(recon_signals.get("js_files", []))
    html_signal = _is_html_response(recon_signals.get("content_type", ""))
    js_count = int(recon_signals.get("js_count", 0) or 0)
    spa_bundle_signal = js_count >= 3
    spa_app_signal = spa_signal and js_count >= 5

    primary = login_signal or password_signal or spa_app_signal
    secondary = spa_signal or html_signal or spa_bundle_signal

    if primary and secondary:
        # Tag the strongest reason for audit clarity
        if login_signal and spa_signal:
            return True, "spa_login"
        if login_signal:
            return True, "login_path"
        if password_signal:
            return True, "password_form"
        if spa_app_signal:
            return True, "spa_app_root"
    return False, ""


# ---------------------------------------------------------------------
#  Throttle helper (R3) — in-memory dedup of (target, path-prefix)
# ---------------------------------------------------------------------

class VisionAutoThrottle:
    """Track (target, path-prefix) pairs already auto-captured this run."""

    def __init__(self):
        self._seen: set[tuple[str, str]] = set()

    @staticmethod
    def _key(target: str, url: str) -> tuple[str, str]:
        try:
            path = urlparse(url).path or "/"
        except Exception:
            path = "/"
        # Path-prefix = first 2 segments (e.g., /app/login → /app/login,
        # /app/login/forgot → /app/login)
        parts = [p for p in path.split("/") if p]
        prefix = "/" + "/".join(parts[:2]) if parts else "/"
        return (target, prefix.lower())

    def should_skip(self, target: str, url: str) -> bool:
        return self._key(target, url) in self._seen

    def mark(self, target: str, url: str) -> None:
        self._seen.add(self._key(target, url))

    def reset(self) -> None:
        self._seen.clear()


# ---------------------------------------------------------------------
#  R4 — Telemetry log
# ---------------------------------------------------------------------

def default_audit_path(repo_root: Path | str | None = None) -> Path:
    repo = Path(repo_root) if repo_root else BASE_DIR
    return repo / "hunt-memory" / "audit" / "vision_auto.jsonl"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_auto_trigger(
    target: str,
    url: str,
    *,
    trigger_reason: str,
    screenshot_seq: int | None = None,
    path: Path | str | None = None,
) -> dict:
    """Append a single auto-trigger event to the audit log."""
    record = {
        "ts": _utc_now(),
        "target": str(target or ""),
        "url": str(url or ""),
        "trigger_reason": str(trigger_reason or ""),
        "screenshot_seq": int(screenshot_seq) if screenshot_seq is not None else None,
    }
    target_path = Path(path) if path else default_audit_path()
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        line = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(str(target_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.write(fd, line)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return record
    except Exception:
        return {}
