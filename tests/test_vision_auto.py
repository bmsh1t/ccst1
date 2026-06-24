"""tests/test_vision_auto.py — P5-VA vision auto-trigger tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import vision_auto as va  # noqa: E402


# ---------------------------------------------------------------------
#  R1 — Detection heuristic
# ---------------------------------------------------------------------

class TestShouldAutoTrigger:
    def test_login_path_plus_html_triggers(self):
        sig = {"content_type": "text/html; charset=utf-8", "js_files": []}
        fire, reason = va.should_auto_trigger(sig, "https://x.com/login")
        assert fire is True
        assert reason in {"login_path", "spa_login"}

    def test_spa_login_combo_uses_spa_login_tag(self):
        sig = {
            "content_type": "text/html",
            "js_files": ["/_next/static/main.js", "react.bundle.js"],
        }
        fire, reason = va.should_auto_trigger(sig, "https://x.com/app/login")
        assert fire is True
        assert reason == "spa_login"

    def test_password_form_plus_html_triggers(self):
        sig = {
            "content_type": "text/html",
            "html_snippet": '<input name="pw" type="password">',
        }
        fire, reason = va.should_auto_trigger(sig, "https://x.com/")
        assert fire is True
        assert reason == "password_form"

    def test_login_path_alone_does_not_trigger(self):
        # No HTML/SPA secondary signal → no trigger
        sig = {"content_type": "application/json", "js_files": []}
        fire, reason = va.should_auto_trigger(sig, "https://x.com/login")
        assert fire is False
        assert reason == ""

    def test_marketing_page_with_footer_login_link_does_not_trigger(self):
        # URL is just the homepage, no /login in path, no password form
        sig = {"content_type": "text/html", "js_files": ["analytics.js"]}
        fire, reason = va.should_auto_trigger(sig, "https://x.com/about")
        assert fire is False

    def test_static_asset_does_not_trigger(self):
        sig = {"content_type": "image/png", "js_files": []}
        fire, reason = va.should_auto_trigger(sig, "https://x.com/login")
        assert fire is False

    def test_dashboard_path_triggers_when_spa(self):
        sig = {"content_type": "text/html",
                "js_files": ["vue.runtime.js", "main.bundle.js", "vendor.js"]}
        fire, _ = va.should_auto_trigger(sig, "https://x.com/dashboard")
        assert fire is True

    def test_app_path_triggers_when_html(self):
        sig = {"content_type": "text/html", "js_count": 5}
        fire, _ = va.should_auto_trigger(sig, "https://x.com/app/billing")
        assert fire is True

    def test_invalid_url_returns_false(self):
        sig = {"content_type": "text/html"}
        fire, _ = va.should_auto_trigger(sig, "")
        assert fire is False

    def test_invalid_signals_returns_false(self):
        fire, _ = va.should_auto_trigger("not-a-dict", "https://x.com/login")  # type: ignore[arg-type]
        assert fire is False

    def test_spa_app_root_triggers_without_login_path(self):
        # SPA root path with no /login URL and no visible password form,
        # but a real SPA bundle (Juice Shop-style: login modal loads via JS).
        sig = {
            "content_type": "text/html",
            "js_files": [
                "/main-es2015.js",
                "/runtime-es2015.js",
                "/vendor-es2015.js",
                "/polyfills-es2015.js",
                "/styles-es2015.js",
                "/scripts.js",
            ],
            "js_count": 6,
        }
        fire, reason = va.should_auto_trigger(sig, "https://juice-shop.example.com/")
        assert fire is True
        assert reason == "spa_app_root"

    def test_spa_app_root_requires_framework_fingerprint(self):
        # ≥5 plain JS files without a known SPA framework name → no spa_app primary.
        sig = {
            "content_type": "text/html",
            "js_files": [
                "/jquery.min.js",
                "/site.js",
                "/banner.js",
                "/cookieconsent.js",
                "/gtm.js",
            ],
            "js_count": 5,
        }
        fire, _ = va.should_auto_trigger(sig, "https://marketing.example.com/")
        assert fire is False


# ---------------------------------------------------------------------
#  R3 — Throttling
# ---------------------------------------------------------------------

class TestThrottle:
    def test_first_url_not_skipped(self):
        t = va.VisionAutoThrottle()
        assert t.should_skip("x.com", "https://x.com/app/login") is False

    def test_second_same_prefix_is_skipped(self):
        t = va.VisionAutoThrottle()
        t.mark("x.com", "https://x.com/app/login")
        assert t.should_skip("x.com", "https://x.com/app/login") is True
        # Same prefix, different leaf, still skipped
        assert t.should_skip("x.com", "https://x.com/app/login/forgot") is True

    def test_different_prefix_not_skipped(self):
        t = va.VisionAutoThrottle()
        t.mark("x.com", "https://x.com/app/login")
        assert t.should_skip("x.com", "https://x.com/admin/users") is False

    def test_different_target_not_skipped(self):
        t = va.VisionAutoThrottle()
        t.mark("x.com", "https://x.com/login")
        assert t.should_skip("y.com", "https://y.com/login") is False

    def test_reset_clears_state(self):
        t = va.VisionAutoThrottle()
        t.mark("x.com", "https://x.com/login")
        t.reset()
        assert t.should_skip("x.com", "https://x.com/login") is False


# ---------------------------------------------------------------------
#  R4 — Telemetry log
# ---------------------------------------------------------------------

class TestAuditLog:
    def test_log_auto_trigger_writes_jsonl(self, tmp_path):
        path = tmp_path / "vision_auto.jsonl"
        rec = va.log_auto_trigger(
            "x.com", "https://x.com/login",
            trigger_reason="spa_login",
            screenshot_seq=3,
            path=path,
        )
        assert rec["target"] == "x.com"
        assert rec["screenshot_seq"] == 3
        parsed = json.loads(path.read_text().strip())
        assert parsed["trigger_reason"] == "spa_login"
        assert "ts" in parsed

    def test_log_auto_trigger_appends(self, tmp_path):
        path = tmp_path / "vision_auto.jsonl"
        va.log_auto_trigger("x", "u1", trigger_reason="login_path", path=path)
        va.log_auto_trigger("x", "u2", trigger_reason="password_form", path=path)
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_log_swallows_errors(self, tmp_path):
        bad = tmp_path / "f"
        bad.write_text("blocker")
        rec = va.log_auto_trigger("x", "u", trigger_reason="r",
                                   path=bad / "x" / "log.jsonl")
        assert isinstance(rec, dict)
