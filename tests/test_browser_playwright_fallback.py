"""Local Playwright fallback keeps the existing browser evidence owner."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from tools import browser_playwright_fallback


class _Request:
    def __init__(self, url: str, method: str = "GET", resource_type: str = "xhr"):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = ""


class _Response:
    def __init__(self, request: _Request, status: int):
        self.request = request
        self.status = status


class _Message:
    type = "info"
    text = "page ready"


class _Page:
    def __init__(self):
        self.handlers = {}

    def on(self, event, callback):
        self.handlers[event] = callback

    def goto(self, _url, **_kwargs):
        request = _Request("https://target.local/api/me")
        self.handlers["request"](request)
        self.handlers["response"](_Response(request, 200))
        self.handlers["console"](_Message())

    def wait_for_timeout(self, _milliseconds):
        return None

    def content(self):
        return '<form action="/api/me?token=secret" method="post"></form>'

    def screenshot(self, path, **_kwargs):
        Path(path).write_bytes(b"PNG")


class _Context:
    def route(self, _pattern, _callback):
        return None

    def new_page(self):
        return _Page()

    def close(self):
        return None


class _Browser:
    def new_context(self, **kwargs):
        assert kwargs["service_workers"] == "block"
        return _Context()

    def close(self):
        return None


class _Chromium:
    def launch(self, *, headless):
        assert headless is True
        return _Browser()


class _Playwright:
    chromium = _Chromium()


class _PlaywrightManager:
    def __enter__(self):
        return _Playwright()

    def __exit__(self, *_args):
        return None


def test_playwright_fallback_imports_capture_into_existing_surface(tmp_path, monkeypatch):
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: _PlaywrightManager()
    package = types.ModuleType("playwright")
    package.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    result = browser_playwright_fallback.capture_with_playwright(
        target="target.local",
        url="https://target.local/app",
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    assert result["status"] == "ok"
    assert result["capture_backend"] == "playwright-fallback"
    assert result["counts"]["requests"] == 1
    assert (tmp_path / "recon" / "target.local" / "browser" / "api_endpoints.txt").read_text(
        encoding="utf-8"
    ).splitlines() == ["https://target.local/api/me"]


def test_playwright_fallback_rejects_off_target_seed():
    with pytest.raises(ValueError, match="outside target scope"):
        browser_playwright_fallback._resolve_url(
            "target.local", "https://off-target.local/app"
        )
