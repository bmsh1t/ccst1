"""Tests for the evidence-gated Packer-InfoFinder adapter."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

import tools.deep_js_packer as deep_js_packer
from tools.deep_js_packer import (
    _RateLimitedSession,
    _RateLimiter,
    _copy_recovered_artifacts,
    _guard_browser_route,
    _install_browser_request_guard,
    run_packer,
    select_bundle_urls,
)
from tools.js_reader import prepare_materials


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _fake_packer(
    root: Path, *, include_js: bool = True, page_delay: float = 0
) -> Path:
    _write(root / "Packer-InfoFinder.py", "# fake tool root\n")
    _write(root / "lib" / "__init__.py", "")
    _write(root / "lib" / "runner" / "__init__.py", "")
    _write(
        root / "lib" / "DownloadJs.py",
        """from concurrent.futures import ThreadPoolExecutor

class DownloadJs:
    def __init__(self, *_args, **_kwargs):
        self.session = object()

    def _is_sane_js_url(self, url):
        return url.startswith(("http://", "https://"))
""",
    )
    _write(
        root / "lib" / "runner" / "js_only_scan.py",
        f"INCLUDE_JS = {include_js!r}\n"
        + """import json
import os
from pathlib import Path
from lib import DownloadJs as download_module
from lib.DownloadJs import DownloadJs

def testProxy(_options, _show):
    Path("proxy-called").write_text("unexpected", encoding="utf-8")

def run_js_only_scan(options):
    testProxy(options, 1)
    pool = download_module.ThreadPoolExecutor(max_workers=30)
    downloader = DownloadJs()
    Path("tmp").mkdir(exist_ok=True)
    if INCLUDE_JS:
        Path("tmp/recovered.js").write_text("fetch('/api/recovered')", encoding="utf-8")
    Path("tmp/worker.json").write_text(json.dumps({
        "workers": pool._max_workers,
        "proxy_called": Path("proxy-called").exists(),
        "session_wrapper": type(downloader.session).__name__,
        "in_scope": downloader._is_sane_js_url(options.js.split(",")[0]),
        "out_of_scope": downloader._is_sane_js_url("https://outside.invalid/app.js"),
        "auth_env": {
            key: value for key, value in os.environ.items()
            if key.startswith("BBHUNT_AUTH_") or key in {
                "BBHUNT_COOKIE", "BBHUNT_BEARER", "BBHUNT_API_KEY", "BBHUNT_SESSION_ID"
            }
        },
    }), encoding="utf-8")
    pool.shutdown()
""",
    )
    _write(
        root / "lib" / "Controller.py",
        f"PAGE_DELAY = {page_delay!r}\n" + """import json
import time
from pathlib import Path

class Project:
    def __init__(self, url, options):
        self.url = url
        self.options = options

    def parseStart(self):
        time.sleep(PAGE_DELAY)
        Path("tmp").mkdir(exist_ok=True)
        Path("tmp/page.js").write_text("fetch('/api/page')", encoding="utf-8")
        Path("tmp/page.json").write_text(json.dumps({
            "url": self.url,
            "finder": self.options.finder,
            "browser": self.options.browser,
            "cookie": self.options.cookie,
        }), encoding="utf-8")
""",
    )
    return root


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    (tmp_path / "recon").mkdir()
    (tmp_path / "findings").mkdir()
    return tmp_path


def _raw_published_path(repo_root: Path, result: dict, suffix: str) -> Path:
    return next(
        repo_root / item
        for item in result["published_artifacts"]
        if item.endswith(suffix)
    )


def test_select_bundle_urls_prefers_runtime_and_preserves_source_file(
    tmp_path: Path,
) -> None:
    candidates = tmp_path / "deep_candidates.txt"
    original = (
        "https://www.example.test/static/auth.js\n"
        "https://www.example.test/static/runtime-abcd.js\n"
        "https://cdn.invalid/vendor.js\n"
    )
    candidates.write_text(original, encoding="utf-8")

    selected = select_bundle_urls("example.test", candidates, max_bundles=2)

    assert selected == [
        "https://www.example.test/static/runtime-abcd.js",
        "https://www.example.test/static/auth.js",
    ]
    assert candidates.read_text(encoding="utf-8") == original


def test_explicit_out_of_scope_bundle_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outside target scope"):
        select_bundle_urls(
            "example.test",
            tmp_path / "missing.txt",
            explicit_urls=["https://outside.invalid/app.js"],
        )


def test_recovered_artifacts_dedupe_random_packer_prefixes_by_content(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write(first / "tmp" / "Ab12Cd.runtime.js", "const runtime = true;\n")
    _write(second / "tmp" / "Zy98Xw.runtime.js", "const runtime = true;\n")

    first_created, first_reused, first_raw, _ = _copy_recovered_artifacts(first, output)
    second_created, second_reused, second_raw, published = _copy_recovered_artifacts(
        second, output
    )

    assert (first_created, first_reused, first_raw) == (1, 0, 0)
    assert (second_created, second_reused, second_raw) == (0, 1, 0)
    assert len(list((output / "files").glob("*.js"))) == 1
    assert Path(published[0]).name.endswith("_runtime.js")


def test_rate_limited_session_rejects_out_of_scope_source_map() -> None:
    class Session:
        def get(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("out-of-scope URL reached upstream session")

    session = _RateLimitedSession(Session(), _RateLimiter(5), "example.test")
    with pytest.raises(PermissionError, match="outside target scope"):
        session.get("https://outside.invalid/app.js.map")


def test_browser_route_aborts_out_of_scope_and_limits_target_requests() -> None:
    class Limiter:
        calls = 0

        def wait(self) -> None:
            self.calls += 1

    class Route:
        aborted = False
        continued = False

        async def abort(self) -> None:
            self.aborted = True

        async def continue_(self) -> None:
            self.continued = True

    class Request:
        def __init__(self, url: str) -> None:
            self.url = url

    limiter = Limiter()
    blocked = Route()
    allowed = Route()
    asyncio.run(
        _guard_browser_route(
            blocked,
            Request("https://outside.invalid/app.js"),
            limiter=limiter,
            target="example.test",
        )
    )
    asyncio.run(
        _guard_browser_route(
            allowed,
            Request("https://app.example.test/app.js"),
            limiter=limiter,
            target="example.test",
        )
    )

    assert blocked.aborted is True
    assert blocked.continued is False
    assert allowed.continued is True
    assert limiter.calls == 1


def test_browser_guard_blocks_service_workers_and_records_navigation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {}

    class Browser:
        async def new_context(self, **kwargs: object) -> object:
            calls["context_options"] = kwargs
            return Context()

    class Context:
        async def route(self, pattern: str, _handler: object) -> None:
            calls["route"] = pattern

    class Page:
        async def goto(self, url: str) -> str:
            calls["url"] = url
            return "response"

    async_api = ModuleType("playwright.async_api")
    async_api.Browser = Browser
    async_api.Page = Page
    playwright = ModuleType("playwright")
    playwright.async_api = async_api
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)

    status_path = tmp_path / "browser-status.json"
    _install_browser_request_guard(_RateLimiter(5), "example.test", status_path)
    context = asyncio.run(Browser().new_context(service_workers="allow"))
    response = asyncio.run(Page().goto("https://app.example.test/"))

    assert context.__class__ is Context
    assert response == "response"
    assert calls["context_options"] == {"service_workers": "block"}
    assert calls["route"] == "**/*"
    assert json.loads(status_path.read_text(encoding="utf-8")) == {
        "failure_summary": "",
        "status": "ok",
    }


def test_recovered_module_sources_feed_js_reader(repo_root: Path, tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    _write(work_dir / "tmp" / "chunk.mjs", "export const route = '/api/module';\n")

    recovered, reused, _raw, _published = _copy_recovered_artifacts(
        work_dir,
        repo_root / "recon" / "example.test" / "js_dump" / "packer",
    )
    materials = prepare_materials("example.test", repo_root=repo_root)
    selected = json.loads(Path(materials["artifacts"]["materials"]).read_text())[
        "selected_js_files"
    ]

    assert (recovered, reused) == (1, 0)
    assert any(item["path"].endswith("_chunk.mjs") for item in selected)


def test_bundle_worker_is_scoped_bounded_and_feeds_js_reader(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool_root = _fake_packer(tmp_path / "packer")
    for key in (
        "BBHUNT_COOKIE",
        "BBHUNT_BEARER",
        "BBHUNT_API_KEY",
        "BBHUNT_SESSION_ID",
        "BBHUNT_AUTH_HEADER",
        "BBHUNT_AUTH_HEADERS",
        "BBHUNT_AUTH_TARGET",
        "BBHUNT_AUTH_ORIGINS",
    ):
        monkeypatch.setenv(key, "must-not-reach-worker")
    _write(
        repo_root / "recon" / "example.test" / "js_dump" / "runtime.js", "// evidence\n"
    )
    result = run_packer(
        "example.test",
        mode="bundle",
        signal_name="webpack-runtime",
        evidence_ref="recon/example.test/js_dump/runtime.js",
        explicit_urls=["https://app.example.test/static/runtime.js"],
        tool_root=str(tool_root),
        repo_root=repo_root,
    )

    assert result["status"] == "ok"
    assert result["recovered_files"] >= 1
    worker = json.loads(
        _raw_published_path(repo_root, result, "worker.json").read_text(
            encoding="utf-8"
        )
    )
    assert worker == {
        "workers": 5,
        "proxy_called": False,
        "session_wrapper": "_RateLimitedSession",
        "in_scope": True,
        "out_of_scope": False,
        "auth_env": {},
    }
    manifest = json.loads(
        (
            repo_root
            / "recon"
            / "example.test"
            / "js_dump"
            / "packer"
            / "manifest.json"
        ).read_text()
    )
    assert manifest["status"] == "ok"

    materials = prepare_materials("example.test", repo_root=repo_root)
    selected = [
        item["path"]
        for item in json.loads(Path(materials["artifacts"]["materials"]).read_text())[
            "selected_js_files"
        ]
    ]
    assert any(path.endswith("recovered.js") for path in selected)


def test_bundle_worker_without_recovered_source_stays_partial(
    repo_root: Path, tmp_path: Path
) -> None:
    _write(
        repo_root / "recon" / "example.test" / "js_dump" / "runtime.js", "// evidence\n"
    )

    result = run_packer(
        "example.test",
        mode="bundle",
        signal_name="webpack-runtime",
        evidence_ref="recon/example.test/js_dump/runtime.js",
        explicit_urls=["https://app.example.test/static/runtime.js"],
        tool_root=str(_fake_packer(tmp_path / "packer", include_js=False)),
        repo_root=repo_root,
    )

    assert result["status"] == "partial"
    assert result["recovered_files"] == 0
    assert result["reused_files"] == 0
    assert (
        result["failure_summary"]
        == "Packer worker completed without recovered source files"
    )


def test_page_mode_reports_browser_fallback_without_credentials(
    repo_root: Path, tmp_path: Path
) -> None:
    _write(repo_root / "recon" / "example.test" / "browser" / "network.jsonl", "{}\n")
    result = run_packer(
        "example.test",
        mode="page",
        signal_name="dynamic-import",
        evidence_ref="recon/example.test/browser/network.jsonl",
        explicit_urls=["https://app.example.test/dashboard"],
        browser=True,
        tool_root=str(_fake_packer(tmp_path / "packer")),
        repo_root=repo_root,
    )

    assert result["status"] == "partial"
    assert result["browser_requested"] is True
    assert result["browser_status"] == "error"
    assert result["browser_failure_summary"] == "browser stage did not complete"
    page = json.loads(
        _raw_published_path(repo_root, result, "page.json").read_text(encoding="utf-8")
    )
    assert page == {
        "url": "https://app.example.test/dashboard",
        "finder": True,
        "browser": True,
        "cookie": None,
    }


def test_page_worker_timeout_is_published(repo_root: Path, tmp_path: Path) -> None:
    _write(repo_root / "evidence.json", "{}\n")

    result = run_packer(
        "example.test",
        mode="page",
        signal_name="dynamic-import",
        evidence_ref="evidence.json",
        explicit_urls=["https://app.example.test/dashboard"],
        timeout=1,
        tool_root=str(_fake_packer(tmp_path / "packer", page_delay=3)),
        repo_root=repo_root,
    )

    assert result["status"] == "error"
    assert result["failure_summary"] == "worker timed out after 1s"


def test_page_worker_workspace_budget_is_published(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(repo_root / "evidence.json", "{}\n")
    monkeypatch.setattr(deep_js_packer, "DEFAULT_MAX_WORKSPACE_FILES", 1)

    result = run_packer(
        "example.test",
        mode="page",
        signal_name="dynamic-import",
        evidence_ref="evidence.json",
        explicit_urls=["https://app.example.test/dashboard"],
        tool_root=str(_fake_packer(tmp_path / "packer", page_delay=3)),
        repo_root=repo_root,
    )

    assert result["status"] == "error"
    assert result["failure_summary"].startswith("worker reached workspace budget")


def test_missing_tool_is_explicit_unavailable_and_keeps_candidates(
    repo_root: Path,
) -> None:
    candidates = repo_root / "recon" / "example.test" / "js" / "deep_candidates.txt"
    _write(candidates, "https://app.example.test/static/runtime.js\n")
    _write(
        repo_root / "recon" / "example.test" / "js_dump" / "runtime.js", "// evidence\n"
    )

    result = run_packer(
        "example.test",
        mode="bundle",
        signal_name="chunk-map",
        evidence_ref="recon/example.test/js_dump/runtime.js",
        tool_root=str(repo_root / "missing-packer"),
        repo_root=repo_root,
    )

    assert result["status"] == "unavailable"
    assert (
        candidates.read_text(encoding="utf-8")
        == "https://app.example.test/static/runtime.js\n"
    )
    manifest = json.loads(
        (
            repo_root
            / "recon"
            / "example.test"
            / "js_dump"
            / "packer"
            / "manifest.json"
        ).read_text()
    )
    assert (
        manifest["failure_summary"] == "Packer-InfoFinder installation is unavailable"
    )


def test_page_mode_requires_single_entry_url(repo_root: Path) -> None:
    _write(repo_root / "recon" / "example.test" / "js_dump" / "app.js", "// evidence\n")
    with pytest.raises(ValueError, match="exactly one --url"):
        run_packer(
            "example.test",
            mode="page",
            signal_name="source-map",
            evidence_ref="recon/example.test/js_dump/app.js",
            explicit_urls=[],
            repo_root=repo_root,
        )


@pytest.mark.parametrize("evidence_ref", ["missing.json", "../outside.json"])
def test_evidence_ref_must_exist_inside_repo(
    repo_root: Path, evidence_ref: str
) -> None:
    with pytest.raises(ValueError, match="evidence_ref"):
        run_packer(
            "example.test",
            mode="bundle",
            signal_name="source-map",
            evidence_ref=evidence_ref,
            explicit_urls=["https://example.test/app.js"],
            repo_root=repo_root,
        )


def test_browser_flag_is_page_only(repo_root: Path) -> None:
    _write(repo_root / "evidence.json", "{}\n")
    with pytest.raises(ValueError, match="only valid in page mode"):
        run_packer(
            "example.test",
            mode="bundle",
            signal_name="dynamic-import",
            evidence_ref="evidence.json",
            explicit_urls=["https://example.test/app.js"],
            browser=True,
            repo_root=repo_root,
        )


def test_autopilot_routes_packer_only_from_concrete_js_evidence() -> None:
    root = Path(__file__).resolve().parents[1]
    command = (root / "commands" / "autopilot.md").read_text(encoding="utf-8")
    agent = (root / "agents" / "autopilot.md").read_text(encoding="utf-8")
    js_read = (root / "commands" / "js-read.md").read_text(encoding="utf-8")

    for text in (command, agent, js_read):
        assert "deep_js_packer.py" in text
        assert "partial/unavailable" in text
    assert "JS volume" in command
    assert "JS count alone is not a trigger" in agent
    assert "Do not run Packer-InfoFinder merely because JS files" in js_read
