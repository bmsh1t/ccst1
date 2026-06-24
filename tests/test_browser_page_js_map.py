"""Tests for tools/browser_surface.py per-page JS map (PR-19).

Covers `build_page_js_map` aggregation, `load_page_js_map` defaults, and
the `_is_js_request` heuristic that gates which requests become JS edges.
"""

from __future__ import annotations

import json
from pathlib import Path

import browser_surface


# ─── Fixtures ───────────────────────────────────────────────────────────────
def _seed_capture(
    evidence_root: Path,
    target_key: str,
    *,
    label: str,
    page_url: str,
    captured_at: str,
    requests: list[dict],
) -> Path:
    """Create one fake capture dir with summary.json + requests.json."""
    cap_dir = evidence_root / target_key / "browser" / label
    cap_dir.mkdir(parents=True, exist_ok=True)
    requests_path = cap_dir / "requests.json"
    requests_path.write_text(json.dumps(requests), encoding="utf-8")
    summary = {
        "url": page_url,
        "captured_at": captured_at,
        "artifacts": {"requests_json": str(requests_path)},
    }
    (cap_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    return cap_dir


# ─── _is_js_request heuristic ──────────────────────────────────────────────
class TestIsJsRequest:
    """Primary signal: resource_type='script'. Fallback: URL extension.
    Must NOT flag CSS/images/fonts/JSON or substrings like '/jspath/'."""

    def test_resource_type_script(self):
        assert browser_surface._is_js_request(
            {"resource_type": "script", "url": "/anything"}
        )

    def test_extension_js(self):
        assert browser_surface._is_js_request(
            {"url": "https://x.com/static/app.js"}
        )

    def test_extension_mjs(self):
        assert browser_surface._is_js_request(
            {"url": "https://x.com/main.mjs"}
        )

    def test_extension_cjs(self):
        assert browser_surface._is_js_request(
            {"url": "https://x.com/index.cjs"}
        )

    def test_cache_buster(self):
        assert browser_surface._is_js_request(
            {"url": "https://x.com/static/app.js?v=12345"}
        )

    def test_excludes_css(self):
        assert not browser_surface._is_js_request(
            {"url": "https://x.com/style.css"}
        )

    def test_excludes_image(self):
        assert not browser_surface._is_js_request(
            {"url": "https://x.com/logo.png"}
        )

    def test_excludes_font(self):
        assert not browser_surface._is_js_request(
            {"url": "https://x.com/inter.woff2"}
        )

    def test_excludes_json(self):
        assert not browser_surface._is_js_request(
            {"url": "https://x.com/api/data.json"}
        )

    def test_does_not_flag_substring_match(self):
        """`/api/jspatch/` contains 'js' but is not a JS asset — must not
        trigger the extension heuristic."""
        assert not browser_surface._is_js_request(
            {"url": "https://x.com/api/jspatch/health"}
        )

    def test_empty_url(self):
        assert not browser_surface._is_js_request({"url": ""})

    def test_non_dict(self):
        assert not browser_surface._is_js_request("not-a-dict")

    def test_resource_type_overrides_extension(self):
        """Even when extension doesn't match, resource_type=script wins."""
        assert browser_surface._is_js_request(
            {"resource_type": "script", "url": "https://x.com/no-ext"}
        )


# ─── build_page_js_map ─────────────────────────────────────────────────────
class TestBuildPageJsMap:
    def test_empty_evidence_returns_empty_map(self, tmp_path):
        """AC2: target with no captures yet — no crash, well-formed empty map."""
        m = browser_surface.build_page_js_map(
            evidence_root=tmp_path / "evidence",
            recon_root=tmp_path / "recon",
            target_key="ghost.com",
        )
        assert m["pages"] == {}
        assert m["js_index"] == {}
        # Map persisted to disk regardless of content
        out = tmp_path / "recon" / "ghost.com" / "browser" / "page_js_map.json"
        assert out.is_file()

    def test_two_captures_two_pages(self, tmp_path):
        """AC3: /blog loads two JS files; /catalog loads one JS file. Both
        forward (pages) and reverse (js_index) lookups must populate."""
        evidence = tmp_path / "evidence"
        _seed_capture(
            evidence,
            "shop.com",
            label="20260515T100000Z-blog",
            page_url="https://shop.com/blog",
            captured_at="2026-05-15T10:00:00Z",
            requests=[
                {"resource_type": "script", "url": "https://shop.com/static/searchLogger.js"},
                {"resource_type": "script", "url": "https://shop.com/static/deparam.js"},
                {"resource_type": "stylesheet", "url": "https://shop.com/style.css"},
            ],
        )
        _seed_capture(
            evidence,
            "shop.com",
            label="20260515T101000Z-catalog",
            page_url="https://shop.com/catalog",
            captured_at="2026-05-15T10:10:00Z",
            requests=[
                {"resource_type": "script", "url": "https://shop.com/static/bundle.js"},
                {"resource_type": "image", "url": "https://shop.com/logo.png"},
            ],
        )

        m = browser_surface.build_page_js_map(
            evidence_root=evidence,
            recon_root=tmp_path / "recon",
            target_key="shop.com",
        )

        assert set(m["pages"]) == {
            "https://shop.com/blog",
            "https://shop.com/catalog",
        }
        assert m["pages"]["https://shop.com/blog"]["js_files"] == [
            "https://shop.com/static/searchLogger.js",
            "https://shop.com/static/deparam.js",
        ]
        assert m["pages"]["https://shop.com/catalog"]["js_files"] == [
            "https://shop.com/static/bundle.js",
        ]
        # Reverse lookup
        assert m["js_index"]["https://shop.com/static/searchLogger.js"] == [
            "https://shop.com/blog",
        ]
        assert m["js_index"]["https://shop.com/static/bundle.js"] == [
            "https://shop.com/catalog",
        ]
        # Persisted to disk
        out = tmp_path / "recon" / "shop.com" / "browser" / "page_js_map.json"
        loaded = json.loads(out.read_text())
        assert loaded["pages"] == m["pages"]

    def test_recapture_accumulates_history(self, tmp_path):
        """AC4: re-capturing /blog must extend capture_dirs (length 2) and
        union JS sets; never lose history from the first visit."""
        evidence = tmp_path / "evidence"
        cap1 = _seed_capture(
            evidence,
            "shop.com",
            label="20260515T100000Z-blog",
            page_url="https://shop.com/blog",
            captured_at="2026-05-15T10:00:00Z",
            requests=[
                {"resource_type": "script", "url": "https://shop.com/searchLogger.js"},
            ],
        )
        cap2 = _seed_capture(
            evidence,
            "shop.com",
            label="20260515T120000Z-blog",
            page_url="https://shop.com/blog",
            captured_at="2026-05-15T12:00:00Z",
            requests=[
                {"resource_type": "script", "url": "https://shop.com/searchLogger.js"},
                {"resource_type": "script", "url": "https://shop.com/extra.js"},
            ],
        )
        m = browser_surface.build_page_js_map(
            evidence_root=evidence,
            recon_root=tmp_path / "recon",
            target_key="shop.com",
        )
        entry = m["pages"]["https://shop.com/blog"]
        assert len(entry["capture_dirs"]) == 2
        assert str(cap1) in entry["capture_dirs"]
        assert str(cap2) in entry["capture_dirs"]
        # Union of JS files (order: first-seen)
        assert entry["js_files"] == [
            "https://shop.com/searchLogger.js",
            "https://shop.com/extra.js",
        ]
        # Latest captured_at wins
        assert entry["captured_at"] == "2026-05-15T12:00:00Z"

    def test_excludes_non_js_resources(self, tmp_path):
        """AC5: a capture with images/CSS/fonts/JSON/JS — only the JS shows
        up in the page's js_files list."""
        evidence = tmp_path / "evidence"
        _seed_capture(
            evidence,
            "shop.com",
            label="20260515T100000Z-app",
            page_url="https://shop.com/app",
            captured_at="2026-05-15T10:00:00Z",
            requests=[
                {"resource_type": "image", "url": "https://shop.com/img.png"},
                {"resource_type": "stylesheet", "url": "https://shop.com/style.css"},
                {"resource_type": "fetch", "url": "https://shop.com/api/data.json"},
                {"resource_type": "font", "url": "https://shop.com/font.woff2"},
                {"resource_type": "script", "url": "https://shop.com/app.js"},
            ],
        )
        m = browser_surface.build_page_js_map(
            evidence_root=evidence,
            recon_root=tmp_path / "recon",
            target_key="shop.com",
        )
        assert m["pages"]["https://shop.com/app"]["js_files"] == [
            "https://shop.com/app.js",
        ]

    def test_captures_without_url_are_skipped(self, tmp_path):
        """A summary with empty url field is unusable as a graph node —
        skip without raising."""
        evidence = tmp_path / "evidence"
        cap_dir = evidence / "shop.com" / "browser" / "20260515T100000Z-broken"
        cap_dir.mkdir(parents=True)
        (cap_dir / "summary.json").write_text(
            json.dumps({"url": "", "captured_at": "2026-05-15T10:00:00Z"}),
            encoding="utf-8",
        )
        (cap_dir / "requests.json").write_text(
            json.dumps([{"resource_type": "script", "url": "https://shop.com/x.js"}]),
            encoding="utf-8",
        )
        m = browser_surface.build_page_js_map(
            evidence_root=evidence,
            recon_root=tmp_path / "recon",
            target_key="shop.com",
        )
        assert m["pages"] == {}

    def test_load_page_js_map_returns_empty_when_missing(self, tmp_path):
        """Surface ranking calls this on every load — must never raise."""
        m = browser_surface.load_page_js_map(tmp_path / "recon", "ghost.com")
        assert m == {"pages": {}, "js_index": {}}

    def test_load_page_js_map_reads_persisted(self, tmp_path):
        evidence = tmp_path / "evidence"
        _seed_capture(
            evidence,
            "shop.com",
            label="20260515T100000Z-x",
            page_url="https://shop.com/x",
            captured_at="2026-05-15T10:00:00Z",
            requests=[{"resource_type": "script", "url": "https://shop.com/x.js"}],
        )
        browser_surface.build_page_js_map(
            evidence_root=evidence,
            recon_root=tmp_path / "recon",
            target_key="shop.com",
        )
        loaded = browser_surface.load_page_js_map(tmp_path / "recon", "shop.com")
        assert "https://shop.com/x" in loaded["pages"]
        assert loaded["js_index"]["https://shop.com/x.js"] == ["https://shop.com/x"]
