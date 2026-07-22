"""Intel v2 远端来源、缓存与批量富化回归。"""

import json
import threading
import time
from datetime import datetime, timedelta, timezone

from tools import intel_sources


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _component(name="next.js", version="15.2.1"):
    return {
        "name": name,
        "display_name": name,
        "version": version,
        "host": "app.target.test",
        "url": "https://app.target.test",
    }


def test_component_queries_preserve_hosts_and_resolve_package():
    queries = intel_sources.build_component_queries([
        _component(),
        {**_component(), "host": "api.target.test", "url": "https://api.target.test"},
    ])
    assert queries == [{
        "name": "next.js",
        "display_name": "next.js",
        "version": "15.2.1",
        "hosts": ["app.target.test", "api.target.test"],
        "urls": ["https://app.target.test", "https://api.target.test"],
        "package": "next",
        "osv_ecosystem": "npm",
        "github_ecosystem": "npm",
        "nvd_keyword": "Next.js",
    }]


def test_unknown_versioned_component_gets_nvd_fallback_without_fake_package_mapping():
    queries = intel_sources.build_component_queries([
        _component(name="New Product", version="3.4.5"),
    ])

    assert queries[0]["nvd_keyword"] == "New Product"
    assert "package" not in queries[0]
    assert "osv_ecosystem" not in queries[0]


def test_network_service_uses_cpe_and_unknown_port_is_not_queryable(tmp_path):
    service = {
        "name": "openssh",
        "display_name": "OpenSSH",
        "version": "9.1",
        "host": "svc.target.test",
        "kind": "network_service",
        "port": 22,
        "protocol": "tcp",
        "cpe": "cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*",
    }
    unknown = {
        "name": "redis",
        "display_name": "redis",
        "version": "",
        "host": "svc.target.test",
        "kind": "unknown_service",
        "port": 6379,
        "protocol": "tcp",
    }
    queries = intel_sources.build_component_queries([service, unknown])
    assert len(queries) == 1
    assert queries[0]["name"] == "openssh"
    assert queries[0]["ports"] == [22]
    assert queries[0]["nvd_cpe"].startswith("cpe:2.3:a:openbsd:openssh:9.1")

    urls = []
    result = intel_sources.fetch_nvd_for_components(
        [service, unknown],
        tmp_path,
        fetcher=lambda url, **_kwargs: urls.append(url) or {"vulnerabilities": []},
        now=NOW,
    )
    assert result["status"] == "ok"
    assert len(urls) == 1
    assert "cpeName=" in urls[0]
    assert "6379" not in urls[0]


def test_osv_exact_version_is_affected_and_cached(tmp_path):
    calls = []

    def fetcher(url, **kwargs):
        calls.append((url, kwargs))
        return {"vulns": [{
            "id": "GHSA-test-0001",
            "aliases": ["CVE-2026-0001"],
            "summary": "Middleware bypass",
            "published": "2026-07-18T00:00:00Z",
            "modified": "2026-07-19T00:00:00Z",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "15.2.2"}]}]
            }],
            "references": [{"url": "https://github.com/advisories/GHSA-test-0001"}],
        }]}

    first = intel_sources.fetch_osv_for_components([_component()], tmp_path, fetcher=fetcher, now=NOW)
    second = intel_sources.fetch_osv_for_components([_component()], tmp_path, fetcher=fetcher, now=NOW)

    assert first["status"] == "ok"
    assert first["items"][0]["applicability"] == "affected"
    assert first["items"][0]["fixed_versions"] == ["15.2.2"]
    assert first["items"][0]["aliases"] == ["GHSA-test-0001", "CVE-2026-0001"]
    assert first["items"][0]["poc_available"] is False
    assert second["cached"] is True
    assert second["fetched_at"] == first["fetched_at"]
    assert len(calls) == 1


def test_poc_signal_requires_explicit_reference_shape():
    assert intel_sources._reference_has_poc_signal(
        "https://github.com/example/security-poc"
    ) is True
    assert intel_sources._reference_has_poc_signal(
        "https://github.com/example/project/commit/abc123"
    ) is False
    assert intel_sources._reference_has_poc_signal(
        "https://github.com/advisories/GHSA-test-0001"
    ) is False


def test_osv_without_exact_package_version_is_unavailable(tmp_path):
    result = intel_sources.fetch_osv_for_components(
        [_component(name="wordpress", version="")],
        tmp_path,
        fetcher=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not fetch")),
        now=NOW,
    )
    assert result["status"] == "unavailable"
    assert result["items"] == []


def test_source_partial_failure_keeps_successful_items(tmp_path):
    def fetcher(url, **kwargs):
        body = kwargs.get("body") or {}
        package = (body.get("package") or {}).get("name")
        if package == "next":
            return {"vulns": [{"id": "CVE-2026-0002", "summary": "A"}]}
        raise intel_sources.IntelSourceError("rate limited")

    result = intel_sources.fetch_osv_for_components(
        [_component(), _component(name="django", version="5.1.2")],
        tmp_path,
        fetcher=fetcher,
        now=NOW,
    )
    assert result["status"] == "partial"
    assert [item["id"] for item in result["items"]] == ["CVE-2026-0002"]
    assert result["stats"]["error_count"] == 1


def test_successful_empty_query_plus_failure_is_partial_not_error(tmp_path):
    def fetcher(url, **kwargs):
        body = kwargs.get("body") or {}
        package = (body.get("package") or {}).get("name")
        if package == "next":
            return {"vulns": []}
        raise intel_sources.IntelSourceError("rate limited")

    result = intel_sources.fetch_osv_for_components(
        [_component(), _component(name="django", version="5.1.2")],
        tmp_path,
        fetcher=fetcher,
        now=NOW,
    )

    assert result["status"] == "partial"
    assert result["items"] == []
    assert result["stats"]["attempted_queries"] == 2


def test_osv_and_github_component_requests_are_bounded_concurrent_and_ordered(tmp_path):
    components = [
        _component(name=name, version="1.0")
        for name in ("next.js", "django", "flask", "react", "express")
    ]

    def run(source):
        lock = threading.Lock()
        active = 0
        peak = 0

        def fetcher(url, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.03)
                if source == "osv":
                    package = kwargs["body"]["package"]["name"]
                    return {"vulns": [{"id": f"OSV-{package}"}]}
                affects = intel_sources.urllib.parse.parse_qs(
                    intel_sources.urllib.parse.urlparse(url).query
                )["affects"][0]
                package = affects.split("@", 1)[0]
                return [{"ghsa_id": f"GHSA-{package}"}]
            finally:
                with lock:
                    active -= 1

        if source == "osv":
            result = intel_sources.fetch_osv_for_components(
                components,
                tmp_path / source,
                fetcher=fetcher,
                now=NOW,
                max_workers=2,
            )
        else:
            result = intel_sources.fetch_github_advisories_for_components(
                components,
                tmp_path / source,
                fetcher=fetcher,
                now=NOW,
                max_workers=2,
            )
        return result, peak

    osv, osv_peak = run("osv")
    github, github_peak = run("github")

    assert 1 < osv_peak <= 2
    assert 1 < github_peak <= 2
    assert [item["component"]["name"] for item in osv["items"]] == [
        "next.js", "django", "flask", "react", "express",
    ]
    assert [item["component"]["name"] for item in github["items"]] == [
        "next.js", "django", "flask", "react", "express",
    ]


def test_bad_response_shape_is_source_error_and_not_cached(tmp_path):
    result = intel_sources.fetch_osv_for_components(
        [_component()],
        tmp_path,
        fetcher=lambda *_args, **_kwargs: [],
        now=NOW,
    )

    assert result["status"] == "error"
    assert "JSON object" in result["error"]
    assert not list((tmp_path / "state" / "intel-cache" / "osv").glob("*.json"))


def test_corrupt_cache_is_replaced_by_fresh_response(tmp_path):
    query = {"catalog": "cisa-kev"}
    path = intel_sources._cache_path(tmp_path, "kev", query)
    path.parent.mkdir(parents=True)
    path.write_text("not-json", encoding="utf-8")

    result = intel_sources.fetch_kev(
        tmp_path,
        fetcher=lambda *_args, **_kwargs: {
            "catalogVersion": "2026.07.19",
            "vulnerabilities": [{"cveID": "CVE-2026-0003", "dateAdded": "2026-07-19"}],
        },
        now=NOW,
    )
    assert result["status"] == "ok"
    assert "CVE-2026-0003" in result["items"]
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1


def test_semantically_invalid_cache_is_refetched(tmp_path):
    query = {"catalog": "cisa-kev"}
    path = intel_sources._cache_path(tmp_path, "kev", query)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "source": "kev",
        "query": query,
        "fetched_at": "2026-07-19T12:00:00Z",
        "expires_at": "2026-07-19T18:00:00Z",
        "data": [],
    }), encoding="utf-8")
    calls = []

    result = intel_sources.fetch_kev(
        tmp_path,
        fetcher=lambda *_args, **_kwargs: calls.append(1) or {"vulnerabilities": []},
        now=NOW,
    )

    assert result["status"] == "ok"
    assert calls == [1]
    assert isinstance(json.loads(path.read_text(encoding="utf-8"))["data"], dict)


def test_stale_cache_is_used_explicitly_when_refresh_fails(tmp_path):
    query = {"catalog": "cisa-kev"}
    path = intel_sources._cache_path(tmp_path, "kev", query)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "source": "kev",
        "query": query,
        "fetched_at": "2026-07-18T00:00:00Z",
        "expires_at": "2026-07-18T06:00:00Z",
        "data": {"vulnerabilities": [{"cveID": "CVE-2026-0004"}]},
    }), encoding="utf-8")

    result = intel_sources.fetch_kev(
        tmp_path,
        fetcher=lambda *_args, **_kwargs: (_ for _ in ()).throw(intel_sources.IntelSourceError("offline")),
        ttl_seconds=60,
        now=NOW,
    )
    assert result["status"] == "partial"
    assert result["stale"] is True
    assert result["fetched_at"] == "2026-07-18T00:00:00Z"
    assert result["error"] == "offline"
    assert "CVE-2026-0004" in result["items"]


def test_epss_batches_and_normalizes_scores(tmp_path, monkeypatch):
    monkeypatch.setattr(intel_sources, "EPSS_BATCH_SIZE", 2)
    urls = []

    def fetcher(url, **_kwargs):
        urls.append(url)
        query = url.split("cve=", 1)[1]
        cves = query.replace("%2C", ",").split(",")
        return {"data": [
            {"cve": cve, "epss": "0.75", "percentile": "0.98", "date": "2026-07-19"}
            for cve in cves
        ]}

    result = intel_sources.fetch_epss(
        ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
        tmp_path,
        fetcher=fetcher,
        now=NOW,
    )
    assert result["status"] == "ok"
    assert result["stats"] == {"item_count": 3, "batch_count": 2}
    assert result["items"]["CVE-2026-0001"]["score"] == 0.75
    assert len(urls) == 2


def test_epss_empty_success_plus_failed_batch_is_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(intel_sources, "EPSS_BATCH_SIZE", 1)

    def fetcher(url, **_kwargs):
        if "CVE-2026-0001" in url:
            return {"data": []}
        raise intel_sources.IntelSourceError("offline")

    result = intel_sources.fetch_epss(
        ["CVE-2026-0001", "CVE-2026-0002"],
        tmp_path,
        fetcher=fetcher,
        now=NOW,
    )

    assert result["status"] == "partial"
    assert result["items"] == {}


def test_github_and_nvd_projection_keep_applicability_distinction(tmp_path):
    def fetcher(url, **_kwargs):
        if "api.github.com" in url:
            return [{
                "ghsa_id": "GHSA-test-0005",
                "cve_id": "CVE-2026-0005",
                "severity": "critical",
                "summary": "Exact package advisory",
                "published_at": "2026-07-18T00:00:00Z",
                "updated_at": "2026-07-19T00:00:00Z",
                "cvss": {"score": 9.8},
                "identifiers": [
                    {"type": "GHSA", "value": "GHSA-test-0005"},
                    {"type": "CVE", "value": "CVE-2026-0005"},
                ],
                "vulnerabilities": [{
                    "vulnerable_version_range": "< 15.2.2",
                    "first_patched_version": {"identifier": "15.2.2"},
                }],
                "html_url": "https://github.com/advisories/GHSA-test-0005",
                "references": ["https://github.com/example/security-poc"],
            }]
        return {"vulnerabilities": [{
            "cve": {
                "id": "CVE-2026-0006",
                "published": "2026-07-17T00:00:00Z",
                "lastModified": "2026-07-18T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "Keyword match only"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
            }
        }]}

    github = intel_sources.fetch_github_advisories_for_components([_component()], tmp_path, fetcher=fetcher, now=NOW)
    nvd = intel_sources.fetch_nvd_for_components([_component()], tmp_path, fetcher=fetcher, now=NOW)

    assert github["items"][0]["applicability"] == "affected"
    assert github["items"][0]["fixed_versions"] == ["15.2.2"]
    assert github["items"][0]["poc_available"] is True
    assert nvd["items"][0]["applicability"] == "unknown"


def _nvd_wordpress_item(version: str, summary: str):
    return intel_sources._nvd_item(
        {
            "cve": {
                "id": "CVE-2026-63030",
                "descriptions": [{"lang": "en", "value": summary}],
            }
        },
        {
            "name": "wordpress",
            "display_name": "WordPress",
            "version": version,
            "hosts": ["target.test"],
        },
        "2026-07-21T00:00:00Z",
    )


def test_nvd_summary_boundary_marks_observed_branch_affected_or_fixed():
    summary = (
        "WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected "
        "by REST API route confusion."
    )

    affected = _nvd_wordpress_item("6.9.4", summary)
    fixed = _nvd_wordpress_item("6.9.5", summary)
    other_branch = _nvd_wordpress_item("7.0.1", summary)

    assert affected["applicability"] == "affected"
    assert fixed["applicability"] == "not_affected"
    assert other_branch["applicability"] == "affected"
    assert affected["fixed_versions"] == ["6.9.5", "7.0.2"]
    assert [item["branch"] for item in affected["affected_ranges"]] == ["6.9.x", "7.0.x"]


def test_nvd_summary_boundary_keeps_ambiguous_inputs_unknown():
    summary = "WordPress 6.9.x before 6.9.5 is affected."

    assert _nvd_wordpress_item("6.8.9", summary)["applicability"] == "unknown"
    assert _nvd_wordpress_item("6.9.5-beta1", summary)["applicability"] == "unknown"
    unrelated = _nvd_wordpress_item("6.9.4", "AnotherCMS 6.9.x before 6.9.5 is affected.")
    assert unrelated["applicability"] == "unknown"
    assert unrelated["fixed_versions"] == []
    plugin = _nvd_wordpress_item(
        "6.9.4",
        "Example Forms plugin for WordPress 6.9.x before 6.9.5 is affected.",
    )
    assert plugin["applicability"] == "unknown"


def test_nvd_structured_configurations_are_not_overridden_by_summary_parser():
    item = intel_sources._nvd_item(
        {
            "cve": {
                "id": "CVE-2026-0007",
                "descriptions": [{
                    "lang": "en",
                    "value": "WordPress 6.9.x before 6.9.5 is affected.",
                }],
                "configurations": [{"nodes": [{"negate": False}]}],
            }
        },
        {"name": "wordpress", "display_name": "WordPress", "version": "6.9.4"},
        "2026-07-21T00:00:00Z",
    )

    assert item["applicability"] == "unknown"
    assert item["fixed_versions"] == []
    assert item["affected_ranges"] == [{"nodes": [{"negate": False}]}]


def test_github_package_without_observed_version_stays_unknown(tmp_path):
    result = intel_sources.fetch_github_advisories_for_components(
        [_component(version="")],
        tmp_path,
        fetcher=lambda *_args, **_kwargs: [{
            "ghsa_id": "GHSA-test-unknown",
            "severity": "high",
            "summary": "Package advisory without target version proof",
            "vulnerabilities": [{"vulnerable_version_range": "< 99.0.0"}],
        }],
        now=NOW,
    )

    assert result["status"] == "ok"
    assert result["items"][0]["applicability"] == "unknown"


def test_nvd_component_limit_is_explicit_partial_coverage(tmp_path):
    components = [
        _component(name=f"Product {index}", version="1.0")
        for index in range(3)
    ]
    result = intel_sources.fetch_nvd_for_components(
        components,
        tmp_path,
        fetcher=lambda *_args, **_kwargs: {"vulnerabilities": []},
        max_components=2,
        now=NOW,
    )

    assert result["status"] == "partial"
    assert result["stats"]["eligible_queries"] == 3
    assert result["stats"]["attempted_queries"] == 2
    assert "queried 2 of 3" in result["error"]


def test_nvd_fetches_all_reported_pages(tmp_path):
    starts = []

    def fetcher(url, **_kwargs):
        query = intel_sources.urllib.parse.parse_qs(
            intel_sources.urllib.parse.urlparse(url).query
        )
        start = int(query.get("startIndex", ["0"])[0])
        starts.append(start)
        rows = [
            {"cve": {"id": f"CVE-2026-{index:04d}"}}
            for index in range(start + 1, min(start + 2, 3) + 1)
        ]
        return {
            "totalResults": 3,
            "startIndex": start,
            "resultsPerPage": 2,
            "vulnerabilities": rows,
        }

    result = intel_sources.fetch_nvd_for_components(
        [_component(name="Product", version="1.0")],
        tmp_path,
        fetcher=fetcher,
        now=NOW,
    )

    assert starts == [0, 2]
    assert result["status"] == "ok"
    assert [item["id"] for item in result["items"]] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    ]


def test_nvd_paginates_components_round_robin_with_bounded_pages(tmp_path):
    calls = []

    def fetcher(url, **_kwargs):
        query = intel_sources.urllib.parse.parse_qs(
            intel_sources.urllib.parse.urlparse(url).query
        )
        keyword = query["keywordSearch"][0]
        start = int(query["startIndex"][0])
        calls.append((keyword, start, int(query["resultsPerPage"][0])))
        return {
            "totalResults": 2,
            "startIndex": start,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{keyword[-3:]}-{start}"}}],
        }

    result = intel_sources.fetch_nvd_for_components(
        [
            _component(name="Product One", version="1.0"),
            _component(name="Product Two", version="2.0"),
        ],
        tmp_path,
        fetcher=fetcher,
        now=NOW,
    )

    assert calls == [
        ("Product One", 0, 200),
        ("Product Two", 0, 200),
        ("Product One", 1, 200),
        ("Product Two", 1, 200),
    ]
    assert result["status"] == "ok"
    assert result["stats"]["attempted_queries"] == 2


def test_nvd_request_wall_timeout_continues_other_components(tmp_path, monkeypatch):
    monkeypatch.setattr(intel_sources, "DEFAULT_NVD_REQUEST_MAX_SECONDS", 0.05)
    calls = []

    def fetcher(url, **_kwargs):
        query = intel_sources.urllib.parse.parse_qs(
            intel_sources.urllib.parse.urlparse(url).query
        )
        keyword = query["keywordSearch"][0]
        calls.append(keyword)
        if keyword == "Product One":
            time.sleep(0.2)
        return {"vulnerabilities": []}

    started = time.monotonic()
    result = intel_sources.fetch_nvd_for_components(
        [
            _component(name="Product One", version="1.0"),
            _component(name="Product Two", version="2.0"),
        ],
        tmp_path,
        fetcher=fetcher,
        max_seconds=1,
        now=NOW,
    )

    assert time.monotonic() - started < 0.15
    assert calls == ["Product One", "Product Two"]
    assert result["status"] == "partial"
    assert result["stats"]["attempted_queries"] == 2
    assert "request timeout; continuing other components" in result["error"]


def test_nvd_time_budget_preserves_fetched_pages_as_partial(tmp_path, monkeypatch):
    ticks = iter([0.0, 0.0, 121.0])
    monkeypatch.setattr(intel_sources.time, "monotonic", lambda: next(ticks))
    calls = []

    def fetcher(url, **kwargs):
        calls.append((url, kwargs))
        return {
            "totalResults": 2001,
            "startIndex": 0,
            "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}],
        }

    result = intel_sources.fetch_nvd_for_components(
        [_component(name="Product", version="1.0")],
        tmp_path,
        fetcher=fetcher,
        now=NOW,
    )

    assert len(calls) == 1
    assert calls[0][1]["timeout"] == 25.0
    assert result["status"] == "partial"
    assert [item["id"] for item in result["items"]] == ["CVE-2026-0001"]
    assert "time budget exhausted after 120s" in result["error"]


def test_nvd_next_run_reuses_cached_page_and_continues_pagination(tmp_path, monkeypatch):
    calls = []

    def fetcher(url, **_kwargs):
        query = intel_sources.urllib.parse.parse_qs(
            intel_sources.urllib.parse.urlparse(url).query
        )
        start = int(query["startIndex"][0])
        calls.append(start)
        return {
            "totalResults": 2,
            "startIndex": start,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-000{start + 1}"}}],
        }

    first_ticks = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(intel_sources.time, "monotonic", lambda: next(first_ticks))
    first = intel_sources.fetch_nvd_for_components(
        [_component(name="Product", version="1.0")],
        tmp_path,
        fetcher=fetcher,
        max_seconds=1,
        now=NOW,
    )

    second_ticks = iter([10.0, 10.0, 10.0])
    monkeypatch.setattr(intel_sources.time, "monotonic", lambda: next(second_ticks))
    second = intel_sources.fetch_nvd_for_components(
        [_component(name="Product", version="1.0")],
        tmp_path,
        fetcher=fetcher,
        max_seconds=1,
        now=NOW,
    )

    assert first["status"] == "partial"
    assert calls == [0, 1]
    assert second["status"] == "ok"
    assert second["stats"]["cached_queries"] == 1
    assert [item["id"] for item in second["items"]] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]


def test_nvd_api_key_is_request_only(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret-test-key")
    calls = []

    result = intel_sources.fetch_nvd_for_components(
        [_component(name="Product", version="1.0")],
        tmp_path,
        fetcher=lambda url, **kwargs: calls.append((url, kwargs)) or {"vulnerabilities": []},
        now=NOW,
    )

    assert result["status"] == "ok"
    assert calls[0][1]["headers"] == {"apiKey": "secret-test-key"}
    assert "secret-test-key" not in json.dumps(result)
    cache_files = list((tmp_path / "state" / "intel-cache" / "nvd").glob("*.json"))
    assert len(cache_files) == 1
    assert "secret-test-key" not in cache_files[0].read_text(encoding="utf-8")


def test_nvd_rate_limit_stops_remaining_components_as_partial(tmp_path):
    for status_code in (403, 429):
        calls = []

        def fetcher(url, **_kwargs):
            calls.append(url)
            raise intel_sources.IntelSourceError(f"HTTP {status_code} retry-after=30")

        result = intel_sources.fetch_nvd_for_components(
            [
                _component(name="Product One", version="1.0"),
                _component(name="Product Two", version="2.0"),
            ],
            tmp_path / str(status_code),
            fetcher=fetcher,
            now=NOW,
        )

        assert len(calls) == 1
        assert result["status"] == "partial"
        assert result["stats"]["attempted_queries"] == 1
        assert "rate limit stopped remaining queries" in result["error"]


def test_nvd_rate_limit_with_stale_cache_stops_remaining_components(tmp_path):
    first = _component(name="Product One", version="1.0")
    cached = intel_sources.fetch_nvd_for_components(
        [first],
        tmp_path,
        fetcher=lambda _url, **_kwargs: {
            "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}],
        },
        ttl_seconds=1,
        now=NOW,
    )
    assert cached["status"] == "ok"

    calls = []

    def rate_limited(url, **_kwargs):
        calls.append(url)
        raise intel_sources.IntelSourceError("HTTP 429 retry-after=30")

    result = intel_sources.fetch_nvd_for_components(
        [first, _component(name="Product Two", version="2.0")],
        tmp_path,
        fetcher=rate_limited,
        ttl_seconds=1,
        now=NOW + timedelta(seconds=2),
    )

    assert len(calls) == 1
    assert result["status"] == "partial"
    assert result["stale"] is True
    assert result["stats"]["attempted_queries"] == 1
    assert [item["id"] for item in result["items"]] == ["CVE-2026-0001"]
    assert "rate limit stopped remaining queries" in result["error"]


def test_cache_refreshes_after_ttl(tmp_path):
    calls = []

    def fetcher(*_args, **_kwargs):
        calls.append(1)
        return {"vulnerabilities": []}

    intel_sources.fetch_kev(tmp_path, fetcher=fetcher, ttl_seconds=60, now=NOW)
    intel_sources.fetch_kev(tmp_path, fetcher=fetcher, ttl_seconds=60, now=NOW + timedelta(seconds=61))
    assert len(calls) == 2
