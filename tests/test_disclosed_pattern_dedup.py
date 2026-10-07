"""Disclosed research preserves reports without guessing duplicates from legacy memory."""

from __future__ import annotations

import json
from pathlib import Path
import shlex

import pytest

from tools import disclosure_search
from tools.disclosure_search import DisclosedReport, render_disclosed_patterns_md, write_disclosed_patterns
from tools.target_store import TargetStore


def _report(title, index):
    return DisclosedReport(title=title, severity="high", disclosed_at="2026-05-15",
                           url=f"https://reports.example.test/{index}", state="closed",
                           program="fixture", program_name="Fixture")


@pytest.mark.parametrize("legacy", [None, "", "{broken", json.dumps({
    "target": "other.test", "vuln_class": "IDOR", "technique": "PRIVATE_CROSS_TARGET",
    "tech_stack": ["express"],
})])
def test_cached_disclosures_ignore_legacy_patterns_and_keep_every_report(tmp_path, monkeypatch, legacy):
    target = "fixture.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.remember(command_id="note", kind="note", statement="Target-local premise",
                   conditions="unverified", reopen_when="", next_intent="", evidence=[], actor="test")
    before = store.binding()
    legacy_path = tmp_path / "hunt-memory" / "patterns.jsonl"
    if legacy is not None:
        legacy_path.parent.mkdir(parents=True)
        legacy_path.write_text(legacy)
    same = [_report("IDOR in /orders", 1), _report("Unknown boundary in /widgets", 2)]
    similar = [_report("IDOR in /accounts", 3)]
    disclosure_search._save_cache(tmp_path, target, {
        "target": target, "same": [vars(item) for item in same],
        "similar": [vars(item) for item in similar], "coverage_status": "covered",
    })
    monkeypatch.setattr(disclosure_search, "_load_h1_client", lambda: None)
    original_read = Path.read_text

    def reject_legacy(path, *args, **kwargs):
        if path == legacy_path:
            raise AssertionError("disclosed research read legacy target memory")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", reject_legacy)
    output = write_disclosed_patterns(target, repo_root=tmp_path).read_text()
    positions = [output.index(item.url) for item in same + similar]
    assert positions == sorted(positions)
    assert all(item.title in output for item in same + similar)
    assert "Same-target reports: 2 | Similar-target reports: 1" in output
    assert "PRIVATE_CROSS_TARGET" not in output
    assert "[DEDUP:" not in output
    assert "Pattern dedup" not in output
    assert "hypothesis seeds" not in output.lower()
    assert "previously paid" not in output
    assert "industry-recurring" not in output
    command = output.split("```bash\n", 1)[1].split("\n```", 1)[0]
    assert shlex.split(command) == [
        "python3", "tools/experience_recall.py", "--repo-root", str(tmp_path), "--target", target,
    ]
    assert store.binding() == before
    if legacy is not None:
        assert original_read(legacy_path) == legacy


@pytest.mark.parametrize("coverage", ["mcp_unavailable", "no_mcp_coverage", "covered"])
def test_empty_disclosures_keep_distinct_coverage_and_memory_entry(coverage, tmp_path):
    output = render_disclosed_patterns_md("fixture.test", [], [], coverage, repo_root=tmp_path)
    assert f"MCP coverage: {coverage}" in output
    assert "Same-target reports: 0 | Similar-target reports: 0" in output
    assert "tools/experience_recall.py" in output
    assert "[DEDUP:" not in output
    assert "Query status:" not in output
    assert "All executed queries succeeded" not in output


def test_no_mcp_never_loads_a_client_or_reads_target_state(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("--no-mcp attempted network setup or target-state access")

    monkeypatch.setattr(disclosure_search, "_load_h1_client", unexpected)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", unexpected)
    monkeypatch.setattr(disclosure_search, "search_same_target", unexpected)
    monkeypatch.setattr(disclosure_search, "search_similar_targets", unexpected)
    output = write_disclosed_patterns("fresh.test", repo_root=tmp_path, no_mcp=True).read_text()
    assert "MCP coverage: mcp_unavailable" in output
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "hunt-memory").exists()


def test_report_rendering_retains_order_without_category_filtering(tmp_path):
    reports = [_report(f"Custom category {index}", index) for index in range(100)]
    output = render_disclosed_patterns_md("fixture.test", reports, [], repo_root=tmp_path)
    assert [line.split("|")[-2].strip() for line in output.splitlines()
            if line.startswith("| 2026-05-15")] == [report.url for report in reports]


def test_disclosure_queries_and_cached_material_survive_without_title_claims(tmp_path, monkeypatch):
    calls = []
    same = _report("IDOR: repeated title", 41)
    similar = [_report("IDOR: repeated title", 42), _report("IDOR: repeated title", 43)]
    for report in similar:
        report.program = "peer"

    class Client:
        def search_disclosed_reports(self, **kwargs):
            calls.append(kwargs)
            return [vars(same)] if "program" in kwargs else [vars(item) for item in similar]

    monkeypatch.setattr(disclosure_search, "_load_h1_client", Client)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: ["express"])
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    assert calls == [{"program": "fixture", "limit": 15}, {"keyword": "express", "limit": 15}]
    cache_path = disclosure_search._cache_path(tmp_path, "fixture.test")
    original = cache_path.read_bytes()
    cache = json.loads(original)
    assert cache["same"] == [vars(same)]
    assert cache["similar"] == [vars(item) for item in similar]
    assert cache["coverage_status"] == "covered"
    for report in [same, *similar]:
        assert report.url in output and report.title in output
    assert "hypothesis seeds" not in output.lower()
    assert "paid on" not in output and "industry-recurring" not in output
    monkeypatch.setattr(disclosure_search, "_load_h1_client", lambda: None)
    cached_output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    assert "MCP coverage: covered" in cached_output
    assert all(report.url in cached_output for report in [same, *similar])
    assert cache_path.read_bytes() == original
    assert len(calls) == 2


def test_stale_disclosure_cache_refresh_keeps_keyword_fallback(tmp_path, monkeypatch):
    disclosure_search._save_cache(tmp_path, "fixture.test", {
        "target": "fixture.test", "same": [vars(_report("Old report", 1))],
        "similar": [], "coverage_status": "covered",
    })
    cache_path = disclosure_search._cache_path(tmp_path, "fixture.test")
    cache = json.loads(cache_path.read_text())
    cache["cached_at_ts"] = 0
    cache_path.write_text(json.dumps(cache))
    report = _report("Fresh report", 2)
    calls = []

    class Client:
        def search_disclosed_reports(self, **kwargs):
            calls.append(kwargs)
            return [] if "program" in kwargs else [vars(report)]

    monkeypatch.setattr(disclosure_search, "_load_h1_client", Client)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: [])
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    assert calls == [{"program": "fixture", "limit": 15}, {"keyword": "fixture.test", "limit": 15}]
    assert report.url in output and "Old report" not in output
    assert json.loads(cache_path.read_text())["same"] == [vars(report)]


def _old_cache(tmp_path, timestamp=0):
    path = disclosure_search._cache_path(tmp_path, "fixture.test")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "target": "fixture.test", "same": [vars(_report("Old report", 1))],
        "similar": [], "coverage_status": "covered", "cached_at_ts": timestamp,
    }))
    return path


@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("mode", ["total", "client_missing", "partial_report", "partial_empty", "fallback"])
def test_failed_refresh_preserves_success_snapshot(tmp_path, monkeypatch, cached, mode):
    monkeypatch.setattr(disclosure_search.time, "time", lambda: 1_000_000)
    cache = _old_cache(tmp_path) if cached else disclosure_search._cache_path(tmp_path, "fixture.test")
    original = (cache.read_bytes(), cache.stat().st_mtime_ns) if cached else None
    fresh = _report("Fresh report", 2)
    fresh.program = "peer"
    calls = []

    class Client:
        def search_disclosed_reports(self, **kwargs):
            calls.append(kwargs)
            if mode == "fallback" and kwargs.get("keyword") == "fixture.test":
                return [vars(fresh)]
            if mode.startswith("partial") and kwargs.get("keyword") == "express":
                return [vars(fresh)] if mode == "partial_report" else []
            raise RuntimeError("upstream down\n" + "x" * 1000)

    monkeypatch.setattr(disclosure_search, "_load_h1_client", lambda: None if mode == "client_missing" else Client())
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: [] if mode == "fallback" else ["express"])
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    if cached:
        assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original
    else:
        assert not cache.exists()
    partial = mode in {"partial_report", "partial_empty", "fallback"}
    assert f"Query status: {'partial' if partial else 'unavailable'}" in output
    has_fresh = mode in {"partial_report", "fallback"}
    assert ("Fresh report" in output) == has_fresh
    assert ("Old report" in output) == (cached and not has_fresh)
    assert f"Material source: {'live' if has_fresh else 'cache' if cached else 'none'}" in output
    if cached and not has_fresh:
        assert "Material queried at: 1970-01-01 00:00:00 UTC" in output
        assert "Material stale: yes" in output
    if has_fresh:
        assert "MCP coverage: partial" in output
        assert "successful subset only" in output
    if mode != "client_missing":
        assert len(calls) == (2 if mode == "fallback" else 3)
        errors = [line[2:] for line in output.splitlines() if line.startswith("- same")]
        assert errors and all(len(line) <= 500 for line in errors)


@pytest.mark.parametrize("ttl", [72, 0])
def test_complete_empty_refresh_replaces_old_material(tmp_path, monkeypatch, ttl):
    cache = _old_cache(tmp_path, 1_000_000 if ttl == 0 else 0)
    monkeypatch.setattr(disclosure_search.time, "time", lambda: 1_000_000)
    calls = []

    class Client:
        def search_disclosed_reports(self, **kwargs):
            calls.append(kwargs)
            return []

    monkeypatch.setattr(disclosure_search, "_load_h1_client", Client)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: [])
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path, cache_ttl_hours=ttl).read_text()
    assert len(calls) == 2
    assert json.loads(cache.read_text()) == {
        "target": "fixture.test", "same": [], "similar": [],
        "coverage_status": "no_mcp_coverage", "cached_at_ts": 1_000_000,
    }
    assert "Query status: complete" in output
    assert "MCP coverage: no_mcp_coverage" in output
    assert "All executed queries succeeded with zero reports" in output
    assert "Old report" not in output


@pytest.mark.parametrize("timestamp", [999_000, "999000"])
def test_healthy_cache_retains_material_time_without_loading_client(tmp_path, monkeypatch, timestamp):
    cache = _old_cache(tmp_path, timestamp)
    payload = json.loads(cache.read_text())
    del payload["coverage_status"]
    cache.write_text(json.dumps(payload))
    original = cache.read_bytes(), cache.stat().st_mtime_ns
    monkeypatch.setattr(disclosure_search.time, "time", lambda: 1_000_000)

    def unexpected(*args):
        raise AssertionError("fresh cache accessed client or inventory")

    monkeypatch.setattr(disclosure_search, "_load_h1_client", unexpected)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", unexpected)
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original
    assert "Query status: cached" in output and "MCP coverage: covered" in output
    assert "Material queried at: 1970-01-12 13:30:00 UTC" in output
    assert "Generated at: 1970-01-12 13:46:40 UTC" in output
    assert "Material stale: no" in output
    assert "Last updated" not in output


def test_no_mcp_does_not_even_read_existing_cache(tmp_path, monkeypatch):
    cache = _old_cache(tmp_path)
    original = cache.read_bytes(), cache.stat().st_mtime_ns

    def unexpected(*args):
        raise AssertionError("explicit skip performed a read")

    for name in ("_load_cache", "_load_h1_client", "_load_tech_stack_hint"):
        monkeypatch.setattr(disclosure_search, name, unexpected)
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path, no_mcp=True).read_text()
    assert "Query status: skipped" in output and "Material source: none" in output
    assert "Old report" not in output
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original


@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_ttl_is_rejected_without_publishing(tmp_path, monkeypatch, ttl):
    cache = _old_cache(tmp_path)
    original = cache.read_bytes(), cache.stat().st_mtime_ns
    monkeypatch.setattr(disclosure_search, "_load_h1_client", lambda: None)
    with pytest.raises(ValueError, match="cache TTL must be finite"):
        disclosure_search.main([
            "--target", "fixture.test", "--repo-root", str(tmp_path), f"--cache-ttl-hours={ttl}",
        ])
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original
    assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("bad", [None, {}, "", [False], [vars(_report("Discarded request", 3)), []], [{"title": []}]])
def test_malformed_owner_response_does_not_discard_independent_success(tmp_path, monkeypatch, bad):
    cache = _old_cache(tmp_path)
    original = cache.read_bytes(), cache.stat().st_mtime_ns
    monkeypatch.setattr(disclosure_search.time, "time", lambda: 1_000_000)
    report = _report("Healthy request", 2)
    report.program = "peer"
    calls = []

    class Client:
        def search_disclosed_reports(self, **kwargs):
            calls.append(kwargs)
            return [vars(report)] if kwargs.get("keyword") == "healthy" else bad

    monkeypatch.setattr(disclosure_search, "_load_h1_client", Client)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: ["broken", "healthy"])
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    assert len(calls) == 4
    assert "Healthy request" in output
    assert "Discarded request" not in output and "Old report" not in output
    assert "Query status: partial" in output and "ValueError" in output
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original


@pytest.mark.parametrize("bad_cache", [
    b"\xff", b"{broken", b"[]", b"null",
    {"same": None}, {"similar": {}}, {"same": [False]}, {"same": [{"title": []}]},
    {"cached_at_ts": None}, {"cached_at_ts": "bad"}, {"cached_at_ts": "nan"},
    {"cached_at_ts": float("inf")}, {"cached_at_ts": False}, {"target": "foreign.test"},
    {"coverage_status": "mcp_unavailable"},
    {"coverage_status": {}}, {"coverage_status": "partial"}, {"coverage_status": None},
])
def test_bad_cache_is_diagnosed_and_preserved_when_client_unavailable(tmp_path, monkeypatch, bad_cache):
    monkeypatch.setattr(disclosure_search.time, "time", lambda: 1_000_000)
    cache = _old_cache(tmp_path, timestamp=999_000)
    if isinstance(bad_cache, bytes):
        cache.write_bytes(bad_cache)
    else:
        cache.write_text(json.dumps({**json.loads(cache.read_text()), **bad_cache}))
    original = cache.read_bytes(), cache.stat().st_mtime_ns
    monkeypatch.setattr(disclosure_search, "_load_h1_client", lambda: None)
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    assert "Query status: unavailable" in output and "Material source: none" in output
    assert "- cache:" in output and "Old report" not in output
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original


def _provider():
    spec = disclosure_search.importlib.util.spec_from_file_location(
        "disclosure_test_provider", disclosure_search.BASE_DIR / "mcp/hackerone-mcp/server.py",
    )
    module = disclosure_search.importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("response", [
    None, [], {}, {"data": None}, {"data": []}, {"data": {}},
    {"data": {"hacktivity_items": None}}, {"data": {"hacktivity_items": {}}},
    {"data": {"hacktivity_items": {"nodes": None}}},
    {"data": {"hacktivity_items": {"nodes": {}}}},
    *[{"data": {"hacktivity_items": {"nodes": [node]}}} for node in [
        None, [], False,
        *[{"report": value} for value in ([], False, 0, "")],
        *[{"report": {"title": "report"}, "team": value} for value in ([], False, 0, "")],
        {"report": {"severity_rating": []}}, {"report": {"disclosed_at": 0}},
        {"report": {"title": False}}, {"report": {"title": "report"}, "team": {"handle": []}},
    ]],
])
def test_real_provider_malformed_response_preserves_owner_cache(tmp_path, monkeypatch, response):
    provider = _provider()
    requests = []

    def graphql(query):
        requests.append(query)
        return response

    monkeypatch.setattr(provider, "_graphql_request", graphql)
    monkeypatch.setattr(disclosure_search, "_load_h1_client", lambda: provider)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: [])
    monkeypatch.setattr(disclosure_search.time, "time", lambda: 1_000_000)
    cache = _old_cache(tmp_path)
    original = cache.read_bytes(), cache.stat().st_mtime_ns
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    assert len(requests) == 2
    assert "Query status: unavailable" in output and "HackerOneAPIError" in output
    assert "Old report" in output and "Material stale: yes" in output
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original


@pytest.mark.parametrize("nodes", [[], [{}, {"report": None}, {"report": {}, "team": {}}], [
    {"report": {"title": "Optional fields", "severity_rating": None, "disclosed_at": None}, "team": None},
]])
def test_real_provider_compatible_responses_reach_successful_cache(tmp_path, monkeypatch, nodes):
    provider = _provider()
    monkeypatch.setattr(provider, "_graphql_request", lambda query: {"data": {"hacktivity_items": {"nodes": nodes}}})
    monkeypatch.setattr(disclosure_search, "_load_h1_client", lambda: provider)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: [])
    output = write_disclosed_patterns("fixture.test", repo_root=tmp_path).read_text()
    cache = json.loads(disclosure_search._cache_path(tmp_path, "fixture.test").read_text())
    assert "Query status: complete" in output
    expected_count = sum(bool(node.get("report")) for node in nodes)
    assert len(cache["same"]) == expected_count
    assert ("Optional fields" in output) == bool(expected_count)
    if expected_count:
        assert cache["same"][0]["severity"] == "UNKNOWN"
        assert cache["same"][0]["disclosed_at"] == ""
    assert cache["coverage_status"] == ("covered" if cache["same"] else "no_mcp_coverage")


@pytest.mark.parametrize("failed_file", ["cache", "markdown"])
def test_atomic_publication_failure_preserves_corresponding_old_file(tmp_path, monkeypatch, capsys, failed_file):
    cache = _old_cache(tmp_path)
    original_cache = cache.read_bytes()
    markdown = tmp_path / "evidence/fixture.test/disclosed_patterns.md"
    markdown.parent.mkdir(parents=True)
    markdown.write_text("Complete old Markdown\n")
    original_replace = Path.replace

    def fail_replace(path, destination):
        if destination == (cache if failed_file == "cache" else markdown):
            raise OSError("injected replace failure")
        return original_replace(path, destination)

    class Client:
        def search_disclosed_reports(self, **kwargs):
            return []

    monkeypatch.setattr(Path, "replace", fail_replace)
    monkeypatch.setattr(disclosure_search, "_load_h1_client", Client)
    monkeypatch.setattr(disclosure_search, "_load_tech_stack_hint", lambda *args: [])
    with pytest.raises(OSError, match="injected replace failure"):
        disclosure_search.main(["--target", "fixture.test", "--repo-root", str(tmp_path)])
    assert capsys.readouterr().out == ""
    assert markdown.read_text() == "Complete old Markdown\n"
    if failed_file == "cache":
        assert cache.read_bytes() == original_cache
    else:
        assert json.loads(cache.read_text())["same"] == []
    assert not list(tmp_path.rglob("*.tmp"))
