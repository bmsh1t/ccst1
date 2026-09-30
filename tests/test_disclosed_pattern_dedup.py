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
