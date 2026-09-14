"""Keep observations and hard boundaries while retiring judgment substitutes."""

import json

from tools import browser_mcp_import, repo_secret_scan, source_intel, surface
from tools.structured_findings import finding_rank_key
from tools.surface_source_intel import build_source_intel_urls, load_source_intel


def test_source_routes_keep_unfamiliar_inputs_and_real_method_provenance(tmp_path):
    repo = tmp_path / "sample"
    repo.mkdir()
    (repo / "app.js").write_text(
        "router.post('/opaque', handler); fetch('/x');\n"
        "const q = 'mutation UpdateValue { value }';\n"
        "const socket = new WebSocket('wss://target.test/stream');\n",
        encoding="utf-8",
    )
    result = source_intel.run_source_intel(target="target.test", repo_path=str(repo), repo_root=tmp_path)
    observations = load_source_intel(tmp_path / "findings" / "target.test")
    urls = build_source_intel_urls(observations, "https://target.test")
    assert {"https://target.test/opaque", "https://target.test/x"} <= set(urls)
    assert any(row["method"] == "POST" and row["source"] == "repo:app.js" for row in urls["https://target.test/opaque"])
    assert observations["graphql_operations"][0]["operation"] == "mutation"
    assert any("WebSocket" in row["evidence"] for row in observations["signals"])
    assert "hypotheses" not in result["artifacts"]
    assert "tags" not in observations["routes"][0]


def test_browser_novel_evidence_does_not_need_value_keywords(tmp_path):
    url = "https://target.test/opaque"
    har = tmp_path / "capture.har"
    har.write_text(json.dumps({"log": {"entries": [{
        "request": {"url": url, "method": "GET", "headers": []},
        "response": {"status": 200, "headers": [], "content": {"mimeType": "application/json", "text": "{}"}},
    }]}}), encoding="utf-8")
    snapshot = tmp_path / "snapshot.txt"
    snapshot.write_text("A newly observed page with an input field", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"target": "target.test", "captures": [
        {"url": url, "har": str(har), "snapshot": str(snapshot)},
        {"url": "https://external.test/opaque", "har": str(har)},
    ]}), encoding="utf-8")
    args = dict(target="target.test", manifest_path=manifest, repo_root=tmp_path,
                evidence_root=tmp_path / "evidence", recon_root=tmp_path / "recon", enqueue=False)
    first = browser_mcp_import.import_focused_mcp_manifest(**args)
    second = browser_mcp_import.import_focused_mcp_manifest(**args)
    assert first["counts"]["actionable"] == 1
    assert "high_value" not in first["captures"][0]
    assert first["skipped"][0]["reason"] == "off_target"
    assert second["counts"]["actionable"] == 0


def test_legacy_source_routes_survive_malformed_rows_without_restoring_predictions(tmp_path):
    source_dir = tmp_path / "source_intel"
    source_dir.mkdir()
    (source_dir / "hypotheses.jsonl").write_text(
        json.dumps({"candidate": "/first", "type": "idor"}) + "\n{broken\n" +
        json.dumps({"candidate": "/last", "method": "POST", "priority": "high"}) + "\n",
        encoding="utf-8",
    )
    observations = load_source_intel(tmp_path)
    urls = build_source_intel_urls(observations, "https://target.test")
    assert set(urls) == {"https://target.test/first", "https://target.test/last"}
    assert urls["https://target.test/last"][0]["method"] == "POST"
    assert all("type" not in row and "priority" not in row for row in observations["routes"])


def test_secret_detection_retains_location_and_mask_not_guessed_validity(tmp_path):
    token = "ghp_" + "x" * 24
    (tmp_path / "sample.js").write_text(f'const key = "{token}"; // verified owned\n', encoding="utf-8")
    hit = next(row for row in repo_secret_scan._scan_builtin(str(tmp_path)) if row.rule_id == "github-token")
    assert hit.file_path == "sample.js" and hit.line_number == 1
    assert hit.secret_preview != token and "..." in hit.secret_preview
    assert hit.source == "builtin"
    assert "secret_triage" not in hit.metadata


def test_finding_rank_ignores_legacy_rubric_and_prose_keywords():
    base = {"severity": "medium", "confidence": "needs_review"}
    assert finding_rank_key({**base, "rubric": {"score": 0, "ready": False}}) == finding_rank_key({
        **base, "summary": "No actor proof. No request. No private data. No impact.",
        "evidence_rubric": {"score": 100, "ready": True},
    })


def test_surface_words_do_not_choose_a_class_or_hide_routes(tmp_path):
    urls = ["https://target.test/plain", "https://target.test/admin/payment", "https://target.test/blog/page"]
    recon = tmp_path / "recon" / "target.test"
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "live" / "httpx_full.txt").write_text("https://target.test [200] [Fixture] [100]\n", encoding="utf-8")
    (recon / "urls" / "api_endpoints.txt").write_text("\n".join(urls), encoding="utf-8")
    ranked = surface.rank_surface(surface.load_surface_context(str(tmp_path), "target.test", memory_dir=str(tmp_path / "memory")))
    rows = {row["url"]: row for row in ranked["review_pool"]}
    assert set(rows) == set(urls)
    assert len({row["score"] for row in rows.values()}) == 1
    assert all("vuln_class" not in row and not row["suggested"] for row in rows.values())
