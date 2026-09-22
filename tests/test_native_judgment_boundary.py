"""Keep observations and hard boundaries while retiring judgment substitutes."""

import json

import pytest

from tools import browser_mcp_import, repo_secret_scan, source_intel, surface
from tools.structured_findings import finding_rank_key
from tools.surface_source_intel import build_source_intel_urls, load_source_intel
from tools.target_store import TargetStore


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


def test_primary_surface_action_projection_ignores_corrupt_legacy_queue(tmp_path):
    target = "primary-surface.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(
        command_id="create-surface-work",
        action_id="WORK-1",
        intent="Review recorded surface",
        execution_key="work:surface-review",
        actor="ai",
        kind="work",
        subject={"target": target},
    )
    (tmp_path / "state" / target / "action_queue.json").write_text("{not-json", encoding="utf-8")

    projected = surface._primary_action_queue(store)

    assert [item["id"] for item in projected] == ["WORK-1"]
    assert projected[0]["source"] == "target_store"


def test_primary_surface_query_does_not_refresh_projection_sidecars(tmp_path):
    target = "primary-surface-read.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    recon = tmp_path / "recon" / target
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "live" / "httpx_full.txt").write_text(
        f"https://{target} [200] [Fixture] [100]\n", encoding="utf-8"
    )
    (recon / "urls" / "api_endpoints.txt").write_text(
        f"https://{target}/api/objects\n", encoding="utf-8"
    )
    def snapshot_non_sqlite_sidecars():
        return {
            str(path.relative_to(tmp_path)): path.read_bytes()
            for path in tmp_path.rglob("*")
            if path.is_file() and path.name not in {"metadata.sqlite3-shm", "metadata.sqlite3-wal"}
        }

    before = snapshot_non_sqlite_sidecars()
    surface.load_surface_context(tmp_path, target, memory_dir=tmp_path / "memory")
    after = snapshot_non_sqlite_sidecars()
    assert after == before


def test_primary_surface_rejects_store_revision_drift_during_assembly(tmp_path, monkeypatch):
    target = "primary-surface-revision.test"
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, target)
    store.initialize()
    recon = tmp_path / "recon" / target
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "live" / "httpx_full.txt").write_text(
        f"https://{target} [200] [Fixture] [100]\n", encoding="utf-8"
    )
    original = surface._store_binding_snapshot
    first = original(store)
    changed = {**first, "revision": first["revision"] + 1}
    bindings = iter((first, changed))
    monkeypatch.setattr(surface, "_store_binding_snapshot", lambda _store: next(bindings))

    with pytest.raises(ValueError, match="Surface inputs changed during assembly"):
        surface.load_surface_context(tmp_path, target, memory_dir=tmp_path / "memory")


def test_primary_surface_rejects_mutation_after_context_before_publication(tmp_path, monkeypatch):
    target = "primary-surface-publication.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    recon = tmp_path / "recon" / target
    (recon / "urls").mkdir(parents=True)
    (recon / "urls" / "api_endpoints.txt").write_text(
        f"https://{target}/objects\n", encoding="utf-8"
    )
    first = surface.build_surface_review(tmp_path, target, memory_dir=tmp_path / "memory")
    projection_path = first["surface_projection"]["path"]
    from pathlib import Path

    published = Path(projection_path).read_bytes()
    original = surface.load_surface_context

    def mutate_after_context(*args, **kwargs):
        context = original(*args, **kwargs)
        store.create_finding(
            command_id="new-finding", finding_id="F-1", endpoint=f"https://{target}/objects",
            method="GET", family="Authz", title="New claim", claim="Needs review", actor="operator",
        )
        return context

    monkeypatch.setattr(surface, "load_surface_context", mutate_after_context)
    with pytest.raises(surface.SurfaceIndexError, match="inputs changed"):
        surface.build_surface_review(tmp_path, target, memory_dir=tmp_path / "memory")

    assert Path(projection_path).read_bytes() == published
    assert store.finding("F-1")["id"] == "F-1"
    from tools.surface_projection import load_surface_projection

    assert load_surface_projection(tmp_path, target, memory_dir=tmp_path / "memory")["status"] != "valid"


def test_surface_review_excludes_cutover_after_initial_backend_read(tmp_path, monkeypatch):
    import fcntl
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path
    from queue import Queue

    from tools.surface_projection import load_surface_projection
    from tools.target_migration import import_target_staged, promote_target, publish_preview

    target = "surface-cutover.test"
    source = tmp_path / "source"
    source.mkdir()
    staging = tmp_path / "staging"
    repo = tmp_path / "published"
    assert import_target_staged(source, staging, target)["receipt"]["status"] == "complete"
    publish_preview(staging, repo, target)
    store = TargetStore(repo, target)
    recon = repo / "recon" / target / "urls"
    recon.mkdir(parents=True)
    (recon / "api_endpoints.txt").write_text(f"https://{target}/objects\n", encoding="utf-8")
    lock_path = repo / "state" / target / "locks" / "target-switch.lock"
    lock_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    attempted = Queue()
    original = surface.target_backend
    cutover = None

    def switch_backend():
        with lock_path.open("a+") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                attempted.put("blocked")
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)
                attempted.put("unblocked")
        promote_target(repo, target)
        store.create_finding(
            command_id="new-finding", finding_id="F-1", endpoint=f"https://{target}/objects",
            method="GET", family="Authz", title="New claim", claim="Needs review", actor="operator",
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        def read_backend_then_attempt_cutover(*args, **kwargs):
            nonlocal cutover
            backend = original(*args, **kwargs)
            if cutover is None:
                assert backend == "preview"
                cutover = executor.submit(switch_backend)
                assert attempted.get(timeout=5) == "blocked"
            return backend

        monkeypatch.setattr(surface, "target_backend", read_backend_then_attempt_cutover)
        review = surface.build_surface_review(repo, target, memory_dir=tmp_path / "memory")
        cutover.result(timeout=5)

    published = json.loads(Path(review["surface_projection"]["path"]).read_text())
    assert "store_id" not in published["input_manifest"]["binding"]
    assert store.finding("F-1")["id"] == "F-1"
    assert load_surface_projection(repo, target, memory_dir=tmp_path / "memory")["status"] != "valid"
    refreshed = surface.build_surface_review(repo, target, memory_dir=tmp_path / "memory")
    assert refreshed["surface_projection"]["status"] == "valid"
    assert load_surface_projection(repo, target, memory_dir=tmp_path / "memory")["status"] == "valid"
