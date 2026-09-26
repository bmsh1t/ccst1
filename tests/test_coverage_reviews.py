"""Coverage author input survives projection loss without becoming closure proof."""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tools import coverage_matrix as coverage
from tools import target_migration as migration
from tools import target_store as domain


TARGET = "coverage-review.test"
REPO = Path(__file__).resolve().parents[1]


def cli(root, command, *args):
    return subprocess.run(
        [sys.executable, "-B", str(REPO / "tools" / "coverage_matrix.py"), command,
         "--repo-root", str(root), "--target", TARGET, *args],
        capture_output=True, text=True, check=False,
    )


def test_coverage_reads_claims_without_expanding_finding_authorization(tmp_path, monkeypatch):
    store = domain.TargetStore(tmp_path, TARGET)
    store.initialize()
    store.create_finding(command_id="claim", finding_id="claim", endpoint=f"https://{TARGET}/only-claim?owner=peer",
                         method="GET", family="UnknownFamily", title="Claim", claim="Unverified", actor="operator")
    raw = tmp_path / "evidence" / TARGET / "raw.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("Recorded response")
    store.start_attempt(attempt_id="attempt", source="native", started_at="2026-09-25T00:00:00Z", actor="operator")
    store.record_execution(attempt_id="attempt", outcome="complete", actor="operator", observations=[{
        "endpoint": f"https://{TARGET}/observed", "method": "GET", "family": "Authz",
        "observed_at": "2026-09-25T00:00:00Z", "description": "Recorded comparison",
        "result": "tested_clean", "state_changing": False,
        "artifacts": {"response": raw.relative_to(tmp_path).as_posix()},
    }])
    before = store.binding()

    def expanded(*args, **kwargs):
        raise AssertionError("Coverage needs claim endpoints, not Finding authorization")

    monkeypatch.setattr(domain.TargetStore, "finding_page", expanded)
    matrix = coverage.read_matrix(TARGET, tmp_path)
    endpoints = {ep["endpoint"]: ep for ep in matrix["endpoints"]}
    assert endpoints["/only-claim"]["observed_params"] == ["owner"]
    assert all(cell["status"] == "untested" for cell in endpoints["/only-claim"]["cells"].values())
    assert endpoints["/observed"]["cells"]["Authz"]["status"] == "tested_clean"
    raw.write_text("Changed response")
    damaged = coverage.read_matrix(TARGET, tmp_path)
    assert damaged["evidence_health"]["status"] == "partial"
    assert damaged["closure_projection"]["closed_cells"] == []
    assert store.binding() == before


def test_coverage_merges_complete_claim_pages_reviews_and_observations(tmp_path, monkeypatch):
    store = domain.TargetStore(tmp_path, TARGET)
    store.initialize()
    for i in range(1001):
        store.create_finding(command_id=f"claim-{i:04}", finding_id=f"claim-{i:04}",
                             endpoint=f"https://{TARGET}/claim-{i}?alpha=1", method="GET",
                             family="UnknownFamily", title="Claim", claim="Unverified", actor="operator")
    store.create_finding(command_id="tail", finding_id="tail", endpoint=f"https://{TARGET}/claim-1000?beta=2",
                         method="GET", family="UnknownFamily", title="Tail", claim="Unverified", actor="operator")
    store.record_coverage_review(command_id="review", endpoint="/claim-1000", kind="cell_status",
                                 family="Authz", value="n_a", reason="Historical advice", actor="operator")
    raw = tmp_path / "evidence" / TARGET / "raw.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("Recorded response")
    store.start_attempt(attempt_id="attempt", source="native", started_at="2026-09-25T00:00:00Z", actor="operator")
    store.record_execution(attempt_id="attempt", outcome="complete", actor="operator", observations=[{
        "endpoint": f"https://{TARGET}{endpoint}", "method": "GET", "family": "Authz",
        "observed_at": "2026-09-25T00:00:00Z", "description": "Recorded comparison",
        "result": "tested_clean", "state_changing": False,
        "artifacts": {"response": raw.relative_to(tmp_path).as_posix()},
    } for endpoint in ("/claim-1000", "/observed-only", "/observed-only")])
    before = store.binding()
    page = domain.TargetStore.page
    claim_pages = []

    def traced(self, kind, **kwargs):
        result = page(self, kind, **kwargs)
        if kind == "findings":
            claim_pages.append(len(result["items"]))
        return result

    monkeypatch.setattr(domain.TargetStore, "page", traced)
    matrix = coverage.read_matrix(TARGET, tmp_path)
    endpoints = {ep["endpoint"]: ep for ep in matrix["endpoints"]}
    assert claim_pages == [1000, 2]
    assert len(matrix["endpoints"]) == len(endpoints) == 1002
    assert set(endpoints) == {f"/claim-{i}" for i in range(1001)} | {"/observed-only"}
    assert endpoints["/claim-1000"]["observed_params"] == ["alpha", "beta"]
    assert endpoints["/claim-1000"]["cells"]["Authz"]["review"]["id"] == "review"
    assert endpoints["/claim-1000"]["cells"]["Authz"]["status"] == "tested_clean"
    assert endpoints["/observed-only"]["observation_count"] == 2
    assert endpoints["/observed-only"]["cells"]["Authz"]["status"] == "tested_clean"
    assert all(cell["status"] == "untested" for cell in endpoints["/claim-0"]["cells"].values())
    assert matrix["source_snapshot"]["review_ids"] == ["review"]
    assert store.binding() == before
    assert not coverage._matrix_path(tmp_path, TARGET).exists()


def test_author_inputs_survive_new_process_and_projection_loss(tmp_path, monkeypatch):
    root = tmp_path / "root with spaces"
    store = domain.TargetStore(root, TARGET)
    store.initialize()
    kind = cli(root, "mark-endpoint-kind", "--endpoint", "/container", "--kind", "route_prefix",
               "--reason", "Only a container", "--actor", "reviewer", "--command-id", "kind-1")
    assert kind.returncode == 0, kind.stderr
    assert json.loads(kind.stdout)["kind_review"]["recorded_by"] == "reviewer"
    marked = cli(root, "mark", "--endpoint", "/container", "--vuln-class", "Authz", "--status", "n_a",
                 "--reason", "Revisit if a handler appears", "--actor", "reviewer", "--command-id", "cell-1")
    assert marked.returncode == 0, marked.stderr
    assert json.loads(marked.stdout)["advisory"] is True
    assert not (root / "evidence").exists()
    revision = store.binding()["revision"]
    replay = cli(root, "mark", "--endpoint", "/container", "--vuln-class", "Authz", "--status", "n_a",
                 "--reason", "Revisit if a handler appears", "--actor", "reviewer", "--command-id", "cell-1")
    assert json.loads(replay.stdout)["receipt"]["replayed"] is True
    assert store.binding()["revision"] == revision

    coverage.rebuild_matrix(TARGET, root, force_clean=True)
    coverage._matrix_path(root, TARGET).unlink()
    gaps = cli(root, "find-gaps", "--limit", "100")
    assert gaps.returncode == 0, gaps.stderr
    authz = next(row for row in json.loads(gaps.stdout)["items"] if row["vuln_class"] == "Authz")
    assert authz["endpoint_kind"] == "route_prefix"
    assert authz["review"]["reason"] == "Revisit if a handler appears"
    triage = cli(root, "needs-triage", "--all")
    assert json.loads(triage.stdout)["total"] == 0
    assert store.page("attempts")["total"] == store.page("operations")["total"] == 0

    def retired(*args, **kwargs):
        raise AssertionError("primary touched retired matrix")

    monkeypatch.setattr(coverage, "load_matrix", retired)
    matrix = coverage.read_matrix(TARGET, root)
    assert matrix["endpoints"][0]["cells"]["Authz"]["status"] == "untested"
    assert matrix["source_snapshot"]["review_ids"] == ["cell-1", "kind-1"]
    assert store.binding()["revision"] == revision
    assert not coverage._matrix_path(root, TARGET).exists()
    coverage.mark_endpoint_kind(TARGET, "/container", "untriaged", repo_root=root, command_id="reopen-triage")
    assert coverage.needs_endpoint_triage(TARGET, root)[0]["endpoint"] == "/container"


def test_review_history_pagination_conflicts_and_ownership(tmp_path):
    store = domain.TargetStore(tmp_path, TARGET)
    store.initialize()
    for i in range(7):
        store.record_coverage_review(command_id=f"review-{i}", endpoint=f"/item/{i}",
                                     kind="cell_status", family="Authz", value="tested_clean", actor="reviewer")
    first = store.coverage_review_page(limit=5)
    assert first["total"] == 7 and first["remaining"] == 2
    assert len(store.coverage_review_page(limit=5, cursor=first["next_cursor"])["items"]) == 2
    with pytest.raises(domain.ConflictError):
        store.coverage_review_page(latest=False, cursor=first["next_cursor"])
    with pytest.raises(domain.ConflictError):
        store.coverage_review_page(endpoint="/item/1", cursor=first["next_cursor"])
    before = store.binding()
    for endpoint in ("", "https://other.test/item/1", "//other.test/item/1", "/x\nheader", "/x\\y"):
        with pytest.raises(domain.StoreError):
            coverage.mark_cell(TARGET, endpoint, "Authz", "tested_finding", repo_root=tmp_path,
                               write_finding=True, command_id="invalid")
    assert store.binding() == before
    assert store.page("findings")["total"] == 0
    with pytest.raises(domain.ConflictError):
        store.record_coverage_review(command_id="review-0", endpoint="/item/0", kind="cell_status",
                                     family="Authz", value="n_a", actor="reviewer")
    store.record_coverage_review(command_id="replacement", endpoint="/item/0", kind="cell_status",
                                 family="Authz", value="untested", reason="new conditions", actor="reviewer")
    assert store.coverage_review_page(endpoint="/item/0")["items"][0]["id"] == "replacement"
    assert store.coverage_review_page(latest=False, endpoint="/item/0")["total"] == 2
    assert store.coverage_review("review-0")["value"] == "tested_clean"
    with pytest.raises(domain.ConflictError):
        store.coverage_review_page(cursor=first["next_cursor"])


def test_review_and_claim_commit_together_without_authorizing_finding(tmp_path, monkeypatch):
    store = domain.TargetStore(tmp_path, TARGET)
    store.initialize()
    ensure = domain.TargetStore._ensure_finding

    def failed(conn, claim, now):
        ensure(conn, claim, now)
        raise RuntimeError("interrupted after claim insert")

    with monkeypatch.context() as patch:
        patch.setattr(domain.TargetStore, "_ensure_finding", staticmethod(failed))
        with pytest.raises(RuntimeError, match="interrupted"):
            coverage.mark_cell(TARGET, "/claim", "Authz", "tested_finding", reason="first claim",
                               repo_root=tmp_path, write_finding=True, command_id="claim-review")
    assert store.binding()["revision"] == 0
    assert store.page("findings")["total"] == store.coverage_review_page()["total"] == 0
    review = coverage.mark_cell(TARGET, "/claim", "Authz", "tested_finding", reason="first claim",
                                repo_root=tmp_path, write_finding=True, command_id="claim-review")
    finding = store.finding(review["review"]["finding_id"])
    assert finding["assessment"] is None and finding["deliveries"] == []
    coverage.mark_cell(TARGET, "/claim", "Authz", "tested_finding", reason="extra context",
                       repo_root=tmp_path, write_finding=True, command_id="claim-review-2")
    assert store.page("findings")["total"] == 1
    assert store.finding(finding["id"])["claim"] == "first claim"
    matrix = coverage.read_matrix(TARGET, tmp_path)
    cell = matrix["endpoints"][0]["cells"]["Authz"]
    assert cell["status"] == "untested" and cell["review"]["reason"] == "extra context"


@pytest.mark.parametrize("version", [8, 9])
def test_explicit_upgrade_preserves_old_schema_on_failure_and_recovers(tmp_path, monkeypatch, version):
    schema = domain._SCHEMA.replace(domain._COVERAGE_REVIEW_SCHEMA, "")
    if version == 8:
        schema = schema.replace("    created_at TEXT NOT NULL,\n    active_goal TEXT NOT NULL DEFAULT ''\n",
                                "    created_at TEXT NOT NULL\n", 1).replace(
                                    "'primitive','negative','hypothesis','handoff','note'",
                                    "'primitive','negative','hypothesis','handoff'", 1)
    store = domain.TargetStore(tmp_path, TARGET)
    with monkeypatch.context() as patch:
        patch.setattr(domain, "_SCHEMA", schema)
        patch.setattr(domain, "SCHEMA_VERSION", version)
        store.initialize()
    store.remember(command_id="old", kind="hypothesis", statement="old input", conditions="unknown",
                   reopen_when="", next_intent="", evidence=[], actor="reviewer")
    before = store.binding()
    domain.initialize_target_store(tmp_path, TARGET)
    assert store.binding() == before
    with pytest.raises(domain.StoreError, match="upgrade required"):
        coverage.mark_cell(TARGET, "/old", "Authz", "n_a", repo_root=tmp_path)
    with pytest.raises(domain.StoreError, match="upgrade required"):
        coverage.read_matrix(TARGET, tmp_path)
    backup = tmp_path / "failed-backup.sqlite3"
    with monkeypatch.context() as patch:
        patch.setattr(domain, "_digest", lambda _: (_ for _ in ()).throw(RuntimeError("before audit")))
        with pytest.raises(RuntimeError, match="before audit"):
            store.upgrade_schema(backup)
    assert store.binding() == before
    for path in (backup, store.path):
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == version
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert conn.execute("SELECT name FROM sqlite_master WHERE name='coverage_reviews'").fetchone() is None
    result = subprocess.run([sys.executable, "-B", str(REPO / "tools" / "target_store.py"), "upgrade-schema",
                             "--repo-root", str(tmp_path), "--target", TARGET,
                             "--backup", str(tmp_path / "upgrade-backup.sqlite3")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert store.experience("old")["statement"] == "old input"
    assert store.active_goal() == ""
    assert store.coverage_review_page()["total"] == 0
    assert store.binding()["revision"] == before["revision"] + 1
    assert store.upgrade_schema(tmp_path / "unused.sqlite3")["status"] == "already_current"
    assert not (tmp_path / "unused.sqlite3").exists()


def legacy_matrix(root, *, malformed=False):
    path = root / "evidence" / TARGET / "coverage_matrix.json"
    path.parent.mkdir(parents=True)
    payload = {"target": TARGET, "endpoints": [{
        "endpoint": "/container", "endpoint_kind": "route_prefix", "kind_source": "operator",
        "kind_reason": "historical classification", "kind_triaged_at": "2026-09-01T00:00:00Z",
        "cells": {"Authz": {"status": "n_a", "reason": "historical rationale"},
                  "XSS": {"status": "untested"}},
    }]}
    if malformed:
        payload["endpoints"].extend([None, {"endpoint": "https://other.test/a", "cells": {
            "Authz": {"status": "tested_clean"}}}])
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_legacy_reviews_import_and_receipt_survive_new_process(tmp_path):
    source, staging = tmp_path / "source", tmp_path / "staging"
    path = legacy_matrix(source)
    raw = path.read_bytes()
    preview = migration.preview_target(source, TARGET)
    assert preview["source_counts"]["coverage_reviews"] == 2
    assert not (source / "state").exists()
    result = migration.import_target_staged(source, staging, TARGET)
    assert result["status"] == "ready"
    migration.promote_target(staging, TARGET)
    store = domain.TargetStore(staging, TARGET)
    coverage._matrix_path(staging, TARGET).unlink(missing_ok=True)
    listing = cli(staging, "reviews", "--history")
    assert listing.returncode == 0, listing.stderr
    rows = json.loads(listing.stdout)["items"]
    assert len(rows) == 2 and all(row["historical"] == 1 for row in rows)
    imported = result["receipt"]["coverage_backfill"]
    assert {row["review_id"] for row in imported["review_map"]} == {row["id"] for row in rows}
    assert imported["path"] == f"evidence/{TARGET}/coverage_matrix.json"
    assert {row["source_pointer"] for row in imported["review_map"]} == {
        "/endpoints/0", "/endpoints/0/cells/Authz"}
    matrix = coverage.read_matrix(TARGET, staging)
    assert matrix["endpoints"][0]["endpoint_kind"] == "route_prefix"
    assert matrix["endpoints"][0]["cells"]["Authz"]["status"] == "untested"
    assert path.read_bytes() == raw
    revision = store.binding()["revision"]
    assert migration.backfill_coverage_reviews(source, staging, TARGET)["status"] == "complete"
    assert store.binding()["revision"] == revision


def test_backfill_resumes_after_receipt_failure_and_preserves_new_reviews(tmp_path, monkeypatch):
    source, staging = tmp_path / "source", tmp_path / "staging"
    path = legacy_matrix(source)
    # Model a cutover completed by the previous importer, which kept only the file manifest.
    with monkeypatch.context() as patch:
        def skip(report, store, root, canonical, manifest):
            report["legacy"]["coverage"] = {}
        patch.setattr(migration, "_import_coverage_reviews", skip)
        migration.import_target_staged(source, staging, TARGET)
    migration.promote_target(staging, TARGET)
    store = domain.TargetStore(staging, TARGET)
    coverage.mark_endpoint_kind(TARGET, "/container", "api_endpoint", reason="new handler",
                                repo_root=staging, command_id="current-kind")
    with monkeypatch.context() as patch:
        patch.setattr(migration, "_publish_backfill_receipt",
                      lambda *args: (_ for _ in ()).throw(OSError("receipt failure")))
        with pytest.raises(OSError, match="receipt failure"):
            migration.backfill_coverage_reviews(source, staging, TARGET)
    after_rows = store.binding()["revision"]
    result = migration.backfill_coverage_reviews(source, staging, TARGET)
    assert result["status"] == "complete" and store.binding()["revision"] == after_rows
    assert store.coverage_review_page(latest=False)["total"] == 3
    matrix = coverage.read_matrix(TARGET, staging)
    assert matrix["endpoints"][0]["endpoint_kind"] == "api_endpoint"
    assert matrix["endpoints"][0]["kind_reason"] == "new handler"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(domain.StoreError, match="differs from migration manifest"):
        migration.backfill_coverage_reviews(source, staging, TARGET)
    assert store.binding()["revision"] == after_rows


def test_bad_legacy_rows_are_quarantined_without_authorizing_good_rows(tmp_path):
    source, staging = tmp_path / "source", tmp_path / "staging"
    legacy_matrix(source, malformed=True)
    preview = migration.preview_target(source, TARGET)
    assert preview["status"] == "partial"
    result = migration.import_target_staged(source, staging, TARGET)
    assert result["status"] == "partial"
    assert len([row for row in result["quarantined"] if row["owner"] == "coverage"]) == 2
    store = domain.TargetStore(staging, TARGET, allow_preview=True)
    assert store.coverage_review_page()["total"] == 2
    assert store.page("operations")["total"] == 0
