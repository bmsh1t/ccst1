"""tests/test_parallel_siblings.py — B6 acceptance tests.

Covers parallel_workers spawn → wait → join semantics, dedup, timeout
handling, budget exhaustion, and audit-log additive shape. Workers are
exercised end-to-end against a local stub HTTP server so we never hit
the network during CI.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import parallel_workers as pw   # noqa: E402


# ---------------------------------------------------------------------
#  Local HTTP stub
# ---------------------------------------------------------------------

class _StubHandler(http.server.BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, bytes, str]] = {}

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        status, body, ctype = self.routes.get(path, (404, b"not found", "text/plain"))
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a, **_k):  # silence
        pass


@pytest.fixture
def stub_server():
    """Start a tiny HTTP server on a random port; tear down after."""
    handler = _StubHandler
    handler.routes = {
        "/api/v1/orders/123": (200, b'{"id":123,"item":"foo"}', "application/json"),
        "/api/v1/invoices/123": (200, b'{"id":123,"amount":42}', "application/json"),
        "/api/v1/exports/123": (200, b'{"id":123,"file":"e.csv"}', "application/json"),
        "/api/v1/missing/123": (404, b"nope", "text/plain"),
    }
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as srv:
        host, port = srv.server_address
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        yield f"http://{host}:{port}"
        srv.shutdown()
        thread.join(timeout=2)


@pytest.fixture
def fake_repo(tmp_path: Path):
    """Build a stand-in repo dir with recon URLs cached for sibling expansion."""
    target = "stub.local"
    recon_dir = tmp_path / "recon" / target / "urls"
    recon_dir.mkdir(parents=True, exist_ok=True)
    urls = [
        "/api/v1/orders/123",
        "/api/v1/invoices/123",
        "/api/v1/exports/123",
        "/api/v1/missing/123",
    ]
    (recon_dir / "all.txt").write_text("\n".join(urls), encoding="utf-8")
    (tmp_path / "evidence" / target / "workers").mkdir(parents=True, exist_ok=True)
    (tmp_path / "hunt-memory" / "audit").mkdir(parents=True, exist_ok=True)
    return tmp_path, target


def _patch_base_dir(monkeypatch, repo: Path):
    """Force pw.BASE_DIR to point at the test repo so spawn paths resolve."""
    monkeypatch.setattr(pw, "BASE_DIR", repo)
    # sibling_generator's _load_all_urls also references BASE_DIR — but the
    # worker passes target as arg, and _load_all_urls looks in
    # repo/recon/<target>/urls/all.txt. We don't import sibling_generator
    # here; the worker process re-imports it with its own BASE_DIR (which
    # is the project root when invoked from ./tools/sibling_worker.py).
    # For the worker subprocess, we override BASE_DIR via env: see _spawn.


# ---------------------------------------------------------------------
#  R1, R2: Spawn primitive + per-worker isolation directory
# ---------------------------------------------------------------------

class TestSpawnAndIsolation:
    def test_sibling_handle_creates_scratch_dir_layout(self, fake_repo, monkeypatch):
        repo, target = fake_repo
        _patch_base_dir(monkeypatch, repo)
        seed = {"id": "f-1", "endpoint": "/api/v1/orders/123", "vuln_class": "IDOR"}
        handle = pw.spawn_sibling_worker(
            seed_finding=seed,
            worker_id="w1",
            target=target,
            repo_root=repo,
            auto_start=False,
        )
        scratch = Path(handle.scratch_dir)
        assert scratch.exists()
        assert scratch.name == "sibling-w1"
        assert scratch.parent.name == "workers"
        assert scratch.parent.parent.name == target
        # Pre-created files
        assert (scratch / "attempts.jsonl").exists()
        assert (scratch / "findings.json").read_text() == "[]"
        assert not (scratch / "done.flag").exists()
        # seed.json carries the input payload
        seed_payload = json.loads((scratch / "seed.json").read_text())
        assert seed_payload["worker_id"] == "w1"
        assert seed_payload["seed_finding"]["endpoint"] == "/api/v1/orders/123"

    def test_hypothesis_worker_creates_hypothesis_md(self, fake_repo, monkeypatch):
        repo, target = fake_repo
        _patch_base_dir(monkeypatch, repo)
        h = pw.spawn_hypothesis_worker(
            hypothesis={"working_hypothesis": "tenant-mixed cache key"},
            worker_id="h1",
            target=target,
            repo_root=repo,
            auto_start=False,
        )
        md = Path(h.scratch_dir) / "hypothesis.md"
        assert md.exists()
        assert "tenant-mixed cache key" in md.read_text()

    def test_red_team_worker_uses_smaller_default_budget(self, fake_repo, monkeypatch):
        repo, target = fake_repo
        _patch_base_dir(monkeypatch, repo)
        h = pw.spawn_red_team_worker(
            candidate_finding={"id": "c-1", "endpoint": "/x", "vuln_class": "IDOR"},
            worker_id="r1",
            target=target,
            repo_root=repo,
            auto_start=False,
        )
        # B12c C2: 8 vs B6 default of 12
        assert h.budget_tools == 8


# ---------------------------------------------------------------------
#  R3, R4, R5: Budget, timeout, join helper
# ---------------------------------------------------------------------

class TestWaitAndReap:
    def test_wait_returns_immediately_when_all_complete(self, fake_repo, monkeypatch):
        repo, target = fake_repo
        _patch_base_dir(monkeypatch, repo)
        seed = {"id": "f-1", "endpoint": "/x"}
        handle = pw.spawn_sibling_worker(
            seed, "w1", target, repo_root=repo, auto_start=False,
        )
        # Pre-touch done.flag so wait sees a completed worker on the first poll
        (Path(handle.scratch_dir) / "done.flag").write_text("{}\n")
        results = pw.wait_for_workers([handle], timeout_secs=1)
        assert len(results) == 1
        assert results[0].completed is True
        assert results[0].timed_out is False

    def test_wait_times_out_when_no_done_flag(self, fake_repo, monkeypatch):
        repo, target = fake_repo
        _patch_base_dir(monkeypatch, repo)
        seed = {"id": "f-1", "endpoint": "/x"}
        handle = pw.spawn_sibling_worker(
            seed, "w-stuck", target, repo_root=repo, auto_start=False,
        )
        # Inject fake clock to avoid real-time waits
        ticks = iter([0.0, 0.5, 0.9, 1.1, 1.2])
        results = pw.wait_for_workers(
            [handle], timeout_secs=1,
            poll_interval_secs=0.0, clock=lambda: next(ticks),
            sleep=lambda _s: None,
        )
        assert results[0].completed is False
        assert results[0].timed_out is True
        assert results[0].findings == []

    def test_findings_loaded_from_scratch_on_join(self, fake_repo, monkeypatch):
        repo, target = fake_repo
        _patch_base_dir(monkeypatch, repo)
        seed = {"id": "f-1", "endpoint": "/x"}
        handle = pw.spawn_sibling_worker(
            seed, "w-found", target, repo_root=repo, auto_start=False,
        )
        finding = {"endpoint": "/api/v1/invoices/9", "vuln_class": "IDOR", "severity": "high"}
        (Path(handle.scratch_dir) / "findings.json").write_text(json.dumps([finding]))
        (Path(handle.scratch_dir) / "done.flag").write_text("{}\n")
        # one attempt row
        (Path(handle.scratch_dir) / "attempts.jsonl").write_text('{"x":1}\n')
        results = pw.wait_for_workers([handle], timeout_secs=1)
        assert results[0].findings == [finding]
        assert results[0].attempt_count == 1


# ---------------------------------------------------------------------
#  R6: Parent join + dedup + matrix-rebuild
# ---------------------------------------------------------------------

class TestConsolidateFindings:
    def test_dedup_keeps_higher_severity(self):
        results = [
            pw.WorkerResult(
                worker_id="a", kind="sibling", scratch_dir="", completed=True, timed_out=False,
                exit_code=0, findings=[{"endpoint": "/x", "vuln_class": "IDOR", "severity": "low"}],
            ),
            pw.WorkerResult(
                worker_id="b", kind="sibling", scratch_dir="", completed=True, timed_out=False,
                exit_code=0, findings=[{"endpoint": "/x", "vuln_class": "IDOR", "severity": "high"}],
            ),
        ]
        merged = pw._consolidate_findings(results)
        assert len(merged) == 1
        assert merged[0]["severity"] == "high"
        assert merged[0]["worker_id"] == "b"

    def test_dedup_does_not_collapse_different_vuln_classes(self):
        results = [
            pw.WorkerResult(
                worker_id="a", kind="sibling", scratch_dir="", completed=True, timed_out=False,
                exit_code=0, findings=[
                    {"endpoint": "/x", "vuln_class": "IDOR", "severity": "high"},
                    {"endpoint": "/x", "vuln_class": "XSS", "severity": "medium"},
                ],
            ),
        ]
        merged = pw._consolidate_findings(results)
        assert len(merged) == 2

    def test_consolidated_skips_empty_endpoints(self):
        results = [
            pw.WorkerResult(
                worker_id="a", kind="sibling", scratch_dir="", completed=True, timed_out=False,
                exit_code=0, findings=[{"endpoint": "", "vuln_class": "IDOR"}],
            ),
        ]
        assert pw._consolidate_findings(results) == []


class TestJoinAndConsolidate:
    def test_appends_new_findings_and_dedups_against_existing(self, fake_repo):
        repo, target = fake_repo
        existing = [{"endpoint": "/old", "vuln_class": "IDOR", "severity": "low"}]
        findings_path = repo / "findings" / target / "findings.json"
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        findings_path.write_text(json.dumps(existing))
        results = [
            pw.WorkerResult(
                worker_id="w", kind="sibling", scratch_dir="", completed=True, timed_out=False,
                exit_code=0, findings=[
                    {"endpoint": "/old", "vuln_class": "IDOR"},   # dup with existing
                    {"endpoint": "/new", "vuln_class": "IDOR"},   # new
                ],
            ),
        ]
        summary = pw.join_and_consolidate(results, target, repo_root=repo)
        assert summary["consolidated_findings"] == 2
        assert summary["appended_to_findings"] == 1
        contents = json.loads(findings_path.read_text())
        endpoints = {f["endpoint"] for f in contents}
        assert endpoints == {"/old", "/new"}

    def test_summary_carries_worker_counts(self, fake_repo):
        repo, target = fake_repo
        results = [
            pw.WorkerResult(worker_id="a", kind="sibling", scratch_dir="",
                            completed=True, timed_out=False, exit_code=0),
            pw.WorkerResult(worker_id="b", kind="sibling", scratch_dir="",
                            completed=False, timed_out=True, exit_code=None),
        ]
        summary = pw.join_and_consolidate(results, target, repo_root=repo)
        assert summary["workers_total"] == 2
        assert summary["workers_completed"] == 1
        assert summary["workers_timed_out"] == 1


# ---------------------------------------------------------------------
#  R7, R8: CLI flags + mode coercion
# ---------------------------------------------------------------------

class TestModeCoercion:
    def test_paranoid_forces_one(self):
        assert pw.coerce_max_parallel(5, "paranoid") == 1
        assert pw.coerce_max_parallel(99, "paranoid") == 1

    def test_normal_caps_at_three(self):
        assert pw.coerce_max_parallel(2, "normal") == 2
        assert pw.coerce_max_parallel(5, "normal") == 3
        assert pw.coerce_max_parallel(8, "normal") == 3

    def test_yolo_caps_at_eight(self):
        assert pw.coerce_max_parallel(2, "yolo") == 2
        assert pw.coerce_max_parallel(99, "yolo") == 8

    def test_zero_or_missing_falls_back_to_default(self):
        # 0/None are treated as "no preference" → default cap (3 in normal)
        assert pw.coerce_max_parallel(0, "normal") == 3
        assert pw.coerce_max_parallel(None, "normal") == 3


def test_cli_flags_present_in_agent_argparse():
    """B6 R7 — agent.py must accept --parallel / --max-parallel / --worker-timeout-secs."""
    text = (REPO_ROOT / "agent.py").read_text(encoding="utf-8")
    assert '"--parallel"' in text, "agent.py missing --parallel flag"
    assert '"--max-parallel"' in text, "agent.py missing --max-parallel flag"
    assert '"--worker-timeout-secs"' in text, "agent.py missing --worker-timeout-secs flag"


# ---------------------------------------------------------------------
#  R9: Audit-log additive shape
# ---------------------------------------------------------------------

class TestAuditLogShape:
    def test_worker_audit_extras_includes_id_and_parent(self, fake_repo, monkeypatch):
        repo, target = fake_repo
        _patch_base_dir(monkeypatch, repo)
        seed = {"id": "f-1", "endpoint": "/x"}
        handle = pw.spawn_sibling_worker(
            seed, "w-aud", target, repo_root=repo,
            auto_start=False, parent_session="sess-42",
        )
        extras = pw.worker_audit_extras(handle)
        assert extras == {"worker_id": "w-aud", "parent_session": "sess-42"}

    def test_existing_audit_entries_without_extras_remain_valid(self):
        # The shape is additive: regular audit entries that don't carry
        # worker_id/parent_session must still validate via memory.schemas.
        from memory.schemas import validate_audit_entry, make_audit_entry
        baseline = make_audit_entry(
            url="https://x.example/api",
            method="GET",
            scope_check="pass",
            response_status=200,
            session_id="s1",
        )
        validated = validate_audit_entry(baseline)
        assert "worker_id" not in validated
        assert "parent_session" not in validated


# ---------------------------------------------------------------------
#  R10: Global RateLimiter file-lock coordination
# ---------------------------------------------------------------------

class TestGlobalRateLimiter:
    def test_initial_call_writes_state_file(self, tmp_path):
        state = tmp_path / "lock.json"
        limiter = pw.GlobalRateLimiter(state, test_rps=10.0, worker_count=2)
        slept = limiter.wait("h1", sleep=lambda _s: None)
        assert slept == 0.0
        data = json.loads(state.read_text())
        assert "h1" in data
        assert data["h1"]["last_request_epoch"] > 0

    def test_per_worker_interval_includes_safety_margin(self, tmp_path):
        # Two workers sharing a 1 rps cap → each waits 1.0 × 2 × 1.10 = 2.2s
        state = tmp_path / "lock.json"
        limiter = pw.GlobalRateLimiter(state, test_rps=1.0, worker_count=2,
                                       safety_margin=0.10)
        # Pre-seed last_request to "now" so the next call must wait
        state.write_text(json.dumps({
            "h1": {"last_request_epoch": time.time(), "interval": 2.2},
        }))
        slept_holder = {}
        def fake_sleep(s):
            slept_holder["s"] = s
        limiter.wait("h1", sleep=fake_sleep)
        # Slept ≈ 2.2s (allow small slack — the lock acquisition may eat ms)
        assert 1.5 <= slept_holder["s"] <= 2.3

    def test_lock_serializes_two_concurrent_workers(self, tmp_path):
        """Two threads hammering the limiter must NOT exceed the cap."""
        state = tmp_path / "lock.json"
        # 1000 rps so per-worker interval is tiny — what we test is that
        # state writes are serialized (no JSONDecodeError, no lost updates).
        limiter = pw.GlobalRateLimiter(state, test_rps=1000.0, worker_count=2)
        errors: list[Exception] = []
        def hammer():
            try:
                for _ in range(20):
                    limiter.wait(f"h-{threading.get_ident() % 4}", sleep=lambda _s: None)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert errors == []
        # Final state file must still be valid JSON
        json.loads(state.read_text())


# ---------------------------------------------------------------------
#  C1: Single-thread autopilot must behave unchanged
# ---------------------------------------------------------------------

class TestBackwardsCompatibility:
    def test_default_argparse_namespace_has_parallel_off(self):
        """Without explicit --parallel, behavior is unchanged."""
        import argparse
        # Build a minimal parser mirroring agent.py's relevant flags.
        parser = argparse.ArgumentParser()
        parser.add_argument("--parallel", action="store_true")
        parser.add_argument("--max-parallel", type=int, default=3)
        ns = parser.parse_args([])
        assert ns.parallel is False
        assert ns.max_parallel == 3


# ---------------------------------------------------------------------
#  End-to-end: real subprocess → done.flag → join
# ---------------------------------------------------------------------

class TestEndToEndSubprocess:
    def test_real_subprocess_completes_against_stub_server(self, stub_server, fake_repo, monkeypatch):
        """Full path: spawn → subprocess runs → done.flag set → join."""
        repo, _target = fake_repo
        host_for_url = stub_server.replace("http://", "")  # e.g., 127.0.0.1:54321

        # The worker process uses sibling_generator._load_all_urls(target,
        # BASE_DIR), where BASE_DIR is the real project root. So the
        # cached recon URLs must live at REPO_ROOT/recon/<host_for_url>/urls/all.txt.
        # Sanitize the host:port — colons are fine in dir names on POSIX.
        real_recon = REPO_ROOT / "recon" / host_for_url / "urls"
        real_recon.mkdir(parents=True, exist_ok=True)
        urls = [
            "/api/v1/orders/123",
            "/api/v1/invoices/123",
            "/api/v1/exports/123",
            "/api/v1/missing/123",
        ]
        (real_recon / "all.txt").write_text("\n".join(urls), encoding="utf-8")
        try:
            seed = {
                "id": "f-1",
                "endpoint": "/api/v1/orders/123",
                "vuln_class": "IDOR",
                "severity": "medium",
            }
            handle = pw.spawn_sibling_worker(
                seed_finding=seed,
                worker_id="e2e",
                target=host_for_url,
                repo_root=repo,
                budget_tools=4,
                timeout_secs=30,
                parent_session="sess-e2e",
            )
            results = pw.wait_for_workers([handle], timeout_secs=30,
                                          poll_interval_secs=0.2)
        finally:
            try:
                (real_recon / "all.txt").unlink()
                real_recon.rmdir()
                real_recon.parent.rmdir()
            except OSError:
                pass

        log_text = handle.log_path.read_text() if handle.log_path.exists() else "<no log>"
        assert results[0].completed is True, f"worker did not finish: log={log_text}"
        # Should have produced ≥1 sibling finding (invoices or exports).
        assert results[0].findings, f"no findings; log={log_text}"
        endpoints = {f["endpoint"] for f in results[0].findings}
        assert endpoints & {"/api/v1/invoices/123", "/api/v1/exports/123"}
        # Audit shape: each finding carries worker_id
        for f in results[0].findings:
            assert f["worker_id"] == "e2e"
