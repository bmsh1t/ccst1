"""Consumer regressions for the practical audit, using isolated local Stores."""

import json
import os
import subprocess
import threading
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools.auth_session import AuthSession, session_from_args
from tools.browser_mcp_import import import_mcp_browser_evidence
from tools.scope_source import load_scope_source, publish_scope_source
from tools.target_store import StoreError, TargetStore
from tools.validation_runner import record_native_evidence, request_once, run_request_diff, sync_runner_artifacts


def saved_scope(root, target, excluded):
    publish_scope_source(root, target,
                         {"schema_version": 1, "root_target": target, "out_of_scope": excluded},
                         expected_sha256=load_scope_source(root, target)["sha256"])


def seed_evidence(root):
    store = TargetStore(root, "audit.test")
    store.initialize()
    raw = root / ".private/validation/audit.test/response.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text('HTTP/1.1 200 OK\n\n{"owner":"peer"}\n')
    store.start_attempt(attempt_id="attempt-1", source="fixture", started_at="2026-09-26T00:00:00Z", actor="test")
    receipt = store.record_execution(
        attempt_id="attempt-1", outcome="complete", actor="test",
        candidate={"id": "F-1", "endpoint": "https://audit.test/objects/1", "method": "GET",
                   "family": "idor", "title": "Peer disclosure", "claim": "Fixture claim"},
        observations=[{"endpoint": "https://audit.test/objects/1", "method": "GET", "family": "idor",
                       "observed_at": "2026-09-26T00:00:00Z", "description": "Peer response", "actor": "peer",
                       "result": "tested_finding", "state_changing": False,
                       "artifacts": {"response": str(raw.relative_to(root))}}])
    store.assess(command_id="assessment-1", finding_id="F-1", verdict="confirmed",
                 reason="Fixture", boundary="Peer ownership", impact="Disclosure",
                 evidence=[{"operation_id": receipt["entity_id"], "step": 0}],
                 actor="test", expected_assessment=None)
    return store, raw


def test_saved_scope_controls_pair_anonymous_send_redirect_and_auth(tmp_path):
    from tools.param_discovery import _fetch_forms

    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.path)
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/excluded")
            self.end_headers()
            self.wfile.write(b'<form method="POST" action="/submit"><input name="ok"></form>')

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
    sink_thread.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = "127.0.0.1"
    store = TargetStore(tmp_path, target)
    store.initialize()
    origin = f"http://{target}:{server.server_port}"
    excluded = f"http://{target}:{sink.server_port}/excluded"
    try:
        saved_scope(tmp_path, target, [target])
        before = store.binding()
        pair = {"baseline_request": {"url": origin + "/?id=1"},
                "variant_request": {"url": origin + "/?id=2"},
                "subject_side": "baseline", "active_dimension": "query:id"}
        with pytest.raises(ValueError, match="saved Scope"):
            run_request_diff(repo_root=tmp_path, target=target, request_spec=pair)
        assert store.binding() == before
        assert received == []
        assert not (tmp_path / ".private/validation").exists()
        session = session_from_args(Namespace(target=target, repo_root=tmp_path, bearer="fixture"), env={})
        assert session.headers_for_url(origin) == {}
        saved_scope(tmp_path, target, [excluded])
        assert request_once(repo_root=tmp_path, target=target, url=origin + "/allowed")["status"] == 200
        with pytest.raises(ValueError, match="saved Scope"):
            request_once(repo_root=tmp_path, target=target, url=excluded)
        with pytest.raises(ValueError, match="saved Scope"):
            request_once(repo_root=tmp_path, target=target, url=origin + "/redirect")
        assert received == ["/allowed", "/redirect"]
        forms, error = _fetch_forms(origin + "/form", target=target, repo_root=tmp_path,
                                    session=AuthSession(target=target), timeout=2, fetch_html=None)
        assert error is None and forms[0]["action"] == origin + "/submit"
        (tmp_path / "state" / store.key / "scope.json").unlink()
        with pytest.raises(ValueError, match="scope source unavailable"):
            request_once(repo_root=tmp_path, target=target, url=origin + "/allowed")
        (tmp_path / "state" / store.key / "scope.json").write_text("{")
        with pytest.raises(ValueError):
            request_once(repo_root=tmp_path, target=target, url=origin + "/allowed")
        assert received == ["/allowed", "/redirect", "/form"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        sink.shutdown()
        sink.server_close()
        sink_thread.join(timeout=2)


def test_parameter_discovery_preserves_auth_scope_and_filters_saved_scope(tmp_path):
    from tools.param_discovery import discover_parameters
    from tools.scope_context import ScopeContext

    target = "audit.test"
    TargetStore(tmp_path, target).initialize()
    saved_scope(tmp_path, target, ["excluded.audit.test"])
    session = AuthSession(["Authorization: Bearer fixture"], target=target,
                          scope_context=ScopeContext(target, out_of_scope=["narrow.audit.test"]))
    fetched = []

    def fetch(url):
        fetched.append(url)
        return 200, ('<form method="POST" action="https://audit.test/submit"><input name="ok"></form>'
                     '<form method="POST" action="https://excluded.audit.test/submit"><input name="x"></form>')

    view = discover_parameters(repo_root=tmp_path, target=target, session=session,
                               urls=["https://audit.test/form", "https://excluded.audit.test/form"],
                               methods=["POST"], fetch_html=fetch, tool_exists=lambda _: False)
    assert fetched == ["https://audit.test/form"]
    assert list(view["post_forms"]) == ["https://audit.test/submit"]
    assert view["scope"]["rejected"][0]["reason"] == "excluded by saved Scope"
    assert session.headers_for_url("https://narrow.audit.test/form") == {}


def test_scanner_active_input_filter_reads_saved_scope_without_changing_discovery(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    target = "audit.test"
    TargetStore(tmp_path, target).initialize()
    saved_scope(tmp_path, target, ["excluded.audit.test"])
    source, destination = tmp_path / "discovered.txt", tmp_path / "active.txt"
    original = "https://audit.test/allowed\nhttps://excluded.audit.test/blocked\nhttps://foreign.test/\n"
    source.write_text(original)
    helper = (repo / "tools/vuln_scanner.sh").read_text().split("filter_direct_finding_urls_copy()", 1)[0]
    command = helper + '\nfilter_target_urls_copy "$1" "$2"\n'
    env = {**os.environ, "BASE_DIR": str(tmp_path), "SCANNER_AUTH_TARGET": target, "PYTHONPATH": str(repo)}
    result = subprocess.run(["bash", "-c", command, "filter", str(source), str(destination)],
                            env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert destination.read_text() == "https://audit.test/allowed\n"
    assert source.read_text() == original
    (tmp_path / "state/audit.test/scope.json").write_text("{")
    result = subprocess.run(["bash", "-c", command, "filter", str(source), str(destination)],
                            env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert destination.read_text() == ""
    assert source.read_text() == original


def test_browser_import_registers_private_raw_and_rejects_foreign_paths(tmp_path):
    from tools.target_paths import target_owned_nonempty_evidence_ref

    store = TargetStore(tmp_path, "audit.test")
    store.initialize()
    url = "https://audit.test/api/objects/1"
    store.create_finding(command_id="claim", finding_id="F-1", endpoint=url, method="GET",
                         family="idor", title="Browser fixture", claim="Peer difference", actor="test")
    network = tmp_path / "input.json"
    network.write_text(json.dumps({"requests": [{"request": {"url": url, "method": "GET"},
                                                "response": {"status": 200, "body": "private-fixture-body"}}]}))
    capture = import_mcp_browser_evidence(target=store.target, url=url, network_path=network,
                                          evidence_root=tmp_path / "evidence", recon_root=tmp_path / "recon")
    assert capture["status"] == "ok"
    ref = capture["artifacts"]["network_private_json"]
    evidence = {"schema_version": 1, "source": "browser", "generated_at": "2026-09-26T00:00:00Z",
                "attempt_id": "browser-attempt", "result": "tested_finding",
                "observed_difference": "Recorded owner and peer response difference",
                "runs": [{"url": url, "method": "GET", "actor": "owner",
                          "artifacts": {"request": ref, "response": ref}}]}
    summary = record_native_evidence(repo_root=tmp_path, target=store.target, finding_id="F-1",
                                      evidence=evidence, state_changing=False)
    assert sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    assert store.page("operations")["total"] == 1
    assert "private-fixture-body" not in json.dumps(summary)
    for relative in (".private/browser/foreign.test/raw", "state/audit.test/raw", ".private/other/audit.test/raw"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("bytes")
        assert target_owned_nonempty_evidence_ref(tmp_path, store.target, relative) == ""
        with pytest.raises(StoreError, match="raw evidence directories"):
            store._artifact(relative)
    link = tmp_path / ".private/browser/audit.test/escaped"
    link.symlink_to(tmp_path / ".private/browser/foreign.test/raw")
    assert target_owned_nonempty_evidence_ref(tmp_path, store.target, str(link)) == ""
    with pytest.raises(StoreError, match="raw evidence directories"):
        store._artifact(str(link))
    raw = tmp_path / ref
    raw.write_text("changed")
    with pytest.raises(StoreError, match="changed"):
        store.verify_operation(summary["store_operation_id"])


def test_distillation_keeps_current_integrity_beside_historical_verdict(tmp_path):
    from tools.distill_target import build_evidence_view

    store, raw = seed_evidence(tmp_path)
    assert build_evidence_view(tmp_path, store.target)["health"]["status"] == "ready"
    raw.write_text("changed")
    view = build_evidence_view(tmp_path, store.target)
    assert view["health"]["status"] == "partial"
    assert view["health"]["invalid_count"] == 1
    assert view["source"]["truncated"] is False
    assert "historical judgments" in view["view"]
    assert "partial" in view["view"] and "changed" in view["view"]
    assert "technical=confirmed" in view["view"]


def test_current_hypothesis_uses_creation_order_not_custom_id_or_replay(tmp_path, monkeypatch):
    from tools import target_store

    store = TargetStore(tmp_path, "audit.test")
    store.initialize()
    monkeypatch.setattr(target_store, "_now", lambda: "2026-09-27T00:00:00Z")
    old = dict(command_id="old", hypothesis_id="z-old", vuln_class="IDOR", why_now="old", actor="test")
    store.remember_hypothesis(**old)
    store.remember_hypothesis(command_id="new", hypothesis_id="a-new", vuln_class="IDOR", why_now="new", actor="test")
    assert store.memory_context()["current_hypothesis"] == "new"
    assert store.remember_hypothesis(**old)["replayed"]
    store.remember_hypothesis(**{**old, "command_id": "old-context", "status": "closed"})
    assert store.memory_context()["current_hypothesis"] == "new"
    assert store.experience_page()["order"] == "created_at_desc,id_desc"


def test_recall_distinguishes_empty_registry_corruption_and_unreadable_card(tmp_path, capsys):
    from tools.experience_recall import build_recall_view, main

    store = TargetStore(tmp_path, "audit.test")
    store.initialize()
    store.remember(command_id="note", kind="note", statement="retained", conditions="fixture",
                   reopen_when="", next_intent="", evidence=[], actor="test")
    registry = tmp_path / "knowledge/capabilities.yaml"
    registry.parent.mkdir()
    registry.write_text("capabilities: []\n")
    assert build_recall_view(tmp_path, target=store.target)["source_health"]["knowledge"]["status"] == "ready"
    registry.write_text("capabilities: [\n")
    view = build_recall_view(tmp_path, target=store.target)
    assert view["source_health"]["knowledge"]["status"] == "unavailable"
    assert view["target_entries"][0]["text"] == "retained"
    assert main(["--repo-root", str(tmp_path), "--target", store.target]) == 0
    assert "unavailable" in capsys.readouterr().out
    registry.write_text("capabilities:\n  - id: missing\n    kind: card\n    file: knowledge/cards/missing.md\n")
    health = build_recall_view(tmp_path, target=store.target)["source_health"]["knowledge"]
    assert health["status"] == "partial" and health["invalid_count"] == 1
    assert health["errors"][0]["ref"] == "knowledge/cards/missing.md"


def test_report_index_reads_each_immutable_body_and_never_invents_severity(tmp_path):
    from tools.report_generator import process_findings_dir

    store, _ = seed_evidence(tmp_path)
    bodies = {}
    for name, severity in (("critical", "critical"), ("low", "low"), ("unknown", "")):
        store.decide_delivery(command_id="delivery-" + name, finding_id="F-1", assessment_id="assessment-1",
                              destination=name, status="eligible", reason="Fixture", actor="test", expected_decision=None)
        report = tmp_path / "reports/audit.test" / (name + ".md")
        report.parent.mkdir(parents=True, exist_ok=True)
        body = "# Fixture\n\n" + (f"Severity: {severity}\n" if severity else "No declared level.\n")
        report.write_text(body)
        bodies[report] = report.read_bytes()
        store.register_report(command_id="report-" + name, report_id="report-" + name, finding_id="F-1",
                              assessment_id="assessment-1", delivery_id="delivery-" + name,
                              artifact=str(report), actor="test")
    (tmp_path / "findings/audit.test").mkdir(parents=True)
    count, entries = process_findings_dir(tmp_path / "findings/audit.test")
    assert count == 3
    assert {row["destination"]: row["severity"] for row in entries} == {
        "critical": "critical", "low": "low", "unknown": "unknown"}
    assert all(path.read_bytes() == body for path, body in bodies.items())


@pytest.mark.parametrize(("text", "expected"), [
    ("## Severity\n**HIGH** (CVSS: 8.1)", "high"),
    ("**Severity:** LOW", "low"),
    ("A critical issue in a low-level API.", "unknown"),
    ("```text\nSeverity: high\n```\nSeverity: low", "low"),
    ("Severity: high\nSeverity: critical", "unknown"),
    ("Severity: invalid", "unknown"),
])
def test_severity_only_reads_explicit_consistent_fields(text, expected):
    from tools.report_generator import declared_report_severity
    from tools.validate import _machine_report_severity

    assert declared_report_severity(text)["severity"] == expected
    assert _machine_report_severity({}, text) == expected
    with pytest.raises(ValueError, match="explicit Severity"):
        _machine_report_severity({"severity": "medium"}, text)


def test_closure_deduplicates_hashes_only_within_one_read(tmp_path, monkeypatch):
    from tools.current_truth import current_cell_projection

    store, raw = seed_evidence(tmp_path)
    for i in range(3):
        store.start_attempt(attempt_id=f"extra-{i}", source="fixture", started_at="2026-09-26T00:00:00Z", actor="test")
        store.record_execution(attempt_id=f"extra-{i}", outcome="complete", actor="test", observations=[{
            "endpoint": "https://audit.test/objects/1", "method": "GET", "family": "idor",
            "observed_at": "2026-09-26T00:00:00Z", "description": "Extra execution",
            "artifacts": {"response": str(raw.relative_to(tmp_path))}, "state_changing": False}])
    before = store.binding()
    hashed = []
    original = TargetStore._artifact

    def track(self, ref):
        hashed.append(ref)
        return original(self, ref)

    monkeypatch.setattr(TargetStore, "_artifact", track)
    assert current_cell_projection(tmp_path, store.target)["health"]["status"] == "ready"
    assert len(hashed) == 1
    raw.write_text("changed")
    damaged = current_cell_projection(tmp_path, store.target)
    assert len(hashed) == 2
    assert damaged["health"]["invalid_count"] == 4
    assert damaged["projection"]["closed_cells"] == []
    assert store.binding() == before
