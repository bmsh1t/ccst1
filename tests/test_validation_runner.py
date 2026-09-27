"""Tests for deterministic validation runner v1 lanes."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

import validation_runner
from evidence_identity import CLOSURE_FAMILIES
from request_diff import RequestPairError, request_pair_digest, validate_request_pair
from tools.auth_session import AuthSession
from tools.target_store import StoreError, TargetStore, initialize_target_store


@pytest.fixture
def runner_store(tmp_path):
    initialize_target_store(tmp_path, "target.test")
    return TargetStore(tmp_path, "target.test")


def _target_key(target: str) -> str:
    return validation_runner.target_storage_key(validation_runner.canonical_target_value(target))


@pytest.mark.parametrize(
    ("classifier", "explicit", "expected"),
    [
        ("nosqli", "", "NoSQLi"),
        ("generic", "prototype-pollution", "PrototypePollution"),
        ("generic", "open-redirect", "OpenRedirect"),
        ("generic", "business-logic", "BusinessLogic"),
        ("ssti", "", "RCE"),
        ("generic", "command-injection", "RCE"),
        ("generic", "lfi", "Path"),
        ("unknown", "", ""),
    ],
)
def test_request_diff_uses_canonical_vuln_taxonomy(classifier, explicit, expected):
    actual = validation_runner._classifier_vuln_class(classifier, explicit)
    assert actual == expected
    assert not actual or actual in CLOSURE_FAMILIES


def _expect_auth_pair_spec() -> dict:
    return {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "classifier": "authz",
    }


def test_undeclared_same_size_body_change_remains_candidate(runner_store, monkeypatch, tmp_path):
    bodies = iter(['{"value":"first"}', '{"value":"other"}'])
    monkeypatch.setattr(validation_runner, "request_once", lambda **kw: _fake_response(kw["url"], body=next(bodies)))
    summary = validation_runner.run_request_diff(repo_root=tmp_path, target="target.test", request_spec=_expect_auth_pair_spec())
    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    run = summary["runs"][0]
    assert run["baseline"]["body_length"] == run["variant"]["body_length"]
    assert run["baseline"]["body_sha256"] != run["variant"]["body_sha256"]
    assert run["diff"]["changed_any"] is True
    assert run["diff"]["changed"]["body_sha256"] is True
    facts = validation_runner._run_wire_facts(run, '{"value":"first"}', '{"value":"other"}')
    assert facts["identical_success_pair"] is False


def test_partial_pair_preserves_first_response_without_promoting(runner_store, monkeypatch, tmp_path):
    calls = []

    def request(**kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            raise OSError("synthetic transport failure")
        return _fake_response(kwargs["url"], body='{"observation":"retained"}')

    monkeypatch.setattr(validation_runner, "request_once", request)
    summary = validation_runner.run_request_diff(repo_root=tmp_path, target="target.test", request_spec=_expect_auth_pair_spec())
    assert summary["result"] == "partial"
    assert summary["candidate_ready"] is False
    assert summary["error"] == {"side": "variant", "type": "OSError"}
    artifacts = summary["runs"][0]["artifacts"]
    assert "retained" in (tmp_path / artifacts["baseline_response"]).read_text(encoding="utf-8")
    assert "variant_response" not in artifacts
    assert summary["artifact_bindings"]
    validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert not (tmp_path / "findings" / "target.test" / "findings.json").exists()
    assert len(calls) == 2


def test_request_diff_distinct_bodies_promotes_sub_threshold_cross_user_read(runner_store, monkeypatch, tmp_path):
    """V-2: a cross-user read whose body delta is below the 20-byte material
    threshold is still a different object. distinct_bodies has no threshold,
    so the Users/24-vs-Users/1 shape (delta ~15 bytes) promotes."""

    def fake_request_once(**kwargs):
        url = kwargs["url"]
        if url.endswith("/24"):
            return _fake_response(url, body='{"data":{"id":24,"email":"me@target.test"}}')
        return _fake_response(url, body='{"data":{"id":1,"email":"admin@juice-sh.op"}}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/Users/24"},
        "variant_request": {"method": "GET", "url": "https://target.test/api/Users/1"},
        "active_dimension": "path:/api/Users/24",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expected": ["distinct_bodies"],
        "expected_note": "reading another user's record should not return their row",
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    # The diff-relative threshold fact must NOT hold for this pair.
    assert summary["expected_check"]["observed"]["distinct_bodies"] is True


def test_request_diff_needle_facts_promote_structurally_identical_cross_user_read(runner_store, monkeypatch, tmp_path):
    """V-3: a cross-user read whose responses are structurally identical
    (same JSON shape, same size, different owner) cannot be expressed by any
    diff-relative fact. The AI declares a needle — the owner identifier — and
    the runner verifies the substring mechanically."""

    def fake_request_once(**kwargs):
        url = kwargs["url"]
        if url.endswith("/7"):
            return _fake_response(url, body='{"id":7,"UserId":25,"coupon":null}')
        return _fake_response(url, body='{"id":6,"UserId":24,"coupon":null}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/basket/7"},
        "variant_request": {"method": "GET", "url": "https://target.test/rest/basket/6"},
        "active_dimension": "path:/rest/basket/7",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expected": [
            'variant_body_contains::"UserId":24',
            'baseline_body_lacks::"UserId":24',
        ],
        "expected_note": "the non-owner basket read must return the other owner's id",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    assert summary["expected_check"]["observed"] == {
        'variant_body_contains::"UserId":24': True,
        'baseline_body_lacks::"UserId":24': True,
    }


def test_request_diff_needle_fact_contradicted_falls_to_candidate(runner_store, monkeypatch, tmp_path):
    """Anti-forgery for needles: declaring a needle that the wire disproves
    rejects to candidate with the entry named in unmet."""

    def fake_request_once(**kwargs):
        url = kwargs["url"]
        if url.endswith("/7"):
            return _fake_response(url, body='{"id":7,"UserId":25}')
        return _fake_response(url, body='{"id":6,"UserId":24}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/basket/7"},
        "variant_request": {"method": "GET", "url": "https://target.test/rest/basket/6"},
        "active_dimension": "path:/rest/basket/7",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        # Both needles are false here: the variant lacks UserId 99 and the
        # baseline DOES contain the string the declaration says it lacks.
        "expected": [
            'variant_body_contains::"UserId":99',
            'baseline_body_lacks::"UserId":25',
        ],
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["expected_check"]["unmet"] == [
        'variant_body_contains::"UserId":99',
        'baseline_body_lacks::"UserId":25',
    ]


def test_request_pair_needle_fact_validation(tmp_path):
    """Needle parsing: unknown needle-fact name and out-of-bounds needle
    length are hard input errors; a valid entry rides the digest."""

    base = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/a"},
        "variant_request": {"method": "GET", "url": "https://target.test/b"},
        "active_dimension": "path:/a",
        "classifier": "generic",
    }
    base["baseline_request"]["url"] = "https://target.test/users/1"
    base["variant_request"]["url"] = "https://target.test/users/2"
    base["active_dimension"] = "path:/users/1"

    valid = dict(base, expected=['variant_body_contains::"UserId":24'])
    normalized = validate_request_pair(valid)
    assert normalized["expected"] == ['variant_body_contains::"UserId":24']

    with pytest.raises(RequestPairError, match="unknown fact name"):
        validate_request_pair(dict(base, expected=['variant_body_has::"UserId":24']))
    # Short needles are valid: the AI judges what string is discriminative
    # ('49' for a 7*7 render, '7*7' for an unevaluated template).
    assert validate_request_pair(dict(base, expected=['variant_body_contains::49']))["expected"] == [
        'variant_body_contains::49'
    ]
    assert validate_request_pair(dict(base, expected=['variant_body_contains::7*7']))["expected"] == [
        'variant_body_contains::7*7'
    ]
    with pytest.raises(RequestPairError, match="unknown fact name"):
        validate_request_pair(dict(base, expected=['variant_body_contains::']))
    with pytest.raises(RequestPairError, match="needle"):
        validate_request_pair(dict(base, expected=[f'variant_body_contains::{"x" * 201}']))
    assert request_pair_digest(valid) != request_pair_digest(dict(base, expected=['variant_body_contains::"UserId":25']))


def test_request_pair_declaration_intent_parse_and_digest(tmp_path):
    base = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/users/1"},
        "variant_request": {"method": "GET", "url": "https://target.test/users/2"},
        "active_dimension": "path:/users/1",
        "classifier": "generic",
        "expected": ["distinct_bodies"],
    }
    # Absent defaults to hazard (today's behavior for every existing spec).
    assert validate_request_pair(base)["declaration_intent"] == "hazard"
    assert validate_request_pair(dict(base, declaration_intent="clean"))["declaration_intent"] == "clean"
    assert validate_request_pair(dict(base, declaration_intent="HAZARD"))["declaration_intent"] == "hazard"
    with pytest.raises(RequestPairError, match="declaration_intent"):
        validate_request_pair(dict(base, declaration_intent="maybe"))
    # Intent rides the digest: a clean declaration is a different operation.
    assert request_pair_digest(dict(base, declaration_intent="clean")) != request_pair_digest(base)


def test_request_diff_clean_intent_confirmed_lands_tested_clean(runner_store, monkeypatch, tmp_path):
    """O-1: declaring the CLEAN direction and confirming it yields a
    mechanically-backed tested_clean (expected_check archived), not a
    finding-shaped artifact. The runner routes on the declared intent; it
    never infers direction from the fact names."""

    def fake_request_once(**kwargs):
        # Redirect-allowlist shape: both sides rejected identically apart from
        # echoing the input; the boundary holds.
        return _fake_response(kwargs["url"], status=406, body="refused")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/redirect?to=ok"},
        "variant_request": {"method": "GET", "url": "https://target.test/redirect?to=bad"},
        "active_dimension": "query:to",
        "evidence_shape": "request_diff",
        "classifier": "open_redirect",
        "vuln_class": "OpenRedirect",
        "expected": ["both_sides_rejected"],
        "declaration_intent": "clean",
        "expected_note": "the allowlist should refuse both a valid-but-foreign and an offsite target",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    assert summary["declaration_intent"] == "clean"

    # Same pair without intent: hazard default promotes as today (regression).
    spec.pop("declaration_intent")
    hazard = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert hazard["result"] == "tested_finding"

    # Clean declaration NOT holding: kill-condition failure is signal —
    # candidate, reaching review.
    spec["declaration_intent"] = "clean"
    spec["expected"] = ["distinct_bodies"]
    unmet = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert unmet["result"] == "candidate"
    assert unmet["expected_check"]["unmet"] == ["distinct_bodies"]


def test_request_pair_expect_auth_parse_and_digest():
    """expect_auth is an AI-declared boolean judgment: the parser carries it
    unchanged (never infers it), and it participates in the operation digest
    because declaring it makes the replay a different operation."""

    base = _expect_auth_pair_spec()
    normalized = validate_request_pair(base)
    assert normalized["expect_auth"] is False

    declared = dict(base, expect_auth=True)
    assert validate_request_pair(declared)["expect_auth"] is True

    # Absent, null, and empty all mean "no assertion" (legacy behavior).
    assert validate_request_pair(dict(base, expect_auth=None))["expect_auth"] is False
    assert validate_request_pair(dict(base, expect_auth=""))["expect_auth"] is False

    # A spec with and without the declaration are different operations.
    assert request_pair_digest(declared) != request_pair_digest(base)

    # Non-boolean truthy values are hard input errors, not silently coerced.
    with pytest.raises(RequestPairError):
        validate_request_pair(dict(base, expect_auth="yes"))


def _fake_response(url: str, *, status: int = 200, body: str = "{}") -> dict:
    return {
        "url": url,
        "method": "GET",
        "request_text": f"GET {urlparse(url).path or '/'} HTTP/1.1\nHost: {urlparse(url).netloc}\n",
        "status": status,
        "reason": "OK",
        "headers": {"Content-Type": "application/json"},
        "body": body,
        "response_text": f"HTTP/1.1 {status} OK\nContent-Type: application/json\n\n{body}",
    }


def test_request_diff_replays_post_json_with_sql_classifier(runner_store, monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        body = kwargs["body"]
        name = body["filter"]["name"] if isinstance(body, dict) else ""
        count = 3 if "select" in name.lower() or "or" in name.lower() else 1
        return _fake_response(kwargs["url"], body=json.dumps({"data": [{"id": index} for index in range(count)]}))

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec={
            "schema_version": 1,
            "baseline_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"filter": {"name": "SAMPLE"}},
            },
            "variant_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"filter": {"name": "' OR 1=1 --"}},
            },
            "active_dimension": "body:/filter/name",
            "evidence_shape": "request_diff",
            "classifier": "sqli",
            "vuln_class": "SQLi",
            "expected": ["count_delta_positive"],
            "repeat": 2,
        },
        finding_id="SQLI-POST-JSON",
        repeat=2,
    )

    assert summary["method"] == "POST"
    assert summary["active_dimension"] == "body:/filter/name"
    assert summary["evidence_shape"] == "request_diff"
    assert summary["classifier"] == "sqli"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    assert summary["ledger_record"] is None
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["store"]["status"] == "updated"
    operation = runner_store.execution(summary["store_operation_id"])
    assert len(operation["observations"]) == 4
    assert all(row["method"] == "POST" and row["family"] == "SQLi" for row in operation["observations"])
    assert all(run["method"] if "method" in run else True for run in summary["runs"])


def test_request_diff_without_canonical_family_preserves_store_observations(runner_store, monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        query = parse_qs(urlparse(kwargs["url"]).query).get("q", [""])[0]
        count = 2 if query == "banana" else 1
        return _fake_response(kwargs["url"], body=json.dumps({"data": list(range(count))}))

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec={
            "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
            "variant_request": {"method": "GET", "url": "https://target.test/search?q=banana"},
            "active_dimension": "query:q",
            "classifier": "generic",
        },
        finding_id="GENERIC-REQUEST-DIFF",
    )

    sync = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)

    assert summary["ledger_record"] is None
    assert sync["status"] == "updated"
    operation = runner_store.execution(summary["store_operation_id"])
    assert len(operation["observations"]) == 2
    assert all(row["family"] == "runner-observation" for row in operation["observations"])
    assert runner_store.finding("GENERIC-REQUEST-DIFF")["assessment"] is None


def test_request_diff_marks_multipart_manual_required_without_request(runner_store, monkeypatch, tmp_path):
    def fail_request(**kwargs):
        raise AssertionError("unsupported wire body must not be sent")

    monkeypatch.setattr(validation_runner, "request_once", fail_request)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec={
            "baseline_request": {
                "method": "POST",
                "url": "https://target.test/upload",
                "headers": {"Content-Type": "multipart/form-data"},
                "body": "binary",
            },
            "variant_request": {
                "method": "POST",
                "url": "https://target.test/upload",
                "headers": {"Content-Type": "multipart/form-data"},
                "body": "other",
            },
            "active_dimension": "body:/file",
        },
        finding_id="UPLOAD-MANUAL",
    )

    assert summary["result"] == "manual_required"
    assert "multipart" in summary["manual_required"]


def test_request_diff_rerun_creates_attempt_but_registration_replay_is_idempotent(runner_store, monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"data":[{"id":1},{"id":2}]}'),
    )
    spec = {
        "baseline_request": {"method": "POST", "url": "https://target.test/api/search", "body": {"q": "SAMPLE"}},
        "variant_request": {"method": "POST", "url": "https://target.test/api/search", "body": {"q": "PAYLOAD"}},
        "active_dimension": "body:/q",
        "classifier": "sqli",
    }
    first = validation_runner.run_request_diff(repo_root=tmp_path, target="https://target.test", request_spec=spec, finding_id="PAIR-IDEMPOTENT")
    second = validation_runner.run_request_diff(repo_root=tmp_path, target="https://target.test", request_spec=spec, finding_id="PAIR-IDEMPOTENT")
    assert first["attempt_id"] != second["attempt_id"]
    for summary in (first, second):
        assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
        assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "deduplicated"
    assert first["store_operation_id"] != second["store_operation_id"]
    assert runner_store.page("operations")["total"] == 2
    assert not (tmp_path / "memory/evidence/target.test/ledger.jsonl").exists()


def test_request_once_rejects_off_target_before_open(monkeypatch):
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("network opener must not be built")

    monkeypatch.setattr(validation_runner.urllib.request, "build_opener", fail_if_called)
    with pytest.raises(ValueError, match="outside target scope"):
        validation_runner.request_once(
            target="target.test",
            url="https://other.test/api",
        )
    assert called is False


def test_redirect_handler_rejects_off_target_redirect():
    handler = validation_runner._TargetRedirectHandler("target.test")
    with pytest.raises(ValueError, match="redirect left target scope"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://other.test/callback?token=secret")


def test_request_once_records_same_target_redirect_identity():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"final")

        def log_message(self, *_args):
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except OSError as exc:  # pragma: no cover - restricted sandboxes
        pytest.skip(f"localhost listener unavailable: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    requested_url = f"http://127.0.0.1:{server.server_port}/start"
    final_url = f"http://127.0.0.1:{server.server_port}/final"
    try:
        response = validation_runner.request_once(
            target=f"127.0.0.1:{server.server_port}",
            url=requested_url,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert response["url"] == requested_url
    assert response["requested_url"] == requested_url
    assert response["final_url"] == final_url
    assert response["redirect_chain"] == [{
        "status": 302,
        "from_url": requested_url,
        "to_url": final_url,
    }]


def test_cross_origin_redirect_replays_only_explicitly_authorized_session_headers():
    sink_headers: list[dict[str, str]] = []
    source_headers: list[dict[str, str]] = []

    class SinkHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            sink_headers.append(dict(self.headers.items()))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            return

    try:
        sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    except OSError as exc:  # pragma: no cover - restricted sandboxes
        pytest.skip(f"localhost listener unavailable: {exc}")
    sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
    sink_thread.start()
    sink_url = f"http://127.0.0.1:{sink.server_port}/final"

    class SourceHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            source_headers.append(dict(self.headers.items()))
            self.send_response(302)
            self.send_header("Location", sink_url)
            self.end_headers()

        def log_message(self, *_args):
            return

    try:
        source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
    except OSError as exc:  # pragma: no cover - restricted sandboxes
        sink.shutdown()
        sink_thread.join(timeout=2)
        sink.server_close()
        pytest.skip(f"localhost listener unavailable: {exc}")
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    source_thread.start()
    source_url = f"http://127.0.0.1:{source.server_port}/start"
    try:
        untrusted = AuthSession(
            ["Authorization: Bearer session", "Cookie: sid=session"],
            target="127.0.0.1",
        )
        validation_runner.request_once(
            target="127.0.0.1",
            url=source_url,
            headers={"Authorization": "Bearer raw", "X-Raw-Auth": "raw"},
            session=untrusted,
        )

        trusted = AuthSession(
            ["Authorization: Bearer session", "Cookie: sid=session"],
            target="127.0.0.1",
            allowed_origins=[sink_url],
        )
        validation_runner.request_once(
            target="127.0.0.1",
            url=source_url,
            headers={"Authorization": "Bearer raw", "X-Raw-Auth": "raw"},
            session=trusted,
        )
    finally:
        source.shutdown()
        source_thread.join(timeout=2)
        source.server_close()
        sink.shutdown()
        sink_thread.join(timeout=2)
        sink.server_close()

    assert source_headers[0]["Authorization"] == "Bearer raw"
    assert "Authorization" not in sink_headers[0]
    assert "Cookie" not in sink_headers[0]
    assert "X-Raw-Auth" not in sink_headers[0]
    assert sink_headers[1]["Authorization"] == "Bearer session"
    assert sink_headers[1]["Cookie"] == "sid=session"
    assert "X-Raw-Auth" not in sink_headers[1]


def test_cli_auth_file_builds_session_and_raw_header_keeps_precedence(runner_store, monkeypatch, tmp_path, capsys):
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps({"target": "target.test", "bearer": "session-token"}),
        encoding="utf-8",
    )
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"result": "tested_clean"}

    spec_path = tmp_path / "check-spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline_request": {"method": "GET", "url": "https://target.test/check"},
                "variant_request": {
                    "method": "GET",
                    "url": "https://target.test/check",
                    "headers": {"Authorization": "Bearer denied"},
                },
                "active_dimension": "header:Authorization",
                "classifier": "generic",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(validation_runner, "run_request_diff", fake_run)
    assert validation_runner.main([
        "request-diff",
        "--repo-root", str(tmp_path),
        "--target",
        "target.test",
        "--request-spec",
        str(spec_path),
        "--auth-file",
        str(auth),
        "--header",
        "Authorization: Bearer raw-token",
        "--no-ledger",
        "--no-sync",
    ]) == 0
    capsys.readouterr()

    assert validation_runner._request_headers(
        captured["session"],
        "https://target.test/check",
        captured["headers"],
    )["Authorization"] == "Bearer raw-token"


def test_request_once_bounds_response_and_records_hash(monkeypatch):
    class FakeResponse:
        status = 200
        reason = "OK"
        headers = {"Content-Type": "text/plain", "Content-Length": "6"}

        def geturl(self):
            return "https://target.test/api"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, amount):
            assert amount == 5
            return b"abcde"

    class FakeOpener:
        def open(self, request, timeout):
            return FakeResponse()

    monkeypatch.setattr(validation_runner.urllib.request, "build_opener", lambda *args: FakeOpener())
    response = validation_runner.request_once(
        target="target.test",
        url="https://target.test/api",
        max_body_bytes=4,
    )
    snapshot = validation_runner._response_snapshot(response)

    assert response["body"] == "abcd"
    assert response["body_retained_bytes"] == 4
    assert response["body_observed_bytes"] == 6
    assert response["body_truncated"] is True
    assert snapshot["body_truncated"] is True
    assert snapshot["body_sha256"] == validation_runner.hashlib.sha256(b"abcd").hexdigest()
    assert "body_preview" not in snapshot


def test_state_changing_without_redline_fails_before_request(runner_store, monkeypatch, tmp_path):
    called = False

    def fake_request_once(**kwargs):
        nonlocal called
        called = True
        return _fake_response(kwargs["url"], body="MARKER")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    with pytest.raises(ValueError, match="requires --redline-checked"):
        validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="target.test",
            request_spec={
                "schema_version": 1,
                "baseline_request": {"method": "POST", "url": "https://target.test/submit", "body": "a"},
                "variant_request": {"method": "POST", "url": "https://target.test/submit", "body": "b"},
                "active_dimension": "body:",
                "classifier": "generic",
            },
            state_changing=True,
            redline_checked=False,
        )
    assert called is False


@pytest.mark.parametrize("state_changing", [None, False])
def test_patch_without_explicit_state_fact_is_not_redline_blocked(runner_store,
    monkeypatch, tmp_path, state_changing
):
    called = False

    def fake_request_once(**kwargs):
        nonlocal called
        called = True
        return _fake_response(kwargs["url"], body="MARKER")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="target.test",
        request_spec={
            "schema_version": 1,
            "baseline_request": {"method": "PATCH", "url": "https://target.test/submit", "body": "a"},
            "variant_request": {"method": "PATCH", "url": "https://target.test/submit", "body": "b"},
            "active_dimension": "body:",
            "classifier": "generic",
        },
        state_changing=state_changing,
        no_ledger=True,
    )
    assert called is True
    assert summary["state_changing"] is state_changing
    assert summary["redline_checked"] is False


def test_post_defaults_to_unknown_state_and_private_unique_runs(runner_store, monkeypatch, tmp_path):
    secret = "SECRET_VALIDATION_FIXTURE"
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=f"result={secret}"),
    )

    summaries = [
        validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="target.test",
            request_spec={
                "schema_version": 1,
                "baseline_request": {
                    "method": "POST",
                    "url": "https://target.test/submit",
                    "headers": {"Authorization": f"Bearer {secret}"},
                    "body": secret,
                },
                "variant_request": {
                    "method": "POST",
                    "url": f"https://target.test/submit?token={secret}",
                    "headers": {"Authorization": f"Bearer {secret}"},
                    "body": secret,
                },
                "active_dimension": "query:token",
                "classifier": "generic",
            },
            finding_id="MARKER-PRIVATE",
            no_ledger=True,
        )
        for _ in range(2)
    ]

    assert summaries[0]["summary_path"] != summaries[1]["summary_path"]
    assert summaries[0]["attempt_id"] != summaries[1]["attempt_id"]
    assert all(item["state_changing"] is None for item in summaries)
    assert all(item["redline_checked"] is False for item in summaries)
    public_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in (tmp_path / "evidence").rglob("*")
        if path.is_file()
    )
    private_files = [path for path in (tmp_path / ".private").rglob("*") if path.is_file()]
    private_bytes = b"\n".join(path.read_bytes() for path in private_files)

    assert secret not in public_text
    assert secret.encode() in private_bytes
    assert private_files
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in private_files)
    assert all(
        path.stat().st_mode & 0o777 == 0o700
        for path in (tmp_path / ".private").rglob("*")
        if path.is_dir()
    )


def _boundary_pair_spec(active: str, baseline_header: dict, variant_header: dict) -> dict:
    return {
        "schema_version": 1,
        "baseline_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": baseline_header,
        },
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": variant_header,
        },
        "active_dimension": active,
        "evidence_shape": "request_diff",
        "classifier": "authz",
        "repeat": 2,
    }


def test_request_diff_credential_boundary_dimension_promotes_without_shape_detector(runner_store, monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        headers = kwargs.get("headers") or {}
        if "Bearer admin" in str(headers.get("Authorization", "")):
            return _fake_response(kwargs["url"], body='{"users": ["a", "b"]}')
        return _fake_response(kwargs["url"], status=401, body="unauthorized")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = _boundary_pair_spec(
        "header:authorization",
        {},
        {"Authorization": "Bearer admin"},
    )
    # Declared expectation: the credential dimension differentiates the
    # requesters (status delta observed). Reconciliation, not a vocabulary.
    spec["expected"] = ["status_delta"]
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    operation = runner_store.execution(summary["store_operation_id"])
    assert all(row["result"] == "tested_finding" for row in operation["observations"])

    # Undeclared, the same pair keeps the legacy conservative outcome.
    spec.pop("expected")
    undeclared = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert undeclared["result"] == "candidate"


def test_request_diff_declared_boundary_without_actual_difference_stays_candidate(runner_store, monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        headers = kwargs.get("headers") or {}
        # Both requests carry the same declared credential, but the response
        # differs for an unrelated reason (still material).
        marker = "Bearer same"
        body = (
            '{"users": ["a"], "note": "one short body"}'
            if str(headers.get("Authorization", "")).endswith(marker)
            else '{"users": ["a"], "note": "a materially longer unrelated response body"}'
        )
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": {"Authorization": "Bearer same", "X-Tag": "one"},
        },
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": {"Authorization": "Bearer same", "X-Tag": "two"},
        },
        "active_dimension": "header:authorization",
        "evidence_shape": "request_diff",
        "classifier": "authz",
        "repeat": 2,
    }
    # The spec validator enforces that the declared active dimension is the
    # one that actually changed; a mismatched declaration is a hard input
    # error and is rejected before any replay rather than silently re-labeled.
    with pytest.raises(validation_runner.RequestPairError):
        validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="https://target.test",
            request_spec=spec,
        )


def test_request_diff_non_boundary_material_diff_stays_candidate(runner_store, monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        body = '{"page": 1, "items": []}' if "page=1" in kwargs["url"] else '{"page": 2, "items": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?page=1"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?page=2"},
        "active_dimension": "query:page",
        "evidence_shape": "request_diff",
        "classifier": "authz",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False


def test_request_diff_sqli_material_diff_without_strong_shape_is_candidate_not_clean(runner_store, monkeypatch, tmp_path):
    """A material diff must never fall to tested_clean just because the
    classifier label is sqli but the shape detector did not confirm."""

    def fake_request_once(**kwargs):
        # Material length delta but no DB-error/count-expansion/field-added
        # shape: the SQLi detector stays quiet, so a bare material diff must
        # not be promoted and must not fall to tested_clean either.
        body = '{"result": "no rows for this very ordinary baseline query response"}' if "zzz" not in kwargs["url"] else '{"result": "still no rows but a materially much longer ordinary response body padding padding padding"}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?q=zzz"},
        "active_dimension": "query:q",
        "evidence_shape": "request_diff",
        "classifier": "sqli",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False


def test_request_diff_credential_pair_both_sides_succeed_stays_candidate_not_clean(runner_store, monkeypatch, tmp_path):
    """Anonymous 200 + denied-credential 200 with identical bodies means the
    endpoint performs no identity check. That pair must stay a reviewable
    candidate; recording tested_clean would invert the meaning."""

    def fake_request_once(**kwargs):
        body = '{"config": {"chatbot": "shared"}}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/admin/application-configuration"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/rest/admin/application-configuration",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate", (
        "identical 200 responses across a credential boundary are the evidence "
        "of a missing identity check, not a clean auth boundary"
    )


def test_request_diff_missing_auth_expect_auth_pair_promotes_to_tested_finding(runner_store, monkeypatch, tmp_path):
    """Identical 200s across a credential boundary plus an explicit
    expect_auth declaration promote through the missing-auth route: the
    runner asserts the fact (the endpoint does not differentiate requesters)
    and leaves the intent judgment to review."""

    def fake_request_once(**kwargs):
        body = '{"config": {"chatbot": "shared"}}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/admin/application-configuration"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/rest/admin/application-configuration",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["vuln_class"] == "Authz"
    assert "evidence_rubric" not in summary
    assert "ai_next" not in summary
    spec_view = summary.get("request_pair") or {}
    assert spec_view.get("expect_auth") is True
    assert summary["expected_check"]["declared"] == ["identical_success_pair"]
    assert summary["expected_check"]["unmet"] == []
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    operation = runner_store.execution(summary["store_operation_id"])
    assert all(row["result"] == "tested_finding" for row in operation["observations"])


def test_request_diff_expect_auth_trusts_arbitrary_declared_dimension(runner_store, monkeypatch, tmp_path):
    """When the AI declares expect_auth, the declared active dimension IS the
    credential boundary. The runner must not second-guess the header name
    against a fixed well-known vocabulary: custom auth headers
    (X-Internal-Auth, X-Company-Token, ...) promote exactly like
    Authorization. The vocabulary only serves the undeclared default path."""

    def fake_request_once(**kwargs):
        body = '{"internal": {"config": "shared"}}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/internal/config"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/internal/config",
            "headers": {"X-Internal-Auth": "Bearer denied"},
        },
        "active_dimension": "header:X-Internal-Auth",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True

    # Without the declaration the same custom-header pair has no
    # AI-asserted boundary meaning: an ordinary header value that does not
    # change the response is clean for that dimension (same semantics as an
    # ineffective probe). The well-known vocabulary (Authorization & co.)
    # keeps its extra undeclared-candidate conservatism.
    spec.pop("expect_auth")
    summary_undeclared = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary_undeclared["result"] == "candidate"
    assert summary_undeclared["candidate_ready"] is False


def test_request_diff_expected_declaration_is_category_agnostic(runner_store, monkeypatch, tmp_path):
    """The same error-marker declaration promotes a NoSQLi pair and a
    SQLi pair through the identical channel — and would promote an SSTI or
    command-injection pair the same way. classifier is metadata only."""

    def fake_request_once(**kwargs):
        body = kwargs["body"]
        query = body.get("q", "") if isinstance(body, dict) else ""
        if query != "apple":
            return _fake_response(
                kwargs["url"], status=500, body='{"error": "MongoError: CastError in query"}'
            )
        return _fake_response(kwargs["url"], body='{"data": []}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    for classifier, vuln_class, variant_query in (
        ("nosqli", "NoSQLi", '{"$ne": null}'),
        ("sqli", "SQLi", "' || true || '"),
        ("ssti", "RCE", "{{7*7}}"),
    ):
        spec = {
            "schema_version": 1,
            "baseline_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"q": "apple"},
            },
            "variant_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"q": variant_query},
            },
            "active_dimension": "body:/q",
            "evidence_shape": "request_diff",
            "classifier": classifier,
            "vuln_class": vuln_class,
            "expected": ["error_marker_variant_only"],
            "repeat": 1,
        }
        summary = validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="https://target.test",
            request_spec=spec,
            finding_id=f"EXPECTED-AGNOSTIC-{classifier}",
        )
        assert summary["result"] == "tested_finding", classifier
        assert summary["candidate_ready"] is True
        assert summary["expected_check"]["unmet"] == []


def test_request_diff_declared_expectation_contradicted_falls_to_candidate(runner_store, monkeypatch, tmp_path):
    """Anti-forgery: the AI declares a count expansion, the wire shows none —
    the declaration is rejected, the unmet fact is archived, and the result
    never becomes tested_finding on an unconfirmed declaration."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], body='{"data": [{"id": 1}]}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?q=zzz"},
        "active_dimension": "query:q",
        "evidence_shape": "request_diff",
        "classifier": "sqli",
        "expected": ["count_delta_positive", "fields_added"],
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["expected_check"]["unmet"] == ["count_delta_positive", "fields_added"]
    assert summary["expected_check"]["observed"] == {
        "count_delta_positive": False,
        "fields_added": False,
    }


def test_request_diff_unknown_expected_fact_name_is_rejected(runner_store, tmp_path):
    """A typo in a declared fact name is a hard input error, never silently
    ignored — a silently-dropped declaration would silently demote the pair."""

    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?q=zzz"},
        "active_dimension": "query:q",
        "classifier": "sqli",
        "expected": ["count_delta_postive"],  # typo
        "repeat": 1,
    }
    with pytest.raises(validation_runner.RequestPairError, match="unknown fact name"):
        validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="https://target.test",
            request_spec=spec,
        )


def test_request_diff_expected_note_and_digest_distinction(tmp_path):
    """expected/expected_note ride the normalized spec: declaring an
    expectation makes the replay a distinct operation, and the note is
    archived verbatim without being interpreted."""

    base = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/a"},
        "variant_request": {"method": "GET", "url": "https://target.test/b"},
        "active_dimension": "path:",
        "classifier": "generic",
    }
    # path: dimension needs different paths
    base["baseline_request"]["url"] = "https://target.test/users/1"
    base["variant_request"]["url"] = "https://target.test/users/2"
    base["active_dimension"] = "path:/users/1"
    normalized = validate_request_pair(base)
    assert normalized["expected"] == []
    assert normalized["expected_note"] == ""

    declared = dict(base, expected=["material_diff_any"], expected_note="owner swap should change the row")
    normalized_declared = validate_request_pair(declared)
    assert normalized_declared["expected"] == ["material_diff_any"]
    assert normalized_declared["expected_note"] == "owner swap should change the row"

    assert request_pair_digest(declared) != request_pair_digest(base)


def test_request_diff_missing_auth_pair_with_3xx_both_sides_promotes(runner_store, monkeypatch, tmp_path):
    """The success class is 2xx/3xx: redirects on both sides still count as
    'the endpoint answered both requesters' for the missing-auth route."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], status=302, body="")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Cookie": "session=denied"},
        },
        "active_dimension": "cookie:session",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True


def test_request_diff_missing_auth_declaration_alone_does_not_override_held_boundary(runner_store, monkeypatch, tmp_path):
    """expect_auth is a declaration, not a verdict: when the boundary held
    (both sides rejected identically) the declared identical-success fact is
    CONTRADICTED on the wire, so the pair falls to candidate with the unmet
    fact archived — the declaration never manufactures a finding, and the
    contradiction is surfaced instead of silently cleaned."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], status=401, body='{"error": "unauthorized"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Cookie": "session=denied"},
        },
        "active_dimension": "cookie:session",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["expected_check"]["declared"] == ["identical_success_pair"]
    assert summary["expected_check"]["unmet"] == ["identical_success_pair"]


def test_request_diff_equal_rejections_require_explicit_clean_declaration(runner_store, monkeypatch, tmp_path):
    """Equal rejections remain unresolved unless a clean expectation was declared."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], status=401, body='{"error": "unauthorized"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    spec["expected"] = ["both_sides_rejected"]
    spec["declaration_intent"] = "clean"
    declared = validation_runner.run_request_diff(repo_root=tmp_path, target="https://target.test", request_spec=spec)
    assert declared["result"] == "tested_clean"
    assert declared["expected_check"]["unmet"] == []


def test_request_pair_rejects_unknown_vuln_class_before_replay(tmp_path):
    """Exposure/未知拼写必须在 spec 校验期硬失败，而不是 replay 后静默跳写 Ledger。"""
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/basket/1"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/rest/basket/2",
        },
        "active_dimension": "path:/rest/basket/2",
        "classifier": "authz_access",
        "vuln_class": "Exposure",
        "expected": ["identical_success_pair"],
    }
    with pytest.raises(RequestPairError, match="vuln_class must be a canonical closure family"):
        validate_request_pair(spec)
    # 已知拼写（含别名形态）照常通过，并原样进入归一化 spec。
    spec["vuln_class"] = "authz"
    normalized = validate_request_pair(spec)
    assert normalized["vuln_class"] == "authz"


# ---------------------------------------------------------------------------
# record-evidence: register already-executed native observations
# ---------------------------------------------------------------------------


def _native_fixture(tmp_path, *, url="https://target.test/rest/orders/1", finding_id="NATIVE-EVID-1",
                    family="Authz", preview=False):
    """Create a canonical candidate finding + recorded raw artifacts for native registration."""
    target = "https://target.test"
    key = _target_key(target)
    store = TargetStore(tmp_path, target, allow_preview=preview)
    store.initialize(allow_legacy=preview)
    store.create_finding(
        command_id="native-finding", finding_id=finding_id, endpoint=url,
        method="POST", family=family, title="Native fixture",
        claim="Recorded peer transition", actor="operator",
    )
    artifacts_dir = tmp_path / ".private" / "validation" / key / finding_id
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for name, body in (
        ("control.request.txt", "POST /rest/orders/1 HTTP/1.1\r\n\r\n"),
        ("control.response.txt", "HTTP/1.1 200 OK\r\n\r\n{}"),
        ("transition.request.bin", "POST /rest/orders/1 HTTP/1.1\r\nX-Actor: peer\r\n\r\n"),
        ("transition.response.txt", "HTTP/1.1 200 OK\r\n\r\n{\"state\":\"mutated\"}"),
    ):
        path = artifacts_dir / name
        path.write_text(body, encoding="utf-8")
        artifacts[name] = str(path.relative_to(tmp_path))
    evidence = {
        "schema_version": 1,
        "source": "browser",
        "attempt_id": "native-fixture-attempt",
        "generated_at": "2026-09-16T10:00:00Z",
        "result": "tested_finding",
        "observed_difference": "Peer actor transitioned the recorded state; the control did not.",
        "runs": [
            {
                "url": url,
                "method": "POST",
                "actor": "owner",
                "artifacts": {
                    "request": artifacts["control.request.txt"],
                    "response": artifacts["control.response.txt"],
                },
            },
            {
                "url": url,
                "method": "POST",
                "actor": "peer",
                "object_scope": "other_object_same_org",
                "variant": "replay",
                "artifacts": {
                    "request": artifacts["transition.request.bin"],
                    "response": artifacts["transition.response.txt"],
                },
            },
        ],
    }
    return target, finding_id, evidence


def test_record_evidence_binds_native_observation_to_runner_witness(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    assert summary["lane"] == "native_evidence"
    assert summary["evidence_shape"] == "native"
    assert summary["assessment_source"] == "ai"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["url"] == "https://target.test/rest/orders/1"
    assert summary["method"] == "POST"
    # artifacts stay raw; they are not rewritten into a request-diff pair
    assert summary["runs"][0]["method"] == "POST"
    assert summary["runs"][0]["artifact_sha256"]["request"]
    assert Path(tmp_path / summary["summary_path"]).is_file()


def test_primary_record_evidence_registers_store_operation_without_legacy_writer(tmp_path, monkeypatch):
    target, finding_id = "https://target.test", "NATIVE-PRIMARY-1"
    key = _target_key(target)
    artifacts_dir = tmp_path / ".private" / "validation" / key / finding_id
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for name, body in (("request.txt", "POST /orders/1 HTTP/1.1\n"), ("response.txt", "HTTP/1.1 200 OK\n\nfixture")):
        path = artifacts_dir / name
        path.write_text(body, encoding="utf-8")
        artifacts[name.split(".")[0]] = str(path.relative_to(tmp_path))
    evidence = {
        "schema_version": 1, "source": "browser", "generated_at": "2026-09-16T10:00:00Z",
        "result": "tested_finding", "observed_difference": "peer actor observed the object",
        "attempt_id": "native-attempt-1", "runs": [{"url": "https://target.test/orders/1", "method": "POST",
        "actor": "peer", "artifacts": artifacts}],
    }
    for writer in ("record_entry", "upsert_finding", "update_finding_status", "save_queue"):
        assert not hasattr(validation_runner, writer), writer
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="seed-finding", finding_id=finding_id,
        endpoint=evidence["runs"][0]["url"], method="POST", family="Authz",
        title="Native fixture", claim="Recorded actor crossed the boundary", actor="operator",
    )
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    sync = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert sync["status"] == "updated"
    assert summary["store_operation_id"].startswith("operation:")
    assert store.finding(finding_id)["evidence"]
    assert store.execution(summary["store_operation_id"])["attempt"]["id"] == evidence["attempt_id"]

    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert replay["status"] == "deduplicated"
    assert store.page("operations")["total"] == 1


def _claimed_runner_store(root, *, kind="execution"):
    store = TargetStore(root, "target.test")
    store.initialize()
    store.create_finding(
        command_id="finding", finding_id="F-claim", endpoint="https://target.test/api/users",
        method="GET", family="Authz", title="Recorded boundary", claim="Peer read owner data", actor="operator",
    )
    subject = {"endpoint": "https://target.test/api/users", "family": "Authz"} if kind == "execution" else {
        "subject": {"target": "target.test"},
    }
    store.create_action(command_id="action", action_id="A-claim", kind=kind,
                        intent="Compare the recorded actors", execution_key="actor-check", actor="operator", **subject)
    store.transition_action(command_id="claim", action_id="A-claim", expected_version=1,
                            status="claimed", actor="operator")
    raw = root / "evidence" / "target.test" / "native"
    raw.mkdir(parents=True)
    artifacts = {}
    for name, body in (("request", "GET /api/users HTTP/1.1\n"), ("response", "HTTP/1.1 200 OK\n\nowner fixture")):
        path = raw / f"{name}.txt"
        path.write_text(body, encoding="utf-8")
        artifacts[name] = path.relative_to(root).as_posix()
    evidence = {
        "schema_version": 1, "source": "native-fixture", "generated_at": "2026-09-24T00:00:00.123456Z",
        "attempt_id": "native-attempt", "result": "tested_finding", "observed_difference": "Peer received owner fixture",
        "runs": [{"url": "https://target.test/api/users", "method": "GET", "actor": "peer", "artifacts": artifacts}],
    }
    return store, evidence


def _complete_fixture_decision(decision):
    decision["impact"] = "The fixture peer read owner-only data."
    decision["severity"] = "high"
    for gate in decision["gates"].values():
        gate.update(passed=True, notes={"source": "fixture observations"})
    for question in decision["seven_question_gate"]["questions"].values():
        question.update(status="pass", basis="The controlled fixture supports this gate.")
    decision["evidence"]["summary"] = "Peer observation of the owner fixture."
    decision["report"]["content"] = "# Fixture boundary report\n\nSeverity: high\n\nThe peer received owner-only fixture data.\n"
    return decision


def _primary_validation_fixture(root, capsys):
    import validate

    store, evidence = _claimed_runner_store(root)
    summary = validation_runner.record_native_evidence(
        repo_root=root, target="target.test", finding_id="F-claim", evidence=evidence,
        action_id="A-claim", claim_token="claim", command_actor="operator", state_changing=False,
    )
    assert validation_runner.sync_runner_artifacts(summary, repo_root=root)["status"] == "updated"
    (root / summary["summary_path"]).write_text(json.dumps(summary), encoding="utf-8")
    args = ["--findings-dir", str(root / "findings" / "target.test"),
            "--target", "target.test", "--finding-id", "F-claim", "--json"]
    assert validate.main([*args, "--scaffold"]) == 0
    decision = _complete_fixture_decision(json.loads(capsys.readouterr().out))
    decision_path = root / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    return store, summary, decision, decision_path, [*args, "--decision-json", str(decision_path)]


@pytest.mark.parametrize("stage", ["assess", "decide_delivery", "register_report"])
def test_primary_validation_retries_only_uncommitted_judgment(tmp_path, monkeypatch, capsys, stage):
    import validate

    store, summary, decision, decision_path, args = _primary_validation_fixture(tmp_path, capsys)
    before = store.binding()
    with monkeypatch.context() as failure:
        def interrupted(*a, **kw):
            raise validate.StoreError("fixture interrupted judgment")
        failure.setattr(type(validate.runtime_store(tmp_path, "target.test")), stage, interrupted)
        assert validate.main(args) == 2
        assert json.loads(capsys.readouterr().out)["retry"] is True
    partial = store.finding("F-claim")
    assert bool(partial["assessment"]) is (stage != "assess")
    assert bool(partial["deliveries"]) is (stage == "register_report")
    assert partial["reports"] == []
    assert (tmp_path / decision["report"]["path"]).is_file()
    assert validate.main(args) == 0
    assert json.loads(capsys.readouterr().out)["validation_sync"]["status"] == (
        "deduplicated" if stage == "register_report" else "updated"
    )
    completed = store.finding("F-claim")
    if stage == "decide_delivery":
        assert completed["assessment"]["id"] == partial["assessment"]["id"]
    assert store.binding()["revision"] == before["revision"] + 3
    assert store.action("A-claim")["status"] == "claimed"
    binding = store.binding()
    assert validate.main(args) == 0
    replayed = json.loads(capsys.readouterr().out)
    assert replayed["validation_sync"]["status"] == "deduplicated"
    saved = json.loads(Path(replayed["summary_path"]).read_text())
    saved["validated_at"] = "2099-01-01T00:00:00Z"
    assert validate.apply_validation_decision(saved, repo_root=tmp_path)["status"] == "deduplicated"
    assert store.binding() == binding

    decision["impact"] = "A revised boundary interpretation."
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    assert validate.main([*args, "--preflight"]) == 2
    assert "assessment changed" in " ".join(json.loads(capsys.readouterr().out)["errors"])
    assert store.binding() == binding
    decision["store_preconditions"] = {
        "assessment_id": completed["assessment"]["id"], "delivery_id": completed["deliveries"][0]["id"],
    }
    decision["report"]["path"] = "findings/target.test/revised-report.md"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    assert validate.main([*args, "--preflight"]) == 0
    capsys.readouterr()
    assert validate.main(args) == 0
    capsys.readouterr()
    revised = store.finding("F-claim")
    assert revised["assessment"]["id"] != completed["assessment"]["id"]
    assert revised["deliveries"][0]["assessment_id"] == revised["assessment"]["id"]
    assert store.binding()["revision"] == binding["revision"] + 3


@pytest.mark.parametrize("damage", ["tampered", "foreign-operation", "partial-operation", "bad-preconditions",
                                   "severity-conflict", "severity-missing"])
def test_primary_validation_preflight_rejects_invalid_proof_without_writes(tmp_path, capsys, damage):
    import validate

    store, summary, decision, decision_path, args = _primary_validation_fixture(tmp_path, capsys)
    if damage == "tampered":
        (tmp_path / summary["runs"][0]["artifacts"]["response"]).write_text("changed fixture")
    elif damage == "bad-preconditions":
        decision["store_preconditions"] = {"assessment_id": []}
        decision_path.write_text(json.dumps(decision), encoding="utf-8")
    elif damage.startswith("severity-"):
        decision["report"]["content"] = "# Fixture\n" + ("Severity: low\n" if damage == "severity-conflict" else "")
        decision_path.write_text(json.dumps(decision), encoding="utf-8")
    else:
        store.start_attempt(attempt_id="other", source="fixture", started_at="2026-09-24T00:00:00Z", actor="operator")
        observation = {
            "endpoint": "https://target.test/api/users", "method": "GET", "family": "Authz",
            "observed_at": "2026-09-24T00:00:00Z", "description": "Other recorded attempt",
            "artifacts": summary["runs"][0]["artifacts"],
        }
        receipt = store.record_execution(attempt_id="other", outcome="partial" if damage == "partial-operation" else "complete",
                                         observations=[observation], actor="operator")
        summary["store_operation_id"] = receipt["entity_id"]
        (tmp_path / summary["summary_path"]).write_text(json.dumps(summary), encoding="utf-8")
    binding = store.binding()
    assert validate.main([*args, "--preflight"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "preflight_invalid"
    assert result["errors"]
    assert not (tmp_path / decision["report"]["path"]).exists()
    assert store.finding("F-claim")["assessment"] is None
    assert store.binding() == binding


def test_primary_validation_assesses_only_the_selected_operation(tmp_path, capsys):
    import validate

    store, summary, _, _, args = _primary_validation_fixture(tmp_path, capsys)
    finding = store.finding("F-claim")
    store.start_attempt(attempt_id="incomplete", source="fixture", started_at="2026-09-24T00:00:00Z", actor="operator")
    store.record_execution(attempt_id="incomplete", outcome="partial", actor="operator", observations=[{
        "endpoint": finding["endpoint"], "method": finding["method"], "family": finding["family"],
        "observed_at": "2026-09-24T00:00:00Z", "description": "A different incomplete experiment",
        "artifacts": {"request": summary["runs"][0]["artifacts"]["request"]}, "error": "interrupted",
    }], candidate={key: finding[key] for key in ("id", "endpoint", "method", "family", "title", "claim")})
    assert len(store.finding("F-claim")["evidence"]) == 2
    assert validate.main(args) == 0
    capsys.readouterr()
    assert store.finding("F-claim")["assessment"]["verdict"] == "confirmed"
    assert store.page("operations")["total"] == 2


@pytest.mark.parametrize(("gate", "status", "verdict", "delivery"), [
    ("gate4", False, "confirmed", "ineligible"),
    ("q5_not_known_behavior", "fail", "confirmed", "ineligible"),
    ("q7_not_never_submit", "fail", "confirmed", "ineligible"),
    ("q5_not_known_behavior", "unknown", "confirmed", "deferred"),
    ("q6_impact_beyond_possible", "fail", "inconclusive", "deferred"),
    ("gate3", False, "inconclusive", "deferred"),
])
def test_primary_validation_separates_technical_and_delivery_judgments(tmp_path, capsys, gate, status, verdict, delivery):
    import report_generator
    import validate

    store, _, decision, decision_path, args = _primary_validation_fixture(tmp_path, capsys)
    if gate.startswith("gate"):
        decision["gates"][gate]["passed"] = status
    else:
        decision["seven_question_gate"]["questions"][gate].update(status=status, basis="Explicit fixture judgment")
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    assert validate.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    finding = store.finding("F-claim")
    assert finding["assessment"]["verdict"] == verdict
    assert finding["deliveries"][0]["status"] == delivery
    summary = json.loads(Path(result["summary_path"]).read_text())
    assert summary["validation_evidence_passed"] is (verdict == "confirmed")
    assert summary["report_ready"] is False
    assert summary["delivery_judgment"]["status"] == delivery
    binding = store.binding()
    total, _ = report_generator.process_findings_dir(tmp_path / "findings" / "target.test")
    assert total == 0
    assert store.binding() == binding
    assert finding["reports"] == []
    assert store.action("A-claim")["status"] == "claimed"


@pytest.mark.parametrize("lane", ["native", "request"])
@pytest.mark.parametrize("invalid", ["missing-token", "missing-action", "wrong-token", "wrong-actor", "work", "released", "endpoint", "family"])
def test_primary_runner_rejects_invalid_claim_before_side_effects(tmp_path, monkeypatch, lane, invalid):
    store, evidence = _claimed_runner_store(tmp_path, kind="work" if invalid == "work" else "execution")
    args = {"action_id": "A-claim", "claim_token": "claim", "command_actor": "operator"}
    if invalid == "missing-token":
        args.pop("claim_token")
    elif invalid == "missing-action":
        args.pop("action_id")
    elif invalid == "wrong-token":
        args["claim_token"] = "another-claim"
    elif invalid == "wrong-actor":
        args["command_actor"] = "another-operator"
    elif invalid == "released":
        store.transition_action(command_id="release", action_id="A-claim", expected_version=2,
                                status="ready", actor="operator", reason="Changed conditions", claim_token="claim")
    if invalid in {"endpoint", "family"}:
        subject = {"endpoint": "https://target.test/other" if invalid == "endpoint" else "https://target.test/api/users",
                   "family": "sqli" if invalid == "family" else "Authz"}
        store.create_action(command_id="other-action", action_id="A-other", intent="Another experiment",
                            execution_key="another-check", actor="operator", **subject)
        store.transition_action(command_id="other-claim", action_id="A-other", expected_version=1,
                                status="claimed", actor="operator")
        args.update(action_id="A-other", claim_token="other-claim")
    monkeypatch.setattr(validation_runner, "request_once", lambda **kw: pytest.fail("invalid claim reached network"))
    binding = store.binding()
    raw_before = {p.relative_to(tmp_path): p.read_bytes() for p in (tmp_path / "evidence").rglob("*") if p.is_file()}
    with pytest.raises(StoreError):
        if lane == "native":
            validation_runner.record_native_evidence(repo_root=tmp_path, target="target.test", finding_id="F-claim",
                                                     evidence=evidence, **args)
        else:
            validation_runner.run_request_diff(repo_root=tmp_path, target="target.test", finding_id="F-new",
                                                request_spec=_expect_auth_pair_spec(), **args)
    assert store.binding() == binding
    assert {p.relative_to(tmp_path): p.read_bytes() for p in (tmp_path / "evidence").rglob("*") if p.is_file()} == raw_before
    assert not (tmp_path / ".private").exists()
    assert store.page("findings")["total"] == 1


@pytest.mark.parametrize("responses", [0, 1, 2])
def test_primary_request_claim_survives_partial_registration_and_retry(tmp_path, monkeypatch, responses):
    store, _ = _claimed_runner_store(tmp_path)
    calls = []

    def request(**kwargs):
        calls.append(kwargs)
        if len(calls) > responses:
            raise OSError("fixture transport interruption")
        return _fake_response(kwargs["url"], body=f"fixture {len(calls)}")

    monkeypatch.setattr(validation_runner, "request_once", request)
    monkeypatch.setattr(validation_runner, "now_utc", lambda: "2026-09-24T00:00:00Z")
    args = dict(repo_root=tmp_path, target="target.test", finding_id="F-claim", request_spec=_expect_auth_pair_spec(),
                action_id="A-claim", claim_token="claim", command_actor="operator", attempt_id="request-attempt")
    summary = validation_runner.run_request_diff(**args)
    binding = store.binding()
    with pytest.raises(StoreError, match="attempt already started"):
        validation_runner.run_request_diff(**args)
    assert len(calls) == min(responses + 1, 2)
    assert store.binding() == binding
    saved = json.loads((tmp_path / summary["summary_path"]).read_text())
    with monkeypatch.context() as failure:
        def reject_registration(*a, **kw):
            raise OSError("fixture registration interruption")
        failure.setattr(validation_runner, "_record_primary_execution", reject_registration)
        assert validation_runner.sync_runner_artifacts(saved, repo_root=tmp_path)["status"] == "partial"
    assert store.binding() == binding
    assert validation_runner.sync_runner_artifacts(saved, repo_root=tmp_path)["status"] == "updated"
    operation = store.execution(saved["store_operation_id"])
    assert operation["attempt"]["action_id"] == "A-claim"
    assert operation["attempt"]["claim_token"] == "claim"
    assert operation["outcome"] == ("unknown", "partial", "complete")[responses]
    assert store.action("A-claim")["status"] == "claimed"
    binding = store.binding()
    assert validation_runner.sync_runner_artifacts(saved, repo_root=tmp_path)["status"] == "deduplicated"
    assert store.binding() == binding
    completion = dict(command_id="complete", action_id="A-claim", expected_version=2,
                      status="completed", actor="operator", reason="Recorded execution", claim_token="claim",
                      completion={"operation_id": saved["store_operation_id"]})
    if responses == 2:
        store.transition_action(**completion)
        assert store.action("A-claim")["status"] == "completed"
    else:
        with pytest.raises(StoreError, match="complete observation"):
            store.transition_action(**completion)


def test_primary_native_claim_cli_through_validation_report_and_resume(tmp_path):
    import subprocess
    import sys

    root = tmp_path / "isolated root"
    store, evidence = _claimed_runner_store(root)
    tools = Path(__file__).resolve().parents[1] / "tools"

    def cli(tool, *args):
        result = subprocess.run([sys.executable, "-B", str(tools / tool), *map(str, args)],
                                text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        return json.loads(result.stdout)

    evidence_path = root / "observations.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    args = ("record-evidence", "--repo-root", root, "--target", "target.test", "--finding-id", "F-claim",
            "--evidence-json", evidence_path, "--action-id", "A-claim", "--claim-token", "claim",
            "--actor", "operator", "--no-state-changing", "--json")
    pending = cli("validation_runner.py", *args, "--no-sync")
    assert store.page("operations")["total"] == 0
    assert (root / pending["summary_path"]).is_file()
    summary = cli("validation_runner.py", *args)
    operation_id = summary["store_operation_id"]
    execution = store.execution(operation_id)
    assert execution["attempt"]["action_id"] == "A-claim"
    assert execution["attempt"]["claim_token"] == "claim"
    assert execution["observations"][0]["actor"] == "peer"
    assert execution["observations"][0]["observed_at"].endswith(".123456+00:00")
    assert store.action("A-claim")["status"] == "claimed"

    validate_args = ("--findings-dir", root / "findings" / "target.test", "--target", "target.test",
                     "--finding-id", "F-claim", "--json")
    binding = store.binding()
    decision = cli("validate.py", *validate_args, "--scaffold")
    assert decision["evidence"]["runner_summary"] == summary["summary_path"]
    assert decision["vuln_class"] == "Authz"
    _complete_fixture_decision(decision)
    decision_path = root / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    assert cli("validate.py", *validate_args, "--decision-json", decision_path, "--preflight")["status"] == "preflight_ok"
    assert store.binding() == binding
    result = cli("validate.py", *validate_args, "--decision-json", decision_path)
    finding = store.finding("F-claim")
    assert finding["assessment"]["verdict"] == "confirmed"
    assert finding["deliveries"][0]["status"] == "eligible"
    assert len(finding["reports"]) == 1
    assert Path(result["report_path"]).read_text() == decision["report"]["content"]
    generated = subprocess.run([sys.executable, "-B", str(tools / "report_generator.py"),
                                str(root / "findings" / "target.test")],
                               text=True, capture_output=True, timeout=30)
    assert generated.returncode == 0, generated.stdout + generated.stderr
    reports = store.finding("F-claim")["reports"]
    assert len(reports) == 1
    assert not reports[0]["stale"]
    assert (root / reports[0]["artifact_ref"]).read_text() == decision["report"]["content"]
    applied = store.binding()
    repeated = cli("validate.py", *validate_args, "--decision-json", decision_path)
    assert repeated["validation_sync"]["status"] == "deduplicated"
    assert store.binding() == applied
    assert store.finding("F-claim")["reports"] == reports
    assert store.action("A-claim")["status"] == "claimed"
    store.transition_action(command_id="complete", action_id="A-claim", expected_version=2,
                            status="completed", actor="operator", reason="Recorded execution", claim_token="claim",
                            completion={"operation_id": operation_id})
    binding = store.binding()
    replay = cli("validation_runner.py", *args)
    assert replay["store_operation_id"] == operation_id
    assert replay["sync"]["status"] == "deduplicated"
    cli("checkpoint.py", "--repo-root", root, "--target", "target.test", "--no-refresh-coverage", "--json")
    resumed = cli("resume.py", "--repo-root", root, "--memory-dir", root / "hunt-memory", "--target", "target.test", "--json")
    assert resumed["summary"]["target_memory"]["source_kind"] == "store"
    assert store.action("A-claim")["completion"]["operation_id"] == operation_id
    assert store.binding() == binding
    for retired in ("findings/target.test/findings.json", "state/target.test/action_queue.json", "state/target.test/case.json"):
        assert not (root / retired).exists()


def test_primary_native_registration_preserves_each_step_method(tmp_path):
    target, finding_id = "https://target.test", "NATIVE-PRIMARY-METHODS"
    key = _target_key(target)
    artifacts_dir = tmp_path / ".private" / "validation" / key / finding_id
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    def artifact(name: str, body: str) -> str:
        path = artifacts_dir / name
        path.write_text(body, encoding="utf-8")
        return str(path.relative_to(tmp_path))

    evidence = {
        "schema_version": 1,
        "source": "browser",
        "generated_at": "2026-09-16T10:00:00Z",
        "result": "tested_finding",
        "observed_difference": "the second method observed the same object",
        "attempt_id": "native-attempt-methods",
        "runs": [
            {
                "url": "https://target.test/orders/1",
                "method": "POST",
                "actor": "owner",
                "artifacts": {
                    "request": artifact("post.request.txt", "POST /orders/1 HTTP/1.1\n"),
                    "response": artifact("post.response.txt", "HTTP/1.1 200 OK\n"),
                },
            },
            {
                "url": "https://target.test/orders/1",
                "method": "GET",
                "actor": "peer",
                "artifacts": {
                    "request": artifact("get.request.txt", "GET /orders/1 HTTP/1.1\n"),
                    "response": artifact("get.response.txt", "HTTP/1.1 200 OK\n"),
                },
            },
        ],
    }
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="seed-finding-methods", finding_id=finding_id,
        endpoint=evidence["runs"][0]["url"], method="POST", family="Authz",
        title="Native fixture", claim="Recorded method sequence", actor="operator",
    )

    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
    )
    validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    operation = store.execution(summary["store_operation_id"])

    assert [row["method"] for row in operation["observations"]] == ["POST", "GET"]


def test_primary_request_diff_registers_store_operation_without_legacy_ledger(monkeypatch, tmp_path):
    TargetStore(tmp_path, "https://target.test").initialize()
    for writer in ("record_entry", "upsert_finding", "update_finding_status", "save_queue"):
        assert not hasattr(validation_runner, writer), writer
    monkeypatch.setattr(
        validation_runner, "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"id":1}' if "users/1" in kwargs["url"] else '{"id":2}'),
    )
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path, target="https://target.test",
        finding_id="PAIR-PRIMARY",
        request_spec={
            "baseline_request": {"method": "GET", "url": "https://target.test/users/1"},
            "variant_request": {"method": "GET", "url": "https://target.test/users/2"},
            "active_dimension": "path:/users/1", "classifier": "authz",
            "expected": ["distinct_bodies"],
        },
    )
    assert summary["ledger_record"] is None
    store = TargetStore(tmp_path, "https://target.test")
    assert store.backend() == "primary"
    sync = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert sync["status"] == "updated"
    assert store.page("operations")["total"] == 1
    assert store.finding("PAIR-PRIMARY")["evidence"]


def test_primary_partial_request_diff_without_published_artifacts_is_unknown(monkeypatch, tmp_path):
    store = TargetStore(tmp_path, "https://target.test")
    store.initialize()
    calls = {"count": 0}

    def fail_before_response(**kwargs):
        calls["count"] += 1
        raise OSError("fixture transport failure")

    monkeypatch.setattr(validation_runner, "request_once", fail_before_response)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        finding_id="PAIR-PRIMARY-UNKNOWN",
        request_spec={
            "baseline_request": {"method": "GET", "url": "https://target.test/users/1"},
            "variant_request": {"method": "GET", "url": "https://target.test/users/2"},
            "active_dimension": "path:/users/1",
            "classifier": "authz",
            "expected": ["distinct_bodies"],
        },
    )
    assert calls["count"] == 1
    sync = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert sync["status"] == "updated"
    operation = store.execution(summary["store_operation_id"])
    assert operation["outcome"] == "unknown"
    assert operation["observations"] == []


def test_primary_partial_request_diff_keeps_completed_side_observation(monkeypatch, tmp_path):
    store = TargetStore(tmp_path, "https://target.test")
    store.initialize()
    calls = {"count": 0}

    def baseline_then_failure(**kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return _fake_response(kwargs["url"], body="baseline")
        raise OSError("variant transport failure")

    monkeypatch.setattr(validation_runner, "request_once", baseline_then_failure)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        finding_id="PAIR-PRIMARY-PARTIAL",
        request_spec={
            "baseline_request": {"method": "GET", "url": "https://target.test/users/1"},
            "variant_request": {"method": "GET", "url": "https://target.test/users/2"},
            "active_dimension": "path:/users/1",
            "classifier": "authz",
            "expected": ["distinct_bodies"],
        },
    )
    sync = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert sync["status"] == "updated"
    operation = store.execution(summary["store_operation_id"])
    assert operation["outcome"] == "partial"
    assert len(operation["observations"]) == 1
    assert operation["observations"][0]["endpoint"] == "https://target.test/users/1"


def test_record_evidence_requires_existing_canonical_finding(tmp_path):
    target, _, evidence = _native_fixture(tmp_path)
    with pytest.raises(ValueError, match="existing primary finding"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id="GHOST-FINDING", evidence=evidence,
        )


def test_record_evidence_accepts_unknown_family_without_closing_canonical_coverage(tmp_path):
    from current_truth import current_cell_projection
    from closure_resolver import ClosureResolver

    target, finding_id, evidence = _native_fixture(tmp_path, family="custom-state-transition")
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
    )
    assert summary["vuln_class"] == "custom-state-transition"
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    store = TargetStore(tmp_path, target)
    assert all(row["family"] == "custom-state-transition"
               for row in store.execution(summary["store_operation_id"])["observations"])
    closure = ClosureResolver(current_cell_projection(tmp_path, target))
    assert not closure.is_cell_closed(summary["url"], "Authz")
    assert not closure.is_cell_closed(summary["url"], "custom-state-transition")


def test_record_evidence_rejects_nonv1_schema(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    evidence["schema_version"] = 2
    with pytest.raises(ValueError, match="schema-v1"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_rejects_off_target_canonical_url(tmp_path):
    with pytest.raises(StoreError, match="target"):
        _native_fixture(tmp_path, url="https://other.test/rest/orders/1")
    assert TargetStore(tmp_path, "target.test").page("findings")["total"] == 0
    assert not (tmp_path / ".private").exists()


def test_record_evidence_rejects_off_target_run_url(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    evidence["runs"][0]["url"] = "https://other.test/rest/orders/1"
    with pytest.raises(ValueError, match="off-target"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_rejects_missing_anchor_endpoint(tmp_path):
    """runs must contain the finding's exact endpoint+method (the anchor)."""
    target, finding_id, evidence = _native_fixture(tmp_path)
    # finding method is POST; make all runs GET -> no anchor
    for run in evidence["runs"]:
        run["method"] = "GET"
    with pytest.raises(ValueError, match="exact endpoint and method"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_rejects_incomplete_run_as_finding_grade(tmp_path):
    """A run with error/body_truncated or no response must register as partial only."""
    target, finding_id, evidence = _native_fixture(tmp_path)
    del evidence["runs"][1]["artifacts"]["response"]
    with pytest.raises(ValueError, match="result=partial"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_partial_result_is_not_candidate_ready(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    evidence["result"] = "partial"
    del evidence["runs"][1]["artifacts"]["response"]
    evidence["runs"][1]["error"] = "connection reset"
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
    )
    assert summary["result"] == "partial"
    assert summary["candidate_ready"] is False
    assert summary["status"] == "partial"

    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    operation = TargetStore(tmp_path, target).execution(summary["store_operation_id"])
    assert operation["outcome"] == "partial"
    assert operation["observations"][1]["error"] == "connection reset"


def test_record_evidence_rejects_invalid_result_word(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    evidence["result"] = "definitely-hacked"
    with pytest.raises(ValueError, match="result"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_requires_timezone_in_generated_at(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    evidence["generated_at"] = "2026-09-16 10:00:00"
    with pytest.raises(ValueError, match="timezone"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_rejects_missing_or_empty_artifact_file(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    empty = tmp_path / ".private" / "validation" / _target_key(target) / finding_id / "empty.txt"
    empty.write_text("", encoding="utf-8")
    evidence["runs"][0]["artifacts"]["request"] = str(empty.relative_to(tmp_path))
    with pytest.raises(ValueError, match="non-empty target-owned file"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_rejects_off_target_artifact_ref(tmp_path):
    """Artifacts must live under the target's own evidence tree."""
    target, finding_id, evidence = _native_fixture(tmp_path)
    outside = tmp_path / "elsewhere" / "leak.txt"
    outside.parent.mkdir(parents=True)
    outside.write_text("x", encoding="utf-8")
    evidence["runs"][0]["artifacts"]["request"] = str(outside.relative_to(tmp_path))
    with pytest.raises(ValueError, match="target-owned"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_idempotent_reregistration_reuses_operation(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    first = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    second = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    assert first["operation_id"] == second["operation_id"]
    assert first["summary_path"] == second["summary_path"]
    assert Path(tmp_path / first["summary_path"]).is_file()
    # summary file is valid JSON after atomic rewrite (no half-write observable)
    json.loads((tmp_path / second["summary_path"]).read_text())


def test_record_evidence_raw_files_not_modified(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    key = _target_key(target)
    req = tmp_path / ".private" / "validation" / key / finding_id / "transition.request.bin"
    before = req.read_bytes()
    validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    assert req.read_bytes() == before


def test_record_evidence_normalizes_actor_vocabulary(tmp_path):
    """Invalid Ledger vocabulary is rejected before anything is written."""
    target, finding_id, evidence = _native_fixture(tmp_path)
    evidence["runs"][1]["actor"] = "test-owned-actor"
    with pytest.raises(ValueError, match="actor"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )


def test_record_evidence_different_method_runs_allowed_across_steps(tmp_path):
    """Native multi-step flows may legitimately change method between runs."""
    target, finding_id, evidence = _native_fixture(tmp_path)
    # step 1: GET state baseline (different method is fine, it is not the anchor)
    evidence["runs"][0]["method"] = "GET"
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    assert summary["result"] == "tested_finding"
    assert summary["runs"][0]["method"] == "GET"
    # anchor remains the canonical POST step
    assert any(r["method"] == "POST" for r in summary["runs"])


def test_record_evidence_sync_binds_finding_without_matching_unclaimed_actions(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path, finding_id="NATIVE-SYNC-1")
    store = TargetStore(tmp_path, target)
    store.create_action(
        command_id="similar-action", action_id="A-unclaimed", kind="execution",
        endpoint=evidence["runs"][0]["url"], family="Authz", intent="Review the same endpoint",
        execution_key="independent-review", actor="operator", metadata={"finding_id": finding_id},
    )
    before = store.action("A-unclaimed")
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    finding = store.finding(finding_id)
    assert finding["assessment"] is None
    assert {row["operation_id"] for row in finding["evidence"]} == {summary["store_operation_id"]}
    after = store.action("A-unclaimed")
    assert {key: value for key, value in after.items() if key != "revision"} == {
        key: value for key, value in before.items() if key != "revision"
    }
    assert store.execution(summary["store_operation_id"])["attempt"]["action_id"] is None
    assert not (tmp_path / "findings/target.test/findings.json").exists()
    assert not (tmp_path / "state/target.test/action_queue.json").exists()


def test_record_evidence_rejects_malformed_evidence_json(tmp_path, capsys):
    """--evidence-json 指向非 JSON 文件：CLI 报错，不写任何状态。"""
    target, finding_id, _ = _native_fixture(tmp_path)
    bad = tmp_path / "not-json.json"
    bad.write_text("this is not json {", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        validation_runner.main([
            "record-evidence",
            "--repo-root", str(tmp_path),
            "--target", target,
            "--finding-id", finding_id,
            "--evidence-json", str(bad),
        ])

    assert excinfo.value.code == 2
    assert "record-evidence" in capsys.readouterr().err
    assert not (tmp_path / "evidence").exists()


def test_record_evidence_rejects_state_changing_without_redline_confirmation(tmp_path):
    """state_changing 需要显式 redline 确认；未确认时不得登记。"""
    target, finding_id, evidence = _native_fixture(tmp_path)
    with pytest.raises(ValueError, match="redline-checked"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
            state_changing=True, redline_checked=False,
        )
    assert not (tmp_path / "evidence").exists()


def test_record_evidence_resumes_after_interrupted_sync(tmp_path):
    import sqlite3

    target, finding_id, evidence = _native_fixture(tmp_path, finding_id="NATIVE-RESUME")
    store = TargetStore(tmp_path, target)
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        state_changing=True, redline_checked=True,
    )
    summary_file = tmp_path / summary["summary_path"]
    saved = summary_file.read_bytes()
    before = store.binding()
    # Fail after metadata writes, at the same transaction's audit insert.
    with sqlite3.connect(store.path) as conn:
        conn.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON audit "
                     "BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END")
    failed = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert failed["status"] == "partial"
    assert "fixture audit failure" in failed["store"]["error"]
    assert store.binding() == before
    assert store.finding(finding_id)["evidence"] == []
    assert store.page("operations")["total"] == 0
    assert summary_file.read_bytes() == saved
    with sqlite3.connect(store.path) as conn:
        conn.execute("DROP TRIGGER reject_audit")
    resumed = json.loads(saved)
    assert validation_runner.sync_runner_artifacts(resumed, repo_root=tmp_path)["status"] == "updated"
    assert validation_runner.sync_runner_artifacts(resumed, repo_root=tmp_path)["status"] == "deduplicated"
    assert store.page("operations")["total"] == 1
    assert {row["operation_id"] for row in store.finding(finding_id)["evidence"]} == {resumed["store_operation_id"]}
    assert len(list((tmp_path / "evidence").rglob("summary.json"))) == 1


def test_record_evidence_claim_stays_open_until_explicit_completion(tmp_path):
    store, evidence = _claimed_runner_store(tmp_path)
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target="target.test", finding_id="F-claim", evidence=evidence,
        action_id="A-claim", claim_token="claim", command_actor="operator",
    )
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    action = store.action("A-claim")
    assert action["status"] == "claimed"
    operation_id = summary["store_operation_id"]
    assert store.execution(operation_id)["attempt"]["action_id"] == action["id"]
    assert store.execution(operation_id)["attempt"]["claim_token"] == "claim"
    store.transition_action(command_id="complete", action_id=action["id"], expected_version=action["version"],
                            status="completed", reason="Reviewed recorded evidence", actor="operator",
                            claim_token="claim", completion={"operation_id": operation_id})
    store.create_action(command_id="report-work", action_id="report", kind="work",
                        intent="Draft report", execution_key="report", subject={"finding_id": "F-claim"},
                        metadata={"finding_id": "F-claim"}, actor="operator")
    before = store.binding()
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "deduplicated"
    assert store.binding() == before
    assert store.action(action["id"])["status"] == "completed"
    assert store.action("report")["status"] == "ready"


def test_request_diff_invalid_spec_exits_two_without_request(runner_store, tmp_path, monkeypatch, capsys):
    """invalid request spec 必须 exit 2，且不得发任何请求 (validation-evidence.md:38)。

    构造缺 active_dimension 的 spec：validate_request_pair 在发请求前就抛
    RequestPairError。main() 的 request-diff 分支应捕获并 return 2，任何
    build_opener 都不应被调用。
    """
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api"},
        "variant_request": {"method": "GET", "url": "https://target.test/api"},
        "classifier": "authz",
    }), encoding="utf-8")
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("request must not be sent for an invalid spec")

    monkeypatch.setattr(validation_runner.urllib.request, "build_opener", fail_if_called)
    code = validation_runner.main([
        "request-diff",
        "--repo-root", str(tmp_path),
        "--target", "target.test",
        "--request-spec", str(spec),
    ])

    assert code == 2
    assert called is False
    assert "invalid request spec" in capsys.readouterr().err


def test_request_diff_execution_value_error_is_partial(runner_store, monkeypatch, tmp_path):
    """Execution-time scope errors remain partial evidence, not input errors."""
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("validation response left target scope")),
    )

    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="target.test",
        request_spec=_expect_auth_pair_spec(),
    )

    assert summary["result"] == "partial"
    assert summary["status"] == "partial"
    assert summary["error"]["type"] == "ValueError"


def test_request_diff_invalid_repeat_exits_two_without_request(runner_store, tmp_path, monkeypatch, capsys):
    spec = tmp_path / "spec.json"
    payload = _expect_auth_pair_spec()
    payload["repeat"] = "not-an-integer"
    spec.write_text(json.dumps(payload), encoding="utf-8")
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("request must not be sent for an invalid repeat")

    monkeypatch.setattr(validation_runner.urllib.request, "build_opener", fail_if_called)
    code = validation_runner.main([
        "request-diff",
        "--repo-root", str(tmp_path),
        "--target", "target.test",
        "--request-spec", str(spec),
    ])

    assert code == 2
    assert called is False
    assert "invalid request spec" in capsys.readouterr().err


@pytest.mark.parametrize("manual_required", [False, True])
def test_preview_request_diff_rejects_before_execution_or_bundle(tmp_path, monkeypatch, manual_required):
    store = TargetStore(tmp_path, "target.test", allow_preview=True)
    store.initialize(allow_legacy=True)
    spec = _expect_auth_pair_spec()
    if manual_required:
        for side in ("baseline_request", "variant_request"):
            spec[side]["headers"] = {"Content-Type": "multipart/form-data"}
            spec[side]["body"] = "binary"
    monkeypatch.setattr(validation_runner, "request_once", lambda **kwargs: pytest.fail("request before admission"))
    with pytest.raises(validation_runner.StoreError, match="preview"):
        validation_runner.run_request_diff(repo_root=tmp_path, target="target.test", request_spec=spec)
    assert not (tmp_path / "evidence").exists()
    assert not (tmp_path / ".private").exists()


def test_preview_native_registration_preserves_existing_summary(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path, preview=True)
    summary = {"target": target, "finding_id": finding_id, **evidence}
    path = tmp_path / "evidence" / _target_key(target) / "existing-summary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary))
    before = path.read_bytes()
    with pytest.raises(validation_runner.StoreError, match="preview"):
        validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
            state_changing=True, redline_checked=True,
        )
    with pytest.raises(validation_runner.StoreError, match="preview"):
        validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("fault", ["missing", "corrupt"])
def test_fenced_runner_refuses_before_execution_or_bundle(tmp_path, monkeypatch, fault):
    store = TargetStore(tmp_path, "target.test")
    store.initialize()
    if fault == "missing":
        store.path.unlink()
    else:
        store.path.write_bytes(b"not a sqlite database")
    monkeypatch.setattr(validation_runner, "request_once", lambda **kwargs: pytest.fail("request before admission"))
    with pytest.raises(validation_runner.StoreError):
        validation_runner.run_request_diff(repo_root=tmp_path, target="target.test", request_spec=_expect_auth_pair_spec())
    assert not (tmp_path / "evidence").exists()
    assert not (tmp_path / ".private").exists()


def test_runner_cli_holds_switch_lock_through_execution_and_registration(tmp_path, monkeypatch, capsys):
    import fcntl

    target = "target.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    lock_path = store.path.parent / "locks" / "target-switch.lock"
    stages = []

    def assert_cutover_blocked(stage):
        with lock_path.open("a+") as handle:
            with pytest.raises(BlockingIOError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        stages.append(stage)

    def request(**kwargs):
        assert_cutover_blocked("request")
        return _fake_response(kwargs["url"])

    original_sync = validation_runner._sync_primary_store
    def sync(*args, **kwargs):
        assert_cutover_blocked("registration")
        return original_sync(*args, **kwargs)

    monkeypatch.setattr(validation_runner, "_sync_primary_store", sync)
    original_run = validation_runner.run_request_diff
    def run(**kwargs):
        summary = original_run(**kwargs)
        assert_cutover_blocked("between_execution_and_registration")
        return summary

    monkeypatch.setattr(validation_runner, "request_once", request)
    monkeypatch.setattr(validation_runner, "run_request_diff", run)
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(_expect_auth_pair_spec()))
    assert validation_runner.main([
        "request-diff", "--repo-root", str(tmp_path), "--target", target,
        "--request-spec", str(spec),
    ]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert stages == ["request", "request", "between_execution_and_registration", "registration"]
    assert summary["sync"]["status"] == "updated"
    assert summary["backend_binding"]["store_id"] == store.binding()["store_id"]
    with lock_path.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    summary["backend_binding"]["store_id"] = "0" * 32
    with pytest.raises(validation_runner.StoreError, match="backend changed"):
        validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert store.page("operations")["total"] == 1


def test_runner_registration_preserves_existing_assessment_and_delivery(tmp_path, capsys, monkeypatch):
    import validate

    store, _, _, _, args = _primary_validation_fixture(tmp_path, capsys)
    assert validate.main(args) == 0
    capsys.readouterr()
    before = store.finding("F-claim")
    assert before["assessment"]["verdict"] == "confirmed"
    monkeypatch.setattr(validation_runner, "request_once", lambda **kw: _fake_response(kw["url"]))
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path, target="target.test", finding_id="F-claim", request_spec=_expect_auth_pair_spec(),
        action_id="A-claim", claim_token="claim", command_actor="operator",
    )
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    after = store.finding("F-claim")
    assert after["assessment"] == before["assessment"]
    assert after["deliveries"] == before["deliveries"]
    assert len(after["evidence"]) > len(before["evidence"])
    assert store.action("A-claim")["status"] == "claimed"


@pytest.mark.parametrize("field,value", [
    ("endpoint", "https://target.test/another-endpoint"), ("family", "SQLi"), ("method", "DELETE"),
])
def test_runner_registration_rejects_finding_identity_conflict(tmp_path, field, value):
    target, finding_id, evidence = _native_fixture(tmp_path)
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
    )
    # A persisted execution cannot be attached to a different claim identity.
    store = TargetStore(tmp_path, target)
    candidate = {key: store.finding(finding_id)[key] for key in ("id", "endpoint", "method", "family", "title", "claim")}
    candidate[field] = value
    before = store.binding()
    with pytest.raises(StoreError, match="exact observed endpoint, method and family"):
        validation_runner._record_primary_execution(
            store, attempt_id=summary["attempt_id"], actor="validation-runner", started_at=summary["generated_at"],
            result=summary["result"], runs=summary["runs"], method="POST", methods=None,
            family="Authz", native=True, candidate=candidate, state_changing=None, redline_checked=False,
        )
    assert store.binding() == before
    assert store.page("operations")["total"] == 0


@pytest.mark.parametrize("lane", ["native", "request-diff"])
def test_runner_exact_query_identity_stays_private_and_registers(tmp_path, monkeypatch, lane):
    endpoint = "https://target.test/rest/orders/1?token=PRIVATE_VALUE&x=one&x=two"
    target, finding_id, evidence = _native_fixture(tmp_path, url=endpoint)
    if lane == "native":
        summary = validation_runner.record_native_evidence(
            repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence,
        )
    else:
        def response(**kw):
            return {"status": 200, "headers": {}, "body": "ok", "request_text": "request",
                    "response_text": "response", "requested_url": kw["url"], "url": kw["url"]}
        monkeypatch.setattr(validation_runner, "request_once", response)
        summary = validation_runner.run_request_diff(
            repo_root=tmp_path, target=target, finding_id=finding_id,
            request_spec={"schema_version": 1, "classifier": "auth_boundary", "vuln_class": "Authz",
                          "active_dimension": "query:x", "expected_signal": "boundary check",
                          "baseline_request": {"method": "POST", "url": endpoint},
                          "variant_request": {"method": "POST", "url": endpoint.replace("x=two", "x=three")}},
        )
    assert "PRIVATE_VALUE" not in json.dumps(summary)
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    store = TargetStore(tmp_path, target)
    observation = store.execution(summary["store_operation_id"])["observations"][0]
    assert observation["endpoint"] == endpoint
    assert store.finding(finding_id)["endpoint"] == endpoint
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "deduplicated"


def test_native_redacted_query_shape_cannot_anchor_exact_finding(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path, url="https://target.test/rest/orders/1?id=42")
    for run in evidence["runs"]:
        run["url"] = "https://target.test/rest/orders/1?id="
    store = TargetStore(tmp_path, target)
    before = store.binding()
    with pytest.raises(ValueError, match="exact endpoint"):
        validation_runner.record_native_evidence(repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence)
    assert store.binding() == before


def test_runner_registration_refuses_changed_material_before_any_operation(tmp_path):
    target, finding_id, evidence = _native_fixture(tmp_path)
    summary = validation_runner.record_native_evidence(repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence)
    (tmp_path / summary["runs"][0]["artifacts"]["identity"]).write_text("{}")
    result = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert result["status"] == "partial"
    assert "changed" in result["store"]["error"]
    assert TargetStore(tmp_path, target).page("operations")["total"] == 0
