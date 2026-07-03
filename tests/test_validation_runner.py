"""Tests for deterministic validation runner v1 lanes."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

import target_case_state
import validation_runner


def _target_key(target: str) -> str:
    return validation_runner.target_storage_key(validation_runner.canonical_target_value(target))


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


def test_authz_public_exposure_creates_bundle_and_ledger(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        body = json.dumps({
            "config": {
                "application": {"name": "Shop"},
                "googleOauth": {"clientId": "client.apps.example", "authorizedRedirects": []},
            }
        })
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_authz_public_exposure(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/rest/admin/application-configuration",
        finding_id="AUTHZ-1",
        browser_observed=True,
    )

    key = _target_key("https://target.test")
    bundle = tmp_path / "evidence" / key / "validation" / "AUTHZ-1"
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert "admin" in summary["markers"]
    assert "configuration" in summary["markers"]
    assert "oauth" in summary["markers"]
    assert (bundle / "baseline.request.txt").is_file()
    assert (bundle / "baseline.response.txt").is_file()
    assert (bundle / "summary.json").is_file()
    assert ledger.is_file()
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["endpoint"] == "/rest/admin/application-configuration"
    assert entry["vuln_class"] == "Authz"
    assert entry["result"] == "tested_finding"
    assert entry["browser_observed"] is True


def test_authz_public_exposure_without_sensitive_marker_is_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"data":[{"id":1,"name":"Apple"}]}'),
    )

    summary = validation_runner.run_authz_public_exposure(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/Products",
        finding_id="AUTHZ-CLEAN",
    )

    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False


def test_authz_public_exposure_challenge_catalog_keywords_do_not_promote(monkeypatch, tmp_path):
    body = json.dumps(
        {
            "status": "success",
            "data": [
                {
                    "name": "Admin Section",
                    "description": "Reset the password of a user and learn about OAuth security questions.",
                    "difficulty": 2,
                    "tutorialOrder": 8,
                    "mitigationUrl": "https://owasp.example/challenge",
                    "hasCodingChallenge": True,
                    "ChallengeDependencies": [],
                }
            ],
        }
    )
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=body),
    )

    summary = validation_runner.run_authz_public_exposure(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/Challenges",
        finding_id="AUTHZ-CHALLENGE-CLEAN",
    )

    assert summary["markers"] == []
    assert summary["marker_sources"]["body"] == []
    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False


def test_authz_public_exposure_mnemonic_like_secret_promotes(monkeypatch, tmp_path):
    body = json.dumps(
        {
            "status": "success",
            "data": [
                {
                    "comment": (
                        'Please send the wallet seed phrase: '
                        '"purpose betray marriage blame crunch monitor spin slide donate sport lift clutch"'
                    )
                }
            ],
        }
    )
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=body),
    )

    summary = validation_runner.run_authz_public_exposure(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/Feedbacks",
        finding_id="AUTHZ-SECRET-FINDING",
    )

    assert "secret-like" in summary["markers"]
    assert "secret-like" in summary["marker_sources"]["body"]
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["evidence_rubric"]["ready"] is True
    assert summary["evidence_rubric"]["status"] == "candidate-ready"


def test_authz_public_exposure_does_not_promote_path_only_admin_marker(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"ok":true}'),
    )

    summary = validation_runner.run_authz_public_exposure(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/rest/admin/ping",
        finding_id="AUTHZ-PATH-ONLY",
    )

    assert summary["markers"] == ["admin"]
    assert summary["marker_sources"]["body"] == []
    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False


def test_sqli_result_diff_creates_diff_bundle_and_ledger(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        parsed = urlparse(kwargs["url"])
        q = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
        if q == "'))--":
            return _fake_response(kwargs["url"], body='{"data":[{"id":1},{"id":2},{"id":3}]}')
        return _fake_response(kwargs["url"], body='{"data":[{"id":1}]}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_sqli_result_diff(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/rest/products/search?q=",
        param="q",
        baseline_value="",
        variant_value="'))--",
        finding_id="SQLI-1",
        repeat=2,
        browser_observed=True,
    )

    key = _target_key("https://target.test")
    bundle = tmp_path / "evidence" / key / "validation" / "SQLI-1"
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["repeat"] == 2
    assert all(run["diff"]["changed"]["json_count"] for run in summary["runs"])
    assert (bundle / "1.baseline.request.txt").is_file()
    assert (bundle / "1.variant.response.txt").is_file()
    assert (bundle / "diff.json").is_file()
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["endpoint"] == "/rest/products/search"
    assert entry["vuln_class"] == "SQLi"
    assert entry["result"] == "tested_finding"


def test_sqli_result_diff_without_material_delta_is_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"data":[{"id":1}]}'),
    )

    summary = validation_runner.run_sqli_result_diff(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/rest/products/search?q=",
        param="q",
        baseline_value="",
        variant_value="'",
        finding_id="SQLI-CLEAN",
    )

    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False


def test_sqli_result_diff_ordinary_search_delta_is_not_finding(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        parsed = urlparse(kwargs["url"])
        q = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
        if q == "apple":
            return _fake_response(kwargs["url"], body='{"data":[{"id":1},{"id":2}]}')
        return _fake_response(kwargs["url"], body='{"data":[{"id":1}]}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_sqli_result_diff(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/rest/products/search?q=",
        param="q",
        baseline_value="",
        variant_value="apple",
        finding_id="SQLI-ORDINARY-FILTER",
    )

    assert summary["probe_shape"] is False
    assert summary["runs"][0]["diff"]["changed"]["json_count"] is True
    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False


def test_marker_replay_creates_bundle_and_ledger(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="rendered value: CCST_MARKER_42"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?name={{safe_calc}}",
        expect_marker="CCST_MARKER_42",
        finding_id="RCE-MARKER-1",
        vuln_class="SSTI",
        repeat=2,
        browser_observed=True,
    )

    key = _target_key("https://target.test")
    bundle = tmp_path / "evidence" / key / "validation" / "RCE-MARKER-1"
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["lane"] == "marker_replay"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert all(run["marker_found"] for run in summary["runs"])
    assert (bundle / "1.request.txt").is_file()
    assert (bundle / "2.response.txt").is_file()
    assert (bundle / "summary.json").is_file()
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["vuln_class"] == "RCE"
    assert entry["result"] == "tested_finding"
    assert entry["browser_observed"] is True


def test_marker_replay_without_marker_is_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="ordinary render output"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?name=test",
        expect_marker="CCST_MARKER_42",
        finding_id="RCE-MARKER-CLEAN",
        vuln_class="RCE",
    )

    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False
    assert summary["runs"][0]["marker_found"] is False


def test_idor_actor_pair_marker_finding_creates_diff_and_ledger(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        token = (kwargs.get("headers") or {}).get("Authorization", "")
        if token == "Bearer owner":
            return _fake_response(kwargs["url"], body='{"orderId":123,"email":"victim@example.test"}')
        return _fake_response(kwargs["url"], body='{"orderId":123,"email":"victim@example.test"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_idor_actor_pair(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/orders/123",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        expect_marker="victim@example.test",
        finding_id="IDOR-PAIR-1",
        repeat=2,
        browser_observed=True,
    )

    key = _target_key("https://target.test")
    bundle = tmp_path / "evidence" / key / "validation" / "IDOR-PAIR-1"
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["lane"] == "idor_actor_pair"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert all(run["strong_access"] for run in summary["runs"])
    assert (bundle / "1.owner.request.txt").is_file()
    assert (bundle / "2.peer.response.txt").is_file()
    assert (bundle / "diff.json").is_file()
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["vuln_class"] == "IDOR"
    assert entry["actor"] == "peer"
    assert entry["object_scope"] == "other_object_same_org"
    assert entry["variant"] == "id_swap"
    assert entry["result"] == "tested_finding"
    assert entry["browser_observed"] is True


def test_idor_actor_pair_denied_peer_is_clean(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        token = (kwargs.get("headers") or {}).get("Authorization", "")
        if token == "Bearer owner":
            return _fake_response(kwargs["url"], body='{"orderId":123,"email":"victim@example.test"}')
        return _fake_response(kwargs["url"], status=403, body='{"error":"forbidden"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_idor_actor_pair(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/orders/123",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        expect_marker="victim@example.test",
        finding_id="IDOR-PAIR-CLEAN",
    )

    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False
    assert summary["runs"][0]["peer_denied"] is True


def test_idor_actor_pair_invalid_owner_baseline_is_dead_end(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], status=500, body="Unexpected path")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_idor_actor_pair(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/orders/123",
        owner_headers={"Authorization": "Bearer stale-owner"},
        peer_headers={"Authorization": "Bearer peer"},
        expect_marker="victim@example.test",
        finding_id="IDOR-PAIR-DEAD-END",
        repeat=2,
    )

    key = _target_key("https://target.test")
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])

    assert summary["result"] == "dead_end"
    assert summary["candidate_ready"] is False
    assert all(not run["owner_success"] for run in summary["runs"])
    assert entry["result"] == "dead_end"
    assert "refresh the owner baseline" in summary["ai_next"]["next_action"]


def test_idor_actor_pair_peer_access_without_private_marker_stays_candidate(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        token = (kwargs.get("headers") or {}).get("Authorization", "")
        if token == "Bearer owner":
            return _fake_response(kwargs["url"], body='{"orderId":123,"email":"victim@example.test"}')
        return _fake_response(kwargs["url"], body='{"orderId":123,"status":"visible"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_idor_actor_pair(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/orders/123",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        expect_marker="victim@example.test",
        finding_id="IDOR-PAIR-CANDIDATE",
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["runs"][0]["ambiguous_access"] is True


def test_idor_actor_pair_rejects_identical_actor_context(tmp_path):
    with pytest.raises(ValueError, match="identical"):
        validation_runner.run_idor_actor_pair(
            repo_root=tmp_path,
            target="https://target.test",
            url="https://target.test/api/orders/123",
            finding_id="IDOR-BAD-CONTEXT",
        )


def _build_case_state_for_idor(tmp_path):
    target = "https://target.test"
    target_case_state.add_actor(tmp_path, target, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, target, actor="user_b", role="user")
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_user_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner",
        validity="valid",
    )
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_user_b",
        actor="user_b",
        kind="bearer",
        header_value="Bearer peer",
        validity="valid",
    )
    target_case_state.add_object(
        tmp_path,
        target,
        object_ref="order_123",
        object_type="order",
        object_id="123",
        owner_actor="user_a",
        endpoint="https://target.test/api/orders/123",
        private_marker="victim@example.test",
    )
    target_case_state.add_backlog(
        tmp_path,
        target,
        backlog_id="val_001",
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
    )
    return target


def test_idor_actor_pair_from_case_state_cli_resolves_headers_and_object(monkeypatch, tmp_path, capsys):
    target = _build_case_state_for_idor(tmp_path)

    def fake_request_once(**kwargs):
        token = (kwargs.get("headers") or {}).get("Authorization", "")
        if token == "Bearer owner":
            return _fake_response(kwargs["url"], body='{"orderId":123,"email":"victim@example.test"}')
        if token == "Bearer peer":
            return _fake_response(kwargs["url"], body='{"orderId":123,"email":"victim@example.test"}')
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing token"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    rc = validation_runner.main([
        "idor-actor-pair",
        "--repo-root",
        str(tmp_path),
        "--target",
        target,
        "--from-case-state",
        "--backlog-id",
        "val_001",
        "--complete-case-state",
        "--finding-id",
        "IDOR-CASE-STATE",
    ])
    summary = json.loads(capsys.readouterr().out)
    state = target_case_state.load_case_state(tmp_path, target)
    backlog = state["validation_backlog"][0]

    assert rc == 0
    assert summary["result"] == "tested_finding"
    assert summary["url"] == "https://target.test/api/orders/123"
    assert summary["expect_marker"] == "victim@example.test"
    assert summary["case_state_ref"]["backlog_id"] == "val_001"
    assert summary["case_state_ref"]["owner_session_id"] == "sess_user_a"
    assert summary["case_state_ref"]["peer_session_id"] == "sess_user_b"
    assert summary["case_state_write_back"]["status"] == "tested_finding"
    assert backlog["status"] == "tested_finding"
    assert backlog["evidence_ref"].endswith("summary.json")


def test_idor_actor_pair_from_case_state_resolves_multi_header_sessions(tmp_path):
    target = "https://target.test"
    target_case_state.add_actor(tmp_path, target, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, target, actor="user_b", role="user")
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_user_a",
        actor="user_a",
        headers={"Cookie": "sid=owner", "X-CSRF-Token": "csrf-owner"},
        validity="valid",
    )
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_user_b",
        actor="user_b",
        headers={"Cookie": "sid=peer", "X-CSRF-Token": "csrf-peer"},
        validity="valid",
    )
    target_case_state.add_object(
        tmp_path,
        target,
        object_ref="order_123",
        object_type="order",
        owner_actor="user_a",
        endpoint="https://target.test/api/orders/123",
        private_marker="victim@example.test",
    )

    resolved = validation_runner.resolve_idor_actor_pair_from_case_state(
        repo_root=tmp_path,
        target=target,
        object_ref="order_123",
        peer_actor="user_b",
    )

    assert resolved["owner_headers"] == {
        "Cookie": "sid=owner",
        "X-CSRF-Token": "csrf-owner",
    }
    assert resolved["peer_headers"] == {
        "Cookie": "sid=peer",
        "X-CSRF-Token": "csrf-peer",
    }


def test_idor_actor_pair_from_case_state_requires_peer_session(tmp_path):
    target = "https://target.test"
    target_case_state.add_actor(tmp_path, target, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, target, actor="user_b", role="user")
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_user_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner",
    )
    target_case_state.add_object(
        tmp_path,
        target,
        object_ref="order_123",
        object_type="order",
        owner_actor="user_a",
        endpoint="https://target.test/api/orders/123",
        private_marker="victim@example.test",
    )

    with pytest.raises(ValueError, match="peer_actor is required"):
        validation_runner.resolve_idor_actor_pair_from_case_state(
            repo_root=tmp_path,
            target=target,
            object_ref="order_123",
        )

    with pytest.raises(ValueError, match="session missing"):
        validation_runner.resolve_idor_actor_pair_from_case_state(
            repo_root=tmp_path,
            target=target,
            object_ref="order_123",
            peer_actor="user_b",
        )


def test_idor_skeleton_writes_required_actor_pair_artifacts(tmp_path):
    summary = validation_runner.run_idor_skeleton(
        repo_root=tmp_path,
        target="https://target.test",
        endpoint="https://target.test/api/orders/123",
        finding_id="IDOR-1",
    )

    bundle = tmp_path / "evidence" / _target_key("https://target.test") / "validation" / "IDOR-1"
    assert summary["lane"] == "idor_actor_pair_skeleton"
    assert summary["candidate_ready"] is False
    assert "owner_baseline_request" in summary["required_artifacts"]
    assert "peer_variant_response" in summary["required_artifacts"]
    assert (bundle / "README.md").is_file()
    assert (bundle / "summary.json").is_file()
