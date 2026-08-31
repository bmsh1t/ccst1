"""Tests for deterministic validation runner v1 lanes."""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

import finding_index
import target_case_state
import validation_runner
from action_queue import ingest_checkpoint, load_queue, save_queue
from evidence_ledger import ledger_path
from identity_contract import build_closure_cell
from tools.auth_session import AuthSession


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
    assert not actual or actual in validation_runner.CLOSURE_FAMILIES


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


def _runner_reconciliation_fixture(monkeypatch, tmp_path):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-configuration"
    finding_id = "AUTHZ-RECONCILE"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-RECONCILE",
                        "status": "queued",
                        "type": "validation",
                        "metadata": {"finding_id": finding_id, "url": url},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(
            kwargs["url"],
            body=json.dumps({"config": {"googleOauth": {"clientId": "client.apps.test"}}}),
        ),
    )
    summary = validation_runner.run_authz_public_exposure(
        repo_root=tmp_path,
        target=target,
        url=url,
        finding_id=finding_id,
    )
    return summary, queue_dir / "action_queue.json", key


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
    bundle = (tmp_path / summary["summary_path"]).parent
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["observation_kind"] == "baseline_only"
    assert "admin" in summary["markers"]
    assert "configuration" in summary["markers"]
    assert "oauth" in summary["markers"]
    assert (tmp_path / summary["artifacts"]["baseline_request"]).is_file()
    assert (tmp_path / summary["artifacts"]["baseline_response"]).is_file()
    bindings = {item["kind"]: item for item in summary["artifact_bindings"]}
    assert {"baseline_request", "baseline_response"} <= bindings.keys()
    for binding in bindings.values():
        artifact = tmp_path / binding["ref"]
        assert binding["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    identity = json.loads((tmp_path / summary["artifacts"]["baseline_identity"]).read_text(encoding="utf-8"))
    assert identity["requested_url"].endswith("/rest/admin/application-configuration")
    assert identity["final_url"] == identity["requested_url"]
    assert identity["redirect_chain"] == []
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
    assert summary["markers"] == []
    assert summary["candidate_ready"] is False
    assert summary["assessment_scope"] == "anonymous_public_exposure_only"
    assert summary["observation_kind"] == "baseline_only"


def test_authz_public_exposure_baseline_does_not_claim_anonymous_denial(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(
            kwargs["url"],
            body='<html><title>Cargill Sign In</title><div id="okta-sign-in"></div><script>client_id=CLIENT_ID</script></html>',
        ),
    )

    summary = validation_runner.run_authz_public_exposure(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/login",
        finding_id="AUTHZ-LOGIN-BASELINE",
    )

    entry = summary["ledger_record"]
    assert summary["result"] == "tested_clean"
    assert summary["assessment_scope"] == "anonymous_public_exposure_only"
    assert summary["ai_next"]["next_action"].startswith("Treat tested_clean as clean for public-exposure evidence only")
    assert entry["variant"] == "baseline"
    assert "does not establish protected-resource Authz denial" in entry["notes"]


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


def _build_case_state_for_authz_role(tmp_path):
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
    return target


def test_authz_role_replay_from_case_state_cli_detects_role_candidate(monkeypatch, tmp_path, capsys):
    target = _build_case_state_for_authz_role(tmp_path)
    url = "https://target.test/api/admin/export"

    def fake_request_once(**kwargs):
        auth = (kwargs.get("headers") or {}).get("Authorization", "")
        if auth == "Bearer owner":
            return _fake_response(kwargs["url"], status=200, body='{"data":[{"id":1,"export":"owner"}]}')
        if auth == "Bearer peer":
            return _fake_response(kwargs["url"], status=403, body='{"error":"forbidden"}')
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing auth"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    rc = validation_runner.main([
        "authz-role-replay",
        "--target", target,
        "--repo-root", str(tmp_path),
        "--url", url,
        "--from-case-state",
        "--repeat", "1",
    ])

    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["lane"] == "authz_role_replay"
    assert summary["result"] == "candidate"
    assert summary["case_state_ref"]["owner_actor"] == "user_a"
    assert summary["case_state_ref"]["peer_actor"] == "user_b"
    assert summary["case_state_ref"]["owner_role"] == "user"
    assert summary["case_state_ref"]["peer_role"] == "user"
    assert summary["runs"][0]["anonymous_status"] == 401
    assert summary["runs"][0]["owner_status"] == 200
    assert summary["runs"][0]["peer_status"] == 403
    assert (tmp_path / "memory" / "evidence" / _target_key(target) / "ledger.jsonl").is_file()


def test_authz_role_replay_object_endpoint_peer_blocked_is_clean(monkeypatch, tmp_path, capsys):
    target = _build_case_state_for_authz_role(tmp_path)

    def fake_request_once(**kwargs):
        auth = (kwargs.get("headers") or {}).get("Authorization", "")
        if auth == "Bearer owner":
            return _fake_response(
                kwargs["url"],
                status=200,
                body='{"status":"success","data":{"UserId":1,"id":7,"streetAddress":"owner only"}}',
            )
        if auth == "Bearer peer":
            return _fake_response(
                kwargs["url"],
                status=400,
                body='{"status":"error","data":"Malicious activity detected"}',
            )
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing auth"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    rc = validation_runner.main([
        "authz-role-replay",
        "--target", target,
        "--repo-root", str(tmp_path),
        "--url", "https://target.test/api/Addresss/7",
        "--from-case-state",
        "--repeat", "1",
    ])

    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["result"] == "tested_clean"
    assert summary["object_specific_peer_denied"] is True
    assert summary["runs"][0]["peer_denied"] is True


def test_authz_role_replay_same_public_catalog_is_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], status=200, body='{"data":[{"id":1,"name":"catalog"}]}'),
    )

    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/Products",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="AUTHZ-ROLE-CLEAN",
    )

    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False


def test_authz_role_replay_authenticated_broad_user_collection_is_candidate(monkeypatch, tmp_path):
    user_collection = json.dumps({
        "status": "success",
        "data": [
            {
                "id": 1,
                "email": "admin@example.test",
                "username": "admin",
                "role": "admin",
                "lastLoginIp": "127.0.0.1",
            },
            {
                "id": 2,
                "email": "user@example.test",
                "username": "user",
                "role": "customer",
                "lastLoginIp": "127.0.0.2",
            },
        ],
    })

    def fake_request_once(**kwargs):
        if (kwargs.get("headers") or {}).get("Authorization"):
            return _fake_response(kwargs["url"], status=200, body=user_collection)
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing auth"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/Users",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="AUTHZ-ROLE-AUTHENTICATED-COLLECTION",
        repeat=2,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["authenticated_exposure"]["candidate"] is True
    assert summary["runs"][0]["authenticated_exposure_candidate"] is True
    first_check = summary["authenticated_exposure"]["checks"][0]
    assert first_check["item_count"] == 2
    assert "email" in first_check["identity_fields"]
    assert "role" in first_check["authz_fields"]
    assert "authenticated-only broad collection" in summary["evidence_rubric"]["summary"]


def test_authz_role_replay_low_privileged_user_collection_is_finding(monkeypatch, tmp_path):
    target = _build_case_state_for_authz_role(tmp_path)
    user_collection = json.dumps({
        "status": "success",
        "data": [
            {
                "id": 1,
                "email": "admin@example.test",
                "username": "admin",
                "role": "admin",
                "totpSecret": "",
            },
            {
                "id": 2,
                "email": "user@example.test",
                "username": "user",
                "role": "customer",
                "totpSecret": "",
            },
        ],
    })

    def fake_request_once(**kwargs):
        if (kwargs.get("headers") or {}).get("Authorization"):
            return _fake_response(kwargs["url"], status=200, body=user_collection)
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing auth"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    resolved = validation_runner.resolve_authz_role_replay_from_case_state(
        repo_root=tmp_path,
        target=target,
    )
    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target=target,
        url="https://target.test/api/Users",
        owner_headers=resolved["owner_headers"],
        peer_headers=resolved["peer_headers"],
        case_state_ref=resolved["case_state_ref"],
        finding_id="AUTHZ-ROLE-LOW-PRIV-COLLECTION",
        repeat=2,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["authenticated_exposure"]["candidate_ready"] is True
    assert summary["authenticated_exposure"]["policy_inference"]
    assert summary["evidence_rubric"]["status"] == "candidate-ready"
    first_check = summary["authenticated_exposure"]["checks"][0]
    assert first_check["low_privileged_context"] is True
    assert first_check["privileged_record_count"] == 1
    assert "totpsecret" in first_check["secret_fields"]


def test_authz_role_replay_unknown_role_collection_stays_candidate(monkeypatch, tmp_path):
    target = "https://target.test"
    target_case_state.add_actor(tmp_path, target, actor="user_a", role="unknown")
    target_case_state.add_actor(tmp_path, target, actor="user_b", role="unknown")
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
    user_collection = json.dumps({
        "status": "success",
        "data": [
            {"id": 1, "email": "admin@example.test", "role": "admin", "totpSecret": ""},
            {"id": 2, "email": "user@example.test", "role": "customer", "totpSecret": ""},
        ],
    })

    def fake_request_once(**kwargs):
        if (kwargs.get("headers") or {}).get("Authorization"):
            return _fake_response(kwargs["url"], status=200, body=user_collection)
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing auth"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    resolved = validation_runner.resolve_authz_role_replay_from_case_state(
        repo_root=tmp_path,
        target=target,
    )
    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target=target,
        url="https://target.test/api/Users",
        owner_headers=resolved["owner_headers"],
        peer_headers=resolved["peer_headers"],
        case_state_ref=resolved["case_state_ref"],
        finding_id="AUTHZ-ROLE-UNKNOWN-COLLECTION",
    )

    assert summary["result"] == "candidate"
    assert summary["authenticated_exposure"]["candidate"] is True
    assert summary["authenticated_exposure"]["candidate_ready"] is False


def test_authz_role_replay_single_authenticated_profile_is_clean(monkeypatch, tmp_path):
    profile = json.dumps({
        "status": "success",
        "data": {
            "id": 2,
            "email": "user@example.test",
            "username": "user",
            "role": "customer",
        },
    })

    def fake_request_once(**kwargs):
        if (kwargs.get("headers") or {}).get("Authorization"):
            return _fake_response(kwargs["url"], status=200, body=profile)
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing auth"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/Profile",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="AUTHZ-ROLE-SINGLE-PROFILE",
    )

    assert summary["result"] == "tested_clean"
    assert summary["authenticated_exposure"]["candidate"] is False


def test_authz_role_replay_same_shape_dynamic_body_length_is_clean(monkeypatch, tmp_path):
    bodies = iter([
        _fake_response("https://target.test/rest/captcha", status=401, body="login required"),
        _fake_response(
            "https://target.test/rest/captcha",
            status=200,
            body='{"image":"<svg>owner-random-long</svg>","answer":"123","UserId":1}',
        ),
        _fake_response(
            "https://target.test/rest/captcha",
            status=200,
            body='{"image":"<svg>peer-random-even-longer-value</svg>","answer":"456","UserId":2}',
        ),
    ])

    monkeypatch.setattr(validation_runner, "request_once", lambda **kwargs: next(bodies))

    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/rest/captcha",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="AUTHZ-ROLE-DYNAMIC-SAME-SHAPE",
    )

    assert summary["result"] == "tested_clean"
    assert summary["runs"][0]["owner_peer_material_diff"] is False
    assert summary["runs"][0]["owner_peer_diff"]["diff"]["changed"]["body_length"] is True


def test_authz_role_replay_owner_failure_overrides_rubric_to_dead_end(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], status=401, body='{"error":"invalid session"}'),
    )

    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/SecurityAnswers",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="AUTHZ-ROLE-DEAD-END",
    )

    assert summary["result"] == "dead_end"
    assert summary["evidence_rubric"]["status"] == "dead-end"
    assert summary["evidence_rubric"]["score"] == 0
    assert summary["evidence_rubric"]["missing"] == ["owner_baseline_success"]


def test_authz_role_replay_requires_public_marker_in_every_repeat(monkeypatch, tmp_path):
    anonymous_round = 0
    sensitive = json.dumps({
        "note": (
            'wallet seed phrase: '
            '"purpose betray marriage blame crunch monitor spin slide donate sport lift clutch"'
        )
    })

    def fake_request_once(**kwargs):
        nonlocal anonymous_round
        if not kwargs.get("headers"):
            anonymous_round += 1
            body = '{"ok":true}' if anonymous_round == 1 else sensitive
            return _fake_response(kwargs["url"], body=body)
        return _fake_response(kwargs["url"], body='{"ok":true}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_authz_role_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/data",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="AUTHZ-REPEAT-MARKER",
        repeat=2,
    )

    assert summary["candidate_ready"] is False
    assert summary["result"] == "tested_clean"
    assert summary["marker_sources"]["body"] == []
    assert len(summary["marker_sources_by_round"]) == 2
    assert "secret-like" in summary["marker_sources_by_round"][1]["body"]


def test_authz_role_replay_candidate_reopens_previous_tested_queue_action(monkeypatch, tmp_path, capsys):
    target = "https://target.test"
    url = "https://target.test/api/Users"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-0007",
                        "status": "tested",
                        "type": "ranked-surface",
                        "priority": 60,
                        "evidence": f"Continue top ranked surface {url}",
                        "next_question": "Replay the ranked surface.",
                        "action": f"Replay {url} and classify it.",
                        "command_hint": "focused hunt on ranked P1/P2 surface",
                        "metadata": {"url": url, "endpoint": "/api/Users"},
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    user_collection = json.dumps({
        "data": [
            {"id": 1, "email": "admin@example.test", "username": "admin", "role": "admin"},
            {"id": 2, "email": "user@example.test", "username": "user", "role": "customer"},
        ],
    })

    def fake_request_once(**kwargs):
        if (kwargs.get("headers") or {}).get("Authorization"):
            return _fake_response(kwargs["url"], status=200, body=user_collection)
        return _fake_response(kwargs["url"], status=401, body='{"error":"missing auth"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    rc = validation_runner.main([
        "authz-role-replay",
        "--repo-root", str(tmp_path),
        "--target", target,
        "--url", url,
        "--owner-header", "Authorization: Bearer owner",
        "--peer-header", "Authorization: Bearer peer",
        "--repeat", "1",
    ])

    summary = json.loads(capsys.readouterr().out)
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))
    assert rc == 0
    assert summary["result"] == "candidate"
    assert summary["sync"]["action_queue"]["status"] == "updated"
    assert summary["sync"]["action_queue"]["id"] == "AQ-0007"
    assert queue["actions"][0]["status"] == "candidate"
    assert queue["actions"][0]["type"] == "candidate-evidence-gap"
    assert "Do not rerun the same replay" in queue["actions"][0]["action"]
    assert queue["actions"][0]["command_hint"] == "fill missing rubric evidence, then /validate"
    assert queue["actions"][0]["metadata"]["runner"] == "authz_role_replay"
    assert "policy/role expectation" in " ".join(queue["actions"][0]["metadata"]["missing_evidence"])
    assert summary["sync"]["action_queue"]["candidate_followup"]["patched"] is True


def test_candidate_followup_reingest_is_idempotent_across_runner_and_checkpoint(tmp_path):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-configuration"
    original = {
        "id": "A1",
        "priority": 70,
        "type": "surface-review",
        "status": "ready",
        "action": f"Review surface candidate {url}: validate exposure evidence.",
        "command_hint": "capture baseline",
        "source": "checkpoint",
        "source_id": "A1",
        "metadata": {
            "url": url,
            "endpoint": "/rest/admin/application-configuration",
        },
    }
    ingest_checkpoint(tmp_path, target, checkpoint={"next_action_queue": [original]})
    queue = load_queue(tmp_path, target)
    queue["actions"][0]["status"] = "candidate"

    summary = {
        "finding_id": "exposure_f0731e9e75",
        "url": url,
        "summary_path": "evidence/target.test/summary.json",
        "lane": "authz_public_exposure",
        "evidence_rubric": {
            "status": "candidate",
            "missing_labels": ["policy/role expectation"],
        },
    }
    patched = validation_runner._patch_candidate_queue_followup_in_queue(
        queue,
        action_id="AQ-0001",
        summary=summary,
    )
    assert patched["patched"] is True
    duplicate = {
        **queue["actions"][0],
        "id": "AQ-LEGACY-DUP",
        "dedupe_key": "legacy-candidate-gap",
        "metadata": dict(queue["actions"][0]["metadata"]),
    }
    queue["actions"].append(duplicate)
    save_queue(tmp_path, target, queue)

    candidate = validation_runner._candidate_queue_followup(summary)
    candidate.update(
        {
            "id": "A9",
            "priority": 70,
            "status": "ready",
            "source": "checkpoint",
            "source_id": "A9",
        }
    )
    validation = {
        "id": "A10",
        "priority": 100,
        "type": "validation",
        "status": "ready",
        "action": f"Run /validate for finding {summary['finding_id']} on {url}.",
        "command_hint": "/validate",
        "source": "checkpoint",
        "source_id": "A10",
        "metadata": {"finding_id": summary["finding_id"]},
    }

    first = ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={"next_action_queue": [candidate, validation]},
    )
    second = ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={"next_action_queue": [candidate, validation]},
    )
    actions = load_queue(tmp_path, target)["actions"]
    active_candidates = [
        item
        for item in actions
        if item.get("type") == "candidate-evidence-gap"
        and item.get("status") in {"queued", "candidate", "running"}
    ]
    active_validations = [
        item
        for item in actions
        if item.get("type") == "validation"
        and item.get("status") in {"queued", "candidate", "running"}
    ]

    assert first["stats"]["added"] == 1
    assert second["stats"]["added"] == 0
    assert len(active_candidates) == 1
    assert active_candidates[0]["id"] == "AQ-0001"
    assert [item for item in actions if item.get("id") == "AQ-LEGACY-DUP"][0]["status"] == "n/a"
    assert len(active_validations) == 1


def test_runner_queue_sync_prefers_exact_finding_id_over_legacy_url(tmp_path):
    target = "https://target.test"
    url = "https://target.test/api/Users"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-EXACT",
                        "status": "queued",
                        "type": "ranked-surface",
                        "metadata": {"finding_id": "F-EXACT", "url": "https://target.test/other"},
                    },
                    {
                        "id": "AQ-LEGACY",
                        "status": "queued",
                        "type": "ranked-surface",
                        "action": f"Replay {url} and classify it.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    synced = validation_runner._sync_action_queue(
        {"target": target, "finding_id": "F-EXACT", "url": url, "result": "tested_clean"},
        repo_root=tmp_path,
    )
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))
    statuses = {item["id"]: item["status"] for item in queue["actions"]}

    assert synced["status"] == "updated"
    assert synced["id"] == "AQ-EXACT"
    assert synced["match_kind"] == "finding_id"
    assert statuses == {"AQ-EXACT": "tested", "AQ-LEGACY": "queued"}


def test_runner_queue_sync_refuses_ambiguous_legacy_marker(tmp_path):
    target = "https://target.test"
    url = "https://target.test/api/Users"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    actions = [
        {"id": "AQ-ONE", "status": "queued", "type": "ranked-surface", "action": f"Replay {url}."},
        {"id": "AQ-TWO", "status": "queued", "type": "coverage-gap", "evidence": f"Observed {url}."},
    ]
    (queue_dir / "action_queue.json").write_text(
        json.dumps({"schema_version": 1, "target": target, "actions": actions}),
        encoding="utf-8",
    )

    synced = validation_runner._sync_action_queue(
        {"target": target, "url": url, "result": "tested_clean"},
        repo_root=tmp_path,
    )
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))

    assert synced == {
        "status": "ambiguous",
        "reason": "multiple legacy_marker queue actions match runner output",
        "ids": ["AQ-ONE", "AQ-TWO"],
    }
    assert [item["status"] for item in queue["actions"]] == ["queued", "queued"]


def test_queue_endpoint_match_normalizes_trailing_slash_without_path_suffix_match():
    exact = {
        "id": "AQ-EXACT",
        "status": "queued",
        "type": "validation",
        "metadata": {"endpoint": "/api/Users"},
    }
    legacy_suffix = {
        "id": "AQ-SUFFIX",
        "status": "queued",
        "type": "validation",
        "action": "Replay /v1/api/Users and classify it.",
    }
    matches, match_kind = validation_runner._select_queue_actions_for_summary(
        {"actions": [exact, legacy_suffix]},
        {"url": "https://target.test/api/Users/"},
        "tested",
    )

    assert [item["id"] for item in matches] == ["AQ-EXACT"]
    assert match_kind == "endpoint"
    assert validation_runner._action_matches_legacy_marker(
        legacy_suffix,
        ["/api/Users"],
    ) is False


def test_queue_endpoint_match_prefers_running_versioned_hypothesis_over_advisory_review():
    endpoint = "https://target.test/rest/admin"
    versioned = {
        "id": "AQ-VERSIONED",
        "status": "running",
        "type": "coverage-gap",
        "metadata": {
            "endpoint": "/rest/admin",
            "depth_contract_version": 1,
        },
    }
    advisory = {
        "id": "AQ-ADVISORY",
        "status": "queued",
        "type": "surface-review",
        "metadata": {"endpoint": "/rest/admin"},
    }

    matches, match_kind = validation_runner._select_queue_actions_for_summary(
        {"actions": [advisory, versioned]},
        {"url": endpoint},
        "tested",
    )

    assert [item["id"] for item in matches] == ["AQ-VERSIONED"]
    assert match_kind == "versioned_endpoint"


def test_authz_public_exposure_cli_syncs_finding_and_action_queue(monkeypatch, tmp_path, capsys):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-configuration"
    key = _target_key(target)
    findings_dir = tmp_path / "findings" / key
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "target": target,
                "total": 1,
                "findings": [
                    {
                        "id": "AUTHZ-SYNC",
                        "type": "auth_bypass",
                        "severity": "high",
                        "confidence": "medium",
                        "url": url,
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-0001",
                        "status": "queued",
                        "type": "validation",
                        "priority": 100,
                        "evidence": f"Run /validate for finding AUTHZ-SYNC on {url}",
                        "next_question": "Execute this validation.",
                        "action": f"Validate AUTHZ-SYNC at {url}",
                        "command_hint": "/validate",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    def fake_request_once(**kwargs):
        body = json.dumps(
            {
                "config": {
                    "application": {"name": "Shop"},
                    "googleOauth": {"clientId": "client.apps.example"},
                }
            }
        )
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    rc = validation_runner.main(
        [
            "authz-public-exposure",
            "--repo-root",
            str(tmp_path),
            "--target",
            target,
            "--url",
            url,
            "--finding-id",
            "AUTHZ-SYNC",
            "--browser-observed",
        ]
    )
    summary = json.loads(capsys.readouterr().out)
    findings = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert summary["result"] == "tested_finding"
    assert summary["sync"]["finding"]["status"] == "updated"
    assert summary["sync"]["action_queue"]["status"] == "updated"
    finding = findings["findings"][0]
    assert finding["validation_status"] == "candidate"
    assert finding["confidence"] == "high"
    assert finding["validation_summary"].endswith("summary.json")
    assert finding["vuln_class"] == "Authz"
    assert finding["evidence_rubric"]["status"] == "candidate-ready"
    assert queue["actions"][0]["status"] == "candidate"


def test_runner_sync_does_not_downgrade_validated_finding(monkeypatch, tmp_path, capsys):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-configuration"
    key = _target_key(target)
    findings_dir = tmp_path / "findings" / key
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "target": target,
                "total": 1,
                "findings": [
                    {
                        "id": "AUTHZ-VALIDATED",
                        "type": "auth_bypass",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": url,
                        "validation_status": "validated",
                        "validation_summary": "validated/validation-summary.json",
                        "report_status": "not_generated",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    validation_runner.update_finding_status(
        findings_dir,
        "AUTHZ-VALIDATED",
        validation_status="validated",
        report_status="not_generated",
    )

    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(
            kwargs["url"],
            body=json.dumps({"config": {"application": {"name": "Shop"}, "googleOauth": {"clientId": "x"}}}),
        ),
    )

    rc = validation_runner.main(
        [
            "authz-public-exposure",
            "--repo-root",
            str(tmp_path),
            "--target",
            target,
            "--url",
            url,
            "--finding-id",
            "AUTHZ-VALIDATED",
        ]
    )
    summary = json.loads(capsys.readouterr().out)
    findings = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert summary["sync"]["finding"]["validation_status"] == "validated"
    assert findings["findings"][0]["validation_status"] == "validated"
    assert findings["findings"][0]["validation_summary"] == "validated/validation-summary.json"
    assert findings["findings"][0]["evidence_rubric"]["status"] == "candidate-ready"


def test_runner_replay_does_not_reopen_finalized_queue_action(monkeypatch, tmp_path):
    summary, queue_path, key = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    first = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert first["status"] == "updated"

    findings_dir = tmp_path / "findings" / key
    finding_index.update_finding_status(
        findings_dir,
        "AUTHZ-RECONCILE",
        validation_status="validated",
        report_status="not_generated",
    )
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["status"] = "dead-end"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")

    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    persisted_queue = json.loads(queue_path.read_text(encoding="utf-8"))

    assert replay["status"] == "deduplicated"
    assert replay["action_queue"]["status"] == "deduplicated"
    assert persisted_queue["actions"][0]["status"] == "dead-end"


def test_runner_replay_ignores_report_and_sibling_followups(monkeypatch, tmp_path):
    summary, queue_path, _ = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"

    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["status"] = "n/a"
    finding_id = summary["finding_id"]
    queue["actions"].extend(
        [
            {"id": "AQ-REPORT", "status": "queued", "type": "report", "metadata": {"finding_id": finding_id}},
            {
                "id": "AQ-SIBLING",
                "status": "queued",
                "type": "sibling-chain-review",
                "metadata": {"finding_id": finding_id},
            },
        ]
    )
    queue_path.write_text(json.dumps(queue), encoding="utf-8")

    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    persisted = json.loads(queue_path.read_text(encoding="utf-8"))

    assert replay["status"] == "deduplicated"
    assert replay["action_queue"]["status"] == "deduplicated"
    assert {item["status"] for item in persisted["actions"][1:]} == {"queued"}


def test_runner_sync_completes_missing_claim_identity_without_creating_second_finding(tmp_path):
    import finding_index

    target = "target.test"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    claim_path = findings_dir / "manual-authz.json"
    claim_path.write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Interrupted authorization validation",
                "vuln_class": "authz",
                "evidence": {"artifact": "evidence/target.test/raw.json"},
            }
        ),
        encoding="utf-8",
    )
    claim = finding_index.list_root_finding_claims(findings_dir, target=target)[0]
    finding_index.reconcile_root_finding_claims(findings_dir, target=target)
    summary_path = tmp_path / "evidence" / target / "validation" / claim["id"] / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text("{}\n", encoding="utf-8")

    sync = validation_runner._sync_finding_status(
        {
            "target": target,
            "finding_id": claim["id"],
            "result": "tested_finding",
            "url": "https://target.test/api/orders/42",
            "vuln_class": "authz",
            "lane": "authz_public_exposure",
            "summary_path": str(summary_path),
            "evidence_rubric": {"status": "candidate-ready", "ready": True},
        },
        repo_root=tmp_path,
    )
    payload = finding_index.load_finding_index(findings_dir)
    row = payload["findings"][0]

    assert sync["status"] == "updated"
    assert payload["total"] == 1
    assert row["id"] == claim["id"]
    assert row["url"] == "https://target.test/api/orders/42"
    assert "endpoint" not in row["incomplete_fields"]
    assert row["claim_status"] == "complete"


def test_runner_sync_rejects_off_target_completion_for_missing_endpoint(tmp_path):
    import finding_index

    target = "target.test"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    (findings_dir / "manual-authz.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Interrupted authorization validation",
                "vuln_class": "authz",
                "evidence": {"artifact": "evidence/target.test/raw.json"},
            }
        ),
        encoding="utf-8",
    )
    claim = finding_index.list_root_finding_claims(findings_dir, target=target)[0]
    finding_index.reconcile_root_finding_claims(findings_dir, target=target)

    sync = validation_runner._sync_finding_status(
        {
            "target": target,
            "finding_id": claim["id"],
            "result": "tested_finding",
            "url": "other.test/api/orders/42",
            "vuln_class": "authz",
            "lane": "authz_public_exposure",
        },
        repo_root=tmp_path,
    )
    row = finding_index.find_finding(findings_dir, claim["id"])

    assert sync["status"] == "skipped"
    assert "off target" in sync["reason"]
    assert row is not None
    assert row["url"] == ""
    assert "endpoint" in row["incomplete_fields"]


@pytest.mark.parametrize(
    ("runner_url", "runner_class", "reason"),
    [
        (
            "https://target.test/api/orders/99",
            "authz",
            "runner endpoint conflicts with non-empty canonical finding identity",
        ),
        (
            "https://target.test/api/orders/42",
            "sqli",
            "runner vulnerability class conflicts with non-empty canonical finding identity",
        ),
    ],
)
def test_runner_sync_rejects_non_empty_canonical_identity_conflicts(
    tmp_path,
    runner_url,
    runner_class,
    reason,
):
    import finding_index

    target = "target.test"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    (findings_dir / "manual-authz.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Authorization validation",
                "endpoint": "/api/orders/42",
                "vuln_class": "authz",
                "evidence": {"artifact": "evidence/target.test/raw.json"},
            }
        ),
        encoding="utf-8",
    )
    claim = finding_index.list_root_finding_claims(findings_dir, target=target)[0]
    finding_index.reconcile_root_finding_claims(findings_dir, target=target)
    index_path = findings_dir / "findings.json"
    events_path = findings_dir / "mutation-events.jsonl"
    index_before = index_path.read_bytes()
    events_before = events_path.read_bytes()

    sync = validation_runner._sync_finding_status(
        {
            "target": target,
            "finding_id": claim["id"],
            "result": "tested_finding",
            "url": runner_url,
            "vuln_class": runner_class,
            "lane": "authz_public_exposure",
        },
        repo_root=tmp_path,
    )

    assert sync["status"] == "skipped"
    assert sync["reason"] == reason
    assert index_path.read_bytes() == index_before
    assert events_path.read_bytes() == events_before


def test_authz_public_exposure_cli_reuses_existing_url_finding_without_id(monkeypatch, tmp_path, capsys):
    target = "https://target.test"
    url = "https://target.test/api/Feedbacks"
    key = _target_key(target)
    findings_dir = tmp_path / "findings" / key
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "target": target,
                "total": 1,
                "findings": [
                    {
                        "id": "AUTHZ-SCANNER-ID",
                        "type": "auth_bypass",
                        "category": "auth_bypass",
                        "severity": "high",
                        "confidence": "medium",
                        "url": url,
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    body = json.dumps(
        {
            "data": [
                {
                    "comment": (
                        'wallet seed phrase: '
                        '"purpose betray marriage blame crunch monitor spin slide donate sport lift clutch"'
                    )
                }
            ]
        }
    )
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=body),
    )

    rc = validation_runner.main([
        "authz-public-exposure",
        "--repo-root",
        str(tmp_path),
        "--target",
        target,
        "--url",
        url,
    ])
    summary = json.loads(capsys.readouterr().out)
    findings = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert summary["result"] == "tested_finding"
    assert summary["sync"]["finding"]["status"] == "updated"
    assert summary["sync"]["finding"]["finding_id"] == "AUTHZ-SCANNER-ID"
    assert summary["sync"]["finding"]["matched_by"] == "url"
    assert len(findings["findings"]) == 1
    assert findings["findings"][0]["validation_status"] == "candidate"


def test_authz_public_exposure_sync_refuses_ambiguous_validation_actions(monkeypatch, tmp_path, capsys):
    target = "https://target.test"
    url = "https://target.test/api/Feedbacks"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-0001",
                        "status": "queued",
                        "type": "candidate-evidence-gap",
                        "priority": 105,
                        "evidence": f"Candidate evidence gap for finding AUTHZ-SCANNER-ID on {url}",
                        "next_question": "Fill missing evidence.",
                        "action": f"Candidate evidence gap for finding AUTHZ-SCANNER-ID on {url}",
                        "command_hint": "fill missing rubric evidence, then /validate",
                    },
                    {
                        "id": "AQ-0002",
                        "status": "queued",
                        "type": "validation",
                        "priority": 100,
                        "evidence": f"Run /validate for finding AUTHZ-SCANNER-ID on {url}",
                        "next_question": "Validate candidate.",
                        "action": f"Run /validate for finding AUTHZ-SCANNER-ID on {url}",
                        "command_hint": "/validate",
                    },
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    body = json.dumps(
        {
            "data": [
                {
                    "comment": (
                        'wallet seed phrase: '
                        '"purpose betray marriage blame crunch monitor spin slide donate sport lift clutch"'
                    )
                }
            ]
        }
    )
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=body),
    )

    rc = validation_runner.main([
        "authz-public-exposure",
        "--repo-root",
        str(tmp_path),
        "--target",
        target,
        "--url",
        url,
    ])
    summary = json.loads(capsys.readouterr().out)
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert summary["sync"]["action_queue"]["status"] == "ambiguous"
    assert set(summary["sync"]["action_queue"]["ids"]) == {"AQ-0001", "AQ-0002"}
    assert {item["status"] for item in queue["actions"]} == {"queued"}


def test_authz_public_exposure_cli_syncs_ranked_surface_action(monkeypatch, tmp_path, capsys):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-version"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-0002",
                        "status": "queued",
                        "type": "ranked-surface",
                        "priority": 60,
                        "evidence": f"Continue top ranked surface {url}",
                        "next_question": "Replay the ranked surface.",
                        "action": f"Replay {url} and classify it.",
                        "command_hint": "focused hunt on ranked P1/P2 surface",
                        "metadata": {"url": url, "endpoint": "/rest/admin/application-version"},
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"version":"1.2.3"}'),
    )

    rc = validation_runner.main(
        [
            "authz-public-exposure",
            "--repo-root",
            str(tmp_path),
            "--target",
            target,
            "--url",
            url,
            "--finding-id",
            "RANKED-VERSION",
        ]
    )
    summary = json.loads(capsys.readouterr().out)
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert summary["result"] == "tested_clean"
    assert summary["sync"]["finding"]["status"] == "skipped"
    assert summary["sync"]["action_queue"]["status"] == "updated"
    assert queue["actions"][0]["status"] == "tested"


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
    assert summary["evidence_rubric"]["ready"] is False
    assert summary["evidence_rubric"]["status"] == "tested-clean"


def test_sqli_result_diff_creates_diff_bundle_and_ledger(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        parsed = urlparse(kwargs["url"])
        q = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
        if q == "'))--":
            return _fake_response(kwargs["url"], body='{"data":[{"id":1},{"id":2},{"id":3}]}')
        return _fake_response(kwargs["url"], body='{"data":[{"id":1}]}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    identity_v2 = build_closure_cell(
        "/rest/products/search?q=",
        "SQLi",
        {"method": "GET", "parameter": "q"},
    ).key.to_dict()

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
        identity_v2=identity_v2,
    )

    key = _target_key("https://target.test")
    bundle = (tmp_path / summary["summary_path"]).parent
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["repeat"] == 2
    assert all(run["diff"]["changed"]["json_count"] for run in summary["runs"])
    assert (tmp_path / summary["runs"][0]["artifacts"]["baseline_request"]).is_file()
    assert (tmp_path / summary["runs"][0]["artifacts"]["variant_response"]).is_file()
    assert (bundle / "diff.json").is_file()
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["endpoint"] == "/rest/products/search?q="
    assert entry["vuln_class"] == "SQLi"
    assert entry["result"] == "tested_finding"
    assert entry["identity_v2"] == identity_v2


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


def test_sqli_result_diff_quote_only_result_shrink_is_not_finding(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        parsed = urlparse(kwargs["url"])
        q = parse_qs(parsed.query, keep_blank_values=True).get("name", [""])[0]
        if q == "Score Board":
            return _fake_response(
                kwargs["url"],
                body=json.dumps({
                    "data": [{
                        "id": 75,
                        "name": "Score Board",
                        "description": "Find the hidden score board page.",
                    }]
                }),
            )
        return _fake_response(kwargs["url"], body='{"data":[]}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_sqli_result_diff(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/Challenges?name=Score%20Board",
        param="name",
        baseline_value="Score Board",
        variant_value="Score Board'",
        finding_id="SQLI-QUOTE-SHRINK",
        repeat=2,
    )

    assert summary["probe_shape"] is True
    assert summary["runs"][0]["diff"]["changed"]["json_count"] is True
    assert summary["runs"][0]["sqli_evidence"]["strong"] is False
    assert "ordinary search/filter/parser behavior" in summary["sqli_evidence"]["ambiguous"][0]
    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False
    assert summary["evidence_rubric"]["ready"] is False
    assert "strong_sqli_signal" in summary["evidence_rubric"]["missing"]


def test_request_diff_replays_post_json_with_sql_classifier(monkeypatch, tmp_path):
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
    assert summary["ledger_record"]["write_status"] in {"written", "deduplicated", "updated"}
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["ledger"]["status"] in {
        "written",
        "deduplicated",
        "updated",
    }
    assert all(run["method"] if "method" in run else True for run in summary["runs"])


def test_request_diff_without_canonical_ledger_family_keeps_sync_skipped(monkeypatch, tmp_path):
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

    assert summary["ledger_record"]["write_status"] == "skipped"
    assert sync["status"] == "skipped"
    assert sync["ledger"]["status"] == "skipped"
    assert "error" not in sync["ledger"]


def test_request_diff_marks_multipart_manual_required_without_request(monkeypatch, tmp_path):
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


def test_request_diff_replay_keeps_operation_id_and_one_ledger_event(monkeypatch, tmp_path):
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
    ledger = tmp_path / "memory" / "evidence" / _target_key("https://target.test") / "ledger.jsonl"
    assert first["operation_id"] == second["operation_id"]
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 1


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
    bundle = (tmp_path / summary["summary_path"]).parent
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["lane"] == "marker_replay"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert all(run["marker_found"] for run in summary["runs"])
    assert (tmp_path / summary["runs"][0]["artifacts"]["request"]).is_file()
    assert (tmp_path / summary["runs"][1]["artifacts"]["response"]).is_file()
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


def test_websocket_protocol_replay_binds_frames_and_resumes_operation(tmp_path):
    calls = []

    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"private":"FRAME_MARKER"}\n', stderr="")

    spec = {
        "schema_version": 1,
        "protocol": "websocket",
        "endpoint": "wss://target.test/socket",
        "frames": ['{"op":"subscribe","channel":"SAMPLE"}'],
        "expect": {"marker": "FRAME_MARKER", "finding_grade": True},
        "vuln_class": "Authz",
        "actor": "peer",
        "object_scope": "other_object_same_org",
    }
    first = validation_runner.run_protocol_replay(
        repo_root=tmp_path,
        target="target.test",
        spec=spec,
        finding_id="WS-FRAME-1",
        state_changing=False,
        headers={"Origin": "https://target.test"},
        execute=execute,
        which=lambda name: f"/usr/bin/{name}",
    )
    second = validation_runner.run_protocol_replay(
        repo_root=tmp_path,
        target="target.test",
        spec=spec,
        finding_id="WS-FRAME-1",
        state_changing=False,
        headers={"Origin": "https://target.test"},
        execute=execute,
        which=lambda name: f"/usr/bin/{name}",
    )

    assert first["result"] == "tested_finding"
    assert first["operation_id"] == second["operation_id"]
    assert calls[0][0] == [
        "/usr/bin/websocat", "-n1", "-t", "-H",
        "Origin: https://target.test", "wss://target.test/socket",
    ]
    assert calls[0][1]["input"].endswith("\n")
    assert "shell" not in calls[0][1]
    assert (tmp_path / first["artifacts"]["protocol_request"]).is_file()
    assert (tmp_path / first["artifacts"]["response"]).is_file()


def test_grpc_protocol_replay_keeps_request_off_argv_and_saves_trailers(tmp_path):
    observed = {}

    def execute(argv, **kwargs):
        observed.update({"argv": argv, **kwargs})
        return SimpleNamespace(
            returncode=0,
            stdout='{"record":"SERIAL"}\n{"done":true}\n',
            stderr="Response trailers received:\ngrpc-status: 0\n",
        )

    summary = validation_runner.run_protocol_replay(
        repo_root=tmp_path,
        target="target.test:50051",
        spec={
            "schema_version": 1,
            "protocol": "grpc",
            "endpoint": "target.test:50051",
            "method": "sample.Inventory/List",
            "request": {"cursor": "OFFSET"},
            "plaintext": True,
            "expect": {"marker": "SERIAL", "finding_grade": True},
            "vuln_class": "Authz",
        },
        finding_id="GRPC-STREAM-1",
        state_changing=False,
        headers={"x-tenant": "SAMPLE"},
        execute=execute,
        which=lambda name: f"/usr/bin/{name}",
    )

    assert summary["result"] == "tested_finding"
    assert observed["argv"][-2:] == ["target.test:50051", "sample.Inventory/List"]
    assert observed["argv"][-4:-2] == ["-H", "x-tenant: SAMPLE"]
    assert "OFFSET" not in " ".join(observed["argv"])
    assert json.loads(observed["input"])["cursor"] == "OFFSET"
    assert "grpc-status: 0" in (tmp_path / summary["artifacts"]["trailers"]).read_text()


def test_llm_tool_call_protocol_replay_parses_exact_tool_and_arguments(monkeypatch, tmp_path):
    body = json.dumps({
        "choices": [{
            "message": {
                "tool_calls": [{
                    "type": "function",
                    "function": {"name": "lookup_record", "arguments": '{"id":"SERIAL"}'},
                }],
            },
        }],
    })
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=body),
    )

    summary = validation_runner.run_protocol_replay(
        repo_root=tmp_path,
        target="target.test",
        spec={
            "schema_version": 1,
            "protocol": "llm_tool_call",
            "endpoint": "https://target.test/v1/chat",
            "body": {"prompt": "SAMPLE"},
            "expect": {
                "tool_name": "lookup_record",
                "argument_marker": "SERIAL",
                "finding_grade": True,
            },
            "vuln_class": "BusinessLogic",
        },
        finding_id="LLM-TOOL-1",
        state_changing=False,
    )

    assert summary["result"] == "tested_finding"
    assert summary["observation"]["tool_calls"] == [
        {"name": "lookup_record", "arguments": '{"id":"SERIAL"}'},
    ]
    assert (tmp_path / summary["artifacts"]["request"]).is_file()
    assert (tmp_path / summary["artifacts"]["response"]).is_file()


def test_marker_replay_control_proves_baseline_absence(monkeypatch, tmp_path):
    marker = "CCST_UNIQUE_MARKER_42"

    def fake_request_once(**kwargs):
        return _fake_response(
            kwargs["url"],
            body="ordinary output" if "neutral" in kwargs["url"] else f"rendered {marker}",
        )

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url=f"https://target.test/render?q={marker}",
        baseline_url="https://target.test/render?q=neutral",
        expect_marker=marker,
        finding_id="MARKER-ORACLE-PASS",
        vuln_class="SSTI",
        no_ledger=True,
    )

    assert summary["result"] == "tested_finding"
    assert summary["marker_oracle"]["status"] == "passed"
    assert summary["marker_oracle"]["baseline_absent"] is True
    assert summary["runs"][0]["baseline_marker_found"] is False


def test_marker_replay_valid_control_without_marker_is_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="ordinary output"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?q=neutral",
        baseline_url="https://target.test/render?q=control",
        expect_marker="CCST_UNIQUE_MARKER_42",
        finding_id="MARKER-ORACLE-CLEAN",
        no_ledger=True,
    )

    assert summary["result"] == "tested_clean"
    assert summary["marker_oracle"]["status"] == "rejected"
    assert summary["marker_oracle"]["baseline_valid"] is True


def test_marker_replay_control_rejects_natural_marker_and_weak_token(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="already contains MARKER"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?q=MARKER",
        baseline_url="https://target.test/render?q=neutral",
        expect_marker="MARKER",
        finding_id="MARKER-ORACLE-REJECT",
        no_ledger=True,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["marker_oracle"]["status"] == "rejected"
    assert summary["marker_oracle"]["baseline_absent"] is False
    assert summary["marker_oracle"]["marker_quality"]["sufficient"] is False


@pytest.mark.parametrize("invalid_kind", ["status", "truncated"])
def test_marker_replay_invalid_control_never_returns_tested_terminal(
    monkeypatch, tmp_path, invalid_kind
):
    marker = "CCST_UNIQUE_MARKER_42"

    def fake_request_once(**kwargs):
        if "neutral" in kwargs["url"]:
            response = _fake_response(
                kwargs["url"],
                status=500 if invalid_kind == "status" else 200,
                body="ordinary output",
            )
            if invalid_kind == "truncated":
                response["body_truncated"] = True
            return response
        return _fake_response(kwargs["url"], body=f"rendered {marker}")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url=f"https://target.test/render?q={marker}",
        baseline_url="https://target.test/render?q=neutral",
        expect_marker=marker,
        finding_id=f"MARKER-INVALID-{invalid_kind}",
        no_ledger=True,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["marker_oracle"]["status"] == "invalid_control"
    assert summary["marker_oracle"]["baseline_valid"] is False


def test_xss_marker_reflection_stays_open_signal_until_browser_context(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="reflected CCST_XSS_MARKER"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/reflected?q=CCST_XSS_MARKER",
        expect_marker="CCST_XSS_MARKER",
        finding_id="XSS-MARKER-SIGNAL",
        vuln_class="XSS",
        repeat=2,
    )

    ledger = tmp_path / "memory" / "evidence" / _target_key("https://target.test") / "ledger.jsonl"
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])

    assert summary["result"] == "tested_finding"
    assert summary["evidence_rubric"]["ready"] is False
    assert entry["result"] == "signal"
    assert "reflected" in summary["ai_next"]["hypothesis"]
    assert "browser execution context" in summary["ai_next"]["next_action"]


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
    bundle = (tmp_path / summary["summary_path"]).parent
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["lane"] == "idor_actor_pair"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert all(run["strong_access"] for run in summary["runs"])
    assert (tmp_path / summary["runs"][0]["artifacts"]["owner_request"]).is_file()
    assert (tmp_path / summary["runs"][1]["artifacts"]["peer_response"]).is_file()
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
    assert summary["evidence_rubric"]["status"] == "tested-clean"
    assert "peer denied" in summary["evidence_rubric"]["summary"]


def test_idor_actor_pair_blocked_400_peer_is_clean(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        token = (kwargs.get("headers") or {}).get("Authorization", "")
        if token == "Bearer owner":
            return _fake_response(kwargs["url"], body='{"id":7,"email":"victim@example.test"}')
        return _fake_response(
            kwargs["url"],
            status=400,
            body='{"status":"error","data":"Malicious activity detected"}',
        )

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)

    summary = validation_runner.run_idor_actor_pair(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/cards/7",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        expect_marker="victim@example.test",
        finding_id="IDOR-PAIR-BLOCKED-400",
    )

    assert summary["result"] == "tested_clean"
    assert summary["runs"][0]["peer_denied"] is True
    assert summary["evidence_rubric"]["status"] == "tested-clean"
    assert "peer denied" in summary["evidence_rubric"]["summary"]


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


def test_idor_actor_pair_exact_empty_collection_match_is_not_finding(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"status":"success","data":[]}'),
    )

    summary = validation_runner.run_idor_actor_pair(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/cards",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="IDOR-EMPTY-COLLECTION",
    )

    assert summary["runs"][0]["exact_body_match"] is True
    assert summary["runs"][0]["private_body_match"] is False
    assert summary["runs"][0]["ambiguous_access"] is True
    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False


def test_idor_actor_pair_exact_private_body_match_without_marker_is_finding(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"orderId":123,"email":"victim@example.test"}'),
    )

    summary = validation_runner.run_idor_actor_pair(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/api/orders/123",
        owner_headers={"Authorization": "Bearer owner"},
        peer_headers={"Authorization": "Bearer peer"},
        finding_id="IDOR-PRIVATE-BODY-MATCH",
    )

    assert summary["runs"][0]["exact_body_match"] is True
    assert summary["runs"][0]["private_body_match"] is True
    assert summary["runs"][0]["strong_access"] is True
    assert summary["result"] == "tested_finding"


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
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True, exist_ok=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-0001",
                        "status": "queued",
                        "type": "case-state-validation",
                        "priority": 110,
                        "evidence": "Case-state validation backlog val_001",
                        "next_question": "Run validation runner from case state.",
                        "action": "Run idor-actor-pair --from-case-state --backlog-id val_001",
                        "command_hint": "python3 tools/validation_runner.py idor-actor-pair --from-case-state --backlog-id val_001",
                        "metadata": {
                            "backlog_id": "val_001",
                            "runner": "idor-actor-pair",
                            "object_ref": "order_123",
                        },
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

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
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))
    findings = json.loads((tmp_path / "findings" / key / "findings.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert summary["result"] == "tested_finding"
    assert summary["url"] == "https://target.test/api/orders/123"
    assert summary["expect_marker_sha256"] == validation_runner.hashlib.sha256(
        b"victim@example.test"
    ).hexdigest()
    assert summary["case_state_ref"]["backlog_id"] == "val_001"
    assert summary["case_state_ref"]["owner_session_id"] == "sess_user_a"
    assert summary["case_state_ref"]["peer_session_id"] == "sess_user_b"
    assert summary["case_state_write_back"]["status"] == "tested_finding"
    assert summary["sync"]["finding"]["status"] == "created"
    assert summary["sync"]["action_queue"]["status"] == "updated"
    assert backlog["status"] == "tested_finding"
    assert backlog["evidence_ref"].endswith("summary.json")
    assert queue["actions"][0]["status"] == "candidate"
    assert findings["findings"][0]["id"] == "IDOR-CASE-STATE"
    assert findings["findings"][0]["validation_status"] == "candidate"
    assert findings["findings"][0]["title"].startswith("Candidate IDOR")
    assert findings["findings"][0]["confidence"] == "high"
    assert findings["findings"][0]["report_status"] == "not_generated"


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
    )

    assert resolved["case_state_ref"]["owner_actor"] == "user_a"
    assert resolved["case_state_ref"]["peer_actor"] == "user_b"
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

    with pytest.raises(ValueError, match="at least two case_state actor sessions"):
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


def test_cli_auth_file_builds_session_and_raw_header_keeps_precedence(monkeypatch, tmp_path, capsys):
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps({"target": "target.test", "bearer": "session-token"}),
        encoding="utf-8",
    )
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"result": "tested_clean"}

    monkeypatch.setattr(validation_runner, "run_marker_replay", fake_run)
    assert validation_runner.main([
        "marker-replay",
        "--target",
        "target.test",
        "--url",
        "https://target.test/check",
        "--expect-marker",
        "SAFE",
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


@pytest.mark.parametrize("failed_owner", ["ledger", "finding", "action_queue"])
def test_runner_reconciliation_replay_repairs_each_owner_without_duplicates(
    monkeypatch,
    tmp_path,
    failed_owner,
):
    summary, queue_path, key = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    owner_functions = {
        "ledger": "_sync_evidence_ledger",
        "finding": "_sync_finding_status",
        "action_queue": "_sync_action_queue",
    }
    owner_name = owner_functions[failed_owner]
    original = getattr(validation_runner, owner_name)
    if failed_owner == "ledger":
        ledger_path(tmp_path, summary["target"]).unlink()

    monkeypatch.setattr(
        validation_runner,
        owner_name,
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(f"{failed_owner} fault")),
    )
    partial = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert partial["status"] == "partial"
    assert partial[failed_owner]["status"] == "error"

    findings_dir = tmp_path / "findings" / key
    assert (findings_dir / "findings.json").is_file() is (failed_owner != "finding")
    assert ledger_path(tmp_path, summary["target"]).is_file() is (failed_owner != "ledger")
    interrupted_queue = json.loads(queue_path.read_text(encoding="utf-8"))["actions"][0]
    assert interrupted_queue["status"] == ("queued" if failed_owner == "action_queue" else "candidate")

    monkeypatch.setattr(validation_runner, owner_name, original)
    recovered = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)

    finding = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    events = (findings_dir / "mutation-events.jsonl").read_text(encoding="utf-8").splitlines()
    queue = json.loads(queue_path.read_text(encoding="utf-8"))["actions"][0]
    rows = ledger_path(tmp_path, summary["target"]).read_text(encoding="utf-8").splitlines()

    assert recovered["status"] == "updated"
    assert replay["status"] == "deduplicated"
    assert len(rows) == 1
    assert len(events) == 1
    assert finding["runner_operation_id"] == summary["operation_id"]
    assert queue["metadata"]["runner_operation_id"] == summary["operation_id"]
    assert queue["attempts"] == 1


def test_runner_replay_repairs_finding_event_missing_after_canonical_write(monkeypatch, tmp_path):
    original_append = finding_index._append_mutation_events
    failed = {"value": False}

    def fail_once(path, events):
        if not failed["value"]:
            failed["value"] = True
            raise OSError("mutation event fault")
        return original_append(path, events)

    monkeypatch.setattr(finding_index, "_append_mutation_events", fail_once)
    summary, queue_path, key = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(finding_index, "_append_mutation_events", original_append)

    recovered = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    findings_dir = tmp_path / "findings" / key
    finding = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    events = (findings_dir / "mutation-events.jsonl").read_text(encoding="utf-8").splitlines()
    queue = json.loads(queue_path.read_text(encoding="utf-8"))["actions"][0]

    assert recovered["status"] == "updated"
    assert replay["status"] == "deduplicated"
    assert len(events) == 1
    assert finding_index.verify_finding_owner_provenance(
        findings_dir,
        finding,
        target=summary["target"],
    )["valid"] is True
    assert queue["metadata"]["runner_operation_id"] == summary["operation_id"]


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


def test_state_changing_without_redline_fails_before_request(monkeypatch, tmp_path):
    called = False

    def fake_request_once(**kwargs):
        nonlocal called
        called = True
        return _fake_response(kwargs["url"], body="MARKER")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    with pytest.raises(ValueError, match="requires --redline-checked"):
        validation_runner.run_marker_replay(
            repo_root=tmp_path,
            target="target.test",
            url="https://target.test/submit",
            expect_marker="MARKER",
            method="POST",
            state_changing=True,
            redline_checked=False,
        )
    assert called is False


@pytest.mark.parametrize("state_changing", [None, False])
def test_patch_without_explicit_state_fact_is_not_redline_blocked(
    monkeypatch, tmp_path, state_changing
):
    called = False

    def fake_request_once(**kwargs):
        nonlocal called
        called = True
        return _fake_response(kwargs["url"], body="MARKER")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/submit",
        expect_marker="MARKER",
        method="PATCH",
        state_changing=state_changing,
        no_ledger=True,
    )
    assert called is True
    assert summary["state_changing"] is state_changing
    assert summary["redline_checked"] is False


def test_post_defaults_to_unknown_state_and_private_unique_runs(monkeypatch, tmp_path):
    secret = "SECRET_VALIDATION_FIXTURE"
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=f"result={secret}"),
    )

    summaries = [
        validation_runner.run_marker_replay(
            repo_root=tmp_path,
            target="target.test",
            url=f"https://target.test/submit?token={secret}",
            expect_marker=secret,
            method="POST",
            headers={"Authorization": f"Bearer {secret}"},
            body=secret,
            finding_id="MARKER-PRIVATE",
            no_ledger=True,
        )
        for _ in range(2)
    ]

    assert summaries[0]["summary_path"] != summaries[1]["summary_path"]
    assert summaries[0]["operation_id"] == summaries[1]["operation_id"]
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
