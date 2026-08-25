from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import workflow_sequence as sequence
from tools.action_queue import load_queue


def _response(url: str, body: str, *, headers=None) -> dict:
    return {
        "url": url,
        "method": "GET",
        "request_text": f"GET {url} HTTP/1.1",
        "status": 200,
        "headers": headers or {"Content-Type": "application/json"},
        "body": body,
        "body_truncated": False,
        "body_observed_bytes": len(body),
        "response_text": body,
    }


def _write_steps(tmp_path, steps):
    path = tmp_path / "browser" / "flow.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema_version": 1, "target": "target.test", "steps": steps}), encoding="utf-8")
    return path


def test_sequence_replay_perturb_diff_writes_private_evidence_and_queue(monkeypatch, tmp_path):
    evidence = _write_steps(tmp_path, [
        {"id": "login", "url": "https://target.test/api/login", "method": "POST", "body": "x=1", "state_effect": "read_only"},
        {"id": "profile", "url": "https://target.test/api/profile", "method": "GET", "state_effect": "read_only"},
    ])
    calls = []

    def fake_request_once(**kwargs):
        calls.append(kwargs["url"])
        if kwargs["url"].endswith("/profile") and len(calls) > 2:
            return _response(kwargs["url"], '{"data":{"error":"guest"}}')
        return _response(kwargs["url"], '{"data":{"owner":true}}')

    monkeypatch.setattr(sequence, "request_once", fake_request_once)
    summary = sequence.run_sequence(
        repo_root=tmp_path,
        target="target.test",
        evidence_ref=str(evidence),
        perturb="remove",
        step_index=0,
        max_requests=8,
    )

    assert summary["status"] == "candidate_pending"
    assert summary["request_count"] == 3
    assert summary["diffs"][0]["changed"] is True
    assert (tmp_path / summary["evidence_artifact"]).is_file()
    queue = load_queue(tmp_path, "target.test")
    assert queue["actions"][0]["type"] == "workflow-sequence"
    assert queue["actions"][0]["status"] == "candidate"
    assert '"owner":true' not in json.dumps(summary)


def test_sequence_transition_identity_is_distinct_and_idempotent(monkeypatch, tmp_path):
    evidence = _write_steps(tmp_path, [
        {"id": "login", "url": "https://target.test/api/login", "method": "POST", "body": "x=1", "state_effect": "read_only"},
        {"id": "profile", "url": "https://target.test/api/profile", "method": "GET", "state_effect": "read_only"},
    ])
    calls = []

    def fake_request_once(**kwargs):
        calls.append(kwargs["url"])
        return _response(kwargs["url"], '{"ok":true}')

    monkeypatch.setattr(sequence, "request_once", fake_request_once)

    def run(perturb, step_index):
        return sequence.run_sequence(
            repo_root=tmp_path,
            target="target.test",
            evidence_ref=str(evidence),
            perturb=perturb,
            step_index=step_index,
            max_requests=8,
        )

    first = run("remove", 0)
    different_perturb = run("repeat", 0)
    different_step = run("remove", -1)
    replay = run("remove", 1)
    transitions = [first, different_perturb, different_step]
    request_count_before_replay = len(calls)

    assert len({item["summary_path"] for item in transitions}) == 3
    assert len({item["evidence_artifact"] for item in transitions}) == 3
    assert replay["summary_path"] == different_step["summary_path"]
    assert replay["evidence_artifact"] == different_step["evidence_artifact"]
    assert len(calls) == request_count_before_replay
    assert all((tmp_path / item["summary_path"]).is_file() for item in transitions)
    assert all((tmp_path / item["evidence_artifact"]).is_file() for item in transitions)
    queue = load_queue(tmp_path, "target.test")
    actions = [item for item in queue["actions"] if item["type"] == "workflow-sequence"]
    assert len(actions) == 3
    assert len({item["id"] for item in actions}) == 3
    assert len({item["source_id"] for item in actions}) == 3
    assert {item["metadata"]["generation"] for item in actions} == {
        Path(item["summary_path"]).parent.name for item in transitions
    }


def test_sequence_refreshes_scoped_token_per_step(monkeypatch, tmp_path):
    evidence = _write_steps(tmp_path, [
        {"id": "token", "url": "https://target.test/api/token", "method": "GET", "state_effect": "read_only"},
        {
            "id": "submit",
            "url": "https://target.test/api/submit",
            "method": "POST",
            "body": "csrf={TOKEN}",
            "state_effect": "read_only",
            "token": {"url": "https://target.test/api/token", "regex": "csrf=([A-Za-z0-9]+)", "header": "X-CSRF"},
        },
    ])
    seen = []

    def fake_request_once(**kwargs):
        seen.append(kwargs)
        if kwargs["url"].endswith("/token"):
            return _response(kwargs["url"], "csrf=abc123")
        return _response(kwargs["url"], "ok")

    monkeypatch.setattr(sequence, "request_once", fake_request_once)
    summary = sequence.run_sequence(
        repo_root=tmp_path,
        target="target.test",
        evidence_ref=str(evidence),
        perturb="repeat",
        step_index=0,
        max_requests=10,
    )

    assert summary["status"] == "tested_clean"
    assert summary["token_refresh_count"] == 2
    assert any(call.get("headers", {}).get("X-CSRF") == "abc123" for call in seen if call["url"].endswith("/submit"))


@pytest.mark.parametrize(
    ("token_spec", "body", "headers", "expected"),
    [
        ({"response_header": "X-CSRF-Token"}, "", {"x-csrf-token": "header-token"}, "header-token"),
        ({"cookie": "csrf"}, "", {"Set-Cookie": "csrf=cookie-token; Path=/; HttpOnly"}, "cookie-token"),
        ({"json_path": "$.data.0.token"}, '{"data":[{"token":"json-token"}]}', {}, "json-token"),
    ],
)
def test_refresh_token_supports_header_cookie_and_bounded_json_path(
    monkeypatch, token_spec, body, headers, expected
):
    monkeypatch.setattr(
        sequence,
        "request_once",
        lambda **kwargs: _response(kwargs["url"], body, headers=headers),
    )

    token, request_count = sequence._refresh_token(
        {"url": "https://target.test/api/use", "token": token_spec},
        target="target.test",
        session=sequence.AuthSession(target="target.test"),
        timeout=5,
    )

    assert token == expected
    assert request_count == 1


def test_refresh_token_rejects_ambiguous_extractors_before_request(monkeypatch):
    monkeypatch.setattr(
        sequence,
        "request_once",
        lambda **_: (_ for _ in ()).throw(AssertionError("network must not run")),
    )

    with pytest.raises(ValueError, match="exactly one extraction source"):
        sequence._refresh_token(
            {
                "url": "https://target.test/api/use",
                "token": {"regex": "token=(.+)", "json_path": "token"},
            },
            target="target.test",
            session=sequence.AuthSession(target="target.test"),
            timeout=5,
        )


def test_refresh_token_rejects_off_target_source_before_request(monkeypatch):
    monkeypatch.setattr(
        sequence,
        "request_once",
        lambda **_: (_ for _ in ()).throw(AssertionError("network must not run")),
    )

    with pytest.raises(ValueError, match="leaves target scope"):
        sequence._refresh_token(
            {
                "url": "https://target.test/api/use",
                "token": {"url": "https://other.test/token", "regex": "token=(.+)"},
            },
            target="target.test",
            session=sequence.AuthSession(target="target.test"),
            timeout=5,
        )


def test_step_request_rejects_token_without_injection_destination(monkeypatch):
    monkeypatch.setattr(
        sequence,
        "request_once",
        lambda **kwargs: _response(kwargs["url"], "csrf=token"),
    )

    with pytest.raises(ValueError, match="destination"):
        sequence._step_request(
            {
                "url": "https://target.test/api/use",
                "method": "POST",
                "headers": {},
                "body": "value=1",
                "token": {"regex": "csrf=([A-Za-z]+)"},
            },
            target="target.test",
            session=sequence.AuthSession(target="target.test"),
            timeout=5,
        )


def test_sequence_does_not_add_a_state_effect_gate(monkeypatch, tmp_path):
    evidence = _write_steps(tmp_path, [
        {"id": "one", "url": "https://target.test/api/one", "method": "POST", "body": "x=1"},
        {"id": "two", "url": "https://target.test/api/two", "method": "GET"},
    ])
    monkeypatch.setattr(sequence, "request_once", lambda **kwargs: _response(kwargs["url"], '{"ok":true}'))
    summary = sequence.run_sequence(repo_root=tmp_path, target="target.test", evidence_ref=str(evidence))
    assert summary["status"] == "tested_clean"
    assert summary["request_count"] == 3


def test_sequence_claims_before_first_request_and_resolves_after_summary(monkeypatch, tmp_path):
    evidence = _write_steps(tmp_path, [
        {"id": "one", "url": "https://target.test/api/one", "method": "POST", "body": "x=1"},
        {"id": "two", "url": "https://target.test/api/two", "method": "GET"},
    ])
    observed = {}

    def fake_request_once(**kwargs):
        observed.setdefault("request_status", load_queue(tmp_path, "target.test")["actions"][0]["status"])
        return _response(kwargs["url"], '{"ok":true}')

    real_resolve = sequence.resolve_action

    def checked_resolve(*args, **kwargs):
        summary_path = tmp_path / kwargs["result"]
        observed["summary_exists"] = summary_path.is_file()
        observed["summary_status"] = json.loads(summary_path.read_text())["status"]
        return real_resolve(*args, **kwargs)

    monkeypatch.setattr(sequence, "request_once", fake_request_once)
    monkeypatch.setattr(sequence, "resolve_action", checked_resolve)
    summary = sequence.run_sequence(repo_root=tmp_path, target="target.test", evidence_ref=str(evidence))

    assert summary["status"] == "tested_clean"
    assert observed == {"request_status": "running", "summary_exists": True, "summary_status": "tested_clean"}


def test_sequence_request_error_leaves_claim_running(monkeypatch, tmp_path):
    evidence = _write_steps(tmp_path, [
        {"id": "one", "url": "https://target.test/api/one", "method": "POST", "body": "x=1"},
        {"id": "two", "url": "https://target.test/api/two", "method": "GET"},
    ])
    monkeypatch.setattr(sequence, "request_once", lambda **_: (_ for _ in ()).throw(RuntimeError("fixture failure")))

    summary = sequence.run_sequence(repo_root=tmp_path, target="target.test", evidence_ref=str(evidence))

    assert summary["status"] == "partial"
    action = load_queue(tmp_path, "target.test")["actions"][0]
    assert action["status"] == "running"


def test_sequence_rejects_relative_step_url(tmp_path):
    evidence = _write_steps(tmp_path, [
        {"id": "one", "url": "/api/one", "method": "GET", "state_effect": "read_only"},
        {"id": "two", "url": "https://target.test/api/two", "method": "GET", "state_effect": "read_only"},
    ])
    with pytest.raises(ValueError, match=r"absolute HTTP\(S\)"):
        sequence.run_sequence(repo_root=tmp_path, target="target.test", evidence_ref=str(evidence))
