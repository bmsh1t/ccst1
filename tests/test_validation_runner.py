"""Tests for deterministic validation runner v1 lanes."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
