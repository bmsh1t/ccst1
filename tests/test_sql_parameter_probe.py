"""Regression tests for the shared non-JSON SQL matrix adapter."""

from __future__ import annotations

import sys

from tools import sql_parameter_probe as probe
from tools.json_inject_probe import PAYLOADS
from tools.sql_payloads import SQL_PAYLOADS


def _response(body: str, *, status: int = 200, latency: float = 0.05) -> dict:
    return {
        "status": status,
        "body_text": body,
        "body_size": len(body.encode("utf-8")),
        "headers": "",
        "latency": latency,
        "error": None,
    }


def test_json_and_parameter_adapters_share_the_same_sql_catalog():
    assert SQL_PAYLOADS == [item for item in PAYLOADS if item["class"].startswith("sqli_")]


def test_query_transport_rejects_out_of_scope_before_network():
    result = probe._http_request(
        "https://other.test/search?q=x",
        method="GET",
        timeout=1,
        target="target.test",
        session=None,
    )

    assert result["status"] == 0
    assert result["error"].startswith("OutOfScopeURL:")


def test_parameter_adapter_rejects_method_mismatch():
    assert probe._parameter_source(
        {"url": "https://target.test/search?q=x", "method": "POST"},
        "query",
    ) is None
    assert probe._parameter_source(
        {"url": "https://target.test/search", "method": "PUT", "body": "q=x"},
        "form",
    ) is None


def test_query_adapter_reuses_shared_boolean_matrix_and_encodes_query(monkeypatch):
    monkeypatch.setattr(probe, "SQL_PAYLOADS", [
        {
            "class": "sqli_boolean_true",
            "family": "boolean_pair",
            "pair_id": "q",
            "pair_side": "true",
            "value": "' AND 1=1--",
            "field_hint": ".*",
        },
        {
            "class": "sqli_boolean_false",
            "family": "boolean_pair",
            "pair_id": "q",
            "pair_side": "false",
            "value": "' AND 1=2--",
            "field_hint": ".*",
        },
    ])
    calls: list[str] = []
    responses = iter([
        _response('{"items":[1,2]}'),
        _response('{"items":[1,2]}'),
        _response('{"items":[]}', status=400),
    ])

    def fake_request(url, **kwargs):
        calls.append(url)
        return next(responses)

    monkeypatch.setattr(probe, "_http_request", fake_request)
    hits, events = probe.probe_parameter_endpoint(
        {"url": "https://target.test/search?q=hello world", "method": "GET"},
        mode="query",
        max_requests=6,
        target="target.test",
        session=None,
    )

    assert events == []
    assert len(hits) == 1
    assert hits[0]["payload_class"] == "sqli_boolean_pair"
    assert hits[0]["signal"] == "sqli_boolean_pair_difference"
    assert len(calls) == 3
    assert "q=%27+AND+1%3D1--" in calls[1]
    assert "q=%27+AND+1%3D2--" in calls[2]


def test_form_adapter_preserves_form_encoding_and_method(monkeypatch):
    monkeypatch.setattr(probe, "SQL_PAYLOADS", [{
        "class": "sqli_error",
        "value": "'",
        "field_hint": ".*",
    }])
    calls: list[dict] = []

    def fake_request(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return _response("{}")

    monkeypatch.setattr(probe, "_http_request", fake_request)
    probe.probe_parameter_endpoint(
        {"url": "https://target.test/search", "method": "POST", "body": "q=hello+world&sort=name"},
        mode="form",
        max_requests=4,
        target="target.test",
        session=None,
    )

    assert len(calls) == 3
    assert all(item["method"] == "POST" for item in calls)
    assert calls[0]["content_type"] == "application/x-www-form-urlencoded"
    assert b"q=%27" in calls[1]["body"]
    assert b"sort=%27" in calls[2]["body"]


def test_parameter_probe_shares_one_request_budget_across_endpoints(monkeypatch):
    endpoints = [
        {"url": f"https://target.test/search/{index}?q=x", "method": "GET"}
        for index in range(3)
    ]
    allocated: list[int] = []
    captured: dict = {}

    class Session:
        def bind_target(self, _target):
            return self

    def fake_probe(_endpoint, *, max_requests, stats, **_kwargs):
        allocated.append(max_requests)
        stats["request_count"] += max_requests
        return [], []

    def fake_write(_target, _lane, _hits, _events, execution):
        captured.update(execution)
        return {"summary": "", "files": []}

    monkeypatch.setattr(probe, "session_from_args", lambda _args: Session())
    monkeypatch.setattr(probe, "_read_inputs", lambda _path, _mode: endpoints)
    monkeypatch.setattr(probe, "probe_parameter_endpoint", fake_probe)
    monkeypatch.setattr(probe, "_write_results", fake_write)
    monkeypatch.setattr(sys, "argv", [
        "sql_parameter_probe", "--target", "target.test", "--urls-file", "unused", "--max-requests", "6"
    ])

    assert probe.main() == 0
    assert allocated == [2, 2, 2]
    assert captured["request_count"] == captured["request_budget"] == 6
    assert captured["budget_exhausted"] is True
