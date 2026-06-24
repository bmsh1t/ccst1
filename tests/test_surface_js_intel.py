from pathlib import Path

import surface_js_intel


def test_load_js_intel_hypotheses_returns_empty_payload_when_missing(tmp_path):
    payload = surface_js_intel.load_js_intel_hypotheses(tmp_path / "findings" / "target.com")

    assert payload == {
        "available": False,
        "endpoints": [],
        "leads": [],
        "graphql_operations": [],
    }


def test_load_js_intel_hypotheses_uses_attack_surface_or_ranked_leads(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    js_intel_dir = findings_dir / "js_intel"
    js_intel_dir.mkdir(parents=True)

    (js_intel_dir / "hypotheses.json").write_text(
        (
            '{"endpoints":[{"path":"/api/admin/export"}],'
            '"ranked_leads":[{"title":"fallback lead"}],'
            '"graphql_operations":[{"name":"ExportOrders"}]}'
        ),
        encoding="utf-8",
    )

    payload = surface_js_intel.load_js_intel_hypotheses(findings_dir)

    assert payload["available"] is True
    assert payload["endpoints"] == [{"path": "/api/admin/export"}]
    assert payload["leads"] == [{"title": "fallback lead"}]
    assert payload["graphql_operations"] == [{"name": "ExportOrders"}]


def test_build_js_intel_urls_and_counts_normalize_relative_paths():
    js_intel = {
        "endpoints": [
            {"path": "/api/admin/export?order_id=42", "method": "POST"},
            {"path": "graphql", "method": "POST"},
            {"path": "wss://api.target.com/ws?tenantId=acme", "method": "WS"},
            {"path": "https://cdn.target.com/api/public", "method": "GET"},
        ],
        "leads": [{"title": "lead 1"}, {"title": "lead 2"}],
        "graphql_operations": [{"name": "ExportOrders"}],
    }

    urls = surface_js_intel.build_js_intel_urls(js_intel, "https://app.target.com")

    assert urls == {
        "https://app.target.com/api/admin/export?order_id=42": [
            {"path": "/api/admin/export?order_id=42", "method": "POST"}
        ],
        "https://app.target.com/graphql": [
            {"path": "graphql", "method": "POST"}
        ],
        "wss://api.target.com/ws?tenantId=acme": [
            {"path": "wss://api.target.com/ws?tenantId=acme", "method": "WS"}
        ],
        "https://cdn.target.com/api/public": [
            {"path": "https://cdn.target.com/api/public", "method": "GET"}
        ],
    }
    assert surface_js_intel.js_intel_counts(js_intel) == {
        "endpoint_count": 4,
        "lead_count": 2,
        "graphql_count": 1,
    }
