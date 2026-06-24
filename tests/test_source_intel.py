"""Tests for lightweight source intelligence extraction."""

import json

import source_intel


def test_source_intel_extracts_routes_graphql_and_hypotheses(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        """
        router.get("/api/users/:id/orders", handler)
        fetch("/api/admin/export?tenant_id=acme")
        const q = `mutation ApproveOrder($order_id: ID!) { approveOrder(order_id: $order_id) { id } }`
        """,
        encoding="utf-8",
    )
    recon_dir = tmp_path / "recon" / "target.com" / "browser"
    recon_dir.mkdir(parents=True)
    (recon_dir / "api_endpoints.txt").write_text(
        "https://app.target.com/api/invoice/download?invoice_id=9\n",
        encoding="utf-8",
    )

    result = source_intel.run_source_intel(
        target="target.com",
        repo_path=str(repo),
        repo_root=tmp_path,
    )

    out_dir = tmp_path / "findings" / "target.com" / "source_intel"
    routes = json.loads((out_dir / "routes.json").read_text(encoding="utf-8"))
    hypotheses = [
        json.loads(line)
        for line in (out_dir / "hypotheses.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    summary = (out_dir / "summary.md").read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert result["route_count"] >= 3
    assert result["graphql_count"] == 1
    assert any(item["route"] == "/api/users/:id/orders" for item in routes["routes"])
    assert any(item["type"] == "idor" and "invoice" in item["candidate"] for item in hypotheses)
    assert any(item["type"] == "business-logic" and "ApproveOrder" in item["candidate"] for item in hypotheses)
    assert "Source Intelligence Summary" in summary


def test_source_intel_extracts_realtime_oauth_and_framework_signals(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        """
        const ws = new WebSocket("wss://api.target.com/ws?tenantId=acme")
        fetch("/api/preview?url=https://example.test/image.png")
        fetch("/oauth/callback?redirect_uri=https://app.target.com/cb&state=x&client_id=abc")
        fetch("/api/files/upload")
        const csrfToken = window.__BOOT__.csrfToken
        //# sourceMappingURL=app.js.map
        window.__NEXT_DATA__ = {"props":{}}
        """,
        encoding="utf-8",
    )

    source_intel.run_source_intel(
        target="target.com",
        repo_path=str(repo),
        repo_root=tmp_path,
    )

    out_dir = tmp_path / "findings" / "target.com" / "source_intel"
    hypotheses = [
        json.loads(line)
        for line in (out_dir / "hypotheses.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    types = {item["type"] for item in hypotheses}

    assert {"websocket", "ssrf", "oauth", "upload", "csrf", "framework-intel"} <= types
    assert any(item["candidate"].startswith("wss://") for item in hypotheses)
    assert any(item["type"] == "framework-intel" and item.get("evidence") for item in hypotheses)
