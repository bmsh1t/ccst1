"""Regression tests for importing browser MCP artifacts into recon surface."""

import json
from pathlib import Path

import browser_mcp_import


def test_browser_mcp_import_writes_surface_and_evidence(tmp_path):
    network_path = tmp_path / "network.json"
    network_path.write_text(
        json.dumps(
            [
                {
                    "url": "https://target.local/api/me?account_id=123",
                    "method": "GET",
                    "resourceType": "xhr",
                    "status": 200,
                },
                {
                    "request": {
                        "url": "https://target.local/graphql",
                        "method": "POST",
                        "postData": {
                            "text": '{"query":"query User($id:ID!){user(id:$id){email}}","variables":{"id":"123"}}'
                        },
                    },
                    "type": "fetch",
                    "response": {"status": 200},
                },
                {
                    "url": "https://target.local/static/app.js?v=1",
                    "method": "GET",
                    "type": "script",
                },
            ]
        ),
        encoding="utf-8",
    )
    snapshot_path = tmp_path / "snapshot.txt"
    snapshot_path.write_text('<form action="/login" method="post"></form>', encoding="utf-8")
    console_path = tmp_path / "console.json"
    console_path.write_text(json.dumps({"messages": [{"type": "log", "text": "ready"}]}), encoding="utf-8")
    screenshot_path = tmp_path / "shot.png"
    screenshot_path.write_bytes(b"fake-png")

    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        url="https://target.local/app",
        network_path=network_path,
        snapshot_path=snapshot_path,
        console_path=console_path,
        screenshot_path=screenshot_path,
        label="chrome-devtools-mcp",
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
        source="chrome-devtools-mcp",
    )

    capture_dir = Path(summary["evidence_dir"])
    recon_browser = tmp_path / "recon" / "target.local" / "browser"
    pointer_path = tmp_path / "evidence" / "target.local" / "browser" / "last-capture.json"

    assert summary["capture_backend"] == "chrome-devtools-mcp"
    assert summary["counts"]["requests"] == 3
    assert summary["counts"]["console"] == 1
    assert summary["counts"]["browser_xhr_endpoints"] == 2
    assert summary["counts"]["browser_api_endpoints"] == 2
    assert summary["counts"]["browser_params"] == 5
    assert (capture_dir / "requests.json").is_file()
    assert (capture_dir / "snapshot.txt").read_text(encoding="utf-8") == '<form action="/login" method="post"></form>'
    assert (capture_dir / "screenshot.png").read_bytes() == b"fake-png"
    assert pointer_path.is_file()

    assert (recon_browser / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=123",
        "https://target.local/graphql",
    ]
    assert (recon_browser / "api_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=123",
        "https://target.local/graphql",
    ]
    assert (recon_browser / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=123 :: account_id",
        "https://target.local/graphql :: id",
        "https://target.local/graphql :: query",
        "https://target.local/graphql :: variables",
        "https://target.local/static/app.js?v=1 :: v",
    ]
    forms = json.loads((recon_browser / "forms.json").read_text(encoding="utf-8"))
    assert forms["forms"] == [{"action": "/login", "method": "POST"}]


def test_normalize_mcp_network_accepts_har_entries():
    payload = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://target.local/rest/products/search?q=chair",
                        "method": "POST",
                        "postData": "sort=price",
                    },
                    "response": {"status": 200},
                }
            ]
        }
    }

    normalized = browser_mcp_import.normalize_mcp_network(payload)

    assert normalized == [
        {
            "url": "https://target.local/rest/products/search?q=chair",
            "method": "POST",
            "resourceType": "",
            "status": 200,
            "postData": "sort=price",
        }
    ]


def test_browser_mcp_import_accepts_raw_playwright_network_text(tmp_path):
    network_path = tmp_path / "network.txt"
    network_path.write_text(
        "1. [GET] http://127.0.0.1:3002/rest/products/search?q= => [200] OK\n"
        "2. [POST] http://127.0.0.1:3002/socket.io/?EIO=4&transport=polling => [200] OK\n"
        '\nNote: static requests not shown.\n',
        encoding="utf-8",
    )

    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="http://127.0.0.1:3002",
        url="http://127.0.0.1:3002/#/",
        network_path=network_path,
        label="playwright-mcp",
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
        source="playwright-mcp",
    )

    target_key = "http:_127.0.0.1:3002"
    recon_browser = tmp_path / "recon" / target_key / "browser"
    assert summary["counts"]["requests"] == 2
    assert (recon_browser / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "http://127.0.0.1:3002/rest/products/search?q=",
        "http://127.0.0.1:3002/socket.io/?EIO=4&transport=polling",
    ]
    assert (recon_browser / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "http://127.0.0.1:3002/rest/products/search?q= :: q",
        "http://127.0.0.1:3002/socket.io/?EIO=4&transport=polling :: EIO",
        "http://127.0.0.1:3002/socket.io/?EIO=4&transport=polling :: transport",
    ]
