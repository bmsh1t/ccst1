"""Regression tests for importing browser MCP artifacts into recon surface."""

import json
from pathlib import Path

import pytest

import browser_mcp_import
from tools.action_queue import load_queue
from tools import vision_browser
from runtime_state import inspect_browser_evidence


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
    assert '<form action="/login" method="POST">' in (capture_dir / "snapshot.txt").read_text(encoding="utf-8")
    assert Path(summary["artifacts"]["snapshot_private_txt"]).read_text(encoding="utf-8") == '<form action="/login" method="post"></form>'
    assert Path(summary["artifacts"]["screenshot_png"]).read_bytes() == b"fake-png"
    assert not (capture_dir / "screenshot.png").exists()
    assert pointer_path.is_file()
    screenshots = vision_browser.list_screenshots(
        "target.local",
        evidence_root=tmp_path / "evidence",
    )
    assert screenshots[0]["screenshot_path"] == summary["artifacts"]["screenshot_png"]
    assert screenshots[0]["dom_path"] == summary["artifacts"]["snapshot_private_txt"]

    assert (recon_browser / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=",
        "https://target.local/graphql",
    ]
    assert (recon_browser / "api_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=",
        "https://target.local/graphql",
    ]
    assert (recon_browser / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id= :: account_id",
        "https://target.local/graphql :: id",
        "https://target.local/graphql :: query",
        "https://target.local/graphql :: variables",
        "https://target.local/static/app.js?v= :: v",
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


def test_normalize_mcp_network_accepts_wrapped_mcp_data_envelope():
    payload = {
        "success": True,
        "data": {
            "requests": [
                {
                    "url": "https://target.local/api/export?format=csv",
                    "method": "POST",
                    "resourceType": "fetch",
                    "status": 202,
                }
            ]
        },
        "error": None,
    }

    assert browser_mcp_import.normalize_mcp_network(payload) == [
        {
            "url": "https://target.local/api/export?format=csv",
            "method": "POST",
            "resourceType": "fetch",
            "status": 202,
            "postData": "",
        }
    ]


def test_browser_mcp_import_accepts_current_chrome_devtools_envelopes(tmp_path):
    network_path = tmp_path / "network.json"
    network_path.write_text(
        json.dumps(
            {
                "networkRequests": [
                    {
                        "requestId": 1,
                        "method": "GET",
                        "url": "https://target.local/api/admin/export?account_id=42",
                        "status": "200",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    console_path = tmp_path / "console.json"
    console_path.write_text(
        json.dumps({"consoleMessages": [{"type": "info", "text": "ready", "id": 1}]}),
        encoding="utf-8",
    )

    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        url="https://target.local/app",
        network_path=network_path,
        console_path=console_path,
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
        source="chrome-devtools-mcp",
    )

    assert summary["status"] == "ok"
    assert summary["counts"]["requests"] == 1
    assert summary["counts"]["console"] == 1
    assert (tmp_path / "recon/target.local/browser/api_endpoints.txt").read_text(
        encoding="utf-8"
    ).splitlines() == ["https://target.local/api/admin/export?account_id="]


def test_browser_mcp_import_keeps_raw_console_and_state_private(tmp_path):
    secret = "PRIVATE_BROWSER_STATE"
    network_path = tmp_path / "network.log"
    network_path.write_text(
        "1. [GET] https://target.local/api/me => [200] OK\n",
        encoding="utf-8",
    )
    console_path = tmp_path / "console.log"
    console_path.write_text(
        f"Total messages: 2 (Errors: 1, Warnings: 0)\n\n[info] ready\n[error] {secret}\n",
        encoding="utf-8",
    )
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps({"cookie": secret, "localStorage": {"token": secret}}),
        encoding="utf-8",
    )

    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        url="https://target.local/app",
        network_path=network_path,
        console_path=console_path,
        state_path=state_path,
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    public_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in (tmp_path / "evidence").rglob("*")
        if path.is_file()
    )
    private_meta = summary["private_artifacts"]["browser_state"]
    assert summary["counts"]["console"] == 2
    assert private_meta["bytes"] > 0
    assert len(private_meta["sha256"]) == 64
    assert secret not in public_text
    assert secret in Path(private_meta["path"]).read_text(encoding="utf-8")


def test_focused_manifest_is_bounded_target_owned_and_queue_idempotent(tmp_path):
    secret = "FOCUSED_PRIVATE_STATE"

    def write_capture(name, request_url, snapshot_text):
        network = tmp_path / f"{name}-network.log"
        snapshot = tmp_path / f"{name}-snapshot.md"
        network.write_text(f"1. [GET] {request_url} => [200] OK\n", encoding="utf-8")
        snapshot.write_text(snapshot_text, encoding="utf-8")
        return network, snapshot

    high_network, high_snapshot = write_capture(
        "high",
        "https://target.local/api/admin/export?account_id=42",
        "admin export view",
    )
    high_network.write_text(
        high_network.read_text(encoding="utf-8")
        + "2. [GET] https://target.local/static/admin.js => [200] OK\n",
        encoding="utf-8",
    )
    low_network, low_snapshot = write_capture(
        "low",
        "https://target.local/marketing",
        "marketing view",
    )
    extra_network, extra_snapshot = write_capture(
        "extra",
        "https://target.local/api/orders/7",
        "order view",
    )
    state_path = tmp_path / "high-state.json"
    state_path.write_text(json.dumps({"token": secret}), encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": "target.local",
                "captures": [
                    {
                        "url": "https://target.local/admin",
                        "source": "playwright-mcp",
                        "network": str(high_network),
                        "snapshot": str(high_snapshot),
                        "state": str(state_path),
                    },
                    {
                        "url": "https://off-target.local/admin",
                        "network": str(high_network),
                    },
                    {
                        "url": "file:///tmp/not-target-owned",
                        "network": str(high_network),
                    },
                    {
                        "url": "https://target.local/marketing",
                        "network": str(low_network),
                        "snapshot": str(low_snapshot),
                    },
                    {
                        "url": "https://target.local/orders/7",
                        "network": str(extra_network),
                        "snapshot": str(extra_snapshot),
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    common = {
        "target": "target.local",
        "manifest_path": manifest_path,
        "max_urls": 2,
        "evidence_root": tmp_path / "evidence",
        "recon_root": tmp_path / "recon",
        "repo_root": tmp_path,
    }
    first = browser_mcp_import.import_focused_mcp_manifest(**common)
    second = browser_mcp_import.import_focused_mcp_manifest(**common)
    queue = load_queue(tmp_path, "target.local")

    assert first["counts"] == {"selected": 2, "successful": 2, "actionable": 1, "skipped": 3}
    assert {item["reason"] for item in first["skipped"]} == {
        "invalid_url",
        "off_target",
        "budget_exhausted",
    }
    assert first["captures"][0]["actionable"] is True
    assert first["captures"][0]["new_surface"]["js_files"] == [
        "https://target.local/static/admin.js"
    ]
    assert first["captures"][1]["actionable"] is False
    assert second["counts"]["actionable"] == 0
    assert len(queue["actions"]) == 1
    assert queue["actions"][0]["source"] == "browser-context-discovery"

    public_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for root in (tmp_path / "evidence", tmp_path / "recon", tmp_path / "state")
        for path in root.rglob("*")
        if path.is_file()
    )
    assert secret not in public_text


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

    target_key = "127.0.0.1:3002"
    recon_browser = tmp_path / "recon" / target_key / "browser"
    assert summary["counts"]["requests"] == 2
    assert (recon_browser / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "http://127.0.0.1:3002/rest/products/search?q=",
        "http://127.0.0.1:3002/socket.io/?EIO=&transport=",
    ]
    assert (recon_browser / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "http://127.0.0.1:3002/rest/products/search?q= :: q",
        "http://127.0.0.1:3002/socket.io/?EIO=&transport= :: EIO",
        "http://127.0.0.1:3002/socket.io/?EIO=&transport= :: transport",
    ]


def test_browser_mcp_import_falls_back_to_har_when_network_file_is_missing(tmp_path):
    har_path = tmp_path / "network.har"
    har_path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {"url": "https://target.local/api/me", "method": "GET"},
                            "response": {"status": 200},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        network_path=tmp_path / "missing-network.json",
        har_path=har_path,
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    assert summary["status"] == "ok"
    assert summary["counts"]["requests"] == 1
    assert Path(summary["private_artifacts"]["network_har"]["path"]).read_bytes() == har_path.read_bytes()


def test_browser_readiness_requires_success_network_fresh_fingerprint(tmp_path):
    network_path = tmp_path / "network.json"
    network_path.write_text(json.dumps([{
        "url": "https://target.local/api/me",
        "method": "GET",
        "resourceType": "xhr",
        "status": 200,
    }]))
    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        network_path=network_path,
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    ready = inspect_browser_evidence(tmp_path, "target.local")
    assert ready["ready"] is True
    assert ready["core_network"] is True
    assert ready["fresh"] is True
    assert ready["fingerprint_valid"] is True

    summary_path = Path(summary["summary_path"])
    saved_summary = json.loads(summary_path.read_text())
    saved_summary["captured_at"] = "2000-01-01T00:00:00Z"
    summary_path.write_text(json.dumps(saved_summary))
    old = inspect_browser_evidence(tmp_path, "target.local")
    assert old["ready"] is False
    assert old["fresh"] is False
    saved_summary["captured_at"] = summary["captured_at"]
    summary_path.write_text(json.dumps(saved_summary))

    Path(summary["artifacts"]["requests_json"]).write_text("{}\n")
    stale = inspect_browser_evidence(tmp_path, "target.local")
    assert stale["ready"] is False
    assert stale["fingerprint_valid"] is False


def test_authenticated_browser_capture_reports_missing_state(tmp_path):
    network_path = tmp_path / "network.json"
    network_path.write_text(json.dumps([{
        "url": "https://target.local/api/account",
        "method": "GET",
        "resourceType": "xhr",
        "status": 200,
    }]))
    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        network_path=network_path,
        auth_required=True,
        auth_state="present",
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    readiness = inspect_browser_evidence(tmp_path, "target.local")
    assert summary["status"] == "partial"
    assert summary["success"] is True
    assert summary["auth_state"] == "missing"
    assert readiness["ready"] is False
    assert readiness["auth_required"] is True
    assert "missing_state" in readiness["reason"]


def test_authenticated_browser_readiness_rechecks_archived_state(tmp_path):
    network_path = tmp_path / "network.json"
    network_path.write_text(json.dumps([{
        "url": "https://target.local/api/account",
        "method": "GET",
        "resourceType": "xhr",
        "status": 200,
    }]))
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"cookies": [{"name": "session"}]}))
    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        network_path=network_path,
        state_path=state_path,
        auth_required=True,
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    assert inspect_browser_evidence(tmp_path, "target.local")["ready"] is True
    Path(summary["private_artifacts"]["browser_state"]["path"]).unlink()

    readiness = inspect_browser_evidence(tmp_path, "target.local")
    assert readiness["ready"] is False
    assert readiness["auth_state"] == "missing"
    assert "missing_state" in readiness["reason"]


def test_failed_browser_envelope_is_not_ready_even_with_requests(tmp_path):
    network_path = tmp_path / "network.json"
    network_path.write_text(json.dumps({
        "success": False,
        "status": "error",
        "data": {"requests": [{"url": "https://target.local/api/me"}]},
        "error": "capture failed",
    }))
    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        network_path=network_path,
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    readiness = inspect_browser_evidence(tmp_path, "target.local")
    assert summary["status"] == "error"
    assert summary["success"] is False
    assert readiness["ready"] is False


def test_failed_browser_import_rolls_back_new_capture_artifacts(tmp_path, monkeypatch):
    network_path = tmp_path / "network.json"
    network_path.write_text(json.dumps([{"url": "https://target.local/api/me"}]), encoding="utf-8")

    def fail_surface_write(*_args, **_kwargs):
        raise OSError("surface fixture failure")

    monkeypatch.setattr(browser_mcp_import, "write_browser_surface", fail_surface_write)
    with pytest.raises(OSError, match="surface fixture failure"):
        browser_mcp_import.import_mcp_browser_evidence(
            target="target.local",
            network_path=network_path,
            evidence_root=tmp_path / "evidence",
            recon_root=tmp_path / "recon",
        )

    public_browser = tmp_path / "evidence" / "target.local" / "browser"
    private_browser = tmp_path / ".private" / "browser" / "target.local"
    assert not list(public_browser.glob("*") if public_browser.is_dir() else [])
    assert not list(private_browser.glob("*") if private_browser.is_dir() else [])


def test_browser_mcp_import_merges_incremental_surface_instead_of_erasing(tmp_path):
    target_key = "127.0.0.1:3002"
    recon_browser = tmp_path / "recon" / target_key / "browser"
    recon_browser.mkdir(parents=True)
    (recon_browser / "xhr_endpoints.txt").write_text(
        "http://127.0.0.1:3002/rest/order-history\n",
        encoding="utf-8",
    )
    (recon_browser / "api_endpoints.txt").write_text(
        "http://127.0.0.1:3002/rest/order-history\n",
        encoding="utf-8",
    )
    (recon_browser / "browser_params.txt").write_text(
        "http://127.0.0.1:3002/rest/track-order/abc :: id\n",
        encoding="utf-8",
    )

    network_path = tmp_path / "network.txt"
    network_path.write_text(
        "1. [GET] http://127.0.0.1:3002/rest/products/search?q= => [200] OK\n",
        encoding="utf-8",
    )

    browser_mcp_import.import_mcp_browser_evidence(
        target="http://127.0.0.1:3002",
        url="http://127.0.0.1:3002/#/",
        network_path=network_path,
        label="playwright-mcp",
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
        source="playwright-mcp",
    )

    assert (recon_browser / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "http://127.0.0.1:3002/rest/order-history",
        "http://127.0.0.1:3002/rest/products/search?q=",
    ]
    assert (recon_browser / "api_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "http://127.0.0.1:3002/rest/order-history",
        "http://127.0.0.1:3002/rest/products/search?q=",
    ]
    assert (recon_browser / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "http://127.0.0.1:3002/rest/track-order/abc :: id",
        "http://127.0.0.1:3002/rest/products/search?q= :: q",
    ]


def test_browser_mcp_import_keeps_secret_values_private(tmp_path):
    secret = "SECRET_MCP_FIXTURE"
    network_path = tmp_path / "network.json"
    network_path.write_text(
        json.dumps([{"url": f"https://target.local/api?token={secret}", "postData": secret}]),
        encoding="utf-8",
    )
    console_path = tmp_path / "console.json"
    console_path.write_text(json.dumps([{"type": "log", "text": secret}]), encoding="utf-8")
    screenshot_path = tmp_path / "shot.png"
    screenshot_path.write_bytes(secret.encode())

    summary = browser_mcp_import.import_mcp_browser_evidence(
        target="target.local",
        url=f"https://target.local/app?token={secret}",
        network_path=network_path,
        console_path=console_path,
        screenshot_path=screenshot_path,
        evidence_root=tmp_path / "evidence",
        recon_root=tmp_path / "recon",
    )

    public_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in (tmp_path / "evidence").rglob("*")
        if path.is_file()
    )
    private_dir = Path(summary["artifacts"]["network_private_json"]).parent
    private_bytes = b"\n".join(path.read_bytes() for path in private_dir.rglob("*") if path.is_file())

    assert secret not in public_text
    assert secret.encode() in private_bytes
    assert private_dir.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in private_dir.rglob("*") if path.is_file())
