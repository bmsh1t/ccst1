"""Tests for browser-observed surface extraction."""

import json

import browser_surface


def test_browser_surface_parses_playwright_cli_raw_requests(tmp_path):
    requests_path = tmp_path / "requests.json"
    requests_path.write_text(
        json.dumps(
            {
                "raw": (
                    "2. [POST] https://app.target.com/api/me?account_id=123 => [200] OK\n"
                    "3. [GET] https://app.target.com/graphql => [200] OK\n"
                    "\n"
                    "Note: 1 static request not shown, run with --static option to see it.\n"
                )
            }
        ),
        encoding="utf-8",
    )

    summary = browser_surface.write_browser_surface(
        recon_root=tmp_path / "recon",
        target_key="target.com",
        requests_path=requests_path,
    )

    browser_dir = tmp_path / "recon" / "target.com" / "browser"
    assert summary["counts"]["requests"] == 2
    assert (browser_dir / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://app.target.com/api/me?account_id=123",
        "https://app.target.com/graphql",
    ]
    assert (browser_dir / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "https://app.target.com/api/me?account_id=123 :: account_id",
    ]


def test_browser_surface_parses_wrapped_mcp_data_envelope(tmp_path):
    requests_path = tmp_path / "requests.json"
    requests_path.write_text(
        json.dumps(
            {
                "success": True,
                "data": {
                    "requests": [
                        {
                            "url": "https://target.local/api/orders?id=123",
                            "method": "GET",
                            "resourceType": "xhr",
                        }
                    ]
                },
                "error": None,
            }
        ),
        encoding="utf-8",
    )

    summary = browser_surface.write_browser_surface(
        recon_root=tmp_path / "recon",
        target_key="target.local",
        requests_path=requests_path,
    )

    browser_dir = tmp_path / "recon" / "target.local" / "browser"
    assert summary["counts"]["requests"] == 1
    assert (browser_dir / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/orders?id=123"
    ]
    assert (browser_dir / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/orders?id=123 :: id"
    ]


def test_browser_surface_keeps_hidden_field_names_without_values(tmp_path):
    snapshot_path = tmp_path / "page.html"
    snapshot_path.write_text(
        '<form action="/account" method="post">'
        '<input type="hidden" name="__VIEWSTATE" value="sensitive-state-value">'
        '<input name="__VIEWSTATEGENERATOR" type="hidden" value="ABC123">'
        '<input type="hidden" name="__EVENTVALIDATION" value="secret-event-value">'
        '</form>',
        encoding="utf-8",
    )

    browser_surface.write_browser_surface(
        recon_root=tmp_path / "recon",
        target_key="target.local",
        snapshot_path=snapshot_path,
    )

    forms = json.loads((tmp_path / "recon" / "target.local" / "browser" / "forms.json").read_text(encoding="utf-8"))
    assert forms["forms"] == [{
        "action": "/account",
        "method": "POST",
        "hidden_fields": ["__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"],
    }]
    assert "sensitive-state-value" not in json.dumps(forms)


def test_browser_surface_keeps_unclosed_form_as_a_surface_signal(tmp_path):
    snapshot_path = tmp_path / "partial.html"
    snapshot_path.write_text('<form action="/login" method="post">', encoding="utf-8")

    browser_surface.write_browser_surface(
        recon_root=tmp_path / "recon",
        target_key="target.local",
        snapshot_path=snapshot_path,
    )

    forms = json.loads((tmp_path / "recon" / "target.local" / "browser" / "forms.json").read_text(encoding="utf-8"))
    assert forms["forms"] == [{"action": "/login", "method": "POST"}]
