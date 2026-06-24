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
