"""Offline Browser -> Recon -> Surface fidelity and legacy shape compatibility."""

import hashlib
import json
from pathlib import Path

import pytest

from tools.browser_mcp_import import import_mcp_browser_evidence
from tools.browser_surface import public_request_payload, public_url_shape, write_browser_surface
from tools.surface import build_surface_review
from tools.surface_index import surface_safe_preview
from tools.target_store import TargetStore


TARGET = "browser-fixture.test"


def test_import_preserves_exact_urls_forms_and_body_structure(tmp_path):
    urls = [
        f"https://{TARGET}/api/items?term=apple&term=hello%20world&%71=one+two",
        f"https://{TARGET}/api/items?term=pear&term=hello%20world&%71=one+two",
    ]
    body = {"account": "fixture-body-value", "options": {"mode": "preview"}}
    network = tmp_path / "network.json"
    raw = {"requests": [{"url": url, "method": "POST", "resourceType": "fetch", "postData": body}
                        for url in urls]}
    network.write_text(json.dumps(raw))
    snapshot = tmp_path / "snapshot.html"
    snapshot.write_text('<form action="/submit?mode=preview" method="post">'
                        '<input type="hidden" name="csrf_nonce" value="fixture-nonce">'
                        '<input type="hidden" name="object_id" value="42"></form>')
    summary = import_mcp_browser_evidence(
        target=TARGET, network_path=network, snapshot_path=snapshot,
        evidence_root=tmp_path / "evidence", recon_root=tmp_path / "recon",
    )
    artifacts = summary["artifacts"]
    requests = json.loads(Path(artifacts["requests_json"]).read_text())["requests"]
    assert [item["url"] for item in requests] == urls
    assert [item["url_sha256"] for item in requests] == [hashlib.sha256(url.encode()).hexdigest() for url in urls]
    assert "fixture-body-value" not in Path(artifacts["requests_json"]).read_text()
    assert json.loads(Path(artifacts["network_private_json"]).read_text()) == raw
    assert Path(artifacts["network_private_json"]).stat().st_mode & 0o777 == 0o600
    assert Path(artifacts["snapshot_private_txt"]).read_text() == snapshot.read_text()
    assert Path(artifacts["snapshot_private_txt"]).stat().st_mode & 0o777 == 0o600
    assert "fixture-nonce" not in Path(artifacts["snapshot_txt"]).read_text()
    browser = tmp_path / "recon" / TARGET / "browser"
    assert (browser / "xhr_endpoints.txt").read_text().splitlines() == urls
    assert (browser / "api_endpoints.txt").read_text().splitlines() == urls
    assert f"{urls[0]} :: q" in (browser / "browser_params.txt").read_text().splitlines()
    forms = json.loads((browser / "forms.json").read_text())["forms"]
    assert forms == [{"action": "/submit?mode=preview", "method": "POST", "hidden_fields": ["csrf_nonce", "object_id"]}]
    shapes = json.loads((browser / "request_shapes.json").read_text())
    assert len(shapes) == 1
    assert shapes[0]["url"] == public_url_shape(urls[0])
    assert shapes[0]["postData"] == requests[0]["postData"]
    assert shapes[0]["resourceType"] == "fetch"

    TargetStore(tmp_path, TARGET).initialize()
    review = build_surface_review(tmp_path, TARGET)
    entries = {item["url"]: item for item in review["review_pool"]}
    for url in urls:
        assert entries[url]["request_shapes"][0]["method"] == "POST"
        assert entries[url]["request_shapes"][0]["body"]["parameter_names"] == ["account", "options"]


def test_legacy_shape_inputs_merge_without_inventing_values(tmp_path):
    legacy = f"https://{TARGET}/api/items?q="
    exact = f"https://{TARGET}/api/items?q=apple%27"
    requests = tmp_path / "requests.json"
    for url in (legacy, exact):
        requests.write_text(json.dumps(public_request_payload({"requests": [{"url": url, "method": "POST", "postData": {"id": "42"}}]})))
        write_browser_surface(recon_root=tmp_path / "recon", target_key=TARGET,
                              requests_path=requests, merge_existing=True)
    browser = tmp_path / "recon" / TARGET / "browser"
    assert (browser / "api_endpoints.txt").read_text().splitlines() == [legacy, exact]
    shapes = json.loads((browser / "request_shapes.json").read_text())
    assert len(shapes) == 1
    assert shapes[0]["url"] == legacy
    assert shapes[0]["postData"]["parameter_names"] == ["id"]
    TargetStore(tmp_path, TARGET).initialize()
    entries = build_surface_review(tmp_path, TARGET)["review_pool"]
    assert any(row["url"] == legacy and row["request_shapes"][0]["method"] == "POST" for row in entries)


@pytest.mark.parametrize("query", ["q=apple%27", "q=%7B%22key%22%3A42%7D", "query={user{id}}", "token=abcdefghijklmnopqrstuvwxyz0123456789", "%71=one+two&q=%2f#route"])
def test_preview_preserves_values_and_encoding(query):
    url = f"https://{TARGET}/api?{query}"
    assert surface_safe_preview(url) == url


def test_preview_keeps_budget_and_empty_input():
    url = f"https://{TARGET}/api?q=" + "x" * 500
    assert surface_safe_preview(url, limit=90) == url[:87] + "..."
    assert surface_safe_preview("") == ""
    assert public_request_payload({"requests": [{}, None]})["requests"] == []


def test_har_fallback_keeps_exact_url_and_raw_body_reference(tmp_path):
    url = f"https://{TARGET}/graphql?query=%7Buser%7Bid%7D%7D"
    network = tmp_path / "failed.json"
    network.write_text('{"requests": []}')
    har = tmp_path / "network.har"
    payload = {"log": {"entries": [{"request": {
        "url": url, "method": "POST",
        "postData": {"text": '{"query":"query User($id: ID!) { user(id: $id) { id } }","variables":{"id":"fixture-object"}}'},
    }}]}}
    har.write_text(json.dumps(payload))
    summary = import_mcp_browser_evidence(
        target=TARGET, network_path=network, har_path=har,
        evidence_root=tmp_path / "evidence", recon_root=tmp_path / "recon",
    )
    assert summary["status"] == "ok"
    requests = json.loads(Path(summary["artifacts"]["requests_json"]).read_text())["requests"]
    assert requests[0]["url"] == url
    assert requests[0]["postData"]["graphql_operations"] == ["User"]
    assert requests[0]["postData"]["graphql_variables"] == ["id"]
    assert json.loads(Path(summary["artifacts"]["network_private_json"]).read_text()) == payload
    assert Path(summary["artifacts"]["network_har_private"]).read_bytes() == har.read_bytes()
