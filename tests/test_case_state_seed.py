"""Tests for tools/case_state_seed.py."""

from __future__ import annotations

import json
import subprocess
import sys

import case_state_seed
import target_case_state


def test_case_state_seed_suggests_order_object_and_idor_backlog(tmp_path):
    target = "http://127.0.0.1:3002"
    browser_dir = tmp_path / "recon" / "127.0.0.1:3002" / "browser"
    browser_dir.mkdir(parents=True)
    (browser_dir / "xhr_endpoints.txt").write_text(
        "http://127.0.0.1:3002/rest/order-history/123\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target)

    assert payload["status"] == "suggestions"
    assert payload["artifact_endpoints"] == 1
    assert payload["suggested_actors"] == [
        {"actor": "user_a", "role": "user", "label": "owner account candidate"},
        {"actor": "user_b", "role": "user", "label": "peer account candidate"},
    ]
    assert payload["suggested_objects"][0]["object_ref"] == "order_123"
    assert payload["suggested_objects"][0]["type"] == "order"
    assert payload["suggested_objects"][0]["object_id"] == "123"
    assert payload["suggested_backlog"][0]["runner"] == "idor-actor-pair"
    assert payload["suggested_backlog"][0]["object_ref"] == "order_123"
    assert payload["suggested_backlog"][0]["priority"] == "high"
    assert payload["suggested_backlog"][0]["missing"] == [
        "owner session",
        "peer session",
        "owner private marker",
    ]
    assert any("add-object" in command and "order_123" in command for command in payload["commands"])
    assert any(
        "add-backlog" in command and "idor-actor-pair" in command and "--priority high" in command
        for command in payload["commands"]
    )


def test_case_state_seed_extracts_query_object_from_browser_params(tmp_path):
    target = "target.com"
    browser_dir = tmp_path / "recon" / "target.com" / "browser"
    browser_dir.mkdir(parents=True)
    (browser_dir / "browser_params.txt").write_text(
        "https://app.target.com/api/admin/export?order_id=42 :: order_id\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target)

    assert payload["suggested_objects"][0]["object_ref"] == "order_42"
    assert payload["suggested_objects"][0]["endpoint"] == "https://app.target.com/api/admin/export?order_id=42"
    assert "query parameter 'order_id'" in payload["suggested_objects"][0]["reason"]


def test_case_state_seed_extracts_objects_from_browser_json_artifacts(tmp_path):
    target = "http://127.0.0.1:3002"
    browser_dir = tmp_path / "recon" / "127.0.0.1:3002" / "browser"
    browser_dir.mkdir(parents=True)
    (browser_dir / "xhr_endpoints.txt").write_text(
        "http://127.0.0.1:3002/rest/track-order/4cf8-fc54260b56afa3ce\n",
        encoding="utf-8",
    )
    (browser_dir / "stateful_order_probe.json").write_text(
        json.dumps({
            "created": {
                "address_id": 7,
                "basket_id": 6,
                "order_confirmation": "4cf8-fc54260b56afa3ce",
                "payment_id": 8,
            },
            "owner_history": {
                "body": {
                    "data": [
                        {
                            "addressId": 7,
                            "orderId": "4cf8-fc54260b56afa3ce",
                            "paymentId": 8,
                        }
                    ]
                }
            },
        }),
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target, limit=10)
    objects = {item["object_ref"]: item for item in payload["suggested_objects"]}

    assert {"address_7", "basket_6", "order_4cf8-fc54260b56afa3ce", "payment_8"} <= set(objects)
    assert objects["order_4cf8-fc54260b56afa3ce"]["endpoint"].endswith(
        "/rest/track-order/4cf8-fc54260b56afa3ce"
    )
    assert objects["order_4cf8-fc54260b56afa3ce"]["private_marker"] == "4cf8-fc54260b56afa3ce"
    assert "json field" in objects["address_7"]["reason"]
    address_backlog = next(
        item for item in payload["suggested_backlog"]
        if item["object_ref"] == "address_7"
    )
    assert "object endpoint" in address_backlog["missing"]
    order_backlog = next(
        item for item in payload["suggested_backlog"]
        if item["object_ref"] == "order_4cf8-fc54260b56afa3ce"
    )
    assert "owner private marker" not in order_backlog["missing"]
    assert any("--private-marker" in command for command in payload["commands"])


def test_case_state_seed_reuses_existing_custom_actor_sessions(tmp_path):
    target = "target.com"
    target_case_state.add_actor(tmp_path, target, actor="owner_account", role="user")
    target_case_state.add_actor(tmp_path, target, actor="peer_account", role="user")
    target_case_state.add_session(
        tmp_path,
        target,
        session="owner_session",
        actor="owner_account",
        kind="bearer",
        header_value="Bearer owner",
    )
    target_case_state.add_session(
        tmp_path,
        target,
        session="peer_session",
        actor="peer_account",
        kind="bearer",
        header_value="Bearer peer",
    )
    browser_dir = tmp_path / "recon" / "target.com" / "browser"
    browser_dir.mkdir(parents=True)
    (browser_dir / "object_probe.json").write_text(
        json.dumps({"addressId": 7}),
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target)

    assert payload["suggested_actors"] == []
    assert payload["suggested_backlog"][0]["owner_actor"] == "owner_account"
    assert payload["suggested_backlog"][0]["peer_actor"] == "peer_account"
    assert payload["suggested_backlog"][0]["missing"] == ["object endpoint"]
    assert any("--owner-actor owner_account" in command for command in payload["commands"])


def test_case_state_seed_ignores_socket_session_ids(tmp_path):
    target = "target.com"
    browser_dir = tmp_path / "recon" / "target.com" / "browser"
    browser_dir.mkdir(parents=True)
    (browser_dir / "xhr_endpoints.txt").write_text(
        "https://target.com/socket.io/?EIO=4&transport=polling&t=abc&sid=8cjQfls9bMd2w3WWAAAM\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target)

    assert payload["status"] == "no_seed_candidates"
    assert payload["suggested_objects"] == []
    assert payload["suggested_backlog"] == []
    assert payload["commands"] == []


def test_case_state_seed_uses_existing_actors_and_sessions_for_missing_matrix(tmp_path):
    target = "target.com"
    target_case_state.add_actor(tmp_path, target, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, target, actor="user_b", role="user")
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner",
    )
    urls_dir = tmp_path / "recon" / "target.com" / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "api_endpoints.txt").write_text(
        "https://api.target.com/api/accounts/42/export\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target)

    assert payload["suggested_actors"] == []
    assert payload["suggested_objects"][0]["object_ref"] == "account_42"
    assert payload["suggested_backlog"][0]["missing"] == [
        "peer session",
        "owner private marker",
    ]


def test_case_state_seed_skips_existing_objects_and_backlogs(tmp_path):
    target = "target.com"
    target_case_state.add_actor(tmp_path, target, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, target, actor="user_b", role="user")
    target_case_state.add_object(
        tmp_path,
        target,
        object_ref="order_123",
        object_type="order",
        object_id="123",
        owner_actor="user_a",
        endpoint="https://api.target.com/orders/123",
    )
    target_case_state.add_backlog(
        tmp_path,
        target,
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
    )
    urls_dir = tmp_path / "recon" / "target.com" / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "api_endpoints.txt").write_text(
        "https://api.target.com/orders/123\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target)

    assert payload["status"] == "no_seed_candidates"
    assert payload["suggested_objects"] == []
    assert payload["suggested_backlog"] == []
    assert payload["commands"] == []


def test_case_state_seed_reads_js_and_source_intel(tmp_path):
    target = "target.com"
    js_dir = tmp_path / "findings" / "target.com" / "js_intel"
    src_dir = tmp_path / "findings" / "target.com" / "source_intel"
    js_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)
    (js_dir / "hypotheses.json").write_text(
        json.dumps({"endpoints": [{"path": "/api/invoices/77"}]}),
        encoding="utf-8",
    )
    (src_dir / "routes.json").write_text(
        json.dumps({"routes": [{"route": "/api/reports/88/export"}]}),
        encoding="utf-8",
    )
    (src_dir / "hypotheses.jsonl").write_text(
        json.dumps({"candidate": "/api/tenants/abc123/settings", "type": "idor"}) + "\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, target)
    refs = {item["object_ref"] for item in payload["suggested_objects"]}

    assert {"invoice_77", "report_88", "tenant_abc123"} <= refs


def test_case_state_seed_cli_json(tmp_path):
    target = "target.com"
    urls_dir = tmp_path / "recon" / "target.com" / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "api_endpoints.txt").write_text(
        "https://api.target.com/orders/123\n",
        encoding="utf-8",
    )

    output = subprocess.check_output(
        [
            sys.executable,
            "tools/case_state_seed.py",
            "--repo-root",
            str(tmp_path),
            "--target",
            target,
            "--json",
        ],
        text=True,
    )
    payload = json.loads(output)

    assert payload["target"] == target
    assert payload["suggested_objects"][0]["object_ref"] == "order_123"
