"""Tests for tools/case_state_seed.py."""

from __future__ import annotations

import json
import subprocess
import sys

import case_state_seed
import target_case_state


def test_case_state_seed_keeps_object_without_inventing_actors_or_tests(tmp_path):
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
    obj = payload["suggested_objects"][0]
    assert obj["object_ref"] == "order_123"
    assert obj["type"] == "order"
    assert obj["object_id"] == "123"
    assert obj["source"].endswith("browser/xhr_endpoints.txt")
    assert not {"suggested_actors", "suggested_backlog", "commands"} & payload.keys()
    assert not {"owner_actor", "private_marker", "runner", "confidence"} & obj.keys()
    assert not (tmp_path / "state").exists()
    assert "request-diff" not in case_state_seed.format_seed(payload)


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


def test_case_state_seed_does_not_seed_external_protocol_relative_objects(tmp_path):
    urls_dir = tmp_path / "recon" / "target.com" / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "api_endpoints.txt").write_text(
        "//api.external.test/orders/123\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, "target.com")

    assert payload["artifact_endpoints"] == 1
    assert payload["status"] == "no_seed_candidates"
    assert payload["suggested_objects"] == []
    assert "suggested_backlog" not in payload


def test_raw_unknown_query_id_is_retained_without_a_confidence_verdict(tmp_path):
    urls_dir = tmp_path / "recon" / "target.com" / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "with_params.txt").write_text(
        "https://target.com/?option=com_demo&Itemid=0\n",
        encoding="utf-8",
    )

    payload = case_state_seed.build_case_state_seed(tmp_path, "target.com")

    assert payload["status"] == "suggestions"
    assert payload["suggested_objects"][0]["object_ref"] == "item_0"
    assert "confidence" not in payload["suggested_objects"][0]


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
                "delivery_id": 1,
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

    assert {"address_7", "basket_6", "delivery_1", "order_4cf8-fc54260b56afa3ce", "payment_8"} <= set(objects)
    assert payload["suggested_objects"][0]["object_ref"] == "order_4cf8-fc54260b56afa3ce"
    assert list(objects).index("delivery_1") > list(objects).index("address_7")
    assert objects["order_4cf8-fc54260b56afa3ce"]["endpoint"].endswith(
        "/rest/track-order/4cf8-fc54260b56afa3ce"
    )
    assert objects["order_4cf8-fc54260b56afa3ce"]["object_id"] == "4cf8-fc54260b56afa3ce"
    assert all("private_marker" not in item for item in objects.values())
    assert "json field" in objects["address_7"]["reason"]
    assert objects["address_7"]["endpoint"] == ""


def test_case_state_seed_does_not_infer_ownership_from_existing_actor_sessions(tmp_path):
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

    before = target_case_state.load_case_state(tmp_path, target)
    payload = case_state_seed.build_case_state_seed(tmp_path, target)

    assert payload["suggested_objects"][0]["object_ref"] == "address_7"
    assert payload["suggested_objects"][0]["endpoint"] == ""
    assert "suggested_actors" not in payload and "suggested_backlog" not in payload
    assert "owner_actor" not in payload["suggested_objects"][0]
    assert "commands" not in payload
    assert target_case_state.load_case_state(tmp_path, target) == before


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
    assert "suggested_backlog" not in payload
    assert "commands" not in payload


def test_case_state_seed_does_not_choose_a_peer_for_a_single_session(tmp_path):
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

    assert "suggested_actors" not in payload and "suggested_backlog" not in payload
    assert payload["suggested_objects"][0]["object_ref"] == "account_42"
    assert "peer_actor" not in payload["suggested_objects"][0]


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
    assert "suggested_backlog" not in payload
    assert "commands" not in payload


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
