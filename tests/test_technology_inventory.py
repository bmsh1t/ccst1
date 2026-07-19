"""统一 httpx 技术组件清单的行为回归。"""

import json
from pathlib import Path

import pytest

from tools.technology_inventory import (
    TechnologyInventoryError,
    component_labels,
    load_or_build_inventory,
    load_or_build_inventory_for_recon_dir,
    parse_httpx_json_line,
    parse_httpx_text_line,
    read_inventory,
)


ARTICLE19_LINES = [
    "https://article19.org [403] [5638] [Just a moment...] [Cloudflare]",
    "https://missing.article19.org [404] [1485] [404 - Page Not Found]",
]

CHINAAID_LINE = (
    "https://chinaaid.org [200] [260808] [ChinaAid: Walking with the Persecuted Faithful] "
    "[Akismet,Cloudflare,Cloudflare Bot Management,Elementor:4.0.2,"
    "Gravity Forms:2.10.5,PHP,WordPress:7.0.1,jQuery Migrate:3.4.1]"
)


def test_text_parser_does_not_promote_titles_to_components():
    parsed = parse_httpx_text_line(ARTICLE19_LINES[0])
    assert parsed is not None
    assert parsed["title"] == "Just a moment..."
    assert [item["name"] for item in parsed["components"]] == ["cloudflare"]

    no_tech = parse_httpx_text_line(ARTICLE19_LINES[1])
    assert no_tech is not None
    assert no_tech["title"] == "404 - Page Not Found"
    assert no_tech["components"] == []


def test_text_parser_extracts_real_component_versions():
    parsed = parse_httpx_text_line(CHINAAID_LINE)
    assert parsed is not None
    versions = {item["name"]: item["version"] for item in parsed["components"]}
    assert versions["wordpress"] == "7.0.1"
    assert versions["gravity forms"] == "2.10.5"
    assert versions["elementor"] == "4.0.2"
    assert "chinaaid: walking with the persecuted faithful" not in versions
    assert "260808" not in versions


def test_text_parser_accepts_legacy_length_after_tech_group():
    parsed = parse_httpx_text_line(
        "https://api.target.test [200] [API] [Next.js,GraphQL] [1000]"
    )

    assert parsed is not None
    assert parsed["title"] == "API"
    assert [item["name"] for item in parsed["components"]] == ["next.js", "graphql"]


def test_jsonl_parser_preserves_structured_fields_and_versions():
    parsed = parse_httpx_json_line(json.dumps({
        "url": "https://app.example.test",
        "input": "app.example.test",
        "host": "app.example.test",
        "status_code": 200,
        "title": "App",
        "tech": ["Next.js:15.2.1", "Cloudflare"],
        "webserver": "nginx/1.26.1",
    }))
    assert parsed is not None
    assert parsed["host"] == "app.example.test"
    assert parsed["status"] == "200"
    versions = {item["name"]: item["version"] for item in parsed["components"]}
    assert versions == {"next.js": "15.2.1", "cloudflare": "", "nginx": "1.26.1"}
    assert all(item["source"] == "httpx_jsonl" for item in parsed["components"])


def test_load_or_build_prefers_jsonl_and_rebuilds_when_source_changes(tmp_path):
    live = tmp_path / "recon" / "target.test" / "live"
    live.mkdir(parents=True)
    (live / "httpx_full.txt").write_text(CHINAAID_LINE + "\n", encoding="utf-8")
    jsonl_path = live / "httpx_full.jsonl"
    jsonl_path.write_text(json.dumps({
        "url": "https://target.test",
        "status_code": 200,
        "title": "Target",
        "tech": ["Django:5.1.2"],
    }) + "\n", encoding="utf-8")

    first = load_or_build_inventory(tmp_path, "target.test")
    assert first["source"]["format"] == "jsonl"
    assert component_labels(first) == ["django:5.1.2"]

    jsonl_path.write_text(json.dumps({
        "url": "https://target.test",
        "status_code": 200,
        "title": "Target",
        "tech": ["Django:5.1.3"],
    }) + "\n", encoding="utf-8")
    second = load_or_build_inventory(tmp_path, "target.test")
    assert component_labels(second) == ["django:5.1.3"]


def test_empty_or_invalid_jsonl_falls_back_to_legacy_text(tmp_path):
    live = tmp_path / "recon" / "target.test" / "live"
    live.mkdir(parents=True)
    (live / "httpx_full.jsonl").write_text("not-json\n", encoding="utf-8")
    (live / "httpx_full.txt").write_text(
        "https://target.test [200] [100] [Target] [nginx]\n",
        encoding="utf-8",
    )

    payload = load_or_build_inventory(tmp_path, "target.test")

    assert payload["source"]["format"] == "text"
    assert component_labels(payload) == ["nginx"]


def test_load_or_build_writes_atomic_schema_bound_inventory(tmp_path):
    live = tmp_path / "recon" / "target.test" / "live"
    live.mkdir(parents=True)
    (live / "httpx_full.txt").write_text("\n".join(ARTICLE19_LINES) + "\n", encoding="utf-8")

    payload = load_or_build_inventory(tmp_path, "target.test")
    path = live / "technology_inventory.json"
    assert path.is_file()
    assert read_inventory(path) == payload
    assert payload["schema_version"] == 1
    assert payload["source"]["sha256"]
    assert payload["stats"] == {"host_count": 2, "component_count": 1, "parse_errors": 0}
    assert not list(live.glob(".technology_inventory.json.*.tmp"))


def test_invalid_inventory_records_and_target_drift_are_rebuilt(tmp_path):
    recon_dir = tmp_path / "recon" / "target.test"
    live = recon_dir / "live"
    live.mkdir(parents=True)
    (live / "httpx_full.txt").write_text(
        "https://target.test [200] [100] [Target] [nginx]\n",
        encoding="utf-8",
    )
    first = load_or_build_inventory_for_recon_dir(recon_dir, target="target.test")
    inventory_path = live / "technology_inventory.json"
    broken = dict(first)
    broken["target"] = "other.test"
    broken["components"] = ["not-an-object"]
    inventory_path.write_text(json.dumps(broken), encoding="utf-8")

    rebuilt = load_or_build_inventory_for_recon_dir(recon_dir, target="target.test")

    assert rebuilt["target"] == "target.test"
    assert rebuilt["components"][0]["name"] == "nginx"


def test_missing_source_is_explicitly_unavailable(tmp_path):
    payload = load_or_build_inventory(tmp_path, "target.test")
    assert payload["status"] == "unavailable"
    assert payload["components"] == []
    assert payload["hosts"] == []


def test_invalid_inventory_schema_fails_fast(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text('{"schema_version": 999, "components": [], "hosts": []}', encoding="utf-8")
    with pytest.raises(TechnologyInventoryError, match="unsupported"):
        read_inventory(path)
