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
    parse_nmap_normal_text,
    parse_nmap_xml_text,
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


def test_nmap_xml_preserves_product_version_cpe_and_unknown_service():
    observations = parse_nmap_xml_text(
        """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="svc.target.test"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.1"><cpe>cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*</cpe></service></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
<port protocol="tcp" portid="25"><state state="closed"/><service name="smtp" product="Postfix"/></port>
</ports></host></nmaprun>""",
        evidence_ref="recon/target.test/ports/nmap_results.xml",
    )

    assert len(observations) == 1
    components = observations[0]["components"]
    assert components[0]["name"] == "openssh"
    assert components[0]["version"] == "9.1"
    assert components[0]["port"] == 22
    assert components[0]["kind"] == "network_service"
    assert components[0]["cpe"].startswith("cpe:2.3:a:openbsd:openssh:9.1")
    assert components[1]["name"] == "redis"
    assert components[1]["kind"] == "unknown_service"
    assert components[1]["confidence"] == "low"


def test_nmap_cpe_without_product_is_still_identified_service():
    observations = parse_nmap_xml_text(
        """<nmaprun><host><status state="up"/><address addr="192.0.2.10"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"><cpe>cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*</cpe></service></port>
</ports></host></nmaprun>"""
    )

    component = observations[0]["components"][0]
    assert component["name"] == "openssh"
    assert component["kind"] == "network_service"
    assert component["confidence"] == "high"


def test_nmap_cpe_22_without_product_preserves_product_and_version():
    observations = parse_nmap_xml_text(
        """<nmaprun><host><status state="up"/><address addr="192.0.2.10"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"><cpe>cpe:/a:openbsd:openssh:9.1</cpe></service></port>
</ports></host></nmaprun>"""
    )

    component = observations[0]["components"][0]
    assert component["name"] == "openssh"
    assert component["version"] == "9.1"
    assert component["kind"] == "network_service"


def test_nmap_normal_parser_does_not_infer_product_from_open_port():
    observations = parse_nmap_normal_text(
        """Nmap scan report for mail.target.test (192.0.2.20)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu
3306/tcp open mysql
""",
        evidence_ref="nmap_results.txt",
    )

    components = observations[0]["components"]
    assert components[0]["display_name"] == "OpenSSH"
    assert components[0]["version"] == "8.9p1"
    assert components[1]["display_name"] == "mysql"
    assert components[1]["kind"] == "unknown_service"


def test_inventory_merges_httpx_and_nmap_and_rebuilds_on_service_change(tmp_path):
    recon = tmp_path / "recon" / "target.test"
    live = recon / "live"
    ports = recon / "ports"
    live.mkdir(parents=True)
    ports.mkdir(parents=True)
    (live / "httpx_full.txt").write_text(
        "https://target.test [200] [100] [Target] [WordPress:6.7.1]\n",
        encoding="utf-8",
    )
    nmap = ports / "nmap_results.xml"
    nmap.write_text(
        """<nmaprun><host><status state="up"/><address addr="192.0.2.10"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.1"/></port>
</ports></host></nmaprun>""",
        encoding="utf-8",
    )

    first = load_or_build_inventory(tmp_path, "target.test")
    assert [item["format"] for item in first["sources"]] == ["text", "nmap_xml"]
    assert {(item["name"], item["version"]) for item in first["components"]} == {
        ("wordpress", "6.7.1"),
        ("openssh", "9.1"),
    }
    assert first["stats"]["service_count"] == 1
    fingerprint = first["fingerprint"]

    nmap.write_text(nmap.read_text(encoding="utf-8").replace("9.1", "9.2"), encoding="utf-8")
    second = load_or_build_inventory(tmp_path, "target.test")
    assert ("openssh", "9.2") in {
        (item["name"], item["version"]) for item in second["components"]
    }
    assert second["fingerprint"] != fingerprint


def test_invalid_nmap_xml_falls_back_to_normal_output(tmp_path):
    recon = tmp_path / "recon" / "target.test"
    ports = recon / "ports"
    ports.mkdir(parents=True)
    (ports / "nmap_results.xml").write_text("<broken", encoding="utf-8")
    (ports / "nmap_results.txt").write_text(
        """Nmap scan report for svc.target.test (192.0.2.20)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2
""",
        encoding="utf-8",
    )

    inventory = load_or_build_inventory(tmp_path, "target.test")

    assert [item["format"] for item in inventory["sources"]] == ["nmap_normal"]
    assert [(item["name"], item["version"]) for item in inventory["components"]] == [
        ("openssh", "9.2")
    ]


def test_empty_nmap_xml_and_normal_fall_back_to_greppable(tmp_path):
    recon = tmp_path / "recon" / "target.test"
    ports = recon / "ports"
    ports.mkdir(parents=True)
    (ports / "nmap_results.xml").write_text("<nmaprun></nmaprun>\n", encoding="utf-8")
    (ports / "nmap_results.txt").write_text("Nmap done.\n", encoding="utf-8")
    (ports / "nmap_greppable.txt").write_text(
        "Host: 192.0.2.30 (db.target.test)\tPorts: 5432/open/tcp//postgresql//PostgreSQL 16.1/\n",
        encoding="utf-8",
    )

    inventory = load_or_build_inventory(tmp_path, "target.test")

    assert [item["format"] for item in inventory["sources"]] == ["nmap_greppable"]
    assert inventory["components"][0]["name"] == "postgresql"
    assert inventory["components"][0]["version"] == "16.1"
