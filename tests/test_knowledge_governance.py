from pathlib import Path

import json

from context_pack import build_context_pack
from knowledge_registry import load_registry


DISTILLED_ROUTER_CARDS = [
    "cli-argument-injection.md",
    "connection-reuse-key.md",
    "connection-string-injection.md",
    "import-migration-trust.md",
    "path-allowlist-normalization.md",
    "redirect-header-leak.md",
    "render-pipeline-ssrf.md",
    "second-order-sink.md",
    "signature-scope-mismatch.md",
    "stale-derived-authz.md",
    "type-confusion-controlflow.md",
    "view-differential.md",
    "xs-leak-oracle.md",
]

ARCHIVED_DISTILLED_NOTES = [
    "csp-bypass-exfil.md",
    "llm-invisible-unicode.md",
    "oauth-sso-trust.md",
    "payment-logic-bypass.md",
    "postmessage-trust.md",
    "request-smuggling.md",
    "runtime-primitive-override.md",
    "sanitizer-parser-xss.md",
    "sqli-non-parameterizable.md",
]

FOLDED_DISTILLED_CARDS = [
    "api-idor.md",
    "auth-access.md",
    "ssrf-url-fetch.md",
    "upload-parser.md",
]

DISTILLED_ROUTER_TRIGGER_CASES = {
    "signature-scope-mismatch.md": "signature scope mismatch signed bytes consumption object xsw duplicate assertion",
    "view-differential.md": "view differential validation view consumption view canonicalization gap",
    "path-allowlist-normalization.md": "path allowlist normalization prefix check startswith weak string dot-segment",
    "connection-string-injection.md": "connection string jdbc mongodb uri driver option protocol handler",
    "import-migration-trust.md": "import migration restore trust backup import tenant import",
    "stale-derived-authz.md": "stale derived authz revoked permission cache deprovision role cache",
    "connection-reuse-key.md": "connection reuse pool key tenant key keep-alive boundary",
    "redirect-header-leak.md": "redirect header authorization header leak sensitive header redirect",
    "xs-leak-oracle.md": "xs-leak timing oracle image size oracle resource timing oracle",
    "cli-argument-injection.md": "cli argument injection flag injection option injection terminal escape",
    "type-confusion-controlflow.md": "type confusion string boolean array object duplicate json reserved key",
    "second-order-sink.md": "second-order delayed sink async sink stored render deferred template",
    "render-pipeline-ssrf.md": "render pipeline pdf render screenshot service server-side browser wkhtmltopdf html to pdf",
}

ABSORBED_DISTILLED_TRIGGER_CASES = [
    ("oauth sso trust email trust audience confusion redirect_uri trust", "knowledge/cards/auth-sso-token-edge-cases.md"),
    ("h2 crlf pseudo-header injection response queue poisoning non-url crlf", "knowledge/cards/proxy-cache-boundaries.md"),
    ("sanitizer dompurify mxss mutation xss parser xss second decode", "knowledge/cards/xss-client-injection.md"),
    ("csp bypass no-script exfil script-src exfil", "knowledge/cards/xss-client-injection.md"),
    ("runtime primitive primitive override monkey patch same realm override fetch", "knowledge/cards/node-prototype-pollution.md"),
    ("non-parameterizable order by identifier column name injection placeholder name", "knowledge/cards/sqli-hidden-surfaces.md"),
    ("invisible unicode unicode tag hidden unicode prompt", "knowledge/cards/web-llm-tool-chains.md"),
    ("payment logic rounding bypass gateway state recipient mismatch refund logic", "knowledge/cards/business-logic-state-machines.md"),
    ("postmessage trust message event origin targetorigin trust window.name trust", "knowledge/cards/browser-client-boundaries.md"),
]

ABSORBED_DISTILLED_TARGET_CARDS = [
    "auth-sso-token-edge-cases.md",
    "business-logic-state-machines.md",
    "browser-client-boundaries.md",
    "proxy-cache-boundaries.md",
    "xss-client-injection.md",
    "sqli-hidden-surfaces.md",
    "web-llm-tool-chains.md",
    "node-prototype-pollution.md",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_capability_registry() -> tuple[dict[str, int], list[dict[str, str]]]:
    """通过生产 parser 读取 registry，避免测试维护第二套 YAML 契约。"""
    registry = load_registry(_repo_root())
    contracts = {
        key: int(registry.contracts[key])
        for key in ("max_core_cards", "default_cards_max")
    }
    return contracts, [dict(item) for item in registry.capabilities]


def _card_capabilities() -> list[dict[str, str]]:
    _, capabilities = _load_capability_registry()
    return [item for item in capabilities if item.get("kind") == "card"]


def _capabilities_by_kind(kind: str) -> list[dict[str, str]]:
    _, capabilities = _load_capability_registry()
    return [item for item in capabilities if item.get("kind") == kind]


def test_distilled_cards_are_marked_as_on_demand_case_routers():
    cards_dir = _repo_root() / "knowledge" / "cards"

    for name in DISTILLED_ROUTER_CARDS + FOLDED_DISTILLED_CARDS:
        text = (cards_dir / name).read_text(encoding="utf-8")
        assert "## 源报告（on-demand）" in text
        assert "source_report_ids:" in text
        assert "本地案例库查询指针" in text
        assert "不要默认拉取全文" in text


def test_absorbed_distilled_notes_are_preserved_in_archive():
    archive_dir = _repo_root() / "knowledge" / "archive" / "distilled"

    for name in ARCHIVED_DISTILLED_NOTES:
        text = (archive_dir / name).read_text(encoding="utf-8")
        assert "## 源报告（on-demand）" in text
        assert "source_report_ids:" in text


def test_absorbed_distilled_sources_are_reconnected_to_target_cards():
    cards_dir = _repo_root() / "knowledge" / "cards"

    for name in ABSORBED_DISTILLED_TARGET_CARDS:
        text = (cards_dir / name).read_text(encoding="utf-8")
        assert "## 源报告（on-demand）" in text
        assert "source_report_ids:" in text
        assert "本地案例库查询指针" in text


def test_capability_registry_registers_every_card_once():
    cards_dir = _repo_root() / "knowledge" / "cards"
    actual_cards = {f"knowledge/cards/{path.name}" for path in cards_dir.glob("*.md")}
    registered_cards = [item.get("file", "") for item in _card_capabilities()]

    assert set(registered_cards) == actual_cards
    assert len(registered_cards) == len(set(registered_cards))


def test_capability_registry_registers_every_payload_pack_and_playbook_once():
    payload_dir = _repo_root() / "knowledge" / "payloads"
    playbook_dir = _repo_root() / "knowledge" / "playbooks"
    actual_payloads = {f"knowledge/payloads/{path.name}" for path in payload_dir.glob("*.md")}
    actual_playbooks = {f"knowledge/playbooks/{path.name}" for path in playbook_dir.glob("*.md")}

    registered_payloads = [item.get("file", "") for item in _capabilities_by_kind("payload-pack")]
    registered_playbooks = [item.get("file", "") for item in _capabilities_by_kind("playbook")]

    assert set(registered_payloads) == actual_payloads
    assert len(registered_payloads) == len(set(registered_payloads))
    assert set(registered_playbooks) == actual_playbooks
    assert len(registered_playbooks) == len(set(registered_playbooks))


def test_capability_registry_enforces_layer_and_loading_contracts():
    contracts, capabilities = _load_capability_registry()
    card_caps = [item for item in capabilities if item.get("kind") == "card"]
    valid_layers = {"core", "reference", "case-router", "payload-pack", "playbook"}
    valid_loads = {"default", "signal-or-default", "signal-only", "on-demand", "gated"}

    for item in capabilities:
        assert item.get("layer") in valid_layers
        assert item.get("load") in valid_loads
        assert item.get("purpose")

    core_cards = [item for item in card_caps if item.get("layer") == "core"]
    default_cards = [item for item in card_caps if item.get("load") == "default"]
    assert len(core_cards) <= contracts["max_core_cards"]
    assert len(default_cards) <= contracts["default_cards_max"]
    assert all(item.get("load") == "on-demand" for item in card_caps if item.get("layer") == "case-router")


def test_payload_packs_and_playbooks_remain_gated_non_card_capabilities():
    for item in _capabilities_by_kind("payload-pack"):
        assert item["file"].startswith("knowledge/payloads/")
        assert item["layer"] == "payload-pack"
        assert item["load"] == "gated"

    for item in _capabilities_by_kind("playbook"):
        assert item["file"].startswith("knowledge/playbooks/")
        assert item["layer"] == "playbook"
        assert item["load"] == "gated"

    registry = {item["file"]: item for item in _card_capabilities()}
    assert all(not path.startswith("knowledge/payloads/") for path in registry)
    assert all(not path.startswith("knowledge/playbooks/") for path in registry)
    assert all(f"knowledge/cards/{name}" not in registry for name in ARCHIVED_DISTILLED_NOTES)


def test_distilled_router_cards_are_registered_as_case_router_layer():
    registry = {Path(item["file"]).name: item for item in _card_capabilities()}

    for name in DISTILLED_ROUTER_CARDS:
        assert registry[name]["layer"] == "case-router"
        assert registry[name]["load"] == "on-demand"

    for name in FOLDED_DISTILLED_CARDS:
        assert registry[name].get("case_router") == "folded-source-report-footer"


def test_capability_registry_tracks_secondary_sweep_workflows():
    _, capabilities = _load_capability_registry()
    workflows = {item["id"]: item for item in capabilities if item.get("kind") == "workflow"}

    assert workflows["external-url-secondary-sweep"]["purpose"] == "chain-intel"
    assert workflows["standard-public-metadata-secondary-sweep"]["purpose"] == "false-positive-control"


def test_knowledge_index_preserves_card_layering_contract():
    index = (_repo_root() / "knowledge" / "index.md").read_text(encoding="utf-8")

    assert "## Capability Registry" in index
    assert "knowledge/capabilities.yaml" in index
    assert "最多 1 张 core card" in index
    assert "最多 1 个 payload pack 或 playbook（仅验证阶段 gated）" in index
    assert "## 核心决策知识卡" in index
    assert "## 蒸馏 Router 知识卡" in index
    assert "## 已折叠吸收 / 归档的蒸馏笔记" in index
    assert "knowledge/archive/distilled/" in index
    assert "## 深度附录 / Payload Packs" in index
    assert "## 深度 Playbooks" in index
    assert "router / recall 层" in index
    assert "source_report_ids" in index
    assert "不要默认拉取报告全文" in index


def test_context_loading_prefers_evidence_and_case_pointers_over_methodology_prose():
    rules = (_repo_root() / "rules" / "context-loading.md").read_text(encoding="utf-8")

    assert "前沿模型上下文价值判据" in rules
    assert "方法论 prose 不应默认进入上下文" in rules
    assert "真实案例指针" in rules
    assert "蒸馏知识卡默认作为 router / recall 层" in rules


def test_distilled_router_cards_are_discoverable_by_context_pack(tmp_path):
    for card_name, focus in DISTILLED_ROUTER_TRIGGER_CASES.items():
        pack = build_context_pack(tmp_path, target="target.test", focus=focus)

        assert f"knowledge/cards/{card_name}" in pack["knowledge_cards"]


def test_absorbed_distilled_patterns_route_to_kept_base_cards(tmp_path):
    for focus, expected_card in ABSORBED_DISTILLED_TRIGGER_CASES:
        pack = build_context_pack(tmp_path, target="target.test", focus=focus)

        assert expected_card in pack["knowledge_cards"]


def test_distilled_router_cards_are_discoverable_from_real_evidence_indexes(tmp_path):
    for card_name, evidence in DISTILLED_ROUTER_TRIGGER_CASES.items():
        target = card_name.removesuffix(".md")
        source_dir = tmp_path / "findings" / target / "source_intel"
        source_dir.mkdir(parents=True)
        (source_dir / "hypotheses.jsonl").write_text(
            json.dumps({
                "type": "distilled-lab",
                "candidate": evidence,
                "reason": "synthetic lab evidence index pressure test",
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        pack = build_context_pack(tmp_path, target=target)

        assert f"knowledge/cards/{card_name}" in pack["knowledge_cards"]
        assert f"findings/{target}/source_intel/hypotheses.jsonl" in pack["must_read"]
