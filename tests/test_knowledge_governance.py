from pathlib import Path

import json

from context_pack import build_context_pack


DISTILLED_ROUTER_CARDS = [
    "cli-argument-injection.md",
    "connection-reuse-key.md",
    "connection-string-injection.md",
    "csp-bypass-exfil.md",
    "import-migration-trust.md",
    "llm-invisible-unicode.md",
    "oauth-sso-trust.md",
    "path-allowlist-normalization.md",
    "payment-logic-bypass.md",
    "postmessage-trust.md",
    "redirect-header-leak.md",
    "render-pipeline-ssrf.md",
    "request-smuggling.md",
    "runtime-primitive-override.md",
    "sanitizer-parser-xss.md",
    "second-order-sink.md",
    "signature-scope-mismatch.md",
    "sqli-non-parameterizable.md",
    "stale-derived-authz.md",
    "type-confusion-controlflow.md",
    "view-differential.md",
    "xs-leak-oracle.md",
]

FOLDED_DISTILLED_CARDS = [
    "api-idor.md",
    "auth-access.md",
    "ssrf-url-fetch.md",
    "upload-parser.md",
]

DISTILLED_ROUTER_TRIGGER_CASES = {
    "signature-scope-mismatch.md": "signature scope mismatch signed bytes consumption object xsw duplicate assertion",
    "oauth-sso-trust.md": "oauth sso trust email trust audience confusion redirect_uri trust",
    "view-differential.md": "view differential validation view consumption view canonicalization gap",
    "request-smuggling.md": "h2 crlf pseudo-header injection response queue poisoning non-url crlf",
    "path-allowlist-normalization.md": "path allowlist normalization prefix check startswith weak string dot-segment",
    "sanitizer-parser-xss.md": "sanitizer dompurify mxss mutation xss parser xss second decode",
    "csp-bypass-exfil.md": "csp bypass no-script exfil script-src exfil",
    "connection-string-injection.md": "connection string jdbc mongodb uri driver option protocol handler",
    "runtime-primitive-override.md": "runtime primitive primitive override monkey patch same realm override fetch",
    "import-migration-trust.md": "import migration restore trust backup import tenant import",
    "stale-derived-authz.md": "stale derived authz revoked permission cache deprovision role cache",
    "connection-reuse-key.md": "connection reuse pool key tenant key keep-alive boundary",
    "redirect-header-leak.md": "redirect header authorization header leak sensitive header redirect",
    "xs-leak-oracle.md": "xs-leak timing oracle image size oracle resource timing oracle",
    "cli-argument-injection.md": "cli argument injection flag injection option injection terminal escape",
    "sqli-non-parameterizable.md": "non-parameterizable order by identifier column name injection placeholder name",
    "type-confusion-controlflow.md": "type confusion string boolean array object duplicate json reserved key",
    "llm-invisible-unicode.md": "invisible unicode unicode tag hidden unicode prompt",
    "second-order-sink.md": "second-order delayed sink async sink stored render deferred template",
    "payment-logic-bypass.md": "payment logic rounding bypass gateway state recipient mismatch refund logic",
    "postmessage-trust.md": "postmessage trust message event origin targetorigin trust window.name trust",
    "render-pipeline-ssrf.md": "render pipeline pdf render screenshot service server-side browser wkhtmltopdf html to pdf",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def test_distilled_cards_are_marked_as_on_demand_case_routers():
    cards_dir = _repo_root() / "knowledge" / "cards"

    for name in DISTILLED_ROUTER_CARDS + FOLDED_DISTILLED_CARDS:
        text = (cards_dir / name).read_text(encoding="utf-8")
        assert "## 源报告（on-demand）" in text
        assert "source_report_ids:" in text
        assert "本地案例库查询指针" in text
        assert "不要默认拉取全文" in text


def test_knowledge_index_preserves_card_layering_contract():
    index = (_repo_root() / "knowledge" / "index.md").read_text(encoding="utf-8")

    assert "## 核心决策知识卡" in index
    assert "## 蒸馏 Router 知识卡" in index
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


def test_distilled_router_cards_are_discoverable_from_real_evidence_indexes(tmp_path):
    target_key = "target.test"
    source_dir = tmp_path / "findings" / target_key / "source_intel"
    source_dir.mkdir(parents=True)
    (source_dir / "hypotheses.jsonl").write_text(
        json.dumps({
            "type": "authz",
            "candidate": "stale derived authz after deprovision",
            "reason": "source evidence shows a revoked permission cache can keep role cache entries usable",
        }, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    pack = build_context_pack(tmp_path, target="target.test")

    assert "knowledge/cards/stale-derived-authz.md" in pack["knowledge_cards"]
    assert "findings/target.test/source_intel/hypotheses.jsonl" in pack["must_read"]
