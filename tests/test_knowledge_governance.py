from pathlib import Path


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
