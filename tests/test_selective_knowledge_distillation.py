"""专项知识卡的 registry、路由和内容边界回归。"""

from __future__ import annotations

from pathlib import Path

from tools.context_pack import build_context_pack
from tools.knowledge_audit import audit_repository
from tools.knowledge_registry import load_registry


REPO_ROOT = Path(__file__).resolve().parents[1]
CARD_IDS = (
    "payment-callback-idempotency",
    "cicd-trust-boundaries",
    "cloud-control-plane-pivots",
    "dns-email-trust-boundaries",
)


def test_specialized_cards_are_registered_and_strict_audit_clean():
    registry = load_registry(REPO_ROOT)
    paths = registry.card_paths()
    for card_id in CARD_IDS:
        assert card_id in paths
        assert (REPO_ROOT / paths[card_id]).is_file()
    report = audit_repository(REPO_ROOT)
    assert report.errors == 0
    assert report.warnings == 0


def test_specialized_focus_routes_to_incremental_card_without_budget_growth(tmp_path):
    cases = [
        (
            "payment callback webhook idempotency replay window",
            "knowledge/cards/payment-callback-idempotency.md",
        ),
        (
            "CI/CD GitHub Actions runner OIDC artifact deploy",
            "knowledge/cards/cicd-trust-boundaries.md",
        ),
        (
            "cloud control plane metadata IAM RBAC service account",
            "knowledge/cards/cloud-control-plane-pivots.md",
        ),
        (
            "DNS dangling CNAME subdomain takeover SPF DKIM DMARC MX",
            "knowledge/cards/dns-email-trust-boundaries.md",
        ),
    ]
    for focus, expected in cases:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert pack["knowledge_cards"][0] == expected
        assert len(pack["knowledge_cards"]) <= 2
        assert pack["knowledge_card_capabilities"]


def test_specialized_cards_keep_existing_route_boundaries(tmp_path):
    payment = build_context_pack(
        tmp_path,
        target="target.com",
        focus="payment callback signature scope mismatch idempotency",
    )
    assert "knowledge/cards/payment-callback-idempotency.md" in payment["knowledge_cards"]
    assert "knowledge/cards/signature-scope-mismatch.md" in payment["knowledge_cards"] or any(
        "签名" in seed for seed in payment["hypothesis_seeds"]
    )

    cloud = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SSRF internal metadata cloud IAM control plane",
    )
    assert "knowledge/cards/cloud-control-plane-pivots.md" in cloud["knowledge_cards"]
    assert "knowledge/cards/ssrf-internal-impact.md" in cloud["knowledge_cards"]


def test_specialized_card_content_has_evidence_and_stop_sections():
    required = (
        "Quick Recall",
        "触发信号",
        "最小验证",
        "常见误判 / 死路",
        "关联 Skills",
        "可晋升经验",
    )
    for card_id in CARD_IDS:
        text = (REPO_ROOT / "knowledge" / "cards" / f"{card_id}.md").read_text(encoding="utf-8")
        for marker in required:
            assert marker in text, (card_id, marker)
        assert "/root/tool/" not in text
        assert "source_report_ids" not in text
