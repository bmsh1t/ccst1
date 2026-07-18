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
    "cloud-cognito-identity-pool",
    "grpc-api-boundaries",
    "k8s-control-plane-boundaries",
    "dns-email-trust-boundaries",
    "odata-query-boundaries",
    "ldap-xpath-query-boundaries",
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
            "AWS Cognito IdentityPoolId unauth role GetCredentialsForIdentity",
            "knowledge/cards/cloud-cognito-identity-pool.md",
        ),
        (
            "gRPC-Web protobuf server reflection grpc-status JSON transcoding",
            "knowledge/cards/grpc-api-boundaries.md",
        ),
        (
            "Kubernetes kubelet RBAC nodes/proxy projected service account",
            "knowledge/cards/k8s-control-plane-boundaries.md",
        ),
        (
            "DNS dangling CNAME subdomain takeover SPF DKIM DMARC MX",
            "knowledge/cards/dns-email-trust-boundaries.md",
        ),
        (
            "OData $metadata $filter $expand $batch entity field authorization",
            "knowledge/cards/odata-query-boundaries.md",
        ),
        (
            "LDAP injection search filter DN XPath directory query",
            "knowledge/cards/ldap-xpath-query-boundaries.md",
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

    cognito = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Cognito IdentityPoolId GetId unauth role",
    )
    assert cognito["knowledge_cards"][0] == "knowledge/cards/cloud-cognito-identity-pool.md"
    assert any(item["layer"] == "case-router" for item in cognito["knowledge_card_capabilities"])


def test_cicd_dependency_confusion_requires_dependency_and_public_fallback():
    skill = (REPO_ROOT / "skills" / "cicd-security" / "SKILL.md").read_text(encoding="utf-8")
    card = (REPO_ROOT / "knowledge" / "cards" / "cicd-trust-boundaries.md").read_text(encoding="utf-8")
    router = (REPO_ROOT / "rules" / "playbook-router.md").read_text(encoding="utf-8")
    combined = "\n".join((skill, card, router))

    assert "public registry miss" in combined
    assert "target build actually depends on the package" in combined
    assert "resolver/config can fall back to the public registry" in combined
    assert "404 单独" in combined
    assert "Docker/GHCR" in combined
    assert "SPDX/CycloneDX" in combined


def test_protocol_and_cloud_cards_preserve_negative_evidence_gates():
    cognito = (REPO_ROOT / "knowledge" / "cards" / "cloud-cognito-identity-pool.md").read_text(encoding="utf-8")
    grpc = (REPO_ROOT / "knowledge" / "cards" / "grpc-api-boundaries.md").read_text(encoding="utf-8")
    k8s = (REPO_ROOT / "knowledge" / "cards" / "k8s-control-plane-boundaries.md").read_text(encoding="utf-8")

    assert "`GetId` 成功只证明" in cognito
    assert "匿名凭证 + role identity + 非预期 IAM action + 具体影响" in cognito
    assert "status `12` 只说明 transport" in grpc
    assert "Reflection 是 schema/enumeration enabler，不是漏洞" in grpc
    assert "`10255` 主要是历史只读信息面" in k8s
    assert "SelfSubjectRulesReview / SelfSubjectAccessReview" in k8s


def test_query_boundary_cards_preserve_context_and_candidate_gates(tmp_path):
    odata = build_context_pack(
        tmp_path,
        target="target.com",
        focus="OData $metadata $filter $orderby $expand $batch field navigation authorization",
    )
    assert odata["knowledge_cards"][0] == "knowledge/cards/odata-query-boundaries.md"
    assert any("operator 可用" in seed and "query signal" in seed for seed in odata["hypothesis_seeds"])
    assert any("direct-vs-batch" in seed and "Candidate" in seed for seed in odata["hypothesis_seeds"])

    ldap = build_context_pack(
        tmp_path,
        target="target.com",
        focus="LDAP injection search filter DN XPath Active Directory query",
    )
    assert ldap["knowledge_cards"][0] == "knowledge/cards/ldap-xpath-query-boundaries.md"
    assert any("search filter、DN" in seed and "control" in seed for seed in ldap["hypothesis_seeds"])
    assert any("unicodePwd" in seed and "不可读取" in seed for seed in ldap["hypothesis_seeds"])


def test_framework_signals_route_to_existing_owners_with_negative_gates(tmp_path):
    cases = [
        (
            "Next.js /_next/image image optimizer returned HTTP 200 SSRF",
            "knowledge/cards/ssrf-url-fetch.md",
            ("返回 200", "唯一 OAST"),
        ),
        (
            "Next.js /_next/data BUILD_ID profile JSON object ID",
            "knowledge/cards/api-idor.md",
            ("anonymous、owner", "不等于 IDOR"),
        ),
        (
            "Spring Boot /actuator/env returned 200 Whitelabel",
            "knowledge/cards/path-pattern-management-exposure.md",
            ("路径 200", "Whitelabel"),
        ),
        (
            "ASP.NET __VIEWSTATE ViewState MAC signed serialized object",
            "knowledge/cards/insecure-deserialization.md",
            ("三阶段", "可利用"),
        ),
        (
            "legacy authentication mobile login SOAP XMLRPC alternate auth surface",
            "knowledge/cards/auth-hidden-switches.md",
            ("同一测试账号", "端点可达"),
        ),
        (
            "shadow throttle known-good control rate-limit regime",
            "knowledge/cards/auth-credential-recovery-flows.md",
            ("known-good", "没有 429"),
        ),
    ]

    for focus, expected_card, required_seed_fragments in cases:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert pack["knowledge_cards"][0] == expected_card
        assert len(pack["knowledge_cards"]) <= 2
        assert any(
            all(fragment in seed for fragment in required_seed_fragments)
            for seed in pack["hypothesis_seeds"]
        ), (focus, pack["hypothesis_seeds"])


def test_generic_framework_labels_do_not_trigger_specialized_boundary_cards(tmp_path):
    """普通技术栈/登录描述不能被当成专项边界信号。"""
    for focus in (
        "Next.js homepage with public marketing content",
        "Next.js image component documentation",
        "Next.js data fetching guide",
    ):
        nextjs = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert "knowledge/cards/ssrf-url-fetch.md" not in nextjs["knowledge_cards"]
        assert "knowledge/cards/api-idor.md" not in nextjs["knowledge_cards"]

    spring = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Spring Boot homepage",
    )
    assert "knowledge/cards/path-pattern-management-exposure.md" not in spring["knowledge_cards"]

    active_directory = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Active Directory login page",
    )
    assert "knowledge/cards/ldap-xpath-query-boundaries.md" not in active_directory["knowledge_cards"]


def test_distilled_framework_and_query_content_keeps_negative_evidence_gates():
    cards = {
        "ssrf-url-fetch": ("`/_next/image` 返回 200", "唯一 OAST callback"),
        "api-idor": ("`/_next/data", "anonymous、owner"),
        "path-pattern-management-exposure": ("Actuator/Jolokia 路径 200", "Whitelabel"),
        "insecure-deserialization": ("三阶段判断", "真实消费或状态影响"),
        "auth-hidden-switches": ("端点可达本身不是漏洞", "同账号策略对照"),
        "auth-credential-recovery-flows": ("没有 429", "shadow throttle"),
        "odata-query-boundaries": ("operator 可用", "不是漏洞"),
        "ldap-xpath-query-boundaries": ("unicodePwd", "不可读取"),
    }

    for card_id, markers in cards.items():
        text = (REPO_ROOT / "knowledge" / "cards" / f"{card_id}.md").read_text(encoding="utf-8")
        for marker in markers:
            assert marker in text, (card_id, marker)


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
