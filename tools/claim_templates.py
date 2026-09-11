#!/usr/bin/env python3
"""Claim templates: category-stable activation fields pre-filled (stage-one #1).

模板只覆盖"类别稳定字段"（family/technique/active_dimension/skill_route/
risk_tier/max_hypothesis_actions/depth_contract_version）。四个临场判断字段
（hypothesis_id / expected_learning / kill_condition / decision_reason）永远
不出现在任何模板里——缺了照样被 Queue 的 FORMAT gate 拒绝。模板是格式税的
削减，不是门槛的削减。

合并优先级（与 from-evidence 的既有契约同构）：

    final = {**template, **from_evidence_derived, **metadata_json}

AI 显式值永远赢 > 证据推导 > 模板默认。
"""

from __future__ import annotations

# 深度契约版本硬编码（避免 claim_templates <-> action_queue 循环 import）；
# tests/test_claim_templates.py 断言它与 action_queue.DEPTH_CONTRACT_VERSION 一致。
DEPTH_CONTRACT_VERSION = 1


# 首批高频形态（实测 transcript 的高频假设类别）。
# skill_route 的 skill_id/path 必须真实存在于仓库 skills/。
CLAIM_TEMPLATES: dict[str, dict] = {
    "idor-cross-actor": {
        "family": "IDOR",
        "technique": "cross_actor_access",
        "active_dimension": "object_access",
        "skill_route": {
            "skill_id": "web2-vuln-classes",
            "skill_path": "skills/web2-vuln-classes/SKILL.md",
            "required_dimensions": ["object_access", "actor_diff"],
        },
        "risk_tier": "medium",
        "max_hypothesis_actions": 4,
        "depth_contract_version": DEPTH_CONTRACT_VERSION,
    },
    "sqli-error-based": {
        "family": "SQLi",
        "technique": "error_based_injection",
        "active_dimension": "input_parser",
        "skill_route": {
            "skill_id": "web2-vuln-classes",
            "skill_path": "skills/web2-vuln-classes/SKILL.md",
            "required_dimensions": ["input_parser", "error_oracle"],
        },
        "risk_tier": "high",
        "max_hypothesis_actions": 4,
        "depth_contract_version": DEPTH_CONTRACT_VERSION,
    },
    "authz-header-swap": {
        "family": "Authz",
        "technique": "identity_header_swap",
        "active_dimension": "actor_diff",
        "skill_route": {
            "skill_id": "web2-vuln-classes",
            "skill_path": "skills/web2-vuln-classes/SKILL.md",
            "required_dimensions": ["actor_diff", "object_access"],
        },
        "risk_tier": "medium",
        "max_hypothesis_actions": 4,
        "depth_contract_version": DEPTH_CONTRACT_VERSION,
    },
    "ssrf-url-param": {
        "family": "SSRF",
        "technique": "url_fetch_internal",
        "active_dimension": "url_fetch",
        "skill_route": {
            "skill_id": "web2-vuln-classes",
            "skill_path": "skills/web2-vuln-classes/SKILL.md",
            "required_dimensions": ["url_fetch", "internal_reach"],
        },
        "risk_tier": "high",
        "max_hypothesis_actions": 4,
        "depth_contract_version": DEPTH_CONTRACT_VERSION,
    },
    "auth-bypass-header": {
        "family": "Auth",
        "technique": "bypass_via_header",
        "active_dimension": "actor_diff",
        "skill_route": {
            "skill_id": "credential-attack",
            "skill_path": "skills/credential-attack/SKILL.md",
            "required_dimensions": ["actor_diff", "auth_boundary"],
        },
        "risk_tier": "high",
        "max_hypothesis_actions": 4,
        "depth_contract_version": DEPTH_CONTRACT_VERSION,
    },
}

# 防内容门槛：判断字段永不进模板（P0 分桶纪律的模板侧负断言）。
FORBIDDEN_TEMPLATE_FIELDS = (
    "hypothesis_id",
    "expected_learning",
    "kill_condition",
    "decision_reason",
)


def resolve_template(name: str) -> dict:
    """Return a copy of the named template or raise a FORMAT-bucket error."""
    try:
        template = CLAIM_TEMPLATES[name]
    except KeyError:
        available = ", ".join(sorted(CLAIM_TEMPLATES))
        raise ValueError(
            f"unknown claim template {name!r}; available: {available}"
        ) from None
    return dict(template)


def apply_template(template_name: str, metadata: dict | None) -> dict:
    """Merge {**template, **metadata}; explicit metadata wins everywhere."""
    if not template_name:
        return dict(metadata or {})
    template = resolve_template(template_name)
    merged = {**template, **(metadata or {})}
    # skill_route 是嵌套 dict——显式 metadata 的 skill_route 整体覆盖
    if metadata and isinstance(metadata.get("skill_route"), dict):
        merged["skill_route"] = dict(metadata["skill_route"])
    return merged
