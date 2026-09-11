"""Claim templates: category-stable pre-fill without content gates."""

from __future__ import annotations

import pytest

from tools.action_queue import DEPTH_CONTRACT_VERSION as QUEUE_DEPTH_CONTRACT_VERSION
from tools.claim_templates import (
    CLAIM_TEMPLATES,
    FORBIDDEN_TEMPLATE_FIELDS,
    DEPTH_CONTRACT_VERSION,
    apply_template,
    resolve_template,
)


def test_every_template_prefills_category_stable_fields():
    for name, template in CLAIM_TEMPLATES.items():
        for field in (
            "family",
            "technique",
            "active_dimension",
            "skill_route",
            "risk_tier",
            "max_hypothesis_actions",
            "depth_contract_version",
        ):
            assert template.get(field), (name, field)


def test_judgment_fields_never_appear_in_any_template():
    """P0 分桶纪律：模板是格式税削减，不是门槛削减。"""
    for name, template in CLAIM_TEMPLATES.items():
        for field in FORBIDDEN_TEMPLATE_FIELDS:
            assert field not in template, (name, field)
            assert field not in str(template), (name, field)


def test_depth_contract_version_stays_in_sync_with_queue_owner():
    assert DEPTH_CONTRACT_VERSION == QUEUE_DEPTH_CONTRACT_VERSION


def test_apply_template_merges_and_explicit_metadata_wins():
    merged = apply_template(
        "idor-cross-actor",
        {"risk_tier": "critical", "hypothesis_id": "h-1"},
    )
    assert merged["family"] == "IDOR"  # template value
    assert merged["risk_tier"] == "critical"  # explicit wins
    assert merged["hypothesis_id"] == "h-1"  # passthrough


def test_apply_template_nested_skill_route_overrides_wholesale():
    explicit_route = {"skill_id": "bb-methodology", "skill_path": "skills/bb-methodology/SKILL.md", "required_dimensions": ["actor_diff"]}
    merged = apply_template("idor-cross-actor", {"skill_route": explicit_route})
    assert merged["skill_route"] == explicit_route


def test_apply_template_without_name_is_passthrough():
    metadata = {"family": "X"}
    assert apply_template("", metadata) == metadata


def test_unknown_template_rejected_with_available_list():
    with pytest.raises(ValueError, match="available"):
        resolve_template("nope")


def test_template_skill_routes_point_at_real_skill_files():
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    for name, template in CLAIM_TEMPLATES.items():
        route = template["skill_route"]
        assert (repo / route["skill_path"]).is_file(), (name, route["skill_path"])


def test_claim_via_cli_template_fills_stable_fields(tmp_path, capsys):
    """端到端：template 预填稳定字段后，AI 只需 4 个判断字段 + 证据推导。"""
    import json as jsonlib

    from tools import action_queue as aq

    probe_dir = tmp_path / "evidence" / "t.example" / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    (probe_dir / "1.json").write_text('{"kind": "probe"}', encoding="utf-8")
    aq.add_manual_action(
        tmp_path,
        target="t.example",
        action_type="next-action",
        evidence="manual seed",
        next_question="q",
        action="probe /rest/basket/1",
    )
    queue = aq.load_queue(tmp_path, "t.example")
    action_id = queue["actions"][0]["id"]

    metadata = {
        "hypothesis_id": "h-basket-1",
        "expected_learning": "anonymous can read peer basket",
        "kill_condition": "401/403 or own-data-only",
        "decision_reason": "probe saw cross-actor read",
        "input_boundary": "read-only GET",
        "endpoint": "http://t.example/rest/basket/1",
        "method": "GET",
        "evidence_ref": "evidence/t.example/probe/1.json",
        "baseline_ref": "evidence/t.example/probe/1.json",
    }
    merged = apply_template("idor-cross-actor", metadata)
    for field in ("family", "technique", "active_dimension", "skill_route", "risk_tier", "max_hypothesis_actions"):
        assert merged.get(field), field

    # 模板值必须通过 Queue 的完整激活校验（不是绕过 gate）
    claimed = aq.claim_next_action(
        tmp_path,
        "t.example",
        action_id=action_id,
        metadata=merged,
    )
    assert claimed["status"] in ("running", "active") or claimed.get("id") == action_id
    claimed_meta = claimed.get("metadata") or {}
    assert claimed_meta.get("family") == "IDOR"
    assert claimed_meta.get("hypothesis_id") == "h-basket-1"
