"""Guard the fixed decision cases used by the AI-native convergence A/B."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_DIR = REPO_ROOT / "tests" / "skill-validator"
if str(VALIDATOR_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATOR_DIR))

from ab_runner import load_jsonl  # noqa: E402


CASE_FILE = VALIDATOR_DIR / "cases" / "ai_native_skill_convergence_ab.jsonl"
EXPECTED_CASES = {
    "A01_sparse_discovery",
    "A02_actor_object_priority",
    "A03_stack_only_signal",
    "A04_high_value_roi",
    "A05_repeated_progress",
    "A06_fresh_evidence_reopen",
    "A07_missing_validation_proof",
    "A08_residual_inventory",
}


@pytest.mark.parametrize(
    ("case_file", "expected_cases"),
    [
        (CASE_FILE, EXPECTED_CASES),
        (
            VALIDATOR_DIR / "cases" / "evidence_counterexamples_ab.jsonl",
            {
                "A09_scoped_negative_with_residual_session",
                "A10_local_denial_is_not_global_repair",
                "A11_shared_login_is_not_component_identity",
                "A12_login_fallback_preserves_unknown",
            },
        ),
    ],
    ids=["baseline", "evidence-counterexamples"],
)
def test_ai_native_decision_cases_are_fixed_and_parseable(case_file, expected_cases):
    rows = load_jsonl(case_file)

    assert len(rows) == len(expected_cases)
    assert {row["case_id"] for row in rows} == expected_cases
    assert {row["oracle_status"] for row in rows} == {"passed"}
    assert {row["oracle_label"] for row in rows} == {"safe", "vulnerable"}
    assert all(isinstance(row["prompt"], str) and row["prompt"].strip() for row in rows)


def test_web2_vuln_pattern_map_keeps_java_deserialization_and_webhook_routes():
    """Anchor the discovery-side routing rows (signal -> lane).

    43d22fb deleted the skill-side card route table expecting context_pack to
    rebuild recall; the rebuild never happened and the deserialization chain
    went dark silently. These anchors make removing the routing rows loud:
    decision text belongs in the skill (A/B-testable), not in hidden regexes.
    """
    skill = (REPO_ROOT / "skills" / "web2-vuln-classes" / "SKILL.md").read_text(encoding="utf-8")

    # Pattern Map rows: shape signals (not confirmed-vuln words) must have a route.
    assert "JSON body with `@type`" in skill
    # First branch: target profile -> high-value surface distribution (direction only).
    assert "Target Profile First Branch" in skill
    assert "不是决策树也不排除任何类别" in skill
    # Lane notes stay direction-only (no how-to-test methodology): entry
    # condition + card pointer, nothing more.
    assert "Java Deserialization Lane" in skill
    assert "insecure-deserialization.md" in skill
    assert "版本指纹先行" not in skill  # methodology stays in the model, not the skill
    # Webhook lane covers the SSRF / signature / concurrency triple.
    assert "Webhook / Callback Lane" in skill


def test_phase0_and_intel_route_keep_selection_reason_and_urgency():
    """Anchor the two desredteam-derived prose weights.

    - Phase 0 requires a one-line selection reason (advisory, not a gate):
      why this hypothesis over alternatives.
    - The recon /intel route marks a concrete version fingerprint as an
      immediate trigger, not a deferred enrichment step.
    """
    methodology = (REPO_ROOT / "skills" / "bb-methodology" / "SKILL.md").read_text(encoding="utf-8")
    assert "why this hypothesis over the alternatives" in methodology
    assert "not a favorite class" in methodology

    recon = (REPO_ROOT / "skills" / "web2-recon" / "SKILL.md").read_text(encoding="utf-8")
    assert "immediate next step, not a deferred one" in recon


def test_runtime_protocol_has_single_substantive_criterion():
    """Substantive work is one criterion, not an enumerated decision tree.

    Touching the target or writing owner state (requests, evidence records,
    queue writes) is substantive; pure explanation, planning, and retrospection
    are not. Whether a substantive action queries the pack is decided by
    information gain alone: if the pack's recommendations and card contents for
    that focus are already in context (no new information), skip the re-query
    and act; no "what counts as basic knowledge" proxy. Model keeps full
    boundary discretion otherwise.
    """
    protocol = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    assert "substantive 的判据只有一条" in protocol
    assert "纯解释、规划、复盘不触发" in protocol
    # A1': information-gain criterion replaces the unconditional re-query.
    assert "以信息增量为唯一判据" in protocol
    assert "免重查，直接动手" in protocol
    # "什么算基础知识" must stay a rejected proxy, not a reintroduced rule.
    assert "不引入“什么算基础知识”的类别判断" in protocol
    # Recommended path is not the same as file read: contents still must be loaded.
    assert "推荐路径不等于文件已读" in protocol


def test_runtime_protocol_invalidates_pack_recommendations_after_compaction():
    """Compaction expires in-conversation Pack recommendations.

    refreshFactIndexInMessages (desredteam) rebuilds the injected blackboard
    index after every summarization. The CLI equivalent is a protocol rule:
    after compaction, recall judgments rebuild from on-disk owner state, never
    from recommendations preserved in the compressed summary.
    """
    protocol = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    assert "会话上下文压缩（compaction/summary）后" in protocol
    assert "不从压缩摘要里复用旧推荐" in protocol


def test_focus_recall_pulls_deserialization_cards():
    """The pull channel (focus-based recall) must reach the execution-chain cards."""
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    from context_pack import build_context_pack

    pack = build_context_pack(REPO_ROOT, target="127.0.0.1:3001", focus="java deserialization fastjson")
    cards = " ".join(str(item) for item in pack.get("knowledge_cards") or [])
    assert "insecure-deserialization.md" in cards
    assert "controlled-rce-impact.md" in cards


def test_autopilot_contract_keeps_selection_authority_with_ai():
    """Machine ordering is advisory; the session owns selection.

    Anchor the two contract lines added after the juice-shop blind run:
    route-kind labels are GET observations (never close a cell, never block a
    chosen test), and any deviation from suggested order is legal with an
    evidence-backed reason.
    """
    skill = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
    assert "Machine ordering (weights," in skill
    assert "route-kind labels) is advisory input, not a decision" in skill
    assert "never close a cell or block a chosen test" in skill
