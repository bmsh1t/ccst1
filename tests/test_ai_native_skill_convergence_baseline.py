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
    assert "动态决策树" in skill
    assert "固定流程或类别白名单" in skill
    assert "版本、租户关系、数据流" in skill
    assert "Context Pack publishes the card catalog" in skill
    assert "Context Pack selects cards" not in skill
    # Lane notes stay direction-only (no how-to-test methodology): entry
    # condition + card pointer, nothing more.
    assert "Java Deserialization Lane" in skill
    assert "insecure-deserialization.md" in skill
    assert "版本指纹先行" not in skill  # methodology stays in the model, not the skill
    # Webhook lane covers the SSRF / signature / concurrency triple.
    assert "Webhook / Callback Lane" in skill

    router = (REPO_ROOT / "rules" / "playbook-router.md").read_text(encoding="utf-8")
    assert "测试自有且可回滚资源可在红线控制内验证" in router
    assert "订单生命周期 mutation 只记录不执行" not in router


def test_race_card_does_not_treat_serial_negative_as_parallel_proof():
    card = (REPO_ROOT / "knowledge" / "cards" / "race-conditions.md").read_text(encoding="utf-8")
    assert "串行阴性只约束已观察的串行路径" in card
    assert "不能排除并发交错窗口" in card


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
    assert "current `/intel` research, chosen by Claude" in recon
    assert "immediate next step, not a deferred one" not in recon


def test_runtime_protocol_has_single_substantive_criterion():
    """Substantive work is one criterion, not an enumerated decision tree.

    Touching the target or writing owner state (requests, evidence records,
    queue writes) is substantive; pure explanation, planning, and retrospection
    are not. Whether a substantive action queries the pack is decided by
    information gain alone: if the pack's target facts and card contents for
    that focus are already in context (no new information), skip the re-query
    and act; no "what counts as basic knowledge" proxy. Model keeps full
    boundary discretion otherwise.
    """
    protocol = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    assert "substantive 的判据只有一条" in protocol
    assert "纯解释、规划、复盘不触发" in protocol
    # A1': information-gain criterion replaces the unconditional re-query.
    assert "以信息增量为唯一判据" in protocol
    # A4 (2026-09-13 native audit): generic judgment needs no card lookup;
    # target/scope/owner facts remain mandatory reads.
    assert "通用判断不需要先找到一张卡来证明可以" in protocol
    assert "不能用通用知识猜测现场状态" in protocol
    # "什么算基础知识" must stay a rejected proxy, not a reintroduced rule.
    assert "不引入“什么算基础知识”的类别判断" in protocol
    # Catalog discovery does not mean the card body has been read.
    assert "目录路径不等于文件已读" in protocol
    assert "已读正文不重复加载" in protocol
    assert "不设固定选卡或补读上限" in protocol
    assert "全量发布 `card_catalog`" in protocol
    for field in ("knowledge_cards", "deferred_knowledge_cards", "knowledge_card_recall"):
        assert f"`{field}`" in protocol
    assert "恒空，仅保留字段兼容" in protocol
    assert "默认推荐 0-2" not in protocol
    assert "选择 0-2" not in protocol
    assert "已有 deferred recall" not in protocol


def test_runtime_protocol_rebuilds_recall_judgments_after_compaction():
    """Compaction expires in-conversation Pack references and recall judgments.

    refreshFactIndexInMessages (desredteam) rebuilds the injected blackboard
    index after every summarization. The CLI equivalent is a protocol rule:
    after compaction, recall judgments rebuild from on-disk owner state, never
    from prior judgments preserved in the compressed summary.
    """
    protocol = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    assert "会话上下文压缩（compaction/summary）后" in protocol
    assert "不从压缩摘要里复用旧判断" in protocol
    assert "按当前 owner 重新核对事实与引用" in protocol


def test_recovery_guidance_checks_inherited_constraints_without_full_source_read():
    """Guard the consumed guidance, not a claim that a model obeyed it."""
    protocol = (REPO_ROOT / "skills/runtime-protocol.md").read_text(encoding="utf-8")
    command = (REPO_ROOT / "commands/autopilot.md").read_text(encoding="utf-8")
    assert "原始观察与继承判断" in protocol
    assert "只核对该操作的当前命令契约" in protocol
    assert "不全量读源码或命令文档" in protocol
    assert "继承、未核实" in protocol
    assert "缺失或不可比较才保留顺序未知" in protocol
    assert "可达性未知也不抹去可判定的历史顺序" in protocol
    assert "记忆写入不确认 Finding、不自动晋升知识" in protocol
    recovery = command.split("### Startup And Recovery", 1)[1].split("### State Consumption Loop", 1)[0]
    assert "current commands" in recovery
    assert "not all source" in recovery
    assert "label unchecked judgments inherited/unverified" in recovery
    assert "read/apply complete" in recovery
    assert "resume/compaction" in recovery and "start, target change" in recovery
    assert "注明来源、时区" in protocol and "和精度" in protocol
    assert "先后关系不证明当前可达性" in protocol


def test_focus_recall_pulls_deserialization_cards(tmp_path):
    """The pull channel must reach the execution-chain cards via the catalog.

    Focus-based keyword selection is retired (2026-09-13 native audit): the
    pack publishes the full card catalog as the discovery surface and the AI
    pulls cards by information gap. What must hold: the execution-chain cards
    are discoverable in the catalog."""
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    from context_pack import build_context_pack

    from tools.target_store import TargetStore
    TargetStore(tmp_path, "deserialization.test").initialize()
    pack = build_context_pack(tmp_path, target="deserialization.test", focus="java deserialization fastjson")
    catalog = " ".join(str(item.get("file")) for item in pack.get("card_catalog") or [])
    assert "insecure-deserialization.md" in catalog
    assert "controlled-rce-impact.md" in catalog
    assert pack.get("knowledge_cards") == []


def test_autopilot_contract_keeps_selection_authority_with_ai():
    """Machine ordering is advisory; the session owns selection.

    Anchor the two contract lines added after the juice-shop blind run:
    route-kind labels are GET observations (never close a cell, never block a
    chosen test), and any deviation from suggested order is legal with an
    evidence-backed reason.
    """
    command = (REPO_ROOT / "commands/autopilot.md").read_text(encoding="utf-8")
    skill = (REPO_ROOT / "skills/bb-methodology/SKILL.md").read_text(encoding="utf-8")
    assert "skills/bb-methodology/SKILL.md" in command
    assert "order is advisory" in command
    assert "Read selected evidence/owner contracts before" in command
    assert "Machine ordering" in skill and "(weights," in skill
    assert "route-kind labels) is advisory input, not a decision" in skill
    assert "never close a cell or block a chosen test" in skill


def test_runtime_protocol_dropped_the_transition_review_ritual():
    """A4 (batch 7): the three modes stay, the switching ritual goes.

    The mode definitions are a thinking framework; what was deleted is only
    the "compact transition review before every switch" ceremony. The AI
    selection/override paragraph (capability ceiling protection) must stay.
    """
    protocol = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    # Mode definitions preserved.
    assert "**Discovery mode**" in protocol
    assert "**Exploitation mode**" in protocol
    assert "**Validation mode**" in protocol
    # The switching ritual is gone.
    assert "compact transition review" not in protocol
    assert "先做一次 compact transition review" not in protocol
    # Replaced by a no-ritual statement anchored at the existing heartbeat.
    assert "不需要显式 review 仪式" in protocol
    # AI selection/override (capability ceiling protection) preserved.
    assert "AI selection / override 是能力上限保护" in protocol


def test_runtime_protocol_output_contract_is_five_required_fields():
    """A7 (batch 7): 13-field template slims to 5 AI-required fields.

    The other 8 field definitions stay (owner-side consumers), but they are
    marked as owner-recorded so the AI output obligation drops. The four
    禁止事项 lines must remain unchanged.
    """
    protocol = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")
    assert "## 输出契约" in protocol
    # 5 required fields, marked 必填.
    for field in ("Evidence", "Candidates", "Dead ends", "Still unknown", "Next actions"):
        assert f"- {field}:" in protocol
        assert f"- {field}:" in protocol.split("## 输出契约")[1].split("## 禁止事项")[0]
    # 必填 marks exist exactly for the 5 fields.
    contract_body = protocol.split("## 输出契约")[1].split("## 禁止事项")[0]
    assert contract_body.count("(必填)") == 5
    # The 8 owner-recorded fields are marked, not deleted.
    for field in (
        "Target", "Phase", "Hypotheses", "Actions taken",
        "Coverage update", "Leads / Signals", "Write-back",
    ):
        assert f"- {field}:" in contract_body
        assert "owner:" in contract_body.split(f"- {field}:")[1].splitlines()[0]
    # 禁止事项 intact (security residual).
    assert "不得跳过目标层直接进入大范围测试" in protocol
    assert "不得默认全量读取知识库" in protocol
    assert "不得把 Lead 包装成 Candidate" in protocol
    assert "不得把推荐字段、单个 seed 或工具输出当成已执行状态" in protocol


def test_autopilot_heartbeat_is_conditional():
    command = " ".join((REPO_ROOT / "commands/autopilot.md").read_text().split())
    assert "write decision/next_action only on rotation/blocker/stall" in command
    assert "unlike mandatory Round heartbeats" in command
    assert "Decide continue/rotate/stop in-turn" in command
    assert "--loop-check --projection-only --json" in command
    assert "`loop_guard.repetition_facts` is advisory, never overrides hard gates/claims" in command
    assert "Coverage `rebuild` then `find-gaps`" in command
    assert "Global Review covers bounded" in command


def test_autopilot_lane_contract_is_inlined_into_bootstrap():
    command = " ".join((REPO_ROOT / "commands/autopilot.md").read_text().split())
    assert "Reuse `state.lane_contract` at `text_available=true`" in command
    assert "otherwise/new selection read that section in `docs/autopilot-lanes.md`" in command


def test_autopilot_business_model_read_is_native():
    """Native-capability audit (2026-09-13): Business Model Read no longer routes
    through a deterministic stub generator. AI writes and edits the note directly
    from bounded evidence; the generator (five blank AI sections, 30-day mtime
    freshness, refresh losing AI judgment) was a re-implementation of native work."""
    skill = (REPO_ROOT / "skills/bb-methodology/SKILL.md").read_text(encoding="utf-8")
    assert "tools/business_model_stub.py" not in skill
    assert "maintain `evidence/<target>/business_model.md`" in skill
    assert "AI writes and edits" in skill
    assert "do not\nregenerate or overwrite" in skill
    assert "discard existing judgments and sources" in skill
    assert "Separate observations from judgments" in skill
    for dimension in ("observed purpose", "actors' roles", "crown jewels", "trust boundaries", "sensitive workflows"):
        assert dimension in " ".join(skill.split())
    assert "After fresh Recon starts" in skill
    assert "depth pack from target-observed request shapes" in skill
    assert "one passive observation is not API" in skill
    assert "Partial cursors and untested dimensions remain" in skill


def test_action_queue_lanes_doc_keeps_explicit_store_work_and_ai_choice():
    lanes = (REPO_ROOT / "docs" / "autopilot-lanes.md").read_text(encoding="utf-8")
    assert "explicit" in lanes
    assert "Store" in lanes
    assert "--from-evidence" in lanes and "retired" in lanes
    assert "--id" in lanes
    assert "AI" in lanes


def test_optional_autopilot_is_one_bounded_task_with_parent_owned_writeback():
    agent = (REPO_ROOT / "agents/autopilot.md").read_text(encoding="utf-8")
    normalized = " ".join(agent.split())
    assert "docs/autopilot-lanes.md#inline-specialist-propagation" in agent
    assert "the parent alone claims lanes, writes owner state, and decides closure" in normalized
    for field in ("arguments.deep", "invocation_batch.bounded", "invocation_batch.max_lanes", "invocation_batch.handoff"):
        assert f"`{field}`" in agent
    assert "DEEP HUNT MODE" in agent
    assert "Missing target or test boundary means no execution" in normalized
    assert "Do not mutate owner state" in agent
    assert "Do not initialize/repair stores, build/refresh projections" in normalized
    assert "fact key | summary | evidence refs | suggested owner action" in agent
    assert "Effective mode / batch boundary / request budget used and remaining" in agent
    assert "findings.json" not in agent and "case_state.json" not in agent
    assert "## Core Loop" not in agent and "## Deep Mode" not in agent
    assert "## Session Summary" not in agent
    for command in (
        "target_memory.py show TARGET --json",
        "target_store.py findings --target TARGET --limit 8",
        "target_case_state.py summary --target TARGET --json",
    ):
        assert command in agent
    for capability in ("filename", "filePath", "HttpOnly", "Network", "Console", "JSHook", "standard_public_metadata.txt"):
        assert capability in agent
    assert "only when visible in this session" in normalized
    assert "Mark newly saved originals as unregistered" in agent


def test_autopilot_agent_mode_reference_resolves():
    agent = (REPO_ROOT / "agents" / "autopilot.md").read_text(encoding="utf-8")
    protocol = (REPO_ROOT / "skills/runtime-protocol.md").read_text(encoding="utf-8")
    reference = "skills/runtime-protocol.md#21-三模式决策discovery--exploitation--validation-modes"
    heading = "### 2.1 三模式决策：Discovery / Exploitation / Validation modes"

    assert reference in agent
    assert "#2-1-三模式决策" not in agent
    assert heading in protocol
    modes = protocol.split(heading, 1)[1].split("\n### ", 1)[0]
    for mode in ("Discovery", "Exploitation", "Validation"):
        assert f"**{mode} mode**" in modes
    assert "AI selection / override" in modes


def test_dns_expansion_returns_surface_refresh_to_caller():
    lanes = (REPO_ROOT / "docs" / "autopilot-lanes.md").read_text(encoding="utf-8")
    section = lanes.split("## Credentials And Asset Expansion\n", 1)[1].split("\n## ", 1)[0]
    prefix = "- DNS expansion handoff:"
    assert prefix in section
    handoff = next(line for line in section.splitlines() if line.startswith(prefix))

    assert "`new_resolved_hosts` or `new_all_hosts` is positive" in handoff
    assert "counts and evidence refs" in handoff
    assert "「待落库」" in handoff
    assert "The caller refreshes `/surface`" in handoff
    assert "the specialist never refreshes parent state" in handoff
    assert "With no added hosts, do not request a refresh" in handoff


@pytest.mark.parametrize("entry", ["commands/autopilot.md", "commands/hunt.md", "agents/autopilot.md"])
def test_investigation_methods_are_reachable_in_every_execution_mode(entry):
    text = (REPO_ROOT / entry).read_text(encoding="utf-8")
    for owner in ("skills/bug-bounty/SKILL.md", "skills/bb-methodology/SKILL.md"):
        assert owner in text
    assert "on demand" in text.lower()
    assert "business_model.md" not in text


def test_controller_prompt_sizes_stay_within_spec_guards():
    """recon-surface.md: controller prompts are not embedded playbooks; guard
    UTF-8 sizes at 20 KiB (commands/autopilot.md) and 32 KiB
    (agents/autopilot.md). B3 minimal closure: the merged 11 KiB combined
    budget is the stricter day-to-day guard for the two entry command files;
    this pins the standing per-file spec values so they cannot drift open."""
    assert (REPO_ROOT / "commands/autopilot.md").stat().st_size <= 20 * 1024
    assert (REPO_ROOT / "agents/autopilot.md").stat().st_size <= 32 * 1024


def test_manual_hunt_reuses_shared_rotation_and_browser_contracts():
    hunt = (REPO_ROOT / "commands/hunt.md").read_text(encoding="utf-8")
    coordinator = (REPO_ROOT / "skills/bug-bounty/SKILL.md").read_text(encoding="utf-8")
    lanes = (REPO_ROOT / "docs/autopilot-lanes.md").read_text(encoding="utf-8")
    assert "autopilot's promotion contract" not in hunt
    assert "rules/coverage-gate.md" in hunt and "docs/evidence-runners.md" in hunt
    assert "three focused variants" not in hunt
    assert "skills/bb-methodology/SKILL.md#evidence-driven-rotation" in hunt
    assert hunt.count("python3 tools/surface.py --target target.com") == 1
    assert "docs/autopilot-lanes.md#browser-source-and-js" in hunt
    assert "docs/autopilot-lanes.md" in coordinator
    assert "does not authorize automatic continuation or delegation" in lanes
    assert "This section applies only to automatic mode" in lanes
    browser = lanes.split("## Browser Source And JS", 1)[1].split("## Software And Intel", 1)[0]
    for boundary in ("one active backend at a time", "tools/browser_mcp_import.py", "browser_close", "partial", "blocked"):
        assert boundary in browser


def test_automatic_mode_keeps_receipts_and_bounded_post_lane_refresh():
    command = " ".join((REPO_ROOT / "commands/autopilot.md").read_text().split())
    for boundary in ("### State Consumption Loop", "Consume Bootstrap `state`, then refreshed `control`",
                     "Do not loop `/hunt`", "docs/evidence-runners.md#绑定已认领行动",
                     "same explicit `--actor OPERATOR`", "require actual receipts",
                     "Failed claim: inspect once; never guess/retry", "exactly one post-lane refresh",
                     "re-read only after owner writes", "never replay unknown effects",
                     "`max_lanes` limits only new lanes, not evidence import/owner write-back/cleanup/Checkpoint/Closure"):
        assert boundary in command


@pytest.mark.parametrize(
    ("section", "required"),
    [
        ("state-and-queue", "Automatic mode only:"),
        ("access-limit", "if absent, use any self-owned mailbox and keep the raw evidence"),
    ],
)
def test_shared_lane_sections_keep_local_mode_and_fallback_contracts(section, required):
    from tools.autopilot_bootstrap import _lane_contract_text

    projection = _lane_contract_text(REPO_ROOT, f"docs/autopilot-lanes.md#{section}")
    assert projection["available"]
    assert required in " ".join(projection["text"].split())


def test_memory_recommendation_section_is_required_once_and_presentation_only():
    """B2 live gate (2026-10-10): the merged optional downgrade dropped the section
    in a real round and conflicted with the spec scenario "Advisory Memory
    Recommendation at Bounded Finish" (runtime-autopilot.md), which requires exactly
    one section per bounded invocation. Saves stay mandatory throughout; promotion
    stays review-gated."""
    command = " ".join((REPO_ROOT / "commands/autopilot.md").read_text().split())
    assert "exactly one presentation-only `Memory recommendations` section in this final response" in command
    assert "promote / target-only / reject" in command
    assert "`none` + reason per empty bucket" in command
    assert "Save memory/current handoff via Shared Memory Continuity before pause/handoff/finish" in command
    assert "Promotion stays review-gated" in command
    # Regression guard: the merged downgrade phrase must not return.
    assert "memory advice is optional" not in command
    for owner in ("knowledge/promotion-rules.md", "rules/retrospective.md"):
        assert owner in command and (REPO_ROOT / owner).is_file()


def test_memory_h2_keeps_recovery_without_loading_skill_methods():
    protocol = (REPO_ROOT / "skills/runtime-protocol.md").read_text(encoding="utf-8")
    memory = protocol.split("\n## Shared Memory Continuity\n", 1)[1].split("\n## ", 1)[0]
    assert "Skill layer" not in memory
    for contract in (
        "### 1. Target layer", "原始观察与继承判断", "只核对该操作的当前命令契约",
        "先后关系不证明当前可达性", "current_handoff", "next_actions", "selection_status=failed",
        "--operation-ref OPERATION_ID:0", "记忆写入不确认 Finding、不自动晋升知识", "当轮 Bootstrap",
    ):
        assert contract in memory
    skill = protocol.split("\n## 2. Skill layer\n", 1)[1].split("\n## ", 1)[0]
    for method in (
        "### 2.1 三模式决策", "### 2.2 Web 深水区启发式路由", "### 2.3 层级归属标准",
        "**Discovery mode**", "**Exploitation mode**", "**Validation mode**", "AI selection / override",
    ):
        assert method in skill
        assert method not in memory
