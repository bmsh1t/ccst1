#!/usr/bin/env python3
"""自动生成 Claude CLI 目标 checkpoint 和目标记忆写回建议。

默认只读并输出建议；只有传入 `--apply-target-memory` 时，才会把
lead / next / dead-end / handoff 追加写入目标记忆层。知识库、Skills、
Rules 永远只给建议，不在这里自动修改。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.action_queue import (
        FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES,
        _checkpoint_item_to_action as action_queue_checkpoint_item_to_action,
        _dedupe_key as action_queue_dedupe_key,
        load_queue as load_action_queue,
        select_next_action as action_queue_select_next_action,
    )
    from tools.autopilot_state import build_autopilot_state
    from tools.context_pack import build_context_pack
    from tools.coverage_matrix import class_relevance, high_value_gaps_from_matrix, rebuild_matrix, save_matrix
    from tools.evidence_rubric import evaluate_candidate_evidence, first_missing_action
    from tools.evidence_ledger import build_summary as build_evidence_summary, record_command as evidence_record_command
    from tools.case_state_seed import build_case_state_seed
    from tools.structured_findings import format_validation_runner_candidate_lines
    from tools.target_case_state import load_case_state, summary as build_case_state_summary
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import (  # type: ignore
        FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES,
        _checkpoint_item_to_action as action_queue_checkpoint_item_to_action,
        _dedupe_key as action_queue_dedupe_key,
        load_queue as load_action_queue,
        select_next_action as action_queue_select_next_action,
    )
    from autopilot_state import build_autopilot_state  # type: ignore
    from context_pack import build_context_pack  # type: ignore
    from coverage_matrix import class_relevance, high_value_gaps_from_matrix, rebuild_matrix, save_matrix  # type: ignore
    from evidence_rubric import evaluate_candidate_evidence, first_missing_action  # type: ignore
    from evidence_ledger import build_summary as build_evidence_summary, record_command as evidence_record_command  # type: ignore
    from case_state_seed import build_case_state_seed  # type: ignore
    from structured_findings import format_validation_runner_candidate_lines  # type: ignore
    from target_case_state import load_case_state, summary as build_case_state_summary  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _json_list(items: object) -> list[dict]:
    out: list[dict] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, str):
            try:
                item = json.loads(item)
            except json.JSONDecodeError:
                item = {"title": item}
        if isinstance(item, dict):
            out.append(item)
    return out


def _matrix_gaps(matrix: dict, min_weight: float = 3.0) -> list[dict]:
    return high_value_gaps_from_matrix(matrix, min_weight=min_weight)


def _actionable_coverage_gaps(coverage_gaps: list[dict]) -> list[dict]:
    """Return coverage gaps with concrete semantic fit for immediate action.

    The coverage matrix intentionally tracks broad high-impact cells, but the
    action queue should not be driven by generic "endpoint × vuln class" pairs
    with no path/parameter/source/browser signal.  Keep those gaps visible in
    coverage statistics; only promote semantically relevant cells into the
    next-action loop.
    """
    actionable: list[dict] = []
    for gap in coverage_gaps:
        try:
            relevance = int(gap.get("relevance_score", 0) or 0)
        except (TypeError, ValueError):
            relevance = 0
        if relevance > 0:
            actionable.append(gap)
    return actionable


def _gap_observed_params(gap: dict) -> list[str]:
    params = gap.get("observed_params") or []
    if not isinstance(params, list):
        return []
    return [str(item).strip() for item in params if str(item or "").strip()]


def _is_path_only_authz_gap(gap: dict) -> bool:
    """Return true for Authz gaps backed only by path semantics.

    `/admin`-like paths are useful leads, but without an observed parameter,
    exact browser request, existing finding, or body evidence they are not yet a
    two-actor replay candidate. Treat them as baseline-classification work so
    checkpoint does not turn every admin-looking parent path into a noisy
    authorization task.
    """
    vuln_class = str(gap.get("vuln_class") or "").strip().lower()
    if vuln_class != "authz" or _gap_observed_params(gap):
        return False
    reason = str(gap.get("relevance_reason") or "").lower()
    try:
        relevance = int(gap.get("relevance_score", 0) or 0)
    except (TypeError, ValueError):
        relevance = 0
    return "admin/internal path" in reason or relevance <= 5


def _coverage_gap_validation_path(gap: dict) -> str:
    """Return the first evidence-producing step for a coverage gap.

    Coverage gaps are discovery tasks, but autopilot should immediately know
    what proof would promote the lead to a candidate.  Reuse the same evidence
    rubric that `/validate` uses so discovery and validation stay aligned.
    """
    vuln_class = str(gap.get("vuln_class") or "").strip()
    endpoint = str(gap.get("endpoint") or "").strip()
    reason = str(gap.get("relevance_reason") or "").strip()
    if not vuln_class:
        return ""
    if _is_path_only_authz_gap(gap):
        return (
            "First run an anonymous baseline GET or observed-method replay and "
            "classify status/body before any role-diff work. If 200 with "
            "body-backed sensitive/admin/config markers, run "
            "`python3 tools/validation_runner.py authz-public-exposure --target "
            "<target> --url <target>{endpoint}` and preserve raw evidence. If "
            "401/403, record the auth boundary. If 404/5xx/framework error or "
            "SPA fallback, record tested_clean/dead-end and pivot to "
            "browser-observed sibling endpoints."
        ).format(endpoint=endpoint)
    evaluation = evaluate_candidate_evidence({
        "type": vuln_class,
        "url": endpoint,
        "summary": reason,
    })
    return first_missing_action(evaluation)


def _matrix_summary(matrix: dict, gaps: list[dict]) -> dict:
    endpoints = matrix.get("endpoints") or []
    total_cells = 0
    counts = {
        "tested_clean": 0,
        "tested_finding": 0,
        "untested": 0,
        "n_a": 0,
    }
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        cells = endpoint.get("cells") or {}
        if not isinstance(cells, dict):
            continue
        for cell in cells.values():
            if not isinstance(cell, dict):
                continue
            total_cells += 1
            status = str(cell.get("status") or "untested")
            if status in counts:
                counts[status] += 1
    return {
        "endpoints": len([item for item in endpoints if isinstance(item, dict)]),
        "total_cells": total_cells,
        **counts,
        "high_value_gaps_count": len(gaps),
        "actionable_high_value_gaps_count": len(_actionable_coverage_gaps(gaps)),
    }


def _surface_stats(state: dict) -> dict:
    surface = state.get("surface") or {}
    stats = surface.get("stats") or {}
    return {
        "p1": int(stats.get("p1", 0) or 0),
        "p2": int(stats.get("p2", 0) or 0),
        "review_pool": int(stats.get("review_pool", 0) or 0),
        "workflow_leads": len(_json_list(surface.get("workflow_leads"))),
    }


def _structured_findings(state: dict) -> dict:
    payload = state.get("structured_findings") or {}
    return payload if isinstance(payload, dict) else {}


def _unsafe_leads(state: dict) -> list[dict]:
    surface = state.get("surface") or {}
    leads = _json_list(surface.get("workflow_leads"))
    return [
        item for item in leads
        if str(item.get("category") or "").lower() in {"unsafe-skipped", "action-gated"}
    ]


def _unsafe_skipped_proposals(state: dict) -> list[str]:
    proposals: list[str] = []
    for lead in _unsafe_leads(state)[:3]:
        artifact = str(lead.get("artifact") or "").strip()
        unsafe_id = str(lead.get("unsafe_skipped_id") or "").strip()
        evidence = str(lead.get("evidence") or "").strip()
        if not artifact and not unsafe_id:
            continue
        proposals.append(
            "Review action-gated scanner lane {unsafe_id}: {evidence}. "
            "Artifact={artifact}. Decide tested, blocked, dead-end, n/a, or candidate; "
            "only rerun broad scanner probes with ALLOW_UNSAFE_HTTP_TESTS=1 after explicit operator opt-in; "
            "safe observed-method replay may continue when it has no destructive side effect.".format(
                unsafe_id=unsafe_id or "-",
                evidence=evidence or "side-effect-capable scanner probe was skipped",
                artifact=artifact or "findings/<target>/manual_review/unsafe_skipped.txt",
            )
        )
    return proposals


SECONDARY_SWEEP_CATEGORIES = {"open-200-api-review", "public-metadata"}


def _secondary_sweep_leads(state: dict) -> list[dict]:
    surface = state.get("surface") or {}
    leads = _json_list(surface.get("workflow_leads"))
    return [
        item for item in leads
        if str(item.get("category") or "").lower() in SECONDARY_SWEEP_CATEGORIES
    ]


def _secondary_sweep_proposals(state: dict) -> list[str]:
    proposals: list[str] = []
    for lead in _secondary_sweep_leads(state)[:3]:
        category = str(lead.get("category") or "").strip() or "secondary-sweep"
        title = str(lead.get("title") or "").strip()
        artifact = str(lead.get("artifact") or "").strip() or "findings/<target>/manual_review/<artifact>.txt"
        next_action = str(lead.get("next_action") or "").strip()
        rationale = str(lead.get("rationale") or "").strip()
        evidence = str(lead.get("evidence") or "").strip()
        if not title:
            continue
        proposals.append(
            "Secondary-sweep lead [{category}]: {title}. "
            "Artifact={artifact}. Why it matters: {rationale}. "
            "Next action: {next_action}. "
            "Stop condition: either promote to candidate/chain-intel with concrete evidence, "
            "or keep demoted with a written reason after reviewing the raw artifact.".format(
                category=category,
                title=title[:180],
                artifact=artifact,
                rationale=(rationale or evidence or category)[:220],
                next_action=(next_action or "inspect the raw manual_review artifact for chain, secret, or pivot signals")[:220],
            )
        )
    return proposals


def _evidence_focus_endpoints(state: dict, coverage_gaps: list[dict]) -> list[str]:
    surface = state.get("surface") or {}
    endpoints: list[str] = []
    for item in (surface.get("p1") or [])[:4] + (surface.get("p2") or [])[:2]:
        if isinstance(item, dict):
            endpoints.append(str(item.get("url") or item.get("path") or ""))
    for gap in coverage_gaps[:5]:
        endpoints.append(str(gap.get("endpoint") or ""))
    for item in (state.get("recommended_targets") or [])[:3]:
        if isinstance(item, dict):
            endpoints.append(str(item.get("url") or ""))
    return _dedupe(endpoints)[:8]


def _evidence_vuln_classes(coverage_gaps: list[dict], context_pack: dict) -> list[str]:
    classes: list[str] = []
    for gap in coverage_gaps[:8]:
        classes.append(str(gap.get("vuln_class") or ""))
    for card in context_pack.get("knowledge_cards", []) or []:
        card_text = str(card)
        if "api-idor" in card_text:
            classes.append("IDOR")
        if "auth-access" in card_text:
            classes.append("Authz")
        if "graphql" in card_text:
            classes.append("GraphQL")
    return _dedupe([item for item in classes if item])[:3] or ["IDOR", "Authz"]


def _actor_gaps(evidence_summary: dict) -> list[dict]:
    matrix = evidence_summary.get("actor_matrix") or {}
    return [
        item for item in matrix.get("gaps", [])
        if isinstance(item, dict) and item.get("status") in {"missing", "pending", "blocked"}
    ]


def _case_state_count(case_state: dict | None, key: str) -> int:
    if not isinstance(case_state, dict):
        return 0
    try:
        return int(case_state.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _actor_gap_ready(gap: dict, case_state: dict | None) -> bool:
    """判断 actor-gap 是否具备进入可执行队列的运行态前置条件。

    anonymous baseline 不依赖目标运行态，可直接验证匿名访问行为。owner/peer/
    low_role/cross_tenant 这类角色差异验证必须先有 case state 中的 actor、
    session、object，否则 checkpoint 会生成“看起来可执行、实际缺上下文”的队列。
    """
    actor = str(gap.get("actor") or "").strip().lower()
    if actor == "anonymous":
        return True

    actors = _case_state_count(case_state, "actors")
    sessions = _case_state_count(case_state, "sessions")
    objects = _case_state_count(case_state, "objects")
    if actor == "owner":
        return actors >= 1 and sessions >= 1 and objects >= 1
    if actor in {"peer", "low_role", "cross_tenant"}:
        return actors >= 2 and sessions >= 2 and objects >= 1
    return actors >= 1 and sessions >= 1


def _actionable_actor_gaps(evidence_summary: dict, case_state: dict | None = None) -> list[dict]:
    return [
        gap for gap in _actor_gaps(evidence_summary)
        if _actor_gap_ready(gap, case_state)
    ]


def _actor_gap_enrichment_proposal(evidence_summary: dict, case_state: dict | None = None) -> str:
    blocked = [
        gap for gap in _actor_gaps(evidence_summary)
        if not _actor_gap_ready(gap, case_state)
    ]
    if not blocked:
        return ""

    first = blocked[0]
    missing: list[str] = []
    actors = _case_state_count(case_state, "actors")
    sessions = _case_state_count(case_state, "sessions")
    objects = _case_state_count(case_state, "objects")
    actor = str(first.get("actor") or "").strip().lower()
    if actor in {"peer", "low_role", "cross_tenant"} and actors < 2:
        missing.append("second actor")
    elif actors < 1:
        missing.append("actor")
    if actor in {"peer", "low_role", "cross_tenant"} and sessions < 2:
        missing.append("peer/second session")
    elif sessions < 1:
        missing.append("session")
    if objects < 1:
        missing.append("business object")
    missing = _dedupe(missing) or ["case-state actor/session/object"]

    return (
        "Case-state enrichment lead: actor matrix has {count} role/object gap(s) "
        "that are not executable until runtime context is registered. Example: "
        "{endpoint} x {vuln} with {actor}/{scope}/{variant}. Missing evidence: "
        "{missing}. Next: register actor/session/object with tools/target_case_state.py "
        "or use tools/case_state_seed.py suggestions; keep anonymous baselines and "
        "ranked-surface discovery moving while enrichment is missing."
    ).format(
        count=len(blocked),
        endpoint=first.get("endpoint", ""),
        vuln=first.get("vuln_class", ""),
        actor=first.get("actor", ""),
        scope=first.get("object_scope", ""),
        variant=first.get("variant", ""),
        missing=", ".join(missing),
    )


def _case_state_summary(repo_root: Path | str, target: str) -> dict:
    """Load sanitized target case state summary for checkpoint routing.

    这里故意吞掉 case_state 读取异常，避免 checkpoint 因可选运行态记忆损坏而整体失败。
    """
    try:
        payload = build_case_state_summary(repo_root, target)
        state = load_case_state(repo_root, target)
        objects = state.get("objects") if isinstance(state.get("objects"), dict) else {}
        if isinstance(payload, dict):
            payload["object_samples"] = [
                {
                    "object_ref": str(ref),
                    "type": str(obj.get("type") or ""),
                    "object_id": str(obj.get("object_id") or ""),
                    "endpoint": str(obj.get("endpoint") or ""),
                    "owner_actor": str(obj.get("owner_actor") or ""),
                    "private_marker": str(obj.get("private_marker") or ""),
                }
                for ref, obj in list(objects.items())[:8]
                if isinstance(obj, dict)
            ]
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _case_state_top_next(case_state: dict) -> dict:
    top = case_state.get("top_next_action") or {}
    return top if isinstance(top, dict) else {}


def _list_clause(values: object) -> str:
    if not isinstance(values, list):
        return ""
    clean = [str(item or "").strip() for item in values if str(item or "").strip()]
    return ", ".join(clean)


def _case_state_proposal(case_state: dict) -> str:
    top = _case_state_top_next(case_state)
    action = str(top.get("next_action") or "").strip().lower()
    if not action or action == "none":
        return ""

    backlog_id = str(top.get("backlog_id") or "").strip()
    label = "Case-state next action"
    if action == "run_validation_runner":
        label = "Case-state validation backlog"
    elif action == "enrich_case_state":
        label = "Case-state enrichment backlog"
    elif action == "create_validation_backlog":
        label = "Case-state backlog creation"

    headline = f"{label} {backlog_id}".strip()
    if headline.endswith("backlog creation"):
        headline = headline.rstrip()

    parts = [headline + ":"]
    hypothesis = str(top.get("hypothesis") or "").strip()
    if hypothesis:
        parts.append(f"Hypothesis: {hypothesis}.")
    why_now = str(top.get("why_now") or "").strip()
    if why_now:
        parts.append(f"Why now: {why_now}.")

    runner = str(top.get("runner") or "").strip()
    owner_actor = str(top.get("owner_actor") or "").strip()
    peer_actor = str(top.get("peer_actor") or "").strip()
    object_ref = str(top.get("object_ref") or "").strip()
    endpoint = str(top.get("endpoint") or "").strip()
    if runner:
        parts.append(f"Runner: {runner}.")
    if owner_actor or peer_actor:
        parts.append(
            "Actors: owner={owner}, peer={peer}.".format(
                owner=owner_actor or "-",
                peer=peer_actor or "-",
            )
        )
    if object_ref:
        parts.append(f"Object ref: {object_ref}.")
    if endpoint:
        parts.append(f"Endpoint: {endpoint}.")

    replay_draft = str(top.get("redacted_command") or top.get("command") or "").strip()
    if action == "run_validation_runner" and replay_draft:
        parts.append(f"Exact replay draft: {replay_draft}.")

    required = _list_clause(top.get("required_evidence"))
    if required:
        parts.append(f"Required evidence: {required}.")
    missing = _list_clause(top.get("missing_evidence"))
    if missing:
        parts.append(f"Missing evidence: {missing}.")
    optional = _list_clause(top.get("optional_evidence_gaps"))
    if optional:
        parts.append(f"Optional evidence gaps: {optional}.")

    downgrade_rule = str(top.get("downgrade_rule") or "").strip()
    if downgrade_rule:
        parts.append(f"Downgrade rule: {downgrade_rule}.")
    stop_condition = str(top.get("stop_condition") or "").strip()
    if stop_condition:
        parts.append(f"Stop condition: {stop_condition}.")
    write_back = str(top.get("write_back") or "").strip()
    if write_back:
        parts.append(f"Write-back: {write_back}.")
    chain_extensions = _list_clause(top.get("chain_extensions_if_blocked"))
    if chain_extensions:
        parts.append(f"Chain extensions if blocked: {chain_extensions}.")
    return " ".join(parts).strip()


def _case_state_seed_summary(repo_root: Path | str, target: str) -> dict:
    """Load suggestion-only case_state seed opportunities."""
    try:
        payload = build_case_state_seed(repo_root, target, limit=3)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _case_state_seed_proposal(seed: dict) -> str:
    if str(seed.get("status") or "") != "suggestions":
        return ""
    objects = seed.get("suggested_objects") if isinstance(seed.get("suggested_objects"), list) else []
    backlog = seed.get("suggested_backlog") if isinstance(seed.get("suggested_backlog"), list) else []
    if not objects and not backlog:
        return ""
    selected_index = 0
    for index, item in enumerate(backlog):
        if not isinstance(item, dict):
            continue
        missing = {str(value).strip().lower() for value in item.get("missing") or []}
        if "object endpoint" not in missing:
            selected_index = index
            break
    first_object = objects[selected_index] if selected_index < len(objects) and isinstance(objects[selected_index], dict) else {}
    first_backlog = backlog[selected_index] if selected_index < len(backlog) and isinstance(backlog[selected_index], dict) else {}
    target = str(seed.get("target") or "").strip()
    command = f"python3 tools/case_state_seed.py --target {_quote(target)} --json" if target else "python3 tools/case_state_seed.py --target <target> --json"
    missing = ", ".join(str(item) for item in (first_backlog.get("missing") or [])[:4])
    endpoint = str(first_object.get("endpoint") or "").strip()
    if "object endpoint" in {part.strip().lower() for part in (first_backlog.get("missing") or [])}:
        return (
            "Case-state endpoint discovery lead: Found object candidate {object_ref} "
            "type={object_type} endpoint=<missing>. Runner: {runner}. "
            "Missing evidence: {missing}. Next action: identify a concrete "
            "object-specific endpoint from browser XHR, source routes, or MCP "
            "observations before adding IDOR backlog. Seed command: {command}. "
            "Stop condition: no endpoint can be tied to the object ID without "
            "substring or collection-only guessing."
        ).format(
            object_ref=first_object.get("object_ref", "-"),
            object_type=first_object.get("type", "-"),
            runner=first_backlog.get("runner", "idor-actor-pair"),
            missing=missing or "object endpoint",
            command=command,
        )
    return (
        "Case-state seed opportunity: Found object candidate {object_ref} "
        "type={object_type} endpoint={endpoint}. Runner: {runner}. "
        "Missing evidence: {missing}. Next: {command}. "
        "Review suggested add-actor/add-object/add-backlog commands; do not treat "
        "seed suggestions as validated findings."
    ).format(
        object_ref=first_object.get("object_ref", "-"),
        object_type=first_object.get("type", "-"),
        endpoint=endpoint or "-",
        runner=first_backlog.get("runner", "idor-actor-pair"),
        missing=missing or "review required",
        command=command,
    )


def _decide(state: dict, coverage_gaps: list[dict], actor_gaps: list[dict], case_state: dict | None = None) -> str:
    findings = _structured_findings(state)
    if findings.get("next_validation"):
        return "validate"
    top_case_state = _case_state_top_next(case_state or {})
    if str(top_case_state.get("next_action") or "").strip().lower() in {
        "run_validation_runner",
        "enrich_case_state",
        "create_validation_backlog",
    }:
        return "continue"
    if _unsafe_leads(state):
        return "checkpoint"
    if _actionable_coverage_gaps(coverage_gaps):
        return "continue"
    if actor_gaps:
        return "continue"
    if state.get("next_tool_hint"):
        return "enrich"
    stats = _surface_stats(state)
    if stats["review_pool"] or stats["p1"] or stats["p2"] or state.get("recommended_targets"):
        return "hunt"
    if findings.get("validated_pending_report"):
        return "report"
    if not state.get("has_recon"):
        return "refresh-recon"
    if _secondary_sweep_leads(state):
        return "continue"
    return "handoff"


def _lead_proposals(state: dict, context_pack: dict) -> list[str]:
    proposals: list[str] = []
    surface = state.get("surface") or {}
    for lead in _json_list(surface.get("workflow_leads"))[:3]:
        title = str(lead.get("title") or "").strip()
        next_action = str(lead.get("next_action") or "").strip()
        why = str(lead.get("rationale") or lead.get("category") or "workflow lead").strip()
        if title:
            proposals.append(
                "Evidence: Workflow lead: {title}. Why it matters: {why}. "
                "Next action: {next_action}. Stop condition: no reproducible "
                "behavior difference or new evidence after focused replay.".format(
                    title=title[:180],
                    why=why[:180],
                    next_action=next_action[:180] or "inspect the linked artifact",
                )
            )

    for item in (surface.get("p1") or [])[:2]:
        url = str(item.get("url") or "").strip()
        reasons = ", ".join(str(reason) for reason in (item.get("reasons") or [])[:2])
        suggested = str(item.get("suggested") or "").strip()
        if url:
            proposals.append(
                "Evidence: Surface review candidate {url} ({reasons}). Why it matters: "
                "interesting attack-surface evidence from cached recon/browser/source signals. "
                "Next action: {suggested}. Stop condition: no authz/data/state "
                "difference after minimal replay.".format(
                    url=url,
                    reasons=reasons or "ranked surface",
                    suggested=suggested or "run focused authz and workflow checks",
                )
            )

    if not proposals and state.get("has_recon"):
        for seed in (context_pack.get("hypothesis_seeds") or [])[:1]:
            proposals.append(
                f"Evidence: Context-pack hypothesis seed. Why it matters: {seed} "
                "Next action: collect the smallest surface artifact that can confirm "
                "or reject this hypothesis. Stop condition: no matching endpoint, "
                "role boundary, or workflow evidence appears."
            )
    return _dedupe(proposals)[:3]


def _active_contradictions(context_pack: dict) -> list[str]:
    return [
        str(item).strip()
        for item in (context_pack.get("contradictions") or [])
        if str(item).strip() and str(item).strip().lower() != "none detected."
    ]


def _canonicalize_url_path(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            parsed = urlparse(raw)
        except ValueError:
            return raw.split("?", 1)[0].split("#", 1)[0]
        return (parsed.path or "/").split("?", 1)[0].split("#", 1)[0]
    return raw.split("?", 1)[0].split("#", 1)[0]


def _normalise_endpoint_path(value: str) -> str:
    path = _canonicalize_url_path(value).strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    if path != "/":
        path = path.rstrip("/")
    return path


def _finalized_finding_surfaces(state: dict) -> tuple[set[str], set[str]]:
    """返回已经由 `/validate` 或报告流程收束的 URL/path。

    ranked-surface 仍然可以给 AI 提示线索，但不应该在同一个 finding
    已 validated/rejected/generated 后继续把它推成下一步。这里仅做状态过滤，
    未验证的 finding 仍保留给 AI 判断。
    """
    findings = _structured_findings(state)
    findings_dir = str(findings.get("findings_dir") or "").strip()
    if not findings_dir:
        return set(), set()
    path = Path(findings_dir) / "findings.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set(), set()

    exact_urls: set[str] = set()
    endpoint_paths: set[str] = set()
    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        validation_status = str(item.get("validation_status") or "").strip().lower()
        report_status = str(item.get("report_status") or "").strip().lower()
        if validation_status not in {"validated", "rejected"} and report_status != "generated":
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        exact_urls.add(url)
        normalised = _normalise_endpoint_path(url)
        # Hash-route findings normalise to "/"；不能因此隐藏整个 SPA 根路由。
        if normalised and normalised != "/":
            endpoint_paths.add(normalised)
    return exact_urls, endpoint_paths


PLACEHOLDER_OBJECT_SEGMENTS = {"nan", "undefined", "null", "none", "object", "[object object]"}


def _path_segments(value: str) -> list[str]:
    path = _canonicalize_url_path(value)
    return [segment for segment in path.split("/") if segment]


def _non_concrete_object_segments(value: str) -> list[str]:
    """Return high-confidence placeholder path segments that must not be replayed directly."""
    out: list[str] = []
    for segment in _path_segments(value):
        lowered = segment.strip().lower()
        if lowered in PLACEHOLDER_OBJECT_SEGMENTS:
            out.append(segment)
        elif lowered.startswith(":") or (lowered.startswith("{") and lowered.endswith("}")):
            out.append(segment)
        elif lowered.startswith("<") and lowered.endswith(">"):
            out.append(segment)
    return out


def _case_state_object_for_surface(url: str, case_state: dict | None) -> dict:
    """Find a concrete case_state object whose type appears in the surface path."""
    if not isinstance(case_state, dict):
        return {}
    samples = case_state.get("object_samples") if isinstance(case_state.get("object_samples"), list) else []
    segments = [segment.lower().replace("_", "-") for segment in _path_segments(url)]
    for obj in samples:
        if not isinstance(obj, dict):
            continue
        object_type = str(obj.get("type") or "").strip().lower().replace("_", "-")
        if not object_type:
            continue
        aliases = {object_type, f"{object_type}s"}
        if object_type == "basket":
            aliases.add("cart")
        if object_type == "cart":
            aliases.add("basket")
        if aliases.intersection(segments):
            return obj
    return {}


def _placeholder_object_replay_guidance(url: str, case_state: dict | None, target: str = "") -> str:
    placeholders = _non_concrete_object_segments(url)
    if not placeholders:
        return ""
    matched = _case_state_object_for_surface(url, case_state)
    placeholder_text = ", ".join(placeholders)
    if matched and matched.get("endpoint"):
        target_arg = _quote(target or "<target>")
        object_ref = str(matched.get("object_ref") or "")
        endpoint = str(matched.get("endpoint") or "")
        command = ""
        if object_ref:
            command = (
                f"`python3 tools/validation_runner.py idor-actor-pair --target {target_arg} "
                f"--from-case-state --object-ref {_quote(object_ref)} --repeat 2`"
            )
        return (
            f"observed URL contains non-concrete object value {placeholder_text}; "
            f"do not replay it directly. Substitute case_state object {object_ref or matched.get('type')} "
            f"endpoint {endpoint} and run {command or 'owner/peer replay on the concrete endpoint'}"
        )
    return (
        f"observed URL contains non-concrete object value {placeholder_text}; do not replay it directly. "
        "First capture a browser/MCP request with a real object ID or register a concrete "
        "case_state object, then replay the underlying API"
    )


def _placeholder_concrete_endpoint(url: str, case_state: dict | None) -> str:
    if not _non_concrete_object_segments(url):
        return ""
    matched = _case_state_object_for_surface(url, case_state)
    return str(matched.get("endpoint") or "").strip() if matched else ""


def _is_parent_endpoint(parent: str, child: str) -> bool:
    parent_path = _normalise_endpoint_path(parent)
    child_path = _normalise_endpoint_path(child)
    if not parent_path or not child_path or parent_path == "/" or parent_path == child_path:
        return False
    return child_path.startswith(parent_path + "/")


def _ranked_surface_entry(state: dict, url: str) -> dict:
    surface = state.get("surface") or {}
    for bucket in ("p1", "p2"):
        for item in (surface.get(bucket) or []):
            if isinstance(item, dict) and str(item.get("url") or "").strip() == str(url or "").strip():
                return item
    return {}


def _ranked_surface_query_keys(url: str) -> list[str]:
    return [key.lower() for key in re.findall(r"[?&]([^=&]+)=", str(url or ""))]


def _path_only_authz_gap_for_url(url: str, vuln_hint: str = "Authz") -> dict:
    endpoint = _canonicalize_url_path(url)
    query_keys = _ranked_surface_query_keys(url)
    rel = class_relevance(endpoint, "Authz", query_keys)
    return {
        "endpoint": endpoint,
        "vuln_class": vuln_hint,
        "weight": "",
        "relevance_score": rel.get("relevance_score", 0),
        "relevance_reason": rel.get("relevance_reason", ""),
        "observed_params": query_keys,
    }


def _ranked_surface_vuln_hint(entry: dict, url: str) -> str:
    scanner_types = [
        str(item.get("type") or "").strip()
        for item in (entry.get("scanner_findings") or [])
        if isinstance(item, dict) and str(item.get("type") or "").strip()
    ]
    if scanner_types:
        return scanner_types[0]

    source_types = [
        str(item.get("type") or "").strip()
        for item in (entry.get("source_intel_hypotheses") or [])
        if isinstance(item, dict) and str(item.get("type") or "").strip()
    ]
    if source_types:
        return source_types[0]

    endpoint = _canonicalize_url_path(url)
    query_keys = _ranked_surface_query_keys(url)
    candidates = ["Authz", "IDOR", "SQLi", "SSRF", "Race", "Upload", "GraphQL", "RCE"]
    scored = [
        (klass, class_relevance(endpoint, klass, query_keys))
        for klass in candidates
    ]
    scored.sort(key=lambda item: int(item[1].get("relevance_score", 0) or 0), reverse=True)
    best_class, best_rel = scored[0]
    if int(best_rel.get("relevance_score", 0) or 0) > 0:
        return best_class
    return "generic"


def _canonical_vuln_for_ledger(vuln_hint: str) -> str:
    value = str(vuln_hint or "").strip().lower().replace("_", "-")
    mapping = {
        "idor": "IDOR",
        "authz": "Authz",
        "auth": "Authz",
        "access-control": "Authz",
        "business-logic": "Authz",
        "sqli": "SQLi",
        "sql": "SQLi",
        "sql-injection": "SQLi",
        "ssrf": "SSRF",
        "race": "Race",
        "toctou": "Race",
        "graphql": "GraphQL",
        "upload": "Upload",
        "file-upload": "Upload",
        "openredirect": "OpenRedirect",
        "open-redirect": "OpenRedirect",
        "redirect": "OpenRedirect",
        "rce": "RCE",
        "ssti": "RCE",
        "command-injection": "RCE",
        "path": "Path",
        "lfi": "Path",
        "path-traversal": "Path",
        "xxe": "XXE",
    }
    return mapping.get(value, "Authz")


def _case_state_has_role_replay_context(case_state: dict | None) -> bool:
    return (
        _case_state_count(case_state, "actors") >= 2
        and _case_state_count(case_state, "sessions") >= 2
        and _case_state_count(case_state, "objects") >= 1
    )


def _ranked_surface_needs_role_context(vuln_class: str, baseline_first: bool) -> bool:
    if baseline_first:
        return False
    return vuln_class in {"IDOR", "Authz", "GraphQL", "CSRF"}


def _ranked_surface_role_replay_ready(vuln_class: str, baseline_first: bool, case_state: dict | None) -> bool:
    return (
        _ranked_surface_needs_role_context(vuln_class, baseline_first)
        and _case_state_has_role_replay_context(case_state)
    )


def _ranked_surface_browser_state_first(url: str, vuln_class: str, query_keys: list[str]) -> bool:
    """Return true for client-side page routes where raw GET replay is low-value.

    页面路由不能丢：`/orders`、`/order-summary` 这类入口经常是复杂链路的门。
    但直接对 SPA shell 做 owner/peer HTTP GET replay 通常只得到同一份 HTML。
    这里仅改变下一步执行方式：先抓浏览器态真实 XHR/对象 ID，再 replay 底层 API。
    """
    if vuln_class not in {"Authz", "IDOR"}:
        return False
    if query_keys:
        return False
    path = urlparse(str(url or "")).path.lower() or "/"
    api_prefixes = (
        "/api",
        "/rest",
        "/graphql",
        "/socket.io",
        "/oauth",
        "/.well-known",
    )
    if any(path == prefix or path.startswith(prefix + "/") for prefix in api_prefixes):
        return False
    # 静态资源/下载类路径保留普通 replay；无扩展或 .html 更像客户端路由。
    suffix = Path(path).suffix.lower()
    return suffix in {"", ".html", ".htm"}


def _ranked_surface_auth_workflow_first(url: str, js_methods: list[str]) -> bool:
    """Auth workflow actions need exact method/body before replay.

    Login/reset/token 类端点通常不是 GET 资源读面；没有浏览器/source 捕获到
    method、body、CSRF/CAPTCHA、会话语义前，默认 owner/peer GET 只会制造
    dead-end 噪声。这里不裁剪攻击面，只把下一步改为 exact-request capture。
    """
    path = urlparse(str(url or "")).path.lower()
    if not path:
        return False
    segments = [segment for segment in re.split(r"[/._-]+", path) if segment]
    action_terms = {
        "login",
        "logout",
        "signin",
        "signout",
        "register",
        "signup",
        "reset",
        "forgot",
        "password",
        "change",
        "token",
        "session",
        "authenticate",
        "authentication",
    }
    if not any(term in segments for term in action_terms):
        return False
    # 已有明确 GET/HEAD 观测时，按真实观测走；否则先捕获真实 workflow 请求。
    return not any(method in {"GET", "HEAD"} for method in js_methods)


def _ranked_surface_parameter_behavior_first(url: str, query_keys: list[str]) -> bool:
    """URL/redirect/fetch 参数应先做参数行为验证，而不是 role replay。"""
    path = urlparse(str(url or "")).path.lower()
    keys = {str(key or "").lower().replace("-", "_") for key in query_keys}
    redirect_keys = {
        "to",
        "url",
        "uri",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "return_url",
        "next",
        "continue",
        "callback",
        "target",
        "dest",
        "destination",
    }
    if keys & redirect_keys:
        return True
    return any(segment in {"redirect", "callback"} for segment in path.split("/") if segment)


def _matrix_endpoint_paths(matrix: dict) -> set[str]:
    """提取 coverage matrix 中的端点路径，供 checkpoint 做父子关系 hint。

    这里不是用 matrix 给端点下结论，只补足 ranked surface 窗口看不到的
    child endpoint。最终仍只生成 route-prefix triage 建议，由 AI/操作者
    根据 baseline/body/browser 证据决定是否 mark-endpoint-kind。
    """
    paths: set[str] = set()
    for item in matrix.get("endpoints") or []:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("endpoint") or "").strip()
        if not endpoint:
            continue
        path = _normalise_endpoint_path(endpoint).rstrip("/")
        if path:
            paths.add(path)
    return paths


def _ranked_surface_state_with_matrix_paths(state: dict, matrix: dict) -> dict:
    """给 ranked-surface 判读补充 matrix 端点全集，避免窗口截断误导。"""
    paths = _matrix_endpoint_paths(matrix)
    if not paths:
        return state
    enriched = dict(state)
    existing = enriched.get("_matrix_endpoint_paths")
    merged = set(existing) if isinstance(existing, (set, list, tuple)) else set()
    merged.update(paths)
    enriched["_matrix_endpoint_paths"] = merged
    return enriched


def _ranked_surface_route_prefix_first(state: dict, url: str, query_keys: list[str]) -> bool:
    """父级容器路径先做 handler/triage，不直接进入 role replay。"""
    if query_keys:
        return False
    path = _canonicalize_url_path(url).rstrip("/")
    if not path or path == "/":
        return False
    suffix = Path(path).suffix.lower()
    if suffix:
        return False
    child_paths: set[str] = set()
    surface = state.get("surface") if isinstance(state.get("surface"), dict) else {}
    for bucket in ("p1", "p2"):
        for item in surface.get(bucket) or []:
            if isinstance(item, dict):
                child_paths.add(_canonicalize_url_path(str(item.get("url") or "")).rstrip("/"))
    for item in state.get("recommended_targets") or []:
        if isinstance(item, dict):
            child_paths.add(_canonicalize_url_path(str(item.get("url") or "")).rstrip("/"))
    extra_paths = state.get("_matrix_endpoint_paths")
    if isinstance(extra_paths, (set, list, tuple)):
        child_paths.update(str(item or "").rstrip("/") for item in extra_paths if str(item or "").strip())
    return any(child and child != path and child.startswith(path + "/") for child in child_paths)


def _ranked_surface_context_prereq(state: dict, item: dict, case_state: dict | None = None) -> bool:
    url = str(item.get("url") or "").strip()
    if not url:
        return False
    entry = _ranked_surface_entry(state, url)
    vuln_hint = _ranked_surface_vuln_hint(entry, url)
    vuln_class = _canonical_vuln_for_ledger(vuln_hint)
    authz_gap = _path_only_authz_gap_for_url(url, vuln_hint)
    baseline_first = _is_path_only_authz_gap(authz_gap)
    return (
        _ranked_surface_needs_role_context(vuln_class, baseline_first)
        and not _case_state_has_role_replay_context(case_state)
    )


def _recent_anonymous_authz_clean_count(evidence_summary: dict) -> int:
    count = 0
    for entry in evidence_summary.get("recent_entries") or []:
        if not isinstance(entry, dict):
            continue
        result = str(entry.get("result") or "")
        vuln_class = _canonical_vuln_for_ledger(str(entry.get("vuln_class") or ""))
        actor = str(entry.get("actor") or "").strip().lower()
        object_scope = str(entry.get("object_scope") or "").strip().lower()
        if (
            result in {"tested_clean", "dead_end", "not_applicable"}
            and vuln_class == "Authz"
            and actor == "anonymous"
            and object_scope in {"none", ""}
        ):
            count += 1
    return count


def _case_state_acquisition_proposal(deferred_count: int, clean_count: int) -> str:
    return (
        "Case-state acquisition lead: {clean_count} recent anonymous Authz "
        "baseline(s) are already clean, and {deferred_count} ranked role/object "
        "surface(s) need runtime actor/session/object context before meaningful "
        "owner/peer replay. Next: capture a real browser session or create test-owned "
        "actors where authorized, then register actors/sessions/objects with "
        "tools/target_case_state.py; if no authorized session path exists, record "
        "no-auth-context and pivot to unauth/source-intel lanes instead of testing "
        "more identical 401 baselines."
    ).format(clean_count=clean_count, deferred_count=deferred_count)


def _ranked_surface_replay_draft(
    state: dict,
    item: dict,
    case_state: dict | None = None,
    *,
    target: str = "",
) -> str:
    url = str(item.get("url") or "").strip()
    if not url:
        return ""
    entry = _ranked_surface_entry(state, url)
    query_keys = _ranked_surface_query_keys(url)
    js_methods = [
        str(js.get("method") or "").upper()
        for js in (entry.get("js_intel_endpoints") or [])
        if isinstance(js, dict) and str(js.get("method") or "").strip()
    ]
    js_methods = list(dict.fromkeys([method for method in js_methods if method]))
    source_types = [
        str(src.get("type") or "").lower()
        for src in (entry.get("source_intel_hypotheses") or [])
        if isinstance(src, dict) and str(src.get("type") or "").strip()
    ]
    source_types = list(dict.fromkeys([value for value in source_types if value]))

    vuln_hint = _ranked_surface_vuln_hint(entry, url)
    evidence_text = " ".join([
        str(entry.get("suggested") or item.get("suggested") or ""),
        " ".join(query_keys),
        " ".join(source_types),
        "browser observed" if entry.get("browser_observed") else "",
        " ".join(js_methods),
    ])
    authz_gap = _path_only_authz_gap_for_url(url, vuln_hint)
    vuln_class = _canonical_vuln_for_ledger(vuln_hint)
    baseline_first = _is_path_only_authz_gap(authz_gap)
    browser_state_first = _ranked_surface_browser_state_first(url, vuln_class, query_keys)
    auth_workflow_first = _ranked_surface_auth_workflow_first(url, js_methods)
    parameter_behavior_first = _ranked_surface_parameter_behavior_first(url, query_keys)
    route_prefix_first = _ranked_surface_route_prefix_first(state, url, query_keys)
    placeholder_guidance = _placeholder_object_replay_guidance(url, case_state, target)
    role_replay_ready = (
        _ranked_surface_role_replay_ready(vuln_class, baseline_first, case_state)
        and not browser_state_first
        and not auth_workflow_first
        and not parameter_behavior_first
        and not route_prefix_first
        and not placeholder_guidance
    )
    if placeholder_guidance:
        validation_path = placeholder_guidance
    elif baseline_first:
        validation_path = _coverage_gap_validation_path(authz_gap)
    elif browser_state_first:
        validation_path = (
            "Use browser-state first for this page route: open it as owner and peer, "
            "capture/import MCP browser artifacts, extract the real XHR/object IDs, "
            "then run validation_runner authz-role-replay or idor-actor-pair on the "
            "underlying API instead of replaying the raw SPA HTML shell"
        )
    elif auth_workflow_first:
        validation_path = (
            "Capture the exact auth workflow request first: browser/source observed "
            "method, headers, body, CSRF/CAPTCHA/session state, and success/failure "
            "signal; then choose authn/business-logic/credential-lane or bounded "
            "marker replay. Do not run default GET role replay on this action endpoint"
        )
    elif parameter_behavior_first:
        validation_path = (
            "Run parameter-behavior validation first: anonymous baseline vs controlled "
            "variant for the observed URL/redirect parameter, compare status, Location "
            "header, body reflection, and target normalization; then choose open-redirect, "
            "SSRF, cache, or browser-boundary lane. Do not run owner/peer role replay "
            "until a real auth boundary appears"
        )
    elif route_prefix_first:
        validation_path = (
            "Treat this as a possible route-prefix/container path: run one anonymous "
            "handler baseline, compare it to concrete child endpoints, and if it is "
            "only a prefix or 404/500 container, mark endpoint_kind=route_prefix and "
            "focus replay on concrete child handlers. Do not run owner/peer role replay "
            "against the parent prefix"
        )
    elif role_replay_ready:
        target_arg = _quote(target or "<target>")
        url_arg = _quote(url)
        validation_path = (
            "Run authenticated role replay from case_state: "
            f"`python3 tools/validation_runner.py authz-role-replay --target {target_arg} "
            f"--url {url_arg} --from-case-state --repeat 2`; compare anonymous/owner/peer "
            "status, JSON shape, and body diff; only promote body-backed public exposure "
            "or role/object-specific authorization delta"
        )
    elif _ranked_surface_context_prereq(state, item, case_state):
        validation_path = (
            "First capture/register actor, session, and object context in "
            "tools/target_case_state.py; until owner/peer context exists, only run "
            "anonymous or exact browser baseline classification and do not claim "
            "two-actor replay evidence"
        )
    else:
        validation_path = first_missing_action(evaluate_candidate_evidence({
            "type": vuln_hint,
            "url": url,
            "summary": evidence_text,
        }))

    parts: list[str] = []
    if entry.get("browser_observed"):
        parts.append("capture the exact browser-observed request/response baseline first")
    if js_methods:
        parts.append("prefer " + "/".join(js_methods[:2]) + " replay")
    if query_keys:
        parts.append("reuse observed parameters: " + ", ".join(query_keys[:4]))
    if source_types:
        parts.append("follow source hints: " + ", ".join(source_types[:3]))
    if vuln_hint and vuln_hint != "generic":
        parts.append(f"focus {vuln_hint} evidence")
    if role_replay_ready:
        parts.append("use registered case_state owner/peer sessions")
    if browser_state_first:
        parts.append("browser-state-first page route; avoid treating identical SPA HTML as clean")
    if auth_workflow_first:
        parts.append("auth-workflow endpoint; exact method/body required before replay")
    if parameter_behavior_first:
        parts.append("parameter-behavior-first redirect/url input; avoid role replay")
    if route_prefix_first:
        parts.append("route-prefix-first parent path; validate concrete child handlers")
    if placeholder_guidance:
        parts.append("placeholder object path; require concrete object ID before replay")
    if validation_path:
        parts.append(validation_path)
    return "; ".join(parts)


def _ranked_surface_ledger_skeleton(
    state: dict,
    item: dict,
    target: str,
    replay_draft: str,
    case_state: dict | None = None,
) -> str:
    """Build a copyable ledger record command for the suggested ranked-surface replay.

    This is intentionally a skeleton, not an auto-write: the operator/agent should
    run it after the replay and adjust `--result` / `--evidence-ref` to the actual
    evidence captured.
    """
    url = str(item.get("url") or "").strip()
    if not url:
        return ""
    entry = _ranked_surface_entry(state, url)
    endpoint = _canonicalize_url_path(url)
    js_methods = [
        str(js.get("method") or "").upper()
        for js in (entry.get("js_intel_endpoints") or [])
        if isinstance(js, dict) and str(js.get("method") or "").strip()
    ]
    method = next((value for value in js_methods if value), "GET")
    vuln_hint = _ranked_surface_vuln_hint(entry, url)
    vuln_class = _canonical_vuln_for_ledger(vuln_hint)
    authz_gap = _path_only_authz_gap_for_url(url, vuln_hint)
    baseline_first = _is_path_only_authz_gap(authz_gap)
    context_prereq = _ranked_surface_context_prereq(state, item, case_state)
    query_keys = _ranked_surface_query_keys(url)
    browser_state_first = _ranked_surface_browser_state_first(url, vuln_class, query_keys)
    auth_workflow_first = _ranked_surface_auth_workflow_first(url, js_methods)
    parameter_behavior_first = _ranked_surface_parameter_behavior_first(url, query_keys)
    route_prefix_first = _ranked_surface_route_prefix_first(state, url, query_keys)
    if parameter_behavior_first:
        vuln_class = "OpenRedirect"
    placeholder_guidance = _placeholder_object_replay_guidance(url, case_state, target)
    placeholder_object = _case_state_object_for_surface(url, case_state) if placeholder_guidance else {}
    role_replay_ready = (
        _ranked_surface_role_replay_ready(vuln_class, baseline_first, case_state)
        and not browser_state_first
        and not auth_workflow_first
        and not parameter_behavior_first
        and not route_prefix_first
        and not placeholder_guidance
    )
    actor = (
        "anonymous"
        if baseline_first or context_prereq or auth_workflow_first or parameter_behavior_first or route_prefix_first
        else "owner"
    )
    object_scope = (
        "none"
        if baseline_first or context_prereq or auth_workflow_first or parameter_behavior_first or route_prefix_first
        else "unknown"
    )
    if placeholder_object.get("object_ref"):
        object_scope = str(placeholder_object.get("object_ref") or "unknown")
    if placeholder_object.get("endpoint"):
        endpoint = _normalise_endpoint_path(str(placeholder_object.get("endpoint") or ""))
    if placeholder_guidance:
        variant = "concrete_object_required" if not placeholder_object.get("endpoint") else "object_replay"
    elif baseline_first:
        variant = "unauth_baseline"
    elif context_prereq:
        variant = "context_prereq"
    elif browser_state_first:
        variant = "browser_observed"
    elif auth_workflow_first:
        variant = "exact_request_required"
    elif parameter_behavior_first:
        variant = "parameter_behavior"
    elif route_prefix_first:
        variant = "route_prefix_triage"
    elif role_replay_ready:
        variant = "role_diff"
    else:
        variant = "browser_observed" if entry.get("browser_observed") else "replay"
    evidence_ref = ""
    if entry.get("browser_observed"):
        evidence_ref = f"recon/{target_storage_key(canonical_target_value(target))}/browser/xhr_endpoints.txt"
    notes = (
        "Checkpoint ranked-surface replay skeleton; update result/evidence-ref "
        "after baseline/variant evidence is captured."
    )
    if context_prereq:
        notes = (
            "Checkpoint ranked-surface context prerequisite; register actor/session/object "
            "before owner/peer replay, or update this record after baseline classification."
        )
    elif placeholder_guidance:
        notes = (
            "Checkpoint ranked-surface placeholder object path; do not replay the observed "
            "placeholder URL directly. Replace it with a concrete case_state/browser object "
            "endpoint before recording final result."
        )
    elif browser_state_first:
        notes = (
            "Checkpoint ranked-surface browser-state-first page route; capture/import MCP "
            "browser artifacts, extract underlying XHR/object IDs, then replay the API."
        )
    elif auth_workflow_first:
        notes = (
            "Checkpoint ranked-surface auth workflow; capture exact observed method, "
            "headers, body, CSRF/CAPTCHA/session state, and success/failure signal before "
            "recording replay or role-diff evidence."
        )
    elif parameter_behavior_first:
        notes = (
            "Checkpoint ranked-surface URL/redirect parameter behavior; compare anonymous "
            "baseline and controlled variants for status, Location, reflection, and target "
            "normalization before choosing open-redirect/SSRF/browser-boundary follow-up."
        )
    elif route_prefix_first:
        notes = (
            "Checkpoint ranked-surface route prefix triage; run one anonymous handler "
            "baseline and, if this is only a parent/container path, mark endpoint_kind="
            "route_prefix and focus concrete child endpoints."
        )
    elif role_replay_ready:
        notes = (
            "Checkpoint ranked-surface authenticated role replay; run validation_runner "
            "authz-role-replay and update result/evidence-ref from the generated summary."
        )
    parts = [
        "python3 tools/evidence_ledger.py record",
        "--target", _quote(target),
        "--endpoint", _quote(endpoint),
        "--method", _quote(method),
        "--vuln-class", _quote(vuln_class),
        "--actor", _quote(actor),
        "--object-scope", _quote(object_scope),
        "--variant", _quote(variant),
        "--source", _quote("checkpoint-ranked-surface"),
        "--result", _quote("signal"),
        "--replayed",
    ]
    if entry.get("browser_observed"):
        parts.append("--browser-observed")
    if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        parts.extend(["--state-changing", "--redline-checked"])
    if evidence_ref:
        parts.extend(["--evidence-ref", _quote(evidence_ref)])
    parts.extend(["--notes", _quote(notes)])
    return " ".join(parts)


def _tested_finding_endpoints(matrix: dict) -> set[str]:
    endpoints: set[str] = set()
    for endpoint in matrix.get("endpoints") or []:
        if not isinstance(endpoint, dict):
            continue
        path = str(endpoint.get("endpoint") or "").strip()
        cells = endpoint.get("cells") or {}
        if not path or not isinstance(cells, dict):
            continue
        if any(
            isinstance(cell, dict) and str(cell.get("status") or "") == "tested_finding"
            for cell in cells.values()
        ):
            endpoints.add(path)
    return endpoints


def _ledger_covered_cells(evidence_summary: dict) -> set[tuple[str, str]]:
    """Return endpoint/vuln cells already closed by deterministic evidence.

    A validation runner can close a ranked-surface hypothesis as tested_clean
    without creating a structured finding or action-queue match. Checkpoint must
    still consume that ledger fact, otherwise it keeps asking Claude to rerun
    the same baseline.
    """
    covered: set[tuple[str, str]] = set()
    for cell in evidence_summary.get("closed_cells") or []:
        if not isinstance(cell, dict):
            continue
        endpoint = _normalise_endpoint_path(str(cell.get("endpoint") or ""))
        vuln_class = str(cell.get("vuln_class") or "").strip()
        if endpoint and vuln_class:
            covered.add((endpoint, vuln_class))
    for entry in evidence_summary.get("recent_entries") or []:
        if not isinstance(entry, dict):
            continue
        result = str(entry.get("result") or "")
        if result not in {"tested_clean", "tested_finding", "dead_end", "not_applicable"}:
            continue
        endpoint = _normalise_endpoint_path(str(entry.get("endpoint") or entry.get("raw_endpoint") or ""))
        vuln_class = str(entry.get("vuln_class") or "").strip()
        if endpoint and vuln_class:
            covered.add((endpoint, vuln_class))
    return covered


def _ledger_covers_cell(covered_cells: set[tuple[str, str]], endpoint: str, vuln_class: str) -> bool:
    endpoint_path = _normalise_endpoint_path(endpoint)
    canonical_class = _canonical_vuln_for_ledger(vuln_class)
    if not endpoint_path:
        return False
    if (endpoint_path, canonical_class) in covered_cells:
        return True
    # IDOR and generic Authz are the same authorization family for replay
    # de-duplication: a confirmed object replay should close a later generic
    # role-diff suggestion for the same concrete endpoint.
    if canonical_class in {"Authz", "IDOR"}:
        return any((endpoint_path, sibling) in covered_cells for sibling in ("Authz", "IDOR"))
    return False


def _ledger_candidate_proposals(evidence_summary: dict, *, limit: int = 3) -> list[str]:
    """把 Evidence Ledger 里的开放 candidate 变成 AI-facing 验证动作。

    这里不判断 candidate 是否“该报”，只防止 AI 手工验证出的复杂链路
    被 ledger 吃掉后从 checkpoint 视野里消失。最终升降级仍交给 Claude
    结合原始证据、7-Question Gate 和四个验证门判断。
    """
    proposals: list[str] = []
    for entry in (evidence_summary.get("open_candidates") or [])[:limit]:
        if not isinstance(entry, dict):
            continue
        endpoint = str(entry.get("endpoint") or entry.get("raw_endpoint") or "").strip()
        vuln_class = str(entry.get("vuln_class") or "").strip()
        method = str(entry.get("method") or "GET").strip().upper()
        evidence_ref = str(entry.get("evidence_ref") or "").strip()
        notes = str(entry.get("notes") or "").strip()
        if not endpoint or not vuln_class:
            continue
        evidence_suffix = f" Evidence={evidence_ref}." if evidence_ref else ""
        notes_suffix = f" Notes={notes[:220]}." if notes else ""
        proposals.append(
            "Run /validate for ledger candidate {method} {endpoint} x {vuln_class}. "
            "AI task: review raw evidence, impact, replayability, and side-effect/risk status; "
            "then promote to finding/report or downgrade with evidence ledger update."
            "{evidence}{notes} Stop condition: validated finding, tested_clean, "
            "dead_end, or blocked_redline is recorded.".format(
                method=method,
                endpoint=endpoint,
                vuln_class=vuln_class,
                evidence=evidence_suffix,
                notes=notes_suffix,
            )
        )
    return proposals


def _is_parent_closure_gap(gap: dict, tested_endpoints: set[str]) -> bool:
    """Return true when a path-only gap is only a parent of validated evidence.

    If `/rest/admin/application-configuration` is already validated, the parent
    `/rest/admin` may still be interesting as a route-enumeration clue, but it
    should not consume the immediate checkpoint queue as another Authz replay
    unless it has its own params/body/browser evidence.
    """
    endpoint = str(gap.get("endpoint") or "").strip()
    if not endpoint or not _is_path_only_authz_gap(gap):
        return False
    return any(_is_parent_endpoint(endpoint, tested) for tested in tested_endpoints)


def _checkpoint_coverage_gaps(coverage_gaps: list[dict], matrix: dict, limit: int = 2) -> list[dict]:
    """Select coverage gaps for the immediate checkpoint queue.

    Coverage itself keeps all untested cells.  The execution queue is stricter:
    it skips parent-only Authz closure gaps that are already represented by a
    validated child endpoint, preventing noisy loops while preserving other
    high-signal gaps for Claude to reason over.
    """
    tested_endpoints = _tested_finding_endpoints(matrix)
    selected: list[dict] = []
    for gap in _actionable_coverage_gaps(coverage_gaps):
        if _is_parent_closure_gap(gap, tested_endpoints):
            continue
        selected.append(gap)
        if len(selected) >= limit:
            break
    return selected


def _next_proposals(
    state: dict,
    coverage_gaps: list[dict],
    matrix: dict,
    target: str,
    context_pack: dict,
    evidence_summary: dict,
    case_state: dict | None = None,
) -> list[str]:
    proposals: list[str] = []
    # Contradictions are Claude-facing advisory context, not executable work.
    # Promoting them into the action queue makes the tool steer the hunt back to
    # meta-review whenever a fresh dead-end shares tokens with cached evidence.
    # Keep them visible in checkpoint output and let the model decide whether
    # they matter for the next hypothesis.

    findings = _structured_findings(state)
    next_validation = findings.get("next_validation") or {}
    next_report = findings.get("next_report") or {}
    if next_validation:
        rubric = next_validation.get("rubric") if isinstance(next_validation.get("rubric"), dict) else {}
        missing_items = []
        if rubric:
            missing_items = [
                str(item)
                for item in (rubric.get("missing_labels") or rubric.get("missing") or [])[:3]
                if str(item).strip()
            ]
        if rubric and (not rubric.get("ready", False) or missing_items):
            missing = ", ".join(missing_items)
            evidence_step = ""
            for action in rubric.get("next_actions") or []:
                evidence_step = str(action or "").strip()
                if evidence_step:
                    break
            proposals.append(
                "Candidate evidence gap for finding {id} on {url}: rubric={status}, "
                "missing={missing}. Next evidence step: {step}. Then rerun /validate "
                "when the smallest replayable impact proof is captured.".format(
                    id=next_validation.get("id", "-"),
                    url=next_validation.get("url", ""),
                    status=rubric.get("status", "needs-evidence"),
                    missing=missing or "candidate evidence",
                    step=evidence_step or "fill the missing candidate evidence item",
                )
            )
        proposals.append(
            "Run /validate for finding {id} on {url}; verify replay, A/B diff, "
            "impact, evidence rubric, and red-line safety before report.".format(
                id=next_validation.get("id", "-"),
                url=next_validation.get("url", ""),
            )
        )
    if next_report:
        proposals.append(
            "Draft report for validated finding {id}; do not submit without human review.".format(
                id=next_report.get("id", "-"),
            )
        )
    proposals.extend(_ledger_candidate_proposals(evidence_summary))
    if not state.get("has_recon"):
        proposals.append(f"Run /recon {target}, then /surface {target}, then rerun /checkpoint {target}.")

    next_tool_hint = str(state.get("next_tool_hint") or "").strip()
    if next_tool_hint:
        hint = (state.get("enrichment_hints") or [{}])[0] or {}
        proposals.append(
            f"Run enrichment {next_tool_hint}: {str(hint.get('reason') or '').strip()}"
        )

    proposals.extend(_unsafe_skipped_proposals(state))
    proposals.extend(_secondary_sweep_proposals(state))
    covered_findings = _tested_finding_endpoints(matrix)
    covered_ledger_cells = _ledger_covered_cells(evidence_summary)

    repo_source_summary = state.get("repo_source_summary") or {}
    secret_findings = int(repo_source_summary.get("secret_findings", 0) or 0)
    if secret_findings > 0:
        proposals.append(
            "Secret verification lane: repo/source artifacts contain {count} secret "
            "finding(s). Triage provider/type/source ownership, then run only the "
            "minimal safe identity/capability check or record a verification blocker; "
            "promote to Candidate only with validity/usability and impact path.".format(
                count=secret_findings,
            )
        )

    surface = state.get("surface") or {}
    for lead in _json_list(surface.get("workflow_leads"))[:5]:
        if str(lead.get("source") or "") != "evidence_convergence":
            continue
        title = str(lead.get("title") or "").strip()
        next_action = str(lead.get("next_action") or "").strip()
        evidence = str(lead.get("evidence") or lead.get("category") or "").strip()
        if title:
            proposals.append(
                "Cross-evidence high-value surface {title}: {evidence}. "
                "Next action: {next_action}. Stop condition: record tested, "
                "blocked, dead-end, signal, or candidate after focused replay.".format(
                    title=title,
                    evidence=evidence[:180],
                    next_action=next_action[:180] or "focused replay with source/JS/browser evidence",
                )
            )

    for gap in _checkpoint_coverage_gaps(coverage_gaps, matrix):
        relevance = ""
        if int(gap.get("relevance_score", 0) or 0) > 0:
            reason = str(gap.get("relevance_reason") or "").strip()
            relevance = ", relevance={score}{reason}".format(
                score=gap.get("relevance_score", 0),
                reason=f": {reason}" if reason else "",
            )
        validation_path = _coverage_gap_validation_path(gap)
        validation_suffix = f" Validation path: {validation_path}" if validation_path else ""
        proposals.append(
            "Cover high-value matrix gap: {endpoint} x {vuln_class} "
            "(weight={weight}{relevance}).{validation_suffix} If concrete side-effect risk appears, mark blocked "
            "and use low-risk evidence instead.".format(
                endpoint=gap.get("endpoint", ""),
                vuln_class=gap.get("vuln_class", ""),
                weight=gap.get("weight", ""),
                relevance=relevance,
                validation_suffix=validation_suffix,
            )
        )
    for gap in _actionable_actor_gaps(evidence_summary, case_state)[:3]:
        redline = " Run red-line check first." if gap.get("redline_required") else ""
        proposals.append(
            "Cover actor matrix gap: {endpoint} x {vuln} with {actor}/{scope}/{variant} "
            "expected={expected} status={status}.{redline} Record result with: {cmd}".format(
                endpoint=gap.get("endpoint", ""),
                vuln=gap.get("vuln_class", ""),
                actor=gap.get("actor", ""),
                scope=gap.get("object_scope", ""),
                variant=gap.get("variant", ""),
                expected=gap.get("expected", ""),
                status=gap.get("status", ""),
                redline=redline,
                cmd=evidence_record_command(target, gap),
            )
        )
    actor_enrichment = _actor_gap_enrichment_proposal(evidence_summary, case_state)
    if actor_enrichment:
        proposals.append(actor_enrichment)

    clean_authz_baselines = _recent_anonymous_authz_clean_count(evidence_summary)
    defer_role_ranked = (
        clean_authz_baselines >= 3
        and not _case_state_has_role_replay_context(case_state)
    )
    deferred_role_ranked = 0
    ranked_surface_added = 0
    ranked_state = _ranked_surface_state_with_matrix_paths(state, matrix)
    finalized_urls, finalized_paths = _finalized_finding_surfaces(state)
    for item in (ranked_state.get("recommended_targets") or []):
        # Generate a small candidate window, not just the first two. Persistent
        # action_queue final-state filtering happens after this function; if
        # the first P1 items were already closed, we still need fresh ranked
        # surfaces behind them so /autopilot does not hand off prematurely.
        if ranked_surface_added >= 4:
            break
        url = str(item.get("url") or "").strip()
        suggested = str(item.get("suggested") or "").strip()
        endpoint_path = _normalise_endpoint_path(url)
        if url in finalized_urls or (endpoint_path and endpoint_path != "/" and endpoint_path in finalized_paths):
            continue
        if endpoint_path in covered_findings:
            continue
        if url:
            entry = _ranked_surface_entry(ranked_state, item.get("url") or "")
            vuln_class = _canonical_vuln_for_ledger(_ranked_surface_vuln_hint(entry, url))
            concrete_endpoint = _placeholder_concrete_endpoint(url, case_state)
            concrete_endpoint_path = _normalise_endpoint_path(concrete_endpoint)
            if (
                _ledger_covers_cell(covered_ledger_cells, endpoint_path, vuln_class)
                or _ledger_covers_cell(covered_ledger_cells, concrete_endpoint_path, vuln_class)
            ):
                continue
            if defer_role_ranked and _ranked_surface_context_prereq(ranked_state, item, case_state):
                deferred_role_ranked += 1
                continue
            replay_draft = _ranked_surface_replay_draft(ranked_state, item, case_state, target=target)
            replay_suffix = f". Replay draft: {replay_draft.rstrip('.')}" if replay_draft else ""
            ledger_skeleton = _ranked_surface_ledger_skeleton(ranked_state, item, target, replay_draft, case_state)
            ledger_suffix = f". Ledger skeleton: {ledger_skeleton}" if ledger_skeleton else ""
            reason = str(item.get("review_reason") or "advisory surface evidence").strip()
            proposals.append(
                f"Review surface candidate {url}: {suggested}. "
                f"Reason: {reason}. AI decision required: choose the exact lane, "
                f"capture missing browser/source/actor evidence, or defer with evidence"
                f"{replay_suffix}{ledger_suffix}"
            )
            ranked_surface_added += 1
    if deferred_role_ranked:
        proposals.append(_case_state_acquisition_proposal(deferred_role_ranked, clean_authz_baselines))
    # Keep a slightly wider queue window. Secondary-sweep and coverage items can
    # be final-state filtered after queue construction; if we truncate too early
    # the next fresh ranked surface disappears and /autopilot hands off while
    # P1 surface remains.
    return _dedupe(proposals)[:8]


def _classify_next_action(text: str, target: str = "") -> tuple[str, int, str]:
    """把 checkpoint 的自然语言建议归类成 Claude 可消费的执行队列。"""
    value = str(text or "").strip()
    lowered = value.lower()
    replay_match = re.search(
        r"Exact replay draft:\s+(?P<cmd>.*?)(?:\.\s+(?:Required evidence|Missing evidence|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)",
        value,
        re.I,
    )
    replay_hint = replay_match.group("cmd").strip() if replay_match else ""
    if "case-state validation backlog" in lowered:
        return "case-state-validation", 110, replay_hint or "python3 tools/validation_runner.py ... --from-case-state"
    if "case-state enrichment backlog" in lowered:
        return "case-state-enrichment", 108, "enrich actor/session/object/private-marker evidence in case_state"
    if "case-state acquisition lead" in lowered:
        return "case-state-enrichment", 66, "capture/register actors, sessions, and owned objects with tools/target_case_state.py"
    if "case-state enrichment lead" in lowered:
        return "case-state-enrichment", 54, "register actor/session/object with tools/target_case_state.py or review tools/case_state_seed.py"
    if "case-state backlog creation" in lowered:
        return "case-state-backlog-create", 103, "promote the active hypothesis into validation backlog"
    if "case-state endpoint discovery lead" in lowered:
        return "case-state-enrichment", 66, "identify concrete object endpoint from browser/source evidence, then update case_state"
    if "case-state seed opportunity" in lowered:
        seed_match = re.search(r"Next:\s+(?P<cmd>python3\s+tools/case_state_seed\.py\s+.*?)(?:\.\s+Review|$)", value, re.I)
        return "case-state-seed", 99, seed_match.group("cmd").strip() if seed_match else "python3 tools/case_state_seed.py --target <target> --json"
    if "candidate evidence gap" in lowered:
        return "candidate-evidence-gap", 105, "fill missing rubric evidence, then /validate"
    if "run /validate" in lowered:
        return "validation", 100, "/validate"
    if "draft report" in lowered:
        return "report", 90, "/report"
    if "review context contradiction" in lowered:
        quoted_target = _quote(target) if target else "target.com"
        return "context-review", 90, f"python3 tools/context_pack.py --target {quoted_target}"
    if "run /recon" in lowered:
        quoted_target = _quote(target) if target else "target.com"
        return (
            "recon",
            85,
            "python3 tools/hunt.py --target {target} --recon-only && "
            "python3 tools/surface.py --target {target} && "
            "python3 tools/checkpoint.py --target {target}".format(target=quoted_target),
        )
    if "actor matrix gap" in lowered:
        return "actor-gap", 96, "focused replay + tools/evidence_ledger.py record"
    if "action-gated scanner lane" in lowered or "unsafe-skipped scanner lane" in lowered:
        return "action-gated-review", 93, "review legacy unsafe_skipped.txt; resolve queue with tested/blocked/dead-end/n/a/candidate"
    if "secondary-sweep lead" in lowered:
        if "[public-metadata]" in lowered:
            return "secondary-sweep", 52, "review public metadata only for unusual fields or chain pivots"
        return "secondary-sweep", 72, "review demoted raw artifact; re-promote only with concrete secret/chain evidence"
    if "high-value matrix gap" in lowered:
        return "coverage-gap", 94, "focused low-risk probe + evidence ledger"
    if "cross-evidence high-value surface" in lowered:
        return "evidence-convergence", 98, "focused replay with browser/JS/source evidence"
    if "secret verification lane" in lowered:
        return "secret-verification", 86, "python3 tools/secret_triage.py --file findings/<target>/exposure/repo_secrets.json"
    if "run enrichment run_browser_probe" in lowered:
        return "browser-enrichment", 70, "browser/playwright probe, then /surface"
    if "run enrichment run_source_intel" in lowered:
        return "source-enrichment", 70, "python3 tools/source_intel.py"
    if "run enrichment run_js_read" in lowered:
        return "js-enrichment", 70, "python3 tools/js_reader.py"
    if "review surface candidate" in lowered:
        return "surface-review", 70, "AI reviews surface evidence, then chooses the exact lane"
    if "continue top ranked surface" in lowered:
        return "ranked-surface", 70, "AI reviews ranked surface evidence, then chooses the exact lane"
    return "next-action", 50, "execute the smallest safe evidence-producing step"


def _extract_action_metadata(text: str) -> dict:
    """从 checkpoint 的动作文本中提取可机器消费的轻量字段。

    target_write_back 仍保持人类可读文本；action queue 额外保存这些字段，
    让后续执行/resolve 不必重新从自然语言猜 endpoint 和漏洞类型。
    """
    value = str(text or "").strip()
    metadata: dict = {}
    case_state_match = re.search(
        r"Case-state\s+(?:validation backlog|enrichment backlog|backlog creation)\s+(?P<backlog_id>[A-Za-z0-9_-]+)",
        value,
        re.I,
    )
    if case_state_match:
        metadata["backlog_id"] = case_state_match.group("backlog_id")
        for key, pattern in (
            ("runner", r"Runner:\s+(?P<value>[^.]+)"),
            ("object_ref", r"Object ref:\s+(?P<value>[^.]+)"),
            ("endpoint", r"Endpoint:\s+(?P<value>\S+)"),
            ("downgrade_rule", r"Downgrade rule:\s+(?P<value>.*?)(?:\.\s+(?:Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("stop_condition", r"Stop condition:\s+(?P<value>.*?)(?:\.\s+(?:Write-back|Chain extensions if blocked):|$)"),
            ("write_back", r"Write-back:\s+(?P<value>.*?)(?:\.\s+Chain extensions if blocked:|$)"),
            ("hypothesis", r"Hypothesis:\s+(?P<value>.*?)(?:\.\s+Why now:|$)"),
            ("why_now", r"Why now:\s+(?P<value>.*?)(?:\.\s+(?:Runner|Actors|Object ref|Endpoint|Exact replay draft):|$)"),
        ):
            match = re.search(pattern, value, re.I)
            if match:
                clean = match.group("value").strip()
                if key == "endpoint":
                    clean = clean.rstrip(".")
                metadata[key] = clean

        actors_match = re.search(
            r"Actors:\s+owner=(?P<owner>[^,]+),\s+peer=(?P<peer>[^.]+)",
            value,
            re.I,
        )
        if actors_match:
            metadata["owner_actor"] = actors_match.group("owner").strip()
            metadata["peer_actor"] = actors_match.group("peer").strip()

        for key, pattern in (
            ("replay_draft", r"Exact replay draft:\s+(?P<value>.*?)(?:\.\s+(?:Required evidence|Missing evidence|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("required_evidence", r"Required evidence:\s+(?P<value>.*?)(?:\.\s+(?:Missing evidence|Optional evidence gaps|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("missing_evidence", r"Missing evidence:\s+(?P<value>.*?)(?:\.\s+(?:Optional evidence gaps|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("optional_evidence_gaps", r"Optional evidence gaps:\s+(?P<value>.*?)(?:\.\s+(?:Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("chain_extensions_if_blocked", r"Chain extensions if blocked:\s+(?P<value>.*?)(?:\.$|$)"),
        ):
            match = re.search(pattern, value, re.I)
            if match:
                raw = match.group("value").strip()
                if key in {"required_evidence", "missing_evidence", "optional_evidence_gaps", "chain_extensions_if_blocked"}:
                    metadata[key] = [part.strip() for part in raw.split(",") if part.strip()]
                else:
                    metadata[key] = raw
        return metadata

    seed_match = re.search(
        r"Case-state seed opportunity:\s+Found object candidate\s+(?P<object_ref>\S+)\s+"
        r"type=(?P<object_type>\S+)\s+endpoint=(?P<endpoint>\S+)\.\s+"
        r"Runner:\s+(?P<runner>\S+)\.\s+Missing evidence:\s+(?P<missing>.*?)(?:\.\s+Next:|$)",
        value,
        re.I,
    )
    if seed_match:
        metadata.update({
            "object_ref": seed_match.group("object_ref"),
            "object_type": seed_match.group("object_type"),
            "endpoint": seed_match.group("endpoint"),
            "runner": seed_match.group("runner"),
            "missing_evidence": [
                part.strip()
                for part in seed_match.group("missing").split(",")
                if part.strip() and part.strip() != "review required"
            ],
        })
        command_match = re.search(r"Next:\s+(?P<cmd>python3\s+tools/case_state_seed\.py\s+.*?)(?:\.\s+Review|$)", value, re.I)
        if command_match:
            metadata["seed_command"] = command_match.group("cmd").strip()
        return metadata

    endpoint_seed_match = re.search(
        r"Case-state endpoint discovery lead:\s+Found object candidate\s+(?P<object_ref>\S+)\s+"
        r"type=(?P<object_type>\S+)\s+endpoint=(?P<endpoint>\S+)\.\s+"
        r"Runner:\s+(?P<runner>\S+)\.\s+Missing evidence:\s+(?P<missing>.*?)(?:\.\s+Next action:|$)",
        value,
        re.I,
    )
    if endpoint_seed_match:
        metadata.update({
            "object_ref": endpoint_seed_match.group("object_ref"),
            "object_type": endpoint_seed_match.group("object_type"),
            "endpoint": endpoint_seed_match.group("endpoint"),
            "runner": endpoint_seed_match.group("runner"),
            "missing_evidence": [
                part.strip()
                for part in endpoint_seed_match.group("missing").split(",")
                if part.strip() and part.strip() != "review required"
            ],
        })
        command_match = re.search(r"Seed command:\s+(?P<cmd>python3\s+tools/case_state_seed\.py\s+.*?)(?:\.\s+Stop condition:|$)", value, re.I)
        if command_match:
            metadata["seed_command"] = command_match.group("cmd").strip()
        return metadata

    enrichment_match = re.search(
        r"Case-state enrichment lead:.*?Example:\s+"
        r"(?P<endpoint>\S+)\s+x\s+(?P<vuln>[A-Za-z0-9_-]+)\s+with\s+"
        r"(?P<actor>[^/]+)/(?P<object_scope>[^/]+)/(?P<variant>\S+).*?"
        r"Missing evidence:\s+(?P<missing>.*?)(?:\.\s+Next:|$)",
        value,
        re.I,
    )
    if enrichment_match:
        metadata.update({
            "endpoint": enrichment_match.group("endpoint"),
            "vuln_class": enrichment_match.group("vuln"),
            "actor": enrichment_match.group("actor"),
            "object_scope": enrichment_match.group("object_scope"),
            "variant": enrichment_match.group("variant").rstrip("."),
            "missing_evidence": [
                part.strip()
                for part in enrichment_match.group("missing").split(",")
                if part.strip()
            ],
        })
        return metadata

    acquisition_match = re.search(
        r"Case-state acquisition lead:\s+(?P<clean>\d+)\s+recent anonymous Authz "
        r"baseline\(s\).*?and\s+(?P<deferred>\d+)\s+ranked role/object surface\(s\)",
        value,
        re.I,
    )
    if acquisition_match:
        metadata.update({
            "clean_authz_baselines": int(acquisition_match.group("clean")),
            "deferred_role_surfaces": int(acquisition_match.group("deferred")),
            "missing_evidence": ["actor", "session", "business object"],
        })
        return metadata

    validation_match = re.search(
        r"Validation path:\s+(?P<path>.*?)(?:\s+If red-line|\s+Stop condition:|$)",
        value,
        re.I,
    )

    match = re.search(
        r"Cover high-value matrix gap:\s+(?P<endpoint>\S+)\s+x\s+"
        r"(?P<vuln>[A-Za-z0-9_-]+)\s+\(weight=(?P<weight>[^,\)]+)"
        r"(?:,\s*relevance=(?P<score>\d+)(?::\s*(?P<reason>[^\)]+))?)?\)",
        value,
    )
    if match:
        metadata.update({
            "endpoint": match.group("endpoint"),
            "vuln_class": match.group("vuln"),
            "weight": match.group("weight"),
        })
        if match.group("score"):
            metadata["relevance_score"] = int(match.group("score"))
        if match.group("reason"):
            metadata["relevance_reason"] = match.group("reason").strip()
        if validation_match:
            metadata["validation_path"] = validation_match.group("path").strip()
        return metadata

    match = re.search(
        r"Cover actor matrix gap:\s+(?P<endpoint>\S+)\s+x\s+"
        r"(?P<vuln>[A-Za-z0-9_-]+)\s+with\s+"
        r"(?P<actor>[^/]+)/(?P<object_scope>[^/]+)/(?P<variant>\S+)",
        value,
    )
    if match:
        metadata.update({
            "endpoint": match.group("endpoint"),
            "vuln_class": match.group("vuln"),
            "actor": match.group("actor"),
            "object_scope": match.group("object_scope"),
            "variant": match.group("variant"),
        })

    match = re.search(
        r"Review (?:action-gated|unsafe-skipped) scanner lane\s+(?P<unsafe_id>[a-f0-9]{8,64}|-)"
        r".*?Artifact=(?P<artifact>\S*unsafe_skipped\.txt)",
        value,
        re.I,
    )
    if match:
        unsafe_id = match.group("unsafe_id")
        metadata.update({
            "unsafe_skipped_id": "" if unsafe_id == "-" else unsafe_id,
            "artifact": match.group("artifact"),
        })

    match = re.search(r"Draft report for validated finding\s+(?P<finding_id>[^;\s]+)", value, re.I)
    if match:
        metadata["finding_id"] = match.group("finding_id").strip().rstrip(".")

    match = re.search(
        r"Secondary-sweep lead\s+\[(?P<category>[^\]]+)\]:\s+(?P<title>.*?)[.]\s+Artifact=(?P<artifact>\S+)",
        value,
        re.I,
    )
    if match:
        metadata.update({
            "lead_category": match.group("category").strip(),
            "lead_title": match.group("title").strip(),
            "artifact": match.group("artifact").strip().rstrip("."),
        })

    match = re.match(
        r"(?:Continue top ranked surface|Review surface candidate)\s+(?P<url>\S+):\s*(?P<rest>.*)$",
        value,
        re.I,
    )
    if match:
        rest = match.group("rest").strip()
        ledger_skeleton = ""
        if "Ledger skeleton:" in rest:
            rest, ledger_skeleton = rest.split("Ledger skeleton:", 1)
        suggested = rest
        replay_draft = ""
        if "Replay draft:" in rest:
            suggested, replay_draft = rest.split("Replay draft:", 1)
        metadata.update({
            "url": match.group("url"),
            "endpoint": _canonicalize_url_path(match.group("url")),
            "suggested": suggested.strip().rstrip("."),
        })
        if replay_draft.strip():
            metadata["replay_draft"] = replay_draft.strip().rstrip(".")
        if ledger_skeleton.strip():
            metadata["ledger_record_skeleton"] = ledger_skeleton.strip()

    return metadata


def _build_next_action_queue(next_items: list[str], target: str = "") -> list[dict]:
    queue: list[dict] = []
    for idx, item in enumerate(next_items, 1):
        action_type, priority, command_hint = _classify_next_action(item, target)
        metadata = _extract_action_metadata(item)
        lowered = item.lower()
        redline_required = any(
            token in lowered
            for token in ("red-line", "state-changing", "mutation", "unsafe", "delete", "destructive")
        )
        row = {
            "id": f"A{idx}",
            "priority": priority,
            "type": action_type,
            "status": "ready",
            "action": item,
            "command_hint": command_hint,
            "redline_required": redline_required,
            "stop_condition": (
                "record tested, blocked, dead-end, candidate, or validated finding "
                "before moving to the next queued action"
            ),
        }
        if metadata:
            row["metadata"] = metadata
        queue.append(row)
    queue.sort(key=lambda item: (-int(item["priority"]), str(item["id"])))
    return queue


def _filter_final_action_queue_items(repo_root: Path, target: str, items: list[dict]) -> list[dict]:
    """Remove checkpoint actions already closed in persistent action_queue state."""
    try:
        existing = load_action_queue(repo_root, target)
    except Exception:  # pragma: no cover - checkpoint should stay best-effort
        return items

    def is_final_for_checkpoint(action: dict) -> bool:
        """Return whether a persisted action should suppress checkpoint work.

        validation_runner historically synced ``tested_finding`` to
        ``status=validated``. Under the current AI-first contract that only
        means runner evidence exists; `/validate` must still run the
        seven-question + four-gate report-readiness audit. Treat those legacy
        runner-only rows as non-final so they do not hide the real validate
        action.
        """
        status = str(action.get("status") or "")
        if status not in ACTION_QUEUE_FINAL_STATUSES:
            return False
        result = str(action.get("result") or "").strip()
        if status == "validated" and result.startswith("validation-runner-result="):
            return False
        return True

    def action_identities(action: dict) -> set[str]:
        """Return stable finding/endpoint identities for stale candidate suppression."""
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        identities: set[str] = set()
        finding_id = str(metadata.get("finding_id") or "").strip().lower()
        if finding_id:
            identities.add(f"finding:{finding_id}")
        for key in ("endpoint", "url"):
            value = str(metadata.get(key) or "").strip()
            if not value:
                continue
            endpoint = _normalise_endpoint_path(value).rstrip("/")
            if endpoint:
                identities.add(f"endpoint:{endpoint.lower()}")
        return identities

    def from_existing_action(action: dict) -> dict:
        """把持久队列里的候选动作投影回 checkpoint item。"""
        item = {
            "id": str(action.get("id") or ""),
            "priority": int(action.get("priority", 50) or 50),
            "type": str(action.get("type") or "next-action"),
            "status": str(action.get("status") or "queued"),
            "action": str(action.get("action") or action.get("evidence") or ""),
            "command_hint": str(action.get("command_hint") or ""),
            "redline_required": bool(action.get("redline_required", False)),
            "stop_condition": str(action.get("stop_condition") or ""),
        }
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        if metadata:
            item["metadata"] = metadata
        return item

    final_keys = {
        str(action.get("dedupe_key") or action_queue_dedupe_key(action))
        for action in existing.get("actions", [])
        if isinstance(action, dict)
        and is_final_for_checkpoint(action)
    }
    final_identities: set[str] = set()
    for action in existing.get("actions", []):
        if not isinstance(action, dict):
            continue
        if not is_final_for_checkpoint(action):
            continue
        final_identities.update(action_identities(action))

    active_candidate_by_key = {
        str(action.get("dedupe_key") or action_queue_dedupe_key(action)): from_existing_action(action)
        for action in existing.get("actions", [])
        if isinstance(action, dict)
        and str(action.get("status") or "") == "candidate"
        and str(action.get("type") or "") == "candidate-evidence-gap"
        and not (action_identities(action) & final_identities)
    }
    if not final_keys and not active_candidate_by_key:
        return items

    filtered: list[dict] = []
    emitted_candidate_keys: set[str] = set()
    for item in items:
        try:
            queue_shape = action_queue_checkpoint_item_to_action(target, item)
            key = str(queue_shape.get("dedupe_key") or action_queue_dedupe_key(queue_shape))
        except Exception:  # pragma: no cover - keep item if matching fails
            filtered.append(item)
            continue
        if key not in final_keys:
            if key in active_candidate_by_key:
                if key not in emitted_candidate_keys:
                    filtered.append(active_candidate_by_key[key])
                    emitted_candidate_keys.add(key)
                continue
            filtered.append(item)
    for key, candidate in active_candidate_by_key.items():
        if key not in emitted_candidate_keys:
            filtered.append(candidate)
    return filtered


def _select_default_candidate(target: str, items: list[dict]) -> dict:
    """用 action_queue 的真实选择规则挑 checkpoint 默认项。

    checkpoint 的 `next_action_queue` 是候选集；`recommended_executable_action`
    只是兼容字段。如果这里单纯取 priority 最高项，report 会因为分数高而压过
    已有 replay 草案的 surface-review，和 `/autopilot` 的“report 是阶段收束”
    规则冲突。这里复用 action_queue 的选择器，只把选中的 queue action 映射回
    原始 checkpoint item，避免两套排序语义漂移。
    """
    if not items:
        return {}
    try:
        converted: list[dict] = []
        by_key: dict[str, dict] = {}
        for item in items:
            queue_item = action_queue_checkpoint_item_to_action(target, item)
            key = str(queue_item.get("dedupe_key") or action_queue_dedupe_key(queue_item))
            converted.append(queue_item)
            by_key.setdefault(key, item)
        selected = action_queue_select_next_action({"actions": converted})
        if selected:
            selected_key = str(selected.get("dedupe_key") or action_queue_dedupe_key(selected))
            if selected_key in by_key:
                return by_key[selected_key]
    except Exception:
        # checkpoint 必须保持 best-effort；选择器异常时退回旧行为。
        pass
    return items[0]


def _align_decision_with_default_candidate(decision: str, default_candidate: dict) -> str:
    """Keep checkpoint's phase label consistent with the selected executable item.

    `_decide` uses broad state signals, while `_next_proposals` later filters
    stale/covered ranked surfaces through ledger and action-queue state. If that
    filtering leaves only a report candidate, the final checkpoint should say
    `report` instead of `hunt`; otherwise Claude sees contradictory steering.
    """
    if (
        decision in {"continue", "hunt", "enrich", "checkpoint"}
        and isinstance(default_candidate, dict)
        and str(default_candidate.get("type") or "") == "report"
    ):
        return "report"
    return decision


def _dead_end_proposals(state: dict, coverage_gaps: list[dict]) -> list[str]:
    if state.get("has_recon") and not coverage_gaps:
        stats = _surface_stats(state)
        if not stats["review_pool"] and not stats["p1"] and not stats["p2"] and not _unsafe_leads(state):
            return [
                "Evidence: cached surface has no review candidates and no high-value matrix gaps. "
                "Why it matters: broad cached recon is currently low-signal. "
                "Next action: only reopen after new recon, browser, source, or target-memory evidence. "
                "Stop condition: no new evidence source appears."
            ]
    return []


def _handoff_summary(
    *,
    target: str,
    decision: str,
    state: dict,
    coverage_summary: dict,
    evidence_summary: dict,
    next_action: str = "",
    note: str = "",
) -> str:
    stats = _surface_stats(state)
    findings = _structured_findings(state)
    actor_matrix = evidence_summary.get("actor_matrix") or {}
    parts = [
        f"Decision={decision}",
        f"next_action={next_action or state.get('next_action', '-')}",
        f"review_pool={stats['review_pool']}",
        f"advisory_first_review={stats['p1']}",
        f"advisory_follow_up={stats['p2']}",
        f"workflow_leads={stats['workflow_leads']}",
        f"coverage_gaps={coverage_summary.get('high_value_gaps_count', 0)}",
        f"actionable_coverage_gaps={coverage_summary.get('actionable_high_value_gaps_count', 0)}",
        f"actor_gaps={actor_matrix.get('gap_count', 0)}",
        f"runner_candidates={len(state.get('validation_runner_candidates') or [])}",
    ]
    if findings.get("pending_validation"):
        next_validation = findings.get("next_validation") or {}
        parts.append(f"pending_validation={next_validation.get('id', findings.get('pending_validation'))}")
    if findings.get("validated_pending_report"):
        next_report = findings.get("next_report") or {}
        parts.append(f"pending_report={next_report.get('id', findings.get('validated_pending_report'))}")
    if note:
        parts.append(f"operator_note={note.strip()[:180]}")
    return f"{target} checkpoint: " + "; ".join(parts)


def _target_memory_path(repo_root: Path, target: str) -> Path:
    return repo_root / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json"


def _empty_target_memory(target: str) -> dict:
    ts = now_utc()
    return {
        "schema_version": 1,
        "target": target,
        "created_at": ts,
        "updated_at": ts,
        "mode": "hunt",
        "phase": "unknown",
        "scope_notes": [],
        "active_leads": [],
        "dead_ends": [],
        "next_actions": [],
        "useful_patterns": [],
        "session_handoffs": [],
    }


def _append_unique_entries(memory: dict, field: str, entries: list[str]) -> int:
    existing = {
        str(item.get("text") or "").strip()
        for item in (memory.get(field) or [])
        if isinstance(item, dict)
    }
    added = 0
    for text in entries:
        clean = str(text or "").strip()
        if not clean or clean in existing:
            continue
        memory.setdefault(field, []).append({"ts": now_utc(), "text": clean})
        existing.add(clean)
        added += 1
    return added


def apply_target_memory(repo_root: Path | str, target: str, checkpoint: dict) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    path = _target_memory_path(repo, resolved_target)
    memory = _read_json(path) or _empty_target_memory(resolved_target)
    memory.setdefault("target", resolved_target)

    added = {
        "lead": _append_unique_entries(
            memory,
            "active_leads",
            checkpoint.get("target_write_back", {}).get("lead", [])[:3],
        ),
        "next": _append_unique_entries(
            memory,
            "next_actions",
            checkpoint.get("target_write_back", {}).get("next", [])[:5],
        ),
        "dead_end": _append_unique_entries(
            memory,
            "dead_ends",
            checkpoint.get("target_write_back", {}).get("dead_end", [])[:2],
        ),
    }

    handoff = str(checkpoint.get("target_write_back", {}).get("handoff") or "").strip()
    session_path = ""
    if handoff:
        sessions_dir = repo / "memory" / "goals" / "sessions"
        stamp = now_utc().replace(":", "").replace("-", "").replace("Z", "Z")
        session_file = sessions_dir / f"{stamp}-{target_storage_key(resolved_target)}.md"
        session_file.parent.mkdir(parents=True, exist_ok=True)
        session_file.write_text(
            "\n".join([
                f"# Target Handoff: {resolved_target}",
                "",
                f"- Time: {now_utc()}",
                f"- Decision: {checkpoint.get('decision', '-')}",
                "",
                "## Summary",
                handoff,
                "",
            ]),
            encoding="utf-8",
        )
        try:
            session_path = str(session_file.relative_to(repo))
        except ValueError:
            session_path = str(session_file)
        handoff_entry = {"ts": now_utc(), "path": session_path, "summary": handoff}
        existing_handoffs = memory.setdefault("session_handoffs", [])
        if not any(isinstance(item, dict) and item.get("summary") == handoff for item in existing_handoffs):
            existing_handoffs.append(handoff_entry)
            added["handoff"] = 1
        else:
            added["handoff"] = 0
    else:
        added["handoff"] = 0

    memory["updated_at"] = now_utc()
    _write_json(path, memory)
    return {
        "target_memory_path": str(path.relative_to(repo)) if path.is_relative_to(repo) else str(path),
        "session_path": session_path,
        "added": added,
    }


def build_checkpoint(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    note: str = "",
    memory_dir: str | None = None,
    refresh_coverage: bool = True,
) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    coverage_target = target_storage_key(resolved_target)
    state = build_autopilot_state(str(repo), resolved_target, memory_dir=memory_dir)
    context = build_context_pack(repo, target=resolved_target, memory_dir=memory_dir)

    matrix = rebuild_matrix(coverage_target, repo_root=repo)
    gaps = _matrix_gaps(matrix)
    if refresh_coverage:
        save_matrix(coverage_target, matrix, repo_root=repo)
    coverage_summary = _matrix_summary(matrix, gaps)
    evidence_summary = build_evidence_summary(
        repo,
        target=resolved_target,
        focus_endpoints=_evidence_focus_endpoints(state, gaps),
        vuln_classes=_evidence_vuln_classes(gaps, context),
    )
    case_state = _case_state_summary(repo, resolved_target)
    actor_gaps = _actor_gaps(evidence_summary)
    executable_actor_gaps = _actionable_actor_gaps(evidence_summary, case_state)
    case_state_proposal = _case_state_proposal(case_state)
    case_state_seed = _case_state_seed_summary(repo, resolved_target) if not case_state_proposal else {}
    case_state_seed_proposal = _case_state_seed_proposal(case_state_seed)

    decision = _decide(state, gaps, executable_actor_gaps, case_state)
    lead = _lead_proposals(state, context)
    next_items = _next_proposals(state, gaps, matrix, resolved_target, context, evidence_summary, case_state)
    if case_state_proposal:
        next_items = [case_state_proposal, *next_items]
    elif case_state_seed_proposal:
        next_items = [case_state_seed_proposal, *next_items]
    next_action_queue = _filter_final_action_queue_items(
        repo,
        resolved_target,
        _build_next_action_queue(next_items, resolved_target),
    )
    if decision in {"continue", "hunt", "enrich", "checkpoint"} and not next_action_queue:
        decision = "handoff"
    dead_ends = _dead_end_proposals(state, gaps)
    default_candidate = _select_default_candidate(resolved_target, next_action_queue)
    decision = _align_decision_with_default_candidate(decision, default_candidate)
    # Backward compatibility: older command docs and tests still consume the
    # historical field name. The new name makes the contract explicit: this is
    # only the default pointer from the candidate set, not a replacement for
    # Claude's final judgment.
    recommended_executable_action = default_candidate
    next_action_label = str(
        recommended_executable_action.get("type")
        or decision
        or ""
    )
    handoff = _handoff_summary(
        target=resolved_target,
        decision=decision,
        state=state,
        coverage_summary=coverage_summary,
        evidence_summary=evidence_summary,
        next_action=next_action_label,
        note=note,
    )

    return {
        "target": resolved_target,
        "decision": decision,
        "phase": context.get("phase", "unknown"),
        "next_action": next_action_label,
        "context_pack": {
            "selected_skill": context.get("selected_skill", ""),
            "knowledge_cards": context.get("knowledge_cards", []),
            "required_checks": context.get("required_checks", []),
            "contradictions": context.get("contradictions", []),
        },
        "evidence_reviewed": {
            "autopilot_state": True,
            "context_pack": True,
            "coverage_rebuilt": bool(refresh_coverage),
            "surface": bool(state.get("surface")),
        },
        "coverage": {
            "summary": coverage_summary,
            "high_value_gaps": gaps[:10],
        },
        "case_state": {
            "actors": case_state.get("actors", 0),
            "sessions": case_state.get("sessions", 0),
            "objects": case_state.get("objects", 0),
            "pending_validation_backlog": case_state.get("pending_validation_backlog", 0),
            "top_next_action": _case_state_top_next(case_state),
        },
        "case_state_seed": {
            "status": case_state_seed.get("status", ""),
            "suggested_objects": (case_state_seed.get("suggested_objects") or [])[:3],
            "suggested_backlog": (case_state_seed.get("suggested_backlog") or [])[:3],
        },
        "evidence_ledger": {
            "path": evidence_summary.get("path", ""),
            "entry_count": evidence_summary.get("entry_count", 0),
            "redline_unchecked_count": evidence_summary.get("redline_unchecked_count", 0),
            "open_candidates": (evidence_summary.get("open_candidates") or [])[:10],
            "actor_matrix": {
                "gap_count": (evidence_summary.get("actor_matrix") or {}).get("gap_count", 0),
                "covered_count": (evidence_summary.get("actor_matrix") or {}).get("covered_count", 0),
                "gaps": actor_gaps[:8],
            },
            "record_commands": (evidence_summary.get("record_commands") or [])[:5],
        },
        "surface": _surface_stats(state),
        "structured_findings": _structured_findings(state),
        "validation_runner_candidates": state.get("validation_runner_candidates") or [],
        "unsafe_skipped": _unsafe_leads(state),
        "target_write_back": {
            "lead": lead,
            "next": next_items,
            "dead_end": dead_ends,
            "handoff": handoff,
        },
        "next_action_queue": next_action_queue,
        "default_candidate": default_candidate,
        "recommended_executable_action": recommended_executable_action,
        "commands": _write_back_commands(resolved_target, lead, next_items, dead_ends, handoff),
        "retrospect": f"/retrospect {resolved_target}",
        "apply_status": "not applied; rerun with --apply-target-memory to write target memory",
    }


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _write_back_commands(
    target: str,
    leads: list[str],
    next_items: list[str],
    dead_ends: list[str],
    handoff: str,
) -> list[str]:
    commands: list[str] = []
    quoted_target = _quote(target)
    for item in leads[:3]:
        commands.append(f"python3 tools/target_memory.py lead {_quote(item)} --target {quoted_target}")
    for item in next_items[:5]:
        commands.append(f"python3 tools/target_memory.py next {_quote(item)} --target {quoted_target}")
    for item in dead_ends[:2]:
        commands.append(f"python3 tools/target_memory.py dead-end {_quote(item)} --target {quoted_target}")
    if handoff:
        commands.append(f"python3 tools/target_memory.py handoff {_quote(handoff)} --target {quoted_target}")
    return commands


def _fmt_list(items: list[str]) -> list[str]:
    if not items:
        return ["  - none"]
    return [f"  - {item}" for item in items]


def _fmt_nested(items: list[str]) -> list[str]:
    if not items:
        return ["    - none"]
    return [f"    - {item}" for item in items]


def _fmt_action_queue(items: list[dict]) -> list[str]:
    if not items:
        return ["  - none"]
    lines: list[str] = []
    for item in items[:5]:
        redline = " red-line-first" if item.get("redline_required") else ""
        lines.append(
            "  - {id} [{type} p{priority}{redline}] {action} | hint: {hint}".format(
                id=item.get("id", ""),
                type=item.get("type", ""),
                priority=item.get("priority", ""),
                redline=redline,
                action=item.get("action", ""),
                hint=item.get("command_hint", ""),
            )
        )
    return lines


def format_checkpoint(checkpoint: dict) -> str:
    coverage = checkpoint.get("coverage") or {}
    summary = coverage.get("summary") or {}
    write_back = checkpoint.get("target_write_back") or {}
    context = checkpoint.get("context_pack") or {}
    case_state = checkpoint.get("case_state") or {}
    case_state_next = case_state.get("top_next_action") or {}
    evidence = checkpoint.get("evidence_ledger") or {}
    actor_matrix = evidence.get("actor_matrix") or {}

    lines = [
        "CHECKPOINT DECISION",
        f"- Target: {checkpoint.get('target', '')}",
        f"- Phase: {checkpoint.get('phase', '')}",
        f"- Decision: {checkpoint.get('decision', '')}",
        f"- Next action: {checkpoint.get('next_action', '')}",
        f"- Selected skill: {context.get('selected_skill', '')}",
        "- Knowledge cards:",
        *_fmt_list([str(item) for item in context.get("knowledge_cards", [])]),
        "- Contradictions:",
        *_fmt_list([
            str(item) for item in context.get("contradictions", [])
            if str(item).strip() and str(item).strip().lower() != "none detected."
        ]),
        "- Coverage:",
        f"  - endpoints: {summary.get('endpoints', 0)}",
        f"  - high-value gaps: {summary.get('high_value_gaps_count', 0)}",
        f"  - actionable high-value gaps: {summary.get('actionable_high_value_gaps_count', 0)}",
        "- Case state:",
        f"  - actors: {case_state.get('actors', 0)}",
        f"  - sessions: {case_state.get('sessions', 0)}",
        f"  - objects: {case_state.get('objects', 0)}",
        f"  - pending backlog: {case_state.get('pending_validation_backlog', 0)}",
        "  - top next action:",
        *_fmt_nested([
            "{action} backlog={backlog} runner={runner} object={object_ref} owner={owner} peer={peer}".format(
                action=case_state_next.get("next_action", "none"),
                backlog=case_state_next.get("backlog_id", "-"),
                runner=case_state_next.get("runner", "-"),
                object_ref=case_state_next.get("object_ref", "-"),
                owner=case_state_next.get("owner_actor", "-"),
                peer=case_state_next.get("peer_actor", "-"),
            ) if case_state_next else "none"
        ]),
        "- Evidence ledger:",
        f"  - entries: {evidence.get('entry_count', 0)}",
        f"  - open candidates: {len(evidence.get('open_candidates') or [])}",
        f"  - actor matrix gaps: {actor_matrix.get('gap_count', 0)}",
        f"  - red-line unchecked: {evidence.get('redline_unchecked_count', 0)}",
        "  - candidate validation:",
        *_fmt_nested([
            "{method} {endpoint} x {vuln} evidence={evidence}".format(
                method=item.get("method", ""),
                endpoint=item.get("endpoint", ""),
                vuln=item.get("vuln_class", ""),
                evidence=item.get("evidence_ref", ""),
            )
            for item in (evidence.get("open_candidates") or [])[:3]
        ]),
        "  - actor gaps:",
        *_fmt_nested([
            "{endpoint} x {vuln}: {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=item.get("endpoint", ""),
                vuln=item.get("vuln_class", ""),
                actor=item.get("actor", ""),
                scope=item.get("object_scope", ""),
                variant=item.get("variant", ""),
                expected=item.get("expected", ""),
                status=item.get("status", ""),
            )
            for item in actor_matrix.get("gaps", [])[:5]
        ]),
        "  - record commands:",
        *_fmt_nested(evidence.get("record_commands", [])[:3]),
        "- Validation runner candidates (advisory; require /validate before report):",
        *_fmt_list(format_validation_runner_candidate_lines(
            checkpoint.get("validation_runner_candidates") or [],
            limit=5,
        )),
        "- Next action queue:",
        *_fmt_action_queue(checkpoint.get("next_action_queue", [])),
        "- Default candidate (compat pointer):",
        f"  - {((checkpoint.get('default_candidate') or checkpoint.get('recommended_executable_action') or {}).get('action') or 'none')}",
        "- Target write-back:",
        "  - lead:",
        *_fmt_nested(write_back.get("lead", [])),
        "  - next:",
        *_fmt_nested(write_back.get("next", [])),
        "  - dead-end:",
        *_fmt_nested(write_back.get("dead_end", [])),
        f"  - handoff: {write_back.get('handoff', '') or 'none'}",
        "- Commands:",
        *_fmt_list(checkpoint.get("commands", [])),
        f"- Retrospect: {checkpoint.get('retrospect', '')}",
        f"- Apply status: {checkpoint.get('apply_status', '')}",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an autopilot checkpoint write-back proposal.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--memory-dir", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--no-refresh-coverage", action="store_true")
    parser.add_argument("--apply-target-memory", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo_root)
    checkpoint = build_checkpoint(
        repo,
        target=args.target,
        note=args.note,
        memory_dir=args.memory_dir or None,
        refresh_coverage=not args.no_refresh_coverage,
    )
    if args.apply_target_memory:
        result = apply_target_memory(repo, checkpoint["target"], checkpoint)
        checkpoint["apply_status"] = "applied target memory"
        checkpoint["apply_result"] = result

    if args.json:
        print(json.dumps(checkpoint, ensure_ascii=False, indent=2))
    else:
        print(format_checkpoint(checkpoint))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
