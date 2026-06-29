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

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.autopilot_state import build_autopilot_state
    from tools.context_pack import build_context_pack
    from tools.coverage_matrix import high_value_gaps_from_matrix, rebuild_matrix, save_matrix
    from tools.evidence_ledger import build_summary as build_evidence_summary
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_state import build_autopilot_state  # type: ignore
    from context_pack import build_context_pack  # type: ignore
    from coverage_matrix import high_value_gaps_from_matrix, rebuild_matrix, save_matrix  # type: ignore
    from evidence_ledger import build_summary as build_evidence_summary  # type: ignore
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
    }


def _surface_stats(state: dict) -> dict:
    surface = state.get("surface") or {}
    stats = surface.get("stats") or {}
    return {
        "p1": int(stats.get("p1", 0) or 0),
        "p2": int(stats.get("p2", 0) or 0),
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
        if str(item.get("category") or "").lower() == "unsafe-skipped"
    ]


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


def _decide(state: dict, coverage_gaps: list[dict], actor_gaps: list[dict]) -> str:
    findings = _structured_findings(state)
    if findings.get("pending_validation"):
        return "validate"
    if findings.get("validated_pending_report"):
        return "report"
    if not state.get("has_recon"):
        return "refresh-recon"
    if _unsafe_leads(state):
        return "checkpoint"
    if coverage_gaps:
        return "continue"
    if actor_gaps:
        return "continue"
    if state.get("next_tool_hint"):
        return "enrich"
    stats = _surface_stats(state)
    if stats["p1"] or stats["p2"] or state.get("recommended_targets"):
        return "hunt"
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
                "Evidence: Ranked P1 surface {url} ({reasons}). Why it matters: "
                "high-value attack surface from cached recon/browser/source signals. "
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


def _next_proposals(
    state: dict,
    coverage_gaps: list[dict],
    target: str,
    context_pack: dict,
    evidence_summary: dict,
) -> list[str]:
    proposals: list[str] = []
    for contradiction in _active_contradictions(context_pack)[:2]:
        proposals.append(
            f"Review context contradiction before continuing: {contradiction}"
        )

    findings = _structured_findings(state)
    next_validation = findings.get("next_validation") or {}
    next_report = findings.get("next_report") or {}
    if next_validation:
        rubric = next_validation.get("rubric") if isinstance(next_validation.get("rubric"), dict) else {}
        if rubric and not rubric.get("ready", False):
            missing = ", ".join(str(item) for item in (rubric.get("missing_labels") or [])[:3])
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
    if not state.get("has_recon"):
        proposals.append(f"Run /recon {target}, then /surface {target}, then rerun /checkpoint {target}.")

    next_tool_hint = str(state.get("next_tool_hint") or "").strip()
    if next_tool_hint:
        hint = (state.get("enrichment_hints") or [{}])[0] or {}
        proposals.append(
            f"Run enrichment {next_tool_hint}: {str(hint.get('reason') or '').strip()}"
        )

    repo_source_summary = state.get("repo_source_summary") or {}
    secret_findings = int(repo_source_summary.get("secret_findings", 0) or 0)
    if secret_findings > 0:
        proposals.append(
            "Secret verification lane: repo/source artifacts contain {count} secret "
            "finding(s). Triage provider/type/source ownership, then run only the "
            "minimal safe identity/scope check or record a verification blocker; "
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

    for gap in coverage_gaps[:2]:
        relevance = ""
        if int(gap.get("relevance_score", 0) or 0) > 0:
            reason = str(gap.get("relevance_reason") or "").strip()
            relevance = ", relevance={score}{reason}".format(
                score=gap.get("relevance_score", 0),
                reason=f": {reason}" if reason else "",
            )
        proposals.append(
            "Cover high-value matrix gap: {endpoint} x {vuln_class} "
            "(weight={weight}{relevance}). If red-line risk appears, mark blocked and use "
            "low-risk evidence instead.".format(
                endpoint=gap.get("endpoint", ""),
                vuln_class=gap.get("vuln_class", ""),
                weight=gap.get("weight", ""),
                relevance=relevance,
            )
        )
    record_commands = evidence_summary.get("record_commands") or []
    for idx, gap in enumerate(_actor_gaps(evidence_summary)[:3]):
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
                cmd=record_commands[idx] if idx < len(record_commands) else "",
            )
        )

    for item in (state.get("recommended_targets") or [])[:2]:
        url = str(item.get("url") or "").strip()
        suggested = str(item.get("suggested") or "").strip()
        if url:
            proposals.append(f"Continue top ranked surface {url}: {suggested}")
    return _dedupe(proposals)[:5]


def _classify_next_action(text: str) -> tuple[str, int, str]:
    """把 checkpoint 的自然语言建议归类成 Claude 可消费的执行队列。"""
    value = str(text or "").strip()
    lowered = value.lower()
    if "candidate evidence gap" in lowered:
        return "candidate-evidence-gap", 105, "fill missing rubric evidence, then /validate"
    if "run /validate" in lowered:
        return "validation", 100, "/validate"
    if "draft report" in lowered:
        return "report", 95, "/report"
    if "review context contradiction" in lowered:
        return "context-review", 90, "/context-pack"
    if "run /recon" in lowered:
        return "recon", 85, "/recon"
    if "actor matrix gap" in lowered:
        return "actor-gap", 80, "focused replay + tools/evidence_ledger.py record"
    if "high-value matrix gap" in lowered:
        return "coverage-gap", 75, "focused low-risk probe + evidence ledger"
    if "cross-evidence high-value surface" in lowered:
        return "evidence-convergence", 82, "focused replay with browser/JS/source evidence"
    if "secret verification lane" in lowered:
        return "secret-verification", 86, "python3 tools/secret_triage.py --file findings/<target>/exposure/repo_secrets.json"
    if "run enrichment run_browser_probe" in lowered:
        return "browser-enrichment", 70, "browser/playwright probe, then /surface"
    if "run enrichment run_source_intel" in lowered:
        return "source-enrichment", 70, "python3 tools/source_intel.py"
    if "run enrichment run_js_read" in lowered:
        return "js-enrichment", 70, "python3 tools/js_reader.py"
    if "continue top ranked surface" in lowered:
        return "ranked-surface", 60, "focused hunt on ranked P1/P2 surface"
    return "next-action", 50, "execute the smallest safe evidence-producing step"


def _extract_action_metadata(text: str) -> dict:
    """从 checkpoint 的动作文本中提取可机器消费的轻量字段。

    target_write_back 仍保持人类可读文本；action queue 额外保存这些字段，
    让后续执行/resolve 不必重新从自然语言猜 endpoint 和漏洞类型。
    """
    value = str(text or "").strip()
    metadata: dict = {}

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

    return metadata


def _build_next_action_queue(next_items: list[str]) -> list[dict]:
    queue: list[dict] = []
    for idx, item in enumerate(next_items, 1):
        action_type, priority, command_hint = _classify_next_action(item)
        metadata = _extract_action_metadata(item)
        redline_required = any(
            token in item.lower()
            for token in ("red-line", "state", "mutation", "unsafe", "role", "actor")
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


def _dead_end_proposals(state: dict, coverage_gaps: list[dict]) -> list[str]:
    if state.get("has_recon") and not coverage_gaps:
        stats = _surface_stats(state)
        if not stats["p1"] and not stats["p2"] and not _unsafe_leads(state):
            return [
                "Evidence: cached surface has no P1/P2 and no high-value matrix gaps. "
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
    note: str = "",
) -> str:
    stats = _surface_stats(state)
    findings = _structured_findings(state)
    actor_matrix = evidence_summary.get("actor_matrix") or {}
    parts = [
        f"Decision={decision}",
        f"next_action={state.get('next_action', '-')}",
        f"P1={stats['p1']}",
        f"P2={stats['p2']}",
        f"workflow_leads={stats['workflow_leads']}",
        f"coverage_gaps={coverage_summary.get('high_value_gaps_count', 0)}",
        f"actor_gaps={actor_matrix.get('gap_count', 0)}",
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
    actor_gaps = _actor_gaps(evidence_summary)

    decision = _decide(state, gaps, actor_gaps)
    lead = _lead_proposals(state, context)
    next_items = _next_proposals(state, gaps, resolved_target, context, evidence_summary)
    next_action_queue = _build_next_action_queue(next_items)
    dead_ends = _dead_end_proposals(state, gaps)
    handoff = _handoff_summary(
        target=resolved_target,
        decision=decision,
        state=state,
        coverage_summary=coverage_summary,
        evidence_summary=evidence_summary,
        note=note,
    )

    return {
        "target": resolved_target,
        "decision": decision,
        "phase": context.get("phase", "unknown"),
        "next_action": state.get("next_action", ""),
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
        "evidence_ledger": {
            "path": evidence_summary.get("path", ""),
            "entry_count": evidence_summary.get("entry_count", 0),
            "redline_unchecked_count": evidence_summary.get("redline_unchecked_count", 0),
            "actor_matrix": {
                "gap_count": (evidence_summary.get("actor_matrix") or {}).get("gap_count", 0),
                "covered_count": (evidence_summary.get("actor_matrix") or {}).get("covered_count", 0),
                "gaps": actor_gaps[:8],
            },
            "record_commands": (evidence_summary.get("record_commands") or [])[:5],
        },
        "surface": _surface_stats(state),
        "structured_findings": _structured_findings(state),
        "unsafe_skipped": _unsafe_leads(state),
        "target_write_back": {
            "lead": lead,
            "next": next_items,
            "dead_end": dead_ends,
            "handoff": handoff,
        },
        "next_action_queue": next_action_queue,
        "recommended_executable_action": next_action_queue[0] if next_action_queue else {},
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
        "- Evidence ledger:",
        f"  - entries: {evidence.get('entry_count', 0)}",
        f"  - actor matrix gaps: {actor_matrix.get('gap_count', 0)}",
        f"  - red-line unchecked: {evidence.get('redline_unchecked_count', 0)}",
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
        "- Next action queue:",
        *_fmt_action_queue(checkpoint.get("next_action_queue", [])),
        "- Recommended executable action:",
        f"  - {((checkpoint.get('recommended_executable_action') or {}).get('action') or 'none')}",
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
