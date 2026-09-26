#!/usr/bin/env python3
"""
resume.py — summarize prior hunt state for a target from hunt memory.
"""

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    # Support `import tools.resume`.
    from .repo_source_artifacts import load_repo_source_summary
    from .runtime_state import (
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        load_runtime_state,
    )
    from .runtime_state import _derive_owner_projection
    from .structured_findings import (
        format_structured_findings_lines,
        compact_structured_finding,
    )
except ImportError:
    # Keep legacy top-level `import resume` working.
    from repo_source_artifacts import load_repo_source_summary
    from runtime_state import (
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        load_runtime_state,
    )
    from runtime_state import _derive_owner_projection
    from structured_findings import (
        format_structured_findings_lines,
        compact_structured_finding,
    )
from memory.hunt_journal import HuntJournal
from memory.target_profile import default_memory_dir
try:
    from tools.context_pack import format_source_queries
    from tools.target_store import runtime_store
    from tools.target_memory import load_goal_memory
    from tools.target_paths import (
        canonical_target_value,
        target_storage_key,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from context_pack import format_source_queries
    from target_store import runtime_store  # type: ignore
    from target_memory import load_goal_memory
    from target_paths import canonical_target_value, target_storage_key

_SESSION_SUMMARY_RE = re.compile(
    r"Endpoints tested:\s*(?P<endpoints_count>\d+)\.\s*"
    r"Vuln classes tried:\s*(?P<vuln_classes>.*?)\.\s*"
    r"Findings:\s*(?P<findings_count>\d+)\."
    r"(?:\s*Session:\s*(?P<session_id>[^.]+)\.)?"
)

def load_structured_finding_followup(
    base_dir: str | Path,
    target: str,
    *,
    migrate_legacy: bool = True,
) -> dict:
    """Project current Store findings for validation/report follow-up."""
    return _structured_finding_followup(runtime_store(base_dir, target).finding_summary(), base_dir, target)


def _structured_finding_followup(snapshot: dict, base_dir: str | Path, target: str) -> dict:
    """Summarize recorded posture; current truth owns evidence/delivery checks."""
    findings_dir = Path(base_dir) / "findings" / target_storage_key(target)
    counts = snapshot["counts"]
    summary = {key: counts[key] for key in (
        "total", "pending_validation", "validated_pending_report", "reported",
    )}
    summary.update(owner_revalidation_pending=0, draft_completion_pending=0, findings_dir=str(findings_dir))
    if counts["total"]:
        summary["evidence_gap_count"] = 0
    for key in ("next_validation", "next_report"):
        item = snapshot.get(key)
        if item is None:
            continue
        verdict = (item.get("assessment") or {}).get("verdict", "")
        summary[key] = compact_structured_finding({
            "id": item["id"], "type": item["family"], "severity": "medium", "confidence": verdict,
            "url": item["endpoint"],
            "validation_status": {"confirmed": "validated", "refuted": "rejected"}.get(verdict, "candidate"),
            "report_status": "generated" if item["report_recorded"] else "not_generated",
        }, findings_dir)
    return summary


def format_minutes(total_minutes: int | float) -> str:
    minutes = int(round(float(total_minutes or 0)))
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins:02d}m"


def _split_preview_list(raw: str) -> list[str]:
    value = str(raw or "").strip()
    if not value or value in {"none", "session"}:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_session_summary_entry(entry: dict) -> dict:
    """Parse the standardized auto session summary journal entry into structured fields."""
    notes = str(entry.get("notes", "") or "")
    endpoint_preview = _split_preview_list(str(entry.get("endpoint", "")))
    parsed = {
        "ts": entry.get("ts", ""),
        "action": entry.get("action", ""),
        "session_id": "",
        "findings_count": 0,
        "endpoints_count": len(endpoint_preview),
        "endpoints_preview": endpoint_preview[:3],
        "vuln_classes": [],
        "raw_notes": notes,
        # User-intent ledger: the operator's original instruction for the
        # session, preserved verbatim so a resumed run rebuilds intent.
        "user_intent": str(entry.get("user_intent") or ""),
    }

    match = _SESSION_SUMMARY_RE.search(notes)
    if not match:
        return parsed

    parsed["session_id"] = (match.group("session_id") or "").strip()
    parsed["findings_count"] = int(match.group("findings_count") or 0)
    parsed["endpoints_count"] = int(match.group("endpoints_count") or 0)

    vuln_classes_raw = (match.group("vuln_classes") or "").strip()
    if vuln_classes_raw and vuln_classes_raw != "none":
        parsed["vuln_classes"] = [
            item.strip()
            for item in vuln_classes_raw.split(",")
            if item.strip()
        ]

    return parsed


def latest_session_summary(entries: list[dict]) -> dict | None:
    """Return the most recent auto-logged session summary entry, if any."""
    session_entries = [
        entry for entry in entries
        if entry.get("vuln_class") == "session_summary"
    ]
    if not session_entries:
        return None
    return parse_session_summary_entry(session_entries[-1])


def recent_guard_advisories(entries: list[dict], *, limit: int = 3) -> list[dict]:
    """Return recent request-guard advisory notes, including legacy block notes."""
    advisories = []
    for entry in reversed(entries):
        if entry.get("vuln_class") not in {"guard_advisory", "guard_block"}:
            continue
        advisories.append({
            "ts": entry.get("ts", ""),
            "action": entry.get("action", ""),
            "endpoint": entry.get("endpoint", ""),
            "notes": str(entry.get("notes", "") or ""),
        })
        if len(advisories) >= limit:
            break
    return list(reversed(advisories))


# Compatibility alias for older callers and stored state naming.
recent_guard_blocks = recent_guard_advisories


def load_resume_summary(
    memory_dir: str | Path, target: str, *, repo_root: str | Path | None = None,
    fast_recon: bool = False, full_domain_context: bool = False,
) -> dict | None:
    return _load_resume_summary(memory_dir, target, repo_root=repo_root, fast_recon=fast_recon,
                                full_domain_context=full_domain_context)


def _load_resume_summary(
    memory_dir: str | Path, target: str, *, repo_root: str | Path | None = None,
    fast_recon: bool = False, full_domain_context: bool = False, coverage_state: dict | None = None,
) -> dict | None:
    """Load the minimum data needed to resume a target hunt."""
    memory_dir = Path(memory_dir)
    root = Path(repo_root) if repo_root is not None else Path(BASE_DIR)
    requested_target = target
    canonical_target = canonical_target_value(target)
    store = runtime_store(root, canonical_target)
    binding = store.binding()
    profile_target = canonical_target
    owner_projection = _derive_owner_projection(root, profile_target, finding_limit=None if full_domain_context else 5,
                                                 coverage_state=coverage_state)
    finding_summary = owner_projection.pop("finding_summary", None)
    if finding_summary is None:
        finding_summary = store.finding_summary()
    memory_view = load_goal_memory(root, profile_target, experience_limit=5)
    target_memory = memory_view["target"]
    memory_source = memory_view.get("source") or {}
    experience_window = memory_source.get("experience_window") or {}
    owner_key = target_storage_key(profile_target)
    canonical_sources = ["store"]
    if (root / "state" / owner_key / "session.json").is_file():
        canonical_sources.append("runtime")
    journal = HuntJournal(memory_dir / "journal.jsonl")
    entries = journal.query(target=profile_target)
    confirmed_findings = finding_summary["counts"]["confirmed"]
    confirmed_payout = None
    latest_session = latest_session_summary(entries)

    # 跨目标模式匹配已移除（2026-09-12 收敛裁定）：按 tech_stack 自动带入
    # 其他目标的历史现场经验，相关性难保证且易带入过期条件。本目标模式经
    # experience_recall 统一入口读取；跨项目复用唯一通道 = 人工审核晋升的
    # 知识卡（/distill -> promote）。
    pattern_matches: list[dict] = []

    expand_command = shlex.join([
        "python3", "tools/resume.py", "--repo-root", str(root.resolve()),
        "--target", profile_target, "--memory-dir", str(memory_dir.resolve()), "--json", "--full",
    ])
    domain_windows = {}
    domain_values = {}
    for field in ("findings", "tested_endpoints", "untested_endpoints"):
        values = owner_projection.get(field, [])
        preview = values if full_domain_context else values[:5]
        domain_values[field] = preview
        total = finding_summary["total"] if field == "findings" else len(values)
        domain_windows[field] = {
            "total": total, "returned": len(preview), "remaining": total - len(preview),
            "limit": None if full_domain_context else 5,
            "order": "id" if field == "findings" else "endpoint_asc",
            "expand_command": expand_command,
        }
    findings = domain_values["findings"]
    tested_endpoints = domain_values["tested_endpoints"]
    untested_endpoints = domain_values["untested_endpoints"]
    finding_titles = []
    for finding in findings[:5]:
        vuln = finding.get("vuln_class") or finding.get("type") or "finding"
        endpoint = finding.get("endpoint") or finding.get("url") or ""
        payout = finding.get("payout", 0)
        finding_titles.append({
            "vuln_class": vuln,
            "endpoint": endpoint,
            "payout": payout,
        })

    guard_advisories = recent_guard_advisories(entries)

    summary = {
        "target": requested_target,
        "resolved_target": profile_target,
        "target_memory_path": memory_view.get("target_path", "") if target_memory else "",
        "target_memory": {
            "source_kind": memory_source.get("kind", "legacy"),
            "active_goal": target_memory.get("active_goal", ""),
            "recent_entries": memory_view.get("recent_entries") or [],
            "experience_window": experience_window,
        } if target_memory else {},
        "sessions": sum(entry.get("vuln_class") == "session_summary" for entry in entries),
        "last_hunted": (latest_session or {}).get("ts", ""),
        "total_time_minutes": None,
        "tech_stack": [],
        "tested_endpoints": tested_endpoints,
        "untested_endpoints": untested_endpoints,
        "findings": findings,
        "finding_titles": finding_titles,
        "owner_projection": {key: value for key, value in owner_projection.items() if key not in domain_values},
        "domain_windows": domain_windows,
        "journal_entries": len(entries),
        "confirmed_findings": confirmed_findings,
        "confirmed_payout": confirmed_payout,
        "pattern_matches": pattern_matches[:5],
        "matched_targets": len({item["target"] for item in pattern_matches}),
        "latest_session_summary": latest_session,
        "recent_guard_advisories": guard_advisories,
        "recent_guard_blocks": guard_advisories,
        "repo_source_summary": load_repo_source_summary(root, profile_target),
        "runtime_state": load_runtime_state(root, profile_target),
        "recon_artifacts": (
            inspect_recon_artifacts_fast(root, profile_target)
            if fast_recon
            else inspect_recon_artifacts(root, profile_target)
        ),
        "structured_findings": _structured_finding_followup(finding_summary, root, profile_target),
        "canonical_sources": canonical_sources,
        "source_binding": binding,
    }
    if store.binding() != binding:
        raise ValueError("primary resume inputs changed during assembly")
    return summary


def load_checkpoint_followup(base_dir: str | Path, target: str, memory_dir: str | Path | None = None) -> dict:
    """Load a read-only checkpoint summary for pickup output.

    Import is local to avoid a module cycle: checkpoint -> autopilot_state ->
    resume. The checkpoint call is explicitly read-only for pickup, so it does
    not write coverage matrix or target memory.
    """
    try:
        from tools.checkpoint import build_checkpoint
    except ImportError:  # pragma: no cover - direct tools/ execution
        from checkpoint import build_checkpoint  # type: ignore

    try:
        checkpoint = build_checkpoint(
            Path(base_dir),
            target=target,
            memory_dir=str(memory_dir) if memory_dir else None,
            refresh_coverage=False,
        )
    except Exception as exc:  # pragma: no cover - defensive pickup path
        return {
            "available": False,
            "error": str(exc),
        }

    return _checkpoint_followup(checkpoint)


def _checkpoint_followup(checkpoint: dict) -> dict:
    coverage = checkpoint.get("coverage") or {}
    coverage_summary = coverage.get("summary") or {}
    write_back = checkpoint.get("target_write_back") or {}
    queue = checkpoint.get("next_action_queue") or []
    current_action = checkpoint.get("recommended_executable_action")
    if not isinstance(current_action, dict) or not current_action:
        current_action = checkpoint.get("default_candidate")
    if not isinstance(current_action, dict) or not current_action:
        current_action = (queue[0] if "action_queue_window" not in checkpoint
                          and queue and isinstance(queue[0], dict) else {})

    evidence = []
    for value in (
        current_action.get("evidence_ref"),
        current_action.get("evidence"),
        current_action.get("result"),
    ):
        text = str(value or "").strip()
        if text and text not in evidence:
            evidence.append(text[:300])
    context = checkpoint.get("context_pack") or {}
    for value in context.get("evidence_anchors") or []:
        text = str(value or "").strip()
        if text and text not in evidence:
            evidence.append(text[:300])
    ledger = checkpoint.get("evidence_ledger") or {}
    for item in ledger.get("open_candidates") or []:
        if not isinstance(item, dict):
            continue
        text = str(item.get("evidence_ref") or item.get("artifact") or "").strip()
        if text and text not in evidence:
            evidence.append(text[:300])

    decision = str(checkpoint.get("decision") or "").strip()
    status = str(current_action.get("status") or "").strip()
    redline_unchecked = ledger.get("redline_unchecked_count", 0)
    if not isinstance(redline_unchecked, (int, float)):
        redline_unchecked = 0
    if decision in {"wait_recon", "wait_scan"}:
        blocker = f"{decision}: an existing long-running phase owns the target"
    elif status == "blocked":
        blocker = str(current_action.get("result") or current_action.get("notes") or "blocked").strip()
    elif redline_unchecked > 0:
        blocker = "red-line evidence remains unchecked"
    else:
        blocker = ""

    control = {
        "current_action": {
            key: current_action.get(key, "")
            for key in ("id", "type", "status", "action", "command_hint", "evidence_ref")
        } if current_action else {},
        "recent_evidence": evidence[:6],
        "blocker": blocker,
        "next_action": str(checkpoint.get("next_action") or decision or "none"),
    }
    return {
        "available": True,
        "next_action_queue": queue,
        "decision": checkpoint.get("decision", ""),
        "next_action": checkpoint.get("next_action", ""),
        "knowledge_cards": (checkpoint.get("context_pack") or {}).get("knowledge_cards", []),
        "source_queries": context.get("source_queries", {}),
        "high_value_gaps_count": int(coverage_summary.get("high_value_gaps_count", 0) or 0),
        "lead_count": len(write_back.get("lead") or []),
        "next_count": len(write_back.get("next") or []),
        "dead_end_count": len(write_back.get("dead_end") or []),
        "handoff": str(write_back.get("handoff") or ""),
        **({"action_queue_window": checkpoint["action_queue_window"]}
           if "action_queue_window" in checkpoint else {}),
        **control,
    }


def load_pickup_summary(
    memory_dir: str | Path,
    target: str,
    *,
    repo_root: str | Path | None = None,
    full_domain_context: bool = False,
) -> dict | None:
    """Load resume summary plus a read-only checkpoint follow-up."""
    root = Path(repo_root) if repo_root is not None else Path(BASE_DIR)
    try:
        from tools.checkpoint import _build_checkpoint
    except ImportError:  # pragma: no cover - direct tools/ execution
        from checkpoint import _build_checkpoint
    try:
        checkpoint, summary = _build_checkpoint(
            root, target=target, memory_dir=str(memory_dir), refresh_coverage=False,
            full_domain_context=full_domain_context,
        )
    except Exception as exc:
        # Preserve pickup's independently available Resume when Checkpoint fails.
        summary = load_resume_summary(memory_dir, target, repo_root=root, full_domain_context=full_domain_context)
        if summary is None:
            return None
        summary["checkpoint"] = {"available": False, "error": str(exc)}
    else:
        summary["checkpoint"] = _checkpoint_followup(checkpoint)
    summary["target"] = target
    resolved_target = summary.get("resolved_target") or target
    summary["target_leads"] = _target_active_leads(root, resolved_target)
    return summary


def _target_active_leads(repo_root: Path, target: str) -> list:
    """Read active leads through the root- and target-bound memory owner."""
    return load_goal_memory(repo_root, target)["target"].get("active_leads", [])


def format_resume_output(summary: dict | None, target: str) -> str:
    """Format a resume summary for terminal display."""
    if summary is None:
        return (
            f"No previous hunt data for {target}.\n"
            f"Run /recon {target} first, then /hunt {target}."
        )

    lines = [
        f"PICKUP: {target}",
        "═══════════════════════════════════════",
        "",
        "Hunt History:",
        f"  Sessions:    {summary['sessions']}",
        f"  Last hunt:   {summary['last_hunted'] or 'unknown'}",
        f"  Total time:  {format_minutes(summary['total_time_minutes']) if summary['total_time_minutes'] is not None else 'not recorded'}",
        f"  Journal:     {summary['journal_entries']} entries",
    ]

    if summary["confirmed_findings"]:
        payout = summary.get("confirmed_payout")
        amount = f" (${payout:.0f} total)" if payout is not None else ""
        lines.append(f"  Findings:    {summary['confirmed_findings']} confirmed{amount}")
    else:
        lines.append("  Findings:    0 confirmed")

    if summary.get("target_memory_path"):
        lines.extend(["", f"Target Memory: {summary['target_memory_path']}"])
        memory = summary.get("target_memory") or {}
        if memory.get("source_kind") == "store":
            window = memory.get("experience_window") or {}
            entries = memory.get("recent_entries") or []
            lines.append(f"  Saved experiences: {window.get('total', 0)}")
            lines.append(f"  Showing: {len(entries)}; remaining: {window.get('remaining', 0)}")
            if memory.get("active_goal"):
                lines.append(f"  Goal: {memory['active_goal']}")
            for item in entries:
                lines.append(f"  - [{item.get('entry_id', '')}] ({item.get('kind', '')}) {item.get('text', '')}")
                structured = item.get("structured") or {}
                for key in ("conditions", "reopen_when", "next_intent"):
                    if structured.get(key):
                        lines.append(f"    {key}: {structured[key]}")
                if item.get("evidence_refs"):
                    lines.append(f"    evidence: {', '.join(item['evidence_refs'])}")
                lines.append(f"    recorded_by: {item.get('recorded_by', '')}")
            if window.get("has_more"):
                lines.append(f"  More: {window['remaining']}; {window['recall_command']} "
                             f"--cursor {shlex.quote(window['next_cursor'])}")
            if entries:
                lines.append(f"  Expand: {window['recall_command']} --id {shlex.quote(entries[0]['entry_id'])}")

    if summary["finding_titles"]:
        lines.append("")
        lines.append("Recent Findings:")
        for item in summary["finding_titles"]:
            payout = f" (${item['payout']:.0f})" if item.get("payout") else ""
            endpoint = f" on {item['endpoint']}" if item.get("endpoint") else ""
            lines.append(f"  - {item['vuln_class']}{endpoint}{payout}")
    domain_windows = summary.get("domain_windows") or {}
    finding_window = domain_windows.get("findings") or {}
    if finding_window:
        lines.append(f"  Finding preview: {len(summary['finding_titles'])} of {finding_window['total']}; "
                     f"remaining={finding_window['total'] - len(summary['finding_titles'])}")

    latest_session = summary.get("latest_session_summary")
    if latest_session:
        lines.append("")
        lines.append("Latest Session Snapshot:")
        user_intent = str(latest_session.get("user_intent") or "").strip()
        if user_intent:
            lines.append(f"  User Intent: {user_intent}")
        lines.append(f"  Time: {latest_session.get('ts') or 'unknown'}")
        if latest_session.get("session_id"):
            lines.append(f"  Session: {latest_session['session_id']}")
        tried = latest_session.get("vuln_classes", [])
        lines.append(
            f"  Tried: {', '.join(tried) if tried else 'none'}"
        )
        lines.append(
            f"  Findings in session: {int(latest_session.get('findings_count', 0) or 0)}"
        )
        preview = latest_session.get("endpoints_preview", [])
        if preview:
            lines.append(f"  Endpoint sample: {', '.join(preview)}")

    guard_advisories = summary.get("recent_guard_advisories") or summary.get("recent_guard_blocks", [])
    if guard_advisories:
        lines.append("")
        lines.append("Recent Guard Advisories:")
        for item in guard_advisories[:3]:
            details = item.get("notes", "") or item.get("endpoint", "")
            lines.append(f"  - {details}")

    repo_source_summary = summary.get("repo_source_summary") or {}
    repo_source_hint = str(repo_source_summary.get("summary_hint", "") or "").strip()
    if repo_source_hint:
        lines.append("")
        lines.append(f"Repo Source: {repo_source_hint}")

    runtime_state = summary.get("runtime_state") or {}
    recon_artifacts = summary.get("recon_artifacts") or {}
    runtime_workflow = str(
        runtime_state.get("last_executed_workflow")
        or runtime_state.get("current_stage")
        or ""
    ).strip()
    runtime_mode = str(runtime_state.get("mode", "") or "").strip()
    if runtime_workflow or recon_artifacts.get("available"):
        lines.append("")
        if runtime_workflow:
            lines.append(f"Last Workflow: {runtime_workflow}" + (f" (mode: {runtime_mode})" if runtime_mode else ""))
        if recon_artifacts.get("available"):
            counts = recon_artifacts.get("counts") or {}
            lines.append(
                "Recon Cache: "
                f"hosts={counts.get('hosts', 0)}, "
                f"surface={counts.get('api_urls', 0) + counts.get('param_urls', 0) + counts.get('js_endpoints', 0) + counts.get('browser_xhr_urls', 0) + counts.get('browser_api_urls', 0)}"
            )
            warnings = recon_artifacts.get("warnings") or []
            if warnings:
                lines.append(f"Recon Warning: {warnings[0]}")

    structured_findings = summary.get("structured_findings") or {}
    if structured_findings.get("total"):
        lines.append("")
        lines.extend(
            format_structured_findings_lines(
                structured_findings,
                header="Structured Findings:",
                indent="  ",
                next_validation_label="Next validate",
            )
        )
        next_validation = structured_findings.get("next_validation") or {}
        if next_validation:
            lines.append(
                "  Command: python3 tools/validate.py --findings-dir "
                f"{next_validation.get('findings_dir')} --finding-id {next_validation.get('id')}"
            )
        next_report = structured_findings.get("next_report") or {}
        if next_report:
            lines.append(f"  Command: python3 tools/report_generator.py {next_report.get('findings_dir')}")

    checkpoint = summary.get("checkpoint") or {}
    if checkpoint:
        lines.append("")
        lines.append("Checkpoint:")
        if checkpoint.get("available"):
            lines.append(f"  Decision: {checkpoint.get('decision') or '-'}")
            lines.append(f"  Next action: {checkpoint.get('next_action') or '-'}")
            current_action = checkpoint.get("current_action") or {}
            lines.append(
                "  Current action: "
                + (str(current_action.get("action") or current_action.get("type") or "none"))
            )
            evidence = checkpoint.get("recent_evidence") or []
            lines.append(f"  Recent evidence: {evidence[0] if evidence else 'none'}")
            lines.append(f"  Blocker: {checkpoint.get('blocker') or 'none'}")
            action_window = checkpoint.get("action_queue_window") or {}
            if action_window:
                lines.append(f"  Stored nonterminal actions: {action_window['total']}; "
                             f"remaining={action_window['remaining']}; AI chooses")
                lines.append(f"  Expand all stored actions: {action_window['expand_command']}")
            for candidate in checkpoint.get("next_action_queue") or []:
                lines.append(f"  - [{candidate.get('id', '')}] {candidate.get('status', '')}: "
                             f"{candidate.get('action', '')}")
            lines.append(f"  High-value gaps: {checkpoint.get('high_value_gaps_count', 0)}")
            lines.extend(format_source_queries(checkpoint.get("source_queries") or {}))
            lines.append(
                "  Target write-back proposals: "
                f"lead={checkpoint.get('lead_count', 0)}, "
                f"next={checkpoint.get('next_count', 0)}, "
                f"dead-end={checkpoint.get('dead_end_count', 0)}"
            )
        else:
            lines.append(f"  unavailable: {checkpoint.get('error', 'unknown error')}")

    tested_window = domain_windows.get("tested_endpoints") or {}
    if tested_window:
        tested_preview = summary["tested_endpoints"][:5]
        lines.extend(["", "Tested Surface:",
                      f"  {len(tested_preview)} of {tested_window['total']}; "
                      f"remaining={tested_window['total'] - len(tested_preview)}"])
        lines.extend(f"  - {endpoint}" for endpoint in tested_preview)

    lines.append("")
    lines.append("Untested Surface:")
    untested = summary["untested_endpoints"]
    untested_window = domain_windows.get("untested_endpoints") or {}
    if untested:
        total = untested_window.get("total", len(untested))
        lines.append(f"  {total} endpoints from current coverage; "
                     f"showing={min(5, len(untested))}; remaining={total - min(5, len(untested))}:")
        for idx, endpoint in enumerate(untested[:5], 1):
            lines.append(f"  {idx}. {endpoint}")
    else:
        lines.append("  No cached untested endpoints. Consider re-running recon.")
    if finding_window:
        lines.append(f"  Expand all Findings and endpoints: {finding_window['expand_command']}")

    lines.append("")
    lines.append("Memory Suggestions:")
    if summary["tech_stack"]:
        lines.append(f"  Tech stack: [{', '.join(summary['tech_stack'])}]")
    # 跨目标 pattern 建议已移除（收敛裁定）；本目标经验走 experience_recall。

    scene = _scene_summary(summary)
    if scene:
        lines.extend(["", "Scene (我上次在干嘛):", scene])

    lines.extend([
        "",
        "Actions:",
        "  [r] Continue hunting untested endpoints",
        "  [c] Read a fresh Checkpoint; save handoff through target memory",
        "  [n] Re-run recon first (surface may have changed)",
        "  [s] Show full hunt journal for this target",
    ])

    return "\n".join(lines)


def _scene_summary(summary: dict) -> str:
    """One human-readable paragraph from structured leads + checkpoint state."""
    checkpoint = summary.get("checkpoint") or {}
    parts: list[str] = []
    leads: list = []
    leads = summary.get("target_leads") or []
    structured_leads = [
        item
        for item in leads
        if isinstance(item, dict) and isinstance(item.get("structured"), dict)
    ]
    for lead in structured_leads[-2:]:
        s = lead["structured"]
        parts.append(
            "假设：{h}（证据 {e}）；下一步 {n}；停止条件 {s}".format(
                h=s.get("hypothesis") or "?",
                e=s.get("evidence_ref") or "?",
                n=s.get("next") or "?",
                s=s.get("stop_condition") or "?",
            )
        )
    if not parts:
        plain = leads
        if plain:
            text = plain[-1].get("text") if isinstance(plain[-1], dict) else str(plain[-1])
            if text:
                parts.append(f"最近 lead：{text}")
    decision = str(checkpoint.get("decision") or "").strip()
    if decision:
        parts.append(f"checkpoint 决策：{decision}")
    return "\n".join(f"  - {p}" for p in parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Resume a target hunt from hunt memory")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--repo-root", default="", help="Repository root for runtime artifacts")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    parser.add_argument("--full", action="store_true", help="Include complete Finding and endpoint collections in JSON")
    args = parser.parse_args()
    if args.full and not args.json:
        parser.error("--full requires --json")

    repo_root = Path(args.repo_root) if args.repo_root else Path(BASE_DIR)
    memory_dir = args.memory_dir or str(default_memory_dir(repo_root))
    try:
        summary = load_pickup_summary(memory_dir, args.target, repo_root=repo_root, full_domain_context=args.full)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"pickup state read failed: {exc}\n")

    if args.json:
        print(json.dumps({"summary": summary}, indent=2))
        return

    print(format_resume_output(summary, args.target))


if __name__ == "__main__":
    main()
