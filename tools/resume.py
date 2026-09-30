#!/usr/bin/env python3
"""
resume.py — summarize prior hunt state for a target from hunt memory.
"""

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from tools.resume_read import (
        latest_session_summary as latest_session_summary, load_resume_summary as _load_resume_summary,
        load_structured_finding_followup as load_structured_finding_followup, parse_session_summary_entry as parse_session_summary_entry,
        recent_guard_advisories,
    )
    from tools.structured_findings import format_structured_findings_lines
except ImportError:  # pragma: no cover - direct tools/ execution
    from resume_read import (
        latest_session_summary as latest_session_summary, load_resume_summary as _load_resume_summary,
        load_structured_finding_followup as load_structured_finding_followup, parse_session_summary_entry as parse_session_summary_entry,
        recent_guard_advisories,
    )
    from structured_findings import format_structured_findings_lines
from memory.target_profile import default_memory_dir
try:
    from tools.context_pack import format_source_queries
    from tools.target_memory import load_goal_memory, format_current_handoff
except ImportError:  # pragma: no cover - direct tools/ execution
    from context_pack import format_source_queries
    from target_memory import load_goal_memory, format_current_handoff


def format_minutes(total_minutes: int | float) -> str:
    minutes = int(round(float(total_minutes or 0)))
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins:02d}m"


# Compatibility alias for older callers and stored state naming.
recent_guard_blocks = recent_guard_advisories


def load_resume_summary(
    memory_dir: str | Path, target: str, *, repo_root: str | Path | None = None,
    fast_recon: bool = False, full_domain_context: bool = False,
) -> dict | None:
    return _load_resume_summary(
        memory_dir, target, repo_root=repo_root if repo_root is not None else BASE_DIR,
        fast_recon=fast_recon, full_domain_context=full_domain_context,
    )


def load_checkpoint_followup(base_dir: str | Path, target: str, memory_dir: str | Path | None = None) -> dict:
    """Load a read-only checkpoint summary for pickup output.

    The checkpoint call does not write coverage matrix or target memory;
    shared target queries live in resume_read and do not depend on this CLI.
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
            lines.extend(format_current_handoff(memory))
            lines.append("  Recent experience (bounded history; historical intents are not pending actions):")
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
