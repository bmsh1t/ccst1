#!/usr/bin/env python3
"""
resume.py — summarize prior hunt state for a target from hunt memory.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    # Support `import tools.resume`.
    from .legacy_bridge import open_hunt_journal
    from .repo_source_artifacts import load_repo_source_summary
    from .runtime_state import inspect_recon_artifacts, load_runtime_state
    from .structured_findings import (
        format_structured_findings_lines,
        summarize_structured_findings,
    )
except ImportError:
    # Keep legacy top-level `import resume` working.
    from legacy_bridge import open_hunt_journal
    from repo_source_artifacts import load_repo_source_summary
    from runtime_state import inspect_recon_artifacts, load_runtime_state
    from structured_findings import (
        format_structured_findings_lines,
        summarize_structured_findings,
    )
from memory.pattern_db import PatternDB
from memory.target_profile import default_memory_dir, load_target_profile
try:
    from tools.finding_index import load_finding_index
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from finding_index import load_finding_index
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target

_SESSION_SUMMARY_RE = re.compile(
    r"Endpoints tested:\s*(?P<endpoints_count>\d+)\.\s*"
    r"Vuln classes tried:\s*(?P<vuln_classes>.*?)\.\s*"
    r"Findings:\s*(?P<findings_count>\d+)\."
    r"(?:\s*Session:\s*(?P<session_id>[^.]+)\.)?"
)


def load_structured_finding_followup(base_dir: str | Path, target: str) -> dict:
    """Load validation/report follow-up state from findings.json."""
    findings_dir = Path(base_dir) / "findings" / target_storage_key(target)
    payload = load_finding_index(findings_dir)
    findings = [
        item for item in payload.get("findings", [])
        if isinstance(item, dict) and url_belongs_to_target(str(item.get("url") or ""), target)
    ]
    return summarize_structured_findings(findings, findings_dir)


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


def load_resume_summary(memory_dir: str | Path, target: str) -> dict | None:
    """Load the minimum data needed to resume a target hunt."""
    memory_dir = Path(memory_dir)
    requested_target = target
    canonical_target = canonical_target_value(target)
    profile = load_target_profile(memory_dir, canonical_target)
    if profile is None:
        return None

    profile_target = str(profile.get("target") or canonical_target or requested_target)
    journal = open_hunt_journal(memory_dir)
    entries = journal.query(target=profile_target)
    confirmed_entries = [entry for entry in entries if entry.get("result") == "confirmed"]
    confirmed_payout = round(sum(float(entry.get("payout", 0) or 0) for entry in confirmed_entries), 2)
    latest_session = latest_session_summary(entries)

    pattern_db = PatternDB(memory_dir / "patterns.jsonl")
    pattern_matches = []
    seen = set()
    for pattern in pattern_db.match(tech_stack=profile.get("tech_stack", [])):
        if pattern.get("target") == profile_target:
            continue
        key = (pattern.get("target", ""), pattern.get("technique", ""), pattern.get("vuln_class", ""))
        if key in seen:
            continue
        seen.add(key)
        pattern_matches.append({
            "target": pattern.get("target", ""),
            "technique": pattern.get("technique", ""),
            "vuln_class": pattern.get("vuln_class", ""),
            "payout": pattern.get("payout", 0),
        })

    findings = profile.get("findings", [])
    finding_titles = []
    for finding in findings[:3]:
        vuln = finding.get("vuln_class") or finding.get("type") or "finding"
        endpoint = finding.get("endpoint") or finding.get("url") or ""
        payout = finding.get("payout", 0)
        finding_titles.append({
            "vuln_class": vuln,
            "endpoint": endpoint,
            "payout": payout,
        })

    guard_advisories = recent_guard_advisories(entries)

    return {
        "target": requested_target,
        "resolved_target": profile_target,
        "sessions": int(profile.get("hunt_sessions", 0)),
        "last_hunted": profile.get("last_hunted", ""),
        "total_time_minutes": round(float(profile.get("total_time_minutes", 0) or 0), 2),
        "tech_stack": profile.get("tech_stack", []),
        "tested_endpoints": profile.get("tested_endpoints", []),
        "untested_endpoints": profile.get("untested_endpoints", []),
        "findings": findings,
        "finding_titles": finding_titles,
        "journal_entries": len(entries),
        "confirmed_findings": len(confirmed_entries),
        "confirmed_payout": confirmed_payout,
        "pattern_matches": pattern_matches[:5],
        "matched_targets": len({item["target"] for item in pattern_matches}),
        "latest_session_summary": latest_session,
        "recent_guard_advisories": guard_advisories,
        "recent_guard_blocks": guard_advisories,
        "repo_source_summary": load_repo_source_summary(BASE_DIR, profile_target),
        "runtime_state": load_runtime_state(BASE_DIR, profile_target),
        "recon_artifacts": inspect_recon_artifacts(BASE_DIR, profile_target),
        "structured_findings": load_structured_finding_followup(BASE_DIR, profile_target),
    }


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

    coverage = checkpoint.get("coverage") or {}
    coverage_summary = coverage.get("summary") or {}
    write_back = checkpoint.get("target_write_back") or {}
    return {
        "available": True,
        "decision": checkpoint.get("decision", ""),
        "next_action": checkpoint.get("next_action", ""),
        "selected_skill": (checkpoint.get("context_pack") or {}).get("selected_skill", ""),
        "knowledge_cards": (checkpoint.get("context_pack") or {}).get("knowledge_cards", []),
        "high_value_gaps_count": int(coverage_summary.get("high_value_gaps_count", 0) or 0),
        "lead_count": len(write_back.get("lead") or []),
        "next_count": len(write_back.get("next") or []),
        "dead_end_count": len(write_back.get("dead_end") or []),
        "handoff": str(write_back.get("handoff") or ""),
        "commands": checkpoint.get("commands", [])[:3],
    }


def load_pickup_summary(memory_dir: str | Path, target: str) -> dict | None:
    """Load resume summary plus a read-only checkpoint follow-up."""
    summary = load_resume_summary(memory_dir, target)
    if summary is None:
        return None

    resolved_target = summary.get("resolved_target") or target
    summary["checkpoint"] = load_checkpoint_followup(
        BASE_DIR,
        resolved_target,
        memory_dir=memory_dir,
    )
    return summary


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
        f"  Total time:  {format_minutes(summary['total_time_minutes'])}",
        f"  Journal:     {summary['journal_entries']} entries",
    ]

    if summary["confirmed_findings"]:
        lines.append(
            f"  Findings:    {summary['confirmed_findings']} confirmed (${summary['confirmed_payout']:.0f} total)"
        )
    else:
        lines.append("  Findings:    0 confirmed")

    if summary["finding_titles"]:
        lines.append("")
        lines.append("Recent Findings:")
        for item in summary["finding_titles"]:
            payout = f" (${item['payout']:.0f})" if item.get("payout") else ""
            endpoint = f" on {item['endpoint']}" if item.get("endpoint") else ""
            lines.append(f"  - {item['vuln_class']}{endpoint}{payout}")

    latest_session = summary.get("latest_session_summary")
    if latest_session:
        lines.append("")
        lines.append("Latest Session Snapshot:")
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
            selected_skill = str(checkpoint.get("selected_skill") or "").strip()
            if selected_skill:
                lines.append(f"  Selected skill: {selected_skill}")
            lines.append(f"  High-value gaps: {checkpoint.get('high_value_gaps_count', 0)}")
            lines.append(
                "  Target write-back proposals: "
                f"lead={checkpoint.get('lead_count', 0)}, "
                f"next={checkpoint.get('next_count', 0)}, "
                f"dead-end={checkpoint.get('dead_end_count', 0)}"
            )
            commands = checkpoint.get("commands") or []
            if commands:
                lines.append("  Suggested command:")
                lines.append(f"  {commands[0]}")
        else:
            lines.append(f"  unavailable: {checkpoint.get('error', 'unknown error')}")

    lines.append("")
    lines.append("Untested Surface:")
    untested = summary["untested_endpoints"]
    if untested:
        lines.append(f"  {len(untested)} endpoints from last recon:")
        for idx, endpoint in enumerate(untested[:5], 1):
            lines.append(f"  {idx}. {endpoint}")
    else:
        lines.append("  No cached untested endpoints. Consider re-running recon.")

    lines.append("")
    lines.append("Memory Suggestions:")
    if summary["tech_stack"]:
        lines.append(f"  Tech stack: [{', '.join(summary['tech_stack'])}]")
    if summary["pattern_matches"]:
        lines.append(f"  Matches {summary['matched_targets']} past targets:")
        for item in summary["pattern_matches"][:3]:
            payout = f" (${item['payout']:.0f})" if item.get("payout") else ""
            lines.append(
                f"  - {item['target']}: {item['technique']} [{item['vuln_class']}]{payout}"
            )
    else:
        lines.append("  No cross-target pattern matches yet.")

    lines.extend([
        "",
        "Actions:",
        "  [r] Continue hunting untested endpoints",
        "  [c] Run checkpoint write-back when ready",
        "  [n] Re-run recon first (surface may have changed)",
        "  [s] Show full hunt journal for this target",
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Resume a target hunt from hunt memory")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    memory_dir = args.memory_dir or str(default_memory_dir(BASE_DIR))
    summary = load_pickup_summary(memory_dir, args.target)

    if args.json:
        print(json.dumps({"summary": summary}, indent=2))
        return

    print(format_resume_output(summary, args.target))


if __name__ == "__main__":
    main()
