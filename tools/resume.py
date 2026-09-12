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
    from .repo_source_artifacts import load_repo_source_summary
    from .runtime_state import (
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        load_runtime_state,
    )
    from .runtime_state import derive_owner_projection
    from .structured_findings import (
        format_structured_findings_lines,
        summarize_structured_findings,
    )
except ImportError:
    # Keep legacy top-level `import resume` working.
    from repo_source_artifacts import load_repo_source_summary
    from runtime_state import (
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        load_runtime_state,
    )
    from runtime_state import derive_owner_projection
    from structured_findings import (
        format_structured_findings_lines,
        summarize_structured_findings,
    )
from memory.hunt_journal import HuntJournal
from memory.target_profile import default_memory_dir, load_target_profile
try:
    from tools.finding_index import load_finding_index
    from tools.target_paths import (
        canonical_target_value,
        compact_url,
        target_storage_key,
        url_belongs_to_target,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from finding_index import load_finding_index
    from target_paths import canonical_target_value, compact_url, target_storage_key, url_belongs_to_target

_SESSION_SUMMARY_RE = re.compile(
    r"Endpoints tested:\s*(?P<endpoints_count>\d+)\.\s*"
    r"Vuln classes tried:\s*(?P<vuln_classes>.*?)\.\s*"
    r"Findings:\s*(?P<findings_count>\d+)\."
    r"(?:\s*Session:\s*(?P<session_id>[^.]+)\.)?"
)

_CHAIN_CONTEXT_LIMIT = 8
_CHAIN_CONTEXT_ITEM_LIMIT = 8
_CHAIN_CONTEXT_ASSET_FIELDS = ("assets", "related_assets", "external_assets")
_CHAIN_CONTEXT_REFERENCE_FIELDS = (
    "related_evidence",
    "chain_extension_summary",
    "cross_source_links",
)
_CHAIN_CONTEXT_RELATION_FIELDS = ("chain_context",)
_CHAIN_CONTEXT_EVIDENCE_FIELDS = (
    "source_file",
    "evidence_ref",
    "evidence_refs",
    "source_ref",
    "source_refs",
    "poc_ref",
)


def _text_values(value: object) -> list[str]:
    """Return bounded-source strings without interpreting arbitrary finding prose."""
    values = value if isinstance(value, list) else [value]
    return [str(item).strip() for item in values if str(item or "").strip()]


def _external_chain_asset(value: str, target: str) -> str:
    """Return an inert external asset preview, or an empty string for target assets."""
    raw = str(value or "").strip()
    if not raw or raw.startswith(("./", "../")) or (
        raw.startswith("/") and not raw.startswith("//")
    ):
        return ""
    candidate = raw if ("://" in raw or raw.startswith("//")) else f"https://{raw}"
    try:
        if url_belongs_to_target(candidate, target):
            return ""
    except (OSError, ValueError):
        return ""
    return compact_url(raw, limit=240)


def _finding_chain_context(finding: dict, target: str) -> dict | None:
    """Project external dependencies without turning them into direct findings."""
    finding_id = str(finding.get("id") or "").strip()
    if not finding_id:
        return None

    external_assets: list[str] = []
    for field in _CHAIN_CONTEXT_ASSET_FIELDS:
        for value in _text_values(finding.get(field)):
            preview = _external_chain_asset(value, target)
            if preview and preview not in external_assets:
                external_assets.append(preview)

    explicit_refs: list[str] = []
    for field in _CHAIN_CONTEXT_REFERENCE_FIELDS:
        for value in _text_values(finding.get(field)):
            preview = compact_url(value, limit=240) if "://" in value or value.startswith("//") else value[:512]
            if preview and preview not in explicit_refs:
                explicit_refs.append(preview)

    chain_relations: list[str] = []
    for field in _CHAIN_CONTEXT_RELATION_FIELDS:
        for value in _text_values(finding.get(field)):
            preview = compact_url(value, limit=512)
            if preview and preview not in chain_relations:
                chain_relations.append(preview)

    if not external_assets and not explicit_refs and not chain_relations:
        return None

    scope_status = str(finding.get("scope_status") or "").strip()
    if not scope_status:
        scope_status = "external-chain-context" if external_assets else "evidence-context"
    evidence_refs: list[str] = []
    evidence_values = []
    for field in _CHAIN_CONTEXT_EVIDENCE_FIELDS:
        evidence_values.extend(_text_values(finding.get(field)))
    evidence_values.extend(explicit_refs)
    for value in evidence_values:
        preview = compact_url(value, limit=512) if "://" in value or value.startswith("//") else value[:512]
        if preview and preview not in evidence_refs:
            evidence_refs.append(preview)
    return {
        "finding_id": finding_id[:240],
        "finding_type": str(
            finding.get("type") or finding.get("vuln_class") or finding.get("category") or "finding"
        ).strip()[:128],
        "validation_status": str(finding.get("validation_status") or "unvalidated").strip()[:64],
        "report_status": str(finding.get("report_status") or "not_generated").strip()[:64],
        "external_assets": external_assets[:_CHAIN_CONTEXT_ITEM_LIMIT],
        "chain_context": chain_relations[:_CHAIN_CONTEXT_ITEM_LIMIT],
        "scope_status": scope_status[:64],
        "evidence_refs": evidence_refs[:_CHAIN_CONTEXT_ITEM_LIMIT],
        "active": False,
    }


def load_structured_finding_followup(
    base_dir: str | Path,
    target: str,
    *,
    migrate_legacy: bool = True,
) -> dict:
    """Load owner-verified validation/report follow-up state from findings.json.

    ``migrate_legacy=False`` is reserved for strictly read-only projections such
    as slash-command bootstrap.  Mutation owners can keep the historical
    default and perform the canonical legacy migration when appropriate.
    """
    findings_dir = Path(base_dir) / "findings" / target_storage_key(target)
    payload = load_finding_index(
        findings_dir,
        migrate_legacy=migrate_legacy,
        target=target,
        allow_legacy=True,
    )
    all_findings = [
        item for item in payload.get("findings", []) if isinstance(item, dict)
    ]
    findings = []
    for item in all_findings:
        url = str(item.get("url") or "").strip()
        if (
            (bool(url) and url_belongs_to_target(url, target))
            # An incomplete root claim may not know its endpoint yet.  It is
            # already scoped by the target-owned findings directory and must
            # remain recoverable instead of disappearing from bootstrap.
            or (
                not url
                and bool(item.get("claim_id") or item.get("claim_source_file"))
            )
        ):
            findings.append(item)

    chain_context = []
    for item in findings:
        context = _finding_chain_context(item, target)
        if context:
            chain_context.append(context)
        if len(chain_context) >= _CHAIN_CONTEXT_LIMIT:
            break

    summary = summarize_structured_findings(
        findings,
        findings_dir,
        target=target,
        enforce_owner_provenance=True,
    )
    if chain_context:
        summary["chain_context"] = chain_context
        summary["chain_context_count"] = len(chain_context)
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
    memory_dir: str | Path,
    target: str,
    *,
    repo_root: str | Path | None = None,
    fast_recon: bool = False,
) -> dict | None:
    """Load the minimum data needed to resume a target hunt."""
    memory_dir = Path(memory_dir)
    root = Path(repo_root) if repo_root is not None else Path(BASE_DIR)
    requested_target = target
    canonical_target = canonical_target_value(target)
    profile_error = ""
    try:
        profile = load_target_profile(memory_dir, canonical_target)
    except ValueError as exc:
        # Legacy target profiles are optional compatibility metadata. A
        # damaged profile must not hide canonical owner facts that can still
        # be resumed safely.
        profile = None
        profile_error = str(exc)

    profile = profile if isinstance(profile, dict) else {}

    profile_target = str(profile.get("target") or canonical_target or requested_target)
    owner_projection = derive_owner_projection(root, profile_target)
    owner_key = target_storage_key(profile_target)
    canonical_owner_paths = {
        "queue": root / "state" / owner_key / "action_queue.json",
        "runtime": root / "state" / owner_key / "session.json",
        "case": root / "state" / owner_key / "case_state.json",
    }
    canonical_sources = [
        name for name, path in canonical_owner_paths.items() if path.is_file()
    ]
    journal = HuntJournal(memory_dir / "journal.jsonl")
    entries = journal.query(target=profile_target)
    if not profile and not owner_projection.get("available") and not canonical_sources and not entries:
        return None
    confirmed_entries = [entry for entry in entries if entry.get("result") == "confirmed"]
    confirmed_payout = round(sum(float(entry.get("payout", 0) or 0) for entry in confirmed_entries), 2)
    latest_session = latest_session_summary(entries)

    # 跨目标模式匹配已移除（2026-09-12 收敛裁定）：按 tech_stack 自动带入
    # 其他目标的历史现场经验，相关性难保证且易带入过期条件。本目标模式经
    # experience_recall 统一入口读取；跨项目复用唯一通道 = 人工审核晋升的
    # 知识卡（/distill -> promote）。
    pattern_matches: list[dict] = []

    findings = (
        owner_projection.get("findings", [])
        if owner_projection.get("findings_authoritative")
        else profile.get("findings", [])
    )
    tested_endpoints = (
        owner_projection.get("tested_endpoints", [])
        if owner_projection.get("tested_authoritative")
        else profile.get("tested_endpoints", [])
    )
    untested_endpoints = (
        owner_projection.get("untested_endpoints", [])
        if owner_projection.get("untested_authoritative")
        else profile.get("untested_endpoints", [])
    )
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
        "tested_endpoints": tested_endpoints,
        "untested_endpoints": untested_endpoints,
        "findings": findings,
        "finding_titles": finding_titles,
        "owner_projection": owner_projection,
        "journal_entries": len(entries),
        "confirmed_findings": len(confirmed_entries),
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
        "structured_findings": load_structured_finding_followup(root, profile_target, migrate_legacy=False),
        "canonical_sources": canonical_sources,
        "legacy_profile": {
            "status": "invalid" if profile_error else ("loaded" if profile else "missing"),
            "error": profile_error,
        },
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
    queue = checkpoint.get("next_action_queue") or []
    current_action = checkpoint.get("recommended_executable_action")
    if not isinstance(current_action, dict) or not current_action:
        current_action = checkpoint.get("default_candidate")
    if not isinstance(current_action, dict) or not current_action:
        current_action = queue[0] if queue and isinstance(queue[0], dict) else {}

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
        "decision": checkpoint.get("decision", ""),
        "next_action": checkpoint.get("next_action", ""),
        "selected_skill": (checkpoint.get("context_pack") or {}).get("selected_skill", ""),
        "knowledge_cards": (checkpoint.get("context_pack") or {}).get("knowledge_cards", []),
        "high_value_gaps_count": int(coverage_summary.get("high_value_gaps_count", 0) or 0),
        "lead_count": len(write_back.get("lead") or []),
        "next_count": len(write_back.get("next") or []),
        "dead_end_count": len(write_back.get("dead_end") or []),
        "handoff": str(write_back.get("handoff") or ""),
        **control,
    }


def load_pickup_summary(
    memory_dir: str | Path,
    target: str,
    *,
    repo_root: str | Path | None = None,
) -> dict | None:
    """Load resume summary plus a read-only checkpoint follow-up."""
    root = Path(repo_root) if repo_root is not None else Path(BASE_DIR)
    summary = load_resume_summary(memory_dir, target, repo_root=root)
    if summary is None:
        return None

    resolved_target = summary.get("resolved_target") or target
    summary["checkpoint"] = load_checkpoint_followup(
        root,
        resolved_target,
        memory_dir=memory_dir,
    )
    summary["target_leads"] = _target_active_leads(root, resolved_target)
    return summary


def _target_active_leads(repo_root: Path, target: str) -> list:
    """Bounded read of the target-memory active leads for the scene summary."""
    try:
        from tools.target_memory import load_target_memory

        memory = load_target_memory(target)
    except Exception:  # pragma: no cover - memory is optional context
        return []
    if not isinstance(memory, dict):
        return []
    leads = memory.get("active_leads")
    return leads if isinstance(leads, list) else []


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

    chain_context = structured_findings.get("chain_context") or []
    if chain_context:
        lines.append("")
        lines.append("Chain Context:")
        for item in chain_context[:_CHAIN_CONTEXT_LIMIT]:
            if not isinstance(item, dict):
                continue
            finding_id = str(item.get("finding_id") or "finding").strip()
            scope_status = str(item.get("scope_status") or "external-chain-context").strip()
            details = f"  - {finding_id} [{scope_status}]"
            assets = ", ".join(
                str(value).strip()
                for value in (item.get("external_assets") or [])[:_CHAIN_CONTEXT_ITEM_LIMIT]
                if str(value).strip()
            )
            refs = ", ".join(
                str(value).strip()
                for value in (item.get("evidence_refs") or [])[:_CHAIN_CONTEXT_ITEM_LIMIT]
                if str(value).strip()
            )
            relations = "; ".join(
                str(value).strip()
                for value in (item.get("chain_context") or [])[:_CHAIN_CONTEXT_ITEM_LIMIT]
                if str(value).strip()
            )
            if assets:
                details += f" assets={assets}"
            if relations:
                details += f" chain={relations}"
            if refs:
                details += f" evidence={refs}"
            lines.append(details)

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
            selected_skill = str(checkpoint.get("selected_skill") or "").strip()
            if selected_skill:
                lines.append(f"  Recommended skill: {selected_skill}")
            lines.append(f"  High-value gaps: {checkpoint.get('high_value_gaps_count', 0)}")
            lines.append(
                "  Target write-back proposals: "
                f"lead={checkpoint.get('lead_count', 0)}, "
                f"next={checkpoint.get('next_count', 0)}, "
                f"dead-end={checkpoint.get('dead_end_count', 0)}"
            )
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
    # 跨目标 pattern 建议已移除（收敛裁定）；本目标经验走 experience_recall。

    scene = _scene_summary(summary)
    if scene:
        lines.extend(["", "Scene (我上次在干嘛):", scene])

    lines.extend([
        "",
        "Actions:",
        "  [r] Continue hunting untested endpoints",
        "  [c] Run checkpoint write-back when ready",
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
    args = parser.parse_args()

    repo_root = Path(args.repo_root) if args.repo_root else Path(BASE_DIR)
    memory_dir = args.memory_dir or str(default_memory_dir(repo_root))
    summary = load_pickup_summary(memory_dir, args.target, repo_root=repo_root)

    if args.json:
        print(json.dumps({"summary": summary}, indent=2))
        return

    print(format_resume_output(summary, args.target))


if __name__ == "__main__":
    main()
