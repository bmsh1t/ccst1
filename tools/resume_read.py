"""Read-only target memory and prior-session summaries, independent of CLI/pickup."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from memory.hunt_journal import HuntJournal

try:
    from tools.repo_source_artifacts import load_repo_source_summary
    from tools.runtime_state import (
        _derive_owner_projection, inspect_recon_artifacts,
        inspect_recon_artifacts_fast, load_runtime_state,
    )
    from tools.structured_findings import compact_structured_finding
    from tools.target_memory import load_goal_memory
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.target_store import runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from repo_source_artifacts import load_repo_source_summary
    from runtime_state import (
        _derive_owner_projection, inspect_recon_artifacts,
        inspect_recon_artifacts_fast, load_runtime_state,
    )
    from structured_findings import compact_structured_finding
    from target_memory import load_goal_memory
    from target_paths import canonical_target_value, target_storage_key
    from target_store import runtime_store

BASE_DIR = Path(__file__).resolve().parents[1]

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


def load_resume_summary(
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
            "current_handoff": target_memory["current_handoff"],
            "next_actions": target_memory["next_actions"],
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
