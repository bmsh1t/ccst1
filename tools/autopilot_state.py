#!/usr/bin/env python3
"""
autopilot_state.py — combine resume + surface context into one practical state view.
"""

import argparse
import json
import os
import sys
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from memory.target_profile import default_memory_dir
try:
    from tools.repo_source_artifacts import (
        list_repo_source_artifacts,
        load_repo_source_summary,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from repo_source_artifacts import (
        list_repo_source_artifacts,
        load_repo_source_summary,
    )
try:
    from tools.request_guard import load_guard_status
    from tools.resume import load_resume_summary, load_structured_finding_followup
    from tools.surface import load_surface_context, rank_surface
except ImportError:  # pragma: no cover - direct tools/ execution
    from request_guard import load_guard_status
    from resume import load_resume_summary, load_structured_finding_followup
    from surface import load_surface_context, rank_surface
try:
    from tools.runtime_state import inspect_recon_artifacts, load_runtime_state
    from tools.structured_findings import format_structured_findings_lines
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from runtime_state import inspect_recon_artifacts, load_runtime_state
    from structured_findings import format_structured_findings_lines
    from target_paths import canonical_target_value, target_storage_key


APP_LIKE_HINT_TOKENS = (
    "login",
    "register",
    "signup",
    "signin",
    "dashboard",
    "portal",
    "account",
    "admin",
    "workspace",
    "graphql",
)


def _read_json_file(path: str) -> dict:
    """Read a JSON object from disk; return empty dict on missing or invalid data."""
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def load_target_goal_memory(repo_root: str, target: str) -> dict:
    """Load the four-layer target memory for autopilot bootstrapping."""
    resolved_target = canonical_target_value(target)
    goals_dir = os.path.join(repo_root, "memory", "goals")
    active = _read_json_file(os.path.join(goals_dir, "active.json"))
    target_memory = _read_json_file(
        os.path.join(goals_dir, "targets", f"{target_storage_key(resolved_target)}.json")
    )

    active_target = canonical_target_value(str(active.get("target", "") or ""))
    active_matches = bool(active_target and active_target == resolved_target)

    return {
        "active": active if active_matches else {},
        "target": target_memory,
        "active_matches": active_matches,
    }


def _matches_resume_target(url: str, resume_targets: list[str]) -> bool:
    """Check whether a ranked URL matches any remembered resume target path."""
    parsed = urlparse(url or "")
    normalized = parsed.path or "/"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"

    for target in resume_targets:
        candidate = str(target or "").strip()
        if not candidate:
            continue
        if normalized == candidate or normalized.endswith(candidate):
            return True
    return False


def _build_recommended_targets(
    p1: list[dict],
    guard_status: dict,
    resume_targets: list[str] | None = None,
    *,
    prefer_resume_targets: bool = False,
) -> list[dict]:
    """Prefer non-tripped hosts first, then optionally front-load resume targets within a bucket."""
    host_status = {
        item.get("host", ""): item
        for item in guard_status.get("hosts", [])
        if item.get("host")
    }

    preferred = resume_targets or []
    recommended = []
    for item in p1:
        status = host_status.get(item.get("host", ""), {})
        recommended.append({
            "url": item.get("url", ""),
            "host": item.get("host", ""),
            "suggested": item.get("suggested", ""),
            "score": item.get("score", 0),
            "tripped": bool(status.get("tripped", False)),
            "remaining_seconds": float(status.get("remaining_seconds", 0.0) or 0.0),
            "matches_resume_target": _matches_resume_target(item.get("url", ""), preferred),
        })

    recommended.sort(
        key=lambda item: (
            item["tripped"],
            0 if (prefer_resume_targets and item["matches_resume_target"]) else 1,
            -item["score"],
            item["url"],
        )
    )
    return recommended[:5]


def _build_resume_targets(summary: dict | None) -> list[str]:
    """Prefer continuing the latest session focus, then fall back to untested endpoints."""
    if not summary:
        return []

    latest_session = summary.get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]
    if preview:
        return list(dict.fromkeys(preview))[:3]

    untested = [item for item in summary.get("untested_endpoints", []) if item]
    if not untested:
        return []
    return untested[:3]


def _pick_next_action(
    has_recon: bool,
    ranked: dict,
    resume_summary: dict | None,
    structured_findings: dict | None = None,
) -> str:
    """Bias toward resumable session context before widening to generic P1/P2 surface."""
    structured_findings = structured_findings or {}
    if structured_findings.get("pending_validation"):
        return "validate_finding"
    if structured_findings.get("validated_pending_report"):
        return "report_finding"

    if not has_recon:
        return "run_recon"

    resume_targets = _build_resume_targets(resume_summary)
    latest_session = (resume_summary or {}).get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]

    if latest_session and preview:
        return "continue_last_focus"
    if latest_session and resume_targets:
        return "resume_untested"

    if ranked.get("p1"):
        return "hunt_p1"
    if ranked.get("p2"):
        return "hunt_p2"
    if resume_summary and resume_summary.get("untested_endpoints"):
        return "resume_untested"
    return "refresh_recon"


def _describe_next_step(state: dict) -> str:
    """Render a human-friendly next-step hint from the computed state."""
    action = state.get("next_action", "")
    target = state.get("target", "target")
    resume_targets = state.get("resume_targets", []) or []
    recommended_targets = state.get("recommended_targets", []) or []
    tripped_hosts = (state.get("guard_status", {}) or {}).get("tripped_hosts", []) or []
    recon_artifacts = state.get("recon_artifacts") or {}

    if action == "run_recon":
        missing = recon_artifacts.get("missing") or []
        if recon_artifacts.get("available") and missing:
            return f"rerun /recon {target}; cached recon is incomplete ({', '.join(missing[:2])})."
        return f"run /recon {target} first."
    if action == "validate_finding":
        followup = (state.get("structured_findings") or {}).get("next_validation") or {}
        if followup:
            return f"validate structured finding {followup.get('id')} on {followup.get('url')}."
        return "validate the highest-priority structured finding."
    if action == "report_finding":
        followup = (state.get("structured_findings") or {}).get("next_report") or {}
        if followup:
            return f"generate a report for validated finding {followup.get('id')}."
        return "generate reports for validated structured findings."
    if action == "continue_last_focus":
        focus = ", ".join(resume_targets[:2]) if resume_targets else "the last focus endpoints"
        return f"continue testing the last focus first: {focus}."
    if action == "resume_untested":
        focus = ", ".join(resume_targets[:2]) if resume_targets else "cached untested endpoints"
        return f"resume the cached untested surface first: {focus}."
    if action == "hunt_p1":
        if recommended_targets:
            first_item = recommended_targets[0]
            first = first_item["url"]
            if first_item.get("tripped"):
                return (
                    f"the top P1 host is cooling down; prefer another surface until cooldown clears: "
                    f"{first}."
                )
            if tripped_hosts:
                return f"start with the top ready P1 target while other hosts cool down: {first}."
            return f"start with the top P1 target: {first}."
        return "start with the top P1 target."
    if action == "hunt_p2":
        return "widen into the P2 surface after P1 paths are exhausted."
    if action == "refresh_recon":
        return f"refresh recon before going deeper on {target}."
    return "follow the highest-confidence target shown below."


def _build_guard_hint(guard_status: dict, recommended_targets: list[dict]) -> str:
    """Render an operator/agent-friendly guard hint for immediate action."""
    tripped_hosts = [item for item in (guard_status.get("tripped_hosts", []) or []) if item.get("host")]
    ready_target = next((item for item in recommended_targets if not item.get("tripped")), None)

    if tripped_hosts:
        cooling = ", ".join(
            f"{item['host']} ({float(item.get('remaining_seconds', 0.0) or 0.0):.1f}s)"
            for item in tripped_hosts[:3]
        )
        if ready_target:
            return (
                f"cooling hosts: {cooling}; prefer the ready host "
                f"{ready_target.get('host', '')} via {ready_target.get('url', '')}"
            )
        return (
            f"all tracked hot hosts are cooling down: {cooling}; pivot to quieter surface, "
            f"repo/source artifacts, or recon refresh until cooldown clears"
        )

    if ready_target and int(guard_status.get("tracked_hosts", 0) or 0) > 0:
        return f"prefer the ready host {ready_target.get('host', '')} via {ready_target.get('url', '')}"

    return ""


def _format_recent_guard_advisory(item: dict) -> str:
    """Render a compact human-readable summary for one recent guard advisory."""
    notes = str(item.get("notes", "") or "").strip()
    if notes:
        return notes
    endpoint = str(item.get("endpoint", "") or "").strip()
    action = str(item.get("action", "") or "").strip()
    if action and endpoint:
        return f"{action} :: {endpoint}"
    return endpoint or action


def _build_pivot_hint(
    *,
    tripped_hosts: list[dict],
    recent_guard_advisories: list[dict],
    repo_source_summary: dict,
) -> str:
    """Build one short advisory hint from current guard + repo-source signals."""
    secret_findings = int(repo_source_summary.get("secret_findings", 0) or 0)
    ci_findings = int(repo_source_summary.get("ci_findings", 0) or 0)
    has_live_guard_pressure = bool(tripped_hosts)
    has_repo_findings = secret_findings > 0 or ci_findings > 0

    if has_live_guard_pressure and has_repo_findings:
        return "live API has guard advisories; inspect repo source findings first."
    if has_live_guard_pressure:
        return "guard advisories are active; continue with the next ready target or quieter surface."
    if secret_findings > 0:
        return "repo source shows secrets; verify credential usability before widening live probing."
    if ci_findings > 0:
        return "repo source shows CI risks; review workflow attack surface before rerunning source hunt."
    return ""


def _has_any_artifact(*paths: str) -> bool:
    """Return whether any provided artifact path exists and is non-empty."""
    for path in paths:
        if not path:
            continue
        if os.path.isfile(path):
            try:
                if os.path.getsize(path) > 0:
                    return True
            except OSError:
                continue
        elif os.path.isdir(path):
            return True
    return False


def _has_browser_probe_signal(surface_context: dict, ranked: dict) -> bool:
    """Return whether cached recon looks app-like enough to justify browser probing."""
    titles = [
        str(item.get("title", "") or "").lower()
        for item in (surface_context.get("hosts") or {}).values()
        if isinstance(item, dict)
    ]
    ranked_urls = [
        str(item.get("url", "") or "").lower()
        for bucket in ("p1", "p2")
        for item in (ranked.get(bucket) or [])
        if isinstance(item, dict)
    ]

    for value in titles + ranked_urls:
        if any(token in value for token in APP_LIKE_HINT_TOKENS):
            return True
    return False


def _has_js_read_signal(recon_dir: str, surface_context: dict) -> bool:
    """Return whether cached JS artifacts exist and are worth handing to js-reader."""
    if surface_context.get("js_endpoints"):
        return True
    return _has_any_artifact(
        os.path.join(recon_dir, "urls", "js_files.txt"),
        os.path.join(recon_dir, "js", "linkfinder_endpoints.txt"),
        os.path.join(recon_dir, "js", "potential_secrets.txt"),
    )


EXPOSURE_SUMMARY_KEYS = (
    "config_exposures",
    "api_doc_candidates",
    "api_leak_candidates",
    "verified_secrets",
    "postman_leaks",
    "postleaks_urls",
    "swagger_leaks",
    "cloud_storage_candidates",
    "s3_bucket_candidates",
    "external_service_hosts",
    "identity_emails",
    "leaksearch_hits",
    "cloud_enum_hits",
)


def _count_value(counts: dict, key: str) -> int:
    """Safely read an integer count from recon artifact metadata."""
    try:
        return int(counts.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _has_exposure_signals(recon_artifacts: dict) -> bool:
    """Return whether cached recon exposure artifacts contain actionable signal."""
    counts = recon_artifacts.get("counts") or {}
    return any(_count_value(counts, key) > 0 for key in EXPOSURE_SUMMARY_KEYS)


def _exposure_review_paths(target: str, recon_artifacts: dict) -> list[str]:
    """Build a short, priority-ordered review list for exposure artifacts."""
    counts = recon_artifacts.get("counts") or {}
    storage_key = target_storage_key(target)
    review = []

    def add_if(condition: bool, relative_path: str) -> None:
        if condition:
            review.append(f"recon/{storage_key}/{relative_path}")

    add_if(
        _count_value(counts, "api_doc_candidates") > 0,
        "exposure/api_doc_candidates.txt",
    )
    add_if(
        any(
            _count_value(counts, key) > 0
            for key in (
                "api_leak_candidates",
                "postman_leaks",
                "postleaks_urls",
                "swagger_leaks",
            )
        ),
        "exposure/api_leak_candidates.txt",
    )
    add_if(
        _count_value(counts, "verified_secrets") > 0,
        "exposure/api_leak_trufflehog_verified.jsonl",
    )
    add_if(
        _count_value(counts, "config_exposures") > 0,
        "exposure/config_files.txt",
    )
    add_if(
        any(
            _count_value(counts, key) > 0
            for key in (
                "cloud_storage_candidates",
                "s3_bucket_candidates",
                "external_service_hosts",
            )
        ),
        "exposure/cloud_storage_candidates.txt",
    )
    add_if(
        any(
            _count_value(counts, key) > 0
            for key in ("identity_emails", "leaksearch_hits", "cloud_enum_hits")
        ),
        "exposure/identity_intel/summary.md",
    )
    add_if(
        _count_value(counts, "cloud_enum_hits") > 0,
        "exposure/cloud/cloud_enum.txt",
    )
    return list(dict.fromkeys(review))[:6]


def _format_exposure_signal_lines(target: str, recon_artifacts: dict) -> list[str]:
    """Render exposure signals without turning them into mandatory next actions."""
    if not _has_exposure_signals(recon_artifacts):
        return []

    counts = recon_artifacts.get("counts") or {}
    lines = ["Exposure signals:"]
    lines.append(f"- API docs: {_count_value(counts, 'api_doc_candidates')}")
    lines.append(
        "- API leaks: "
        f"candidates={_count_value(counts, 'api_leak_candidates')}, "
        f"swagger={_count_value(counts, 'swagger_leaks')}, "
        f"postman={_count_value(counts, 'postman_leaks')}, "
        f"postleaks={_count_value(counts, 'postleaks_urls')}, "
        f"verified_secrets={_count_value(counts, 'verified_secrets')}"
    )
    lines.append(
        "- Config/cloud: "
        f"config={_count_value(counts, 'config_exposures')}, "
        f"cloud={_count_value(counts, 'cloud_storage_candidates')}, "
        f"s3={_count_value(counts, 's3_bucket_candidates')}, "
        f"external_hosts={_count_value(counts, 'external_service_hosts')}"
    )
    lines.append(
        "- Identity/cloud intel: "
        f"emails={_count_value(counts, 'identity_emails')}, "
        f"LeakSearch={_count_value(counts, 'leaksearch_hits')}, "
        f"cloud_enum={_count_value(counts, 'cloud_enum_hits')}"
    )

    review_paths = _exposure_review_paths(target, recon_artifacts)
    if review_paths:
        lines.append("Next exposure review:")
        for path in review_paths:
            lines.append(f"- {path}")
    return lines


def _format_infra_signal_lines(target: str, recon_artifacts: dict) -> list[str]:
    """Render WAF/origin/port recon signals as soft review hints."""
    counts = recon_artifacts.get("counts") or {}
    waf_hits = _count_value(counts, "waf_hits")
    origin_candidates = _count_value(counts, "origin_candidates")
    open_ports = _count_value(counts, "open_ports")
    if waf_hits <= 0 and origin_candidates <= 0 and open_ports <= 0:
        return []

    storage_key = target_storage_key(target)
    lines = [
        "Infra signals:",
        f"- WAF hits: {waf_hits}, origin candidates: {origin_candidates}, open ports: {open_ports}",
    ]
    review_paths = []
    if waf_hits > 0:
        review_paths.append(f"recon/{storage_key}/live/wafw00f_hits.txt")
    if origin_candidates > 0:
        review_paths.append(f"recon/{storage_key}/live/unwaf_bypass_ips.txt")
    if open_ports > 0:
        review_paths.append(f"recon/{storage_key}/ports/open_ports_all.txt")
    if review_paths:
        lines.append("Next infra review:")
        lines.extend(f"- {path}" for path in review_paths[:4])
    return lines


def _build_enrichment_hints(
    *,
    repo_root: str,
    resolved_target: str,
    surface_context: dict,
    ranked: dict,
    repo_source_available: bool,
    next_action: str,
) -> tuple[str, list[dict]]:
    """Suggest the most useful enrichment tool before widening generic hunting."""
    if next_action in {"run_recon", "validate_finding", "report_finding"}:
        return "", []

    storage_key = target_storage_key(resolved_target)
    recon_dir = os.path.join(repo_root, "recon", storage_key)
    findings_dir = os.path.join(repo_root, "findings", storage_key)

    browser_ready = _has_any_artifact(
        os.path.join(recon_dir, "browser", "summary.json"),
        os.path.join(recon_dir, "browser", "xhr_endpoints.txt"),
        os.path.join(recon_dir, "browser", "api_endpoints.txt"),
    )
    js_intel_ready = _has_any_artifact(
        os.path.join(findings_dir, "js_intel", "materials.json"),
        os.path.join(findings_dir, "js_intel", "materials_summary.md"),
        os.path.join(findings_dir, "js_intel", "hypotheses.json"),
    )
    source_intel_ready = _has_any_artifact(
        os.path.join(findings_dir, "source_intel", "summary.md"),
        os.path.join(findings_dir, "source_intel", "hypotheses.jsonl"),
    )

    hints = []
    if not browser_ready and _has_browser_probe_signal(surface_context, ranked):
        hints.append({
            "tool": "run_browser_probe",
            "reason": "app-like or GraphQL surface signals were detected, but no browser-observed surface exists yet",
        })
    if repo_source_available and not source_intel_ready:
        hints.append({
            "tool": "run_source_intel",
            "reason": "repo source artifacts exist, but source_intel artifacts have not been generated yet",
        })
    if not js_intel_ready and _has_js_read_signal(recon_dir, surface_context):
        hints.append({
            "tool": "run_js_read",
            "reason": "cached JS artifacts exist, but js_intel materials have not been prepared yet",
        })

    next_tool_hint = hints[0]["tool"] if hints else ""
    return next_tool_hint, hints


def _memory_action_hint(text: str) -> str:
    lowered = str(text or "").lower()
    if "/validate" in lowered or "validate" in lowered:
        return "/validate"
    if "/report" in lowered or "report" in lowered:
        return "/report"
    if "/recon" in lowered or "recon" in lowered:
        return "/recon"
    if "browser" in lowered or "xhr" in lowered:
        return "browser/playwright probe, then /surface"
    if "postman" in lowered or "leak" in lowered:
        return "review leak artifact, record evidence, then /surface"
    if "oauth" in lowered or "redirect_uri" in lowered:
        return "focused OAuth replay with red-line check"
    if "idor" in lowered or "auth" in lowered or "role" in lowered:
        return "role/object diff with low-risk replay"
    return "execute smallest safe evidence-producing step"


def _build_memory_action_queue(target_goal_memory: dict) -> list[dict]:
    target_memory = target_goal_memory.get("target") or {}
    entries = target_memory.get("next_actions") or []
    if not isinstance(entries, list):
        return []

    queue: list[dict] = []
    for idx, item in enumerate(entries[-5:], 1):
        if isinstance(item, dict):
            text = str(item.get("text", "") or "").strip()
        else:
            text = str(item or "").strip()
        if not text:
            continue
        queue.append({
            "id": f"M{idx}",
            "source": "target_memory",
            "action": text,
            "command_hint": _memory_action_hint(text),
        })
    return queue


def build_autopilot_state(repo_root: str, target: str, memory_dir: str | None = None) -> dict:
    """Build a practical autopilot bootstrap state for a target."""
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    resolved_target = canonical_target_value(target)
    resume_summary = load_resume_summary(resolved_memory_dir, target)
    # autopilot_state 是启动态读取工具，不应改写 surface 的过滤日志。
    surface_context = load_surface_context(
        repo_root,
        resolved_target,
        memory_dir=resolved_memory_dir,
        write_probe_log=False,
    )
    ranked = rank_surface(surface_context)
    guard_status = load_guard_status(resolved_memory_dir, resolved_target)
    tripped_hosts = [item for item in guard_status.get("hosts", []) if item.get("tripped")]
    repo_source_artifacts = list_repo_source_artifacts(repo_root, resolved_target)
    repo_source_available = bool(repo_source_artifacts)
    repo_source_summary = load_repo_source_summary(repo_root, resolved_target) if repo_source_available else {}
    structured_findings = load_structured_finding_followup(repo_root, resolved_target)
    runtime_state = load_runtime_state(repo_root, resolved_target)
    recon_artifacts = inspect_recon_artifacts(repo_root, resolved_target)
    target_goal_memory = load_target_goal_memory(repo_root, resolved_target)

    has_recon = bool(ranked.get("available")) and bool(recon_artifacts.get("host_inventory_ready"))
    has_memory = resume_summary is not None
    resume_targets = _build_resume_targets(resume_summary)
    recent_guard_advisories = list(
        (resume_summary or {}).get("recent_guard_advisories")
        or (resume_summary or {}).get("recent_guard_blocks", [])
        or []
    )

    tech_stack = []
    if resume_summary and resume_summary.get("tech_stack"):
        tech_stack = resume_summary["tech_stack"]
    elif has_recon:
        p1 = ranked.get("p1", [])
        if p1:
            tech_stack = p1[0].get("tech_stack", [])

    next_action = _pick_next_action(has_recon, ranked, resume_summary, structured_findings)
    prefer_resume_targets = next_action == "continue_last_focus"
    recommended_targets = (
        _build_recommended_targets(
            ranked.get("p1", []),
            guard_status,
            resume_targets,
            prefer_resume_targets=prefer_resume_targets,
        )
        if has_recon else []
    )
    guard_state = {
        "tracked_hosts": guard_status.get("tracked_hosts", 0),
        "tripped_hosts": tripped_hosts,
        "settings": guard_status.get("settings", {}),
    }
    pivot_hint = _build_pivot_hint(
        tripped_hosts=tripped_hosts,
        recent_guard_advisories=recent_guard_advisories,
        repo_source_summary=repo_source_summary,
    )
    next_tool_hint, enrichment_hints = _build_enrichment_hints(
        repo_root=repo_root,
        resolved_target=resolved_target,
        surface_context=surface_context,
        ranked=ranked,
        repo_source_available=repo_source_available,
        next_action=next_action,
    )
    memory_action_queue = _build_memory_action_queue(target_goal_memory)

    return {
        "target": target,
        "resolved_target": resolved_target,
        "memory_dir": resolved_memory_dir,
        "has_recon": has_recon,
        "has_memory": has_memory,
        "repo_source_available": repo_source_available,
        "repo_source_artifacts": repo_source_artifacts,
        "repo_source_summary": repo_source_summary,
        "runtime_state": runtime_state,
        "recon_artifacts": recon_artifacts,
        "structured_findings": structured_findings,
        "target_goal_memory": target_goal_memory,
        "resume_summary": resume_summary,
        "surface": ranked if has_recon else None,
        "guard_status": guard_state,
        "guard_hint": _build_guard_hint(guard_state, recommended_targets),
        "pivot_hint": pivot_hint,
        "tech_stack": tech_stack,
        "next_action": next_action,
        "next_tool_hint": next_tool_hint,
        "enrichment_hints": enrichment_hints,
        "memory_action_queue": memory_action_queue,
        "resume_targets": resume_targets,
        "recommended_targets": recommended_targets,
        "recent_guard_advisories": recent_guard_advisories[:3],
        "recent_guard_blocks": recent_guard_advisories[:3],
    }


def format_autopilot_state(state: dict) -> str:
    """Format autopilot bootstrap state for terminal display."""
    summary = state.get("resume_summary") or {}
    latest_session = summary.get("latest_session_summary") or {}
    recent_guard_advisories = state.get("recent_guard_advisories") or state.get("recent_guard_blocks", []) or []
    repo_source_summary = state.get("repo_source_summary") or {}
    repo_source_hint = str(repo_source_summary.get("summary_hint", "") or "").strip()
    pivot_hint = str(state.get("pivot_hint", "") or "").strip()
    structured_findings = state.get("structured_findings") or {}
    runtime_state = state.get("runtime_state") or {}
    recon_artifacts = state.get("recon_artifacts") or {}
    target_goal_memory = state.get("target_goal_memory") or {}
    target_memory = target_goal_memory.get("target") or {}
    active_goal_memory = target_goal_memory.get("active") or {}
    workflow_leads = [
        json.loads(item) if isinstance(item, str) else item
        for item in ((state.get("surface") or {}).get("workflow_leads", []) or [])
    ]

    if not state["has_recon"]:
        lines = [
            f"AUTOPILOT STATE: {state['target']}",
            "═══════════════════════════════════════",
            "",
            "Recon: missing",
            f"Memory: {'available' if state['has_memory'] else 'missing'}",
        ]
        runtime_workflow = str(
            runtime_state.get("last_executed_workflow")
            or runtime_state.get("current_stage")
            or ""
        ).strip()
        runtime_mode = str(runtime_state.get("mode", "") or "").strip()
        if runtime_workflow:
            lines.append(f"Last Workflow: {runtime_workflow}" + (f" (mode: {runtime_mode})" if runtime_mode else ""))
        if recon_artifacts.get("available"):
            missing = recon_artifacts.get("missing") or []
            warnings = recon_artifacts.get("warnings") or []
            if missing:
                lines.append(f"Recon cache issue: {', '.join(missing[:2])}")
            elif warnings:
                lines.append(f"Recon warning: {warnings[0]}")
            lines.extend(
                _format_exposure_signal_lines(
                    state.get("resolved_target") or state["target"],
                    recon_artifacts,
                )
            )
            lines.extend(
                _format_infra_signal_lines(
                    state.get("resolved_target") or state["target"],
                    recon_artifacts,
                )
            )
        if latest_session:
            tried = ", ".join(latest_session.get("vuln_classes", [])[:4]) or "none"
            lines.append(
                f"Last session: {int(latest_session.get('findings_count', 0) or 0)} finding(s), tried {tried}"
            )
        if repo_source_hint:
            lines.append(f"Repo source: {repo_source_hint}")
        elif state.get("repo_source_available"):
            lines.append("Repo source: available — use read_repo_source_summary")
        if active_goal_memory or target_memory:
            lines.extend(_format_target_goal_memory_lines(active_goal_memory, target_memory))
        memory_action_queue = state.get("memory_action_queue") or []
        if memory_action_queue:
            lines.append("Memory action queue:")
            for item in memory_action_queue[:5]:
                lines.append(
                    f"- {item.get('id', '-')}: {item.get('action', '')} "
                    f"| hint: {item.get('command_hint', '')}"
                )
        lines.append(f"Next: {_describe_next_step(state)}")
        guard_hint = str(state.get("guard_hint", "") or "").strip()
        if guard_hint:
            lines.append(f"Guard hint: {guard_hint}")
        if pivot_hint:
            lines.append(f"Pivot hint: {pivot_hint}")
        if structured_findings.get("total"):
            lines.extend(
                format_structured_findings_lines(
                    structured_findings,
                    header="Structured findings:",
                    inline_header=True,
                )
            )
        if recent_guard_advisories:
            lines.append("Recent guard advisories:")
            for item in recent_guard_advisories[:3]:
                details = _format_recent_guard_advisory(item)
                if details:
                    lines.append(f"- {details}")
        return "\n".join(lines) + "\n"

    surface = state["surface"] or {}
    lines = [
        f"AUTOPILOT STATE: {state['target']}",
        "═══════════════════════════════════════",
        "",
        f"Recon: ready",
        f"Memory: {'available' if state['has_memory'] else 'missing'}",
        f"Next action: {state['next_action']}",
        f"Next step: {_describe_next_step(state)}",
    ]
    runtime_workflow = str(
        runtime_state.get("last_executed_workflow")
        or runtime_state.get("current_stage")
        or ""
    ).strip()
    runtime_mode = str(runtime_state.get("mode", "") or "").strip()
    if runtime_workflow:
        lines.append(f"Last Workflow: {runtime_workflow}" + (f" (mode: {runtime_mode})" if runtime_mode else ""))
    if active_goal_memory or target_memory:
        lines.extend(_format_target_goal_memory_lines(active_goal_memory, target_memory))
    next_tool_hint = str(state.get("next_tool_hint", "") or "").strip()
    enrichment_hints = state.get("enrichment_hints") or []
    if next_tool_hint:
        lines.append(f"Next tool hint: {next_tool_hint}")
    if enrichment_hints:
        lines.append("Enrichment hints:")
        for item in enrichment_hints[:3]:
            tool = str(item.get("tool", "") or "").strip()
            reason = str(item.get("reason", "") or "").strip()
            if tool and reason:
                lines.append(f"- {tool}: {reason}")
            elif tool:
                lines.append(f"- {tool}")
    memory_action_queue = state.get("memory_action_queue") or []
    if memory_action_queue:
        lines.append("Memory action queue:")
        for item in memory_action_queue[:5]:
            lines.append(
                f"- {item.get('id', '-')}: {item.get('action', '')} "
                f"| hint: {item.get('command_hint', '')}"
            )

    guard_status = state.get("guard_status", {})
    lines.append(
        f"Guard: {guard_status.get('tracked_hosts', 0)} tracked host(s), {len(guard_status.get('tripped_hosts', []))} tripped"
    )
    guard_hint = str(state.get("guard_hint", "") or "").strip()
    if guard_hint:
        lines.append(f"Guard hint: {guard_hint}")
    if pivot_hint:
        lines.append(f"Pivot hint: {pivot_hint}")
    if repo_source_hint:
        lines.append(f"Repo source: {repo_source_hint}")
    elif state.get("repo_source_available"):
        lines.append("Repo source: available — use read_repo_source_summary")
    if recon_artifacts.get("available"):
        warnings = recon_artifacts.get("warnings") or []
        counts = recon_artifacts.get("counts") or {}
        lines.append(
            "Recon cache: "
            f"hosts={counts.get('hosts', 0)}, "
            f"surface={counts.get('api_urls', 0) + counts.get('param_urls', 0) + counts.get('js_endpoints', 0) + counts.get('browser_xhr_urls', 0) + counts.get('browser_api_urls', 0)}, "
            f"ports={counts.get('open_ports', 0)}, "
            f"waf={counts.get('waf_hits', 0)}, "
            f"origin={counts.get('origin_candidates', 0)}"
        )
        if warnings:
            lines.append(f"Recon warning: {warnings[0]}")
        lines.extend(
            _format_exposure_signal_lines(
                state.get("resolved_target") or state["target"],
                recon_artifacts,
            )
        )
        lines.extend(
            _format_infra_signal_lines(
                state.get("resolved_target") or state["target"],
                recon_artifacts,
            )
        )

    if state["tech_stack"]:
        lines.append(f"Tech stack: {', '.join(state['tech_stack'])}")

    if structured_findings.get("total"):
        lines.extend(
            format_structured_findings_lines(
                structured_findings,
                header="Structured findings:",
                inline_header=True,
            )
        )

    if workflow_leads:
        lines.append("Workflow leads:")
        for item in workflow_leads[:3]:
            lines.append(
                f"- [{item.get('priority', 'medium')}] {item.get('category', 'other')}: "
                f"{item.get('title', '-')}"
            )
            next_action = str(item.get("next_action", "") or "").strip()
            if next_action:
                lines.append(f"  Next: {next_action}")

    if summary:
        lines.append(f"Sessions: {summary.get('sessions', 0)}")
        lines.append(f"Untested endpoints: {len(summary.get('untested_endpoints', []))}")
        if latest_session:
            tried = ", ".join(latest_session.get("vuln_classes", [])[:4]) or "none"
            lines.append(
                f"Last session: {int(latest_session.get('findings_count', 0) or 0)} finding(s), tried {tried}"
            )
            if latest_session.get("endpoints_preview"):
                lines.append(
                    f"Last endpoints: {', '.join(latest_session['endpoints_preview'][:2])}"
                )
        if state.get("resume_targets"):
            lines.append(f"Resume targets: {', '.join(state['resume_targets'][:3])}")

    lines.append(f"P1 targets: {surface.get('stats', {}).get('p1', 0)}")
    lines.append(f"P2 targets: {surface.get('stats', {}).get('p2', 0)}")

    tripped_hosts = guard_status.get("tripped_hosts", [])
    if tripped_hosts:
        lines.append("Cooling down hosts:")
        for item in tripped_hosts[:3]:
            lines.append(
                f"- {item['host']} ({item['remaining_seconds']:.1f}s remaining)"
            )

    if recent_guard_advisories:
        lines.append("")
        lines.append("Recent guard advisories:")
        for item in recent_guard_advisories[:3]:
            details = _format_recent_guard_advisory(item)
            if details:
                lines.append(f"- {details}")

    if state["recommended_targets"]:
        lines.append("")
        lines.append("Recommended first targets:")
        for idx, item in enumerate(state["recommended_targets"], 1):
            suffix = (
                f" [cooldown {item['remaining_seconds']:.1f}s]"
                if item.get("tripped")
                else ""
            )
            lines.append(
                f"{idx}. {item['url']} — {item['suggested']} (score {item['score']}){suffix}"
            )

    return "\n".join(lines)


def _format_target_goal_memory_lines(active: dict, target_memory: dict) -> list[str]:
    """Format compact target-memory context for autopilot output."""
    lines = ["Target memory:"]
    goal = str(active.get("active_goal") or target_memory.get("active_goal") or "").strip()
    hypothesis = str(
        active.get("current_hypothesis")
        or target_memory.get("current_hypothesis")
        or ""
    ).strip()
    if goal:
        lines.append(f"- Goal: {goal}")
    if hypothesis:
        lines.append(f"- Hypothesis: {hypothesis}")

    for label, field in (
        ("Active leads", "active_leads"),
        ("Next actions", "next_actions"),
        ("Dead ends", "dead_ends"),
    ):
        entries = target_memory.get(field) or []
        if not isinstance(entries, list):
            entries = []
        lines.append(f"- {label}: {len(entries)}")
        for item in entries[-2:]:
            if not isinstance(item, dict):
                continue
            text = str(item.get("text", "") or "").strip()
            if text:
                lines.append(f"  - {text}")

    handoffs = target_memory.get("session_handoffs") or []
    if isinstance(handoffs, list) and handoffs:
        latest = handoffs[-1]
        if isinstance(latest, dict):
            summary = str(latest.get("summary", "") or "").strip()
            path = str(latest.get("path", "") or "").strip()
            if summary:
                lines.append(f"- Latest handoff: {summary}")
            if path:
                lines.append(f"- Handoff path: {path}")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Build combined autopilot state for a target")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    state = build_autopilot_state(BASE_DIR, args.target, memory_dir=args.memory_dir or None)
    if args.json:
        print(json.dumps(state, indent=2))
        return
    print(format_autopilot_state(state))


if __name__ == "__main__":
    main()
