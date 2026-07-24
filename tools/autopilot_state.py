#!/usr/bin/env python3
"""
autopilot_state.py — combine resume + surface context into one practical state view.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from memory.target_profile import default_memory_dir
try:
    from tools.action_queue import load_queue, select_next_action
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import load_queue, select_next_action
try:
    from tools.intel_continuation import apply_intel_continuation, inspect_intel_continuation
except ImportError:  # pragma: no cover - direct tools/ execution
    from intel_continuation import apply_intel_continuation, inspect_intel_continuation  # type: ignore
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
    from tools.observation_inventory import peek_inventory_summary
    from tools.surface_projection import load_surface_projection
except ImportError:  # pragma: no cover - direct tools/ execution
    from request_guard import load_guard_status
    from resume import load_resume_summary, load_structured_finding_followup
    from surface import load_surface_context, rank_surface
    from observation_inventory import peek_inventory_summary  # type: ignore
    from surface_projection import load_surface_projection  # type: ignore
try:
    from tools.finding_index import (
        list_root_finding_claims,
        verify_finalized_finding_owner_provenance,
    )
    from tools.runtime_state import (
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        load_runtime_state,
        runtime_phase_in_progress,
    )
    from tools.structured_findings import (
        format_structured_findings_lines,
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from tools.target_paths import (
        canonical_target_value,
        classify_target,
        migrate_legacy_list_storage,
        target_list_entries,
        target_storage_key,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from finding_index import (  # type: ignore
        list_root_finding_claims,
        verify_finalized_finding_owner_provenance,
    )
    from runtime_state import (  # type: ignore
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        load_runtime_state,
        runtime_phase_in_progress,
    )
    from structured_findings import (
        format_structured_findings_lines,
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from target_paths import (  # type: ignore
        canonical_target_value,
        classify_target,
        migrate_legacy_list_storage,
        target_list_entries,
        target_storage_key,
    )




PLACEHOLDER_OBJECT_SEGMENTS = {"nan", "undefined", "null", "none", "object", "[object object]"}


def _normalise_endpoint_path(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            path = parsed.path or "/"
        except ValueError:
            path = raw
    else:
        path = raw
    path = path.split("?", 1)[0].split("#", 1)[0].strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    if path != "/":
        path = path.rstrip("/")
    return path


def _has_placeholder_object_segment(value: str) -> bool:
    path = _normalise_endpoint_path(value).lower()
    segments = [segment for segment in path.split("/") if segment]
    return any(segment in PLACEHOLDER_OBJECT_SEGMENTS for segment in segments)


def _finalized_finding_paths(repo_root: str, resolved_target: str) -> set[str]:
    """Return finding URL paths that are already validated/rejected/reported.

    This is an egress guard for AI-facing next actions. It does not delete raw
    surface; it only prevents old finalized findings from steering startup.
    """
    path = Path(repo_root) / "findings" / target_storage_key(resolved_target) / "findings.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    paths: set[str] = set()
    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        validation_status = str(item.get("validation_status") or "").strip().lower()
        report_status = str(item.get("report_status") or "").strip().lower()
        if validation_status not in {"validated", "rejected"} and report_status != "generated":
            continue
        provenance = verify_finalized_finding_owner_provenance(
            path.parent,
            item,
            target=resolved_target,
        )
        if not provenance.get("valid"):
            # Direct JSON lifecycle claims must not hide a resume target.  The
            # structured state projects them as owner-revalidation candidates.
            continue
        endpoint_path = _normalise_endpoint_path(str(item.get("url") or item.get("endpoint") or ""))
        # Hash-route findings normalize to root; never hide the entire SPA root.
        if endpoint_path and endpoint_path != "/":
            paths.add(endpoint_path)
    return paths


def _is_placeholder_surface(item: dict) -> bool:
    url = str(item.get("url") or item.get("path") or "").strip()
    return _has_placeholder_object_segment(url)


def _filter_resume_targets_for_final_state(targets: list[str], finalized_paths: set[str]) -> list[str]:
    filtered: list[str] = []
    for target in targets:
        endpoint_path = _normalise_endpoint_path(target)
        if endpoint_path and endpoint_path in finalized_paths:
            continue
        if _has_placeholder_object_segment(target):
            continue
        filtered.append(target)
    return list(dict.fromkeys(filtered))[:3]


def _filter_ranked_placeholders(ranked: dict) -> dict:
    """只移除无法直接 replay 的占位对象，不按 finding/dead-end 隐藏 raw surface。"""
    filtered = dict(ranked or {})
    for key in ("review_pool", "p1", "p2"):
        items = ranked.get(key) or []
        filtered[key] = [
            item for item in items
            if isinstance(item, dict) and not _is_placeholder_surface(item)
        ]
    return filtered


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
    """Return advisory surface candidates; Claude chooses the final target."""
    host_status = {
        item.get("host", ""): item
        for item in guard_status.get("hosts", [])
        if item.get("host")
    }

    preferred = resume_targets or []
    recommended = []
    for index, item in enumerate(p1):
        status = host_status.get(item.get("host", ""), {})
        recommended.append({
            "url": item.get("url", ""),
            "host": item.get("host", ""),
            "suggested": item.get("suggested", ""),
            "score": item.get("score", 0),
            "review_reason": item.get("review_reason", ""),
            "review_index": index,
            "tripped": bool(status.get("tripped", False)),
            "remaining_seconds": float(status.get("remaining_seconds", 0.0) or 0.0),
            "matches_resume_target": _matches_resume_target(item.get("url", ""), preferred),
        })

    recommended.sort(
        key=lambda item: (
            item["tripped"],
            0 if (prefer_resume_targets and item["matches_resume_target"]) else 1,
            item["review_index"],
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
    validation_runner_next: dict | None = None,
    action_queue_next: dict | None = None,
    resume_targets: list[str] | None = None,
    recon_in_progress: bool = False,
    scan_in_progress: bool = False,
    recon_completed_no_live_hosts: bool = False,
    memory_candidate_next: dict | None = None,
    root_finding_claim_next: dict | None = None,
    fresh_recon_ready: bool = False,
    surface_context_required: bool = False,
) -> str:
    """Bias toward resumable session context before widening to surface review candidates."""
    structured_findings = structured_findings or {}
    resume_targets = resume_targets if resume_targets is not None else _build_resume_targets(resume_summary)
    # 活跃 phase gate 必须优先于 validation/report/surface，避免第二个 Claude
    # loop 重启或忽略仍持有 flock 的长任务。
    if recon_in_progress:
        return "wait_recon"
    if scan_in_progress:
        return "wait_scan"

    if structured_findings.get("next_owner_revalidation"):
        return "revalidate_finding_owner"
    next_validation = structured_findings.get("next_validation") or {}
    if next_validation:
        rubric = (
            next_validation.get("rubric")
            if isinstance(next_validation, dict)
            and isinstance(next_validation.get("rubric"), dict)
            else {}
        )
        # 旧状态可能没有 rubric；只在显式 non-ready 时改走补证据流程。
        if rubric and "ready" in rubric and not bool(rubric.get("ready")):
            return "collect_candidate_evidence"
        return "validate_finding"
    if root_finding_claim_next:
        # 根目录裸 JSON 是人工/AI 的临时 claim，不是 canonical lifecycle。
        # 它必须先补 locatable raw evidence 并由 checkpoint 归档为 candidate；
        # 不能因为 prose PoC 而直接被称为 validated。
        return "collect_candidate_evidence"
    if validation_runner_next:
        return "review_validation_candidate"
    if action_queue_next:
        return "resume_action_queue"
    if memory_candidate_next:
        # target memory 是兼容层，不是 durable owner。没有可定位原始证据时，
        # 它只能把下一会话带回补证据动作，不能直接把 prose 提升为 finding。
        if bool(memory_candidate_next.get("evidence_available")):
            return "validate_finding"
        return "collect_candidate_evidence"

    if not has_recon:
        if recon_completed_no_live_hosts:
            return "recon_no_live_hosts"
        return "run_recon"

    latest_session = (resume_summary or {}).get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]

    if latest_session and preview and resume_targets:
        return "continue_last_focus"
    if latest_session and resume_targets:
        return "resume_untested"

    if ranked.get("review_pool") or ranked.get("p1"):
        return "hunt_p1"
    if surface_context_required or fresh_recon_ready:
        return "prepare_surface_context"
    if resume_targets:
        return "resume_untested"
    if structured_findings.get("draft_completion_pending"):
        return "complete_report_draft"
    # A validated finding is a closure/report asset, not the steering wheel.
    # Surface/replay/resume work above should stay available when current
    # evidence exposes stronger live leads; otherwise keep the report visible.
    if structured_findings.get("validated_pending_report"):
        return "report_finding"
    return "handoff"


def _should_guard_safe_pivot(next_action: str, guard_status: dict) -> bool:
    """Return whether live probing should pause and cached-evidence work should continue."""
    if next_action in {
        "run_recon",
        "wait_recon",
        "wait_scan",
        "revalidate_finding_owner",
        "collect_candidate_evidence",
        "validate_finding",
        "review_validation_candidate",
        "resume_action_queue",
        "prepare_surface_context",
        "complete_report_draft",
        "recon_no_live_hosts",
        "report_finding",
        "run_intel",
        "collect_web_intel",
        "test_advisory_applicability",
    }:
        return False
    tracked = int(guard_status.get("tracked_hosts", 0) or 0)
    tripped = int(guard_status.get("tripped_hosts", 0) or 0)
    ready = int(guard_status.get("ready_hosts", 0) or 0)
    return tracked > 0 and tripped > 0 and ready == 0


def _describe_next_step(state: dict) -> str:
    """Render a human-friendly next-step hint from the computed state."""
    action = state.get("next_action", "")
    target = state.get("target", "target")
    resume_targets = state.get("resume_targets", []) or []
    surface_review_candidates = (
        state.get("surface_review_candidates")
        or state.get("recommended_targets", [])
        or []
    )
    tripped_hosts = (state.get("guard_status", {}) or {}).get("tripped_hosts", []) or []
    recon_artifacts = state.get("recon_artifacts") or {}

    if action == "run_recon":
        missing = recon_artifacts.get("missing") or []
        if recon_artifacts.get("available") and missing:
            return f"rerun /recon {target}; cached recon is incomplete ({', '.join(missing[:2])})."
        return f"run /recon {target} first."
    if action == "wait_recon":
        return (
            f"wait/poll the existing /recon {target} run; do not launch another recon. "
            "Refresh state after the matching recon phase lock releases."
        )
    if action == "wait_scan":
        return (
            f"wait/poll the existing scan-only quick run for {target}; do not launch another "
            "scan-only quick. Refresh state after the matching scan phase lock releases."
        )
    if action == "revalidate_finding_owner":
        finding = (state.get("structured_findings") or {}).get("next_owner_revalidation") or {}
        return (
            "finding {id} claims {validation}/{report} without valid owner provenance "
            "({reason}); treat it only as a candidate, replay locatable raw evidence, then rerun "
            "/validate with its canonical id so finding_index records the lifecycle mutation. "
            "Do not report or suppress the endpoint from the claim alone."
        ).format(
            id=finding.get("id", "-"),
            validation=finding.get("claimed_validation_status", "-"),
            report=finding.get("claimed_report_status", "-"),
            reason=finding.get("provenance_reason", "owner-provenance-invalid"),
        )
    if action == "collect_candidate_evidence":
        followup = (state.get("structured_findings") or {}).get("next_validation") or {}
        memory_candidate = state.get("memory_candidate_next") or {}
        root_claim = state.get("root_finding_claim_next") or {}
        candidate = followup if followup else (root_claim if root_claim else memory_candidate)
        rubric = followup.get("rubric") if isinstance(followup.get("rubric"), dict) else {}
        missing = [
            str(item).strip()
            for item in (rubric.get("missing_labels") or [])[:3]
            if str(item).strip()
        ]
        evidence_step = next(
            (
                str(item).strip()
                for item in rubric.get("next_actions") or []
                if str(item).strip()
            ),
            "fill the first missing candidate evidence item",
        )
        if followup:
            return (
                "collect candidate evidence for finding {id} on {url}; rubric={status}, "
                "missing={missing}. Next evidence step: {step}. Rerun state before /validate.".format(
                    id=candidate.get("id", "-"),
                    url=candidate.get("url", ""),
                    status=rubric.get("status", "needs-evidence"),
                    missing=", ".join(missing) or "candidate evidence",
                    step=evidence_step,
                )
            )
        if root_claim:
            return (
                "inspect root JSON finding claim {id} at {source}; capture locatable raw "
                "request/response and run /checkpoint to reconcile it as a candidate. "
                "Missing fields: {missing}. Do not call it validated or report-ready "
                "from the claim alone. Never invent an endpoint from the target root."
            ).format(
                id=root_claim.get("id", "-"),
                source=root_claim.get("source_file", ""),
                missing=", ".join(str(item) for item in (root_claim.get("incomplete_fields") or []))
                or "none",
            )
        return (
            "collect raw request/response or a locatable evidence_ref for target-memory "
            "candidate {id}; do not call /validate from prose alone. Candidate: {action}".format(
                id=candidate.get("id", "-"),
                action=candidate.get("action", ""),
            )
        )
    if action == "validate_finding":
        followup = (state.get("structured_findings") or {}).get("next_validation") or {}
        if followup:
            return f"validate structured finding {followup.get('id')} on {followup.get('url')}."
        memory_candidate = state.get("memory_candidate_next") or {}
        if memory_candidate:
            return (
                "validate target-memory candidate {id} after reviewing its linked raw evidence: {action}."
            ).format(
                id=memory_candidate.get("id", "-"),
                action=memory_candidate.get("action", ""),
            )
        return "validate the highest-priority structured finding."
    if action == "review_validation_candidate":
        candidate = state.get("validation_runner_next") or {}
        if candidate:
            return (
                f"review validation-runner candidate {candidate.get('id')}; inspect raw evidence, "
                "then use /validate or record a ledger downgrade."
            )
        return "review the next validation-runner candidate before starting another long phase."
    if action == "resume_action_queue":
        item = state.get("action_queue_next") or {}
        if item:
            return f"resume durable action {item.get('id')}: {item.get('action') or item.get('command_hint')}."
        return "resume the highest-priority substantive durable action."
    if action == "recon_no_live_hosts":
        return (
            "recon completed with no live hosts; review cached infra/exposure/offline evidence "
            "and record the blocker. Explicit refresh, stale artifacts, or contradictory fresh "
            "evidence is required; do not rerun recon automatically."
        )
    if action == "run_intel":
        continuation = state.get("intel_continuation") or {}
        return (
            "run /intel for the current software/service inventory before continuing generic "
            f"hunting; reason: {continuation.get('reason', 'Intel artifact is missing or stale')}."
        )
    if action == "collect_web_intel":
        continuation = state.get("intel_continuation") or {}
        recommended = continuation.get("recommended") or []
        subject = str((recommended[0] if recommended else {}).get("subject") or "the top Intel gap")
        return (
            f"collect and record provider-neutral Web Intel for {subject}; verify selected source "
            "bodies, then rerun /intel so the bounded claim projection is merged."
        )
    if action == "test_advisory_applicability":
        advisory = (state.get("intel_continuation") or {}).get("advisory") or {}
        component = advisory.get("component") if isinstance(advisory.get("component"), dict) else {}
        return (
            "test target reachability and version applicability for {id} on {name}@{version}; "
            "preserve raw evidence and resolve the durable action before moving on."
        ).format(
            id=advisory.get("id", "the top advisory"),
            name=component.get("name", "component"),
            version=component.get("version") or "unknown",
        )
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
    if action == "guard_safe_pivot":
        return (
            "all tracked live hosts are cooling down or locked; continue automatically "
            "with cached recon/browser/JS/source evidence, context-pack, checkpoint, and "
            "coverage updates. Do not use IP rotation, WAF evasion, or social engineering."
        )
    if action == "hunt_p1":
        if surface_review_candidates:
            first_item = surface_review_candidates[0]
            first = first_item["url"]
            if first_item.get("tripped"):
                return (
                    f"the top advisory surface host is cooling down; prefer another surface until cooldown clears: "
                    f"{first}."
                )
            if tripped_hosts:
                return f"review the top ready surface candidate while other hosts cool down: {first}."
            return f"review the top surface candidate, then choose the next evidence step: {first}."
        return "review the surface candidates, then choose the next evidence step."
    if action == "hunt_p2":
        return "widen into follow-up surface hints after first-review candidates are exhausted."
    if action == "prepare_surface_context":
        return (
            "recon is ready but has no ranked replay candidate yet; run /surface and context-pack "
            "from the cached recon, then select the smallest evidence-producing hunt action."
        )
    if action == "complete_report_draft":
        draft = (state.get("structured_findings") or {}).get("next_draft_completion") or {}
        return (
            "complete report draft for validated finding {id} from its linked raw evidence; "
            "replace all placeholders before report generation, without reopening the validated replay. "
            "Draft: {path}".format(
                id=draft.get("id", "-"),
                path=draft.get("report_draft_path", ""),
            )
        )
    if action == "refresh_recon":
        return f"refresh recon before going deeper on {target}."
    if action == "handoff":
        return "no strong executable next action from cached state; use checkpoint or fresh evidence before continuing."
    return "follow the highest-confidence target shown below."


def _runtime_recon_in_progress(
    repo_root: str,
    target: str,
    runtime_state: dict,
    *,
    stale_after_seconds: int = 7200,
) -> bool:
    """兼容现有调用点的 shared runtime-state gate 包装。"""
    return runtime_phase_in_progress(
        repo_root,
        target,
        "recon",
        runtime_state,
        stale_after_seconds=stale_after_seconds,
    )


def _runtime_scan_in_progress(
    repo_root: str,
    target: str,
    runtime_state: dict,
    *,
    stale_after_seconds: int = 7200,
) -> bool:
    """兼容现有调用点的 shared runtime-state gate 包装。"""
    return runtime_phase_in_progress(
        repo_root,
        target,
        "scan",
        runtime_state,
        stale_after_seconds=stale_after_seconds,
    )


def _candidate_items_for_next_action(ranked: dict, next_action: str) -> list[dict]:
    if next_action == "hunt_p2":
        return ranked.get("p2", []) or []
    return ranked.get("review_pool", []) or ranked.get("p1", []) or []

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
            f"all tracked hot hosts are cooling down: {cooling}; do not rotate IPs, "
            f"evade detection, or use social engineering. Pivot to cached recon/browser/JS/source "
            f"artifacts, context-pack, checkpoint, and coverage updates until cooldown clears"
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
    "openapi_specs",
    "openapi_operations",
    "openapi_public_operations",
    "openapi_auth_boundary_candidates",
    "platform_metadata",
    "cloud_storage_candidates",
    "s3_bucket_candidates",
    "external_service_hosts",
    "host_pivot_candidates",
    "ai_asset_candidates",
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
        any(
            _count_value(counts, key) > 0
            for key in (
                "openapi_operations",
                "openapi_auth_boundary_candidates",
                "platform_metadata",
            )
        ),
        "api_specs/summary.md",
    )
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
        _count_value(counts, "host_pivot_candidates") > 0,
        "exposure/host_pivot_candidates.jsonl",
    )
    add_if(
        _count_value(counts, "ai_asset_candidates") > 0,
        "exposure/ai_asset_candidates.jsonl",
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
        "- OpenAPI semantics: "
        f"specs={_count_value(counts, 'openapi_specs')}, "
        f"operations={_count_value(counts, 'openapi_operations')}, "
        f"public_or_optional={_count_value(counts, 'openapi_public_operations')}, "
        f"auth_boundaries={_count_value(counts, 'openapi_auth_boundary_candidates')}, "
        f"platform_metadata={_count_value(counts, 'platform_metadata')}"
    )
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
    lines.append(
        "- Routing candidates: "
        f"host_pivot={_count_value(counts, 'host_pivot_candidates')}, "
        f"ai_asset={_count_value(counts, 'ai_asset_candidates')}"
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
    if next_action in {
        "run_recon",
        "wait_recon",
        "wait_scan",
        "revalidate_finding_owner",
        "collect_candidate_evidence",
        "validate_finding",
        "review_validation_candidate",
        "resume_action_queue",
        "prepare_surface_context",
        "complete_report_draft",
        "recon_no_live_hosts",
        "report_finding",
        "run_intel",
        "collect_web_intel",
        "test_advisory_applicability",
    }:
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
    if next_action == "guard_safe_pivot":
        if repo_source_available and not source_intel_ready:
            hints.append({
                "tool": "run_source_intel",
                "reason": "live hosts are cooling down; source artifacts can still produce offline hypotheses",
            })
        if not js_intel_ready and _has_js_read_signal(recon_dir, surface_context):
            hints.append({
                "tool": "run_js_read",
                "reason": "live hosts are cooling down; cached JS can still produce endpoint and parameter leads",
            })
        hints.extend([
            {
                "tool": "context_pack",
                "reason": "select the safest cached-evidence route while live requests are paused",
            },
            {
                "tool": "checkpoint",
                "reason": "record the live lockout as blocked and preserve concrete next actions",
            },
        ])
        next_tool_hint = hints[0]["tool"] if hints else ""
        return next_tool_hint, hints

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


_NUCLEI_ACTION_RE = re.compile(r"\bnuclei\b", re.IGNORECASE)
_RAW_NUCLEI_CORPUS_RE = re.compile(
    r"(?:"
    r"\ball_historical\.txt\b|"
    r"\ball\.txt\b|"
    r"\bwith_params\.txt\b|"
    r"\b(?:gau|wayback|waymore)(?:urls)?\.txt\b|"
    r"\b(?:raw|historical)\s+(?:urls?|corpus|archive)\b|"
    r"\b(?:gau|wayback|waymore)\s+urls?\b|"
    r"历史\s*(?:URL|url|链接|语料|全集)"
    r")",
    re.IGNORECASE,
)


def _memory_nuclei_action_requires_replan(text: str) -> bool:
    """识别违反 broad-scanner 输入契约的旧 Nuclei 建议。"""
    value = str(text or "")
    return bool(_NUCLEI_ACTION_RE.search(value) and _RAW_NUCLEI_CORPUS_RE.search(value))


_MEMORY_EVIDENCE_REF_RE = re.compile(
    r"\b(?:evidence(?:_ref)?|raw_(?:request|response|artifact)(?:_path)?)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)


def _memory_evidence_ref(text: str) -> str:
    """Extract one explicit artifact pointer from legacy target-memory prose.

    Target memory is intentionally human-readable and is not a second evidence
    schema.  This narrow compatibility parser only recognises an explicit
    ``Evidence=...``/``evidence_ref=...`` token emitted by checkpoint helpers.
    Unknown prose remains evidence-missing and therefore cannot promote itself.
    """
    match = _MEMORY_EVIDENCE_REF_RE.search(str(text or ""))
    if not match:
        return ""
    return match.group(1).strip().strip("'\"").rstrip(".,;:)]}")


def _memory_evidence_available(repo_root: str | Path | None, evidence_ref: str) -> bool:
    """Return whether a legacy memory artifact pointer resolves on disk."""
    if not repo_root or not evidence_ref:
        return False
    path = Path(evidence_ref)
    if not path.is_absolute():
        path = Path(repo_root) / path
    try:
        return path.exists()
    except OSError:
        return False


def _build_memory_action_queue(
    target_goal_memory: dict,
    *,
    repo_root: str | Path | None = None,
) -> list[dict]:
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
        evidence_ref = _memory_evidence_ref(text)
        entry = {
            "id": f"M{idx}",
            "source": "target_memory",
            "action": text,
            "command_hint": _memory_action_hint(text),
        }
        if _memory_nuclei_action_requires_replan(text):
            entry.update(
                {
                    "status": "requires_replan",
                    "executable": False,
                    "command_hint": (
                        "use tools/hunt.py --target <target> --scan-only --quick for broad coverage, "
                        "or build an evidence-driven targeted list with explicit tags/templates"
                    ),
                    "replan_reason": "raw historical URL corpora are not general Nuclei inputs",
                }
            )
        if evidence_ref:
            entry["evidence_ref"] = evidence_ref
            entry["evidence_available"] = _memory_evidence_available(repo_root, evidence_ref)
        else:
            entry["evidence_available"] = False
        queue.append(entry)
    return queue


def _select_memory_candidate(memory_action_queue: list[dict]) -> dict:
    """Return the highest-priority legacy `/validate` handoff, if any.

    A durable action queue and structured finding remain authoritative.  This
    is only a recovery bridge for targets produced before checkpoint CLI queue
    synchronisation existed.
    """
    for item in memory_action_queue:
        if item.get("executable") is False:
            continue
        if str(item.get("command_hint") or "") == "/validate":
            return item
    return {}


def _is_substantive_queue_action(item: dict) -> bool:
    """仅让已有证据状态或明确 replay 命令抢占 fresh recon。"""
    status = str(item.get("status") or "queued").strip().lower()
    if status in {"running", "signal", "candidate"}:
        return True
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    command = " ".join(
        str(value or "").strip()
        for value in (
            item.get("command_hint"),
            metadata.get("replay_draft"),
        )
    ).strip()
    return command.startswith(("python3 ", "/validate ", "curl ", "playwright-cli "))


def _load_substantive_action_queue_next(repo_root: str, target: str) -> dict:
    """复用 action_queue 的公开 selector，不复制其排序与去重规则。"""
    selected = select_next_action(load_queue(repo_root, target))
    if not isinstance(selected, dict) or not _is_substantive_queue_action(selected):
        return {}
    return selected


def _recon_completed_without_live_hosts(
    runtime_state: dict,
    recon_artifacts: dict,
    *,
    recon_in_progress: bool,
) -> bool:
    """识别已退出 recon 长阶段、但没有 HTTP live inventory 的终态。"""
    if recon_in_progress:
        return False
    if not recon_artifacts.get("available") or recon_artifacts.get("host_inventory_ready"):
        return False
    workflow = str(runtime_state.get("last_executed_workflow") or "").strip()
    # 没有完成 breadcrumb 时仍允许首次/损坏缓存执行一次 recon；所有 started
    # marker 都由 runtime gate 负责，不能误判成完成。
    return bool(workflow and not workflow.endswith("_started"))


def _fresh_recon_needs_surface_context(
    runtime_state: dict,
    *,
    has_recon: bool,
    has_memory: bool,
    recon_in_progress: bool,
) -> bool:
    """Identify the one-shot fresh recon -> surface/context handoff.

    A completed fresh recon can legitimately have only a live host inventory.
    Returning generic ``handoff`` in that state makes the next Claude session
    infer the continuation from prose.  Restrict this branch to the immediate
    recon breadcrumb so genuinely exhausted existing targets still hand off.
    """
    if not has_recon or has_memory or recon_in_progress:
        return False
    workflow = str(runtime_state.get("last_executed_workflow") or "").strip().lower()
    mode = str(runtime_state.get("mode") or "").strip().lower()
    return workflow in {"run_recon", "recon"} or mode == "recon_only"


def _read_batch_lines(path: Path) -> list[str]:
    """Read a small batch index file with stable de-duplication."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    values = []
    for line in lines:
        value = line.strip().strip("\ufeff").rstrip("/").lower()
        if value.startswith("*."):
            value = value[2:]
        if value:
            values.append(value)
    return list(dict.fromkeys(values))


def _read_batch_manifest_completed(path: Path) -> list[str]:
    """Recover completed domains from JSONL when the compact list is absent."""
    completed = []
    try:
        handle = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return completed
    with handle:
        for raw in handle:
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or item.get("status") != "ok":
                continue
            target = str(item.get("target") or "").strip().rstrip("/").lower()
            if target.startswith("*."):
                target = target[2:]
            if target:
                completed.append(target)
    return list(dict.fromkeys(completed))


def _read_batch_ranked_targets(path: Path, completed: list[str]) -> list[dict]:
    """Return AI handoff candidates that are backed by completed recon."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = []
    completed_set = set(completed)
    ranked = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        target = str(item.get("target") or "").strip().rstrip("/").lower()
        if target.startswith("*."):
            target = target[2:]
        if target not in completed_set:
            continue
        try:
            score = int(item.get("score", 0) or 0)
        except (TypeError, ValueError):
            score = 0
        ranked.append({
            "target": target,
            "score": score,
            "top_signals": item.get("top_signals") or [],
            "recon_dir": str(item.get("recon_dir") or f"recon/{target_storage_key(target)}"),
        })
    ranked_targets = {item["target"] for item in ranked}
    ranked.extend(
        {
            "target": target,
            "score": 0,
            "top_signals": [],
            "recon_dir": f"recon/{target_storage_key(target)}",
        }
        for target in completed
        if target not in ranked_targets
    )
    return ranked


def _build_batch_autopilot_state(repo_root: str, target: str, resolved_target: str) -> dict:
    """Build the list-only recon/handoff state without treating the index as a target."""
    storage_key = target_storage_key(resolved_target)
    batch_dir = Path(repo_root) / "recon" / storage_key
    manifest_path = batch_dir / "batch_manifest.jsonl"
    current_entries = target_list_entries(resolved_target)
    current_set = set(current_entries)
    completed = _read_batch_lines(batch_dir / "completed_targets.txt")
    if not completed:
        completed = _read_batch_manifest_completed(manifest_path)
    completed = [item for item in completed if item in current_set]
    failed = _read_batch_lines(batch_dir / "failed_targets.txt")
    failed = [item for item in failed if item in current_set and item not in set(completed)]
    artifact_pending = _read_batch_lines(batch_dir / "pending_targets.txt")
    processed = set(completed) | set(failed)
    # 当前 list 是 batch identity。旧 pending 仅提供顺序提示，新加入的输入也必须
    # 进入本轮 pending，不能因为同 stem 的历史 artifact 被漏掉。
    pending = [
        item
        for item in dict.fromkeys([*artifact_pending, *current_entries])
        if item in current_set and item not in processed
    ]
    runtime_state = load_runtime_state(repo_root, resolved_target)
    recon_in_progress = _runtime_recon_in_progress(repo_root, resolved_target, runtime_state)
    candidates = _read_batch_ranked_targets(
        batch_dir / "high_value_targets.json",
        completed,
    )

    blocker = ""
    if not current_entries:
        next_action = "invalid_batch_target"
        blocker = "the current target list has no usable primary-domain entries"
    elif recon_in_progress:
        next_action = "wait_recon"
    elif candidates:
        next_action = "select_completed_domain"
    elif not pending and failed:
        next_action = "batch_failed"
        blocker = "all current batch entries failed and no pending target remains"
    else:
        next_action = "run_batch_recon"

    return {
        "target": target,
        "resolved_target": resolved_target,
        "target_kind": "list",
        "has_recon": bool(completed),
        "has_memory": False,
        "runtime_state": runtime_state,
        "recon_in_progress": recon_in_progress,
        "scan_in_progress": False,
        "next_action": next_action,
        "batch": {
            "batch_dir": str(batch_dir),
            "manifest": str(manifest_path),
            "summary": str(batch_dir / "batch_summary.md"),
            "ai_handoff": str(batch_dir / "ai_handoff.md"),
            "surface_ranking": str(batch_dir / "surface_ranking.txt"),
            "high_value_targets": str(batch_dir / "high_value_targets.json"),
            "current_entries": current_entries,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "candidates": candidates,
            "blocker": blocker,
        },
    }


def _load_autopilot_control_facts(
    repo_root: str,
    resolved_target: str,
    resolved_memory_dir: str,
    *,
    fast_recon: bool,
) -> dict:
    """一次性读取 next-action 所需控制事实。

    Bootstrap 使用 ``fast_recon=True``，因此这里只 stat recon artifact，且
    finding reader 禁止 legacy migration。完整诊断路径复用同一事实集合，
    但保留精确 recon 计数。
    """
    resume_summary = load_resume_summary(resolved_memory_dir, resolved_target)
    finalized_paths = _finalized_finding_paths(repo_root, resolved_target)
    guard_status = load_guard_status(resolved_memory_dir, resolved_target)
    tripped_hosts = [item for item in guard_status.get("hosts", []) if item.get("tripped")]
    repo_source_artifacts = list_repo_source_artifacts(repo_root, resolved_target)
    repo_source_available = bool(repo_source_artifacts)
    repo_source_summary = (
        load_repo_source_summary(repo_root, resolved_target)
        if repo_source_available
        else {}
    )
    structured_findings = load_structured_finding_followup(
        repo_root,
        resolved_target,
        migrate_legacy=False,
    )
    root_finding_claims = list_root_finding_claims(
        Path(repo_root) / "findings" / target_storage_key(resolved_target),
        target=resolved_target,
    )
    root_finding_claim_next = root_finding_claims[0] if root_finding_claims else {}
    validation_runner_candidates = load_validation_runner_candidate_pool(
        repo_root,
        resolved_target,
    )
    validation_runner_next = (
        validation_runner_candidates[0]
        if validation_runner_candidates
        else {}
    )
    action_queue_next = _load_substantive_action_queue_next(repo_root, resolved_target)
    runtime_state = load_runtime_state(repo_root, resolved_target)
    recon_artifacts = (
        inspect_recon_artifacts_fast(repo_root, resolved_target)
        if fast_recon
        else inspect_recon_artifacts(repo_root, resolved_target)
    )
    recon_in_progress = (
        _runtime_recon_in_progress(repo_root, resolved_target, runtime_state)
        and not bool(recon_artifacts.get("ready"))
    )
    scan_in_progress = _runtime_scan_in_progress(repo_root, resolved_target, runtime_state)
    recon_completed_no_live_hosts = _recon_completed_without_live_hosts(
        runtime_state,
        recon_artifacts,
        recon_in_progress=recon_in_progress,
    )
    target_goal_memory = load_target_goal_memory(repo_root, resolved_target)
    has_recon = bool(recon_artifacts.get("host_inventory_ready"))
    has_memory = resume_summary is not None
    fresh_recon_ready = _fresh_recon_needs_surface_context(
        runtime_state,
        has_recon=has_recon,
        has_memory=has_memory,
        recon_in_progress=recon_in_progress,
    )
    resume_targets = _filter_resume_targets_for_final_state(
        _build_resume_targets(resume_summary),
        finalized_paths,
    )
    recent_guard_advisories = list(
        (resume_summary or {}).get("recent_guard_advisories")
        or (resume_summary or {}).get("recent_guard_blocks", [])
        or []
    )
    memory_action_queue = _build_memory_action_queue(
        target_goal_memory,
        repo_root=repo_root,
    )
    intel_continuation = inspect_intel_continuation(repo_root, resolved_target)
    return {
        "repo_root": repo_root,
        "resolved_target": resolved_target,
        "resolved_memory_dir": resolved_memory_dir,
        "resume_summary": resume_summary,
        "guard_status": guard_status,
        "tripped_hosts": tripped_hosts,
        "repo_source_artifacts": repo_source_artifacts,
        "repo_source_available": repo_source_available,
        "repo_source_summary": repo_source_summary,
        "structured_findings": structured_findings,
        "root_finding_claims": root_finding_claims,
        "root_finding_claim_next": root_finding_claim_next,
        "validation_runner_candidates": validation_runner_candidates,
        "validation_runner_next": validation_runner_next,
        "action_queue_next": action_queue_next,
        "runtime_state": runtime_state,
        "recon_artifacts": recon_artifacts,
        "recon_in_progress": recon_in_progress,
        "scan_in_progress": scan_in_progress,
        "recon_completed_no_live_hosts": recon_completed_no_live_hosts,
        "target_goal_memory": target_goal_memory,
        "has_recon": has_recon,
        "has_memory": has_memory,
        "fresh_recon_ready": fresh_recon_ready,
        "resume_targets": resume_targets,
        "recent_guard_advisories": recent_guard_advisories,
        "memory_action_queue": memory_action_queue,
        "memory_candidate_next": _select_memory_candidate(memory_action_queue),
        "intel_continuation": intel_continuation,
    }


def _build_domain_autopilot_state(
    target: str,
    facts: dict,
    ranked: dict,
    *,
    observation_inventory: dict,
    surface_projection: dict,
    surface_context: dict | None = None,
    surface_context_required: bool = False,
    include_enrichment: bool = True,
) -> dict:
    """由共享控制事实和一个 surface 视图生成兼容 state。"""
    resolved_target = str(facts["resolved_target"])
    resolved_memory_dir = str(facts["resolved_memory_dir"])
    ranked_for_next = _filter_ranked_placeholders(ranked)
    resume_summary = facts.get("resume_summary")
    has_recon = bool(facts.get("has_recon"))
    guard_status = facts.get("guard_status") or {}
    tripped_hosts = facts.get("tripped_hosts") or []
    resume_targets = facts.get("resume_targets") or []

    tech_stack = []
    if resume_summary and resume_summary.get("tech_stack"):
        tech_stack = resume_summary["tech_stack"]
    elif has_recon:
        review_pool = ranked_for_next.get("review_pool", []) or ranked_for_next.get("p1", [])
        if review_pool:
            tech_stack = review_pool[0].get("tech_stack", [])

    primary_next_action = _pick_next_action(
        has_recon,
        ranked_for_next,
        resume_summary,
        facts.get("structured_findings"),
        facts.get("validation_runner_next"),
        facts.get("action_queue_next"),
        resume_targets=resume_targets,
        recon_in_progress=bool(facts.get("recon_in_progress")),
        scan_in_progress=bool(facts.get("scan_in_progress")),
        recon_completed_no_live_hosts=bool(facts.get("recon_completed_no_live_hosts")),
        memory_candidate_next=facts.get("memory_candidate_next"),
        root_finding_claim_next=facts.get("root_finding_claim_next"),
        # fresh-recon handoff only requests surface preparation while no exact
        # projection exists. A valid empty/low-value projection is still a
        # completed review, otherwise bootstrap can loop on refresh forever.
        fresh_recon_ready=(
            bool(facts.get("fresh_recon_ready"))
            and surface_projection.get("status") != "valid"
        ),
        surface_context_required=surface_context_required,
    )
    intel_continuation = facts.get("intel_continuation") or {}
    next_action = apply_intel_continuation(primary_next_action, intel_continuation)
    surface_review_candidates = (
        _build_recommended_targets(
            _candidate_items_for_next_action(ranked_for_next, next_action),
            guard_status,
            resume_targets,
            prefer_resume_targets=next_action == "continue_last_focus",
        )
        if has_recon and next_action not in {
            "run_intel",
            "collect_web_intel",
            "test_advisory_applicability",
        }
        else []
    )
    guard_state = {
        "tracked_hosts": guard_status.get("tracked_hosts", 0),
        "ready_hosts": guard_status.get("ready_hosts", 0),
        "tripped_hosts": tripped_hosts,
        "settings": guard_status.get("settings", {}),
    }
    if has_recon and _should_guard_safe_pivot(next_action, guard_status):
        next_action = "guard_safe_pivot"
    pivot_hint = _build_pivot_hint(
        tripped_hosts=tripped_hosts,
        recent_guard_advisories=facts.get("recent_guard_advisories") or [],
        repo_source_summary=facts.get("repo_source_summary") or {},
    )
    if include_enrichment:
        next_tool_hint, enrichment_hints = _build_enrichment_hints(
            repo_root=str(facts["repo_root"]),
            resolved_target=resolved_target,
            surface_context=surface_context or {},
            ranked=ranked_for_next,
            repo_source_available=bool(facts.get("repo_source_available")),
            next_action=next_action,
        )
    else:
        next_tool_hint, enrichment_hints = "", []
    if next_action in {"run_intel", "collect_web_intel", "test_advisory_applicability"}:
        next_tool_hint = next_action
        enrichment_hints = [{
            "tool": next_action,
            "reason": str(intel_continuation.get("reason") or "software intelligence continuation"),
        }]

    recon_completed_no_live_hosts = bool(facts.get("recon_completed_no_live_hosts"))
    recent_guard_advisories = facts.get("recent_guard_advisories") or []
    return {
        "target": target,
        "resolved_target": resolved_target,
        "target_kind": classify_target(resolved_target)["kind"],
        "memory_dir": resolved_memory_dir,
        "has_recon": has_recon,
        "has_memory": bool(facts.get("has_memory")),
        "repo_source_available": bool(facts.get("repo_source_available")),
        "repo_source_artifacts": facts.get("repo_source_artifacts") or [],
        "repo_source_summary": facts.get("repo_source_summary") or {},
        "runtime_state": facts.get("runtime_state") or {},
        "recon_artifacts": facts.get("recon_artifacts") or {},
        "recon_in_progress": bool(facts.get("recon_in_progress")),
        "scan_in_progress": bool(facts.get("scan_in_progress")),
        "recon_completed_no_live_hosts": recon_completed_no_live_hosts,
        "fresh_recon_ready": bool(facts.get("fresh_recon_ready")),
        "recon_blocker": (
            "recon completed with no live host inventory"
            if recon_completed_no_live_hosts
            else ""
        ),
        "structured_findings": facts.get("structured_findings") or {},
        "root_finding_claims": facts.get("root_finding_claims") or [],
        "root_finding_claim_next": facts.get("root_finding_claim_next") or {},
        "validation_runner_candidates": facts.get("validation_runner_candidates") or [],
        "validation_runner_next": facts.get("validation_runner_next") or {},
        "action_queue_next": facts.get("action_queue_next") or {},
        "action_queue": {"next": facts.get("action_queue_next") or {}},
        "target_goal_memory": facts.get("target_goal_memory") or {},
        "memory_candidate_next": facts.get("memory_candidate_next") or {},
        "resume_summary": resume_summary,
        "surface": ranked_for_next if has_recon else None,
        "surface_projection": surface_projection,
        "observation_inventory": observation_inventory,
        "guard_status": guard_state,
        "guard_hint": _build_guard_hint(guard_state, surface_review_candidates),
        "pivot_hint": pivot_hint,
        "tech_stack": tech_stack,
        "next_action": next_action,
        "primary_next_action": primary_next_action,
        "intel_continuation": intel_continuation,
        "next_tool_hint": next_tool_hint,
        "enrichment_hints": enrichment_hints,
        "memory_action_queue": facts.get("memory_action_queue") or [],
        "resume_targets": resume_targets,
        "surface_review_candidates": surface_review_candidates,
        "recommended_targets": surface_review_candidates,
        "recent_guard_advisories": recent_guard_advisories[:3],
        "recent_guard_blocks": recent_guard_advisories[:3],
    }


def build_autopilot_bootstrap_state(
    repo_root: str,
    target: str,
    memory_dir: str | None = None,
) -> dict:
    """构建 slash expansion 专用的严格只读、bounded state。"""
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    resolved_target = canonical_target_value(target)
    if classify_target(resolved_target)["kind"] == "list":
        # Bootstrap 不执行 legacy storage migration；显式 owner 命令负责迁移。
        return _build_batch_autopilot_state(repo_root, target, resolved_target)

    facts = _load_autopilot_control_facts(
        repo_root,
        resolved_target,
        resolved_memory_dir,
        fast_recon=True,
    )
    observation_inventory = peek_inventory_summary(repo_root, resolved_target)
    projection = load_surface_projection(
        repo_root,
        resolved_target,
        memory_dir=resolved_memory_dir,
    )
    if projection.get("status") == "valid":
        ranked = dict(projection.get("surface") or {})
        ranked["available"] = bool(facts.get("has_recon"))
        ranked["target"] = resolved_target
        ranked["runtime_state"] = facts.get("runtime_state") or {}
        ranked["recon_artifacts"] = facts.get("recon_artifacts") or {}
        ranked["observation_inventory"] = observation_inventory
    else:
        ranked = {
            "available": bool(facts.get("has_recon")),
            "target": resolved_target,
            "runtime_state": facts.get("runtime_state") or {},
            "recon_artifacts": facts.get("recon_artifacts") or {},
            "observation_inventory": observation_inventory,
            "p1": [],
            "p2": [],
            "review_pool": [],
        }

    return _build_domain_autopilot_state(
        target,
        facts,
        ranked,
        observation_inventory=observation_inventory,
        surface_projection={
            "status": str(projection.get("status") or "invalid"),
            "reason": str(projection.get("reason") or ""),
            "path": str(projection.get("path") or ""),
            "refresh_command": f"python3 tools/surface.py --target {resolved_target} --refresh",
        },
        surface_context_required=(
            bool(facts.get("has_recon")) and projection.get("status") != "valid"
        ),
        include_enrichment=False,
    )


def build_autopilot_state(
    repo_root: str,
    target: str,
    memory_dir: str | None = None,
    *,
    bounded: bool = False,
) -> dict:
    """Build an autopilot state; bounded mode never rebuilds the full surface."""
    if bounded:
        return build_autopilot_bootstrap_state(repo_root, target, memory_dir=memory_dir)
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    resolved_target = canonical_target_value(target)
    if classify_target(resolved_target)["kind"] == "list":
        migrate_legacy_list_storage(repo_root, resolved_target)
        return _build_batch_autopilot_state(repo_root, target, resolved_target)
    facts = _load_autopilot_control_facts(
        repo_root,
        resolved_target,
        resolved_memory_dir,
        fast_recon=False,
    )
    projection = load_surface_projection(
        repo_root,
        resolved_target,
        memory_dir=resolved_memory_dir,
    )
    if projection.get("status") == "valid":
        # 完整诊断保留精确 recon metadata，但 surface 候选复用同一 exact-hit
        # projection，避免 checkpoint/context-pack 在同一 fingerprint 上重排。
        ranked = dict(projection.get("surface") or {})
        ranked["available"] = bool(facts.get("has_recon"))
        ranked["target"] = resolved_target
        ranked["runtime_state"] = facts.get("runtime_state") or {}
        ranked["recon_artifacts"] = facts.get("recon_artifacts") or {}
        surface_context = {
            "target": resolved_target,
            "available": bool(facts.get("has_recon")),
            "recon_dir": str(
                Path(repo_root) / "recon" / target_storage_key(resolved_target)
            ),
            "hosts": {},
            "js_endpoints": [],
        }
    else:
        # Legacy/missing cache compatibility：显式 full state 仍可重建；slash
        # bootstrap 永远不会走到这个无界 fallback。
        surface_context = load_surface_context(
            repo_root,
            resolved_target,
            memory_dir=resolved_memory_dir,
            write_probe_log=False,
        )
        ranked = rank_surface(surface_context)
    return _build_domain_autopilot_state(
        target,
        facts,
        ranked,
        observation_inventory=ranked.get("observation_inventory") or {},
        surface_projection={
            "status": str(projection.get("status") or "computed"),
            "reason": str(projection.get("reason") or ""),
            "path": str(projection.get("path") or ""),
        },
        surface_context=surface_context,
    )


def _format_durable_action_lines(item: dict) -> list[str]:
    """Format the selected persistent action without dumping the full queue."""
    if not item:
        return []
    lines = [
        "Durable action queue next:",
        f"- {item.get('id', '-')}: {item.get('action') or item.get('type') or ''}",
    ]
    command_hint = str(item.get("command_hint") or "").strip()
    if command_hint:
        lines.append(f"  Command: {command_hint}")
    return lines


def _format_root_finding_claim_lines(claims: list[dict]) -> list[str]:
    """Render unindexed root JSON claims without promoting their lifecycle."""
    if not claims:
        return []
    lines = ["Unreconciled root finding claims (not validated):"]
    for item in claims[:3]:
        missing = ", ".join(str(value) for value in (item.get("incomplete_fields") or []))
        lines.append(
            "- {id} [{severity}] {type} {url} source={source} missing={missing}; collect raw proof, "
            "then run /checkpoint to create the canonical candidate.".format(
                id=item.get("id", "-"),
                severity=item.get("severity", "medium"),
                type=item.get("type", "finding"),
                url=item.get("url", ""),
                source=item.get("source_file", ""),
                missing=missing or "none",
            )
        )
    return lines


def format_autopilot_state(state: dict) -> str:
    """Format autopilot bootstrap state for terminal display."""
    if state.get("target_kind") == "list":
        batch = state.get("batch") or {}
        lines = [
            f"AUTOPILOT BATCH STATE: {state['target']}",
            "═══════════════════════════════════════",
            "",
            f"Next Action: {state['next_action']}",
            f"Recon: {'in progress' if state.get('recon_in_progress') else 'idle'}",
            f"Current Inputs: {len(batch.get('current_entries') or [])}",
            f"Completed: {len(batch.get('completed') or [])}",
            f"Failed: {len(batch.get('failed') or [])}",
            f"Pending: {len(batch.get('pending') or [])}",
            f"AI Handoff: {batch.get('ai_handoff', '')}",
            f"Surface Ranking: {batch.get('surface_ranking', '')}",
            f"Manifest: {batch.get('manifest', '')}",
        ]
        blocker = str(batch.get("blocker") or "").strip()
        if blocker:
            lines.extend(["", f"Blocker: {blocker}"])
        if state.get("next_action") == "invalid_batch_target":
            lines.append("Stop: add at least one usable primary domain before batch recon.")
        elif state.get("next_action") == "batch_failed":
            lines.append("Stop: do not retry the failed batch automatically; review failure evidence or refresh explicitly.")
        candidates = batch.get("candidates") or []
        if candidates:
            lines.extend(["", "Completed-domain candidates:"])
            for index, item in enumerate(candidates[:10], 1):
                lines.append(
                    f"{index}. {item['target']} (score hint {item.get('score', 0)})"
                )
            lines.extend([
                "",
                "Select one completed domain, then rerun autopilot_state.py for that domain.",
                "Do not run surface, scan, or active hunting against the batch index.",
            ])
        return "\n".join(lines)

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
    surface = state.get("surface") or {}
    observation_inventory = (
        state.get("observation_inventory")
        or surface.get("observation_inventory")
        or {}
    )

    if not state["has_recon"]:
        if state.get("recon_in_progress"):
            recon_label = "in progress"
        elif state.get("recon_completed_no_live_hosts"):
            recon_label = "completed; no live hosts"
        else:
            recon_label = "missing"
        lines = [
            f"AUTOPILOT STATE: {state['target']}",
            "═══════════════════════════════════════",
            "",
            f"Recon: {recon_label}",
            f"Memory: {'available' if state['has_memory'] else 'missing'}",
            f"Next action: {state['next_action']}",
        ]
        runtime_workflow = str(
            runtime_state.get("last_executed_workflow")
            or runtime_state.get("current_stage")
            or ""
        ).strip()
        runtime_mode = str(runtime_state.get("mode", "") or "").strip()
        if runtime_workflow:
            lines.append(f"Last Workflow: {runtime_workflow}" + (f" (mode: {runtime_mode})" if runtime_mode else ""))
        if state.get("scan_in_progress"):
            lines.append("Scan: in progress")
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
        inventory_error = str(observation_inventory.get("error") or "").strip()
        if inventory_error:
            lines.append(f"Observation inventory warning: {inventory_error}")
        elif observation_inventory.get("available"):
            lines.append(
                "Observation inventory: "
                f"total={observation_inventory.get('total', 0)}, "
                f"untouched={observation_inventory.get('untouched', 0)}, "
                f"stale={observation_inventory.get('stale', 0)}"
            )
        memory_action_queue = state.get("memory_action_queue") or []
        if memory_action_queue:
            lines.append("Memory action queue:")
            for item in memory_action_queue[:5]:
                contract = ""
                if item.get("status"):
                    contract = (
                        f" | status: {item.get('status')}"
                        f" | executable: {str(item.get('executable', True)).lower()}"
                    )
                lines.append(
                    f"- {item.get('id', '-')}: {item.get('action', '')} "
                    f"| hint: {item.get('command_hint', '')}{contract}"
                )
        memory_candidate = state.get("memory_candidate_next") or {}
        if memory_candidate:
            evidence_state = "available" if memory_candidate.get("evidence_available") else "missing"
            lines.append(
                "Memory candidate fallback: {id} raw-evidence={evidence}".format(
                    id=memory_candidate.get("id", "-"),
                    evidence=evidence_state,
                )
            )
        lines.extend(_format_root_finding_claim_lines(state.get("root_finding_claims") or []))
        lines.extend(_format_durable_action_lines(state.get("action_queue_next") or {}))
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
        runner_candidate_lines = format_validation_runner_candidate_lines(
            state.get("validation_runner_candidates") or [],
            header="Validation runner candidates (advisory; require /validate before report):",
            limit=4,
        )
        if runner_candidate_lines:
            lines.extend(runner_candidate_lines)
        if recent_guard_advisories:
            lines.append("Recent guard advisories:")
            for item in recent_guard_advisories[:3]:
                details = _format_recent_guard_advisory(item)
                if details:
                    lines.append(f"- {details}")
        return "\n".join(lines) + "\n"

    lines = [
        f"AUTOPILOT STATE: {state['target']}",
        "═══════════════════════════════════════",
        "",
        f"Recon: ready",
        f"Memory: {'available' if state['has_memory'] else 'missing'}",
        f"Next action: {state['next_action']}",
        f"Next step: {_describe_next_step(state)}",
    ]
    if state.get("scan_in_progress"):
        lines.append("Scan: in progress")
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
            contract = ""
            if item.get("status"):
                contract = (
                    f" | status: {item.get('status')}"
                    f" | executable: {str(item.get('executable', True)).lower()}"
                )
            lines.append(
                f"- {item.get('id', '-')}: {item.get('action', '')} "
                f"| hint: {item.get('command_hint', '')}{contract}"
            )
    memory_candidate = state.get("memory_candidate_next") or {}
    if memory_candidate:
        evidence_state = "available" if memory_candidate.get("evidence_available") else "missing"
        lines.append(
            "Memory candidate fallback: {id} raw-evidence={evidence}".format(
                id=memory_candidate.get("id", "-"),
                evidence=evidence_state,
            )
        )
    lines.extend(_format_root_finding_claim_lines(state.get("root_finding_claims") or []))
    lines.extend(_format_durable_action_lines(state.get("action_queue_next") or {}))

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
    inventory_error = str(observation_inventory.get("error") or "").strip()
    if inventory_error:
        lines.append(f"Observation inventory warning: {inventory_error}")
    elif observation_inventory.get("available"):
        lines.append(
            "Observation inventory: "
            f"total={observation_inventory.get('total', 0)}, "
            f"untouched={observation_inventory.get('untouched', 0)}, "
            f"stale={observation_inventory.get('stale', 0)}, "
            f"reviewing={observation_inventory.get('reviewing', 0)}"
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

    runner_candidate_lines = format_validation_runner_candidate_lines(
        state.get("validation_runner_candidates") or [],
        header="Validation runner candidates (advisory; require /validate before report):",
        limit=4,
    )
    if runner_candidate_lines:
        lines.extend(runner_candidate_lines)

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

    lines.append(f"Surface review candidates: {surface.get('stats', {}).get('review_pool', 0)}")
    lines.append(f"Advisory first-review score hints: {surface.get('stats', {}).get('p1', 0)}")
    lines.append(f"Advisory follow-up score hints: {surface.get('stats', {}).get('p2', 0)}")

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

    surface_review_candidates = (
        state.get("surface_review_candidates")
        or state.get("recommended_targets")
        or []
    )
    if surface_review_candidates:
        lines.append("")
        lines.append("Surface review candidates (AI decides final priority):")
        for idx, item in enumerate(surface_review_candidates, 1):
            suffix = (
                f" [cooldown {item['remaining_seconds']:.1f}s]"
                if item.get("tripped")
                else ""
            )
            reason = f" [{item['review_reason']}]" if item.get("review_reason") else ""
            lines.append(
                f"{idx}. {item['url']} — {item['suggested']} (score hint {item['score']}){reason}{suffix}"
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
    parser.add_argument(
        "--bounded",
        action="store_true",
        help="Consume only compact projections and bounded control-plane state",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    state = build_autopilot_state(
        BASE_DIR,
        args.target,
        memory_dir=args.memory_dir or None,
        bounded=args.bounded,
    )
    if args.json:
        print(json.dumps(state, indent=2))
        return
    print(format_autopilot_state(state))


if __name__ == "__main__":
    main()
