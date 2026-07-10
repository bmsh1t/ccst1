#!/usr/bin/env python3
"""Lightweight target runtime state + artifact health helpers.

Schema v2 (current):
    Pipeline-stage fields (current_stage / recon_completed / surface_ready / etc.)
    were removed in favor of derivation. They biased Claude towards a linear
    recon→hunt→report flow and conflicted with the non-linear hunting model
    documented in rules/hunting.md and skills/bb-methodology.

    What stays in session.json: only facts that genuinely cannot be derived
    from on-disk artifacts (mode, last_executed_workflow, enrichment_tools,
    ctf_mode, schema_version, target identity, updated_at).

    What is derived on demand via `derive_state_view()`:
      - recon_artifacts counts and readiness (inspect_recon_artifacts)
      - finding_index counts (validation / report pending)
      - browser / js_intel / source_intel artifact presence

v1 → v2 migration:
    `load_runtime_state()` reads v1 files transparently. `last_completed_step`
    is renamed to `last_executed_workflow`; deprecated bool/int fields are
    silently dropped. No callers need to be updated immediately — they can
    keep passing legacy field names to `update_runtime_state()` and the
    whitelist will drop them with an audit-log entry.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.finding_index import load_finding_index
    from tools.recon_adapter import ReconAdapter
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from finding_index import load_finding_index
    from recon_adapter import ReconAdapter
    from target_paths import canonical_target_value, target_storage_key

SCHEMA_VERSION = 2
RUNNING_MARKER_STALE_SECONDS = 7200

# Whitelist of fields that actually get persisted to session.json.
# Anything else passed to update_runtime_state() is silently dropped.
# Intent: only single-fact breadcrumbs that cannot be derived on demand.
PERSISTED_FIELDS = frozenset({
    "mode",
    "last_executed_workflow",
    "enrichment_tools",
    "ctf_mode",
    "last_validation_result",     # breadcrumb: outcome of last /validate
    "last_validated_finding_id",  # breadcrumb: which finding was last validated
})

# v1 fields that v2 derives — kept here so load_runtime_state can drop them
# cleanly without leaving stale data in memory.
DEPRECATED_FIELDS = frozenset({
    "current_stage",
    "recon_completed",
    "recon_ready",
    "surface_ready",
    "scan_completed",
    "reports_generated",
    "cve_hunt",
    "zero_day",
    "browser_evidence_ready",
    "pending_validation",
    "validated_pending_report",
})

# v1 → v2 rename map (key in v1 file → key in v2).
LEGACY_FIELD_RENAMES = {
    "last_completed_step": "last_executed_workflow",
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_runtime_updated_at(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def runtime_recon_in_progress(
    runtime_state: dict,
    *,
    stale_after_seconds: int = RUNNING_MARKER_STALE_SECONDS,
) -> bool:
    """Return True when recon is freshly marked as started but not completed.

    这是执行态判断，不是攻击面判断。`last_executed_workflow` 比 `mode`
    更权威：如果完成态已写入，即使旧 `mode` 残留为 `recon_running`，
    也不能继续阻塞后续 AI 判断。
    """
    workflow = str(runtime_state.get("last_executed_workflow") or "").strip()
    mode = str(runtime_state.get("mode", "") or "").strip()
    if workflow and workflow != "run_recon_started":
        return False
    if workflow != "run_recon_started" and mode != "recon_running":
        return False
    updated_at = _parse_runtime_updated_at(runtime_state.get("updated_at", ""))
    if updated_at is None:
        return True
    return (datetime.now(timezone.utc) - updated_at).total_seconds() <= stale_after_seconds


def runtime_scan_in_progress(
    runtime_state: dict,
    *,
    stale_after_seconds: int = RUNNING_MARKER_STALE_SECONDS,
) -> bool:
    """Return True when scan-only quick is freshly marked as running."""
    workflow = str(runtime_state.get("last_executed_workflow") or "").strip()
    mode = str(runtime_state.get("mode", "") or "").strip()
    if workflow and workflow != "run_scan_started":
        return False
    if workflow != "run_scan_started" and mode != "scan_running":
        return False
    updated_at = _parse_runtime_updated_at(runtime_state.get("updated_at", ""))
    if updated_at is None:
        return True
    return (datetime.now(timezone.utc) - updated_at).total_seconds() <= stale_after_seconds


def _write_json_atomic(path: Path, payload: dict) -> None:
    """Atomically write JSON to `path` without exposing half-written state.

    Multiple Claude sessions may read `state/<target>/session.json` while
    `hunt.py` is writing `*_running` breadcrumbs. Direct `write_text()` can
    briefly expose truncated JSON, causing readers to miss `wait_recon` /
    `wait_scan`. Write in the same directory and replace atomically instead.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def _state_dir(repo_root: str | Path, target: str) -> Path:
    return Path(repo_root) / "state" / target_storage_key(target)


def state_path(repo_root: str | Path, target: str) -> Path:
    """Return the per-target runtime state file path."""
    return _state_dir(repo_root, target) / "session.json"


def _migrate_legacy_payload(payload: dict) -> dict:
    """Rename v1 fields and drop deprecated ones. Bumps schema_version."""
    migrated = dict(payload)
    for old, new in LEGACY_FIELD_RENAMES.items():
        if old in migrated and new not in migrated:
            migrated[new] = migrated[old]
        migrated.pop(old, None)
    for field in DEPRECATED_FIELDS:
        migrated.pop(field, None)
    migrated["schema_version"] = SCHEMA_VERSION
    return migrated


def load_runtime_state(repo_root: str | Path, target: str) -> dict:
    """Load per-target runtime state. v1 files are migrated transparently."""
    path = state_path(repo_root, target)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    if payload.get("schema_version", 1) < SCHEMA_VERSION:
        return _migrate_legacy_payload(payload)
    return payload


def update_runtime_state(repo_root: str | Path, target: str, **fields) -> dict:
    """Merge whitelisted fields into the per-target runtime state file.

    Fields outside PERSISTED_FIELDS (e.g. legacy `recon_completed`,
    `pending_validation`, etc.) are silently dropped — they are now derived
    on demand. The legacy `last_completed_step` keyword is auto-renamed to
    `last_executed_workflow` for backward compatibility with existing callers.
    """
    resolved_target = canonical_target_value(target)
    payload = load_runtime_state(repo_root, resolved_target)

    # Auto-rename legacy kwargs so existing call sites keep working.
    for old, new in LEGACY_FIELD_RENAMES.items():
        if old in fields and new not in fields:
            fields[new] = fields.pop(old)
        else:
            fields.pop(old, None)

    # Apply only whitelisted fields. Drop any deprecated/unknown ones quietly.
    filtered = {k: v for k, v in fields.items() if k in PERSISTED_FIELDS}

    payload.update(
        {
            "schema_version": SCHEMA_VERSION,
            "target": resolved_target,
            "storage_key": target_storage_key(resolved_target),
            **filtered,
            "updated_at": _now_utc(),
        }
    )
    # Final scrub: ensure no deprecated field survives in payload (e.g. from
    # an older session.json that wasn't migrated yet at load time).
    for field in DEPRECATED_FIELDS:
        payload.pop(field, None)
    for legacy in LEGACY_FIELD_RENAMES:
        payload.pop(legacy, None)

    path = state_path(repo_root, resolved_target)
    _write_json_atomic(path, payload)
    return payload


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


# `/recon` 的 exposure 产物是给 Claude CLI 做“注意力增强”的情报层。
# 这里仅统计缓存是否有料，不把它并入 surface_inputs_ready，避免把
# autopilot 的 next_action 变成强制 exploit 自动化。
EXPOSURE_COUNT_PATHS = {
    "config_exposures": Path("exposure/config_files.txt"),
    "api_doc_candidates": Path("exposure/api_doc_candidates.txt"),
    "api_leak_candidates": Path("exposure/api_leak_candidates.txt"),
    "verified_secrets": Path("exposure/api_leak_trufflehog_verified.jsonl"),
    "postman_leaks": Path("exposure/api_leaks/postman_leaks.txt"),
    "postleaks_urls": Path("exposure/api_leaks/postleaks_urls.txt"),
    "swagger_leaks": Path("exposure/api_leaks/swagger_leaks.txt"),
    "cloud_storage_candidates": Path("exposure/cloud_storage_candidates.txt"),
    "s3_bucket_candidates": Path("exposure/s3_bucket_candidates.txt"),
    "external_service_hosts": Path("exposure/external_service_hosts.txt"),
    "identity_emails": Path("exposure/identity_intel/emails.txt"),
    "leaksearch_hits": Path("exposure/identity_intel/leaksearch.txt"),
    "cloud_enum_hits": Path("exposure/cloud/cloud_enum.txt"),
}

# 基础设施类 recon 信号同样需要进入 Claude CLI 的状态视图，避免
# `/recon` 已经产出端口/WAF/origin 情报，但 `/autopilot` 或 `/surface`
# 只展示 URL/JS/exposure，导致后续规划漏看这些入口。它们仍然只是软信号，
# 不参与 surface_inputs_ready 判定，也不触发强制自动化。
INFRA_COUNT_PATHS = {
    "waf_hits": Path("live/wafw00f_hits.txt"),
    "origin_candidates": Path("live/unwaf_bypass_ips.txt"),
    "open_ports": Path("ports/open_ports_all.txt"),
}


def _inspect_exposure_counts(recon_dir: Path) -> tuple[dict[str, int], dict[str, str]]:
    """Return exposure line counts plus relative artifact paths that have data."""
    counts = {}
    paths = {}
    for key, relative_path in EXPOSURE_COUNT_PATHS.items():
        count = _line_count(recon_dir / relative_path)
        counts[key] = count
        if count > 0:
            paths[key] = str(relative_path)
    return counts, paths


def _inspect_named_counts(recon_dir: Path, mapping: dict[str, Path]) -> tuple[dict[str, int], dict[str, str]]:
    """Return line counts and relative paths for a named artifact mapping."""
    counts = {}
    paths = {}
    for key, relative_path in mapping.items():
        count = _line_count(recon_dir / relative_path)
        counts[key] = count
        if count > 0:
            paths[key] = str(relative_path)
    return counts, paths


def inspect_recon_artifacts(repo_root: str | Path, target: str) -> dict:
    """Summarize whether cached recon artifacts are usable for resume/surface."""
    repo_root = Path(repo_root)
    storage_key = target_storage_key(target)
    recon_dir = repo_root / "recon" / storage_key
    findings_dir = repo_root / "findings" / storage_key

    if not recon_dir.is_dir():
        return {
            "available": False,
            "ready": False,
            "host_inventory_ready": False,
            "surface_inputs_ready": False,
            "recon_dir": str(recon_dir),
            "counts": {},
            "missing": ["recon directory"],
            "warnings": [],
        }

    ffuf_summary = ReconAdapter(recon_dir).get_ffuf_summary()
    ffuf_observations = (
        int(ffuf_summary.get("observations", 0) or 0)
        if ffuf_summary.get("available")
        else 0
    )
    ffuf_legacy_raw_files = int(ffuf_summary.get("legacy_raw_files", 0) or 0)
    counts = {
        "hosts": _line_count(recon_dir / "live" / "httpx_full.txt"),
        "api_urls": _line_count(recon_dir / "urls" / "api_endpoints.txt"),
        "param_urls": _line_count(recon_dir / "urls" / "with_params.txt"),
        "js_endpoints": _line_count(recon_dir / "js" / "endpoints.txt"),
        "browser_xhr_urls": _line_count(recon_dir / "browser" / "xhr_endpoints.txt"),
        "browser_api_urls": _line_count(recon_dir / "browser" / "api_endpoints.txt"),
        "ffuf_observations": ffuf_observations,
        "ffuf_legacy_raw_files": ffuf_legacy_raw_files,
    }
    exposure_counts, exposure_paths = _inspect_exposure_counts(recon_dir)
    infra_counts, infra_paths = _inspect_named_counts(recon_dir, INFRA_COUNT_PATHS)
    counts.update(exposure_counts)
    counts.update(infra_counts)
    findings_payload = load_finding_index(findings_dir)
    counts["structured_findings"] = len(
        [
            item
            for item in findings_payload.get("findings", [])
            if isinstance(item, dict) and item.get("url")
        ]
    )

    host_inventory_ready = counts["hosts"] > 0
    surface_inputs_ready = any(
        counts[key] > 0
        for key in (
            "api_urls",
            "param_urls",
            "js_endpoints",
            "browser_xhr_urls",
            "browser_api_urls",
            "ffuf_observations",
            "structured_findings",
        )
    )

    missing = []
    warnings = []
    if not host_inventory_ready:
        missing.append("live/httpx_full.txt")
    if ffuf_summary.get("needs_summary"):
        warnings.append("FFUF artifacts found but compact summary is missing or stale")
    if host_inventory_ready and not surface_inputs_ready and not warnings:
        warnings.append("no URL, JS, browser, or structured finding surface artifacts found yet")

    return {
        "available": True,
        "ready": host_inventory_ready,
        "host_inventory_ready": host_inventory_ready,
        "surface_inputs_ready": surface_inputs_ready,
        "recon_dir": str(recon_dir),
        "counts": counts,
        "exposure_ready": any(value > 0 for value in exposure_counts.values()),
        "exposure_paths": exposure_paths,
        "infra_ready": any(value > 0 for value in infra_counts.values()),
        "infra_paths": infra_paths,
        "ffuf_needs_summary": bool(ffuf_summary.get("needs_summary")),
        "missing": missing,
        "warnings": warnings,
    }


def runtime_wait_action(
    repo_root: str | Path,
    target: str,
    *,
    stale_after_seconds: int = RUNNING_MARKER_STALE_SECONDS,
) -> str:
    """Return the transient wait action required by fresh runtime markers.

    This is the shared egress guard for Claude-facing status views. It only
    prevents duplicate long-running phases; it must not close queue items,
    suppress attack surface, or encode vulnerability value.
    """
    resolved_target = canonical_target_value(target)
    runtime = load_runtime_state(repo_root, resolved_target)
    recon = inspect_recon_artifacts(repo_root, resolved_target)
    if (
        runtime_recon_in_progress(runtime, stale_after_seconds=stale_after_seconds)
        and not bool(recon.get("ready"))
    ):
        return "wait_recon"
    if runtime_scan_in_progress(runtime, stale_after_seconds=stale_after_seconds):
        return "wait_scan"
    return ""


# ─── Derived view ───────────────────────────────────────────────────────────
def derive_state_view(repo_root: str | Path, target: str) -> dict:
    """Unified read of persisted + derived target state.

    This is the canonical "what is true right now" API for callers that need
    the complete picture: persisted session.json, recon artifact health, and
    finding counts. Replaces ad-hoc combinations across surface.py / resume.py /
    autopilot_state.py.

    Returns four layers:
      - persisted: contents of session.json (post v1→v2 migration)
      - recon: inspect_recon_artifacts() result
      - findings: counts derived from finding_index
      - evidence: presence flags for browser/js_intel/source_intel artifacts
    """
    repo_root_p = Path(repo_root)
    storage_key = target_storage_key(target)
    findings_dir = repo_root_p / "findings" / storage_key
    recon_dir = repo_root_p / "recon" / storage_key

    persisted = load_runtime_state(repo_root_p, target)
    recon = inspect_recon_artifacts(repo_root_p, target)

    findings = {
        "structured_total": 0,
        "pending_validation": 0,
        "validated_pending_report": 0,
        "reports_generated": 0,
    }
    try:
        findings_payload = load_finding_index(findings_dir)
    except Exception:  # noqa: BLE001 — derivation must never crash callers
        findings_payload = {}
    items = [
        item for item in findings_payload.get("findings", [])
        if isinstance(item, dict) and item.get("id")
    ]
    findings["structured_total"] = len(items)
    # Use the same field semantics as tools/structured_findings.py so derived
    # counts are consistent with what /pickup / autopilot_state report.
    for item in items:
        val_status = str(item.get("validation_status", "unvalidated") or "unvalidated")
        report_status = str(item.get("report_status", "not_generated") or "not_generated")
        if val_status == "unvalidated":
            findings["pending_validation"] += 1
        elif val_status == "validated" and report_status != "generated":
            findings["validated_pending_report"] += 1
        if report_status == "generated":
            findings["reports_generated"] += 1

    evidence = {
        "browser_evidence_present": (recon_dir / "browser" / "summary.json").is_file(),
        "js_intel_present": (findings_dir / "js_intel" / "materials.json").is_file(),
        "source_intel_present": (findings_dir / "source_intel").is_dir(),
    }

    return {
        "persisted": persisted,
        "recon": recon,
        "findings": findings,
        "evidence": evidence,
    }
