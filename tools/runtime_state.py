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
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import fcntl

try:
    from tools.finding_index import (
        load_finding_index,
        verify_finalized_finding_owner_provenance,
    )
    from tools.recon_adapter import ReconAdapter
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from finding_index import load_finding_index, verify_finalized_finding_owner_provenance
    from recon_adapter import ReconAdapter
    from target_paths import canonical_target_value, target_storage_key

SCHEMA_VERSION = 2
RUNNING_MARKER_STALE_SECONDS = 7200
RUNTIME_PHASES = frozenset({"recon", "scan"})

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


def _runtime_phase_marker_matches(
    runtime_state: dict,
    *,
    phase: str,
) -> bool:
    """判断 runtime marker 是否仍指向指定 phase 的启动状态。

    marker 只记录一次启动意图，不代表执行进程仍然存活。调用方必须再结合
    `runtime_phase_is_active()` 判断对应 flock 是否仍被持有，不能把该
    marker 单独当作 wait gate。
    """
    normalized_phase = str(phase or "").strip().lower()
    if normalized_phase not in RUNTIME_PHASES:
        raise ValueError(f"unsupported runtime phase: {phase}")

    workflow = str(runtime_state.get("last_executed_workflow") or "").strip()
    mode = str(runtime_state.get("mode", "") or "").strip()
    started_workflow = f"run_{normalized_phase}_started"
    running_mode = f"{normalized_phase}_running"
    # 完成态 workflow 比残留的 mode 更权威，不能继续阻塞后续 AI 判断。
    if workflow and workflow != started_workflow:
        return False
    if workflow != started_workflow and mode != running_mode:
        return False
    return True


def _runtime_phase_marker_is_fresh(
    runtime_state: dict,
    *,
    phase: str,
    stale_after_seconds: int = RUNNING_MARKER_STALE_SECONDS,
) -> bool:
    """判断指定 phase 的启动 marker 是否仍在兼容性新鲜窗口内。"""
    if not _runtime_phase_marker_matches(runtime_state, phase=phase):
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


class RuntimePhaseBusy(RuntimeError):
    """Raised when another process already owns a target phase lock."""

    def __init__(self, target: str, phase: str, lock_path: Path):
        self.target = canonical_target_value(target)
        self.phase = phase
        self.lock_path = lock_path
        super().__init__(
            f"{phase} is already running for {self.target}; lock: {lock_path}"
        )


@contextmanager
def runtime_phase_lock(repo_root: str | Path, target: str, phase: str):
    """Hold a non-blocking process lock for one long-running target phase.

    The lock is acquired before a caller writes its running marker. `flock`
    releases automatically when the process exits, so a crash cannot leave a
    stale lock that needs timestamp or PID guessing.
    """
    normalized_phase = str(phase or "").strip().lower()
    if normalized_phase not in RUNTIME_PHASES:
        raise ValueError(f"unsupported runtime phase: {phase}")

    resolved_target = canonical_target_value(target)
    lock_dir = _state_dir(repo_root, resolved_target) / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{normalized_phase}.lock"
    handle = lock_path.open("a+", encoding="utf-8")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimePhaseBusy(resolved_target, normalized_phase, lock_path) from exc

        handle.seek(0)
        handle.truncate()
        handle.write(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "phase": normalized_phase,
                    "target": resolved_target,
                    "acquired_at": _now_utc(),
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        handle.flush()
        os.fsync(handle.fileno())
        yield lock_path
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _runtime_phase_lock_status(
    repo_root: str | Path,
    target: str,
    phase: str,
) -> bool | None:
    """只读探测匹配 lock，不改写 target runtime state。

    锁被其它进程持有时返回 ``True``；能立即获取（或从未创建）时返回
    ``False``；无法探测时返回 ``None``。最后一种情况让调用方保留 fresh
    marker 的保守兜底，而不是把 I/O 错误误判为 phase 已退出。
    """
    normalized_phase = str(phase or "").strip().lower()
    if normalized_phase not in RUNTIME_PHASES:
        raise ValueError(f"unsupported runtime phase: {phase}")

    resolved_target = canonical_target_value(target)
    lock_path = _state_dir(repo_root, resolved_target) / "locks" / f"{normalized_phase}.lock"
    if not lock_path.is_file():
        return False

    try:
        # 只读打开避免 status 查询创建残留 lock 文件。真正的执行方在获取锁前
        # 已经创建该文件；若它在 is_file() 与 open() 之间退出，视为未活跃即可。
        with lock_path.open("r", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            try:
                return False
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except FileNotFoundError:
        return False
    except OSError:
        return None


def runtime_phase_is_active(repo_root: str | Path, target: str, phase: str) -> bool:
    """判断是否有存活进程持有 target phase 的 flock。"""
    return _runtime_phase_lock_status(repo_root, target, phase) is True


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


def runtime_phase_in_progress(
    repo_root: str | Path,
    target: str,
    phase: str,
    runtime_state: dict | None = None,
    *,
    stale_after_seconds: int = RUNNING_MARKER_STALE_SECONDS,
) -> bool:
    """判断 runtime marker 对应的 phase 是否仍有存活执行者。

    `session.json` 会在进程被突然终止后保留，`flock` 则由内核自动释放。
    匹配 marker 与活跃锁必须同时存在，才能避免被杀掉的 Claude 后台任务让
    `/autopilot` 一直停在 `wait_scan` 或 `wait_recon`。活跃锁比时间戳更
    权威，因此长时间扫描不会被旧 marker 窗口错误放行。
    """
    normalized_phase = str(phase or "").strip().lower()
    if normalized_phase not in RUNTIME_PHASES:
        raise ValueError(f"unsupported runtime phase: {phase}")

    resolved_target = canonical_target_value(target)
    state = runtime_state if isinstance(runtime_state, dict) else load_runtime_state(repo_root, resolved_target)
    if not _runtime_phase_marker_matches(state, phase=normalized_phase):
        return False

    lock_status = _runtime_phase_lock_status(repo_root, resolved_target, normalized_phase)
    if lock_status is not None:
        # 活跃锁才是实际 liveness：长扫描超过旧 marker 窗口也必须继续等待。
        return lock_status
    # 时间戳仅在 lock 探测 I/O 失败时保留保守兼容兜底。
    return _runtime_phase_marker_is_fresh(
        state,
        phase=normalized_phase,
        stale_after_seconds=stale_after_seconds,
    )


def runtime_recon_in_progress(
    runtime_state: dict,
    *,
    stale_after_seconds: int = RUNNING_MARKER_STALE_SECONDS,
) -> bool:
    """兼容旧调用：仅判断 recon 的 running marker 是否新鲜。

    该函数没有 repo/target，无法检查 flock；Claude-facing 的 wait gate
    必须使用 `runtime_phase_in_progress()`。
    """
    return _runtime_phase_marker_is_fresh(
        runtime_state,
        phase="recon",
        stale_after_seconds=stale_after_seconds,
    )


def runtime_scan_in_progress(
    runtime_state: dict,
    *,
    stale_after_seconds: int = RUNNING_MARKER_STALE_SECONDS,
) -> bool:
    """兼容旧调用：仅判断 scan 的 running marker 是否新鲜。

    该函数没有 repo/target，无法检查 flock；Claude-facing 的 wait gate
    必须使用 `runtime_phase_in_progress()`。
    """
    return _runtime_phase_marker_is_fresh(
        runtime_state,
        phase="scan",
        stale_after_seconds=stale_after_seconds,
    )


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
    "openapi_specs": Path("api_specs/spec_urls.txt"),
    "openapi_operations": Path("api_specs/operations.jsonl"),
    "openapi_public_operations": Path("api_specs/public_operations.txt"),
    "openapi_auth_boundary_candidates": Path("api_specs/auth_boundary_candidates.jsonl"),
    "platform_metadata": Path("api_specs/platform_metadata.jsonl"),
    "cloud_storage_candidates": Path("exposure/cloud_storage_candidates.txt"),
    "s3_bucket_candidates": Path("exposure/s3_bucket_candidates.txt"),
    "external_service_hosts": Path("exposure/external_service_hosts.txt"),
    "host_pivot_candidates": Path("exposure/host_pivot_candidates.jsonl"),
    "ai_asset_candidates": Path("exposure/ai_asset_candidates.jsonl"),
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
        "js_files": _line_count(recon_dir / "urls" / "js_files.txt"),
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
            "js_files",
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


def _artifact_has_bytes(path: Path) -> bool:
    """只通过 stat 判断 artifact 是否非空，供高频 bootstrap 使用。"""
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def inspect_recon_artifacts_fast(repo_root: str | Path, target: str) -> dict:
    """返回 bootstrap 所需的只读 recon metadata，不逐行扫描大型 artifact。

    ``counts`` 在该视图中只表达已知的 0；非空文件用 ``None`` 表示“存在但精确行数未知”。
    需要精确计数的诊断命令继续调用 :func:`inspect_recon_artifacts`。
    """
    repo = Path(repo_root)
    storage_key = target_storage_key(target)
    recon_dir = repo / "recon" / storage_key
    findings_dir = repo / "findings" / storage_key
    if not recon_dir.is_dir():
        return {
            "available": False,
            "ready": False,
            "host_inventory_ready": False,
            "surface_inputs_ready": False,
            "recon_dir": str(recon_dir),
            "counts": {},
            "counts_exact": False,
            "missing": ["recon directory"],
            "warnings": [],
        }

    paths = {
        "hosts": recon_dir / "live" / "httpx_full.txt",
        "api_urls": recon_dir / "urls" / "api_endpoints.txt",
        "param_urls": recon_dir / "urls" / "with_params.txt",
        "js_files": recon_dir / "urls" / "js_files.txt",
        "js_endpoints": recon_dir / "js" / "endpoints.txt",
        "browser_xhr_urls": recon_dir / "browser" / "xhr_endpoints.txt",
        "browser_api_urls": recon_dir / "browser" / "api_endpoints.txt",
    }
    present = {key: _artifact_has_bytes(path) for key, path in paths.items()}
    counts = {key: (None if value else 0) for key, value in present.items()}

    ffuf_ready = any(
        _artifact_has_bytes(recon_dir / relative)
        for relative in (
            Path("dirs/ffuf_summary.json"),
            Path("dirs/ffuf-results-summary.json"),
        )
    )
    findings_ready = _artifact_has_bytes(findings_dir / "findings.json")
    counts.update(
        {
            "ffuf_observations": None if ffuf_ready else 0,
            "ffuf_legacy_raw_files": 0,
            "structured_findings": None if findings_ready else 0,
        }
    )

    exposure_paths = {
        key: str(relative)
        for key, relative in EXPOSURE_COUNT_PATHS.items()
        if _artifact_has_bytes(recon_dir / relative)
    }
    infra_paths = {
        key: str(relative)
        for key, relative in INFRA_COUNT_PATHS.items()
        if _artifact_has_bytes(recon_dir / relative)
    }
    for key in EXPOSURE_COUNT_PATHS:
        counts[key] = None if key in exposure_paths else 0
    for key in INFRA_COUNT_PATHS:
        counts[key] = None if key in infra_paths else 0

    host_inventory_ready = present["hosts"]
    surface_inputs_ready = any(
        present[key]
        for key in (
            "api_urls",
            "param_urls",
            "js_files",
            "js_endpoints",
            "browser_xhr_urls",
            "browser_api_urls",
        )
    ) or ffuf_ready or findings_ready
    missing = [] if host_inventory_ready else ["live/httpx_full.txt"]
    warnings = []
    if host_inventory_ready and not surface_inputs_ready:
        warnings.append("no URL, JS, browser, or structured finding surface artifacts found yet")

    return {
        "available": True,
        "ready": host_inventory_ready,
        "host_inventory_ready": host_inventory_ready,
        "surface_inputs_ready": surface_inputs_ready,
        "recon_dir": str(recon_dir),
        "counts": counts,
        "counts_exact": False,
        "exposure_ready": bool(exposure_paths),
        "exposure_paths": exposure_paths,
        "infra_ready": bool(infra_paths),
        "infra_paths": infra_paths,
        "ffuf_needs_summary": False,
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
        runtime_phase_in_progress(
            repo_root,
            resolved_target,
            "recon",
            runtime,
            stale_after_seconds=stale_after_seconds,
        )
        and not bool(recon.get("ready"))
    ):
        return "wait_recon"
    if runtime_phase_in_progress(
        repo_root,
        resolved_target,
        "scan",
        runtime,
        stale_after_seconds=stale_after_seconds,
    ):
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
        "owner_revalidation_pending": 0,
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
        val_status = str(item.get("validation_status", "unvalidated") or "unvalidated").lower()
        if val_status == "needs_owner_revalidation":
            findings["owner_revalidation_pending"] += 1
            continue
        provenance = verify_finalized_finding_owner_provenance(
            findings_dir,
            item,
            target=target,
        )
        if provenance.get("required") and not provenance.get("valid"):
            findings["owner_revalidation_pending"] += 1
            continue
        report_status = str(item.get("report_status", "not_generated") or "not_generated").lower()
        if val_status in {"unvalidated", "candidate", "partial", "needs_validation"}:
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
