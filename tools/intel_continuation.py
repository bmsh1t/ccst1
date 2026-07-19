#!/usr/bin/env python3
"""从派生 artifact 推导 `/autopilot` 的确定性 Intel continuation。"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.action_queue import FINAL_STATUSES, load_queue
    from tools.intel_artifact import IntelArtifactError, read_intel_artifact
    from tools.intel_sources import DEFAULT_COMPONENT_TTL_SECONDS
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.technology_inventory import (
        TechnologyInventoryError,
        inventory_source_binding_matches,
        read_inventory,
    )
    from tools.web_intel_artifact import load_web_intel_projection
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import FINAL_STATUSES, load_queue  # type: ignore
    from intel_artifact import IntelArtifactError, read_intel_artifact  # type: ignore
    from intel_sources import DEFAULT_COMPONENT_TTL_SECONDS  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from technology_inventory import (  # type: ignore
        TechnologyInventoryError,
        inventory_source_binding_matches,
        read_inventory,
    )
    from web_intel_artifact import load_web_intel_projection  # type: ignore


_IDENTIFIER_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})\b",
    re.IGNORECASE,
)
GENERIC_ACTIONS = {
    "continue_last_focus",
    "resume_untested",
    "hunt_p1",
    "hunt_p2",
    "handoff",
}
INTEL_REFRESH_TTL_SECONDS = DEFAULT_COMPONENT_TTL_SECONDS
_SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_APPLICABILITY_RANK = {"unknown": 0, "likely": 1, "affected": 2}


def _mtime_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _parse_utc(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _score_hint(item: dict) -> int:
    try:
        return int(float(item.get("score_hint") or 0))
    except (TypeError, ValueError):
        return 0


def _final_queue_dispositions(repo_root: str | Path, target: str) -> dict[str, list[dict]]:
    dispositions: dict[str, list[dict]] = {}
    try:
        queue = load_queue(repo_root, target)
    except ValueError:
        return dispositions
    for item in queue.get("actions") or []:
        if (
            not isinstance(item, dict)
            or str(item.get("status") or "") not in FINAL_STATUSES
            or str(item.get("type") or "") != "intel-advisory"
        ):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        material = json.dumps(
            {
                "action": item.get("action", ""),
                "evidence": item.get("evidence", ""),
                "result": item.get("result", ""),
                "notes": item.get("notes", ""),
                "metadata": metadata,
            },
            ensure_ascii=False,
        )
        disposition = {"metadata": metadata, "material": material.lower()}
        for match in _IDENTIFIER_RE.finditer(material):
            dispositions.setdefault(match.group(0).upper(), []).append(disposition)
    return dispositions


def _advisory_identifiers(item: dict) -> set[str]:
    values = [item.get("id", ""), *(item.get("aliases") or [])]
    return {
        match.group(0).upper()
        for value in values
        if (match := _IDENTIFIER_RE.search(str(value or "")))
    }


def _strict_token_present(material: str, value: str) -> bool:
    """匹配完整组件/版本 token，避免 `1.2` 命中 `1.20`。"""
    token = str(value or "").strip().lower()
    if not token:
        return False
    return bool(
        re.search(
            rf"(?<![a-z0-9._+~-]){re.escape(token)}(?![a-z0-9._+~-])",
            material,
        )
    )


def _metadata_disposition_matches(item: dict, metadata: dict) -> bool | None:
    """返回结构化 binding 的匹配结果；无 binding 字段时交给 legacy 文本。"""
    component_binding = metadata.get("component")
    has_binding = any(
        key in metadata
        for key in (
            "advisory_id",
            "component",
            "component_name",
            "version",
            "component_version",
        )
    )
    if not has_binding:
        return None

    if isinstance(component_binding, dict):
        bound_name = str(
            component_binding.get("name") or component_binding.get("display_name") or ""
        ).strip().lower()
        has_version = "version" in component_binding or "version" in metadata
        bound_version = str(
            component_binding.get("version")
            if "version" in component_binding
            else metadata.get("version") or ""
        ).strip().lower()
    else:
        bound_name = str(
            metadata.get("component_name") or component_binding or ""
        ).strip().lower()
        has_version = "version" in metadata or "component_version" in metadata
        bound_version = str(
            metadata.get("version")
            if "version" in metadata
            else metadata.get("component_version") or ""
        ).strip().lower()

    advisory_id = str(metadata.get("advisory_id") or "").strip().upper()
    component = item.get("component") if isinstance(item.get("component"), dict) else {}
    expected_name = str(component.get("name") or "").strip().lower()
    expected_version = str(component.get("version") or "").strip().lower()
    return bool(
        advisory_id in _advisory_identifiers(item)
        and bound_name
        and bound_name == expected_name
        and has_version
        and bound_version == expected_version
    )


def _legacy_disposition_matches(item: dict, material: str) -> bool:
    component = item.get("component") if isinstance(item.get("component"), dict) else {}
    name = str(component.get("name") or "").strip().lower()
    version = str(component.get("version") or "").strip().lower()
    if not name or not _strict_token_present(material, name):
        return False
    if version:
        return _strict_token_present(material, version)
    unknown_markers = (
        f"{name}@unknown",
        f"{name} version unknown",
        f"{name} unknown version",
    )
    return any(marker in material for marker in unknown_markers)


def _has_final_disposition(item: dict, dispositions: dict[str, list[dict]]) -> bool:
    """同一 advisory 只有在观测版本也一致时才复用既有终态。"""
    for identifier in _advisory_identifiers(item):
        for disposition in dispositions.get(identifier, []):
            metadata = (
                disposition.get("metadata")
                if isinstance(disposition.get("metadata"), dict)
                else {}
            )
            metadata_match = _metadata_disposition_matches(item, metadata)
            if metadata_match is True:
                return True
            if metadata_match is None and _legacy_disposition_matches(
                item,
                str(disposition.get("material") or ""),
            ):
                return True
    return False


def _bound_inventory_sources(repo: Path, inventory: dict) -> list[tuple[dict, Path]]:
    """只检查 owner 实际绑定的 raw 输入，避免兼容副本制造刷新循环。"""
    sources = inventory.get("sources") if isinstance(inventory.get("sources"), list) else []
    if not sources and isinstance(inventory.get("source"), dict):
        sources = [inventory["source"]]
    bound_sources = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        raw_value = str(source.get("path") or "").strip()
        if not raw_value:
            continue
        raw_path = Path(raw_value)
        resolved_path = raw_path if raw_path.is_absolute() else repo / raw_path
        bound_sources.append((source, resolved_path))
    return bound_sources


def _high_value_advisory(item: dict) -> bool:
    if item.get("already_tested") or item.get("applicability") == "not_affected":
        return False
    score = _score_hint(item)
    return bool(
        item.get("applicability") in {"affected", "likely"}
        or item.get("severity") in {"CRITICAL", "HIGH"}
        or item.get("kev")
        or score >= 40
    )


def inspect_intel_continuation(
    repo_root: str | Path,
    target: str,
    *,
    now: datetime | None = None,
) -> dict:
    """只读推导下一步；不刷新 inventory、Intel、Web Intel 或 action queue。"""
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    recon_dir = repo / "recon" / target_storage_key(resolved_target)
    inventory_path = recon_dir / "live" / "technology_inventory.json"
    intel_path = recon_dir / "intel.json"
    web_index_path = repo / "evidence" / target_storage_key(resolved_target) / "web-intel" / "index.json"

    base = {
        "action": "complete",
        "reason": "no pending software intelligence continuation",
        "inventory_path": str(inventory_path),
        "intel_path": str(intel_path),
        "web_intel_path": str(web_index_path),
        "recommended": [],
        "blocked": [],
        "advisory": {},
    }
    # Bootstrap 不解析 raw recon。inventory 由 /surface、/intel 或 recon
    # finalizer 显式构建；只有 owner artifact 存在后才开启 continuation。
    if not inventory_path.is_file():
        return base
    try:
        current_inventory = read_inventory(inventory_path)
    except TechnologyInventoryError as exc:
        return {
            **base,
            "action": "run_intel",
            "reason": f"technology inventory is invalid: {exc}",
        }
    inventory_mtime = _mtime_ns(inventory_path)
    bound_sources = _bound_inventory_sources(repo, current_inventory)
    bound_paths = [path for _binding, path in bound_sources]
    if any(not path.is_file() for path in bound_paths):
        return {
            **base,
            "action": "run_intel",
            "reason": "a software/service inventory source is missing",
        }
    if any(_mtime_ns(path) > inventory_mtime for path in bound_paths):
        return {
            **base,
            "action": "run_intel",
            "reason": "software/service observations are newer than the unified inventory",
        }
    if any(
        not inventory_source_binding_matches(binding, path)
        for binding, path in bound_sources
    ):
        return {
            **base,
            "action": "run_intel",
            "reason": "software/service observation binding changed since the unified inventory",
        }
    if not intel_path.is_file():
        return {
            **base,
            "action": "run_intel",
            "reason": "the unified inventory exists but Intel v2 has not processed it",
        }
    intel_mtime = _mtime_ns(intel_path)
    if inventory_mtime > intel_mtime:
        return {
            **base,
            "action": "run_intel",
            "reason": "the software/service inventory is newer than intel.json",
        }
    try:
        intel = read_intel_artifact(intel_path)
    except IntelArtifactError as exc:
        return {
            **base,
            "action": "run_intel",
            "reason": f"intel.json is invalid: {exc}",
        }
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated_at = _parse_utc(intel.get("generated_at"))
    if generated_at is None or (current - generated_at).total_seconds() > INTEL_REFRESH_TTL_SECONDS:
        return {
            **base,
            "action": "run_intel",
            "reason": "Intel v2 advisory sources are older than the refresh TTL",
        }
    inventory = intel.get("inventory") if isinstance(intel.get("inventory"), dict) else {}
    current_inventory_fingerprint = str(current_inventory.get("fingerprint") or "").strip()
    intel_inventory_fingerprint = str(inventory.get("fingerprint") or "").strip()
    if not intel_inventory_fingerprint:
        return {
            **base,
            "action": "run_intel",
            "reason": "intel.json predates the inventory fingerprint contract",
        }
    if current_inventory_fingerprint != intel_inventory_fingerprint:
        return {
            **base,
            "action": "run_intel",
            "reason": "intel.json was built from a different software/service inventory",
        }
    if web_index_path.is_file():
        current_web = load_web_intel_projection(repo, resolved_target, now=current)
        current_web_fingerprint = str(current_web.get("fingerprint") or "")
        web_intel = intel.get("web_intel") if isinstance(intel.get("web_intel"), dict) else {}
        if not current_web_fingerprint or current_web_fingerprint != str(
            web_intel.get("fingerprint") or ""
        ):
            return {
                **base,
                "action": "run_intel",
                "reason": "Web Intel evidence has not been merged into intel.json",
            }
        for field in ("status", "covered_subjects", "blocked_subjects"):
            default = [] if field.endswith("subjects") else ""
            if current_web.get(field, default) != web_intel.get(field, default):
                return {
                    **base,
                    "action": "run_intel",
                    "reason": "Web Intel TTL/status changed since intel.json was generated",
                }
    if int((intel.get("stats") or {}).get("component_count", 0) or 0) <= 0:
        return base

    gaps = intel.get("intel_gaps") if isinstance(intel.get("intel_gaps"), dict) else {}
    recommended = [item for item in gaps.get("recommended") or [] if isinstance(item, dict)]
    blocked = [item for item in gaps.get("blocked") or [] if isinstance(item, dict)]
    final_dispositions = _final_queue_dispositions(repo, resolved_target)
    candidates = [
        item for item in intel.get("advisories") or []
        if isinstance(item, dict)
        and _high_value_advisory(item)
        and not _has_final_disposition(item, final_dispositions)
    ]
    candidates.sort(
        key=lambda item: (
            -_SEVERITY_RANK.get(str(item.get("severity") or "UNKNOWN").upper(), 0),
            -_APPLICABILITY_RANK.get(str(item.get("applicability") or "unknown").lower(), 0),
            -_score_hint(item),
            str(item.get("id") or ""),
        )
    )
    if candidates:
        selected = candidates[0]
        component = selected.get("component") if isinstance(selected.get("component"), dict) else {}
        return {
            **base,
            "action": "test_advisory_applicability",
            "reason": "a high-value advisory still needs target reachability/applicability evidence",
            "advisory": {
                "id": selected.get("id", ""),
                "aliases": list(selected.get("aliases") or [])[:8],
                "component": {
                    "name": component.get("name", ""),
                    "version": component.get("version", ""),
                    "hosts": list(component.get("hosts") or [])[:5],
                    "ports": list(component.get("ports") or [])[:5],
                },
                "applicability": selected.get("applicability", "unknown"),
                "severity": selected.get("severity", "UNKNOWN"),
                "score_hint": selected.get("score_hint", 0),
                "source_refs": list(selected.get("source_refs") or [])[:5],
            },
        }
    # Web Intel 只补充官方源没有覆盖的内容，不能抢占已有高危/受影响 advisory。
    if gaps.get("web_search_recommended") and recommended:
        return {
            **base,
            "action": "collect_web_intel",
            "reason": "official advisory sources left a bounded software intelligence gap",
            "recommended": recommended[:8],
        }
    if blocked:
        return {
            **base,
            "reason": "Web Intel provider/query is blocked; preserve the handoff and continue other lanes",
            "blocked": blocked[:8],
        }
    return base


def apply_intel_continuation(primary_action: str, continuation: dict) -> str:
    """只抢占普通探索/handoff；finding、queue、recon 和 surface gate 仍优先。"""
    action = str(continuation.get("action") or "complete")
    if primary_action in GENERIC_ACTIONS and action != "complete":
        return action
    return primary_action
