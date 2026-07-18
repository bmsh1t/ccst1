#!/usr/bin/env python3
"""持久化 recon observations，提供中性的 untouched/stale 可见性。

该模块只记录“发现了什么”和“是否审阅过”，不判断漏洞类别、攻击价值，
也不选择 Skill。可执行动作和测试结果仍分别归 action_queue 与 evidence_ledger。
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import heapq
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
SUMMARY_SCHEMA_VERSION = 1
SUMMARY_KIND = "observation_inventory_summary"
STALE_AFTER_SECONDS = 2 * 24 * 60 * 60
ALLOWED_STATUSES = frozenset({"untouched", "reviewing", "reviewed", "parked"})
DEFAULT_SAMPLE_LIMIT = 8
MAX_LIST_LIMIT = 1000
CURSOR_SCHEMA_VERSION = 2
PAGE_ORDER_FIRST_SEEN_ID = "first_seen_id"

# 这里只描述事实来源，不携带漏洞类别或优先级。相同 observation 可来自多个文件，
# 稳定 ID 会将其合并，同时保留全部 source artifact。
ARTIFACT_SPECS = (
    ("host", Path("subdomains/all.txt")),
    ("host", Path("subdomains/resolved.txt")),
    ("url", Path("live/urls.txt")),
    ("host-observation", Path("live/httpx_full.txt")),
    ("url", Path("urls/all.txt")),
    ("url", Path("urls/with_params.txt")),
    ("url", Path("urls/api_endpoints.txt")),
    ("url", Path("urls/api_endpoints_filtered.txt")),
    ("url", Path("urls/js_files.txt")),
    ("url", Path("urls/graphql.txt")),
    ("path", Path("urls/sensitive_paths.txt")),
    ("endpoint", Path("js/endpoints.txt")),
    ("parameter", Path("params/interesting_params.txt")),
    ("url", Path("browser/xhr_endpoints.txt")),
    ("url", Path("browser/api_endpoints.txt")),
    ("exposure", Path("exposure/config_files.txt")),
    ("exposure", Path("exposure/api_doc_candidates.txt")),
    ("exposure", Path("exposure/api_leak_candidates.txt")),
    ("exposure", Path("exposure/api_leaks/postman_leaks.txt")),
    ("exposure", Path("exposure/api_leaks/postleaks_urls.txt")),
    ("exposure", Path("exposure/api_leaks/swagger_leaks.txt")),
    ("exposure", Path("exposure/cloud_storage_candidates.txt")),
    ("exposure", Path("exposure/s3_bucket_candidates.txt")),
    ("infra", Path("live/wafw00f_hits.txt")),
    ("infra", Path("live/unwaf_bypass_ips.txt")),
    ("infra", Path("ports/open_ports_all.txt")),
)


class InventoryError(RuntimeError):
    """Observation inventory 无法可靠读取或校验。"""


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def inventory_path(repo_root: str | Path, target: str) -> Path:
    """返回目标 observation inventory 的规范路径。"""
    resolved = canonical_target_value(target)
    return Path(repo_root) / "state" / target_storage_key(resolved) / "observations.json"


def observation_summary_path(repo_root: str | Path, target: str) -> Path:
    """返回与 monolithic inventory 绑定的小型摘要 sidecar。"""
    resolved = canonical_target_value(target)
    return (
        Path(repo_root)
        / "state"
        / target_storage_key(resolved)
        / "observations-summary.json"
    )


def _empty_inventory(target: str) -> dict:
    resolved = canonical_target_value(target)
    return {
        "schema_version": SCHEMA_VERSION,
        "target": resolved,
        "storage_key": target_storage_key(resolved),
        "source_fingerprint": "",
        "last_synced_at": "",
        "page_order": PAGE_ORDER_FIRST_SEEN_ID,
        "observations": [],
    }


def _validate_inventory(payload: object, path: Path) -> dict:
    if not isinstance(payload, dict):
        raise InventoryError(f"invalid observation inventory at {path}: root must be an object")
    observations = payload.get("observations")
    if not isinstance(observations, list):
        raise InventoryError(f"invalid observation inventory at {path}: observations must be a list")
    for index, item in enumerate(observations):
        _validate_observation_item(item, path, index=index)
    return payload


def _validate_observation_item(item: object, path: Path, *, index: int | None = None) -> dict:
    """校验单条 observation，供完整与流式读取复用。"""
    location = f"observations[{index}]" if index is not None else "observation row"
    if not isinstance(item, dict) or not str(item.get("id") or "").strip():
        raise InventoryError(
            f"invalid observation inventory at {path}: {location} lacks a stable id"
        )
    status = str(item.get("status") or "untouched")
    if status not in ALLOWED_STATUSES:
        raise InventoryError(
            f"invalid observation inventory at {path}: {location} has status {status!r}"
        )
    return item


def load_inventory(repo_root: str | Path, target: str) -> dict:
    """读取 inventory；缺失返回空状态，破损状态显式报错。"""
    path = inventory_path(repo_root, target)
    if not path.is_file():
        return _empty_inventory(target)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"invalid observation inventory at {path}: {exc}") from exc
    return _validate_inventory(payload, path)


def _write_json_atomic(path: Path, payload: dict) -> dict:
    """同目录临时文件 + replace，并返回无需重读正文的内容绑定。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    digest = hashlib.sha256()
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
            encoder = json.JSONEncoder(ensure_ascii=False, indent=2)
            for chunk in encoder.iterencode(payload):
                handle.write(chunk)
                digest.update(chunk.encode("utf-8"))
            handle.write("\n")
            digest.update(b"\n")
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
    stat = path.stat()
    return {
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
        "ctime_ns": int(stat.st_ctime_ns),
        "st_dev": int(stat.st_dev),
        "st_ino": int(stat.st_ino),
        "sha256": digest.hexdigest(),
    }


def _file_binding(path: Path) -> dict:
    """为显式 owner 修复生成正文 binding；bootstrap 不调用该函数。"""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    stat = path.stat()
    return {
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
        "ctime_ns": int(stat.st_ctime_ns),
        "st_dev": int(stat.st_dev),
        "st_ino": int(stat.st_ino),
        "sha256": digest.hexdigest(),
    }


@contextmanager
def _inventory_lock(path: Path):
    """串行化同一 target 的 sync/touch，避免两个 Claude 会话互相覆盖。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / ".observations.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _source_files(recon_dir: Path) -> list[tuple[str, Path, Path]]:
    files = []
    for kind, relative_path in ARTIFACT_SPECS:
        path = recon_dir / relative_path
        if path.is_file():
            files.append((kind, relative_path, path))
    return files


def _source_fingerprint(files: list[tuple[str, Path, Path]]) -> str:
    """使用 path/stat identity 判断 recon artifact 是否发生变化。"""
    digest = hashlib.sha256()
    for kind, relative_path, path in files:
        stat = path.stat()
        digest.update(
            (
                f"{kind}\0{relative_path.as_posix()}\0{stat.st_size}\0{stat.st_mtime_ns}"
                f"\0{stat.st_ctime_ns}\0{stat.st_dev}\0{stat.st_ino}\n"
            ).encode()
        )
    return digest.hexdigest()


def _normalise_value(value: str) -> str:
    return " ".join(str(value or "").strip().splitlines())


def _observation_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}\0{value}".encode("utf-8")).hexdigest()[:20]
    return f"obs-{digest}"


def _iter_current_observations(
    files: list[tuple[str, Path, Path]],
) -> Iterator[tuple[str, str, str]]:
    for kind, relative_path, path in files:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                value = _normalise_value(raw_line)
                if not value or value.startswith("#"):
                    continue
                yield kind, value, relative_path.as_posix()


def sync_inventory(
    repo_root: str | Path,
    target: str,
    *,
    force: bool = False,
    now: str | None = None,
) -> dict:
    """将当前 recon artifacts upsert 到 inventory。

    artifact 指纹未变化时直接返回，避免 `/autopilot` 轮询虚增 seen_count。
    已从当前 artifact 消失的旧 observation 会保留，但标记 `present=false`。
    """
    resolved = canonical_target_value(target)
    repo = Path(repo_root)
    recon_dir = repo / "recon" / target_storage_key(resolved)
    path = inventory_path(repo, resolved)
    if not recon_dir.is_dir():
        return load_inventory(repo, resolved)

    with _inventory_lock(path):
        payload = load_inventory(repo, resolved)
        files = _source_files(recon_dir)
        fingerprint = _source_fingerprint(files)
        if not force and payload.get("source_fingerprint") == fingerprint:
            if payload.get("page_order") != PAGE_ORDER_FIRST_SEEN_ID:
                # owner 路径负责把 legacy body 升级成可流式分页的稳定物理顺序；
                # 仅排序/补元数据，不增加 seen_count。
                payload["page_order"] = PAGE_ORDER_FIRST_SEEN_ID
                payload["observations"].sort(key=_page_sort_key)
                binding = _write_json_atomic(path, payload)
                _write_inventory_summary(repo, resolved, payload, inventory_binding=binding)
                return payload
            # Legacy inventory may predate the sidecar.  Explicit sync owns
            # this repair; bootstrap/peek remains strictly read-only.
            summary = peek_inventory_summary(repo, resolved)
            if summary.get("status") != "valid" and path.is_file():
                _write_inventory_summary(
                    repo,
                    resolved,
                    payload,
                    inventory_binding=_file_binding(path),
                )
            return payload

        timestamp = now or _now_utc()
        existing = {
            str(item["id"]): dict(item)
            for item in payload.get("observations", [])
            if isinstance(item, dict) and item.get("id")
        }
        current: dict[str, dict] = {}
        for kind, value, source in _iter_current_observations(files):
            observation_id = _observation_id(kind, value)
            row = current.setdefault(
                observation_id,
                {"id": observation_id, "kind": kind, "value": value, "sources": []},
            )
            if source not in row["sources"]:
                row["sources"].append(source)

        merged = []
        for observation_id, row in current.items():
            previous = existing.pop(observation_id, None)
            if previous is None:
                # 直接完善 current row，避免在 30 万 observation 上同时保留
                # current dict 与一份完整复制。
                row.update(
                    {
                        "status": "untouched",
                        "notes": "",
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "seen_count": 1,
                        "present": True,
                    }
                )
                item = row
            else:
                previous.update(row)
                previous["last_seen"] = timestamp
                previous["seen_count"] = int(previous.get("seen_count", 0) or 0) + 1
                previous["present"] = True
                item = previous
                item.setdefault("status", "untouched")
                item.setdefault("notes", "")
                item.setdefault("first_seen", timestamp)
            merged.append(item)

        for previous in existing.values():
            previous["present"] = False
            merged.append(previous)

        current.clear()
        existing.clear()
        merged.sort(key=_page_sort_key)
        updated = {
            "schema_version": SCHEMA_VERSION,
            "target": resolved,
            "storage_key": target_storage_key(resolved),
            "source_fingerprint": fingerprint,
            "last_synced_at": timestamp,
            "page_order": PAGE_ORDER_FIRST_SEEN_ID,
            "observations": merged,
        }
        binding = _write_json_atomic(path, updated)
        _write_inventory_summary(repo, resolved, updated, inventory_binding=binding)
        return updated


def _is_stale(item: dict, now: datetime, stale_after_seconds: int) -> bool:
    if str(item.get("status") or "untouched") != "untouched":
        return False
    first_seen = _parse_utc(item.get("first_seen"))
    if first_seen is None:
        return False
    return (now - first_seen).total_seconds() >= stale_after_seconds


def _page_sort_key(item: dict) -> tuple[str, str]:
    """owner 写入的 observation 物理顺序，也是 page 的稳定顺序。"""
    return str(item.get("first_seen") or ""), str(item.get("id") or "")


def summarize_inventory(
    payload: dict,
    *,
    now: datetime | None = None,
    stale_after_seconds: int = STALE_AFTER_SECONDS,
    sample_limit: int = DEFAULT_SAMPLE_LIMIT,
) -> dict:
    """返回 Claude-facing 有界摘要，不进行价值排序。"""
    current_time = now or datetime.now(timezone.utc)
    observations = [item for item in payload.get("observations", []) if isinstance(item, dict)]
    counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    stale_ids = set()
    present = 0
    for item in observations:
        status = str(item.get("status") or "untouched")
        counts[status] = counts.get(status, 0) + 1
        if bool(item.get("present", True)):
            present += 1
        if _is_stale(item, current_time, stale_after_seconds):
            stale_ids.add(str(item.get("id") or ""))

    untouched_candidates = (
        item
        for item in observations
        if str(item.get("status") or "untouched") == "untouched"
    )
    neutral_order = heapq.nsmallest(
        max(0, sample_limit),
        untouched_candidates,
        key=lambda item: (str(item.get("first_seen") or ""), str(item.get("id") or "")),
    )
    if not neutral_order and observations:
        neutral_order = heapq.nsmallest(
            max(0, sample_limit),
            observations,
            key=lambda item: (str(item.get("first_seen") or ""), str(item.get("id") or "")),
        )
    sample = []
    for item in neutral_order:
        observation_id = str(item.get("id") or "")
        sample.append(
            {
                "id": observation_id,
                "kind": str(item.get("kind") or ""),
                "value": str(item.get("value") or ""),
                "sources": list(item.get("sources") or [])[:4],
                "status": str(item.get("status") or "untouched"),
                "stale": observation_id in stale_ids,
            }
        )
    return {
        "available": bool(payload.get("last_synced_at") or observations),
        "path": "state/{}/observations.json".format(payload.get("storage_key") or ""),
        "total": len(observations),
        "present": present,
        "untouched": counts.get("untouched", 0),
        "reviewing": counts.get("reviewing", 0),
        "reviewed": counts.get("reviewed", 0),
        "parked": counts.get("parked", 0),
        "stale": len(stale_ids),
        "last_synced_at": str(payload.get("last_synced_at") or ""),
        "sample": sample,
    }


def _summary_error(
    repo_root: str | Path,
    target: str,
    *,
    status: str,
    reason: str,
    previous: dict | None = None,
) -> dict:
    """保留旧计数用于诊断，但显式标记不可作为 fresh summary 消费。"""
    resolved = canonical_target_value(target)
    base = {
        "available": False,
        "status": status,
        "reason": reason,
        "path": str(inventory_path(repo_root, resolved)),
        "summary_path": str(observation_summary_path(repo_root, resolved)),
        "total": 0,
        "present": 0,
        "untouched": 0,
        "reviewing": 0,
        "reviewed": 0,
        "parked": 0,
        "stale": 0,
        "last_synced_at": "",
        "sample": [],
        "inventory_binding": {},
        "needs_sync": True,
    }
    if isinstance(previous, dict):
        for key in (
            "total",
            "present",
            "untouched",
            "reviewing",
            "reviewed",
            "parked",
            "stale",
            "last_synced_at",
            "sample",
            "inventory_binding",
        ):
            if key in previous:
                base[key] = previous[key]
    return base


def _write_inventory_summary(
    repo_root: str | Path,
    target: str,
    payload: dict,
    *,
    inventory_binding: dict,
) -> dict:
    """在 canonical body 成功替换后发布带 binding 的小型摘要。"""
    resolved = canonical_target_value(target)
    summary = summarize_inventory(payload)
    sidecar = {
        "kind": SUMMARY_KIND,
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "target": resolved,
        "storage_key": target_storage_key(resolved),
        "source_fingerprint": str(payload.get("source_fingerprint") or ""),
        "page_order": str(payload.get("page_order") or ""),
        "inventory_binding": dict(inventory_binding),
        "generated_at": _now_utc(),
        "summary": summary,
    }
    _write_json_atomic(observation_summary_path(repo_root, resolved), sidecar)
    return {
        **summary,
        "status": "valid",
        "reason": "",
        "summary_path": str(observation_summary_path(repo_root, resolved)),
        "inventory_binding": dict(inventory_binding),
    }


def _binding_matches(path: Path, binding: dict) -> bool:
    try:
        stat = path.stat()
        expected_size = int(binding.get("size", -1))
        expected_mtime = int(binding.get("mtime_ns", -1))
        expected_ctime = int(binding.get("ctime_ns", -1))
        expected_dev = int(binding.get("st_dev", -1))
        expected_ino = int(binding.get("st_ino", -1))
    except (OSError, TypeError, ValueError):
        return False
    return (
        stat.st_size == expected_size
        and stat.st_mtime_ns == expected_mtime
        and stat.st_ctime_ns == expected_ctime
        and stat.st_dev == expected_dev
        and stat.st_ino == expected_ino
    )


def peek_inventory_summary(repo_root: str | Path, target: str) -> dict:
    """只读 sidecar + stat/source fingerprint；绝不解析 observations.json 正文。"""
    resolved = canonical_target_value(target)
    body_path = inventory_path(repo_root, resolved)
    summary_path = observation_summary_path(repo_root, resolved)
    if not summary_path.is_file():
        status = "summary_missing" if body_path.is_file() else "missing"
        return _summary_error(
            repo_root,
            resolved,
            status=status,
            reason="summary-sidecar-missing",
        )
    try:
        sidecar = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _summary_error(
            repo_root,
            resolved,
            status="invalid",
            reason=f"invalid-json: {exc}",
        )
    if not isinstance(sidecar, dict):
        return _summary_error(repo_root, resolved, status="invalid", reason="root-not-object")
    summary = sidecar.get("summary") if isinstance(sidecar.get("summary"), dict) else {}
    if sidecar.get("kind") != SUMMARY_KIND or sidecar.get("schema_version") != SUMMARY_SCHEMA_VERSION:
        return _summary_error(
            repo_root,
            resolved,
            status="invalid",
            reason="schema-mismatch",
            previous=summary,
        )
    if sidecar.get("target") != resolved or sidecar.get("storage_key") != target_storage_key(resolved):
        return _summary_error(
            repo_root,
            resolved,
            status="invalid",
            reason="target-mismatch",
            previous=summary,
        )
    binding = sidecar.get("inventory_binding") if isinstance(sidecar.get("inventory_binding"), dict) else {}
    projected = {
        **summary,
        "summary_path": str(summary_path),
        "inventory_binding": binding,
        "page_order": str(sidecar.get("page_order") or ""),
    }
    if not body_path.is_file() or not _binding_matches(body_path, binding):
        return _summary_error(
            repo_root,
            resolved,
            status="stale",
            reason="inventory-binding-mismatch",
            previous=projected,
        )
    recon_dir = Path(repo_root) / "recon" / target_storage_key(resolved)
    files = _source_files(recon_dir) if recon_dir.is_dir() else []
    if str(sidecar.get("source_fingerprint") or "") != _source_fingerprint(files):
        return _summary_error(
            repo_root,
            resolved,
            status="stale",
            reason="source-fingerprint-mismatch",
            previous=projected,
        )
    return {
        **projected,
        "available": bool(summary.get("available")),
        "status": "valid",
        "reason": "",
        "needs_sync": False,
    }


def sync_inventory_summary(
    repo_root: str | Path,
    target: str,
    *,
    force: bool = False,
) -> dict:
    """优先返回有效 sidecar；只有 explicit miss/stale 才执行完整 sync。"""
    if not force:
        cached = peek_inventory_summary(repo_root, target)
        if cached.get("status") == "valid":
            return cached
    payload = sync_inventory(repo_root, target, force=force)
    refreshed = peek_inventory_summary(repo_root, target)
    if refreshed.get("status") != "valid":
        raise InventoryError(
            "observation summary unavailable after sync: "
            f"{refreshed.get('status')} {refreshed.get('reason')}"
        )
    return refreshed


def touch_observation(
    repo_root: str | Path,
    target: str,
    observation_id: str,
    *,
    status: str,
    notes: str | None = None,
    now: str | None = None,
) -> dict:
    """更新审阅生命周期；不接受 tested/finding 等执行结果状态。"""
    normalized_status = str(status or "").strip().lower()
    if normalized_status not in ALLOWED_STATUSES:
        raise ValueError(f"invalid observation status: {status!r}")
    path = inventory_path(repo_root, target)
    with _inventory_lock(path):
        payload = load_inventory(repo_root, target)
        matched = None
        for item in payload.get("observations", []):
            if str(item.get("id") or "") != observation_id:
                continue
            item["status"] = normalized_status
            if notes is not None:
                item["notes"] = str(notes).strip()
            timestamp = now or _now_utc()
            item["status_updated_at"] = timestamp
            if normalized_status == "reviewed":
                item["reviewed_at"] = timestamp
            matched = item
            break
        if matched is None:
            raise KeyError(f"observation not found: {observation_id}")
        payload["page_order"] = PAGE_ORDER_FIRST_SEEN_ID
        payload["observations"].sort(key=_page_sort_key)
        binding = _write_json_atomic(path, payload)
        _write_inventory_summary(repo_root, target, payload, inventory_binding=binding)
        return matched


def _list_items(
    payload: dict,
    *,
    status: str = "",
    stale_only: bool = False,
    limit: int = 50,
) -> list[dict]:
    if limit < 0 or limit > MAX_LIST_LIMIT:
        raise ValueError(f"limit must be between 0 and {MAX_LIST_LIMIT}")
    normalized_status = str(status or "").strip().lower()
    if normalized_status and normalized_status not in ALLOWED_STATUSES:
        raise ValueError(f"invalid observation status: {status!r}")
    now = datetime.now(timezone.utc)
    items = []
    for item in payload.get("observations", []):
        if not isinstance(item, dict):
            continue
        if normalized_status and str(item.get("status") or "untouched") != normalized_status:
            continue
        if stale_only and not _is_stale(item, now, STALE_AFTER_SECONDS):
            continue
        items.append(item)
    items.sort(key=lambda item: (str(item.get("first_seen") or ""), str(item.get("id") or "")))
    return items[:limit]


def _load_inventory_snapshot(repo_root: str | Path, target: str) -> tuple[dict, str]:
    """一次读取 inventory 正文并返回内容 revision，供 cursor 绑定快照。"""
    path = inventory_path(repo_root, target)
    if not path.is_file():
        payload = _empty_inventory(target)
        revision = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return payload, revision
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"invalid observation inventory at {path}: {exc}") from exc
    return _validate_inventory(payload, path), hashlib.sha256(raw).hexdigest()


def _cursor_filters(*, status: str, kind: str, source: str) -> dict:
    return {
        "status": str(status or "").strip().lower(),
        "kind": str(kind or "").strip().lower(),
        "source": str(source or "").strip(),
    }


def _matches_page_filters(item: dict, filters: dict) -> bool:
    if filters["status"] and str(item.get("status") or "untouched").lower() != filters["status"]:
        return False
    if filters["kind"] and str(item.get("kind") or "").lower() != filters["kind"]:
        return False
    if filters["source"] and filters["source"] not in {
        str(value) for value in (item.get("sources") or [])
    }:
        return False
    return True


def _encode_cursor(
    *,
    target: str,
    revision: str,
    filters: dict,
    mode: str,
    offset: int = 0,
    remaining: int = 0,
    total_matching: int = 0,
    last_key: tuple[str, str] | None = None,
) -> str:
    payload = {
        "v": CURSOR_SCHEMA_VERSION,
        "target": canonical_target_value(target),
        "revision": revision,
        "filters": filters,
        "mode": mode,
    }
    if mode == "stream":
        payload.update(
            {
                "offset": offset,
                "remaining": remaining,
                "total_matching": total_matching,
            }
        )
    elif mode == "legacy" and last_key is not None:
        payload["last"] = [last_key[0], last_key[1]]
    else:  # pragma: no cover - 仅供内部调用，避免生成不能消费的 cursor
        raise ValueError("invalid observation cursor mode")
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(encoded.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> dict:
    text = str(cursor or "").strip()
    if not text:
        return {}
    try:
        padding = "=" * (-len(text) % 4)
        payload = json.loads(base64.urlsafe_b64decode(text + padding))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid observation cursor") from exc
    if not isinstance(payload, dict) or payload.get("v") != CURSOR_SCHEMA_VERSION:
        raise ValueError("invalid observation cursor schema")
    if not isinstance(payload.get("filters"), dict):
        raise ValueError("invalid observation cursor filters")
    mode = payload.get("mode")
    if mode == "stream":
        try:
            offset = int(payload.get("offset", -1))
            remaining = int(payload.get("remaining", -1))
            total_matching = int(payload.get("total_matching", -1))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid observation cursor position") from exc
        if offset < 0 or remaining < 0 or total_matching < remaining:
            raise ValueError("invalid observation cursor position")
        payload["offset"] = offset
        payload["remaining"] = remaining
        payload["total_matching"] = total_matching
    elif mode == "legacy":
        last = payload.get("last")
        if not isinstance(last, list) or len(last) != 2 or not all(isinstance(item, str) for item in last):
            raise ValueError("invalid observation cursor position")
    else:
        raise ValueError("invalid observation cursor mode")
    return payload


def _iter_ordered_inventory_rows(path: Path, *, offset: int | None = None) -> Iterator[tuple[dict, int, int]]:
    """流式读取 owner 写入的 pretty JSON observation array，并保留 byte offset。

    ``observations.json`` 仍是唯一的正文事实。这里依赖 owner 的稳定 JSON 编码，
    只在 sidecar 已确认 binding 与 ``page_order`` 时使用；任意 legacy/未知编码都由
    page 的兼容路径完整读取，避免读路径自行重写目标状态。
    """
    with path.open("rb") as handle:
        if offset is None:
            for raw in handle:
                if raw.strip() == b'"observations": [':
                    break
            else:
                raise InventoryError(f"invalid observation inventory at {path}: observations array missing")
        else:
            handle.seek(offset)

        while True:
            row_start = handle.tell()
            first = handle.readline()
            if not first:
                raise InventoryError(f"invalid observation inventory at {path}: observations array unterminated")
            stripped = first.strip()
            if not stripped:
                continue
            if stripped in {b"]", b"],"}:
                return
            if not stripped.startswith(b"{"):
                raise InventoryError(f"invalid observation inventory at {path}: malformed observation row")

            chunks = [first]
            depth = 0
            in_string = False
            escaped = False
            while True:
                for byte in chunks[-1]:
                    if in_string:
                        if escaped:
                            escaped = False
                        elif byte == ord("\\"):
                            escaped = True
                        elif byte == ord('"'):
                            in_string = False
                    elif byte == ord('"'):
                        in_string = True
                    elif byte == ord("{"):
                        depth += 1
                    elif byte == ord("}"):
                        depth -= 1
                if depth == 0 and not in_string:
                    break
                next_line = handle.readline()
                if not next_line:
                    raise InventoryError(f"invalid observation inventory at {path}: observation row unterminated")
                chunks.append(next_line)

            serialized = b"".join(chunks).strip()
            if serialized.endswith(b","):
                serialized = serialized[:-1]
            try:
                item = json.loads(serialized)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise InventoryError(f"invalid observation inventory at {path}: malformed observation row") from exc
            yield _validate_observation_item(item, path), row_start, handle.tell()


def _streaming_page(
    repo_root: str | Path,
    target: str,
    *,
    filters: dict,
    limit: int,
    summary: dict,
    decoded: dict | None,
) -> dict:
    """首次完整流式计数，后续 cursor 仅扫描到下一页所需的 observation。"""
    binding = summary.get("inventory_binding") if isinstance(summary.get("inventory_binding"), dict) else {}
    revision = str(binding.get("sha256") or "")
    path = inventory_path(repo_root, target)
    if not revision or not path.is_file():
        raise InventoryError("observation pagination requires a bound inventory summary")

    if decoded:
        if decoded.get("revision") != revision:
            raise InventoryError("stale observation cursor: inventory snapshot changed")
        prior_remaining = int(decoded["remaining"])
        total_matching = int(decoded["total_matching"])
        wanted = min(limit, prior_remaining)
        items = []
        next_offset = int(decoded["offset"])
        for item, _row_start, after_row in _iter_ordered_inventory_rows(path, offset=next_offset):
            if not _matches_page_filters(item, filters):
                continue
            items.append(item)
            next_offset = after_row
            if len(items) == wanted:
                break
        if len(items) != wanted:
            raise InventoryError("stale observation cursor: inventory page no longer matches snapshot")
        remaining = prior_remaining - len(items)
    else:
        items = []
        next_offset = 0
        total_matching = 0
        for item, _row_start, after_row in _iter_ordered_inventory_rows(path):
            if not _matches_page_filters(item, filters):
                continue
            total_matching += 1
            if len(items) < limit:
                items.append(item)
                next_offset = after_row
        remaining = total_matching - len(items)

    next_cursor = ""
    if items and remaining:
        next_cursor = _encode_cursor(
            target=target,
            revision=revision,
            filters=filters,
            mode="stream",
            offset=next_offset,
            remaining=remaining,
            total_matching=total_matching,
        )
    return {
        "snapshot_revision": revision,
        "items": items,
        "next_cursor": next_cursor,
        "remaining": remaining,
        "total_matching": total_matching,
    }


def _legacy_page(
    repo_root: str | Path,
    target: str,
    *,
    filters: dict,
    limit: int,
    decoded: dict | None,
) -> dict:
    """兼容旧正文：保留既有完整读取/排序语义，绝不在 page 路径升级文件。"""
    payload, revision = _load_inventory_snapshot(repo_root, target)
    if decoded and decoded.get("revision") != revision:
        raise InventoryError("stale observation cursor: inventory snapshot changed")

    matching = [
        item
        for item in payload.get("observations", [])
        if isinstance(item, dict) and _matches_page_filters(item, filters)
    ]
    matching.sort(key=_page_sort_key)
    start = 0
    if decoded:
        last_key = tuple(decoded["last"])
        positions = [
            index
            for index, item in enumerate(matching)
            if _page_sort_key(item) == last_key
        ]
        if len(positions) != 1:
            raise ValueError("invalid observation cursor anchor")
        start = positions[0] + 1

    items = matching[start : start + limit]
    remaining = max(0, len(matching) - start - len(items))
    next_cursor = ""
    if items and remaining:
        next_cursor = _encode_cursor(
            target=target,
            revision=revision,
            filters=filters,
            mode="legacy",
            last_key=_page_sort_key(items[-1]),
        )
    return {
        "snapshot_revision": revision,
        "items": items,
        "next_cursor": next_cursor,
        "remaining": remaining,
        "total_matching": len(matching),
    }


def page_inventory(
    repo_root: str | Path,
    target: str,
    *,
    status: str = "",
    kind: str = "",
    source: str = "",
    limit: int = 50,
    cursor: str = "",
) -> dict:
    """在同一 inventory 快照上稳定分页，不修改 observation lifecycle。"""
    if limit < 1 or limit > MAX_LIST_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
    filters = _cursor_filters(status=status, kind=kind, source=source)
    if filters["status"] and filters["status"] not in ALLOWED_STATUSES:
        raise ValueError(f"invalid observation status: {status!r}")

    decoded = _decode_cursor(cursor)
    if decoded:
        if decoded.get("target") != canonical_target_value(target):
            raise ValueError("observation cursor target mismatch")
        if decoded.get("filters") != filters:
            raise ValueError("observation cursor filter mismatch")

    if decoded and decoded.get("mode") == "legacy":
        return _legacy_page(
            repo_root,
            target,
            filters=filters,
            limit=limit,
            decoded=decoded,
        )

    summary = peek_inventory_summary(repo_root, target)
    has_streaming_owner_body = (
        summary.get("status") == "valid"
        and summary.get("page_order") == PAGE_ORDER_FIRST_SEEN_ID
        and bool((summary.get("inventory_binding") or {}).get("sha256"))
    )
    if decoded and decoded.get("mode") == "stream":
        if not has_streaming_owner_body:
            raise InventoryError("stale observation cursor: inventory snapshot changed")
        return _streaming_page(
            repo_root,
            target,
            filters=filters,
            limit=limit,
            summary=summary,
            decoded=decoded,
        )
    if has_streaming_owner_body:
        return _streaming_page(
            repo_root,
            target,
            filters=filters,
            limit=limit,
            summary=summary,
            decoded=None,
        )
    return _legacy_page(
        repo_root,
        target,
        filters=filters,
        limit=limit,
        decoded=None,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persist and inspect neutral recon observations")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    sub = parser.add_subparsers(dest="command", required=True)

    sync = sub.add_parser("sync", help="upsert current recon artifacts")
    sync.add_argument("--target", required=True)
    sync.add_argument("--force", action="store_true")

    summary = sub.add_parser("summary", help="show bounded untouched/stale counts")
    summary.add_argument("--target", required=True)

    listing = sub.add_parser("list", help="list observations without ranking")
    listing.add_argument("--target", required=True)
    listing.add_argument("--status", choices=sorted(ALLOWED_STATUSES), default="")
    listing.add_argument("--stale", action="store_true")
    listing.add_argument("--limit", type=int, default=50)

    page = sub.add_parser("page", help="page observations on one stable snapshot")
    page.add_argument("--target", required=True)
    page.add_argument("--status", choices=sorted(ALLOWED_STATUSES), default="")
    page.add_argument("--kind", default="")
    page.add_argument("--source", default="")
    page.add_argument("--limit", type=int, default=50)
    page.add_argument("--cursor", default="")

    touch = sub.add_parser("touch", help="update observation review lifecycle")
    touch.add_argument("--target", required=True)
    touch.add_argument("observation_id")
    touch.add_argument("--status", required=True, choices=sorted(ALLOWED_STATUSES))
    touch.add_argument("--notes", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "sync":
            output = sync_inventory_summary(args.repo_root, args.target, force=args.force)
        elif args.command == "summary":
            output = peek_inventory_summary(args.repo_root, args.target)
        elif args.command == "list":
            payload = load_inventory(args.repo_root, args.target)
            output = _list_items(
                payload,
                status=args.status,
                stale_only=args.stale,
                limit=args.limit,
            )
        elif args.command == "page":
            output = page_inventory(
                args.repo_root,
                args.target,
                status=args.status,
                kind=args.kind,
                source=args.source,
                limit=args.limit,
                cursor=args.cursor,
            )
        else:
            output = touch_observation(
                args.repo_root,
                args.target,
                args.observation_id,
                status=args.status,
                notes=args.notes,
            )
    except (InventoryError, KeyError, ValueError, OSError) as exc:
        print(f"observation_inventory: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
