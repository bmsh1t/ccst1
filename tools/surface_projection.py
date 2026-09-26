#!/usr/bin/env python3
"""Surface 派生投影的 manifest、原子发布与只读校验。

该模块只拥有可删除的性能投影，不拥有 recon、finding、action 或 evidence 生命周期。
bootstrap 只能消费 exact manifest hit；missing/stale/invalid 都必须显式请求 refresh。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    from tools.current_truth import current_cell_projection
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.target_store import runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from current_truth import current_cell_projection  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from target_store import runtime_store  # type: ignore


# Bump when selection semantics change; stale derived decisions must not replay.
SCHEMA_VERSION = 6
PROJECTION_KIND = "surface_projection"
MANIFEST_KIND = "surface_input_manifest"

# 这些目录/控制文件由 Recon 收尾阶段生成，不能反过来参与输入 fingerprint。
# `recon_manifest.jsonl` 在 projection 发布后写入，若纳入指纹会让刚发布的
# projection 立即变 stale；原始 surface artifact 仍完整保留。
_GENERATED_RECON_PARTS = frozenset({"surface", "recon_manifest.jsonl"})


def _semantic_closed_cells(value: object) -> list[dict]:
    """Keep closure identity/result while ignoring non-authoritative timestamps."""
    if not isinstance(value, list):
        return []
    cells: list[dict] = []
    for cell in value:
        if not isinstance(cell, dict):
            continue
        cells.append(
            {
                key: cell[key]
                for key in ("identity_v2", "endpoint", "vuln_class", "dimensions", "result")
                if key in cell
            }
        )
    cells.sort(key=lambda item: json.dumps(item, ensure_ascii=True, sort_keys=True))
    return cells


def _semantic_evidence_ledger(repo_root: Path, target: str) -> dict:
    """Project the Ledger closure owner without rewriting or hashing raw rows."""
    truth = current_cell_projection(repo_root, target)
    return {
        "kind": "target_store_closure_projection",
        "status": "invalid" if truth["health"].get("status") in {"partial", "unreadable"} else "ready",
        "store_id": truth["source"].get("store_id", ""),
        "revision": truth["source"].get("revision", 0),
        "closed_cells": _semantic_closed_cells(truth["projection"].get("closed_cells")),
        "closed_cells_v2": _semantic_closed_cells(truth["projection"].get("closed_cells_v2")),
    }


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def surface_projection_path(repo_root: str | Path, target: str) -> Path:
    resolved = canonical_target_value(target)
    return (
        Path(repo_root)
        / "state"
        / target_storage_key(resolved)
        / "surface-projection.json"
    )


def _path_label(repo_root: Path, path: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


def _iter_tree_entries(root: Path, *, skip_parts: frozenset[str] = frozenset()) -> Iterable[Path]:
    """按稳定顺序枚举目录和普通文件，只读取 metadata，不打开文件正文。"""
    if not root.exists():
        return
    if root.is_dir() and skip_parts:
        # 仅含 owner 控制目录的根等价于无业务输入，不能因首次建锁而进入 manifest。
        if not any(child.name not in skip_parts for child in root.iterdir()):
            return
    yield root
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:  # pragma: no cover - root/path 来自同一遍历
            continue
        if any(part in skip_parts for part in relative_parts):
            continue
        if path.is_dir() or path.is_file():
            yield path


def _manifest_roots(
    repo_root: Path,
    target: str,
    *,
    memory_dir: str | Path | None = None,
) -> list[tuple[Path, frozenset[str]]]:
    storage_key = target_storage_key(target)
    return [
        (repo_root / "recon" / storage_key, _GENERATED_RECON_PARTS),
        (repo_root / "findings" / storage_key, frozenset({".locks"})),
        (repo_root / "state" / storage_key / "metadata.sqlite3", frozenset()),
    ]


def build_surface_input_manifest(
    repo_root: str | Path,
    target: str,
    *,
    memory_dir: str | Path | None = None,
    as_of: str = "",
) -> dict:
    """构建稳定输入 manifest；目录只记结构，普通文件记录 metadata。"""
    repo = Path(repo_root).resolve()
    resolved = canonical_target_value(target)
    storage_key = target_storage_key(resolved)
    semantic_paths = {
        f"state/{storage_key}/metadata.sqlite3": _semantic_evidence_ledger,
    }
    # pattern_calibration 绑定已移除（审计 F9）：calibrated pattern 排除只
    # 影响已被删除的跨目标 PatternDB 匹配，surface 排序不再消费该文件；
    # 保留绑定只会让校准行写入无谓地使投影失效。
    items: list[dict] = []
    seen: set[str] = set()
    for root, skip_parts in _manifest_roots(repo, resolved, memory_dir=memory_dir):
        for path in _iter_tree_entries(root, skip_parts=skip_parts):
            label = _path_label(repo, path)
            if label in seen:
                continue
            seen.add(label)
            is_dir = path.is_dir()
            item = {"path": label, "kind": "dir" if is_dir else "file"}
            if not is_dir:
                try:
                    stat = path.stat()
                except OSError as exc:
                    raise OSError(f"cannot stat surface input {path}: {exc}") from exc
                item.update(
                    {
                        "size": int(stat.st_size),
                        "mtime_ns": int(stat.st_mtime_ns),
                        "ctime_ns": int(stat.st_ctime_ns),
                        "st_dev": int(stat.st_dev),
                        "st_ino": int(stat.st_ino),
                    }
                )
            items.append(item)
    items.sort(key=lambda item: (item["path"], item["kind"]))
    semantic_parent_paths = {
        parent.as_posix()
        for path in semantic_paths
        for parent in Path(path).parents
        if parent.as_posix() != "."
    }
    fingerprint_items: list[dict] = []
    for item in items:
        semantic_input = semantic_paths.get(str(item["path"]))
        if semantic_input is None:
            if item["kind"] == "dir" and str(item["path"]) in semantic_parent_paths:
                continue
            fingerprint_items.append(item)
            continue
        fingerprint_items.append(
            {
                "path": item["path"],
                "kind": item["kind"],
                "semantic": semantic_input(repo, resolved),
            }
        )
    present_paths = {str(item["path"]) for item in items}
    for path, semantic_input in semantic_paths.items():
        if path not in present_paths:
            fingerprint_items.append({
                "path": path,
                "kind": "file",
                "semantic": semantic_input(repo, resolved),
            })
    fingerprint_items.sort(key=lambda item: (item["path"], item["kind"]))
    encoded = json.dumps(
        fingerprint_items,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    binding = {"target": resolved, "policy_version": SCHEMA_VERSION, "as_of": str(as_of or "")}
    store = runtime_store(repo, resolved)
    with store._connection() as conn:
        meta = dict(conn.execute("SELECT store_id, revision FROM store WHERE singleton=1").fetchone())
    binding.update({"store_id": meta["store_id"], "revision": int(meta["revision"])})
    return {
        "kind": MANIFEST_KIND,
        "schema_version": SCHEMA_VERSION,
        "target": resolved,
        "storage_key": target_storage_key(resolved),
        "binding": binding,
        "fingerprint": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "items": items,
    }


def _write_json_atomic(path: Path, payload: dict) -> None:
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
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
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


def _bounded_surface(ranked: dict) -> dict:
    """限制投影集合大小，保留中性 URL 窗口及其完整性信息。"""
    allowed = (
        "available",
        "target",
        "runtime_state",
        "recon_artifacts",
        "observation_inventory",
        "memory",
        "target_memory",
        "scanner",
        "intel",
        "ffuf",
        "js_intel",
        "source_intel",
        "browser",
        "semantic_surface",
        "surface_index",
        "review_window",
        "evidence_refs",
        "stats",
    )
    surface = {key: ranked[key] for key in allowed if key in ranked}
    scanner = ranked.get("scanner") if isinstance(ranked.get("scanner"), dict) else {}
    manual_review = scanner.get("manual_review") if isinstance(scanner.get("manual_review"), list) else []
    bounded_manual_review = []
    for item in manual_review[:8]:
        if not isinstance(item, dict):
            continue
        try:
            count = max(0, int(item.get("count", 0) or 0))
        except (TypeError, ValueError):
            count = 0
        bounded_manual_review.append({
            "path": str(item.get("path") or "")[:512],
            "relative_path": str(item.get("relative_path") or "")[:512],
            "count": count,
            "preview": [str(line)[:240] for line in (item.get("preview") or [])[:3]],
        })
    surface["scanner"] = {
        **scanner,
        "manual_review": bounded_manual_review,
        "manual_review_total": len(manual_review),
        "manual_review_summary_path": str(scanner.get("manual_review_summary_path") or "")[:512],
    }
    surface["p1"] = list(ranked.get("p1") or [])[:8]
    surface["p2"] = list(ranked.get("p2") or [])[:8]
    surface["review_pool"] = list(ranked.get("review_pool") or [])[:16]
    surface["kill"] = list(ranked.get("kill") or [])[:32]
    surface["workflow_leads"] = list(ranked.get("workflow_leads") or [])[:32]
    index = ranked.get("surface_index") if isinstance(ranked.get("surface_index"), dict) else {}
    continuation = index.get("continuation") if isinstance(index.get("continuation"), dict) else {}
    surface["surface_index"] = {
        "status": str(index.get("status") or "missing"),
        "row_count": max(0, int(index.get("row_count", 0) or 0)),
        "index_revision": str(index.get("index_revision") or "")[:64],
        "continuation": {
            "available": bool(continuation.get("available")),
            "starts_at": str(continuation.get("starts_at") or ""),
            "scope": str(continuation.get("scope") or ""),
            "next_cursor": str(continuation.get("next_cursor") or ""),
            "command": str(continuation.get("command") or ""),
        },
    }
    return surface


def write_surface_projection(
    repo_root: str | Path,
    target: str,
    ranked: dict,
    *,
    manifest: dict | None = None,
    memory_dir: str | Path | None = None,
    as_of: str = "",
) -> Path:
    """原子发布 bounded projection；调用方必须先完成完整 ranking。"""
    resolved = canonical_target_value(target)
    current_manifest = manifest or build_surface_input_manifest(
        repo_root,
        resolved,
        memory_dir=memory_dir,
        as_of=as_of,
    )
    if current_manifest.get("target") != resolved:
        raise ValueError("surface manifest target mismatch")
    fingerprint = str(current_manifest.get("fingerprint") or "")
    if not fingerprint:
        raise ValueError("surface manifest lacks fingerprint")
    payload = {
        "kind": PROJECTION_KIND,
        "schema_version": SCHEMA_VERSION,
        "target": resolved,
        "storage_key": target_storage_key(resolved),
        "generated_at": _now_utc(),
        "complete": True,
        "input_fingerprint": fingerprint,
        "input_manifest": current_manifest,
        "surface": _bounded_surface(ranked),
    }
    path = surface_projection_path(repo_root, resolved)
    _write_json_atomic(path, payload)
    return path


def _projection_result(
    path: Path,
    status: str,
    reason: str = "",
    surface: dict | None = None,
    input_fingerprint: str = "",
) -> dict:
    result = {
        "status": status,
        "reason": reason,
        "path": str(path),
        "surface": surface or {},
    }
    if input_fingerprint:
        result["input_fingerprint"] = input_fingerprint
    return result


def load_surface_projection(
    repo_root: str | Path,
    target: str,
    *,
    memory_dir: str | Path | None = None,
) -> dict:
    """只在 schema、target 和当前 manifest 全部命中时返回可消费投影。"""
    resolved = canonical_target_value(target)
    store = runtime_store(repo_root, resolved)
    path = surface_projection_path(repo_root, resolved)
    if not path.is_file():
        return _projection_result(path, "missing", "projection-missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _projection_result(path, "invalid", f"invalid-json: {exc}")
    if not isinstance(payload, dict):
        return _projection_result(path, "invalid", "root-not-object")
    if payload.get("kind") != PROJECTION_KIND or payload.get("schema_version") != SCHEMA_VERSION:
        return _projection_result(path, "invalid", "schema-mismatch")
    if payload.get("target") != resolved or payload.get("storage_key") != target_storage_key(resolved):
        return _projection_result(path, "invalid", "target-mismatch")
    binding = payload.get("input_manifest", {}).get("binding") if isinstance(payload.get("input_manifest"), dict) else {}
    if not isinstance(binding, dict) or binding.get("target") != resolved:
        return _projection_result(path, "invalid", "store-binding-missing")
    if not isinstance(binding.get("as_of", ""), str):
        return _projection_result(path, "invalid", "as-of-binding-invalid")
    with store._connection() as conn:
        meta = dict(conn.execute("SELECT store_id, revision FROM store WHERE singleton=1").fetchone())
    if not payload.get("complete") or not isinstance(payload.get("surface"), dict):
        return _projection_result(path, "invalid", "incomplete-projection")
    try:
        current = build_surface_input_manifest(repo_root, resolved, memory_dir=memory_dir)
    except (OSError, ValueError) as exc:
        return _projection_result(path, "invalid", f"manifest-error: {exc}")
    current_fingerprint = str(current.get("fingerprint") or "")
    if binding.get("store_id") != meta["store_id"] or int(binding.get("revision", -1)) != int(meta["revision"]):
        return _projection_result(path, "stale", "store-revision-mismatch", input_fingerprint=current_fingerprint)
    if str(payload.get("input_fingerprint") or "") != current_fingerprint:
        return _projection_result(
            path,
            "stale",
            "input-manifest-mismatch",
            input_fingerprint=current_fingerprint,
        )
    return _projection_result(
        path,
        "valid",
        surface=payload["surface"],
        input_fingerprint=current_fingerprint,
    )
