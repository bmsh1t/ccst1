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
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
PROJECTION_KIND = "surface_projection"
MANIFEST_KIND = "surface_input_manifest"

# 这些目录由本模块自身生成，不能反过来参与输入 fingerprint。
_GENERATED_RECON_PARTS = frozenset({"surface"})


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
    roots: list[tuple[Path, frozenset[str]]] = [
        (repo_root / "recon" / storage_key, _GENERATED_RECON_PARTS),
        (repo_root / "findings" / storage_key, frozenset()),
        (repo_root / "memory" / "evidence" / storage_key, frozenset()),
        (repo_root / "memory" / "goals" / "targets" / f"{storage_key}.json", frozenset()),
        (repo_root / "memory" / "goals" / "active.json", frozenset()),
        (repo_root / "state" / storage_key / "action_queue.json", frozenset()),
        (repo_root / "state" / storage_key / "observations-summary.json", frozenset()),
    ]
    if memory_dir:
        memory_root = Path(memory_dir)
        roots.extend(
            [
                (memory_root / "targets" / f"{storage_key}.json", frozenset()),
                (memory_root / "patterns.jsonl", frozenset()),
                (memory_root / "pattern_calibration.jsonl", frozenset()),
            ]
        )
    return roots


def build_surface_input_manifest(
    repo_root: str | Path,
    target: str,
    *,
    memory_dir: str | Path | None = None,
) -> dict:
    """构建只含 path/stat 的稳定输入 manifest，不读取大型 artifact 正文。"""
    repo = Path(repo_root).resolve()
    resolved = canonical_target_value(target)
    items: list[dict] = []
    seen: set[str] = set()
    for root, skip_parts in _manifest_roots(repo, resolved, memory_dir=memory_dir):
        for path in _iter_tree_entries(root, skip_parts=skip_parts):
            label = _path_label(repo, path)
            if label in seen:
                continue
            seen.add(label)
            try:
                stat = path.stat()
            except OSError as exc:
                raise OSError(f"cannot stat surface input {path}: {exc}") from exc
            items.append(
                {
                    "path": label,
                    "kind": "dir" if path.is_dir() else "file",
                    "size": int(stat.st_size),
                    "mtime_ns": int(stat.st_mtime_ns),
                }
            )
    items.sort(key=lambda item: (item["path"], item["kind"]))
    encoded = json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "kind": MANIFEST_KIND,
        "schema_version": SCHEMA_VERSION,
        "target": resolved,
        "storage_key": target_storage_key(resolved),
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
    """限制投影集合大小；candidate 已是 surface scorer 的有界证据摘要。"""
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
        "stats",
    )
    surface = {key: ranked[key] for key in allowed if key in ranked}
    surface["p1"] = list(ranked.get("p1") or [])[:8]
    surface["p2"] = list(ranked.get("p2") or [])[:8]
    surface["review_pool"] = list(ranked.get("review_pool") or [])[:16]
    surface["kill"] = list(ranked.get("kill") or [])[:32]
    surface["workflow_leads"] = list(ranked.get("workflow_leads") or [])[:32]
    return surface


def write_surface_projection(
    repo_root: str | Path,
    target: str,
    ranked: dict,
    *,
    manifest: dict | None = None,
    memory_dir: str | Path | None = None,
) -> Path:
    """原子发布 bounded projection；调用方必须先完成完整 ranking。"""
    resolved = canonical_target_value(target)
    current_manifest = manifest or build_surface_input_manifest(
        repo_root,
        resolved,
        memory_dir=memory_dir,
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


def _projection_result(path: Path, status: str, reason: str = "", surface: dict | None = None) -> dict:
    return {
        "status": status,
        "reason": reason,
        "path": str(path),
        "surface": surface or {},
    }


def load_surface_projection(
    repo_root: str | Path,
    target: str,
    *,
    memory_dir: str | Path | None = None,
) -> dict:
    """只在 schema、target 和当前 manifest 全部命中时返回可消费投影。"""
    resolved = canonical_target_value(target)
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
    if not payload.get("complete") or not isinstance(payload.get("surface"), dict):
        return _projection_result(path, "invalid", "incomplete-projection")
    try:
        current = build_surface_input_manifest(repo_root, resolved, memory_dir=memory_dir)
    except OSError as exc:
        return _projection_result(path, "invalid", f"manifest-error: {exc}")
    if str(payload.get("input_fingerprint") or "") != current["fingerprint"]:
        return _projection_result(path, "stale", "input-manifest-mismatch")
    return _projection_result(path, "valid", surface=payload["surface"])
