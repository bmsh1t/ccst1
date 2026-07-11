#!/usr/bin/env python3
"""持久化 recon observations，提供中性的 untouched/stale 可见性。

该模块只记录“发现了什么”和“是否审阅过”，不判断漏洞类别、攻击价值，
也不选择 Skill。可执行动作和测试结果仍分别归 action_queue 与 evidence_ledger。
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
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
STALE_AFTER_SECONDS = 2 * 24 * 60 * 60
ALLOWED_STATUSES = frozenset({"untouched", "reviewing", "reviewed", "parked"})
DEFAULT_SAMPLE_LIMIT = 8
MAX_LIST_LIMIT = 1000

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


def _empty_inventory(target: str) -> dict:
    resolved = canonical_target_value(target)
    return {
        "schema_version": SCHEMA_VERSION,
        "target": resolved,
        "storage_key": target_storage_key(resolved),
        "source_fingerprint": "",
        "last_synced_at": "",
        "observations": [],
    }


def _validate_inventory(payload: object, path: Path) -> dict:
    if not isinstance(payload, dict):
        raise InventoryError(f"invalid observation inventory at {path}: root must be an object")
    observations = payload.get("observations")
    if not isinstance(observations, list):
        raise InventoryError(f"invalid observation inventory at {path}: observations must be a list")
    for index, item in enumerate(observations):
        if not isinstance(item, dict) or not str(item.get("id") or "").strip():
            raise InventoryError(
                f"invalid observation inventory at {path}: observations[{index}] lacks a stable id"
            )
        status = str(item.get("status") or "untouched")
        if status not in ALLOWED_STATUSES:
            raise InventoryError(
                f"invalid observation inventory at {path}: observations[{index}] has status {status!r}"
            )
    return payload


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


def _write_json_atomic(path: Path, payload: dict) -> None:
    """同目录临时文件 + replace，避免读者看到半截 JSON。"""
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
    """使用 path/size/mtime 判断 recon artifact 是否发生变化。"""
    digest = hashlib.sha256()
    for kind, relative_path, path in files:
        stat = path.stat()
        digest.update(
            f"{kind}\0{relative_path.as_posix()}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode()
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
                item = {
                    **row,
                    "status": "untouched",
                    "notes": "",
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "seen_count": 1,
                    "present": True,
                }
            else:
                item = {
                    **previous,
                    **row,
                    "last_seen": timestamp,
                    "seen_count": int(previous.get("seen_count", 0) or 0) + 1,
                    "present": True,
                }
                item.setdefault("status", "untouched")
                item.setdefault("notes", "")
                item.setdefault("first_seen", timestamp)
            merged.append(item)

        for previous in existing.values():
            previous["present"] = False
            merged.append(previous)

        merged.sort(key=lambda item: str(item.get("id") or ""))
        updated = {
            "schema_version": SCHEMA_VERSION,
            "target": resolved,
            "storage_key": target_storage_key(resolved),
            "source_fingerprint": fingerprint,
            "last_synced_at": timestamp,
            "observations": merged,
        }
        _write_json_atomic(path, updated)
        return updated


def _is_stale(item: dict, now: datetime, stale_after_seconds: int) -> bool:
    if str(item.get("status") or "untouched") != "untouched":
        return False
    first_seen = _parse_utc(item.get("first_seen"))
    if first_seen is None:
        return False
    return (now - first_seen).total_seconds() >= stale_after_seconds


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

    sample_candidates = [
        item for item in observations
        if str(item.get("status") or "untouched") == "untouched"
    ] or observations
    neutral_order = sorted(
        sample_candidates,
        key=lambda item: (str(item.get("first_seen") or ""), str(item.get("id") or "")),
    )
    sample = []
    for item in neutral_order[: max(0, sample_limit)]:
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
        _write_json_atomic(path, payload)
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
            payload = sync_inventory(args.repo_root, args.target, force=args.force)
            output = summarize_inventory(payload)
        elif args.command == "summary":
            output = summarize_inventory(load_inventory(args.repo_root, args.target))
        elif args.command == "list":
            payload = load_inventory(args.repo_root, args.target)
            output = _list_items(
                payload,
                status=args.status,
                stale_only=args.stale,
                limit=args.limit,
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
