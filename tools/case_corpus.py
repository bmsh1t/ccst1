#!/usr/bin/env python3
"""本地、只读的规范化披露案例 corpus 构建与查询工具。

该模块只处理 ``distill/work/*.jsonl`` 中已经过字段筛选的行，不联网、不启动服务，
也不把案例状态写入 finding、evidence ledger 或 target memory。构建阶段生成一个小型
JSONL + byte-offset 索引；查询阶段只读取索引和请求的单行记录。
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Iterable

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.distill_reports import normalize_report
    from tools.knowledge_registry import (
        KnowledgeRegistryError,
        REPORT_ID_RE,
        SOURCE_REF_CORPUS,
        load_registry,
        parse_knowledge_document,
        parse_source_refs,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from distill_reports import normalize_report  # type: ignore
    from knowledge_registry import (  # type: ignore
        KnowledgeRegistryError,
        REPORT_ID_RE,
        SOURCE_REF_CORPUS,
        load_registry,
        parse_knowledge_document,
        parse_source_refs,
    )


CORPUS_NAME = SOURCE_REF_CORPUS
SCHEMA_VERSION = 1
DEFAULT_REPO_ROOT = BASE_DIR
DEFAULT_CORPUS_DIR = DEFAULT_REPO_ROOT / "distill" / "corpus"
DEFAULT_WORK_DIR = DEFAULT_REPO_ROOT / "distill" / "work"
DATA_FILE = "reports.jsonl"
INDEX_FILE = "index.json"
MANIFEST_FILE = "manifest.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NORMALIZED_FIELDS = (
    "id",
    "title",
    "vulnerability_information",
    "substate",
    "weakness",
    "has_bounty",
    "vote_count",
)
SUMMARY_FIELDS = ("id", "title", "substate", "weakness", "has_bounty", "vote_count")


class CaseCorpusError(RuntimeError):
    """输入或 corpus 契约错误。"""


class CaseCorpusStale(CaseCorpusError):
    """manifest 与当前 artifact 已不一致，需要显式重建。"""


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_report_id(value: Any, *, path: str = "id") -> str:
    """将整数/数字字符串统一成 source_refs 使用的非零十进制字符串。"""
    if isinstance(value, bool):
        raise CaseCorpusError(f"{path} 必须是非零十进制 ID")
    if isinstance(value, int):
        candidate = str(value)
    elif isinstance(value, str):
        candidate = value.strip()
    else:
        raise CaseCorpusError(f"{path} 必须是整数或数字字符串")
    if not REPORT_ID_RE.fullmatch(candidate):
        raise CaseCorpusError(f"{path} 必须是非零十进制 ID")
    return candidate


# Public alias for consumers that need the same ID contract without importing a private helper.
canonical_report_id = _canonical_report_id


def _normalize_case(row: Any, *, path: str) -> dict[str, Any]:
    """复用 distill 的白名单投影，并固定案例 ID/字段形状。"""
    if not isinstance(row, dict):
        raise CaseCorpusError(f"{path} 必须是 JSON object")
    projected = normalize_report(row)
    report_id = _canonical_report_id(projected.get("id"), path=f"{path}.id")
    projected["id"] = report_id
    # 查询契约要求这些字段可稳定序列化；缺失字段保留为 null/空值，而不猜测内容。
    for field in NORMALIZED_FIELDS:
        projected.setdefault(field, None)
    if projected.get("title") is not None and not isinstance(projected["title"], str):
        projected["title"] = str(projected["title"])
    for field in ("vulnerability_information", "substate", "weakness"):
        value = projected.get(field)
        if value is not None and not isinstance(value, str):
            projected[field] = str(value)
    if projected.get("has_bounty") is not None and not isinstance(projected["has_bounty"], bool):
        # 数据集中偶尔出现 0/1；只接受明确的数值布尔值，避免把任意字符串当真值。
        if isinstance(projected["has_bounty"], int) and projected["has_bounty"] in (0, 1):
            projected["has_bounty"] = bool(projected["has_bounty"])
        else:
            raise CaseCorpusError(f"{path}.has_bounty 必须是 boolean/null")
    if projected.get("vote_count") is not None and (
        isinstance(projected["vote_count"], bool)
        or not isinstance(projected["vote_count"], int)
    ):
        raise CaseCorpusError(f"{path}.vote_count 必须是 integer/null")
    # 只写白名单字段，避免未来 normalize_report 扩展时泄漏额外字段。
    return {field: projected.get(field) for field in NORMALIZED_FIELDS}


def _class_key(value: Any) -> str:
    return str(value or "").strip().casefold()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    """在目标目录内原子写 JSON，失败时清理临时文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def _input_paths(paths: Iterable[Path] | None, work_dir: Path) -> list[Path]:
    selected = [Path(path) for path in (paths or ())]
    if not selected:
        selected = sorted(work_dir.glob("batch_*.jsonl"))
    if not selected:
        raise CaseCorpusError(
            f"找不到输入 JSONL；请传入 --input PATH，或在 {work_dir} 放置 batch_*.jsonl"
        )
    for path in selected:
        if not path.is_file():
            raise CaseCorpusError(f"输入文件不存在: {path}")
    return selected


def build_corpus(
    inputs: Iterable[Path | str] | None = None,
    *,
    corpus_dir: Path | str = DEFAULT_CORPUS_DIR,
    work_dir: Path | str = DEFAULT_WORK_DIR,
) -> dict[str, Any]:
    """流式构建 corpus；重复/坏行在替换旧文件前 fail-fast。"""
    destination = Path(corpus_dir)
    input_paths = _input_paths(
        [Path(path) for path in inputs] if inputs is not None else None,
        Path(work_dir),
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.build-", dir=str(destination.parent))
    )
    data_path = staging / DATA_FILE
    seen: dict[str, str] = {}
    by_id: dict[str, dict[str, Any]] = {}
    by_class: dict[str, list[str]] = {}
    records = 0
    try:
        with data_path.open("wb") as output:
            for input_path in input_paths:
                with input_path.open("r", encoding="utf-8") as source:
                    for line_number, raw_line in enumerate(source, start=1):
                        if not raw_line.strip():
                            continue
                        location = f"{input_path}:{line_number}"
                        try:
                            row = json.loads(raw_line)
                        except json.JSONDecodeError as exc:
                            raise CaseCorpusError(f"{location} JSON 无效: {exc.msg}") from exc
                        normalized = _normalize_case(row, path=location)
                        report_id = normalized["id"]
                        previous = seen.get(report_id)
                        if previous is not None:
                            raise CaseCorpusError(
                                f"重复 report ID {report_id}: {previous} 与 {location}"
                            )
                        seen[report_id] = location
                        encoded = (
                            json.dumps(
                                normalized,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                            + b"\n"
                        )
                        offset = output.tell()
                        output.write(encoded)
                        weakness = str(normalized.get("weakness") or "")
                        by_id[report_id] = {
                            "offset": offset,
                            "length": len(encoded),
                            "sha256": _sha256_bytes(encoded),
                            "weakness": weakness,
                        }
                        class_key = _class_key(weakness)
                        if class_key:
                            by_class.setdefault(class_key, []).append(report_id)
                        records += 1
            output.flush()
            os.fsync(output.fileno())

        data_size = data_path.stat().st_size
        data_mtime_ns = data_path.stat().st_mtime_ns
        data_sha256 = _sha256_file(data_path)
        # 数值排序让 search 在不同输入批次下保持稳定且符合 report ID 直觉。
        for ids in by_class.values():
            ids.sort(key=lambda value: (int(value), value))
        index = {
            "schema_version": SCHEMA_VERSION,
            "corpus": CORPUS_NAME,
            "records": records,
            "data_file": DATA_FILE,
            "by_id": by_id,
            "by_class": dict(sorted(by_class.items())),
        }
        index_path = staging / INDEX_FILE
        _atomic_json(index_path, index)
        index_stat = index_path.stat()
        index_sha256 = _sha256_file(index_path)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "corpus": CORPUS_NAME,
            "records": records,
            "data_file": DATA_FILE,
            "index_file": INDEX_FILE,
            "data_size": data_size,
            "data_mtime_ns": data_mtime_ns,
            "data_sha256": data_sha256,
            "index_size": index_stat.st_size,
            "index_mtime_ns": index_stat.st_mtime_ns,
            "index_sha256": index_sha256,
            "normalized_fields": list(NORMALIZED_FIELDS),
            "inputs": [str(path) for path in input_paths],
            "built_at": _now_utc(),
        }
        _atomic_json(staging / MANIFEST_FILE, manifest)
        # 全部校验完成后才替换旧的三个 artifact；重复/坏行不会破坏旧 corpus。
        destination.mkdir(parents=True, exist_ok=True)
        for filename in (DATA_FILE, INDEX_FILE, MANIFEST_FILE):
            (staging / filename).replace(destination / filename)
        return {
            "status": "available",
            "corpus": CORPUS_NAME,
            "records": records,
            "data_file": str(destination / DATA_FILE),
            "index_file": str(destination / INDEX_FILE),
            "manifest_file": str(destination / MANIFEST_FILE),
        }
    except Exception:
        # staging 只包含本次构建产物；旧 corpus 保持不变。
        raise
    finally:
        for child in staging.iterdir():
            try:
                child.unlink()
            except OSError:
                pass
        try:
            staging.rmdir()
        except OSError:
            pass


def _base_result(status: str, *, reason: str = "", corpus_dir: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "corpus": CORPUS_NAME,
        "records": 0,
        "reason": reason,
    }
    if corpus_dir is not None:
        result["corpus_dir"] = str(corpus_dir)
    return result


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CaseCorpusError(f"无法读取 {label}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CaseCorpusError(f"{label} JSON 无效: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise CaseCorpusError(f"{label} 根节点必须是 object")
    return value


def _validate_index(index: dict[str, Any], data_size: int) -> None:
    if index.get("schema_version") != SCHEMA_VERSION:
        raise CaseCorpusError("index schema_version 不受支持")
    if index.get("corpus") != CORPUS_NAME:
        raise CaseCorpusError("index corpus 不匹配")
    by_id = index.get("by_id")
    by_class = index.get("by_class")
    if not isinstance(by_id, dict) or not isinstance(by_class, dict):
        raise CaseCorpusError("index 必须包含 object 类型的 by_id/by_class")
    records = index.get("records")
    if isinstance(records, bool) or not isinstance(records, int) or records != len(by_id):
        raise CaseCorpusError("index.records 与 by_id 数量不一致")
    for report_id, entry in by_id.items():
        _canonical_report_id(report_id, path="index.by_id key")
        if not isinstance(entry, dict):
            raise CaseCorpusError(f"index.by_id[{report_id}] 必须是 object")
        offset = entry.get("offset")
        length = entry.get("length")
        digest = entry.get("sha256")
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
            or isinstance(length, bool)
            or not isinstance(length, int)
            or length <= 0
            or offset + length > data_size
            or not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
        ):
            raise CaseCorpusError(f"index.by_id[{report_id}] offset/length/sha256 无效")
        if not isinstance(entry.get("weakness"), str):
            raise CaseCorpusError(f"index.by_id[{report_id}].weakness 必须是 string")
    for class_key, ids in by_class.items():
        if (
            not isinstance(class_key, str)
            or not class_key
            or class_key != class_key.casefold().strip()
        ):
            raise CaseCorpusError("index.by_class key 必须是规范化 lowercase 字符串")
        if not isinstance(ids, list) or any(not isinstance(item, str) for item in ids):
            raise CaseCorpusError(f"index.by_class[{class_key}] 必须是字符串 ID 列表")
        if len(ids) != len(set(ids)):
            raise CaseCorpusError(f"index.by_class[{class_key}] 必须是无重复 ID 列表")
        for report_id in ids:
            if report_id not in by_id:
                raise CaseCorpusError(f"index.by_class[{class_key}] 引用未知 ID {report_id}")


def _load_state(corpus_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """读取并校验 manifest/index/data 元信息；不返回 corpus 正文。"""
    data_path = corpus_dir / DATA_FILE
    index_path = corpus_dir / INDEX_FILE
    manifest_path = corpus_dir / MANIFEST_FILE
    if not corpus_dir.exists():
        raise FileNotFoundError("corpus directory missing")
    if not all(path.is_file() for path in (data_path, index_path, manifest_path)):
        raise CaseCorpusError("corpus artifact 缺失")
    manifest = _read_json_object(manifest_path, "manifest")
    index = _read_json_object(index_path, "index")
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("corpus") != CORPUS_NAME:
        raise CaseCorpusError("manifest schema/corpus 不匹配")
    if manifest.get("data_file") != DATA_FILE or manifest.get("index_file") != INDEX_FILE:
        raise CaseCorpusError("manifest 文件名不匹配")
    stat = data_path.stat()
    if manifest.get("data_size") != stat.st_size or manifest.get("data_mtime_ns") != stat.st_mtime_ns:
        raise CaseCorpusStale("data-size-or-mtime-mismatch")
    index_stat = index_path.stat()
    _validate_index(index, stat.st_size)
    if manifest.get("index_size") != index_stat.st_size or manifest.get("index_mtime_ns") != index_stat.st_mtime_ns:
        raise CaseCorpusStale("index-size-or-mtime-mismatch")
    if manifest.get("records") != index.get("records"):
        raise CaseCorpusError("manifest.records 与 index.records 不一致")
    return manifest, index, {"data_path": data_path, "index_path": index_path, "manifest_path": manifest_path}


def corpus_status(
    *,
    corpus_dir: Path | str = DEFAULT_CORPUS_DIR,
) -> dict[str, Any]:
    """返回 available/unavailable/stale/invalid，不抛出可恢复的查询状态。"""
    directory = Path(corpus_dir)
    result = _base_result("unavailable", corpus_dir=directory)
    if not directory.is_dir():
        result["reason"] = "corpus-missing"
        return result
    required = (directory / DATA_FILE, directory / INDEX_FILE, directory / MANIFEST_FILE)
    if not all(path.is_file() for path in required):
        result["reason"] = "corpus-artifacts-missing"
        return result
    try:
        manifest, index, paths = _load_state(directory)
    except FileNotFoundError:
        result["reason"] = "corpus-missing"
        return result
    except CaseCorpusStale as exc:
        result["status"] = "stale"
        result["reason"] = str(exc)
        return result
    except (OSError, CaseCorpusError) as exc:
        result["status"] = "invalid"
        result["reason"] = str(exc)
        return result
    data_path = paths["data_path"]
    result["records"] = int(index["records"])
    result["manifest"] = {
        "data_size": manifest.get("data_size"),
        "data_mtime_ns": manifest.get("data_mtime_ns"),
        "data_sha256": manifest.get("data_sha256"),
        "index_size": manifest.get("index_size"),
        "index_mtime_ns": manifest.get("index_mtime_ns"),
        "index_sha256": manifest.get("index_sha256"),
    }
    expected_data_hash = manifest.get("data_sha256")
    expected_index_hash = manifest.get("index_sha256")
    if not isinstance(expected_data_hash, str) or not SHA256_RE.fullmatch(expected_data_hash):
        result["status"] = "invalid"
        result["reason"] = "manifest.data_sha256 无效"
        return result
    if not isinstance(expected_index_hash, str) or not SHA256_RE.fullmatch(expected_index_hash):
        result["status"] = "invalid"
        result["reason"] = "manifest.index_sha256 无效"
        return result
    if _sha256_file(data_path) != expected_data_hash:
        result["status"] = "stale"
        result["reason"] = "data-hash-mismatch"
        return result
    if _sha256_file(paths["index_path"]) != expected_index_hash:
        result["status"] = "stale"
        result["reason"] = "index-hash-mismatch"
        return result
    result["status"] = "available"
    result["reason"] = ""
    return result


def _load_available(corpus_dir: Path) -> tuple[dict[str, Any], dict[str, Any], Path] | dict[str, Any]:
    """加载查询所需的索引，不在每次查询时重新哈希整个 corpus。"""
    if not corpus_dir.is_dir():
        return _base_result("unavailable", reason="corpus-missing", corpus_dir=corpus_dir)
    required = (corpus_dir / DATA_FILE, corpus_dir / INDEX_FILE, corpus_dir / MANIFEST_FILE)
    if not all(path.is_file() for path in required):
        return _base_result(
            "unavailable",
            reason="corpus-artifacts-missing",
            corpus_dir=corpus_dir,
        )
    try:
        manifest, index, paths = _load_state(corpus_dir)
    except FileNotFoundError:
        return _base_result("unavailable", reason="corpus-missing", corpus_dir=corpus_dir)
    except CaseCorpusStale as exc:
        return _base_result("stale", reason=str(exc), corpus_dir=corpus_dir)
    except (OSError, CaseCorpusError) as exc:
        return _base_result("invalid", reason=str(exc), corpus_dir=corpus_dir)
    return manifest, index, paths["data_path"]


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    return {field: record.get(field) for field in SUMMARY_FIELDS}


def _read_record(data_path: Path, entry: dict[str, Any], report_id: str) -> dict[str, Any]:
    try:
        with data_path.open("rb") as handle:
            handle.seek(entry["offset"])
            raw = handle.read(entry["length"])
    except OSError as exc:
        raise CaseCorpusError(f"读取 report {report_id} 失败: {exc}") from exc
    if len(raw) != entry["length"] or _sha256_bytes(raw) != entry["sha256"]:
        raise CaseCorpusError(f"report {report_id} offset/hash 校验失败")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaseCorpusError(f"report {report_id} JSON 损坏") from exc
    if not isinstance(record, dict) or record.get("id") != report_id:
        raise CaseCorpusError(f"report {report_id} 身份校验失败")
    try:
        normalized = _normalize_case(record, path=f"report {report_id}")
    except CaseCorpusError as exc:
        raise CaseCorpusError(f"report {report_id} schema 校验失败: {exc}") from exc
    if str(entry.get("weakness") or "") != str(normalized.get("weakness") or ""):
        raise CaseCorpusError(f"report {report_id} index weakness 不匹配")
    # 再次限制输出字段，防止手工改写 JSONL 后泄漏额外键。
    return normalized


def get_case(
    report_id: str | int,
    *,
    corpus_dir: Path | str = DEFAULT_CORPUS_DIR,
    full: bool = False,
) -> dict[str, Any]:
    directory = Path(corpus_dir)
    canonical_id = _canonical_report_id(report_id, path="report_id")
    loaded = _load_available(directory)
    if isinstance(loaded, dict):
        loaded.setdefault("report_id", canonical_id)
        loaded.setdefault("summary", None)
        loaded.setdefault("payload", None)
        return loaded
    _, index, data_path = loaded
    entry = index["by_id"].get(canonical_id)
    if entry is None:
        return {
            "status": "not-found",
            "corpus": CORPUS_NAME,
            "report_id": canonical_id,
            "summary": None,
            "payload": None,
            "reason": "report-id-not-indexed",
        }
    try:
        record = _read_record(data_path, entry, canonical_id)
    except CaseCorpusError as exc:
        return {
            "status": "invalid",
            "corpus": CORPUS_NAME,
            "report_id": canonical_id,
            "summary": None,
            "payload": None,
            "reason": str(exc),
        }
    return {
        "status": "ok",
        "corpus": CORPUS_NAME,
        "report_id": canonical_id,
        "summary": _summary(record),
        "payload": record if full else None,
        "reason": "",
    }


def _card_source_refs(repo_root: Path, card_id: str) -> tuple[list[dict[str, str]], str | None]:
    try:
        registry = load_registry(repo_root)
    except KnowledgeRegistryError as exc:
        return [], str(exc)
    try:
        paths = registry.card_paths()
    except KnowledgeRegistryError as exc:
        return [], str(exc)
    relative = paths.get(card_id)
    if relative is None:
        return [], f"unknown-card:{card_id}"
    card_path = repo_root / relative
    if not card_path.is_file():
        return [], f"card-file-missing:{relative}"
    try:
        parsed = parse_knowledge_document(card_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        return [], str(exc)
    if parsed.frontmatter_error:
        return [], parsed.frontmatter_error
    if parsed.metadata is None:
        return [], "card-frontmatter-missing"
    try:
        refs = parse_source_refs(parsed.metadata, source_path=relative)
    except KnowledgeRegistryError as exc:
        return [], str(exc)
    return [ref.as_dict() for ref in refs], None


def from_card(
    card_id: str,
    *,
    repo_root: Path | str = DEFAULT_REPO_ROOT,
    corpus_dir: Path | str = DEFAULT_CORPUS_DIR,
    report_id: str | int | None = None,
    full: bool = False,
) -> dict[str, Any]:
    """从 active card 的 source_refs 展开至多一个摘要/完整案例。"""
    root = Path(repo_root)
    refs, error = _card_source_refs(root, card_id)
    if error:
        return {
            "status": "not-found" if error.startswith("unknown-card:") else "invalid",
            "corpus": CORPUS_NAME,
            "card_id": card_id,
            "source_refs": [],
            "pointers": [],
            "summary": None,
            "payload": None,
            "reason": error,
        }
    pointers = [ref["id"] for ref in refs]
    result_base: dict[str, Any] = {
        "card_id": card_id,
        "corpus": CORPUS_NAME,
        "source_refs": refs,
        "pointers": pointers,
        "dangling_refs": [],
        "summary": None,
        "payload": None,
    }
    if not refs:
        result_base.update({"status": "not-found", "reason": "card-has-no-source-refs"})
        return result_base
    if full and report_id is None:
        result_base.update({"status": "invalid", "reason": "--full requires --report-id"})
        return result_base
    selected: str | None = None
    if report_id is not None:
        try:
            selected = _canonical_report_id(report_id, path="report_id")
        except CaseCorpusError as exc:
            result_base.update({"status": "invalid", "reason": str(exc)})
            return result_base
        if selected not in pointers:
            result_base.update({"status": "not-found", "reason": "report-id-not-in-card-source-refs"})
            return result_base
    loaded = _load_available(Path(corpus_dir))
    if isinstance(loaded, dict):
        result_base.update(loaded)
        result_base["card_id"] = card_id
        result_base["source_refs"] = refs
        result_base["pointers"] = pointers
        result_base["dangling_refs"] = pointers
        return result_base
    _, index, data_path = loaded
    candidates = [selected] if selected else pointers
    for candidate in candidates:
        if candidate is None:
            continue
        entry = index["by_id"].get(candidate)
        if entry is None:
            result_base["dangling_refs"].append(candidate)
            continue
        try:
            record = _read_record(data_path, entry, candidate)
        except CaseCorpusError as exc:
            result_base.update({"status": "invalid", "reason": str(exc)})
            return result_base
        result_base.update(
            {
                "status": "ok",
                "report_id": candidate,
                "summary": _summary(record),
                "payload": record if full else None,
                "reason": "",
            }
        )
        return result_base
    result_base.update({"status": "not-found", "reason": "card-source-refs-dangling"})
    return result_base


def search_cases(
    weakness: str,
    *,
    corpus_dir: Path | str = DEFAULT_CORPUS_DIR,
    limit: int = 20,
) -> dict[str, Any]:
    if not isinstance(weakness, str) or not weakness.strip():
        raise ValueError("--class 不能为空")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit 必须是正整数")
    limit = min(limit, 100)
    directory = Path(corpus_dir)
    loaded = _load_available(directory)
    if isinstance(loaded, dict):
        loaded.update({"query": weakness, "results": [], "count": 0})
        return loaded
    _, index, data_path = loaded
    class_key = _class_key(weakness)
    ids = index["by_class"].get(class_key, [])[:limit]
    results: list[dict[str, Any]] = []
    for report_id in ids:
        entry = index["by_id"].get(report_id)
        if entry is None:
            return {
                "status": "invalid",
                "corpus": CORPUS_NAME,
                "query": weakness,
                "results": [],
                "count": 0,
                "reason": f"index.by_class 引用未知 ID {report_id}",
            }
        try:
            record = _read_record(data_path, entry, report_id)
        except CaseCorpusError as exc:
            return {
                "status": "invalid",
                "corpus": CORPUS_NAME,
                "query": weakness,
                "results": [],
                "count": 0,
                "reason": str(exc),
            }
        results.append(_summary(record))
    return {
        "status": "ok",
        "corpus": CORPUS_NAME,
        "query": weakness,
        "class": class_key,
        "results": results,
        "count": len(results),
        "reason": "",
    }


def _print_result(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return
    status = result.get("status", "unknown")
    reason = result.get("reason") or ""
    print(f"status: {status}")
    if result.get("corpus"):
        print(f"corpus: {result['corpus']}")
    if "records" in result:
        print(f"records: {result['records']}")
    if result.get("report_id"):
        print(f"report_id: {result['report_id']}")
    if result.get("summary"):
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2, sort_keys=True))
    if result.get("results") is not None:
        print(json.dumps(result["results"], ensure_ascii=False, indent=2, sort_keys=True))
    if reason:
        print(f"reason: {reason}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--corpus-dir", type=Path, default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_path_options(item: argparse.ArgumentParser) -> None:
        # 兼容 `--repo-root R status` 与 `status --repo-root R` 两种常见 CLI 写法。
        item.add_argument("--repo-root", type=Path, default=argparse.SUPPRESS)
        item.add_argument("--corpus-dir", type=Path, default=argparse.SUPPRESS)

    build = sub.add_parser("build", help="从规范化 JSONL 构建本地案例 corpus")
    add_path_options(build)
    build.add_argument("--input", action="append", type=Path, dest="inputs")
    build.add_argument("--work-dir", type=Path, default=None)
    build.add_argument("--json", action="store_true")

    status = sub.add_parser("status", help="检查 corpus 状态")
    add_path_options(status)
    status.add_argument("--json", action="store_true")

    get = sub.add_parser("get", help="按 report ID 查询案例")
    add_path_options(get)
    get.add_argument("report_id")
    get.add_argument("--full", action="store_true")
    get.add_argument("--json", action="store_true")

    card = sub.add_parser("from-card", help="按 card source_refs 查询案例")
    add_path_options(card)
    card.add_argument("card_id")
    card.add_argument("--report-id")
    card.add_argument("--full", action="store_true")
    card.add_argument("--json", action="store_true")

    search = sub.add_parser("search", help="按 weakness/class 查询摘要")
    add_path_options(search)
    search.add_argument("--class", dest="weakness", required=True)
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    corpus_dir = Path(args.corpus_dir) if args.corpus_dir else repo_root / "distill" / "corpus"
    try:
        if args.command == "build":
            work_dir = Path(args.work_dir) if args.work_dir else repo_root / "distill" / "work"
            result = build_corpus(args.inputs, corpus_dir=corpus_dir, work_dir=work_dir)
            _print_result(result, as_json=args.json)
            return 0
        if args.command == "status":
            result = corpus_status(corpus_dir=corpus_dir)
            _print_result(result, as_json=args.json)
            return 0
        if args.command == "get":
            result = get_case(args.report_id, corpus_dir=corpus_dir, full=args.full)
            _print_result(result, as_json=args.json)
            return 0 if result["status"] in {"ok", "unavailable", "not-found"} else 1
        if args.command == "from-card":
            result = from_card(
                args.card_id,
                repo_root=repo_root,
                corpus_dir=corpus_dir,
                report_id=args.report_id,
                full=args.full,
            )
            _print_result(result, as_json=args.json)
            return 0 if result["status"] in {"ok", "unavailable", "not-found"} else 1
        if args.command == "search":
            result = search_cases(args.weakness, corpus_dir=corpus_dir, limit=args.limit)
            _print_result(result, as_json=args.json)
            return 0 if result["status"] in {"ok", "unavailable"} else 1
    except (CaseCorpusError, ValueError, OSError) as exc:
        print(f"case corpus failed: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
