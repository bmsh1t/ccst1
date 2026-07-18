#!/usr/bin/env python3
"""构建可删除的完整 Surface URL 索引。

索引只对完全相同的原始 URL 做 destructive dedupe，并合并来源。参数值、
顺序、重复 key、编码、scheme/port/path case 等变体始终保留为独立行。
shape 仅用于统计和后续导航，不参与删除或 finding 生命周期。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import heapq
import json
import os
import re
import subprocess
import tempfile
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus, urlparse

try:
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore


SCHEMA_VERSION = 1
INDEX_KIND = "surface_exact_url_index"
MANIFEST_KIND = "surface_exact_url_index_manifest"
SUMMARY_KIND = "surface_exact_url_index_summary"
MAX_PAGE_LIMIT = 1000
CURSOR_SCHEMA_VERSION = 1

URL_ARTIFACT_SPECS = (
    ("api", Path("urls/api_endpoints.txt")),
    ("param", Path("urls/with_params.txt")),
    ("browser_xhr", Path("browser/xhr_endpoints.txt")),
    ("browser_api", Path("browser/api_endpoints.txt")),
)
JS_ENDPOINT_PATH = Path("js/endpoints.txt")
HTTPX_PATH = Path("live/httpx_full.txt")

_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_HEX_SEGMENT_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


class SurfaceIndexError(RuntimeError):
    """Surface 索引无法可靠构建或读取。"""


class SurfaceIndexRaceError(SurfaceIndexError):
    """构建期间输入发生变化，结果未发布。"""


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def surface_index_dir(repo_root: str | Path, target: str) -> Path:
    resolved = canonical_target_value(target)
    return Path(repo_root) / "recon" / target_storage_key(resolved) / "surface"


def surface_index_path(repo_root: str | Path, target: str) -> Path:
    return surface_index_dir(repo_root, target) / "index.jsonl"


def surface_index_manifest_path(repo_root: str | Path, target: str) -> Path:
    return surface_index_dir(repo_root, target) / "manifest.json"


def surface_index_summary_path(repo_root: str | Path, target: str) -> Path:
    return surface_index_dir(repo_root, target) / "summary.json"


def _input_paths(repo_root: Path, target: str) -> list[tuple[str, Path]]:
    key = target_storage_key(target)
    recon_dir = repo_root / "recon" / key
    findings = repo_root / "findings" / key / "findings.json"
    paths = [(label, recon_dir / relative) for label, relative in URL_ARTIFACT_SPECS]
    paths.extend(
        [
            ("js", recon_dir / JS_ENDPOINT_PATH),
            ("httpx", recon_dir / HTTPX_PATH),
            ("scanner", findings),
        ]
    )
    return paths


def build_surface_index_input_manifest(repo_root: str | Path, target: str) -> dict:
    """只用 stat 构建 index 输入绑定，不打开大 URL 文件正文。"""
    repo = Path(repo_root).resolve()
    resolved = canonical_target_value(target)
    items = []
    for label, path in _input_paths(repo, resolved):
        try:
            exists = path.is_file()
            stat = path.stat() if exists else None
        except OSError as exc:
            raise SurfaceIndexError(f"cannot stat surface index input {path}: {exc}") from exc
        try:
            display = path.relative_to(repo).as_posix()
        except ValueError:
            display = str(path)
        items.append(
            {
                "source": label,
                "path": display,
                "exists": exists,
                "size": int(stat.st_size) if stat else 0,
                "mtime_ns": int(stat.st_mtime_ns) if stat else 0,
                "ctime_ns": int(stat.st_ctime_ns) if stat else 0,
                "st_dev": int(stat.st_dev) if stat else 0,
                "st_ino": int(stat.st_ino) if stat else 0,
            }
        )
    encoded = json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "kind": MANIFEST_KIND,
        "schema_version": SCHEMA_VERSION,
        "target": resolved,
        "storage_key": target_storage_key(resolved),
        "fingerprint": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "items": items,
    }


def _iter_lines(path: Path) -> Iterator[str]:
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = " ".join(raw.strip().splitlines())
            if value and not value.startswith("#"):
                yield value


def _default_host(recon_dir: Path) -> str:
    for line in _iter_lines(recon_dir / HTTPX_PATH):
        value = line.split()[0] if line.split() else ""
        if value:
            return value
    return ""


def _iter_js_urls(path: Path, default_host: str) -> Iterator[str]:
    for endpoint in _iter_lines(path):
        if endpoint.startswith(("http://", "https://")):
            yield endpoint
        elif default_host:
            yield default_host.rstrip("/") + endpoint
        else:
            yield endpoint


def _iter_scanner_urls(path: Path) -> Iterator[str]:
    if not path.is_file():
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    rows = payload.get("findings", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return
    for item in rows:
        if not isinstance(item, dict):
            continue
        value = " ".join(str(item.get("url") or "").strip().splitlines())
        if value:
            yield value


def _source_iterators(repo_root: Path, target: str) -> list[tuple[str, Iterable[str]]]:
    key = target_storage_key(target)
    recon_dir = repo_root / "recon" / key
    sources: list[tuple[str, Iterable[str]]] = [
        (label, _iter_lines(recon_dir / relative))
        for label, relative in URL_ARTIFACT_SPECS
    ]
    # 与 legacy rank_surface 的 first-seen 顺序保持一致：scanner 先于 JS。
    sources.append(("scanner", _iter_scanner_urls(repo_root / "findings" / key / "findings.json")))
    sources.append(("js", _iter_js_urls(recon_dir / JS_ENDPOINT_PATH, _default_host(recon_dir))))
    return sources


def _url_key(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")


def _url_from_key(value: str) -> str:
    return base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")


def _sort_annotated(input_path: Path, output_path: Path, *, sort_executable: str) -> None:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            [
                sort_executable,
                "--stable",
                "-t",
                "\t",
                "-k1,1",
                "-k2,2",
                str(input_path),
                "-o",
                str(output_path),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except OSError as exc:
        raise SurfaceIndexError(f"surface index sort failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        raise SurfaceIndexError(
            f"surface index sort failed with exit {result.returncode}: {detail}"
        )


def _iter_annotated(path: Path) -> Iterator[tuple[str, str, str]]:
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line_number, raw in enumerate(handle, 1):
            parts = raw.rstrip("\n").split("\t", 2)
            if len(parts) != 3:
                raise SurfaceIndexError(f"invalid annotated record {path}:{line_number}")
            yield parts[0], parts[1], parts[2]


def _path_template(path: str) -> str:
    segments = []
    for segment in str(path or "/").split("/"):
        if segment.isdigit():
            segments.append("{int}")
        elif _UUID_SEGMENT_RE.fullmatch(segment):
            segments.append("{uuid}")
        elif _HEX_SEGMENT_RE.fullmatch(segment):
            segments.append("{hex}")
        else:
            segments.append(segment)
    return "/".join(segments) or "/"


def surface_shape(value: str) -> dict:
    """返回保守 shape；它只分组，不改变 raw URL identity。"""
    parsed = urlparse(value)
    raw_parts = parsed.query.split("&") if parsed.query else []
    raw_names = [part.split("=", 1)[0] for part in raw_parts]
    decoded_names = [unquote_plus(name) for name in raw_names]
    multiset: dict[str, int] = {}
    for name in decoded_names:
        multiset[name] = multiset.get(name, 0) + 1
    parameter_multiset = sorted(multiset.items(), key=lambda item: item[0])
    shape_payload = {
        "scheme": parsed.scheme.lower(),
        # 不 strip www/default port；shape 也保留这些边界。
        "authority": parsed.netloc.lower(),
        "path_template": _path_template(parsed.path or "/"),
        "parameter_multiset": parameter_multiset,
    }
    encoded = json.dumps(shape_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    flags = []
    if len(decoded_names) != len(set(decoded_names)):
        flags.append("duplicate-query-key")
    if "%" in parsed.query or "+" in parsed.query:
        flags.append("encoded-query")
    try:
        port = parsed.port
    except ValueError:
        port = None
        flags.append("invalid-port")
    if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
        flags.append("non-default-port")
    return {
        "id": hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24],
        **shape_payload,
        "ordered_parameter_names": decoded_names,
        "raw_parameter_names": raw_names,
        "variant_flags": flags,
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


def _file_binding(path: Path) -> dict:
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


def _binding_matches(path: Path, binding: dict) -> bool:
    try:
        stat = path.stat()
        return (
            stat.st_size == int(binding.get("size", -1))
            and stat.st_mtime_ns == int(binding.get("mtime_ns", -1))
            and stat.st_ctime_ns == int(binding.get("ctime_ns", -1))
            and stat.st_dev == int(binding.get("st_dev", -1))
            and stat.st_ino == int(binding.get("st_ino", -1))
        )
    except (OSError, TypeError, ValueError):
        return False


def _shape_stats(sorted_shape_path: Path) -> tuple[int, int]:
    shape_count = 0
    max_variants = 0
    current = ""
    count = 0
    with sorted_shape_path.open("r", encoding="ascii") as handle:
        for raw in handle:
            shape_id = raw.strip()
            if not shape_id:
                continue
            if shape_id != current:
                if current:
                    shape_count += 1
                    max_variants = max(max_variants, count)
                current = shape_id
                count = 1
            else:
                count += 1
    if current:
        shape_count += 1
        max_variants = max(max_variants, count)
    return shape_count, max_variants


def build_surface_index(
    repo_root: str | Path,
    target: str,
    *,
    sort_executable: str = "sort",
) -> dict:
    """以 O(小缓冲) 内存构建 exact URL index，并在输入 race 时拒绝发布。"""
    repo = Path(repo_root).resolve()
    resolved = canonical_target_value(target)
    recon_dir = repo / "recon" / target_storage_key(resolved)
    if not recon_dir.is_dir():
        raise SurfaceIndexError(f"recon directory missing for {resolved}: {recon_dir}")
    initial_manifest = build_surface_index_input_manifest(repo, resolved)
    output_dir = surface_index_dir(repo, resolved)
    output_dir.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".surface-build.", dir=str(output_dir.parent)) as temp_name:
        temp_dir = Path(temp_name)
        sorted_paths = []
        source_counts: dict[str, int] = {}
        sequence = 0
        for source_index, (source, values) in enumerate(_source_iterators(repo, resolved)):
            annotated = temp_dir / f"source-{source_index:02d}.tsv"
            count = 0
            with annotated.open("w", encoding="utf-8") as handle:
                for value in values:
                    if not value:
                        continue
                    handle.write(f"{_url_key(value)}\t{sequence:020d}\t{source}\n")
                    sequence += 1
                    count += 1
            source_counts[source] = count
            if not count:
                annotated.unlink()
                continue
            sorted_path = temp_dir / f"source-{source_index:02d}.sorted.tsv"
            _sort_annotated(annotated, sorted_path, sort_executable=sort_executable)
            sorted_paths.append(sorted_path)

        staged_index = temp_dir / "index.jsonl"
        shape_spool = temp_dir / "shapes.txt"
        unique_count = 0
        target_owned_count = 0
        encoded_count = 0
        duplicate_key_count = 0
        non_default_port_count = 0
        current_key = ""
        current_sequence = 0
        current_sources: list[str] = []

        def emit(handle, shape_handle) -> None:
            nonlocal unique_count, target_owned_count, encoded_count
            nonlocal duplicate_key_count, non_default_port_count
            if not current_key:
                return
            raw_url = _url_from_key(current_key)
            shape = surface_shape(raw_url)
            flags = shape["variant_flags"]
            row = {
                "schema_version": SCHEMA_VERSION,
                "url": raw_url,
                "sequence": current_sequence,
                "sources": current_sources,
                "target_owned": url_belongs_to_target(raw_url, resolved),
                "shape_id": shape["id"],
                "shape": {
                    key: value
                    for key, value in shape.items()
                    if key not in {"id", "variant_flags"}
                },
                "variant_flags": flags,
            }
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            shape_handle.write(shape["id"] + "\n")
            unique_count += 1
            target_owned_count += int(row["target_owned"])
            encoded_count += int("encoded-query" in flags)
            duplicate_key_count += int("duplicate-query-key" in flags)
            non_default_port_count += int("non-default-port" in flags)

        iterators = [_iter_annotated(path) for path in sorted_paths]
        with staged_index.open("w", encoding="utf-8") as index_handle, shape_spool.open(
            "w", encoding="ascii"
        ) as shape_handle:
            for encoded_url, sequence_text, source in heapq.merge(
                *iterators,
                key=lambda item: (item[0], item[1], item[2]),
            ):
                if encoded_url != current_key:
                    emit(index_handle, shape_handle)
                    current_key = encoded_url
                    current_sequence = int(sequence_text)
                    current_sources = [source]
                elif source not in current_sources:
                    current_sources.append(source)
            emit(index_handle, shape_handle)
            index_handle.flush()
            os.fsync(index_handle.fileno())
            shape_handle.flush()
            os.fsync(shape_handle.fileno())

        sorted_shapes = temp_dir / "shapes.sorted.txt"
        if unique_count:
            _sort_annotated_lines(shape_spool, sorted_shapes, sort_executable=sort_executable)
            shape_count, max_shape_variants = _shape_stats(sorted_shapes)
        else:
            shape_count, max_shape_variants = 0, 0

        current_manifest = build_surface_index_input_manifest(repo, resolved)
        if current_manifest["fingerprint"] != initial_manifest["fingerprint"]:
            raise SurfaceIndexRaceError("surface index inputs changed during build")

        output_dir.mkdir(parents=True, exist_ok=True)
        index_path = surface_index_path(repo, resolved)
        staged_index.replace(index_path)
        binding = _file_binding(index_path)
        summary = {
            "kind": SUMMARY_KIND,
            "schema_version": SCHEMA_VERSION,
            "target": resolved,
            "generated_at": _now_utc(),
            "source_rows": sequence,
            "unique_urls": unique_count,
            "exact_duplicates": max(0, sequence - unique_count),
            "target_owned_urls": target_owned_count,
            "off_target_urls": max(0, unique_count - target_owned_count),
            "shape_count": shape_count,
            "max_shape_variants": max_shape_variants,
            "duplicate_key_urls": duplicate_key_count,
            "encoded_query_urls": encoded_count,
            "non_default_port_urls": non_default_port_count,
            "source_counts": source_counts,
        }
        _write_json_atomic(surface_index_summary_path(repo, resolved), summary)
        manifest = {
            "kind": MANIFEST_KIND,
            "schema_version": SCHEMA_VERSION,
            "target": resolved,
            "storage_key": target_storage_key(resolved),
            "generated_at": _now_utc(),
            "input_fingerprint": initial_manifest["fingerprint"],
            "input_manifest": initial_manifest,
            "index_binding": binding,
            "row_count": unique_count,
        }
        # Manifest 最后发布；中途失败时 reader 会因旧 binding 不匹配而拒绝消费。
        _write_json_atomic(surface_index_manifest_path(repo, resolved), manifest)
        return {"status": "valid", "manifest": manifest, "summary": summary}


def _sort_annotated_lines(input_path: Path, output_path: Path, *, sort_executable: str) -> None:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            [sort_executable, "--stable", str(input_path), "-o", str(output_path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except OSError as exc:
        raise SurfaceIndexError(f"surface shape sort failed: {exc}") from exc
    if result.returncode != 0:
        raise SurfaceIndexError(
            f"surface shape sort failed with exit {result.returncode}: {(result.stderr or '').strip()}"
        )


def load_surface_index_status(repo_root: str | Path, target: str) -> dict:
    """仅校验 manifest/stat；不打开完整 index 正文。"""
    repo = Path(repo_root).resolve()
    resolved = canonical_target_value(target)
    manifest_path = surface_index_manifest_path(repo, resolved)
    index_path = surface_index_path(repo, resolved)
    if not manifest_path.is_file():
        return {"status": "missing", "reason": "manifest-missing", "path": str(index_path)}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "invalid", "reason": f"invalid-manifest: {exc}", "path": str(index_path)}
    if not isinstance(manifest, dict) or manifest.get("kind") != MANIFEST_KIND:
        return {"status": "invalid", "reason": "manifest-kind-mismatch", "path": str(index_path)}
    if manifest.get("schema_version") != SCHEMA_VERSION:
        return {"status": "invalid", "reason": "manifest-schema-mismatch", "path": str(index_path)}
    if manifest.get("target") != resolved or manifest.get("storage_key") != target_storage_key(resolved):
        return {"status": "invalid", "reason": "manifest-target-mismatch", "path": str(index_path)}
    binding = manifest.get("index_binding") if isinstance(manifest.get("index_binding"), dict) else {}
    if not _binding_matches(index_path, binding):
        return {"status": "stale", "reason": "index-binding-mismatch", "path": str(index_path)}
    try:
        current = build_surface_index_input_manifest(repo, resolved)
    except SurfaceIndexError as exc:
        return {"status": "invalid", "reason": str(exc), "path": str(index_path)}
    if current["fingerprint"] != str(manifest.get("input_fingerprint") or ""):
        return {"status": "stale", "reason": "input-manifest-mismatch", "path": str(index_path)}
    summary = {}
    summary_path = surface_index_summary_path(repo, resolved)
    try:
        loaded_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if isinstance(loaded_summary, dict) and loaded_summary.get("kind") == SUMMARY_KIND:
            summary = loaded_summary
    except (OSError, json.JSONDecodeError):
        summary = {}
    return {
        "status": "valid",
        "reason": "",
        "path": str(index_path),
        "row_count": int(manifest.get("row_count", 0) or 0),
        "manifest": manifest,
        "summary": summary,
    }


def iter_surface_index(repo_root: str | Path, target: str) -> Iterator[dict]:
    """顺序读取有效 index；坏行 fail-fast，不能静默缩小攻击面。"""
    status = load_surface_index_status(repo_root, target)
    if status.get("status") != "valid":
        raise SurfaceIndexError(
            f"surface index unavailable: {status.get('status')} {status.get('reason')}"
        )
    path = Path(str(status["path"]))
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SurfaceIndexError(f"invalid surface index row {path}:{line_number}: {exc}") from exc
            if not isinstance(item, dict) or not str(item.get("url") or ""):
                raise SurfaceIndexError(f"invalid surface index row {path}:{line_number}")
            yield item


def _page_filters(*, shape_id: str, source: str, target_owned: bool | None) -> dict:
    return {
        "shape_id": str(shape_id or "").strip(),
        "source": str(source or "").strip(),
        "target_owned": target_owned,
    }


def _encode_page_cursor(
    *,
    target: str,
    revision: str,
    offset: int,
    filters: dict,
) -> str:
    payload = {
        "v": CURSOR_SCHEMA_VERSION,
        "target": canonical_target_value(target),
        "revision": revision,
        "offset": offset,
        "filters": filters,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_page_cursor(cursor: str) -> dict:
    value = str(cursor or "").strip()
    if not value:
        return {}
    try:
        padding = "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(value + padding))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid surface index cursor") from exc
    if not isinstance(payload, dict) or payload.get("v") != CURSOR_SCHEMA_VERSION:
        raise ValueError("invalid surface index cursor schema")
    if not isinstance(payload.get("filters"), dict):
        raise ValueError("invalid surface index cursor filters")
    try:
        offset = int(payload.get("offset", -1))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid surface index cursor offset") from exc
    if offset < 0:
        raise ValueError("invalid surface index cursor offset")
    payload["offset"] = offset
    return payload


def page_surface_index(
    repo_root: str | Path,
    target: str,
    *,
    limit: int = 50,
    cursor: str = "",
    shape_id: str = "",
    source: str = "",
    target_owned: bool | None = None,
) -> dict:
    """按稳定 byte cursor 分页访问全部 raw variant，不修改 index。"""
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_PAGE_LIMIT}")
    status = load_surface_index_status(repo_root, target)
    if status.get("status") != "valid":
        raise SurfaceIndexError(
            f"surface index unavailable: {status.get('status')} {status.get('reason')}"
        )
    manifest = status.get("manifest") or {}
    binding = manifest.get("index_binding") or {}
    revision = str(binding.get("sha256") or "")
    filters = _page_filters(
        shape_id=shape_id,
        source=source,
        target_owned=target_owned,
    )
    decoded = _decode_page_cursor(cursor)
    offset = 0
    if decoded:
        if decoded.get("target") != canonical_target_value(target):
            raise ValueError("surface index cursor target mismatch")
        if decoded.get("revision") != revision:
            raise SurfaceIndexError("stale surface index cursor: index revision changed")
        if decoded.get("filters") != filters:
            raise ValueError("surface index cursor filter mismatch")
        offset = int(decoded["offset"])

    path = Path(str(status["path"]))
    items = []
    scanned = 0
    next_offset = offset
    with path.open("rb") as handle:
        handle.seek(offset)
        while len(items) < limit:
            row_start = handle.tell()
            raw = handle.readline()
            if not raw:
                break
            scanned += 1
            next_offset = handle.tell()
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SurfaceIndexError(f"invalid surface index row near byte {next_offset}: {exc}") from exc
            if filters["shape_id"] and str(item.get("shape_id") or "") != filters["shape_id"]:
                continue
            if filters["source"] and filters["source"] not in {
                str(value) for value in (item.get("sources") or [])
            }:
                continue
            if filters["target_owned"] is not None and bool(item.get("target_owned")) != filters["target_owned"]:
                continue
            items.append(item)

        # byte EOF 不能代表还有符合过滤条件的行。仅向前探测到第一条匹配项，
        # cursor 直接指向该行，避免最后一页返回一个空的 follow-up page。
        has_more = False
        while True:
            row_start = handle.tell()
            raw = handle.readline()
            if not raw:
                break
            scanned += 1
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SurfaceIndexError(
                    f"invalid surface index row near byte {handle.tell()}: {exc}"
                ) from exc
            if filters["shape_id"] and str(item.get("shape_id") or "") != filters["shape_id"]:
                continue
            if filters["source"] and filters["source"] not in {
                str(value) for value in (item.get("sources") or [])
            }:
                continue
            if filters["target_owned"] is not None and bool(item.get("target_owned")) != filters["target_owned"]:
                continue
            next_offset = row_start
            has_more = True
            break

    return {
        "index_revision": revision,
        "items": items,
        "next_cursor": (
            _encode_page_cursor(
                target=target,
                revision=revision,
                offset=next_offset,
                filters=filters,
            )
            if has_more
            else ""
        ),
        "scanned": scanned,
        "row_count": int(status.get("row_count", 0) or 0),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and page the exact Surface URL index")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--target", required=True)

    status = sub.add_parser("status")
    status.add_argument("--target", required=True)

    page = sub.add_parser("page")
    page.add_argument("--target", required=True)
    page.add_argument("--limit", type=int, default=50)
    page.add_argument("--cursor", default="")
    page.add_argument("--shape-id", default="")
    page.add_argument("--source", default="")
    ownership = page.add_mutually_exclusive_group()
    ownership.add_argument("--target-owned", action="store_true")
    ownership.add_argument("--off-target", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            result = build_surface_index(args.repo_root, args.target)
            output = {"status": result["status"], "summary": result["summary"]}
        elif args.command == "status":
            status = load_surface_index_status(args.repo_root, args.target)
            output = {
                key: status.get(key)
                for key in ("status", "reason", "path", "row_count", "summary")
                if key in status
            }
        else:
            ownership = True if args.target_owned else (False if args.off_target else None)
            output = page_surface_index(
                args.repo_root,
                args.target,
                limit=args.limit,
                cursor=args.cursor,
                shape_id=args.shape_id,
                source=args.source,
                target_owned=ownership,
            )
    except (OSError, SurfaceIndexError, ValueError) as exc:
        print(f"surface_index: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
