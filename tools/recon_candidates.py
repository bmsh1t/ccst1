#!/usr/bin/env python3
"""从现有 Recon artifact 生成有界 JS、Host、AI 与资产关系中性候选。"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import re
import sqlite3
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
DEFAULT_JS_CANDIDATE_LIMIT = 800
ASSET_RELATION_INPUT_PATH = Path("exposure/asset_relation_observations.jsonl")
ASSET_RELATION_OUTPUT_PATH = Path("exposure/asset_relation_candidates.jsonl")
ASSET_RELATION_WARNING_LIMIT = 10
MAX_ASSET_RELATION_LINE_BYTES = 1_000_000
MAX_ASSET_RELATION_LIST_ITEMS = 256
DEFAULT_ASSET_RELATION_CANDIDATE_LIMIT = 5000
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
IP_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
KEY_VALUE_RE = re.compile(r"\b(ip|cname|subject_cn|subject_an|san)=([^\]\s,;]+)", re.IGNORECASE)
AI_SIGNAL_RE = re.compile(
    r"(?:^|[/_.?&=\s-])"
    r"(chat(?:bot)?|rag|llm|openai|anthropic|ollama|vllm|embeddings?|inference|"
    r"assistant|agent|mcp|prompt|vector|knowledge|model(?:s)?)(?:$|[/_.?&=\s-])",
    re.IGNORECASE,
)

AI_SOURCES = (
    Path("live/httpx_full.txt"),
    Path("urls/api_endpoints.txt"),
    Path("urls/js_files.txt"),
    Path("exposure/api_doc_candidates.txt"),
    Path("js/endpoints.txt"),
    Path("browser/xhr_endpoints.txt"),
    Path("browser/api_endpoints.txt"),
)

JS_CATEGORY_PATTERNS = (
    (
        "auth",
        re.compile(r"(?:^|[/_.?&=-])(auth|oauth|sso|login|session|jwt)(?:$|[/_.?&=-])", re.I),
    ),
    (
        "api",
        re.compile(r"(?:^|[/_.?&=-])(api|graphql|rest|rpc|websocket|ws)(?:$|[/_.?&=-])", re.I),
    ),
    (
        "payment",
        re.compile(r"(?:^|[/_.?&=-])(payment|billing|checkout|invoice|refund|payout)(?:$|[/_.?&=-])", re.I),
    ),
    (
        "file",
        re.compile(r"(?:^|[/_.?&=-])(upload|import|export|download|attachment|file)(?:$|[/_.?&=-])", re.I),
    ),
    ("source-map", re.compile(r"(?:\.map(?:[?#]|$)|source.?map)", re.I)),
    (
        "dynamic",
        re.compile(r"(?:^|[/_.?&=-])(signature|signed|encrypt|crypto|hmac|nonce|token)(?:$|[/_.?&=-])", re.I),
    ),
    (
        "framework",
        re.compile(r"(?:^|[/_.?&=-])(webpack|runtime|chunk|bundle|main|app)(?:$|[/_.?&=-])", re.I),
    ),
    ("general", None),
)


def _iter_lines(path: Path):
    if not path.is_file():
        return
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = " ".join(raw.strip().splitlines())
            if value:
                yield value


def _write_jsonl_atomic(path: Path, rows: list[dict]) -> None:
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
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def _write_lines_atomic(path: Path, values: list[str]) -> None:
    """原子发布有界候选视图；失败时保留上一版文件。"""
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
            if values:
                handle.write("\n".join(values) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def _stable_rank(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big")


def build_js_deep_candidates(
    input_path: str | Path,
    output_path: str | Path,
    *,
    limit: int = DEFAULT_JS_CANDIDATE_LIMIT,
) -> dict:
    """按多类固定配额生成有界 JS 深析候选，完整 inventory 保持不变。"""
    if limit < len(JS_CATEGORY_PATTERNS):
        raise ValueError(f"JS candidate limit must be >= {len(JS_CATEGORY_PATTERNS)}")

    source = Path(input_path)
    destination = Path(output_path)
    per_category = max(1, limit // len(JS_CATEGORY_PATTERNS))
    buckets: dict[str, list[tuple[int, str]]] = {
        category: [] for category, _pattern in JS_CATEGORY_PATTERNS
    }
    input_count = 0

    for value in _iter_lines(source):
        input_count += 1
        matched = [
            category
            for category, pattern in JS_CATEGORY_PATTERNS[:-1]
            if pattern is not None and pattern.search(value)
        ] or ["general"]
        rank = _stable_rank(value)
        for category in matched:
            heap = buckets[category]
            entry = (-rank, value)
            if len(heap) < per_category:
                heapq.heappush(heap, entry)
            elif rank < -heap[0][0]:
                heapq.heapreplace(heap, entry)

    category_order = {
        name: index for index, (name, _pattern) in enumerate(JS_CATEGORY_PATTERNS)
    }
    selected: dict[str, set[str]] = {}
    for category, heap in buckets.items():
        for _negative_rank, value in heap:
            selected.setdefault(value, set()).add(category)

    ordered = sorted(
        selected,
        key=lambda value: (
            min(category_order[category] for category in selected[value]),
            _stable_rank(value),
            value,
        ),
    )[:limit]
    _write_lines_atomic(destination, ordered)
    return {
        "input": str(source),
        "output": str(destination),
        "input_count": input_count,
        "candidate_count": len(ordered),
        "limit": limit,
        "truncated": input_count > len(ordered),
        "category_counts": {
            category: sum(category in selected[value] for value in ordered)
            for category, _pattern in JS_CATEGORY_PATTERNS
        },
    }


def _host_from_line(line: str) -> str:
    first = line.split()[0] if line.split() else ""
    try:
        return (urlsplit(first).hostname or "").lower()
    except ValueError:
        return ""


def _valid_ip(value: str) -> str:
    try:
        return str(ip_address(value.strip("[]")))
    except ValueError:
        return ""


def _asset_text(value: object, field: str, *, max_length: int) -> str:
    """校验外部 observation 的短文本字段，避免把大段原始响应带入候选。"""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = " ".join(value.strip().splitlines())
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    if len(normalized) > max_length:
        raise ValueError(f"{field} exceeds {max_length} characters")
    return normalized


def _asset_text_list(value: object, field: str, *, max_length: int) -> list[str]:
    if value is None:
        return []
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list):
        raise ValueError(f"{field} must be a string or list of strings")
    normalized = sorted({_asset_text(item, field, max_length=max_length) for item in items})
    if len(normalized) > MAX_ASSET_RELATION_LIST_ITEMS:
        raise ValueError(f"{field} exceeds {MAX_ASSET_RELATION_LIST_ITEMS} items")
    return normalized


def _asset_observed_at(value: object) -> str:
    if value in (None, ""):
        return ""
    text = _asset_text(value, "observed_at", max_length=64)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_asset_relation_observation(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("record must be a JSON object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    if payload.get("kind") != "asset-relation-observation":
        raise ValueError("kind must be asset-relation-observation")

    confidence = str(payload.get("confidence") or "low").strip().lower()
    if confidence not in CONFIDENCE_RANK:
        raise ValueError("confidence must be low, medium, or high")
    source_ref = ""
    if payload.get("source_ref") not in (None, ""):
        source_ref = _asset_text(payload.get("source_ref"), "source_ref", max_length=4096)

    return {
        "asset_type": _asset_text(payload.get("asset_type"), "asset_type", max_length=128).lower(),
        "value": _asset_text(payload.get("value"), "value", max_length=4096),
        "relation": _asset_text(payload.get("relation"), "relation", max_length=128).lower(),
        "related": _asset_text_list(payload.get("related"), "related", max_length=4096),
        "signals": _asset_text_list(payload.get("signals"), "signals", max_length=128),
        "source": _asset_text(payload.get("source"), "source", max_length=128).lower(),
        "source_ref": source_ref,
        "confidence": confidence,
        "observed_at": _asset_observed_at(payload.get("observed_at")),
    }


def _asset_relation_candidates(
    source: Path,
    *,
    limit: int = DEFAULT_ASSET_RELATION_CANDIDATE_LIMIT,
) -> tuple[list[dict], dict]:
    """流式合并 observation；完整原始输入保留，候选只发布固定上限。"""
    if limit < 1:
        raise ValueError("asset relation candidate limit must be positive")
    stats = {"input_count": 0, "invalid_count": 0, "warnings": [], "unique_count": 0}
    if not source.is_file():
        return [], stats

    def _candidate_key(observation: dict) -> str:
        return "\x1f".join(
            (observation["asset_type"], observation["value"], observation["relation"])
        )

    def _merge(existing: dict | None, observation: dict) -> dict:
        row = existing or {
            "schema_version": SCHEMA_VERSION,
            "kind": "asset-relation-candidate",
            "asset_type": observation["asset_type"],
            "value": observation["value"],
            "relation": observation["relation"],
            "related": [],
            "signals": [],
            "sources": [],
            "source_refs": [],
            "confidence": "low",
        }
        row["related"] = sorted(set(row["related"]) | set(observation["related"]))[
            :MAX_ASSET_RELATION_LIST_ITEMS
        ]
        row["signals"] = sorted(set(row["signals"]) | set(observation["signals"]))[
            :MAX_ASSET_RELATION_LIST_ITEMS
        ]
        row["sources"] = sorted(set(row["sources"]) | {observation["source"]})[
            :MAX_ASSET_RELATION_LIST_ITEMS
        ]
        if observation["source_ref"]:
            row["source_refs"] = sorted(
                set(row["source_refs"]) | {observation["source_ref"]}
            )[:MAX_ASSET_RELATION_LIST_ITEMS]
        if CONFIDENCE_RANK[observation["confidence"]] > CONFIDENCE_RANK[row["confidence"]]:
            row["confidence"] = observation["confidence"]
        if observation["observed_at"] > str(row.get("observed_at") or ""):
            row["observed_at"] = observation["observed_at"]
        return row

    def _score(row: dict) -> int:
        # 高置信度优先，其次多来源/多信号；同分由稳定 key 决定。
        return (
            CONFIDENCE_RANK[row["confidence"]] * 1_000_000
            + len(row["sources"]) * 10_000
            + len(row["source_refs"]) * 1_000
            + len(row["signals"]) * 100
            + len(row["related"])
        )

    with tempfile.TemporaryDirectory(prefix="asset-relations-") as temp_dir:
        database = Path(temp_dir) / "aggregate.sqlite3"
        with sqlite3.connect(database) as connection:
            connection.execute(
                "CREATE TABLE candidates (key TEXT PRIMARY KEY, payload TEXT NOT NULL, score INTEGER NOT NULL)"
            )
            connection.execute("BEGIN")
            with source.open("rb") as handle:
                line_number = 0
                while True:
                    raw = handle.readline(MAX_ASSET_RELATION_LINE_BYTES + 1)
                    if not raw:
                        break
                    line_number += 1
                    oversized = len(raw) > MAX_ASSET_RELATION_LINE_BYTES
                    if oversized and not raw.endswith(b"\n"):
                        while True:
                            chunk = handle.readline(MAX_ASSET_RELATION_LINE_BYTES + 1)
                            if not chunk or chunk.endswith(b"\n"):
                                break
                    text = "" if oversized else raw.decode("utf-8", errors="replace").strip()
                    if not text and not oversized:
                        continue
                    stats["input_count"] += 1
                    try:
                        if oversized:
                            raise ValueError("record exceeds 1000000 bytes")
                        observation = _normalize_asset_relation_observation(json.loads(text))
                    except (json.JSONDecodeError, ValueError) as exc:
                        stats["invalid_count"] += 1
                        if len(stats["warnings"]) < ASSET_RELATION_WARNING_LIMIT:
                            stats["warnings"].append(f"line {line_number}: {exc}")
                        continue

                    key = _candidate_key(observation)
                    existing_row = connection.execute(
                        "SELECT payload FROM candidates WHERE key = ?", (key,)
                    ).fetchone()
                    row = _merge(
                        json.loads(existing_row[0]) if existing_row else None,
                        observation,
                    )
                    connection.execute(
                        "INSERT OR REPLACE INTO candidates(key, payload, score) VALUES (?, ?, ?)",
                        (key, json.dumps(row, ensure_ascii=False, sort_keys=True), _score(row)),
                    )
            connection.commit()
            stats["unique_count"] = int(
                connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
            )
            rows = [
                json.loads(payload)
                for (payload,) in connection.execute(
                    "SELECT payload FROM candidates ORDER BY score DESC, key ASC LIMIT ?",
                    (limit,),
                )
            ]
    stats["truncated"] = stats["unique_count"] > len(rows)
    return rows, stats


def _host_candidates(recon_dir: Path) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    ip_hosts: dict[str, set[str]] = defaultdict(set)

    for relative in (Path("live/origin_candidates.txt"), Path("live/unwaf_bypass_ips.txt")):
        for value in _iter_lines(recon_dir / relative):
            key = (relative.as_posix(), value)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": "host-pivot-candidate",
                    "value": value,
                    "signals": ["origin-candidate"],
                    "sources": [relative.as_posix()],
                }
            )

    httpx_path = recon_dir / "live/httpx_full.txt"
    for line in _iter_lines(httpx_path):
        host = _host_from_line(line)
        if not host:
            continue
        values = [(key.lower(), value) for key, value in KEY_VALUE_RE.findall(line)]
        for key, value in values:
            if key == "ip":
                normalized_ip = _valid_ip(value)
                if normalized_ip:
                    ip_hosts[normalized_ip].add(host)
            elif key in {"cname", "subject_cn", "subject_an", "san"}:
                rows.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "kind": "host-pivot-candidate",
                        "value": host,
                        "signals": [key.replace("_", "-")],
                        "related": [value],
                        "sources": ["live/httpx_full.txt"],
                    }
                )
        if not any(key == "ip" for key, _value in values):
            for ip in IP_RE.findall(line):
                normalized_ip = _valid_ip(ip)
                if normalized_ip:
                    ip_hosts[normalized_ip].add(host)

    for ip, hosts in sorted(ip_hosts.items()):
        if len(hosts) < 2:
            continue
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "host-pivot-candidate",
                "value": ip,
                "signals": ["shared-ip"],
                "related": sorted(hosts),
                "sources": ["live/httpx_full.txt"],
            }
        )

    unique = {json.dumps(row, sort_keys=True): row for row in rows}
    return list(unique.values())


def _ai_candidates(recon_dir: Path) -> list[dict]:
    merged: dict[str, dict] = {}
    for relative in AI_SOURCES:
        for value in _iter_lines(recon_dir / relative):
            matches = sorted({match.lower() for match in AI_SIGNAL_RE.findall(value)})
            if not matches:
                continue
            row = merged.setdefault(
                value,
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": "ai-asset-candidate",
                    "value": value,
                    "signals": [],
                    "sources": [],
                },
            )
            row["signals"] = sorted(set(row["signals"]) | set(matches))
            if relative.as_posix() not in row["sources"]:
                row["sources"].append(relative.as_posix())
    return list(merged.values())


def build_recon_candidates(
    repo_root: str | Path,
    target: str,
    *,
    asset_input: str | Path | None = None,
    asset_limit: int = DEFAULT_ASSET_RELATION_CANDIDATE_LIMIT,
) -> dict:
    resolved = canonical_target_value(target)
    recon_dir = Path(repo_root) / "recon" / target_storage_key(resolved)
    if not recon_dir.is_dir():
        raise FileNotFoundError(f"recon directory missing: {recon_dir}")

    exposure_dir = recon_dir / "exposure"
    host_rows = _host_candidates(recon_dir)
    ai_rows = _ai_candidates(recon_dir)
    asset_input_path = Path(asset_input) if asset_input else recon_dir / ASSET_RELATION_INPUT_PATH
    asset_rows, asset_stats = _asset_relation_candidates(asset_input_path, limit=asset_limit)
    host_path = exposure_dir / "host_pivot_candidates.jsonl"
    ai_path = exposure_dir / "ai_asset_candidates.jsonl"
    asset_path = recon_dir / ASSET_RELATION_OUTPUT_PATH
    _write_jsonl_atomic(host_path, host_rows)
    _write_jsonl_atomic(ai_path, ai_rows)
    _write_jsonl_atomic(asset_path, asset_rows)
    return {
        "target": resolved,
        "host_pivot_candidates": len(host_rows),
        "ai_asset_candidates": len(ai_rows),
        "asset_relation_candidates": len(asset_rows),
        "asset_relation_observations": asset_stats["input_count"],
        "asset_relation_invalid": asset_stats["invalid_count"],
        "asset_relation_unique": asset_stats["unique_count"],
        "asset_relation_truncated": asset_stats.get("truncated", False),
        "asset_relation_warnings": asset_stats["warnings"],
        "host_path": str(host_path),
        "ai_path": str(ai_path),
        "asset_input_path": str(asset_input_path),
        "asset_path": str(asset_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build bounded JS/Host/AI and generic asset-relation recon candidates"
    )
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--target")
    mode.add_argument("--js-input")
    parser.add_argument(
        "--asset-input",
        help="Optional normalized asset-relation observation JSONL for --target mode",
    )
    parser.add_argument(
        "--asset-limit",
        type=int,
        default=DEFAULT_ASSET_RELATION_CANDIDATE_LIMIT,
        help="Maximum derived asset-relation candidates to publish",
    )
    parser.add_argument("--js-output")
    parser.add_argument("--js-limit", type=int, default=DEFAULT_JS_CANDIDATE_LIMIT)
    args = parser.parse_args(argv)
    try:
        if args.js_input:
            if args.asset_input:
                raise ValueError("--asset-input is only supported with --target")
            if not args.js_output:
                raise ValueError("--js-output is required with --js-input")
            payload = build_js_deep_candidates(
                args.js_input,
                args.js_output,
                limit=args.js_limit,
            )
        else:
            payload = build_recon_candidates(
                args.repo_root,
                str(args.target),
                asset_input=args.asset_input,
                asset_limit=args.asset_limit,
            )
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"recon_candidates: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
