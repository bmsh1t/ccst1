#!/usr/bin/env python3
"""从现有 Recon artifact 生成有界 JS、Host 与 AI 中性路由候选。"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
DEFAULT_JS_CANDIDATE_LIMIT = 800
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


def build_recon_candidates(repo_root: str | Path, target: str) -> dict:
    resolved = canonical_target_value(target)
    recon_dir = Path(repo_root) / "recon" / target_storage_key(resolved)
    if not recon_dir.is_dir():
        raise FileNotFoundError(f"recon directory missing: {recon_dir}")

    host_rows = _host_candidates(recon_dir)
    ai_rows = _ai_candidates(recon_dir)
    exposure_dir = recon_dir / "exposure"
    host_path = exposure_dir / "host_pivot_candidates.jsonl"
    ai_path = exposure_dir / "ai_asset_candidates.jsonl"
    _write_jsonl_atomic(host_path, host_rows)
    _write_jsonl_atomic(ai_path, ai_rows)
    return {
        "target": resolved,
        "host_pivot_candidates": len(host_rows),
        "ai_asset_candidates": len(ai_rows),
        "host_path": str(host_path),
        "ai_path": str(ai_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build bounded JS/Host/AI recon routing candidates")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--target")
    mode.add_argument("--js-input")
    parser.add_argument("--js-output")
    parser.add_argument("--js-limit", type=int, default=DEFAULT_JS_CANDIDATE_LIMIT)
    args = parser.parse_args(argv)
    try:
        if args.js_input:
            if not args.js_output:
                raise ValueError("--js-output is required with --js-input")
            payload = build_js_deep_candidates(
                args.js_input,
                args.js_output,
                limit=args.js_limit,
            )
        else:
            payload = build_recon_candidates(args.repo_root, str(args.target))
    except (OSError, ValueError) as exc:
        print(f"recon_candidates: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
