#!/usr/bin/env python3
"""从现有 Recon artifact 生成有界 JS、Host、AI 与资产关系中性候选。"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import os
import re
import sqlite3
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.target_profile import default_memory_dir, load_target_profile  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402
from tools.scope_context import ScopeContext, ScopeContextError  # noqa: E402
from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # noqa: E402
from tools.technology_inventory import inventory_source_binding_matches  # noqa: E402


SCHEMA_VERSION = 1
DEFAULT_JS_CANDIDATE_LIMIT = 800
ASSET_RELATION_INPUT_PATH = Path("exposure/asset_relation_observations.jsonl")
ASSET_RELATION_OUTPUT_PATH = Path("exposure/asset_relation_candidates.jsonl")
ASSET_RELATION_SUMMARY_PATH = Path("exposure/asset_relation_summary.json")
HOST_RANKING_OUTPUT_PATH = Path("exposure/host_ranking.jsonl")
ASSET_RELATION_WARNING_LIMIT = 10
MAX_ASSET_RELATION_LINE_BYTES = 1_000_000
MAX_ASSET_RELATION_LIST_ITEMS = 256
DEFAULT_ASSET_RELATION_CANDIDATE_LIMIT = 5000
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
HOST_LIKE_ASSET_TYPES = {"domain", "hostname", "url", "ip", "cidr"}
STRONG_RELATION_TOKENS = (
    "certificate",
    "control",
    "majority",
    "owned",
    "owner",
    "ownership",
    "parent",
    "registrant",
    "subsidiary",
)
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

HOST_RANKING_FIXED_SOURCES = (
    ("live_httpx", Path("live/httpx_full.txt"), "live/httpx_full.txt", "live"),
    ("api_endpoints", Path("urls/api_endpoints.txt"), "urls/api_endpoints.txt", "api-endpoint"),
    ("with_params", Path("urls/with_params.txt"), "urls/with_params.txt", "parameterized-url"),
    ("js_files", Path("urls/js_files.txt"), "urls/js_files.txt", "js-file"),
)
# These artifacts are host-bearing inputs too, but are kept separate from the
# weighted lanes above so their provenance remains visible without changing the
# existing score calibration.
HOST_RANKING_ADDITIONAL_SOURCES = (
    (Path("subdomains/subfinder.txt"), "subdomain"),
    (Path("subdomains/resolved.txt"), "resolved-subdomain"),
    (Path("subdomains/all.txt"), "subdomain"),
    (Path("urls/all.txt"), "url"),
    (Path("urls/graphql.txt"), "graphql"),
    (Path("live/urls.txt"), "live-url"),
    (Path("js/endpoints.txt"), "endpoint"),
    (Path("browser/xhr_endpoints.txt"), "browser-xhr"),
    (Path("browser/api_endpoints.txt"), "browser-api"),
)
HOST_RANKING_ADDITIONAL_SOURCE_NAMES = frozenset(
    relative.as_posix() for relative, _signal in HOST_RANKING_ADDITIONAL_SOURCES
)
HOST_RANKING_CANDIDATE_SOURCES = (
    ("host_pivot_candidates", Path("exposure/host_pivot_candidates.jsonl"), "host-pivot"),
    ("ai_asset_candidates", Path("exposure/ai_asset_candidates.jsonl"), "ai-asset"),
    ("asset_relation_candidates", Path("exposure/asset_relation_candidates.jsonl"), "asset-relation"),
)
HOST_RANKING_TECHNOLOGY_PATH = Path("live/technology_inventory.json")
HOST_RANKING_WEIGHTS = {
    "live_httpx": 3,
    "discovery_artifacts": 1,
    "open_host_ports": 2,
    "api_endpoints": 5,
    "with_params": 4,
    "js_files": 2,
    "host_pivot_candidates": 5,
    "ai_asset_candidates": 5,
    "asset_relation_candidates": 3,
    "asset_relation_observations": 1,
    "technology_signals": 2,
}
HOST_RANKING_SIGNAL_ORDER = (
    ("live_httpx", "live"),
    ("discovery_artifacts", "discovery"),
    ("open_host_ports", "open-port"),
    ("api_endpoints", "api-endpoint"),
    ("with_params", "parameterized-url"),
    ("js_files", "js-file"),
    ("host_pivot_candidates", "host-pivot"),
    ("ai_asset_candidates", "ai-asset"),
    ("asset_relation_candidates", "asset-relation"),
    ("asset_relation_observations", "asset-relation-observation"),
    ("technology_signals", "technology"),
)
TECHNOLOGY_HINTS = {
    "apache",
    "asp.net",
    "caddy",
    "cloudflare",
    "django",
    "express",
    "flask",
    "graphql",
    "iis",
    "laravel",
    "nginx",
    "node.js",
    "php",
    "react",
    "ruby",
    "spring",
    "tomcat",
    "varnish",
    "vue",
    "wordpress",
}

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
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
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


def _asset_optional_text(payload: dict, field: str) -> str:
    if payload.get(field) in (None, ""):
        return ""
    return _asset_text(payload[field], field, max_length=4096)


def _asset_ownership_pct(value: object) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("ownership_pct must be a number from 0 through 100")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 100:
        raise ValueError("ownership_pct must be a number from 0 through 100")
    return result


def _asset_depth(value: object) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 4:
        raise ValueError("depth must be an integer from 0 through 4")
    return value


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
        "entity_ref": _asset_optional_text(payload, "entity_ref"),
        "parent_ref": _asset_optional_text(payload, "parent_ref"),
        "ownership_pct": _asset_ownership_pct(payload.get("ownership_pct")),
        "depth": _asset_depth(payload.get("depth")),
    }


def _asset_relation_candidates(
    source: Path,
    *,
    limit: int = DEFAULT_ASSET_RELATION_CANDIDATE_LIMIT,
    target: str = "",
    allowed: ScopeChecker | None = None,
    excluded: ScopeChecker | None = None,
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
            "_target_related": False,
        }
        row["related"] = sorted(set(row["related"]) | set(observation["related"]))[
            :MAX_ASSET_RELATION_LIST_ITEMS
        ]
        if target and any(
            _parseable_network_asset("url" if "://" in value else "domain", value)
            and not (excluded and excluded.is_in_scope(value))
            and _matches_active_scope(value, target, allowed)
            for value in observation["related"]
        ):
            row["_target_related"] = True
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
        if observation["entity_ref"]:
            row["entity_refs"] = sorted(
                set(row.get("entity_refs", [])) | {observation["entity_ref"]}
            )[:MAX_ASSET_RELATION_LIST_ITEMS]
        if observation["parent_ref"]:
            row["parent_refs"] = sorted(
                set(row.get("parent_refs", [])) | {observation["parent_ref"]}
            )[:MAX_ASSET_RELATION_LIST_ITEMS]
        if observation["ownership_pct"] is not None:
            row["ownership_pct"] = max(
                float(row.get("ownership_pct", 0)), observation["ownership_pct"]
            )
        if observation["depth"] is not None:
            row["depth"] = min(int(row.get("depth", observation["depth"])), observation["depth"])
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


def _parseable_network_asset(asset_type: str, value: str) -> bool:
    if asset_type not in HOST_LIKE_ASSET_TYPES:
        return False
    try:
        if asset_type == "ip":
            ip_address(value.strip("[]"))
            return True
        if asset_type == "cidr":
            ip_network(value, strict=False)
            return True
        if asset_type == "url":
            parsed = urlsplit(value)
            return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
        if any(character.isspace() for character in value) or any(
            marker in value for marker in ("/", "?", "#")
        ):
            return False
        parsed = urlsplit(f"//{value}")
        host = (parsed.hostname or "").strip(".")
        if not host:
            return False
        parsed.port
        try:
            ip_address(host)
            return True
        except ValueError:
            ascii_host = host.encode("idna").decode("ascii")
            return all(
                label
                and len(label) <= 63
                and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
                for label in ascii_host.split(".")
            )
    except (UnicodeError, ValueError):
        return False


def _asset_scope_context(repo_root: Path, target: str) -> tuple[ScopeChecker | None, ScopeChecker | None]:
    profile = load_target_profile(default_memory_dir(repo_root), target)
    snapshot = profile.get("scope_snapshot", {}) if profile else {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    allowed = [item.strip() for item in snapshot.get("in_scope", []) if isinstance(item, str) and item.strip()]
    excluded = [
        item.strip()
        for item in snapshot.get("out_of_scope", [])
        if isinstance(item, str) and item.strip()
    ]
    try:
        active_context = ScopeContext(
            root_target=target,
            in_scope=allowed,
            out_of_scope=excluded,
        )
    except ScopeContextError:
        # Invalid profile scope must not widen discovery into active scope.
        return None, None
    return (
        ScopeChecker.from_context(active_context),
        # Keep the legacy exclusion view for callers that explicitly ask
        # whether a row matched a block pattern; active matching still comes
        # from the canonical context above.
        ScopeChecker(excluded) if excluded else None,
    )


def _matches_active_scope(value: str, target: str, allowed: ScopeChecker | None) -> bool:
    return url_belongs_to_target(value, target) or bool(allowed and allowed.is_in_scope(value))


def _related_to_scope(
    row: dict,
    target: str,
    allowed: ScopeChecker | None,
    excluded: ScopeChecker | None,
) -> bool:
    for related in row.get("related", []):
        if not _parseable_network_asset("url" if "://" in related else "domain", related):
            continue
        if excluded and excluded.is_in_scope(related):
            continue
        if _matches_active_scope(related, target, allowed):
            return True
    return False


def _classify_asset_relation_scope(
    row: dict,
    target: str,
    allowed: ScopeChecker | None,
    excluded: ScopeChecker | None,
) -> None:
    network_asset = _parseable_network_asset(row["asset_type"], row["value"])
    if network_asset and excluded and excluded.is_in_scope(row["value"]):
        row["scope_status"] = "excluded"
        row["scope_reason"] = "matched explicit target-profile exclusion"
        return
    if network_asset and _matches_active_scope(row["value"], target, allowed):
        row["scope_status"] = "in_scope"
        row["scope_reason"] = "matched active target set"
        return

    target_linked = bool(row.get("_target_related")) or _related_to_scope(
        row, target, allowed, excluded
    )
    strong_relation = any(token in row["relation"] for token in STRONG_RELATION_TOKENS)
    majority_owned = float(row.get("ownership_pct", 0)) > 50
    if (
        row["confidence"] == "high"
        and target_linked
        and (strong_relation or majority_owned or len(row["sources"]) > 1)
    ):
        row["scope_status"] = "scope-review"
        row["scope_reason"] = (
            f"high-confidence target-linked {row['relation']} relationship"
        )
    elif network_asset:
        row["scope_status"] = "external-chain-context"
        row["scope_reason"] = "external network relationship retained as context"
    else:
        row["scope_status"] = "unknown"
        row["scope_reason"] = "non-network or unparseable relationship candidate"


def _asset_relation_summary(target: str, rows: list[dict], stats: dict) -> dict:
    counts = Counter(row["scope_status"] for row in rows)
    depths = [row["depth"] for row in rows if "depth" in row]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "asset-relation-summary",
        "target": target,
        "candidate_count": len(rows),
        "observation_count": stats["input_count"],
        "invalid_count": stats["invalid_count"],
        "unique_count": stats["unique_count"],
        "truncated": bool(stats.get("truncated")),
        "partial": bool(stats["invalid_count"] or stats.get("truncated")),
        "warnings": stats["warnings"],
        "status_counts": dict(sorted(counts.items())),
        "scope_review_pending": counts["scope-review"],
        "max_depth": max(depths) if depths else None,
    }


def _normalized_host(value: object, *, allow_bare: bool = False) -> str:
    """Return a canonical host from a URL or an explicitly host-like value."""
    if not isinstance(value, str):
        return ""
    token = value.strip().split()[0] if value.strip() else ""
    if not token:
        return ""
    if token.endswith("/open"):
        token = token[:-5]
    if token.startswith("/") and not token.startswith("//"):
        return ""
    has_scheme = "://" in token
    if not has_scheme and not token.startswith("//") and not allow_bare:
        return ""
    if allow_bare and not has_scheme and not token.startswith("//"):
        # urlsplit treats an unbracketed IPv6 literal as a malformed netloc.
        # Handle the host-only form before parsing host:port artifacts.
        try:
            return str(ip_address(token.strip("[]")))
        except ValueError:
            pass
    try:
        parsed = urlsplit(token if has_scheme or token.startswith("//") else f"//{token}")
        host = (parsed.hostname or "").strip(".").lower()
        # A bare path such as ``assets/app.js`` must not become host ``assets``.
        if allow_bare and not has_scheme and not token.startswith("//") and any(
            marker in token for marker in ("/", "?", "#")
        ):
            return ""
        parsed.port
    except ValueError:
        return ""
    if not host:
        return ""
    try:
        return str(ip_address(host))
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
        labels = ascii_host.split(".")
        if not all(
            label
            and len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        ):
            return ""
        return ascii_host.lower()


def _jsonl_objects(path: Path):
    """Yield object rows from a derived JSONL input; malformed rows are ignored."""
    for line in _iter_lines(path):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


def _technology_labels(value: object) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        return []
    labels = []
    for item in values:
        if isinstance(item, dict):
            item = item.get("name") or item.get("display_name") or item.get("raw_label")
        if not isinstance(item, str):
            continue
        label = " ".join(item.strip().split()).lower()
        if label:
            labels.append(label)
    return sorted(set(labels))


def _known_technology_labels(value: object) -> list[str]:
    return [
        label
        for label in _technology_labels(value)
        if label in TECHNOLOGY_HINTS
        or any(
            re.search(rf"(?<![a-z0-9]){re.escape(hint)}(?![a-z0-9])", label)
            for hint in TECHNOLOGY_HINTS
        )
    ]


def _httpx_technology_signals(line: str) -> list[str]:
    signals = []
    for group in re.findall(r"\[([^\]]+)\]", line):
        normalized = " ".join(group.strip().split()).lower()
        if normalized in TECHNOLOGY_HINTS:
            signals.append(normalized)
            continue
        for hint in TECHNOLOGY_HINTS:
            if re.search(rf"(?<![a-z0-9]){re.escape(hint)}(?![a-z0-9])", normalized):
                signals.append(hint)
    return sorted(set(signals))


def _iter_asset_relation_observations(source: Path):
    """Yield valid raw relation observations without applying candidate limits."""
    if not source.is_file():
        return
    try:
        with source.open("rb") as handle:
            while True:
                raw = handle.readline(MAX_ASSET_RELATION_LINE_BYTES + 1)
                if not raw:
                    break
                oversized = len(raw) > MAX_ASSET_RELATION_LINE_BYTES
                if oversized and not raw.endswith(b"\n"):
                    while True:
                        chunk = handle.readline(MAX_ASSET_RELATION_LINE_BYTES + 1)
                        if not chunk or chunk.endswith(b"\n"):
                            break
                    continue
                if oversized:
                    continue
                text = raw.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    yield _normalize_asset_relation_observation(json.loads(text))
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError:
        return


def _iter_asset_relation_ranking_observations(source: Path):
    """Read network values from raw relation rows without candidate list caps."""
    if not source.is_file():
        return
    try:
        with source.open("rb") as handle:
            while True:
                raw = handle.readline(MAX_ASSET_RELATION_LINE_BYTES + 1)
                if not raw:
                    break
                oversized = len(raw) > MAX_ASSET_RELATION_LINE_BYTES
                if oversized and not raw.endswith(b"\n"):
                    while True:
                        chunk = handle.readline(MAX_ASSET_RELATION_LINE_BYTES + 1)
                        if not chunk or chunk.endswith(b"\n"):
                            break
                    continue
                if oversized:
                    continue
                try:
                    payload = json.loads(raw.decode("utf-8", errors="replace"))
                except (UnicodeError, json.JSONDecodeError):
                    continue
                if not isinstance(payload, dict):
                    continue
                if payload.get("schema_version") != SCHEMA_VERSION or payload.get("kind") != "asset-relation-observation":
                    continue
                yield payload
    except OSError:
        return


def _asset_relation_network_values(observation: dict):
    """Return only network assets from a relation row for host ranking."""
    asset_type = str(observation.get("asset_type") or "").lower()
    value = observation.get("value")
    if isinstance(value, str) and _parseable_network_asset(asset_type, value):
        yield value
    for related in observation.get("related") or []:
        if not isinstance(related, str):
            continue
        if "://" in related:
            related_type = "url"
        else:
            try:
                ip_address(related.strip("[]"))
                related_type = "ip"
            except ValueError:
                related_type = "domain"
        if _parseable_network_asset(related_type, related):
            yield related


def _load_host_ranking_inventory(recon_dir: Path, target: str) -> dict:
    """Read an existing technology projection without creating a new artifact."""
    path = recon_dir / HOST_RANKING_TECHNOLOGY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("status") != "ready":
        return {}
    try:
        if target and canonical_target_value(str(payload.get("target") or "")) != canonical_target_value(target):
            return {}
    except ValueError:
        return {}
    bindings = payload.get("sources")
    if not isinstance(bindings, list):
        binding = payload.get("source")
        bindings = [binding] if isinstance(binding, dict) else []
    def _fresh_binding(binding: object) -> bool:
        if not isinstance(binding, dict) or not isinstance(binding.get("path"), str):
            return False
        try:
            return inventory_source_binding_matches(binding, binding["path"])
        except (OSError, TypeError, ValueError):
            return False

    if not bindings or any(not _fresh_binding(binding) for binding in bindings):
        return {}
    return payload


def _host_ranking(
    recon_dir: Path,
    *,
    target: str = "",
    candidate_rows: dict[str, list[dict]] | None = None,
    asset_relation_input: Path | None = None,
) -> tuple[list[dict], dict]:
    """Build an all-host soft ranking from cached recon evidence only.

    The output is a rebuildable attention hint. Every host observed in the
    supported artifacts is retained; only deterministic ordering changes.
    """
    observations: dict[str, dict] = {}

    def add(
        host: str,
        source: str,
        evidence_key: str,
        signal: str,
        *,
        technology: list[str] | None = None,
    ) -> None:
        if not host:
            return
        bucket = observations.setdefault(
            host,
            {
                "evidence": defaultdict(set),
                "signals": set(),
                "technology": set(),
            },
        )
        bucket["evidence"][source].add(evidence_key)
        if signal:
            bucket["signals"].add(signal)
        if technology:
            bucket["technology"].update(technology)

    for source_key, relative, source_name, signal in HOST_RANKING_FIXED_SOURCES:
        path = recon_dir / relative
        for line in _iter_lines(path):
            host = _normalized_host(line, allow_bare=source_key == "live_httpx")
            if not host:
                continue
            technology = _httpx_technology_signals(line) if source_key == "live_httpx" else []
            add(host, source_name, line, signal, technology=technology)
            if technology:
                add(host, "live/httpx_full.txt", line, "technology", technology=technology)

    for relative, signal in HOST_RANKING_ADDITIONAL_SOURCES:
        for line in _iter_lines(recon_dir / relative):
            host = _normalized_host(line, allow_bare=True)
            if host:
                add(host, relative.as_posix(), line, signal)

    ports_dir = recon_dir / "ports"
    if ports_dir.is_dir():
        port_paths = sorted(
            (path for path in ports_dir.glob("open_host_ports*.txt") if path.is_file()),
            key=lambda path: path.name,
        )
        if not port_paths:
            port_paths = [
                path
                for name in ("open_ports_all.txt", "open_ports.txt", "open_ports_naabu.txt")
                if (path := ports_dir / name).is_file()
            ]
    else:
        port_paths = []
    for path in port_paths:
        source_name = f"ports/{path.name}"
        for line in _iter_lines(path):
            host = _normalized_host(line, allow_bare=True)
            if host:
                add(host, source_name, line, "open-port")

    for source_key, path, signal in HOST_RANKING_CANDIDATE_SOURCES:
        source_name = path.as_posix()
        payloads = (
            candidate_rows.get(source_key, [])
            if candidate_rows is not None and source_key in candidate_rows
            else _jsonl_objects(recon_dir / path)
        )
        for payload in payloads:
            evidence_key = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            raw_signals = payload.get("signals")
            row_signals = _technology_labels(raw_signals)
            row_signals.append(signal)
            values = [payload.get("value")]
            related = payload.get("related")
            if isinstance(related, list):
                values.extend(related)
            if source_key == "asset_relation_candidates":
                asset_type = str(payload.get("asset_type") or "").lower()
                values = [
                    value
                    for value in values
                    if isinstance(value, str)
                    and _parseable_network_asset(
                        asset_type if value == payload.get("value") else (
                            "url" if "://" in value else "domain"
                        ),
                        value,
                    )
                ]
            for value in values:
                host = _normalized_host(value, allow_bare=True)
                if not host:
                    continue
                for row_signal in row_signals:
                    add(host, source_name, evidence_key, row_signal)

    technology_payload = _load_host_ranking_inventory(recon_dir, target)
    for row_index, item in enumerate(technology_payload.get("hosts") or []):
        if not isinstance(item, dict):
            continue
        host = _normalized_host(item.get("host") or item.get("url"), allow_bare=True)
        if not host:
            continue
        labels = _known_technology_labels(item.get("components"))
        add(
            host,
            HOST_RANKING_TECHNOLOGY_PATH.as_posix(),
            f"{row_index}:{json.dumps(item, ensure_ascii=False, sort_keys=True)}",
            "technology",
            technology=labels,
        )

    raw_asset_input = asset_relation_input or recon_dir / ASSET_RELATION_INPUT_PATH
    raw_asset_source = ASSET_RELATION_INPUT_PATH.as_posix()
    for observation in _iter_asset_relation_ranking_observations(raw_asset_input):
        evidence_key = json.dumps(observation, ensure_ascii=False, sort_keys=True)
        for value in _asset_relation_network_values(observation):
            host = _normalized_host(value, allow_bare=True)
            if host:
                add(host, raw_asset_source, evidence_key, "asset-relation-observation")

    fixed_source_names = [
        source_name
        for _key, _path, source_name, _signal in HOST_RANKING_FIXED_SOURCES
    ]
    rows: list[dict] = []
    for host in sorted(observations):
        bucket = observations[host]
        source_counts = {
            source_name: len(bucket["evidence"].get(source_name, set()))
            for source_name in fixed_source_names
        }
        source_counts.update(
            {
                source_name: len(bucket["evidence"].get(source_name, set()))
                for source_name in sorted(bucket["evidence"])
                if source_name not in source_counts
            }
        )
        details = {
            "live_httpx": source_counts.get("live/httpx_full.txt", 0),
            "discovery_artifacts": sum(
                source_counts.get(source_name, 0)
                for source_name in HOST_RANKING_ADDITIONAL_SOURCE_NAMES
            ),
            "open_host_ports": sum(
                count for source_name, count in source_counts.items() if source_name.startswith("ports/")
            ),
            "api_endpoints": source_counts.get("urls/api_endpoints.txt", 0),
            "with_params": source_counts.get("urls/with_params.txt", 0),
            "js_files": source_counts.get("urls/js_files.txt", 0),
            "host_pivot_candidates": source_counts.get(
                "exposure/host_pivot_candidates.jsonl", 0
            ),
            "ai_asset_candidates": source_counts.get("exposure/ai_asset_candidates.jsonl", 0),
            "asset_relation_candidates": source_counts.get(
                "exposure/asset_relation_candidates.jsonl", 0
            ),
            "asset_relation_observations": source_counts.get(
                ASSET_RELATION_INPUT_PATH.as_posix(), 0
            ),
            "technology_signals": sorted(bucket["technology"]),
        }
        score_details = []
        score = 0
        for source_key, signal in HOST_RANKING_SIGNAL_ORDER:
            count = (
                len(details["technology_signals"])
                if source_key == "technology_signals"
                else details[source_key]
            )
            points = min(count, 8) * HOST_RANKING_WEIGHTS[source_key]
            if not points:
                continue
            score += points
            score_details.append(
                {
                    "source": source_key,
                    "count": count,
                    "points": points,
                    "reason": f"{count} {signal} observation(s)",
                }
            )
        signals = [
            signal
            for source_key, signal in HOST_RANKING_SIGNAL_ORDER
            if (
                len(details["technology_signals"])
                if source_key == "technology_signals"
                else details[source_key]
            )
        ]
        for signal in sorted(bucket["signals"]):
            if signal not in signals:
                signals.append(signal)
        signals.extend(
            f"technology:{label}"
            for label in details["technology_signals"]
            if f"technology:{label}" not in signals
        )
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "host-ranking-candidate",
                "host": host,
                "value": host,
                "score": score,
                "details": details,
                "source_counts": source_counts,
                "signals": signals,
                "score_details": score_details,
            }
        )
    rows.sort(key=lambda row: (-row["score"], row["host"]))
    aggregate_source_counts = {source_name: 0 for source_name in fixed_source_names}
    for row in rows:
        for source_name in row["source_counts"]:
            aggregate_source_counts[source_name] = aggregate_source_counts.get(source_name, 0) + row[
                "source_counts"
            ][source_name]
    return rows, {
        "host_count": len(rows),
        "source_counts": dict(sorted(aggregate_source_counts.items())),
    }


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
    allowed_scope, excluded_scope = _asset_scope_context(Path(repo_root), resolved)
    asset_rows, asset_stats = _asset_relation_candidates(
        asset_input_path,
        limit=asset_limit,
        target=resolved,
        allowed=allowed_scope,
        excluded=excluded_scope,
    )
    for row in asset_rows:
        _classify_asset_relation_scope(row, resolved, allowed_scope, excluded_scope)
        row.pop("_target_related", None)
    asset_summary = _asset_relation_summary(resolved, asset_rows, asset_stats)
    host_ranking_rows, host_ranking_summary = _host_ranking(
        recon_dir,
        target=resolved,
        candidate_rows={
            "host_pivot_candidates": host_rows,
            "ai_asset_candidates": ai_rows,
            "asset_relation_candidates": asset_rows,
        },
        asset_relation_input=asset_input_path,
    )
    host_path = exposure_dir / "host_pivot_candidates.jsonl"
    ai_path = exposure_dir / "ai_asset_candidates.jsonl"
    host_ranking_path = recon_dir / HOST_RANKING_OUTPUT_PATH
    asset_path = recon_dir / ASSET_RELATION_OUTPUT_PATH
    asset_summary_path = recon_dir / ASSET_RELATION_SUMMARY_PATH
    _write_jsonl_atomic(host_path, host_rows)
    _write_jsonl_atomic(ai_path, ai_rows)
    _write_jsonl_atomic(host_ranking_path, host_ranking_rows)
    _write_jsonl_atomic(asset_path, asset_rows)
    asset_summary["candidate_bytes"] = asset_path.stat().st_size
    _write_json_atomic(asset_summary_path, asset_summary)
    return {
        "target": resolved,
        "host_pivot_candidates": len(host_rows),
        "ai_asset_candidates": len(ai_rows),
        "host_ranking_hosts": host_ranking_summary["host_count"],
        "asset_relation_candidates": len(asset_rows),
        "asset_relation_observations": asset_stats["input_count"],
        "asset_relation_invalid": asset_stats["invalid_count"],
        "asset_relation_unique": asset_stats["unique_count"],
        "asset_relation_truncated": asset_stats.get("truncated", False),
        "asset_relation_warnings": asset_stats["warnings"],
        "host_path": str(host_path),
        "ai_path": str(ai_path),
        "host_ranking_path": str(host_ranking_path),
        "host_ranking_source_counts": host_ranking_summary["source_counts"],
        "asset_input_path": str(asset_input_path),
        "asset_path": str(asset_path),
        "asset_summary_path": str(asset_summary_path),
        "asset_scope_status_counts": asset_summary["status_counts"],
        "asset_scope_review_pending": asset_summary["scope_review_pending"],
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
