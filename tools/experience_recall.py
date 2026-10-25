#!/usr/bin/env python3
"""Read target-owned Store experience and explicitly promoted knowledge cards.

Keyword filtering narrows the view; Claude judges relevance. Other targets'
private history and retired PatternDB files never enter the current view.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent

try:
    from tools.target_paths import canonical_target_value
    from tools.target_store import StoreError, runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from target_paths import canonical_target_value  # type: ignore
    from target_store import StoreError, runtime_store  # type: ignore


KNOWLEDGE_CARD_LIMIT = 10

_STORE_KIND = {
    "note": "note",
    "lead": "hypothesis",
    "dead_end": "negative",
    "useful_pattern": "primitive",
    "next_action": "handoff",
}


def _tokenize(text: str) -> set[str]:
    return {
        token.lower()
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}|[一-鿿]+", str(text or ""))
    }


def _store_entry(row: dict, target: str) -> dict:
    kind_by_store = {value: key for key, value in _STORE_KIND.items()}
    evidence = row.get("evidence", [])
    return {
        **{key: row.get(key) for key in ("claims", "sources", "source_health", "review_state", "applicability", "correction_refs", "dependency_refs")},
        "kind": kind_by_store[row["kind"]], "target": target,
        "ts": row["created_at"], "text": row["statement"],
        "entry_id": row["id"], "conditions": row["conditions"],
        "reopen_when": row["reopen_when"], "next_intent": row["next_intent"],
        "recorded_by": row["recorded_by"], "action_id": row["action_id"],
        "finding_id": row["finding_id"], "evidence": evidence,
        "evidence_refs": [f"{item['operation_id']}:{item['step']}" for item in evidence],
        "structured": {key: row[key] for key in ("conditions", "reopen_when", "next_intent") if row[key]} or None,
    }


def _collect_target_entries(
    repo_root: Path, target: str, kinds: list[str],
    *, query: str = "", limit: int = 5, cursor: str | None = None,
    experience_id: str | None = None,
) -> tuple[list[dict], dict | None]:
    store = runtime_store(repo_root, target)
    selected = sorted({_STORE_KIND[kind] for kind in kinds if kind in _STORE_KIND})
    if not selected:
        if "pattern_db" in kinds:
            raise StoreError("PatternDB is legacy-only for primary targets; use note, dead_end or useful_pattern")
        if cursor or experience_id:
            raise StoreError("target experience cursor or ID requires a target experience kind")
        return [], None
    if experience_id:
        row = store.experience(experience_id)
        if row["kind"] not in selected:
            raise StoreError(f"experience {experience_id} is outside the selected kinds")
        return [_store_entry(row, target)], None
    page = store.experience_page(kinds=selected, query=query, limit=limit, cursor=cursor)
    return [_store_entry(row, target) for row in page["items"]], {
        key: page[key] for key in ("store_id", "revision", "order", "total", "remaining", "has_more", "next_cursor")
    }


def _collect_knowledge_cards(repo_root: Path, query_tokens: set[str]) -> tuple[list[dict], dict]:
    """Legacy display adapter; admission shares the current knowledge source owner."""
    from tools.recall_sources import acquire_knowledge

    documents, health = acquire_knowledge(repo_root)
    entries = []
    for doc in sorted(documents, key=lambda d: d["source_ref"]):
        record = doc["record"]
        metadata = record["metadata"]
        head = " ".join(str(item) for item in metadata.get("trigger_tags", [])) + " " + record["id"].replace("-", " ")
        if query_tokens and not (_tokenize(head) & query_tokens):
            continue
        entries.append({"kind": "knowledge_card", "target": "", "ts": "",
                        "text": record["id"], "ref": record["file"],
                        "maturity": metadata["maturity"], "review": record["review"]})
    if (documents, health) != acquire_knowledge(repo_root):
        raise StoreError("knowledge source health changed; retry query")
    return entries[:KNOWLEDGE_CARD_LIMIT], {
        **health, "invalid_count": len(health.get("errors", [])),
        "matched_count": len(entries), "remaining": max(0, len(entries) - KNOWLEDGE_CARD_LIMIT),
        "order": "card_id", "filter": "keyword_only" if query_tokens else "none",
        "catalog_ref": str((repo_root / "knowledge" / "capabilities.yaml").resolve()),
    }


def _store_sources_stale(before: list[dict], after: list[dict]) -> bool:
    """Whether re-collected entries changed their source-bound projections.

    The store binding only covers DB rows; the files backing an experience's
    sources can change bytes without a revision bump, leaving captured
    source_health/review_state snapshots stale.
    """
    fields = ("sources", "source_health", "review_state", "claims")
    if len(before) != len(after):
        return True
    return any(
        any(entry.get(field) != fresh.get(field) for field in fields)
        for entry, fresh in zip(before, after)
    )


def build_recall_view(
    repo_root: Path,
    *,
    target: str,
    query: str = "",
    kinds: list[str] | None = None,
    limit: int = 5,
    cursor: str | None = None,
    experience_id: str | None = None,
) -> dict[str, Any]:
    """Aggregate one Claude-readable recall view across experience sources."""
    if cursor is not None and experience_id is not None:
        raise ValueError("recall accepts --cursor or --id, not both")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be 1..1000")
    if not isinstance(query, str) or len(query) > 512:
        raise ValueError("query must be a string of at most 512 characters")
    if kinds and any(kind not in {*_STORE_KIND, "knowledge_card", "pattern_db"} for kind in kinds):
        raise ValueError("unknown recall kind")
    from tools.recall_sources import acquire_current
    canonical = canonical_target_value(target)
    current = acquire_current(repo_root, canonical)
    query_tokens = _tokenize(query) if query else set()
    selected_kinds = kinds or list(_STORE_KIND) + ["knowledge_card"]

    target_entries, target_page = _collect_target_entries(
        repo_root, canonical, selected_kinds, query=query,
        limit=limit, cursor=cursor, experience_id=experience_id,
    )
    card_entries, knowledge_health = (
        _collect_knowledge_cards(repo_root, query_tokens)
        if "knowledge_card" in selected_kinds and not experience_id else ([], {"status": "not_requested"})
    )

    if runtime_store(repo_root, canonical).binding() != current["binding"]:
        raise StoreError("recall current revision changed; retry query")
    recheck_entries, _ = _collect_target_entries(
        repo_root, canonical, selected_kinds, query=query,
        limit=limit, cursor=cursor, experience_id=experience_id,
    )
    if _store_sources_stale(target_entries, recheck_entries):
        raise StoreError("experience source health changed during assembly; retry query")
    return {
        "schema_version": 2,
        "current": current,
        "target": canonical,
        "query": query,
        "isolation": {
            "rule": "current-target episodes and patterns only; cross-project reuse "
                    "happens through human-reviewed knowledge cards, not automatic "
                    "recall of other targets' field memory",
            "cross_target_sources": ["knowledge/cards (reviewed only)"],
        },
        "counts": {
            "target_entries": sum(1 for e in target_entries if not e.get("truncated")),
            "pattern_db": 0,
            "knowledge_cards": len(card_entries),
            "truncated_windows": sum(1 for e in target_entries if e.get("truncated"))
                                 + int(bool(target_page and target_page["has_more"]))
                                 + int(bool(knowledge_health.get("remaining"))),
        },
        "target_entries": target_entries,
        "target_page": target_page,
        "pattern_db": [],
        "knowledge_cards": card_entries,
        "source_health": {"knowledge": knowledge_health},
        "note": (
            "query 是词项粗筛，相关性判断由 Claude 完成。情节 evidence_refs/structured "
            "按引用展开原始证据；知识卡只列引用，正文按需读取。"
            "关键词未命中不代表没有相关知识；catalog_ref 指向完整登记目录，"
            "可原生读取目录中的其余卡片引用，不受推荐窗口限制。"
        ),
    }


def query_recall(repo_root: Path, *, target: str, query: str = "", limit: int = 5,
                 cursor: str | None = None, source_ref: str | None = None,
                 encoder_path: str | None = None, reranker_path: str | None = None,
                 include_knowledge: bool = True, context_limit: int = 20, context_max_bytes: int = 64000) -> dict:
    """Independent current facts and fresh-source-checked historical candidates."""
    import base64
    from tools.recall_sources import acquire_snapshot, digest, same_snapshot
    from tools.recall_index import query_text, acquire_index_snapshot
    from tools.recall_context import context_page, verify_context
    if not isinstance(query, str) or len(query) > 512 or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("query must be <=512 characters and limit 1..1000")
    if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 8192):
        raise ValueError("invalid recall cursor")
    if source_ref is not None and (not isinstance(source_ref, str) or not source_ref):
        raise ValueError("source_ref must be a nonempty string")
    if type(context_limit) is not int or not 1 <= context_limit <= 1000 or type(context_max_bytes) is not int or not 1024 <= context_max_bytes <= 4000000:
        raise ValueError("context limit must be 1..1000 and max_bytes 1024..4000000")
    snapshot, generations = acquire_index_snapshot(repo_root, target, include_knowledge=include_knowledge)
    offset, decoded = 0, None
    if cursor:
        try:
            decoded = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
            if not isinstance(decoded, dict) or type(decoded.get("offset")) is not int or decoded["offset"] < 0:
                raise ValueError("invalid recall cursor")
            offset = decoded["offset"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError("invalid or stale recall cursor; restart query") from exc
    result = query_text(repo_root, target, snapshot, query, limit=limit, offset=offset,
                        encoder_path=encoder_path, reranker_path=reranker_path, generations=generations)
    binding = {"source": snapshot["binding"], "query": query, "source_ref": source_ref,
               "generations": result["pagination"]["generations"],
               "ranking": result["pagination"]["ranking_binding"]}
    if decoded is not None and decoded.get("binding") != digest(binding):
        raise ValueError("invalid or stale recall cursor; restart query")
    documents = {doc["source_ref"]: doc for doc in snapshot["documents"]}
    if source_ref:
        if source_ref not in documents:
            raise ValueError("source_ref is not in this target/reviewed knowledge snapshot")
        selected = [documents[source_ref]][offset:offset + limit]
        remaining = max(0, 1 - offset - len(selected))
    else:
        selected = result["items"]
        remaining = result["pagination"]["remaining"]
    roots = [{"experience_id": item["record"]["id"], "version": item["record"]["version"]}
             for item in selected if item["source_ref"].startswith("experience:")]
    counterevidence = context_page(repo_root, target, roots=roots, limit=context_limit, max_bytes=context_max_bytes)
    fresh = acquire_snapshot(repo_root, target, include_knowledge=include_knowledge,
                             previous_capture=snapshot.get("capture"),
                             knowledge_parse_capture=snapshot.get("knowledge_parse_capture"))
    if not same_snapshot(fresh, snapshot):
        raise StoreError("recall sources changed during query; retry")
    verify_context(repo_root, target, counterevidence)
    next_cursor = base64.urlsafe_b64encode(json.dumps({"binding": digest(binding), "offset": offset + len(selected)}).encode()).decode() if remaining else None
    target_entries = [
        _store_entry(item["record"], snapshot["binding"]["target"])
        for item in selected
        if item["source_ref"].startswith("experience:")
    ]
    # Keep the old consumer projection as an explicit, read-only alias.  The
    # ranked result and current facts above remain the canonical v2 contract;
    # this field lets older resume/retrospective readers migrate in one release
    # without reopening a second Store or inventing lifecycle state.
    return {"schema_version": 2, "target": snapshot["binding"]["target"], "query": query,
            "binding": snapshot["binding"], "as_of": fresh["as_of"], "current": fresh["current"],
            "recalled": selected, "target_entries": target_entries,
            "health": {**snapshot["health"], **result["health"]},
            "counterevidence": counterevidence, "acquisition": snapshot.get("acquisition"),
            "pagination": {**result["pagination"], "remaining": remaining, "next_cursor": next_cursor,
                           "total": 1 if source_ref else result["pagination"]["total"],
                           "next_offset": offset + len(selected) if remaining else None,
                           "context_incomplete": remaining > 0 or counterevidence["context_incomplete"]}}


def history_view(repo_root: Path, *, target: str, limit: int = 20,
                 cursor: str | None = None, experience_id: str | None = None) -> dict:
    """Expand a Store history page without translating its cursor into a ranking cursor."""
    from tools.recall_sources import acquire_current

    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be 1..1000")
    if cursor is not None and experience_id is not None:
        raise ValueError("history accepts --cursor or --id, not both")
    current = acquire_current(repo_root, target)
    store = runtime_store(repo_root, target)
    page = ({"items": [store.experience(experience_id)], "remaining": 0, "has_more": False,
             "next_cursor": None, "total": 1, "order": "id"}
            if experience_id else store.experience_page(limit=limit, cursor=cursor))
    if current != acquire_current(repo_root, target):
        raise StoreError("current facts changed during history read; retry")
    entries = [_store_entry(row, store.target) for row in page["items"]]
    return {"schema_version": 2, "view": "history", "target": store.target,
            "binding": current["binding"], "current": current, "experiences": page,
            "target_entries": entries, "target_page": page,
            "health": {"target": {"status": "ready"}},
            "cursor_owner": "TargetStore.experience_page"}


def _compact_recall(result: dict) -> dict:
    """Omit exact display aliases while preserving complete records and context."""
    def same(left, right):
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)

    view = dict(result)
    if result.get("view") == "history":
        page = result["experiences"]
        records = page["items"]
        if same(view.get("target_page"), page):
            view.pop("target_page", None)
    else:
        records, recalled = [], []
        for item in result["recalled"]:
            doc = dict(item)
            if str(doc.get("source_ref", "")).startswith("experience:"):
                record = doc["record"]
                records.append(record)
                for key in ("text", "conditions", "review_state", "kind", "claims",
                            "source_health", "correction_refs", "dependency_refs", "applicability"):
                    record_key = "statement" if key == "text" else key
                    if key in doc and record_key in record and same(doc[key], record[record_key]):
                        doc.pop(key)
            recalled.append(doc)
        view["recalled"] = recalled
    aliases = [_store_entry(row, result["target"]) for row in records]
    if same(view.get("target_entries"), aliases):
        view.pop("target_entries", None)
    return view


def _index_cli(argv: list[str]) -> int:
    from tools.recall_index import build_text_index, index_status, prune_generations
    parser = argparse.ArgumentParser(
        description="Explicit read-only recall and derived-index lifecycle",
        epilog="Use <command> --help for options. Legacy --target TARGET [--kind KIND] invocation remains supported; "
               "use --target TARGET --help for its options.")
    parser.add_argument("command", choices=("query", "history", "context", "index-build", "index-status", "index-prune",
                                             "relation-build", "relation-query", "relation-status", "relation-prune"))
    parser.add_argument("--target")
    parser.add_argument("--shared", action="store_true", help="text/relation index lifecycle and relation query for reviewed shared knowledge; no target Store")
    parser.add_argument("--no-knowledge", action="store_true", help="query/build/status target text only")
    parser.add_argument("--full-rebuild", action="store_true", help="explicit text/relation full acquisition and rebuild without previous capture or source shards")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--query", default="")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--cursor")
    parser.add_argument("--source-ref")
    parser.add_argument("--id", dest="experience_id", help="Store experience ID for history or exact context expansion")
    parser.add_argument("--version", type=int, help="exact retained experience version for context")
    parser.add_argument("--context-limit", type=int, default=20, help="counterevidence page size, independent of query top-k")
    parser.add_argument("--context-max-bytes", type=int, default=64000, help="counterevidence item-body budget; current facts stay separate")
    parser.add_argument("--encoder-path", help="local encoder directory containing recall-model.json; never downloaded")
    parser.add_argument("--reranker-path", help="local reranker directory containing recall-model.json; never downloaded")
    parser.add_argument("--seeds", help="JSON array of exact C6 entity bindings, or @JSON_FILE")
    parser.add_argument("--known-conditions", default="{}", help="role to exact C6 entity JSON; free-text conditions remain unverified")
    parser.add_argument("--direction", choices=("out", "in", "both"), default="out")
    parser.add_argument("--predicate", action="append")
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--min-hops", type=int, default=1)
    parser.add_argument("--max-edges", type=int, default=1000)
    parser.add_argument("--max-bytes", type=int, default=200000)
    parser.add_argument("--max-seconds", type=float, default=1.0)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="complete JSON (default)")
    output.add_argument("--compact", action="store_true", help="query/history JSON without exact display aliases; complete records and counterevidence remain")
    args = parser.parse_args(argv)
    try:
        root = Path(args.repo_root)
        if args.compact and args.command not in {"query", "history"}:
            raise ValueError("--compact belongs to query/history")
        if args.shared:
            if args.command not in {"index-build", "index-status", "index-prune", "relation-build", "relation-query", "relation-status", "relation-prune"} or args.target or args.no_knowledge:
                raise ValueError("--shared requires an index lifecycle or relation query command without --target/--no-knowledge")
        elif not args.target:
            raise ValueError("--target is required except for shared index commands")
        if args.no_knowledge and args.command not in {"query", "index-build", "index-status"}:
            raise ValueError("--no-knowledge belongs to query/index-build/index-status")
        if args.full_rebuild and args.command not in {"index-build", "relation-build"}:
            raise ValueError("--full-rebuild belongs to index-build/relation-build")
        if args.version is not None and args.command != "context":
            raise ValueError("--version belongs to context; full raw history uses target_memory.py version")
        if args.experience_id and args.command not in {"history", "context"}:
            raise ValueError("--id belongs to history; query uses --source-ref experience:ID")
        if args.command == "history" and (args.query or args.source_ref or args.encoder_path or args.reranker_path):
            raise ValueError("history does not rank sources; use query for retrieval")
        if args.command == "query":
            result = query_recall(root, target=args.target, query=args.query, limit=args.limit,
                                  cursor=args.cursor, source_ref=args.source_ref,
                                  encoder_path=args.encoder_path, reranker_path=args.reranker_path,
                                  include_knowledge=not args.no_knowledge,
                                  context_limit=args.context_limit, context_max_bytes=args.context_max_bytes)
        elif args.command == "context":
            from tools.recall_context import context_page
            if args.cursor:
                if args.experience_id or args.version is not None:
                    raise ValueError("context accepts --cursor or --id/--version, not both")
                roots = None
            else:
                if not args.experience_id or args.version is None:
                    raise ValueError("context requires --id and exact --version, or --cursor")
                roots = [{"experience_id": args.experience_id, "version": args.version}]
            result = context_page(root, args.target, roots=roots, cursor=args.cursor,
                                  limit=args.context_limit, max_bytes=args.context_max_bytes)
        elif args.command == "history":
            result = history_view(root, target=args.target, limit=args.limit,
                                  cursor=args.cursor, experience_id=args.experience_id)
        elif args.command == "index-build":
            result = build_text_index(root, args.target, encoder_path=args.encoder_path, reranker_path=args.reranker_path,
                                      shared=args.shared, include_knowledge=not args.no_knowledge,
                                      full_rebuild=args.full_rebuild)
        elif args.command == "index-status":
            result = index_status(root, args.target, shared=args.shared, include_knowledge=not args.no_knowledge)
        elif args.command == "index-prune":
            result = prune_generations(root, args.target, shared=args.shared)
        elif args.command == "relation-build":
            from tools.relation_recall import build_relations
            result = build_relations(root, args.target, shared=args.shared, full_rebuild=args.full_rebuild)
        elif args.command == "relation-query":
            from tools.relation_recall import query_relations
            if not args.seeds:
                raise ValueError("relation-query requires --seeds exact entity JSON")
            raw = Path(args.seeds[1:]).read_text(encoding="utf-8") if args.seeds.startswith("@") else args.seeds
            seeds = json.loads(raw)
            if not isinstance(seeds, list) or not seeds or any(not isinstance(seed, (dict, str)) for seed in seeds):
                raise ValueError("--seeds must be a nonempty JSON array of exact entity bindings")
            result = query_relations(root, args.target, seeds, shared=args.shared, cursor=args.cursor,
                                     known_conditions=json.loads(args.known_conditions),
                                     direction=args.direction, predicates=args.predicate,
                                     max_depth=args.max_depth, min_hops=args.min_hops,
                                     max_edges=args.max_edges, max_paths=args.limit,
                                     max_bytes=args.max_bytes, max_seconds=args.max_seconds,
                                     context_limit=args.context_limit, context_max_bytes=args.context_max_bytes)
        elif args.command == "relation-status":
            from tools.relation_recall import relation_status
            result = relation_status(root, args.target, shared=args.shared)
        else:
            result = prune_generations(root, args.target, "relations", shared=args.shared)
    except (StoreError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(_compact_recall(result) if args.compact else result, ensure_ascii=False, indent=2))
    if args.command in {"index-build", "relation-build"} and result["health"]["status"] != "ready":
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    actual = list(sys.argv[1:] if argv is None else argv)
    if (actual in (["--help"], ["-h"]) or actual and actual[0] in {
            "query", "history", "context", "index-build", "index-status", "index-prune",
            "relation-build", "relation-query", "relation-status", "relation-prune"}):
        return _index_cli(actual)
    parser = argparse.ArgumentParser(
        description="Read Store experiences and reviewed knowledge cards."
    )
    parser.add_argument("--target", required=True, help="current target (isolation anchor)")
    parser.add_argument("--query", default="", help="optional coarse token filter")
    parser.add_argument(
        "--kind", action="append", default=[],
        choices=["note", "lead", "dead_end", "useful_pattern", "next_action", "pattern_db", "knowledge_card"],
        help="restrict to specific kinds (repeatable)",
    )
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--limit", type=int, default=5, help="target experience page size")
    parser.add_argument("--cursor", default=None, help="target experience next-page cursor")
    parser.add_argument("--id", dest="experience_id", default=None, help="expand one target experience")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        view = build_recall_view(
            Path(args.repo_root), target=args.target, query=args.query,
            kinds=args.kind or None, limit=args.limit, cursor=args.cursor,
            experience_id=args.experience_id,
        )
    except (StoreError, ValueError) as exc:
        print(f"experience recall failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(view, ensure_ascii=False, indent=2))
        return 0

    # 人类可读形态（Claude 默认读这个）
    print(f"# Experience recall — {view['target']}"
          + (f" (query: {view['query']})" if view["query"] else ""))
    print()
    print("## Current facts")
    print(json.dumps(view["current"], ensure_ascii=False))
    health = view["source_health"]["knowledge"]
    print("Knowledge source: " + json.dumps(health, ensure_ascii=False))
    if health.get("catalog_ref"):
        print("Knowledge discovery: " + view["note"])
    if view["target_entries"]:
        print("## 当前目标经验")
        for entry in view["target_entries"]:
            ts = entry.get("ts", "")[:10]
            entry_id = f" [{entry['entry_id']}]" if entry.get("entry_id") else ""
            print(f"- ({entry['kind']} {ts}){entry_id} {entry['text']}")
            if entry.get("evidence_refs"):
                print(f"  evidence: {', '.join(entry['evidence_refs'][:3])}")
            for field, label in (("conditions", "conditions"), ("reopen_when", "reopen_when"),
                                 ("next_intent", "next_intent"), ("recorded_by", "recorded_by")):
                if entry.get(field):
                    print(f"  {label}: {entry[field]}")
            for field in ("claims", "review_state", "applicability", "source_health", "sources", "correction_refs", "dependency_refs"):
                print(f"  {field}: {json.dumps(entry.get(field), ensure_ascii=False)}")
            # structured 判断单元的关键字段必须进入默认文本（2026-09-14
            # 审计）：JSON 保留了它们而文本不显示——压缩/接手后默认视图
            # 丢失证据引用、下一步和停止条件，恢复时不得不再读原文件。
            structured = entry.get("structured") if isinstance(entry.get("structured"), dict) else None
            if structured:
                for field, label in (
                    ("evidence_ref", "evidence_ref"),
                    ("next", "next"),
                    ("stop_condition", "stop"),
                ):
                    value = str(structured.get(field) or "").strip()
                    if value:
                        print(f"  {label}: {value}")
        print()
    if view["target_page"] and view["target_page"]["has_more"]:
        print(f"More target experiences: {view['target_page']['remaining']}")
        print(f"Next cursor: {view['target_page']['next_cursor']}")
        print()
    if view["knowledge_cards"]:
        print("## 已晋升知识卡（按需读正文）")
        for entry in view["knowledge_cards"]:
            maturity = f" [{entry['maturity']}]" if entry.get("maturity") else ""
            print(f"- {entry['ref']}{maturity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
