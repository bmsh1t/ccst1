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
    """已晋升跨目标知识卡：按 trigger_tags/id 粗筛，正文由 Claude 按引用展开。

    准入走正式登记边界（审计 F5）：只有 registry（capabilities.yaml）里
    登记的卡才算"已晋升、已审核"——目录位置不是与 registry 并列的第二
    准入来源。未登记的 cards/*.md（晋升中途残留、手工放置）不进召回，
    它们要么走 knowledge_promote 完成登记，要么留在 candidates/。
    """
    try:
        from tools.knowledge_registry import KnowledgeRegistryError, load_registry, parse_knowledge_document
    except ImportError:  # pragma: no cover - direct tools/ execution
        from knowledge_registry import KnowledgeRegistryError, load_registry, parse_knowledge_document  # type: ignore

    try:
        registry = load_registry(repo_root)
        registered_paths = registry.card_paths()
    except (KnowledgeRegistryError, UnicodeError) as exc:
        return [], {"status": "unavailable", "error": " ".join(str(exc).split())[:240]}
    entries: list[dict] = []
    errors = []
    for card_id, rel_path in sorted(registered_paths.items()):
        card_path = repo_root / rel_path
        try:
            text = card_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append({"ref": rel_path, "error": type(exc).__name__})
            continue
        parsed = parse_knowledge_document(text)
        if parsed.frontmatter_error:
            errors.append({"ref": rel_path, "error": "invalid frontmatter"})
            continue
        metadata = parsed.metadata if isinstance(parsed.metadata, dict) else {}
        # 只取 frontmatter 的轻量字段做粗筛，不解析全文
        head = " ".join(
            str(item) for item in (metadata.get("trigger_tags") or [])
        ) + "\n" + card_path.stem.replace("-", " ")
        if query_tokens and not (_tokenize(head) & query_tokens):
            continue
        maturity = str(metadata.get("maturity") or "")
        entries.append({
            "kind": "knowledge_card",
            "target": "",  # 跨目标
            "ts": "",
            "text": card_path.stem,
            "ref": rel_path,
            "maturity": maturity,
        })
    # Inspect every registered card so a full window cannot hide later errors.
    return entries[:KNOWLEDGE_CARD_LIMIT], {
        "status": "partial" if errors else "ready",
        "invalid_count": len(errors), "errors": errors[:5],
        "registered_count": len(registered_paths),
        "matched_count": len(entries),
        "remaining": max(0, len(entries) - KNOWLEDGE_CARD_LIMIT),
        "order": "card_id",
        "filter": "keyword_only" if query_tokens else "none",
        "catalog_ref": str((repo_root / "knowledge" / "capabilities.yaml").resolve()),
    }


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
    canonical = canonical_target_value(target)
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

    return {
        "schema_version": 1,
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


def main(argv: list[str] | None = None) -> int:
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
