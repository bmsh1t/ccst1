#!/usr/bin/env python3
"""统一经验读入口（2026-09-12 记忆复核顺序 2 第一步）。

经验散在 11+ 个目标的 target memory、patterns.jsonl 和知识卡里，Claude
想用历史经验时得先猜读哪个文件。本工具把跨来源经验聚合成一个 Claude
可读的视图：这是"形成→召回→复用→巩固"闭环的召回端。

规模判断（当前 177 条情节）：聚合视图 + Claude 原生语义判断足够；向量
索引等跨目标条目超过 ~500 或视图超预算时再启动（架构契约
memory-contract 的"以真实规模决定"原则）。

目标隔离（评审硬边界）：默认只返回当前目标 + 已晋升跨目标经验；
其他目标的私有情节（leads/handoff）绝不因"召回不足"混入。

查询是 Claude 侧语义判断的辅助过滤：--query 做词项交集粗筛（缩小视图），
相关性判断由 Claude 读聚合结果完成，不在本工具里模拟语义检索。
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


# 每类条目的默认上限：聚合视图是工作集压缩的读形态，不是全量 dump
DEFAULT_LIMITS = {
    "lead": 5,
    "dead_end": 5,
    "useful_pattern": 5,
    "next_action": 3,
    "pattern_db": 10,
    "knowledge_card": 10,
}

_KIND_TO_FIELD = {
    "lead": "active_leads",
    "dead_end": "dead_ends",
    "useful_pattern": "useful_patterns",
    "next_action": "next_actions",
}


def _tokenize(text: str) -> set[str]:
    return {
        token.lower()
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}|[一-鿿]+", str(text or ""))
    }


def _entry_text(entry: dict) -> str:
    """Normalize entry text: plain string, dict, or legacy stringified dict."""
    text = entry.get("text", "")
    if isinstance(text, dict):
        return str(text.get("text", "") or "")
    raw = str(text or "")
    # 历史写入方曾把 dict 的 repr 存成 text（"{'schema_version': 1, ...}"）。
    # 提取内层 'text': '...' 的值；解析失败保持原文。
    if raw.startswith("{'") and "'text': '" in raw:
        try:
            parsed = ast.literal_eval(raw)
            if isinstance(parsed, dict):
                return str(parsed.get("text", "") or raw)
        except (ValueError, SyntaxError):
            pass
    return raw


def _entry_matches(entry: dict, query_tokens: set[str]) -> bool:
    """词项粗筛：文本 + structured 假设全字段并集命中任一 token。"""
    if not query_tokens:
        return True
    haystack = _entry_text(entry)
    structured = entry.get("structured")
    if isinstance(structured, dict):
        haystack += " " + " ".join(str(v) for v in structured.values() if v)
    return bool(_tokenize(haystack) & query_tokens)


def _load_target_memory(repo_root: Path, target: str) -> dict:
    path = repo_root / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _collect_target_entries(
    repo_root: Path, target: str, kinds: list[str], query_tokens: set[str]
) -> list[dict]:
    memory = _load_target_memory(repo_root, target)
    entries: list[dict] = []
    for kind in kinds:
        field = _KIND_TO_FIELD.get(kind)
        if not field:
            continue
        matched = [
            entry for entry in memory.get(field, [])
            if isinstance(entry, dict) and _entry_matches(entry, query_tokens)
        ]
        # 最近优先（列表本身按时间追加，尾部最新）；同文去重（dict 形态与
        # 纯文本形态可能记录同一事件）
        seen_texts: set[str] = set()
        for entry in reversed(matched):
            text = _entry_text(entry)
            if not text or text in seen_texts:
                continue
            seen_texts.add(text)
            if len([e for e in entries if e["kind"] == kind]) >= DEFAULT_LIMITS[kind]:
                break
            structured = entry.get("structured") if isinstance(entry.get("structured"), dict) else None
            entries.append({
                "kind": kind,
                "target": target,
                "ts": entry.get("ts", ""),
                "text": text,
                "entry_id": entry.get("entry_id", ""),
                "evidence_refs": entry.get("evidence_refs", []),
                "structured": structured,
            })
    return entries


def _collect_pattern_db(repo_root: Path, target: str, query_tokens: set[str]) -> list[dict]:
    """PatternDB 经验：默认当前目标 + 全部跨目标（含三类 outcome）。

    patterns.jsonl 的条目本来就是脱敏技术经验（无目标私有 payload），
    跨目标复用是它存在的目的；false-positive/no-signal 带 outcome 标记，
    Claude 自行判断参考价值。
    """
    path = repo_root / "hunt-memory" / "patterns.jsonl"
    if not path.is_file():
        return []
    rows: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in reversed(lines):  # 最新在前
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        # 当前目标的条目与跨目标经验都收；查询粗筛对 technique/notes/tags 生效
        haystack = " ".join(str(row.get(k, "") or "") for k in ("technique", "notes", "vuln_class"))
        haystack += " " + " ".join(str(t) for t in row.get("tags", []))
        if query_tokens and not (_tokenize(haystack) & query_tokens):
            continue
        rows.append({
            "kind": "pattern_db",
            "target": row.get("target", ""),
            "ts": row.get("ts", ""),
            "text": f"{row.get('technique', '')} [{row.get('vuln_class', '')}]"
                    + (f" (outcome={row['outcome']})" if row.get("outcome") else "")
                    + (f" payout={row['payout']}" if row.get("payout") else ""),
            "tech_stack": row.get("tech_stack", []),
            "entry_id": f"{row.get('target', '')}|{row.get('vuln_class', '')}|{row.get('technique', '')}",
        })
        if len(rows) >= DEFAULT_LIMITS["pattern_db"]:
            break
    return rows


def _collect_knowledge_cards(repo_root: Path, query_tokens: set[str]) -> list[dict]:
    """已晋升跨目标知识卡：按 trigger_tags/id 粗筛，正文由 Claude 按引用展开。"""
    cards_dir = repo_root / "knowledge" / "cards"
    if not cards_dir.is_dir():
        return []
    entries: list[dict] = []
    for card_path in sorted(cards_dir.glob("*.md")):
        try:
            text = card_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not text.startswith("---"):
            continue
        # 只取 frontmatter 的轻量字段做粗筛，不解析全文
        frontmatter = text.split("---", 2)[1] if text.count("---") >= 2 else ""
        head = frontmatter + "\n" + card_path.stem.replace("-", " ")
        if query_tokens and not (_tokenize(head) & query_tokens):
            continue
        maturity = ""
        maturity_match = re.search(r"^maturity:\s*(\S+)", frontmatter, re.M)
        if maturity_match:
            maturity = maturity_match.group(1)
        entries.append({
            "kind": "knowledge_card",
            "target": "",  # 跨目标
            "ts": "",
            "text": card_path.stem,
            "ref": f"knowledge/cards/{card_path.name}",
            "maturity": maturity,
        })
        if len(entries) >= DEFAULT_LIMITS["knowledge_card"]:
            break
    return entries


def build_recall_view(
    repo_root: Path,
    *,
    target: str,
    query: str = "",
    kinds: list[str] | None = None,
) -> dict[str, Any]:
    """Aggregate one Claude-readable recall view across experience sources."""
    canonical = canonical_target_value(target)
    query_tokens = _tokenize(query) if query else set()
    selected_kinds = kinds or list(_KIND_TO_FIELD) + ["pattern_db", "knowledge_card"]

    target_entries = _collect_target_entries(repo_root, canonical, selected_kinds, query_tokens)
    pattern_entries = (
        _collect_pattern_db(repo_root, canonical, query_tokens)
        if "pattern_db" in selected_kinds else []
    )
    card_entries = (
        _collect_knowledge_cards(repo_root, query_tokens)
        if "knowledge_card" in selected_kinds else []
    )

    return {
        "schema_version": 1,
        "target": canonical,
        "query": query,
        "isolation": {
            "rule": "current-target episodes + promoted cross-target knowledge only; "
                    "other targets' private episodes never included",
            "cross_target_sources": ["patterns.jsonl (sanitized techniques)", "knowledge/cards"],
        },
        "counts": {
            "target_entries": len(target_entries),
            "pattern_db": len(pattern_entries),
            "knowledge_cards": len(card_entries),
        },
        "target_entries": target_entries,
        "pattern_db": pattern_entries,
        "knowledge_cards": card_entries,
        "note": (
            "query 是词项粗筛，相关性判断由 Claude 完成。情节 evidence_refs/structured "
            "按引用展开原始证据；知识卡只列引用，正文按需读取。"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate one recall view across target memory, patterns, and knowledge cards."
    )
    parser.add_argument("--target", required=True, help="current target (isolation anchor)")
    parser.add_argument("--query", default="", help="optional coarse token filter")
    parser.add_argument(
        "--kind", action="append", default=[],
        choices=["lead", "dead_end", "useful_pattern", "next_action", "pattern_db", "knowledge_card"],
        help="restrict to specific kinds (repeatable)",
    )
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    view = build_recall_view(
        Path(args.repo_root),
        target=args.target,
        query=args.query,
        kinds=args.kind or None,
    )
    if args.json:
        print(json.dumps(view, ensure_ascii=False, indent=2))
        return 0

    # 人类可读形态（Claude 默认读这个）
    print(f"# Experience recall — {view['target']}"
          + (f" (query: {view['query']})" if view["query"] else ""))
    print()
    if view["target_entries"]:
        print("## 当前目标经验")
        for entry in view["target_entries"]:
            ts = entry.get("ts", "")[:10]
            entry_id = f" [{entry['entry_id']}]" if entry.get("entry_id") else ""
            print(f"- ({entry['kind']} {ts}){entry_id} {entry['text']}")
            if entry.get("evidence_refs"):
                print(f"  evidence: {', '.join(entry['evidence_refs'][:3])}")
        print()
    if view["pattern_db"]:
        print("## 跨目标技术经验（PatternDB）")
        for entry in view["pattern_db"]:
            stack = ",".join(entry.get("tech_stack", [])[:4])
            print(f"- [{entry['target']}] {entry['text']}" + (f" (stack: {stack})" if stack else ""))
        print()
    if view["knowledge_cards"]:
        print("## 已晋升知识卡（按需读正文）")
        for entry in view["knowledge_cards"]:
            maturity = f" [{entry['maturity']}]" if entry.get("maturity") else ""
            print(f"- {entry['ref']}{maturity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
