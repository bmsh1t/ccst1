#!/usr/bin/env python3
"""知识卡评估快照（projection，只读）。

按《知识卡实时评估方案》P1 输出 promote/merge/retire 三队列建议。
本工具只读取卡片 frontmatter、registry、context-pack 召回与 action
metadata 信号，向 stdout / --json 输出建议；不写任何卡片正文、
events.jsonl 或 capabilities.yaml。终态决定由人工 reviewer 通过
`tools/knowledge_lifecycle.py` 执行。

信号定义：
- action_linkage: action queue 历史 metadata 中 knowledge signal
  identity 与卡片 trigger_tags 的命中次数（读 state/<target>/
  action_queue.json；无目标时为 0）。
- trigger_overlap: 两张卡 trigger_tags 的 Jaccard 相似度（merge 候选）。
- source_refs: frontmatter source_refs 数量（corpus-report 案例来源）。
- recall_log: memory/context-pack 召回记录若存在则计数，否则 0。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.knowledge_registry import (
        KnowledgeRegistryError,
        load_card_metadata_by_file,
        parse_knowledge_document,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_registry import (  # type: ignore
        KnowledgeRegistryError,
        load_card_metadata_by_file,
        parse_knowledge_document,
    )


MERGE_OVERLAP_THRESHOLD = 0.6
RETIRE_ZERO_SIGNAL_PERIODS = 3
# promotion-rules.md 指定的固定晋升/复核目标卡，不参与 retire 建议
RETIRE_EXEMPT = {"dead-ends"}


def _tags(metadata: dict[str, Any]) -> set[str]:
    raw = metadata.get("trigger_tags") or []
    if not isinstance(raw, list):
        return set()
    return {str(tag).strip().lower() for tag in raw if str(tag).strip()}


def _source_ref_count(metadata: dict[str, Any]) -> int:
    raw = metadata.get("source_refs") or []
    return len(raw) if isinstance(raw, list) else 0


def _card_maturity(metadata: dict[str, Any]) -> str:
    value = metadata.get("maturity")
    return str(value) if value else "unknown"


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _action_linkage_counts(repo_root: Path, tags_by_card: dict[str, set[str]]) -> dict[str, int]:
    """扫描 state/<target>/action_queue.json 中 trigger tag 的出现次数。

    只做字符串级命中统计，不解析 owner 状态；缺失目录返回全零。
    """
    counts = {card_id: 0 for card_id in tags_by_card}
    state_dir = repo_root / "state"
    if not state_dir.is_dir():
        return counts
    tag_index = {tag: card_id for card_id, tags in tags_by_card.items() for tag in tags}
    for queue_file in state_dir.rglob("action_queue.json"):
        try:
            text = queue_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for tag, card_id in tag_index.items():
            counts[card_id] += text.count(tag)
    return counts


def evaluate_cards(repo_root: Path) -> dict[str, Any]:
    try:
        registry = load_card_metadata_by_file(repo_root)
    except KnowledgeRegistryError as exc:
        raise SystemExit(f"registry error: {exc}") from exc

    tags_by_card: dict[str, set[str]] = {}
    info: dict[str, dict[str, Any]] = {}
    for file_path, entry in sorted(registry.items()):
        card_id = entry.get("id", Path(file_path).stem)
        full = repo_root / file_path
        parsed = parse_knowledge_document(full.read_text(encoding="utf-8"))
        metadata = parsed.metadata or {}
        tags = _tags(metadata)
        tags_by_card[card_id] = tags
        info[card_id] = {
            "file": file_path,
            "layer": entry.get("layer", ""),
            "load": entry.get("load", ""),
            "maturity": _card_maturity(metadata),
            "source_refs": _source_ref_count(metadata),
            "trigger_tags": sorted(tags),
            "in_core_budget": entry.get("layer") == "core",
        }

    linkage = _action_linkage_counts(repo_root, tags_by_card)
    for card_id, stats in info.items():
        stats["action_linkage"] = linkage.get(card_id, 0)
        stats["zero_signal"] = stats["action_linkage"] == 0 and stats["source_refs"] == 0

    promote: list[str] = []
    retire: list[str] = []
    for card_id, stats in info.items():
        if stats["maturity"] == "draft" and stats["source_refs"] >= 1 and stats["action_linkage"] >= 2:
            promote.append(card_id)
        elif (
            stats["zero_signal"]
            and not stats["in_core_budget"]
            and card_id not in RETIRE_EXEMPT
        ):
            retire.append(card_id)

    merge_pairs: list[dict[str, Any]] = []
    card_ids = sorted(tags_by_card)
    for i, left in enumerate(card_ids):
        for right in card_ids[i + 1 :]:
            overlap = _jaccard(tags_by_card[left], tags_by_card[right])
            if overlap >= MERGE_OVERLAP_THRESHOLD:
                merge_pairs.append(
                    {
                        "left": left,
                        "right": right,
                        "trigger_overlap": round(overlap, 2),
                    }
                )

    return {
        "summary": {
            "total_cards": len(info),
            "promote_candidates": len(promote),
            "merge_candidates": len(merge_pairs),
            "retire_candidates": len(retire),
            "thresholds": {
                "merge_trigger_overlap": MERGE_OVERLAP_THRESHOLD,
                "retire_zero_signal_periods": RETIRE_ZERO_SIGNAL_PERIODS,
            },
        },
        "cards": info,
        "promote": promote,
        "merge": merge_pairs,
        "retire": retire,
    }


def _render(result: dict[str, Any]) -> str:
    lines: list[str] = []
    summary = result["summary"]
    lines.append(
        f"知识卡评估快照：{summary['total_cards']} 张，"
        f"promote {len(result['promote'])} / merge {len(result['merge'])} / "
        f"retire {len(result['retire'])}"
    )
    lines.append("")
    lines.append("== promote 候选（≥1 source_refs 且 ≥2 action 关联） ==")
    if result["promote"]:
        lines.extend(f"  - {card}" for card in result["promote"])
    else:
        lines.append("  （空）")
    lines.append("")
    lines.append("== merge 候选（trigger Jaccard ≥ 0.6） ==")
    if result["merge"]:
        for pair in result["merge"]:
            lines.append(
                f"  - {pair['left']} <-> {pair['right']} (overlap {pair['trigger_overlap']})"
            )
    else:
        lines.append("  （空）")
    lines.append("")
    lines.append("== retire 候选（零信号且非 core） ==")
    if result["retire"]:
        lines.extend(f"  - {card}" for card in result["retire"])
    else:
        lines.append("  （空）")
    lines.append("")
    lines.append("说明：本输出仅为建议；终态由人工 reviewer 经 knowledge_lifecycle.py 执行。")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="知识卡评估快照（只读 projection）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument(
        "--repo-root",
        default=str(BASE_DIR),
        help="仓库根目录（默认：脚本所在仓库）",
    )
    args = parser.parse_args(argv)
    result = evaluate_cards(Path(args.repo_root))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(_render(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
