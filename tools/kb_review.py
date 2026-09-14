#!/usr/bin/env python3
"""出库治理事实清单：每张卡的 pull 遥测 + registry 元信息（只读，零判断）。

/kb review 的机械端：AI 拿这份清单做三问试金石判定，人裁决后由
tools/knowledge_retire.py 落 retire。本工具不写任何状态。

用法：
  python3 tools/kb_review.py [--limit N] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.knowledge_pull_log import pull_stats
    from tools.knowledge_registry import load_registry
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_pull_log import pull_stats  # type: ignore
    from knowledge_registry import load_registry  # type: ignore


def build_review(repo_root: Path | str, *, limit: int = 0) -> list[dict]:
    """One row per registered card (retired included), pulls=0 first.

    Facts only: card id, registry layer/load/purpose/status, card-file
    maturity (frontmatter), pull count and last pull. The three-question
    verdict is AI judgment and never lives here.
    """
    registry = load_registry(repo_root)
    stats = pull_stats(repo_root)

    rows: list[dict] = []
    for entry in registry.by_kind("card"):
        card_id = str(entry.get("id") or "").strip()
        if not card_id:
            continue
        file_path = str(entry.get("file") or "")
        maturity = ""
        full = Path(repo_root) / file_path
        if full.is_file():
            try:
                for line in full.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
                    if line.startswith("---"):
                        continue
                    if line.startswith("maturity:"):
                        maturity = line.split(":", 1)[1].strip()
                        break
                    if not line.startswith((" ", "-", "\t")) and ":" not in line:
                        break
            except OSError:
                maturity = ""
        pull = stats.get(card_id, {})
        rows.append({
            "card": card_id,
            "layer": str(entry.get("layer") or ""),
            "load": str(entry.get("load") or ""),
            "purpose": str(entry.get("purpose") or ""),
            "status": str(entry.get("status") or "active"),
            "maturity": maturity,
            "pulls": int(pull.get("pulls", 0) or 0),
            "last_pull": str(pull.get("last_pull") or ""),
        })

    # Never-pulled first (the retire-audit surface), then by pull count asc,
    # then layer, then id — deterministic display order, not a recommendation.
    rows.sort(key=lambda r: (r["pulls"], r["layer"], r["card"]))
    if limit and limit > 0:
        rows = rows[:limit]
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only card review facts: pull telemetry + registry metadata.")
    parser.add_argument("--limit", type=int, default=0, help="bound the row count (0 = all)")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rows = build_review(args.repo_root, limit=args.limit)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
    else:
        never = sum(1 for r in rows if r["pulls"] == 0)
        retired = sum(1 for r in rows if r["status"] == "retired")
        print(f"cards: {len(rows)} | never-pulled: {never} | retired: {retired}")
        print(f"{'card':44s} {'layer':12s} {'maturity':9s} {'status':8s} {'pulls':6s} last_pull")
        for r in rows:
            print(
                f"{r['card']:44s} {r['layer']:12s} {r['maturity']:9s} {r['status']:8s} "
                f"{r['pulls']:<6d} {r['last_pull']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
