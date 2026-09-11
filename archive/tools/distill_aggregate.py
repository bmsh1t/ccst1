#!/usr/bin/env python3
"""Aggregate distill shards -> dedup -> single scored.json for ingest.

Reads all distill/shards/shard_*.json, merges candidates, dedups by
normalized card_title / knowledge_point (near-duplicate patterns from
different source reports collapse into one, merging their source_report_ids),
and writes distill/work/corpus_scored.json ready for
`tools/distill_reports.py --ingest`.
"""
from __future__ import annotations

import glob
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHARDS = REPO / "distill" / "shards"
OUT = REPO / "distill" / "work" / "corpus_scored.json"


def norm_key(text: str) -> str:
    """Normalize a title/knowledge_point for dedup keying."""
    t = (text or "").lower()
    t = re.sub(r"[^\w一-鿿]+", "", t)
    return t


def main() -> None:
    shard_files = sorted(glob.glob(str(SHARDS / "shard_*.json")))
    total_reports = 0
    total_round1 = 0
    total_worth = 0
    merged: dict[str, dict] = {}
    collisions = 0

    for sf in shard_files:
        try:
            d = json.loads(Path(sf).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            print(f"[skip] unreadable: {sf}")
            continue
        s = d.get("summary", {})
        total_reports += s.get("total", 0) or 0
        total_round1 += s.get("round1_kept", 0) or 0
        total_worth += s.get("round2_worth_skill", 0) or 0

        for c in d.get("candidates", []):
            if not isinstance(c, dict) or not c.get("worth_skill"):
                continue
            key = norm_key(c.get("card_title") or c.get("knowledge_point") or "")
            if not key:
                continue
            if key in merged:
                # Merge source report ids, keep higher value_score version.
                collisions += 1
                existing = merged[key]
                ids = set(existing.get("source_report_ids") or []) | set(c.get("source_report_ids") or [])
                if (c.get("value_score") or 0) > (existing.get("value_score") or 0):
                    merged[key] = c
                merged[key]["source_report_ids"] = sorted(ids)
            else:
                merged[key] = c

    candidates = list(merged.values())
    candidates.sort(key=lambda c: c.get("value_score", 0), reverse=True)

    out = {
        "summary": {
            "shards": len(shard_files),
            "reports_scored": total_reports,
            "round1_kept": total_round1,
            "raw_worth_skill": total_worth,
            "unique_after_dedup": len(candidates),
            "dedup_collisions": collisions,
        },
        "candidates": candidates,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out["summary"], ensure_ascii=False, indent=2))
    print(f"\nwrote {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
