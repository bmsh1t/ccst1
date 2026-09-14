#!/usr/bin/env python3
"""Knowledge-card pull log: mechanical record of card usage during hunts.

Outbound-governance telemetry (2026-09-14): the promote gate controls what
enters the card library; this module records what actually gets used, so
``/kb review`` can show never-recalled cards for the three-question audit.

Records are bare mechanical facts — card id, target storage key, timestamp,
and the surface that pulled the card. Whether a pull *changed an action* is
AI judgment and stays out of the log.

File: knowledge/pull-log.jsonl (one JSON object per line, append-only under
flock). Safe to commit: no PII, no evidence content, only ids and timestamps.
"""

from __future__ import annotations

import fcntl
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PULL_LOG_RELATIVE = Path("knowledge") / "pull-log.jsonl"


def pull_log_path(repo_root: Path | str) -> Path:
    return Path(repo_root) / PULL_LOG_RELATIVE


def record_pull(
    repo_root: Path | str,
    *,
    card: str,
    target: str = "",
    source: str = "",
) -> bool:
    """Append one pull event. Never raises: telemetry must not interrupt the
    hunting path. Returns True when the event landed on disk."""
    if not str(card or "").strip():
        return False
    event = {
        "card": str(card).strip(),
        "target": str(target or "").strip(),
        "source": str(source or "").strip(),
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path = pull_log_path(repo_root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
                handle.flush()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return True
    except OSError:
        return False


def pull_stats(repo_root: Path | str) -> dict[str, dict[str, Any]]:
    """Aggregate pull counts per card: {"card-id": {"pulls": N, "last_pull": ts}}.

    A missing or unreadable log yields an empty dict (no cards pulled yet),
    never an error — review must work on a fresh clone.
    """
    path = pull_log_path(repo_root)
    stats: dict[str, dict[str, Any]] = {}
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                card = str(event.get("card") or "").strip()
                if not card:
                    continue
                entry = stats.setdefault(card, {"pulls": 0, "last_pull": ""})
                entry["pulls"] += 1
                ts = str(event.get("ts") or "")
                if ts > entry["last_pull"]:
                    entry["last_pull"] = ts
    except OSError:
        return {}
    return stats


def main(argv: list[str] | None = None) -> int:
    """薄 CLI：record 一条 kb-card-read 拉取（配合原生 Read 使用）。

    契约：先 Read `knowledge/cards/<slug>.md`（原生能力），再用本命令记
    遥测——不为计数绕开原生 Read。验证卡文件存在，不存在拒绝记录
    （防笔误污染出库数据）。
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="knowledge_pull_log.py",
        description="Record one knowledge-card pull (source=kb-card-read) after a native Read.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_record = sub.add_parser("record", help="record one card read")
    p_record.add_argument("--card", required=True, help="card slug")
    p_record.add_argument("--target", default="", help="current target storage key")
    p_record.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args(argv)

    if args.cmd == "record":
        slug = args.card.strip()
        if slug.endswith(".md"):
            slug = slug[:-3]
        card_path = Path(args.repo_root) / "knowledge" / "cards" / f"{slug}.md"
        if not card_path.is_file():
            raise SystemExit(f"knowledge_pull_log: no such card: {card_path}")
        record_pull(args.repo_root, card=slug, target=args.target, source="kb-card-read")
        return 0
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
