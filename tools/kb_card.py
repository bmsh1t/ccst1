#!/usr/bin/env python3
"""读取一张知识卡并记录 pull（/kb card 的机械端）。

出库遥测的第二个信号源（2026-09-14）：`selected_knowledge_refs` 记录
"卡被选为假设依据"（强信号），本命令记录"卡被主动查阅"（中信号）。
被动装载（Pack/context-pack）刻意不记——机械投喂不冒充使用信号。

用法（/kb card <name> 的契约入口）：
  python3 tools/kb_card.py --name <slug> [--target <target>] [--json]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.knowledge_pull_log import record_pull
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_pull_log import record_pull  # type: ignore

CARDS_RELATIVE = Path("knowledge") / "cards"


def read_card(repo_root: Path | str, *, name: str, target: str = "") -> str:
    """Return the card's text; every successful read records a pull.

    Raises SystemExit for unknown names — /kb card is an explicit read, so
    a miss is the operator's signal, not a silent empty result. The pull
    log itself stays best-effort (recording never blocks the read).
    """
    slug = str(name or "").strip()
    if not slug:
        raise SystemExit("kb_card: --name must be a card slug")
    if slug.endswith(".md"):
        slug = slug[:-3]
    path = Path(repo_root) / CARDS_RELATIVE / f"{slug}.md"
    if not path.is_file():
        raise SystemExit(f"kb_card: no such card: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    record_pull(repo_root, card=slug, target=target, source="kb-card-read")
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read one knowledge card and record the pull (source=kb-card-read).")
    parser.add_argument("--name", required=True, help="card slug (with or without .md)")
    parser.add_argument("--target", default="", help="current target storage key (telemetry context only)")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    args = parser.parse_args(argv)

    print(read_card(args.repo_root, name=args.name, target=args.target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
