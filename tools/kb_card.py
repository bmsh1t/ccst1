#!/usr/bin/env python3
"""可选脚本化入口：读取一张知识卡并记录 pull。

普通 /kb card 使用原生 Read，无需记录。本命令为需要一次调用读+记的
管道保留；事件只代表显式查阅，不衡量知识质量，也不覆盖所有使用。

用法：
  python3 tools/kb_card.py --name <slug> [--target <target>] [--repo-root <path>]
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
