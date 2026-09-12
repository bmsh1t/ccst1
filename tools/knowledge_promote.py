#!/usr/bin/env python3
"""知识卡晋升：mv + 登记 + 验收，一条命令完成。

记忆复核确认的晋升断点（2026-09-12）：
  - 46462a5 修通了 target-evidence 来源解析（draft 卡能通过 source_refs 校验）
  - 但 `mv candidates/x.md cards/` 本身仍不等于完成晋升：
    knowledge_registry.card_paths() 只从 registry 生成目录 —— 未登记的卡
    在 Pack 不可见；knowledge_audit 的 document-unregistered 是硬错误。

用法：
  python3 tools/knowledge_promote.py --id rest-numeric-id-cross-actor \
      [--layer case-router] [--load on-demand] [--purpose validate] [--triggers a,b]

不引入第二状态机：registry 追加仍走 capabilities.yaml 真源，audit 仍是
验收门。本工具只把"人工记住要改三处"变成"一条命令原子完成"。
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

try:
    from tools.knowledge_registry import load_registry
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from knowledge_registry import load_registry  # type: ignore

VALID_LAYERS = ("core", "reference", "case-router")
VALID_LOAD_MODES = ("default", "signal-or-default", "signal-only", "on-demand", "gated")


def _slug_to_id(slug: str) -> str:
    return Path(slug).stem


def _rollback(src: Path, dst: Path, registry_path: Path, original: str) -> None:
    """Restore candidate + registry after a failed promote."""
    if dst.exists():
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_bytes(dst.read_bytes())
        dst.unlink()
    registry_path.write_text(original, encoding="utf-8")


def promote(
    repo_root: Path,
    *,
    card_id: str,
    layer: str = "case-router",
    load: str = "on-demand",
    purpose: str = "validate",
    triggers: list[str] | None = None,
) -> dict:
    """Move one candidate card to cards/, register it, and verify end-to-end."""
    candidates_dir = repo_root / "knowledge" / "candidates"
    cards_dir = repo_root / "knowledge" / "cards"
    registry_path = repo_root / "knowledge" / "capabilities.yaml"

    src = candidates_dir / f"{card_id}.md"
    dst = cards_dir / f"{card_id}.md"
    if not src.is_file():
        raise SystemExit(f"candidate not found: {src}")
    if dst.exists():
        raise SystemExit(f"destination already exists: {dst}")
    if card_id != _slug_to_id(card_id):
        raise SystemExit(f"--id must be a card stem, got: {card_id!r}")
    if layer not in VALID_LAYERS:
        raise SystemExit(f"--layer must be one of {VALID_LAYERS}")
    if load not in VALID_LOAD_MODES:
        raise SystemExit(f"--load must be one of {VALID_LOAD_MODES}")

    registry = load_registry(repo_root)
    existing = registry.card_paths()
    rel_dst = f"knowledge/cards/{card_id}.md"
    if card_id in existing:
        raise SystemExit(f"id {card_id!r} already registered -> {existing[card_id]}")
    if rel_dst in set(existing.values()):
        raise SystemExit(f"file {rel_dst} already registered under another id")

    # 1) mv（draft 卡的 maturity 由人工按证据强度决定是否同步修改）
    dst.write_bytes(src.read_bytes())
    src.unlink()

    # 2) registry 追加（保持 yaml 真源；不引入第二登记状态）。
    # capabilities 是 block sequence，追加到列表末尾；yaml 不允许在同一
    # mapping 里混用缩进级别，所以直接定位最后一个 capability 条目之后。
    trigger_lines = "".join(f"\n      - {t}" for t in (triggers or [card_id]))
    entry = (
        f"  - id: {card_id}\n"
        f"    kind: card\n"
        f"    file: {rel_dst}\n"
        f"    layer: {layer}\n"
        f"    load: {load}\n"
        f"    purpose: {purpose}\n"
        f"    triggers:{trigger_lines}\n"
    )
    text = registry_path.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    import re as _re

    match = _re.search(r"(?ms)^capabilities:.*?(?=^\S|\Z)", text)
    if not match:
        raise SystemExit("capabilities.yaml has no capabilities: block to append to")
    block = match.group(0)
    if "[]" in block.split("\n")[0]:
        # flow 空列表（capabilities: []）：替换为 block 序列头再追加
        new_text = text[: match.start()] + "capabilities:\n" + entry + text[match.end():]
    elif "  - " not in block:
        # 空块序列（capabilities: 后面没有条目）
        new_text = text[: match.start()] + "capabilities:\n" + entry + text[match.end():]
    else:
        new_text = text[: match.end()] + entry + text[match.end():]
    registry_path.write_text(new_text, encoding="utf-8")
    try:
        reloaded_check = load_registry(repo_root)
    except Exception as exc:
        _rollback(src=src, dst=dst, registry_path=registry_path, original=text)
        raise SystemExit(f"registry append produced invalid yaml (rolled back): {exc}") from exc

    # 3) 验收：audit 必须通过（document-unregistered / source-refs / section 契约）。
    # audit 脚本从本仓库执行（repo 用 --repo-root 指向），tmp/只读挂载也能跑。
    audit = subprocess.run(
        [sys.executable, str(BASE_DIR / "tools" / "knowledge_audit.py"), "--strict", "--repo-root", str(repo_root)],
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    if audit.returncode != 0:
        _rollback(src=src, dst=dst, registry_path=registry_path, original=text)
        raise SystemExit(f"audit failed after promote (rolled back):\n{audit.stdout}\n{audit.stderr}")

    # 4) Pack 可发现验收：登记后的卡必须出现在目录里
    from tools.knowledge_registry import load_registry as reload
    reloaded = reload(repo_root)
    if card_id not in reloaded.card_paths():
        raise SystemExit(f"registered id {card_id!r} not discoverable in catalog")

    return {
        "promoted": card_id,
        "file": rel_dst,
        "layer": layer,
        "load": load,
        "audit": "strict-pass",
        "catalog_discoverable": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Promote one candidate card: mv + register + audit.")
    parser.add_argument("--id", required=True, help="candidate card stem (file name without .md)")
    parser.add_argument("--layer", default="case-router", choices=VALID_LAYERS)
    parser.add_argument("--load", default="on-demand", choices=VALID_LOAD_MODES)
    parser.add_argument("--purpose", default="validate")
    parser.add_argument("--triggers", default="", help="comma-separated trigger tags (default: card id)")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    import json

    result = promote(
        Path(args.repo_root),
        card_id=args.id,
        layer=args.layer,
        load=args.load,
        purpose=args.purpose,
        triggers=[t.strip() for t in args.triggers.split(",") if t.strip()] or None,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"promoted {result['promoted']} -> {result['file']} ({result['layer']}/{result['load']}); audit {result['audit']}; catalog discoverable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
