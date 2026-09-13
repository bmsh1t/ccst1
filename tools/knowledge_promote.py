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
import os
import subprocess
import sys
import tempfile
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


def _atomic_write_text(path: Path, content: str) -> None:
    """原子替换文本文件（tmp 同目录 + fsync + rename），中途崩溃不留半文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def _rollback(src: Path, dst: Path, registry_path: Path, original: str) -> None:
    """Restore candidate + registry after a failed promote."""
    if dst.exists():
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_bytes(dst.read_bytes())
        dst.unlink()
    _atomic_write_text(registry_path, original)


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

    # 2) registry 追加（保持 yaml 真源；不引入第二登记状态）。
    # capabilities 是 block sequence，追加到列表末尾；yaml 不允许在同一
    # mapping 里混用缩进级别，所以直接定位最后一个 capability 条目之后。
    # 原文读取和 new_text 计算都在 mv 之前完成——registry 读取异常发生在
    # 任何文件被改动前，保护圈从"无副作用"状态开始，不留 mv 后读取失败
    # 的半完成窗口。
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

    # 1) mv 进保护圈（审计 F4）：dst 复制、registry 追加、src 删除全部在
    # 同一异常恢复范围内——任何一步失败都回到 candidate + registry 原状。
    # 顺序刻意为 copy -> register -> unlink：unlink 放在 registry 写成功
    # 之后，失败点在更早阶段时 candidate 从未消失，无需"复活"逻辑。
    try:
        dst.write_bytes(src.read_bytes())
    except OSError as exc:
        # dst 可能留半份：立即清掉，candidate 未动。
        try:
            dst.unlink()
        except FileNotFoundError:
            pass
        raise SystemExit(f"card copy to cards/ failed (candidate kept): {exc}") from exc

    # 2a) registry 追加到 audit 通过为止，任何异常都必须回到
    # candidate + registry 原状——半完成态（卡已删未登记 / 已登记未审核）
    # 比失败更糟，因为 registry 消费方会直接吃进未审核知识。
    try:
        _atomic_write_text(registry_path, new_text)
        reloaded_check = load_registry(repo_root)
    except Exception as exc:
        _rollback(src=src, dst=dst, registry_path=registry_path, original=text)
        raise SystemExit(f"registry append failed (rolled back): {exc}") from exc

    # 1b) registry 写成功后才删除 candidate：此刻 cards 有卡、registry 已
    # 登记，剩下任何失败都由 _rollback 复原（含把 candidate 写回）。
    try:
        src.unlink()
    except OSError as exc:
        _rollback(src=src, dst=dst, registry_path=registry_path, original=text)
        raise SystemExit(f"candidate removal failed (rolled back): {exc}") from exc

    # 3) 验收：audit 必须通过（document-unregistered / source-refs / section 契约）。
    # audit 脚本从本仓库执行（repo 用 --repo-root 指向），tmp/只读挂载也能跑。
    try:
        audit = subprocess.run(
            [sys.executable, str(BASE_DIR / "tools" / "knowledge_audit.py"), "--strict", "--repo-root", str(repo_root)],
            capture_output=True,
            text=True,
            cwd=repo_root,
        )
    except OSError as exc:
        _rollback(src=src, dst=dst, registry_path=registry_path, original=text)
        raise SystemExit(f"audit process failed to start (rolled back): {exc}") from exc
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
