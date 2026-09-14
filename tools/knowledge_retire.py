#!/usr/bin/env python3
"""知识卡退役：registry status active -> retired（原子、必填理由、可撤销）。

出库治理（2026-09-14）的执行端：/kb review 出事实清单 + AI 三问判定
建议，人裁决后用本工具落 retire。卡文件保留在 knowledge/cards/（git
历史即审计）；Pack 可见性由 knowledge_registry.card_paths 的
include_retired=False 默认过滤自动收敛。

不引入第二状态机：状态就住在 capabilities.yaml 真源，audit 认识它。

用法：
  python3 tools/knowledge_retire.py --id <slug> --reason "<三问结论>"
  python3 tools/knowledge_retire.py --id <slug> --unretire
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.knowledge_registry import KnowledgeRegistryError, load_registry
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_registry import KnowledgeRegistryError, load_registry  # type: ignore

REGISTRY_RELATIVE = Path("knowledge") / "capabilities.yaml"


def _registry_path(repo_root: Path | str) -> Path:
    return Path(repo_root) / REGISTRY_RELATIVE


def _entry_block_range(text: str, card_id: str) -> tuple[int, int] | None:
    """Locate the `  - id: <card_id>` block's (start, end) line range.

    Block ends at the next `  - ` entry or a non-indented line. Returns
    0-based (start_line, end_line_exclusive).
    """
    lines = text.splitlines(keepends=True)
    start = None
    for i, line in enumerate(lines):
        if line.rstrip("\n") == f"  - id: {card_id}":
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        stripped = lines[j].rstrip("\n")
        if stripped.startswith("  - ") or (stripped and not stripped.startswith(" ")):
            end = j
            break
    return start, end


def _apply_status(
    repo_root: Path | str,
    *,
    card_id: str,
    status: str,
    reason: str,
) -> dict:
    card_id = str(card_id or "").strip()
    if not card_id:
        raise SystemExit("knowledge_retire: --id must be a card id")
    registry_path = _registry_path(repo_root)
    if not registry_path.is_file():
        raise SystemExit(f"knowledge_retire: registry not found: {registry_path}")

    # Validate against the real registry owner before any write: the card
    # must exist and (for retire) be a known kind=card entry.
    try:
        registry = load_registry(repo_root)
    except (KnowledgeRegistryError, Exception) as exc:  # noqa: BLE001 - atomic guard
        raise SystemExit(f"knowledge_retire: registry unreadable (nothing written): {exc}") from exc
    all_cards = registry.card_paths(include_retired=True)
    if card_id not in all_cards:
        raise SystemExit(f"knowledge_retire: unknown card id: {card_id}")

    text = registry_path.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    block = _entry_block_range(text, card_id)
    if block is None:
        raise SystemExit(f"knowledge_retire: registry block not found for {card_id} (nothing written)")
    start, end = block
    lines = text.splitlines(keepends=True)
    block_lines = lines[start:end]

    # Idempotent short-circuit: already in the target state.
    status_re = re.compile(r"^(\s*)status:\s*\S+\s*$")
    has_status = any(status_re.match(l) for l in block_lines)
    current = ""
    for l in block_lines:
        m = status_re.match(l)
        if m:
            current = l.split(":", 1)[1].strip()
    if current == status:
        return {"status": status, "card": card_id, "changed": False}

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_block: list[str] = []
    wrote_status = False
    for l in block_lines:
        if status_re.match(l):
            new_block.append(f"    status: {status}\n")
            wrote_status = True
        elif l.rstrip("\n").startswith("    retired_reason:") or l.rstrip("\n").startswith("    retired_at:"):
            continue  # drop previous retire annotations; rewritten below
        else:
            new_block.append(l)
    if not wrote_status:
        # Insert after the triggers block tail (or at block end).
        insert_at = len(new_block)
        for i, l in enumerate(new_block):
            if l.rstrip("\n").startswith("    triggers:"):
                # find end of triggers list
                j = i + 1
                while j < len(new_block) and (new_block[j].startswith("      - ") or new_block[j].rstrip("\n").startswith("    ")):
                    j += 1
                insert_at = j
                break
        new_block.insert(insert_at, f"    status: {status}\n")
    if status == "retired":
        new_block.append(f"    retired_at: {stamp}\n")
        # YAML-quote the reason: free text with colons/brackets would break
        # the mapping otherwise. json.dumps gives a valid YAML double-quoted
        # scalar for any content.
        new_block.append(f"    retired_reason: {json.dumps(reason, ensure_ascii=False)}\n")
    lines[start:end] = new_block
    new_text = "".join(lines)

    # Pre-write validation（2026-09-14 审计修复）：先在内存里验证新文本
    # 语义正确（registry 可解析、目标卡状态已切换），再落盘。旧顺序是
    # 先写盘再 post-write 校验——块定位被顶格注释截断时，status 行插在
    # 块外，写入后才发现卡仍 active，原文件字节已改且不恢复。
    # 探针目录：只放候选 registry（名为 capabilities.yaml），load_registry
    # 按 <root>/knowledge/capabilities.yaml 解析。
    import tempfile as _tempfile

    probe_dir: Path | None = None
    try:
        probe_dir = Path(_tempfile.mkdtemp(dir=str(registry_path.parent), prefix=".retire-probe."))
        probe_registry_dir = probe_dir / "knowledge"
        probe_registry_dir.mkdir(exist_ok=True)
        (probe_registry_dir / registry_path.name).write_text(new_text, encoding="utf-8")
        try:
            probe_registry = load_registry(probe_dir)
        except KnowledgeRegistryError as exc:
            raise SystemExit(
                f"knowledge_retire: rewritten registry unparseable (nothing written): {exc}"
            ) from exc
        probe_visible = probe_registry.card_paths()
        probe_all = probe_registry.card_paths(include_retired=True)
        if card_id not in probe_all:
            raise SystemExit(
                f"knowledge_retire: rewritten registry lost card {card_id} (nothing written) — "
                "entry block is likely cut by a top-level comment; inspect the registry manually"
            )
        if status == "retired" and card_id in probe_visible:
            raise SystemExit(
                "knowledge_retire: pre-write check failed (card still active after rewrite; "
                "nothing written) — entry block is likely cut by a top-level comment"
            )
        if status == "active" and card_id not in probe_visible:
            raise SystemExit(
                "knowledge_retire: pre-write check failed (card not active after unretire rewrite; "
                "nothing written)"
            )
    finally:
        if probe_dir is not None:
            import shutil as _shutil

            _shutil.rmtree(probe_dir, ignore_errors=True)

    # Atomic write (same envelope as knowledge_promote).
    import os
    import tempfile

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(registry_path.parent),
            prefix=f".{registry_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(new_text)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(registry_path)
    except Exception:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
        raise

    # Post-write validation: the registry must still parse and the state must
    # hold; otherwise refuse silently-corrupt success.
    try:
        reloaded = load_registry(repo_root)
        visible = reloaded.card_paths()
        if status == "retired" and card_id in visible:
            raise SystemExit("knowledge_retire: post-write check failed (card still active; registry left as written — inspect manually)")
        if status == "active" and card_id not in visible:
            raise SystemExit("knowledge_retire: post-write check failed (card not active after unretire; inspect manually)")
    except KnowledgeRegistryError as exc:
        raise SystemExit(f"knowledge_retire: post-write registry invalid: {exc}") from exc

    return {"status": status, "card": card_id, "changed": True, "retired_at": stamp if status == "retired" else ""}


def retire(repo_root: Path | str, *, card_id: str, reason: str) -> dict:
    reason = str(reason or "").strip()
    if not reason:
        raise SystemExit("knowledge_retire: --reason is required for retire (the three-question verdict)")
    return _apply_status(repo_root, card_id=card_id, status="retired", reason=reason)


def unretire(repo_root: Path | str, *, card_id: str) -> dict:
    return _apply_status(repo_root, card_id=card_id, status="active", reason="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Retire or restore one knowledge card (registry status).")
    parser.add_argument("--id", required=True, help="card id (capabilities.yaml entry id)")
    parser.add_argument("--reason", default="", help="required for retire: the three-question verdict")
    parser.add_argument("--unretire", action="store_true", help="restore a retired card to active")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.unretire:
        result = unretire(args.repo_root, card_id=args.id)
    else:
        result = retire(args.repo_root, card_id=args.id, reason=args.reason)
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        print(f"{result['card']}: {result['status']}" + ("" if result["changed"] else " (unchanged)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
