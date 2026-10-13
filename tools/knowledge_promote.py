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
验收门。本工具串行发布并补偿失败，不宣称多文件崩溃事务。
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

try:
    from tools.artifact_io import write_text_atomic as _atomic_write_text
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_text_atomic as _atomic_write_text


try:
    from tools.knowledge_registry import KnowledgeRegistryError, load_registry, parse_knowledge_document
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from knowledge_registry import KnowledgeRegistryError, load_registry, parse_knowledge_document  # type: ignore

if __package__ in (None, ""):
    sys.path.insert(0, str(BASE_DIR))
from tools.recall_update import (add_index_options, format_saved_result,
                                 update_saved_result, validate_index_options)


VALID_LAYERS = ("core", "reference", "case-router")
VALID_LOAD_MODES = ("default", "signal-or-default", "signal-only", "on-demand", "gated")


def _slug_to_id(slug: str) -> str:
    return Path(slug).stem


def _strict_audit(repo_root: Path) -> None:
    audit = subprocess.run(
        [sys.executable, str(BASE_DIR / "tools" / "knowledge_audit.py"), "--strict", "--repo-root", str(repo_root)],
        capture_output=True, text=True, cwd=repo_root,
    )
    if audit.returncode != 0:
        raise RuntimeError(f"audit failed after review/publication:\n{audit.stdout}\n{audit.stderr}")


def _rollback(src: Path, dst: Path, registry_path: Path, original: str,
              expected_registry: str, published: bytes | None,
              new_digests: dict[str, bytes], candidate_bytes: bytes,
              removal_attempted: bool) -> list[str]:
    """Undo only this invocation's bytes; preserve and report concurrent edits."""
    from tools.distill_digest import publish_new_text

    conflicts: list[str] = []
    registry_restored = False
    try:
        current = registry_path.read_bytes()
        if current == expected_registry.encode("utf-8"):
            _atomic_write_text(registry_path, original)
            registry_restored = True
        elif current == original.encode("utf-8"):
            registry_restored = True
        else:
            conflicts.append(f"registry changed: {registry_path}")
    except OSError as exc:
        conflicts.append(f"registry recovery failed: {exc}")
    if removal_attempted and not src.exists():
        try:
            publish_new_text(src, candidate_bytes.decode("utf-8"))
        except OSError as exc:
            conflicts.append(f"candidate recovery failed: {exc}")
    # A concurrent registry edit may still reference these artifacts. Keep them
    # for explicit reconciliation instead of leaving a dangling registered card.
    if registry_restored:
        artifacts = {dst: published} if published is not None else {}
        artifacts.update({registry_path.parent.parent / rel: data for rel, data in new_digests.items()})
        for path, expected in artifacts.items():
            try:
                if path.read_bytes() != expected:
                    conflicts.append(f"artifact changed: {path}")
                else:
                    path.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                conflicts.append(f"artifact recovery failed for {path}: {exc}")
    return conflicts


def _check_review(src: Path, card_id: str, candidate_bytes: bytes) -> tuple[dict, bytes]:
    """Keep admission in the shared knowledge review owner."""
    from tools.knowledge_review import load_review

    root = src.parent.parent.parent
    try:
        return load_review(root, src.with_suffix(".review.json").relative_to(root).as_posix(),
                           card_id, candidate_bytes)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"review unavailable or invalid: {exc}") from exc


def _publish_review(repo_root: Path, *, card_id: str, file: str, candidate: bytes,
                    publication: bytes, review_ref: str, review_bytes: bytes,
                    replaced_refs: dict, created: dict[str, bytes]) -> str:
    from tools.distill_digest import publish_new_text
    from tools.knowledge_review import (knowledge_path, load_review, publication_receipt,
                                       publication_ref, sha256)

    _, current_review = load_review(repo_root, review_ref, card_id, candidate)
    if current_review != review_bytes:
        raise ValueError("review changed before publication; retry after review")
    ref = publication_ref(card_id, sha256(publication), sha256(review_bytes))
    path = knowledge_path(repo_root, ref)
    receipt = publication_receipt(card_id=card_id, file=file, candidate=candidate,
                                  published=publication, review_ref=review_ref,
                                  review_bytes=review_bytes, replaced_refs=replaced_refs)
    text = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path.exists():
        if path.read_bytes() != text.encode("utf-8"):
            raise ValueError(f"conflicting knowledge review receipt: {ref}")
    else:
        publish_new_text(path, text)
        created[ref] = text.encode("utf-8")
    return ref


def promote(
    repo_root: Path, *, card_id: str, layer: str = "case-router",
    load: str = "on-demand", purpose: str = "validate",
    triggers: list[str] | None = None,
) -> dict:
    """Serialize publishers on the stable knowledge directory, not replaced YAML."""
    repo_root = Path(repo_root).resolve()
    descriptor = os.open(repo_root / "knowledge", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return _promote(repo_root, card_id=card_id, layer=layer, load=load,
                        purpose=purpose, triggers=triggers)
    finally:
        os.close(descriptor)


def _promote(
    repo_root: Path,
    *,
    card_id: str,
    layer: str = "case-router",
    load: str = "on-demand",
    purpose: str = "validate",
    triggers: list[str] | None = None,
) -> dict:
    """Move one candidate card to cards/, register it, and verify end-to-end."""
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", card_id):
        raise SystemExit("--id must be a lowercase hyphenated card stem")
    candidates_dir = repo_root / "knowledge" / "candidates"
    cards_dir = repo_root / "knowledge" / "cards"
    registry_path = repo_root / "knowledge" / "capabilities.yaml"

    src = candidates_dir / f"{card_id}.md"
    dst = cards_dir / f"{card_id}.md"
    from tools.knowledge_review import knowledge_path, read_published_review
    knowledge_path(repo_root, src.relative_to(repo_root).as_posix())
    knowledge_path(repo_root, dst.relative_to(repo_root).as_posix())
    knowledge_path(repo_root, "knowledge/capabilities.yaml")

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

    if layer == "case-router" and load != "on-demand":
        raise SystemExit("case-router requires load=on-demand")
    candidate_bytes = src.read_bytes()
    review, review_bytes = _check_review(src, card_id, candidate_bytes)
    parsed = parse_knowledge_document(candidate_bytes.decode("utf-8"))
    if parsed.frontmatter_error or not parsed.metadata or parsed.metadata.get("maturity") not in ("tested", "proven"):
        raise SystemExit("reviewed candidate must declare evidence-backed maturity tested/proven")

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
    original = registry_path.read_bytes().decode("utf-8")
    text = original
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

    from tools.distill_digest import migrate_card_refs, publish_new_text

    new_digests: dict[str, bytes] = {}
    published: bytes | None = None
    removal_attempted = False
    stage = "digest migration"
    try:
        if src.read_bytes() != candidate_bytes:
            raise RuntimeError("candidate changed after review; review again")
        migration = migrate_card_refs(
            repo_root, card_id, candidate_bytes=candidate_bytes,
            publish_card=False, created_digests=new_digests,
        )
        publication = migration["content"].encode("utf-8")
        if src.read_bytes() != candidate_bytes:
            raise RuntimeError("candidate changed during migration; review again")
        stage = "card copy to cards/"
        publish_new_text(dst, migration["content"])
        published = publication
        stage = "review publication"
        review_ref = src.with_suffix(".review.json").relative_to(repo_root).as_posix()
        receipt_ref = _publish_review(repo_root, card_id=card_id, file=rel_dst,
                                     candidate=candidate_bytes, publication=publication,
                                     review_ref=review_ref, review_bytes=review_bytes,
                                     replaced_refs=migration.get("replaced", {}), created=new_digests)
        new_text = new_text.replace(f"    file: {rel_dst}\n",
                                    f"    file: {rel_dst}\n    review_receipt: {receipt_ref}\n")
        stage = "registry append"
        if registry_path.read_bytes() != original.encode("utf-8"):
            raise RuntimeError("registry changed before publication; retry against current registry")
        _atomic_write_text(registry_path, new_text)
        load_registry(repo_root)
        stage = "audit"
        _strict_audit(repo_root)
        stage = "catalog validation"
        reloaded = load_registry(repo_root)
        if reloaded.card_paths().get(card_id) != rel_dst:
            raise RuntimeError(f"registered id {card_id!r} not discoverable at {rel_dst}")
        if registry_path.read_bytes() != new_text.encode("utf-8") or dst.read_bytes() != publication:
            raise RuntimeError("published card or registry changed during verification")
        for rel, expected in new_digests.items():
            if (repo_root / rel).read_bytes() != expected:
                raise RuntimeError(f"digest changed during verification: {rel}")
        review_entry = {"id": card_id, "file": rel_dst, "review_receipt": receipt_ref}
        if read_published_review(repo_root, review_entry, publication)["status"] != "ready":
            raise RuntimeError("published review became unavailable during verification")
        stage = "candidate removal"
        if src.read_bytes() != candidate_bytes:
            raise RuntimeError("candidate changed during verification; current candidate preserved")
        removal_attempted = True
        src.unlink()
    except (Exception, SystemExit) as exc:
        conflicts = _rollback(
            src, dst, registry_path, original, new_text, published,
            new_digests, candidate_bytes, removal_attempted,
        )
        recovery = "rolled back" if not conflicts else "recovery conflict; " + "; ".join(conflicts)
        raise SystemExit(f"{stage} failed ({recovery}): {exc}") from exc

    return {
        "review": {"intake_kind": review["intake_kind"], "candidate_sha256": review["candidate_sha256"]},
        "published_sha256": hashlib.sha256(publication).hexdigest(),
        "review_receipt": receipt_ref,
        "replaced_refs": migration.get("replaced", {}),
        "promoted": card_id,
        "file": rel_dst,
        "layer": layer,
        "load": load,
        "audit": "strict-pass",
        "catalog_discoverable": True,
    }


def review_existing(repo_root: Path, *, card_id: str, review_ref: str) -> dict:
    """Explicitly review current registered bytes, preserving old review receipts."""
    from tools.knowledge_review import knowledge_path, load_review, read_published_review

    repo_root = Path(repo_root).resolve()
    registry_path = knowledge_path(repo_root, "knowledge/capabilities.yaml")
    descriptor = os.open(repo_root / "knowledge", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        original = registry_path.read_text(encoding="utf-8")
        registry = load_registry(repo_root)
        entries = [e for e in registry.method_entries() if e.get("id") == card_id]
        if len(entries) != 1:
            raise ValueError("--id must identify one registered knowledge method")
        entry = entries[0]
        if entry.get("status", "active") != "active":
            raise ValueError("retired knowledge cannot be made active by review")
        path = knowledge_path(repo_root, entry["file"])
        publication = path.read_bytes()
        parsed = parse_knowledge_document(publication.decode("utf-8"))
        if (parsed.frontmatter_error or not parsed.metadata
                or parsed.metadata.get("id") != card_id
                or parsed.metadata.get("status", "active") != "active"
                or parsed.metadata.get("maturity") not in ("tested", "proven")):
            raise ValueError("existing review requires active, evidence-backed tested/proven method bytes")
        review, review_bytes = load_review(repo_root, review_ref, card_id, publication)
        if review["intake_kind"] != "existing-knowledge-review":
            raise ValueError("--review-existing requires intake_kind=existing-knowledge-review")
        # Registry owns the selected receipt; formatting edits never reinterpret YAML.
        block = re.search(r"(?m)^  - id: " + re.escape(card_id) + r"\n(?:(?:[ ]{4,}.*|[ \t]*)\n)*", original)
        if not block:
            raise ValueError("registry entry must use the canonical block style before review binding")
        created: dict[str, bytes] = {}
        expected = original
        try:
            receipt_ref = _publish_review(repo_root, card_id=card_id, file=entry["file"],
                                         candidate=publication, publication=publication,
                                         review_ref=review_ref, review_bytes=review_bytes,
                                         replaced_refs={}, created=created)
            old_block = block.group()
            new_block = re.sub(r"(?m)^    review_receipt:.*\n", "", old_block)
            first, rest = new_block.split("\n", 1)
            new_block = first + f"\n    review_receipt: {receipt_ref}\n" + rest
            expected = original[:block.start()] + new_block + original[block.end():]
            if registry_path.read_text(encoding="utf-8") != original or path.read_bytes() != publication:
                raise ValueError("knowledge changed during review; review current bytes again")
            updated_entry = {**entry, "review_receipt": receipt_ref}
            if read_published_review(repo_root, updated_entry, publication)["status"] != "ready":
                raise ValueError("review source changed before registry binding")
            if expected != original:
                _atomic_write_text(registry_path, expected)
            _strict_audit(repo_root)
            current = load_registry(repo_root)
            if not any(e == updated_entry for e in current.capabilities):
                raise ValueError("review registry binding is not discoverable")
            if (registry_path.read_text(encoding="utf-8") != expected or path.read_bytes() != publication
                    or read_published_review(repo_root, updated_entry, publication)["status"] != "ready"):
                raise ValueError("knowledge changed during review verification")
        except (Exception, SystemExit) as exc:
            conflicts = _rollback(path, path, registry_path, original, expected, None,
                                  created, publication, False)
            recovery = "rolled back" if not conflicts else "recovery conflict; " + "; ".join(conflicts)
            raise ValueError(f"existing review failed ({recovery}): {exc}") from exc
        return {"reviewed": card_id, "file": entry["file"], "review_receipt": receipt_ref,
                "published_sha256": hashlib.sha256(publication).hexdigest(),
                "catalog_discoverable": True}
    except (OSError, UnicodeError, ValueError, KnowledgeRegistryError) as exc:
        raise SystemExit(f"existing review unavailable or invalid: {exc}") from exc
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Promote one candidate card: mv + register + audit.")
    parser.add_argument("--id", required=True, help="candidate card stem (file name without .md)")
    parser.add_argument("--layer", default="case-router", choices=VALID_LAYERS)
    parser.add_argument("--load", default="on-demand", choices=VALID_LOAD_MODES)
    parser.add_argument("--purpose", default="validate")
    parser.add_argument("--triggers", default="", help="comma-separated trigger tags (default: card id)")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--review-existing", action="store_true", help="bind an explicit review to an existing registered method; do not rewrite it")
    parser.add_argument("--review-file", help="repo-relative knowledge/candidates/*.review.json for --review-existing")
    add_index_options(parser)
    args = parser.parse_args(argv)
    try:
        validate_index_options(args.update_index, args.index_encoder)
    except ValueError as exc:
        parser.error(str(exc))

    import json

    if args.review_existing != bool(args.review_file):
        parser.error("--review-existing and --review-file must be supplied together")
    if args.review_existing:
        result = review_existing(Path(args.repo_root), card_id=args.id, review_ref=args.review_file)
    else:
        result = promote(
            Path(args.repo_root), card_id=args.id, layer=args.layer, load=args.load,
            purpose=args.purpose,
            triggers=[t.strip() for t in args.triggers.split(",") if t.strip()] or None,
        )
    if args.update_index:
        result = update_saved_result(result, Path(args.repo_root), update_index=args.update_index,
                                     encoder_path=args.index_encoder, shared=True)
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else format_saved_result(result))
        return 2 if result["partial"] else 0
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"reviewed {args.id} -> {result['file']}; receipt {result['review_receipt']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
