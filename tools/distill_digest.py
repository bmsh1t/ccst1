#!/usr/bin/env python3
"""Distill digests: git-reachable, scrubbed fact summaries for card source refs.

背景（2026-09-14 可复现契约修复）：target-evidence refs 曾直接指向
gitignored 的 raw evidence（evidence/<target>/...）。git-tracked 的知识卡
引用 clone 后不存在的文件，test_knowledge_audit 在干净 clone 上必红。

digest 的边界（与 scrub 红线一致——挡的是泄露，不只是 token）：
- 只存判断可复核的最小事实：method / path / status / body_sha256 /
  body_bytes / actor 指纹 / 时间戳；
- 记录 raw_sha256 供本机原件双向校验；
- 不存 headers、不存 body——真实赏金目标的响应体可能含 PII，
  scrubbed copy 进 git 本身就是泄露事故；
- 溯源链到 digest 为止：本机有 raw 时用 sha256 校验一致，没有就到此为止。

机械生成，零判断：扫 refs -> 提事实 -> 算 sha -> 原子写文件。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

try:
    from tools.knowledge_registry import TARGET_EVIDENCE_REF_TYPE, parse_source_refs
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from knowledge_registry import TARGET_EVIDENCE_REF_TYPE, parse_source_refs  # type: ignore

DIGEST_SCHEMA_VERSION = 1
DIGEST_DIR = Path("knowledge") / "distill-digests"
# 判断可复核的最小事实字段；新增字段必须同样满足"无 headers、无 body"。
FACT_FIELDS = ("method", "path", "status", "body_sha256", "body_bytes", "actor", "ts")


def _atomic_write_text(path: Path, text: str) -> None:
    """同目录 tmp + rename（与 openapi_semantics / knowledge_promote 同形态）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
        Path(tmp_name).replace(path)
    except BaseException:
        try:
            Path(tmp_name).unlink()
        except FileNotFoundError:
            pass
        raise


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _actor_fingerprint(probe: dict[str, Any]) -> str:
    """actor 指纹：身份对比所需的最小区分信息，不含 token/email。

    juice-shop 风格 probe 的 request.headers.Authorization 是 JWT；
    解 payload 只取 id/role。解析失败返回空串——digest 不因格式
    陌生而失败，缺指纹的 digest 仍可校验（body_sha256 是主绑定）。
    """
    auth = (probe.get("request") or {}).get("headers") or {}
    token = ""
    for value in auth.values() if isinstance(auth, dict) else []:
        raw = str(value or "")
        if raw.startswith("Bearer "):
            token = raw[len("Bearer "):]
            break
    if not token:
        return ""
    try:
        import base64

        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        ident = data.get("id")
        role = data.get("role")
        if ident is None and not role:
            return ""
        return f"id={ident} role={role}" if role else f"id={ident}"
    except Exception:
        return ""


def _probe_facts(ref_path: Path, repo_root: Path) -> dict[str, Any]:
    """从一个 raw probe 文件提取最小事实。缺字段跳过，不猜。"""
    try:
        probe = json.loads(ref_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"digest: cannot read raw probe {ref_path}: {exc}") from exc
    if not isinstance(probe, dict):
        raise SystemExit(f"digest: raw probe {ref_path} is not a JSON object")
    request = probe.get("request") if isinstance(probe.get("request"), dict) else {}
    response = probe.get("response") if isinstance(probe.get("response"), dict) else {}
    url = str(request.get("url") or "")
    parsed = urlparse(url)
    return {
        "method": str(request.get("method") or ""),
        "path": parsed.path or url,
        "status": response.get("status"),
        "body_sha256": str(response.get("body_sha256") or ""),
        "body_bytes": response.get("body_retained_bytes")
        if isinstance(response.get("body_retained_bytes"), int)
        else response.get("body_length"),
        "actor": _actor_fingerprint(probe),
        "ts": str(probe.get("ts") or ""),
    }


def digest_path_for(repo_root: Path, target_key: str, ref: str) -> Path:
    """digest 路径：<digest_dir>/<safe-key>/<ref-basename>.json（按 raw 一一对应）。

    目录名做文件系统安全化（: / 等替换为 _）：target key 可能含端口冒号。
    """
    safe_key = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in target_key)
    stem = Path(ref).stem if ref.endswith(".json") else Path(ref).name
    return repo_root / DIGEST_DIR / safe_key / f"{stem}.json"


def build_digest(repo_root: Path, target: str, ref: str) -> dict[str, Any]:
    """为一条 target-evidence ref 构建脱敏 digest payload。"""
    ref_path = repo_root / ref
    if not ref_path.is_file():
        raise SystemExit(f"digest: raw evidence not found: {ref}")
    facts = _probe_facts(ref_path, repo_root)
    return {
        "schema_version": DIGEST_SCHEMA_VERSION,
        "kind": "distill-digest",
        "target": target,
        "raw_path": ref,
        "raw_sha256": _sha256_of(ref_path),
        "facts": {key: facts[key] for key in FACT_FIELDS},
        "note": "scrubbed fact digest; no headers/bodies. Verify locally with raw_sha256 when raw evidence exists.",
    }


def write_digest(repo_root: Path, target: str, ref: str) -> tuple[Path, bool]:
    """写一条 digest；已存在且内容一致则幂等复用。返回 (path, created)。"""
    try:
        from tools.target_paths import target_storage_key
    except ImportError:  # pragma: no cover
        sys.path.insert(0, str(BASE_DIR))
        from target_paths import target_storage_key  # type: ignore
    digest_path = digest_path_for(repo_root, target_storage_key(target), ref)
    payload = build_digest(repo_root, target, ref)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if digest_path.is_file() and digest_path.read_text(encoding="utf-8") == text:
        return digest_path, False
    _atomic_write_text(digest_path, text)
    return digest_path, True


def migrate_card_refs(repo_root: Path, card_id: str) -> dict[str, Any]:
    """把一张候选/正式卡的 target-evidence refs 迁移到 digest 引用。

    机械变换（与 registry 登记同类，非判断替代）：
    - frontmatter refs: raw 路径 -> digest 仓库相对路径；
    - 正文"原始证据"列表行同步替换，避免 frontmatter/body 分裂；
    - 每条 raw 生成 digest，返回新建文件清单供回滚。
    """
    for cards_dir in (repo_root / "knowledge" / "candidates", repo_root / "knowledge" / "cards"):
        card = cards_dir / f"{card_id}.md"
        if card.is_file():
            break
    else:
        raise SystemExit(f"digest: card not found: {card_id}")

    text = card.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    # frontmatter
    if not lines or lines[0].strip() != "---":
        raise SystemExit(f"digest: card has no frontmatter: {card}")
    closing = next(
        (i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing is None:
        raise SystemExit(f"digest: card frontmatter unterminated: {card}")

    try:
        import yaml

        metadata = yaml.safe_load("".join(lines[1:closing])) or {}
    except Exception as exc:  # pragma: no cover - malformed frontmatter
        raise SystemExit(f"digest: card frontmatter unparseable: {exc}") from exc

    try:
        refs = parse_source_refs(metadata, source_path=str(card))
    except Exception as exc:
        raise SystemExit(f"digest: source_refs invalid: {exc}") from exc

    created: list[str] = []
    replaced: dict[str, str] = {}
    try:
        from tools.target_paths import target_storage_key
    except ImportError:  # pragma: no cover
        sys.path.insert(0, str(BASE_DIR))
        from target_paths import target_storage_key  # type: ignore

    for ref in refs:
        if ref.type != TARGET_EVIDENCE_REF_TYPE:
            continue
        target, _, refs_blob = ref.id.partition("|")
        if not target or not refs_blob:
            continue
        new_paths: list[str] = []
        for raw_ref in [part.strip() for part in refs_blob.split(";") if part.strip()]:
            digest_path, was_created = write_digest(repo_root, target, raw_ref)
            rel = digest_path.relative_to(repo_root).as_posix()
            new_paths.append(rel)
            if was_created:
                created.append(rel)
            replaced[raw_ref] = rel
        if new_paths:
            ref_key = f"{target}|{';'.join(new_paths)}"
            # 重写 frontmatter：定位该 source_refs 条目的 refs 列表
            _rewrite_ref_entry(lines, closing, target, new_paths)

    if not replaced:
        return {"changed": False, "created": [], "card": str(card)}

    # 正文"原始证据"行同步替换（同一引用的人读版）
    for index, line in enumerate(lines):
        stripped = line.strip().lstrip("- ").strip("`")
        if stripped in replaced:
            lines[index] = line.replace(stripped, replaced[stripped])
    new_text = "".join(lines)
    _atomic_write_text(card, new_text)
    return {"changed": True, "created": created, "card": str(card), "replaced": replaced}


def _rewrite_ref_entry(lines: list[str], closing: int, target: str, new_paths: list[str]) -> None:
    """在 frontmatter 行列表内把 target-evidence 的 refs 列表替换为 digest 路径。"""
    import re

    pattern = re.compile(r"^(\s*refs:\s*)\[.*\]\s*$")
    for index in range(1, closing):
        line = lines[index]
        if "type: target-evidence" in line:
            # 从这行往后找同条目的 refs:
            for scan in range(index, min(index + 4, closing)):
                match = pattern.match(lines[scan])
                if match:
                    joined = json.dumps(new_paths, ensure_ascii=False)
                    lines[scan] = f"{match.group(1)}{joined}\n"
                    return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate scrubbed distill digests for card target-evidence refs.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_gen = sub.add_parser("generate", help="generate digests for one card's target-evidence refs and migrate its refs")
    p_gen.add_argument("--card-id", required=True)
    p_build = sub.add_parser("digest", help="build one digest for a raw evidence ref (no card rewrite)")
    p_build.add_argument("--target", required=True)
    p_build.add_argument("--ref", required=True)
    args = parser.parse_args(argv)
    repo = Path(args.repo_root)

    if args.cmd == "generate":
        result = migrate_card_refs(repo, args.card_id)
    else:
        _, created = write_digest(repo, args.target, args.ref)
        result = {"changed": created, "created": [args.ref]}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
