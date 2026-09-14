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


def _scrub_identity_value(value: Any) -> str:
    """身份值脱敏：字符串身份（email/用户名）哈希化，数字/布尔原样。

    digest 的消费者只需要"两个 actor 不同"的区分度，不需要身份原文
    （docstring 红线：不含 token/email）。非数字身份一律走短哈希——
    保持可对比性（同 id 同哈希）的同时不把 email/用户名写进知识目录。
    """
    text = str(value).strip()
    if not text:
        return ""
    if isinstance(value, (int, float)) or (isinstance(value, str) and text.isdigit()):
        return text
    return "hash:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _scrub_path_tokens(path: str) -> str:
    """路径段脱敏：像 token/secret 的段替换为占位符。

    判据是形态不是字典：命中敏感参数名（含 reset/verify/auth 场景词），
    或段呈现高熵形态（≥12 混合字符类，或 ≥20 纯字母长串——纯字母
    token 同样可携带凭据，2026-09-14 二轮审计负例）。数字段（对象 ID）
    保留——它们是 IDOR 分析的事实本体，不是凭据。发布边界原则：未命中
    形态正则不等于可以公开，对可疑段保守处理。
    """
    import re

    TOKEN_PARAM = re.compile(
        r"(token|secret|key|password|signature|nonce|session|jwt|otp|code|reset|verify|auth)",
        re.IGNORECASE,
    )
    MIXED_RANDOM = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{12,}$")
    # 字母开头的长标识符（含下划线/连字符 token 形态）；19+ 避免误伤
    # reset/verify 这类场景词段本身（它们是路由词不是凭据值）。
    LONG_ALPHA = re.compile(r"^[A-Za-z][A-Za-z_-]{14,}$")
    segs = []
    for seg in path.split("/"):
        if not seg:
            segs.append(seg)
            continue
        if TOKEN_PARAM.search(seg) and (MIXED_RANDOM.match(seg) or LONG_ALPHA.match(seg)):
            segs.append(f"<{TOKEN_PARAM.search(seg).group(1).lower()}-redacted>")
        elif MIXED_RANDOM.match(seg) and not seg.isdigit():
            segs.append("<opaque-redacted>")
        else:
            segs.append(seg)
    return "/".join(segs)


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
        ident = _scrub_identity_value(ident)
        # role 是权限角色名（customer/admin），不是个人身份——保留短纯字母角色
        # 保持"低权 vs 高权"对比度；只对长/混合角色串（可能携带身份）脱敏。
        role_text = str(role).strip() if role is not None else ""
        if role_text and not (role_text.isalnum() or set(role_text) <= set("abcdefghijklmnopqrstuvwxyz-")) or len(role_text) > 24:
            role_text = _scrub_identity_value(role_text)
        return f"id={ident} role={role_text}" if role_text else f"id={ident}"
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
        "path": _scrub_path_tokens(parsed.path or url),
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
    """写一条 digest；已存在且内容一致则幂等复用。返回 (path, created)。

    digest 身份守卫（2026-09-14 审计）：ref 本身已是一个合法 digest 时，
    复用原文件——不得把它当 raw probe 重新提取（promote 二次运行会把
    已有摘要的 facts 覆盖成空值并形成 raw_path 自引用）。
    """
    try:
        from tools.target_paths import target_storage_key
    except ImportError:  # pragma: no cover
        sys.path.insert(0, str(BASE_DIR))
        from target_paths import target_storage_key  # type: ignore

    ref_path = Path(ref)
    if ref_path.suffix == ".json" and "distill-digests" in ref_path.parts:
        existing = Path(repo_root) / ref if not ref_path.is_absolute() else ref_path
        if existing.is_file():
            try:
                payload = json.loads(existing.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict) and payload.get("kind") == "distill-digest":
                return existing, False  # 已是合法 digest：复用，不重提取

    digest_path = digest_path_for(repo_root, target_storage_key(target), ref)
    # 源=目的守卫：ref 解析出的目标路径就是自身时拒绝（防自引用破坏）。
    try:
        if Path(digest_path) == (Path(repo_root) / ref if not Path(ref).is_absolute() else Path(ref)):
            raise SystemExit(
                f"digest: refusing to rewrite {ref} onto itself — pass the raw probe, "
                "not an already-generated digest"
            )
    except OSError:
        pass
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
            # 重写 frontmatter：按条目当前 refs 内容（raw 路径指纹）定位，
            # 而非只按 target——同 target 的两个条目各自持有不同 raw 引用，
            # 只按 target 会让两个 ref 都改到第一个条目（2026-09-14 二轮审计）。
            # 找不到匹配条目时中止（不静默留下 raw 引用与 digest 不一致）。
            if not _rewrite_ref_entry(lines, closing, target, new_paths, raw_refs=[r for r in refs_blob.split(";") if r.strip()]):
                raise SystemExit(
                    f"digest: no matching target-evidence entry for target={target} "
                    f"(raw refs {[r for r in refs_blob.split(';') if r.strip()]}) "
                    f"in {card.name}; refusing to leave refs inconsistent"
                )

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


def _rewrite_ref_entry(lines: list[str], closing: int, target: str, new_paths: list[str],
                       raw_refs: list[str] | None = None) -> bool:
    """在该条目自身的 frontmatter 块内重写 refs。

    定位规则（2026-09-14 审计修复 + 二轮）：条目以 `type: target-evidence`
    开始，其 `target:` 匹配当前 ref 的 target；**当同一 target 有多个条目时，
    进一步用条目当前 refs 内容匹配 raw 路径指纹**——只按 target 定位会让同
    target 的两个条目都被改到第一个（一轮跨 target 错配，二轮同 target 错配）。
    raw_refs 为空时退化为纯 target 匹配（兼容单条目卡）。
    内联 `refs: [...]` 与列表 `refs:\n  - ...` 两种合法 YAML 都支持。
    返回是否重写；未找到匹配条目时返回 False（调用方据此报错，不静默）。
    """
    import re

    inline = re.compile(r"^(\s*refs:\s*)\[.*\]\s*$")
    list_first = re.compile(r"^(\s*refs:\s*)$")
    entry_type = re.compile(r"^\s*-?\s*type:\s*target-evidence\s*$")
    next_entry = re.compile(r"^\s*-\s+type:")
    target_line = re.compile(r"^\s*target:\s*(\S+)\s*$")  # 值可带 YAML 引号，匹配前剥掉

    for index in range(1, closing):
        if not entry_type.match(lines[index]):
            continue
        # 扫描该条目范围：到下一个 `- type:` 条目或 frontmatter 结束
        entry_end = closing
        for scan in range(index + 1, closing):
            if next_entry.match(lines[scan]):
                entry_end = scan
                break
        entry_target = ""
        entry_refs_text = ""
        for scan in range(index + 1, entry_end):
            m = target_line.match(lines[scan])
            if m and not entry_target:
                entry_target = m.group(1).strip("\"'")
                continue
            if "refs:" in lines[scan]:
                entry_refs_text = "".join(lines[scan:entry_end])
        if entry_target != target:
            continue
        # 同 target 多条目：条目 refs 内容必须含本轮 raw 引用之一才可改写
        if raw_refs and not any(raw in entry_refs_text for raw in raw_refs):
            continue
        joined = json.dumps(new_paths, ensure_ascii=False)
        for scan in range(index + 1, entry_end):
            m = inline.match(lines[scan])
            if m:
                lines[scan] = f"{m.group(1)}{joined}\n"
                return True
            if list_first.match(lines[scan]):
                # 列表形态：替换本行与其后的列表项
                tail = scan + 1
                while tail < entry_end and re.match(r"^\s+-\s", lines[tail]):
                    tail += 1
                indent = re.match(r"^(\s*)", lines[scan]).group(1)
                new_block = [lines[scan].rstrip("\n") + "\n"]
                for p in new_paths:
                    new_block.append(f"{indent}  - {json.dumps(p, ensure_ascii=False)}\n")
                lines[scan:tail] = new_block
                return True
    return False


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
