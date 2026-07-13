#!/usr/bin/env python3
"""知识能力注册表的共享解析与索引边界。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - 由 requirements.txt 保证
    raise RuntimeError(
        "缺少 PyYAML；请先执行 `python3 -m pip install -r requirements.txt`"
    ) from exc


REGISTRY_RELATIVE_PATH = Path("knowledge/capabilities.yaml")
SOURCE_REF_TYPE = "corpus-report"
SOURCE_REF_CORPUS = "hackerone-disclosed-reports"
REPORT_ID_RE = re.compile(r"^[1-9][0-9]*$")


class KnowledgeRegistryError(RuntimeError):
    """注册表无法被可靠读取或索引。"""


@dataclass(frozen=True)
class ParsedKnowledgeDocument:
    """共享 Markdown frontmatter 解码结果，供 audit 和 resolver 复用。"""

    metadata: dict[str, Any] | None
    body: str
    frontmatter_error: str | None = None


@dataclass(frozen=True)
class KnowledgeSourceRef:
    """知识卡来源的规范化 v1 记录。"""

    type: str
    corpus: str
    id: str

    def as_dict(self) -> dict[str, str]:
        return {"type": self.type, "corpus": self.corpus, "id": self.id}


def parse_knowledge_document(text: str) -> ParsedKnowledgeDocument:
    """解析知识 Markdown 的 frontmatter；格式错误由调用方按文件上下文报告。"""
    lines = text.lstrip("\ufeff").splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return ParsedKnowledgeDocument(metadata=None, body=text)
    closing = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing is None:
        return ParsedKnowledgeDocument(
            metadata=None,
            body="",
            frontmatter_error="frontmatter 缺少结束分隔符 `---`",
        )
    raw_frontmatter = "".join(lines[1:closing])
    try:
        metadata = yaml.safe_load(raw_frontmatter)
    except yaml.YAMLError as exc:
        return ParsedKnowledgeDocument(
            metadata=None,
            body="".join(lines[closing + 1 :]),
            frontmatter_error=str(exc),
        )
    if not isinstance(metadata, dict):
        return ParsedKnowledgeDocument(
            metadata=None,
            body="".join(lines[closing + 1 :]),
            frontmatter_error="frontmatter 根节点必须是映射",
        )
    return ParsedKnowledgeDocument(
        metadata=metadata,
        body="".join(lines[closing + 1 :]),
    )


def parse_source_refs(
    metadata: dict[str, Any],
    *,
    source_path: str = "<frontmatter>",
) -> tuple[KnowledgeSourceRef, ...]:
    """严格解析 card frontmatter.source_refs，集中维护来源契约。"""
    raw_refs = metadata.get("source_refs", [])
    if raw_refs is None:
        raw_refs = []
    if not isinstance(raw_refs, list):
        raise KnowledgeRegistryError(
            f"{source_path}: frontmatter.source_refs 必须是对象列表"
        )

    refs: list[KnowledgeSourceRef] = []
    seen: set[tuple[str, str, str]] = set()
    required_keys = {"type", "corpus", "id"}
    for index, raw_ref in enumerate(raw_refs):
        location = f"{source_path}: source_refs[{index}]"
        if not isinstance(raw_ref, dict):
            raise KnowledgeRegistryError(f"{location} 必须是对象")
        unknown = set(raw_ref) - required_keys
        missing = required_keys - set(raw_ref)
        if unknown:
            raise KnowledgeRegistryError(
                f"{location} 含未知字段: {sorted(unknown)}"
            )
        if missing:
            raise KnowledgeRegistryError(
                f"{location} 缺少字段: {sorted(missing)}"
            )
        ref_type = raw_ref["type"]
        corpus = raw_ref["corpus"]
        report_id = raw_ref["id"]
        if ref_type != SOURCE_REF_TYPE:
            raise KnowledgeRegistryError(
                f"{location}.type 必须为 {SOURCE_REF_TYPE!r}"
            )
        if corpus != SOURCE_REF_CORPUS:
            raise KnowledgeRegistryError(
                f"{location}.corpus 必须为 {SOURCE_REF_CORPUS!r}"
            )
        if not isinstance(report_id, str) or not REPORT_ID_RE.fullmatch(report_id):
            raise KnowledgeRegistryError(
                f"{location}.id 必须是非零十进制字符串"
            )
        identity = (ref_type, corpus, report_id)
        if identity in seen:
            raise KnowledgeRegistryError(f"{location} 与前序来源重复: {report_id}")
        seen.add(identity)
        refs.append(KnowledgeSourceRef(*identity))
    return tuple(refs)


@dataclass(frozen=True)
class KnowledgeRegistry:
    """保留原始 YAML 结构，并为可信消费者提供严格索引。"""

    path: Path
    data: dict[str, Any]

    @property
    def capabilities(self) -> tuple[dict[str, Any], ...]:
        raw = self.data.get("capabilities")
        if not isinstance(raw, list):
            raise KnowledgeRegistryError(
                f"{self.path}: `capabilities` 必须是列表"
            )
        if any(not isinstance(item, dict) for item in raw):
            raise KnowledgeRegistryError(
                f"{self.path}: 每个 capability entry 必须是映射"
            )
        return tuple(raw)

    @property
    def contracts(self) -> dict[str, Any]:
        raw = self.data.get("contracts")
        if not isinstance(raw, dict):
            raise KnowledgeRegistryError(f"{self.path}: `contracts` 必须是映射")
        return raw

    def by_kind(self, kind: str) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self.capabilities if item.get("kind") == kind)

    def card_paths(self) -> dict[str, str]:
        """返回 card ID -> repo-relative file，重复或缺失身份时 fail-fast。"""
        result: dict[str, str] = {}
        seen_files: set[str] = set()
        for item in self.by_kind("card"):
            capability_id = item.get("id")
            file_path = item.get("file")
            if not isinstance(capability_id, str) or not capability_id:
                raise KnowledgeRegistryError(f"{self.path}: card 缺少字符串 `id`")
            if not isinstance(file_path, str) or not file_path:
                raise KnowledgeRegistryError(
                    f"{self.path}: card {capability_id!r} 缺少字符串 `file`"
                )
            if capability_id in result:
                raise KnowledgeRegistryError(
                    f"{self.path}: 重复 card id {capability_id!r}"
                )
            if file_path in seen_files:
                raise KnowledgeRegistryError(
                    f"{self.path}: 重复 card file {file_path!r}"
                )
            result[capability_id] = file_path
            seen_files.add(file_path)
        return result

    def card_metadata_by_file(self) -> dict[str, dict[str, Any]]:
        """返回 card file -> 完整 registry entry。"""
        paths = self.card_paths()
        by_id = {item["id"]: item for item in self.by_kind("card")}
        return {file_path: by_id[capability_id] for capability_id, file_path in paths.items()}


def resolve_registry_path(
    repo_root: Path | str,
    *,
    fallback_root: Path | str | None = None,
) -> Path:
    """优先使用目标 repo 的 registry；仅在文件不存在时使用 fallback。"""
    primary = Path(repo_root) / REGISTRY_RELATIVE_PATH
    if primary.is_file():
        return primary
    if fallback_root is not None:
        fallback = Path(fallback_root) / REGISTRY_RELATIVE_PATH
        if fallback.is_file():
            return fallback
    raise KnowledgeRegistryError(f"找不到知识能力注册表: {primary}")


def load_registry(
    repo_root: Path | str,
    *,
    fallback_root: Path | str | None = None,
) -> KnowledgeRegistry:
    """读取完整 YAML；语法或根结构错误立即向调用方报告。"""
    path = resolve_registry_path(repo_root, fallback_root=fallback_root)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise KnowledgeRegistryError(f"无法读取知识能力注册表 {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise KnowledgeRegistryError(f"知识能力注册表 YAML 无效 {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise KnowledgeRegistryError(f"{path}: registry 根节点必须是映射")
    return KnowledgeRegistry(path=path, data=raw)


def load_card_paths(
    repo_root: Path | str,
    *,
    fallback_root: Path | str | None = None,
) -> dict[str, str]:
    return load_registry(repo_root, fallback_root=fallback_root).card_paths()


def load_card_metadata_by_file(
    repo_root: Path | str,
    *,
    fallback_root: Path | str | None = None,
) -> dict[str, dict[str, Any]]:
    return load_registry(
        repo_root,
        fallback_root=fallback_root,
    ).card_metadata_by_file()
