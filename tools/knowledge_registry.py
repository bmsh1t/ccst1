#!/usr/bin/env python3
"""知识能力注册表的共享解析与索引边界。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - 由 requirements.txt 保证
    raise RuntimeError(
        "缺少 PyYAML；请先执行 `python3 -m pip install -r requirements.txt`"
    ) from exc


REGISTRY_RELATIVE_PATH = Path("knowledge/capabilities.yaml")


class KnowledgeRegistryError(RuntimeError):
    """注册表无法被可靠读取或索引。"""


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
