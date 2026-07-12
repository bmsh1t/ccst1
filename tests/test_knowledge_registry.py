"""共享知识能力注册表 parser 的行为测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from knowledge_registry import (
    KnowledgeRegistryError,
    load_card_metadata_by_file,
    load_card_paths,
    load_registry,
)


def _write_registry(root: Path, text: str) -> None:
    path = root / "knowledge" / "capabilities.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")


def _valid_registry() -> str:
    return """\
schema_version: 1
contracts:
  max_core_cards: 2
  default_cards_max: 1
  card_layers: [core, reference, case-router, payload-pack, playbook]
  load_modes: [default, signal-or-default, signal-only, on-demand, gated]
capabilities:
  - id: api-idor
    kind: card
    file: knowledge/cards/api-idor.md
    layer: core
    load: signal-or-default
    purpose: validate
    triggers: [idor]
"""


def test_registry_exposes_card_paths_and_metadata(tmp_path: Path) -> None:
    _write_registry(tmp_path, _valid_registry())

    registry = load_registry(tmp_path)

    assert registry.contracts["max_core_cards"] == 2
    assert load_card_paths(tmp_path) == {
        "api-idor": "knowledge/cards/api-idor.md"
    }
    assert load_card_metadata_by_file(tmp_path)["knowledge/cards/api-idor.md"][
        "purpose"
    ] == "validate"


def test_context_pack_card_paths_are_derived_from_registry() -> None:
    from context_pack import CARD_PATHS

    registry = load_registry(Path(__file__).resolve().parents[1])
    assert CARD_PATHS == registry.card_paths()


def test_registry_only_uses_fallback_when_primary_is_missing(tmp_path: Path) -> None:
    fallback = tmp_path / "fallback"
    primary = tmp_path / "primary"
    _write_registry(fallback, _valid_registry())

    assert load_card_paths(primary, fallback_root=fallback)["api-idor"].endswith(
        "api-idor.md"
    )

    _write_registry(primary, "capabilities: [")
    with pytest.raises(KnowledgeRegistryError, match="YAML 无效"):
        load_registry(primary, fallback_root=fallback)


def test_registry_rejects_missing_or_non_mapping_root(tmp_path: Path) -> None:
    with pytest.raises(KnowledgeRegistryError, match="找不到知识能力注册表"):
        load_registry(tmp_path)

    _write_registry(tmp_path, "- not\n- a\n- mapping\n")
    with pytest.raises(KnowledgeRegistryError, match="根节点必须是映射"):
        load_registry(tmp_path)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("api-idor", "重复 card id"),
        ("knowledge/cards/api-idor.md", "重复 card file"),
    ],
)
def test_card_index_rejects_duplicate_identity(
    tmp_path: Path,
    replacement: str,
    message: str,
) -> None:
    duplicate = _valid_registry() + f"""\
  - id: {replacement if replacement == 'api-idor' else 'second-card'}
    kind: card
    file: {replacement if replacement != 'api-idor' else 'knowledge/cards/second.md'}
    layer: core
    load: signal-or-default
    purpose: validate
    triggers: [second]
"""
    _write_registry(tmp_path, duplicate)

    with pytest.raises(KnowledgeRegistryError, match=message):
        load_card_paths(tmp_path)
