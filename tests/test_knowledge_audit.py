"""知识库质量门的 registry、文档和 CLI 回归测试。"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from knowledge_audit import audit_repository, main


def _base_registry(*capabilities: dict) -> dict:
    return {
        "schema_version": 1,
        "contracts": {
            "max_core_cards": 2,
            "default_cards_max": 1,
            "card_layers": ["core", "reference", "case-router", "payload-pack", "playbook"],
            "load_modes": ["default", "signal-or-default", "signal-only", "on-demand", "gated"],
        },
        "capabilities": list(capabilities),
    }


def _card(
    *,
    identifier: str = "demo-card",
    file_path: str | None = None,
    layer: str = "core",
    load: str = "signal-or-default",
) -> dict:
    return {
        "id": identifier,
        "kind": "card",
        "file": file_path or f"knowledge/cards/{identifier}.md",
        "layer": layer,
        "load": load,
        "purpose": "validate",
        "triggers": ["demo"],
    }


def _v2_card(
    *,
    identifier: str = "demo-card",
    frontmatter_id: str | None = None,
    frontmatter_type: str = "technique-card",
    body: str | None = None,
) -> str:
    metadata = {
        "id": frontmatter_id or identifier,
        "type": frontmatter_type,
        "related_skills": ["demo-skill"],
        "trigger_tags": ["demo"],
        "risk": "low",
        "maturity": "draft",
        "load_priority": "medium",
        "deep_refs": [],
    }
    body = body or """\
# Demo card

## Quick Recall

Use a concrete signal and stop at the smallest reproducible check.

## 触发信号

- demo signal

## 最小验证

- compare a baseline and one variant

## 常见误判 / 死路

- no stable difference means stop

## 推荐动作

- record the evidence and choose the next action
"""
    return "---\n" + yaml.safe_dump(metadata, allow_unicode=True, sort_keys=False) + "---\n" + body


def _write_repo(
    tmp_path: Path,
    registry: dict,
    *,
    card_text: str | None = None,
    extra_files: dict[str, str] | None = None,
) -> Path:
    (tmp_path / "knowledge" / "cards").mkdir(parents=True)
    (tmp_path / "skills" / "demo-skill").mkdir(parents=True)
    (tmp_path / "skills" / "demo-skill" / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    (tmp_path / "knowledge" / "capabilities.yaml").write_text(
        yaml.safe_dump(registry, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    if card_text is not None:
        (tmp_path / "knowledge" / "cards" / "demo-card.md").write_text(
            card_text, encoding="utf-8"
        )
    for relative, text in (extra_files or {}).items():
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    return tmp_path


def _codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def test_current_knowledge_repository_has_no_blocking_errors() -> None:
    report = audit_repository()

    assert report.errors == 0
    assert report.capabilities == 50
    assert report.documents == 48
    assert report.warnings == 18


def test_legacy_card_is_a_single_migration_warning(tmp_path: Path) -> None:
    registry = _base_registry(_card())
    body = """\
# Legacy card

## 触发信号

- a signal

## 推荐动作

- a bounded action

## 停止条件

- no stable evidence
"""
    _write_repo(tmp_path, registry, card_text=body)

    report = audit_repository(tmp_path)

    assert report.errors == 0
    assert report.warnings == 1
    assert report.issues[0].code == "legacy-card"


def test_registry_and_inventory_errors_are_reported_together(tmp_path: Path) -> None:
    duplicate = _card(identifier="demo-card", file_path="knowledge/cards/other.md")
    registry = _base_registry(_card(), duplicate)
    _write_repo(
        tmp_path,
        registry,
        card_text=_v2_card(),
        extra_files={"knowledge/cards/unregistered.md": "# stray\n"},
    )

    report = audit_repository(tmp_path)

    assert "capability-duplicate-id" in _codes(report)
    assert "capability-file-missing" in _codes(report)
    assert "document-unregistered" in _codes(report)


def test_v2_identity_sections_and_internal_links_are_blocking(tmp_path: Path) -> None:
    registry = _base_registry(_card())
    broken_body = """\
# Demo card

## Quick Recall

- short

## 触发信号

- signal

[missing](knowledge/cards/nope.md)
"""
    _write_repo(
        tmp_path,
        registry,
        card_text=_v2_card(
            frontmatter_id="wrong-id",
            frontmatter_type="payload-pack",
            body=broken_body,
        ),
    )

    report = audit_repository(tmp_path)
    codes = _codes(report)

    assert "frontmatter-id-mismatch" in codes
    assert "frontmatter-type" in codes
    assert "document-section" in codes
    assert "markdown-link-missing" in codes


def test_duplicate_budget_and_kind_contracts_are_blocking(tmp_path: Path) -> None:
    first = _card(identifier="first", file_path="knowledge/cards/first.md")
    second = _card(identifier="second", file_path="knowledge/cards/second.md")
    second["layer"] = "payload-pack"
    second["load"] = "signal-or-default"
    registry = _base_registry(first, second)
    registry["contracts"]["max_core_cards"] = 0
    _write_repo(
        tmp_path,
        registry,
        extra_files={
            "knowledge/cards/first.md": _v2_card(identifier="first"),
            "knowledge/cards/second.md": _v2_card(identifier="second"),
        },
    )

    report = audit_repository(tmp_path)
    codes = _codes(report)

    assert "budget-max-core" in codes
    assert "capability-kind-contract" in codes


def test_cli_json_and_strict_exit_codes(tmp_path: Path, capsys) -> None:
    registry = _base_registry(_card())
    _write_repo(tmp_path, registry, card_text="# legacy\n")

    assert main(["--repo-root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"] == 0
    assert payload["warnings"] == 1
    assert payload["issues"][0]["code"] == "legacy-card"

    assert main(["--repo-root", str(tmp_path), "--strict"]) == 1
    assert "warnings=1" in capsys.readouterr().out


def test_malformed_registry_fails_without_traceback(tmp_path: Path, capsys) -> None:
    (tmp_path / "knowledge").mkdir(parents=True)
    (tmp_path / "knowledge" / "capabilities.yaml").write_text(
        "capabilities: [\n", encoding="utf-8"
    )

    assert main(["--repo-root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "registry-load" in output
    assert "Traceback" not in output
