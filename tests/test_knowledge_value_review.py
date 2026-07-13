"""全量知识卡价值矩阵的覆盖与字段契约测试。"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from knowledge_value_review import audit_matrix, build_matrix, write_matrix


def _repo(tmp_path: Path) -> Path:
    cards = []
    for card_id, tags in (("first-card", ["authz", "role"]), ("second-card", ["authz", "tenant"])):
        cards.append(
            {
                "id": card_id,
                "kind": "card",
                "file": f"knowledge/cards/{card_id}.md",
                "layer": "core",
                "load": "signal-or-default",
                "purpose": "validate",
                "triggers": tags,
            }
        )
        path = tmp_path / "knowledge" / "cards" / f"{card_id}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"""---
id: {card_id}
type: technique-card
related_skills: [demo]
trigger_tags: {json.dumps(tags)}
risk: low
maturity: draft
load_priority: medium
deep_refs: []
---
# {card_id}

## Quick Recall

- signal

## 能力定位

用于验证 {card_id} 的连接器。
""",
            encoding="utf-8",
        )
    (tmp_path / "skills" / "demo").mkdir(parents=True)
    (tmp_path / "skills" / "demo" / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    (tmp_path / "knowledge" / "capabilities.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "contracts": {},
                "capabilities": cards,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_matrix_covers_registry_and_records_overlap(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    matrix = build_matrix(repo)
    path = write_matrix(matrix, tmp_path / "knowledge" / "governance" / "value-review.json")

    assert path.is_file()
    assert {item["card_id"] for item in matrix["cards"]} == {"first-card", "second-card"}
    first = next(item for item in matrix["cards"] if item["card_id"] == "first-card")
    assert "second-card" in first["overlap_with"]
    assert first["disposition"] == "keep-draft"
    assert audit_matrix(repo, matrix_path=path)["ok"] is True


def test_matrix_audit_rejects_missing_active_card(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = tmp_path / "value-review.json"
    matrix = build_matrix(repo)
    matrix["cards"].pop()
    write_matrix(matrix, path)

    result = audit_matrix(repo, matrix_path=path)

    assert result["ok"] is False
    assert any("ID mismatch" in item for item in result["errors"])


def test_matrix_audit_rejects_duplicate_card_record(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = tmp_path / "value-review.json"
    matrix = build_matrix(repo)
    matrix["cards"].append(dict(matrix["cards"][0]))
    write_matrix(matrix, path)

    result = audit_matrix(repo, matrix_path=path)

    assert result["ok"] is False
    assert any("duplicate card IDs" in item for item in result["errors"])


def test_matrix_audit_rejects_registry_projection_drift(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = tmp_path / "value-review.json"
    matrix = build_matrix(repo)
    matrix["cards"][0]["layer"] = "reference"
    write_matrix(matrix, path)

    result = audit_matrix(repo, matrix_path=path)

    assert result["ok"] is False
    assert any("layer differs from registry" in item for item in result["errors"])
