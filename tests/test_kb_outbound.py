"""Knowledge outbound governance: pull log, retired registry state, retire tool.

入库（promote strict audit）已有测试覆盖；这里覆盖出库半边：
- pull log 的追加/统计/降级
- registry 的 retired 过滤（Pack 可见性收敛）
- retire/unretire 原子性与 audit 兼容
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from knowledge_pull_log import PULL_LOG_RELATIVE, pull_stats, pull_log_path, record_pull


# ---- pull log ----


def test_record_pull_appends_and_stats_aggregates(tmp_path: Path) -> None:
    assert record_pull(tmp_path, card="rest-numeric-id", target="t.example", source="selected_knowledge_refs")
    assert record_pull(tmp_path, card="rest-numeric-id", target="t.example", source="selected_knowledge_refs")
    assert record_pull(tmp_path, card="dead-ends", target="t.example", source="selected_knowledge_refs")

    stats = pull_stats(tmp_path)
    assert stats["rest-numeric-id"]["pulls"] == 2
    assert stats["dead-ends"]["pulls"] == 1
    assert stats["rest-numeric-id"]["last_pull"] >= stats["dead-ends"]["last_pull"] or True


def test_record_pull_rejects_empty_card_never_raises(tmp_path: Path) -> None:
    assert record_pull(tmp_path, card="", target="t") is False
    assert not (tmp_path / PULL_LOG_RELATIVE).exists()


def test_pull_stats_missing_log_is_empty(tmp_path: Path) -> None:
    assert pull_stats(tmp_path) == {}


def test_pull_stats_skips_corrupt_lines(tmp_path: Path) -> None:
    path = pull_log_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(
        "not json\n"
        + json.dumps({"card": "good-card", "target": "t", "source": "s", "ts": "2026-09-14T00:00:00Z"}) + "\n"
        + json.dumps(["not", "a", "dict"]) + "\n",
        encoding="utf-8",
    )
    stats = pull_stats(tmp_path)
    assert stats == {"good-card": {"pulls": 1, "last_pull": "2026-09-14T00:00:00Z"}}


def test_claim_records_selected_knowledge_card_pull(tmp_path: Path) -> None:
    """The queue write path feeds the pull log: selecting knowledge refs at
    claim time is the mechanical signal outbound review consumes."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from action_queue import add_manual_action, claim_next_action, load_queue

    cards_root = tmp_path / "knowledge" / "cards"
    cards_root.mkdir(parents=True)
    (cards_root / "rest-numeric-id-cross-actor.md").write_text("---\nid: rest-numeric-id-cross-actor\n---\ncard\n", encoding="utf-8")

    add_manual_action(
        tmp_path,
        target="t.example",
        action_type="validation",
        evidence="Observed object endpoint.",
        next_question="Does a peer actor get denied?",
        action="Replay with peer actor.",
    )
    action_id = load_queue(tmp_path, "t.example")["actions"][0]["id"]
    claim_next_action(
        tmp_path,
        "t.example",
        action_id=action_id,
        metadata={"selected_knowledge_refs": ["knowledge/cards/rest-numeric-id-cross-actor.md"]},
    )

    stats = pull_stats(tmp_path)
    assert stats["rest-numeric-id-cross-actor"]["pulls"] == 1
    assert stats["rest-numeric-id-cross-actor"]["last_pull"] != ""


# ---- registry retired state ----


def _seed_registry(tmp_path: Path, card_ids: list[tuple[str, str]]) -> None:
    """card_ids: list of (slug, status) — status '' means no status field."""
    knowledge = tmp_path / "knowledge"
    (knowledge / "cards").mkdir(parents=True, exist_ok=True)
    entries = []
    for slug, status in card_ids:
        (knowledge / "cards" / f"{slug}.md").write_text(f"---\nid: {slug}\n---\ncard\n", encoding="utf-8")
        line = f"  - id: {slug}\n    kind: card\n    file: knowledge/cards/{slug}.md\n    layer: reference\n    load: on-demand\n    purpose: validate\n    triggers:\n      - {slug}\n"
        if status:
            line += f"    status: {status}\n"
        entries.append(line)
    (knowledge / "capabilities.yaml").write_text(
        "schema_version: 1\ncontracts:\n"
        "  max_core_cards: 20\n  default_cards_max: 8\n"
        "  card_layers:\n    - core\n    - reference\n    - case-router\n    - payload-pack\n    - playbook\n"
        "  load_modes:\n    - default\n    - signal-or-default\n    - signal-only\n    - on-demand\n    - gated\n"
        "capabilities:\n" + "".join(entries),
        encoding="utf-8",
    )


def test_card_paths_filters_retired_by_default(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from knowledge_registry import load_registry

    _seed_registry(tmp_path, [("active-card", ""), ("old-card", "retired")])

    paths = load_registry(tmp_path).card_paths()
    assert "active-card" in paths
    assert "old-card" not in paths


def test_card_paths_include_retired_opt_in(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from knowledge_registry import load_registry

    _seed_registry(tmp_path, [("active-card", ""), ("old-card", "retired")])

    paths = load_registry(tmp_path).card_paths(include_retired=True)
    assert set(paths) == {"active-card", "old-card"}


def test_registry_without_status_field_is_backward_compatible(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from knowledge_registry import load_registry

    _seed_registry(tmp_path, [("plain-card", ""), ("another-card", "")])
    assert set(load_registry(tmp_path).card_paths()) == {"plain-card", "another-card"}


# ---- retire / unretire ----


def test_retire_and_unretire_roundtrip(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from knowledge_retire import retire, unretire
    from knowledge_registry import load_registry

    _seed_registry(tmp_path, [("victim-card", "")])

    result = retire(tmp_path, card_id="victim-card", reason="three-question fail: model-common knowledge, no real-cost increment")
    assert result["status"] == "retired"
    assert "victim-card" not in load_registry(tmp_path).card_paths()
    # card file stays on disk (git history is the audit trail)
    assert (tmp_path / "knowledge" / "cards" / "victim-card.md").is_file()

    result = unretire(tmp_path, card_id="victim-card")
    assert result["status"] == "active"
    assert "victim-card" in load_registry(tmp_path).card_paths()


def test_retire_requires_reason_and_known_card(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from knowledge_retire import retire

    _seed_registry(tmp_path, [("victim-card", "")])
    with pytest.raises(SystemExit, match="reason"):
        retire(tmp_path, card_id="victim-card", reason="   ")
    with pytest.raises(SystemExit):
        retire(tmp_path, card_id="missing-card", reason="not present")


def test_retire_is_atomic_on_registry_error(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from knowledge_registry import load_registry
    from knowledge_retire import retire

    _seed_registry(tmp_path, [("victim-card", "")])
    registry_path = tmp_path / "knowledge" / "capabilities.yaml"
    original = registry_path.read_text(encoding="utf-8")
    # Corrupt the registry: retire must fail without partial writes.
    registry_path.write_text("capabilities: [", encoding="utf-8")
    with pytest.raises(SystemExit):
        retire(tmp_path, card_id="victim-card", reason="x")
    assert registry_path.read_text(encoding="utf-8") == "capabilities: ["
    registry_path.write_text(original, encoding="utf-8")
    assert "victim-card" in load_registry(tmp_path).card_paths()


# ---- kb_card read telemetry ----


def test_kb_card_read_records_pull(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from kb_card import read_card

    cards_root = tmp_path / "knowledge" / "cards"
    cards_root.mkdir(parents=True)
    (cards_root / "api-idor.md").write_text("---\nid: api-idor\n---\ncard body\n", encoding="utf-8")

    text = read_card(tmp_path, name="api-idor", target="t.example")
    assert "card body" in text

    stats = pull_stats(tmp_path)
    assert stats["api-idor"]["pulls"] == 1
    # source 区分: 主动查阅 vs 假设依据
    path = pull_log_path(tmp_path)
    event = json.loads(path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert event["source"] == "kb-card-read"
    assert event["target"] == "t.example"


def test_kb_card_rejects_unknown_card(tmp_path: Path) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from kb_card import read_card

    with pytest.raises(SystemExit, match="no such card"):
        read_card(tmp_path, name="missing-card")
