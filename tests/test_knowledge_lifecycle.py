"""正式知识卡治理日志与状态机回归。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from knowledge_lifecycle import (
    KnowledgeLifecycleError,
    audit_lifecycle,
    bootstrap_cards,
    replay_events,
    restore_card,
    review_card,
    retire_card,
    supersede_card,
)


def _repo(tmp_path: Path, *, card_ids: tuple[str, ...] = ("first-card", "second-card")) -> Path:
    cards = []
    for card_id in card_ids:
        cards.append(
            {
                "id": card_id,
                "kind": "card",
                "file": f"knowledge/cards/{card_id}.md",
                "layer": "core",
                "load": "signal-or-default",
                "purpose": "validate",
                "triggers": [card_id],
            }
        )
        card = tmp_path / "knowledge" / "cards" / f"{card_id}.md"
        card.parent.mkdir(parents=True, exist_ok=True)
        card.write_text(
            f"""---
id: {card_id}
type: technique-card
related_skills: [demo]
trigger_tags: [demo]
risk: low
maturity: draft
load_priority: medium
deep_refs: []
---
# {card_id}

## Quick Recall

- signal

## 触发信号

- signal

## 最小验证

- baseline

## 常见误判 / 死路

- stop

## 推荐动作

- action
""",
            encoding="utf-8",
        )
    (tmp_path / "skills" / "demo").mkdir(parents=True, exist_ok=True)
    (tmp_path / "skills" / "demo" / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    (tmp_path / "knowledge" / "capabilities.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "contracts": {
                    "max_core_cards": 5,
                    "default_cards_max": 5,
                    "card_layers": ["core", "reference", "case-router", "payload-pack", "playbook"],
                    "load_modes": ["default", "signal-or-default", "signal-only", "on-demand", "gated"],
                },
                "capabilities": cards,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return tmp_path


def _events(repo: Path) -> Path:
    return repo / "knowledge" / "governance" / "events.jsonl"


def test_bootstrap_adopts_every_active_card_and_audit_is_clean(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    created = bootstrap_cards(repo)
    result = audit_lifecycle(repo)

    assert len(created) == 2
    assert result["ok"] is True
    assert result["active_count"] == 2
    states, errors = replay_events(repo)
    assert not errors
    assert {state["maturity"] for state in states.values()} == {"draft"}


def test_bootstrap_is_idempotent_and_duplicate_adoption_is_rejected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first = bootstrap_cards(repo)
    second = bootstrap_cards(repo)

    assert len(first) == 2
    assert second == []
    lines = _events(repo).read_text(encoding="utf-8").splitlines()
    duplicate = json.loads(lines[0])
    duplicate["event_id"] = "kg-duplicate"
    _events(repo).open("a", encoding="utf-8").write(json.dumps(duplicate) + "\n")

    result = audit_lifecycle(repo)
    assert result["ok"] is False
    assert any("duplicate adoption" in item for item in result["errors"])


def test_tested_and_proven_reviews_require_evidence_and_frontmatter_sync(tmp_path: Path) -> None:
    repo = _repo(tmp_path, card_ids=("first-card",))
    bootstrap_cards(repo)
    with pytest.raises(KnowledgeLifecycleError, match="evidence_refs"):
        review_card(
            "first-card",
            repo_root=repo,
            maturity="tested",
            reviewer="human",
            reason="review",
            model_profile="claude-cli/test",
        )

    evidence = repo / "tests" / "fixtures" / "review.md"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("review evidence\n", encoding="utf-8")
    review_card(
        "first-card",
        repo_root=repo,
        maturity="tested",
        reviewer="human",
        reason="replayed on two fixtures",
        model_profile="claude-cli/test",
        evidence_refs=["tests/fixtures/review.md#L1"],
    )
    card = repo / "knowledge" / "cards" / "first-card.md"
    card.write_text(card.read_text(encoding="utf-8").replace("maturity: draft", "maturity: tested"), encoding="utf-8")
    assert audit_lifecycle(repo)["ok"] is True

    with pytest.raises(KnowledgeLifecycleError, match="evaluation_kind"):
        review_card(
            "first-card",
            repo_root=repo,
            maturity="proven",
            reviewer="human",
            reason="proven",
            model_profile="claude-cli/test",
            evidence_refs=["tests/fixtures/review.md#L1"],
        )


def test_supersede_requires_active_replacement_and_archive_consistency(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    bootstrap_cards(repo)
    event = supersede_card(
        "first-card",
        "second-card",
        repo_root=repo,
        reviewer="human",
        reason="second card supersedes first",
    )
    assert event["event"] == "superseded"
    assert audit_lifecycle(repo)["ok"] is False  # old card still active in registry

    registry_path = repo / "knowledge" / "capabilities.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["capabilities"] = [item for item in registry["capabilities"] if item["id"] != "first-card"]
    registry_path.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
    archive = repo / "knowledge" / "archive" / "cards" / "first-card.md"
    archive.parent.mkdir(parents=True)
    archive.write_text("# archived\n", encoding="utf-8")
    assert audit_lifecycle(repo)["ok"] is True

    restored = restore_card(
        "first-card",
        repo_root=repo,
        reverts_event_id=event["event_id"],
        reviewer="human",
        reason="new evidence restores the card",
    )
    assert restored["event"] == "restored"


def test_retire_restore_and_illegal_terminal_transition(tmp_path: Path) -> None:
    repo = _repo(tmp_path, card_ids=("first-card",))
    bootstrap_cards(repo)
    event = retire_card("first-card", repo_root=repo, reviewer="human", reason="obsolete")
    states, errors = replay_events(repo)
    assert not errors
    assert states["first-card"]["status"] == "retired"
    with pytest.raises(KnowledgeLifecycleError, match="from_status"):
        retire_card("first-card", repo_root=repo, reviewer="human", reason="again")
    assert event["to_status"] == "retired"


def test_malformed_or_duplicate_event_is_reported_without_silent_replay(tmp_path: Path) -> None:
    repo = _repo(tmp_path, card_ids=("first-card",))
    path = _events(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not-json\n", encoding="utf-8")

    result = audit_lifecycle(repo)

    assert result["ok"] is False
    assert any("invalid JSON" in item for item in result["errors"])
