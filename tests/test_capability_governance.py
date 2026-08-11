"""Tests for the unified read-only capability governance command."""

from __future__ import annotations

import json
from pathlib import Path

import capability_governance as governance


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_skill_catalog_and_trigger_collision_projection_are_complete() -> None:
    skills = governance.audit_skill_catalog(REPO_ROOT)
    collisions = governance.trigger_collisions(REPO_ROOT)

    assert skills["ok"] is True
    assert skills["catalog_count"] == skills["disk_count"] == 12
    assert skills["primary_count"] == 6
    assert collisions == sorted(collisions, key=lambda item: item["trigger"])
    assert all(item["capability_ids"] == sorted(item["capability_ids"]) for item in collisions)
    assert {
        "trigger": "rce",
        "capability_ids": [
            "command-execution-probes",
            "controlled-rce-impact",
            "controlled-rce-validation",
        ],
    } in collisions


def _stub_owners(
    monkeypatch,
    *,
    failed_section: str = "",
    knowledge_warnings: int = 0,
) -> None:
    class Report:
        def to_dict(self):
            return {
                "errors": int(failed_section == "knowledge"),
                "warnings": knowledge_warnings,
                "capabilities": 1,
                "documents": 1,
            }

    monkeypatch.setattr(governance, "audit_repository", lambda *_args, **_kwargs: Report())
    monkeypatch.setattr(
        governance,
        "audit_lifecycle",
        lambda *_args, **_kwargs: {
            "ok": failed_section != "lifecycle",
            "errors": ["lifecycle drift"] if failed_section == "lifecycle" else [],
            "event_count": 1,
            "active_count": 1,
        },
    )
    monkeypatch.setattr(
        governance,
        "audit_candidates",
        lambda **_kwargs: {
            "ok": failed_section != "candidates",
            "errors": ["candidate drift"] if failed_section == "candidates" else [],
            "candidate_count": 0,
        },
    )
    monkeypatch.setattr(
        governance,
        "audit_matrix",
        lambda *_args, **_kwargs: {
            "ok": failed_section != "value_review",
            "errors": ["missing card"] if failed_section == "value_review" else [],
            "cards": 1,
            "registry_cards": 1,
        },
    )
    monkeypatch.setattr(
        governance,
        "audit_skill_catalog",
        lambda *_args: {
            "ok": failed_section != "skills",
            "errors": ["Skill catalog drift"] if failed_section == "skills" else [],
            "catalog_count": 12,
            "disk_count": 12,
            "primary_count": 6,
        },
    )
    monkeypatch.setattr(
        governance,
        "trigger_collisions",
        lambda *_args: [{"trigger": "demo", "capability_ids": ["a", "b"]}],
    )


def test_cli_json_identifies_every_hard_section_failure(monkeypatch, capsys) -> None:
    for failed_section in (
        "knowledge",
        "lifecycle",
        "candidates",
        "value_review",
        "skills",
    ):
        _stub_owners(monkeypatch, failed_section=failed_section)

        assert governance.main(["--repo-root", str(REPO_ROOT), "--json"]) == 1
        result = json.loads(capsys.readouterr().out)

        assert result["ok"] is False
        assert result["sections"][failed_section]["ok"] is False
        assert result["advisories"]["trigger_collisions"][0]["trigger"] == "demo"


def test_cli_strict_fails_on_knowledge_warning(monkeypatch, capsys) -> None:
    _stub_owners(monkeypatch, knowledge_warnings=1)

    assert governance.main(["--repo-root", str(REPO_ROOT), "--json"]) == 0
    capsys.readouterr()
    assert governance.main(["--repo-root", str(REPO_ROOT), "--strict", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)

    assert result["sections"]["knowledge"]["ok"] is False


def test_cli_text_reports_every_section_and_advisories(monkeypatch, capsys) -> None:
    _stub_owners(monkeypatch)

    assert governance.main(["--repo-root", str(REPO_ROOT), "--strict"]) == 0
    output = capsys.readouterr().out

    for section in ("knowledge", "lifecycle", "candidates", "value_review", "skills"):
        assert f"[PASS] {section}:" in output
    assert "[ADVISORY] trigger collision demo: a, b" in output


def test_missing_optional_corpus_is_visible_and_read_only(tmp_path: Path) -> None:
    owned_paths = [
        REPO_ROOT / "knowledge" / "governance" / "events.jsonl",
        REPO_ROOT / "knowledge" / "candidates" / "lifecycle.jsonl",
        REPO_ROOT / "knowledge" / "governance" / "value-review.json",
    ]
    before = {
        path: path.read_bytes() if path.is_file() else None for path in owned_paths
    }

    result = governance.audit_governance(
        REPO_ROOT,
        source_mode="if-present",
        corpus_dir=tmp_path / "missing-corpus",
    )

    assert result["ok"] is True
    assert "states" not in result["sections"]["lifecycle"]
    assert result["sections"]["knowledge"]["skipped"][0]["check"] == "source-resolution"
    assert result["sections"]["candidates"]["skipped"][0]["check"] == "source-resolution"
    assert {
        path: path.read_bytes() if path.is_file() else None for path in owned_paths
    } == before
