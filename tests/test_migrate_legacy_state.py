"""Focused fixtures for the v6 -> canonical state migration command."""

from __future__ import annotations

import json
from pathlib import Path

from tools.migrate_legacy_state import migrate_legacy_state
from tools.target_paths import target_storage_key


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")


def test_queue_migration_is_dry_run_then_idempotent(tmp_path: Path) -> None:
    target = "target.com"
    path = tmp_path / "state" / target / "action_queue.json"
    _write_json(
        path,
        {
            "target": target,
            "actions": [
                {
                    "status": "queued",
                    "type": "legacy-review",
                    "metadata": {"legacy_note": "preserve"},
                }
            ],
        },
    )
    before = path.read_bytes()

    dry_run = migrate_legacy_state(tmp_path, target)
    assert any(item["owner"] == "action_queue" for item in dry_run["migratable"])
    assert path.read_bytes() == before

    applied = migrate_legacy_state(tmp_path, target, apply=True)
    assert "state/target.com/action_queue.json" in applied["changed_paths"]
    queue = json.loads(path.read_text(encoding="utf-8"))
    assert queue["schema_version"] == 1
    assert queue["actions"][0]["id"].startswith("LEGACY-")
    assert queue["actions"][0]["metadata"]["legacy_note"] == "preserve"

    again = migrate_legacy_state(tmp_path, target, apply=True)
    assert again["changed_paths"] == []
    assert not any(item["owner"] == "action_queue" for item in again["migratable"])


def test_active_activation_gap_is_reported_without_inventing_ai_fields(tmp_path: Path) -> None:
    target = "activation.example"
    path = tmp_path / "state" / target / "action_queue.json"
    _write_json(
        path,
        {
            "schema_version": 1,
            "target": target,
            "actions": [
                {
                    "id": "AQ-legacy-depth",
                    "status": "queued",
                    "type": "validation",
                    "metadata": {"activation_required": True},
                }
            ],
        },
    )

    report = migrate_legacy_state(tmp_path, target, apply=True)

    item = next(
        item
        for item in report["needs_review"]
        if item["owner"] == "action_queue" and "actions[0]" in item["path"]
    )
    assert "depth_contract_version" in item["missing_fields"]
    assert "decision_reason" in item["missing_fields"]
    assert "skill_route" in item["missing_fields"]
    assert "max_hypothesis_actions" in item["missing_fields"]
    assert "refresh checkpoint" in item["repair_action"]
    migrated = json.loads(path.read_text(encoding="utf-8"))
    assert migrated["actions"][0]["metadata"] == {"activation_required": True}


def test_versioned_active_row_without_activation_marker_is_reviewed(tmp_path: Path) -> None:
    target = "versioned.example"
    path = tmp_path / "state" / target / "action_queue.json"
    _write_json(
        path,
        {
            "schema_version": 1,
            "target": target,
            "actions": [
                {
                    "id": "AQ-versioned-depth",
                    "status": "running",
                    "type": "validation",
                    "metadata": {"depth_contract_version": 1},
                }
            ],
        },
    )

    report = migrate_legacy_state(tmp_path, target)

    item = next(item for item in report["needs_review"] if item["owner"] == "action_queue")
    assert "activation_required" not in item["missing_fields"]
    assert "skill_route" in item["missing_fields"]
    assert report["changed_paths"] == []


def test_findings_list_uses_existing_owner_migration(tmp_path: Path) -> None:
    target = "example.com"
    path = tmp_path / "findings" / target / "findings.json"
    _write_json(
        path,
        [{"id": "legacy-1", "url": "https://example.com/a", "type": "exposure"}],
    )

    dry_run = migrate_legacy_state(tmp_path, target)
    assert any(item["owner"] == "finding_index" for item in dry_run["migratable"])
    assert json.loads(path.read_text(encoding="utf-8"))[0]["id"] == "legacy-1"

    migrate_legacy_state(tmp_path, target, apply=True)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert payload["findings"][0]["id"] == "legacy-1"
    assert (path.parent / "mutation-events.jsonl").is_file()
    again = migrate_legacy_state(tmp_path, target)
    assert not any(item["owner"] == "finding_index" for item in again["migratable"])


def test_target_memory_defaults_are_written_without_losing_entries(tmp_path: Path) -> None:
    target = "memory.example"
    path = tmp_path / "memory" / "goals" / "targets" / f"{target}.json"
    _write_json(path, {"schema_version": 1, "target": target, "mode": "hunt"})

    dry_run = migrate_legacy_state(tmp_path, target)
    memory_item = next(item for item in dry_run["migratable"] if item["owner"] == "target_memory")
    assert "scope_notes" in memory_item["changes"]
    assert "created_at" in memory_item["changes"]
    assert "mode" not in memory_item["changes"]
    assert json.loads(path.read_text(encoding="utf-8")) == {"schema_version": 1, "target": target, "mode": "hunt"}

    migrate_legacy_state(tmp_path, target, apply=True)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["scope_notes"] == []
    assert payload["active_goal"] == ""
    assert payload["created_at"]
    assert migrate_legacy_state(tmp_path, target)["changed_paths"] == []


def test_runtime_v1_is_normalized_by_runtime_owner(tmp_path: Path) -> None:
    target = "runtime.example"
    path = tmp_path / "state" / target / "session.json"
    _write_json(
        path,
        {
            "schema_version": 1,
            "target": target,
            "storage_key": target,
            "last_completed_step": "run_recon",
            "recon_completed": True,
        },
    )

    dry_run = migrate_legacy_state(tmp_path, target)
    item = next(item for item in dry_run["migratable"] if item["owner"] == "runtime_state")
    assert "last_completed_step" in item["dropped_fields"]
    assert path.read_text(encoding="utf-8").find('"schema_version": 1') >= 0

    migrate_legacy_state(tmp_path, target, apply=True)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["last_executed_workflow"] == "run_recon"
    assert "recon_completed" not in payload


def test_ambiguous_source_paths_never_guess_a_command_flag(tmp_path: Path) -> None:
    target = "source.example"
    key = target_storage_key(target)
    source = tmp_path / "evidence" / key / "inputs.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("https://source.example/a\n", encoding="utf-8")
    summary = tmp_path / "state" / key / "legacy-summary.json"
    _write_json(summary, {"source_paths": [f"evidence/{key}/inputs.txt"]})

    report = migrate_legacy_state(tmp_path, target, apply=True)
    item = next(item for item in report["needs_review"] if item["owner"] == "source_refs")
    assert "no unambiguous kind" in item["reason"]
    assert "source_refs" not in json.loads(summary.read_text(encoding="utf-8"))


def test_empty_source_refs_do_not_hide_ambiguous_source_paths(tmp_path: Path) -> None:
    target = "empty-refs.example"
    key = target_storage_key(target)
    summary = tmp_path / "state" / key / "legacy-summary.json"
    _write_json(summary, {"source_paths": ["recon/input.txt"], "source_refs": []})

    report = migrate_legacy_state(tmp_path, target)
    assert any(item["owner"] == "source_refs" for item in report["needs_review"])


def test_typed_source_bindings_become_source_refs(tmp_path: Path) -> None:
    target = "typed.example"
    key = target_storage_key(target)
    source = tmp_path / "evidence" / key / "endpoints.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("https://typed.example/a\n", encoding="utf-8")
    summary = tmp_path / "state" / key / "typed-summary.json"
    _write_json(
        summary,
        {
            "source_paths": [f"evidence/{key}/endpoints.txt"],
            "source_bindings": [{"kind": "endpoints", "path": f"evidence/{key}/endpoints.txt"}],
        },
    )

    report = migrate_legacy_state(tmp_path, target, apply=True)
    assert any(item["owner"] == "source_refs" for item in report["migratable"])
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["source_refs"] == [{"kind": "endpoints", "path": f"evidence/{key}/endpoints.txt"}]
    assert migrate_legacy_state(tmp_path, target)["changed_paths"] == []


def test_invalid_json_is_reported_without_overwrite(tmp_path: Path) -> None:
    target = "broken.example"
    path = tmp_path / "state" / target / "action_queue.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")
    before = path.read_bytes()

    report = migrate_legacy_state(tmp_path, target, apply=True)
    assert any(item["owner"] == "action_queue" for item in report["invalid"])
    assert path.read_bytes() == before


def test_owned_legacy_list_storage_is_only_moved_on_apply(tmp_path: Path) -> None:
    scope = tmp_path / "scope.txt"
    scope.write_text("one.example\n", encoding="utf-8")
    old_key = scope.stem
    old_state = tmp_path / "state" / old_key
    old_state.mkdir(parents=True)
    _write_json(old_state / "session.json", {"target": str(scope), "schema_version": 2})
    (tmp_path / "recon" / old_key).mkdir(parents=True)
    new_key = target_storage_key(str(scope))

    dry_run = migrate_legacy_state(tmp_path, str(scope))
    assert any(item["owner"] == "target_paths" for item in dry_run["migratable"])
    assert old_state.is_dir()
    assert not (tmp_path / "state" / new_key).exists()

    migrate_legacy_state(tmp_path, str(scope), apply=True)
    assert not old_state.exists()
    assert (tmp_path / "state" / new_key / "session.json").is_file()
    assert (tmp_path / "recon" / new_key).is_dir()
