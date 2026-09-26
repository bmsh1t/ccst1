from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from tools.target_migration import (
    backfill_target_memory,
    backfill_target_patterns,
    import_target,
    import_target_staged,
    quarantine_id,
    preview_target,
    publish_preview,
    promote_target,
    restore_legacy_metadata,
)
import tools.target_migration as migration
from tools.action_queue import load_queue
import tools.action_queue as action_queue
import tools.evidence_ledger as evidence_ledger
import tools.finding_index as finding_index
from tools.target_store import StoreError, TargetStore, target_backend


def test_import_isolated_queue_and_reports_ambiguous_legacy_claims(tmp_path):
    target = "target.test"
    key = "target.test"
    queue = tmp_path / "state" / key / "action_queue.json"
    queue.parent.mkdir(parents=True)
    queue.write_text(json.dumps({"schema_version": 1, "target": target, "actions": [{
        "id": "AQ-1", "status": "queued", "action": "Compare object ownership",
        "priority": 7, "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "custom-state-transition"}
    }]}))
    findings = tmp_path / "findings" / key / "findings.json"
    findings.parent.mkdir(parents=True)
    findings.write_text(json.dumps({"schema_version": 1, "target": target, "findings": [{
        "id": "F-1", "url": "https://target.test/api/object", "vuln_class": "Authz", "title": "claim"
    }]}))
    result = import_target(tmp_path, target)
    assert result["status"] == "partial"
    assert result["imported"]["actions"] == 1
    assert any(row["owner"] == "findings" and row["id"] == "F-1" for row in result["quarantined"])
    store = TargetStore(tmp_path, target)
    assert store.page("actions")["items"][0]["id"] == "AQ-1"
    assert not store.page("findings")["items"]


def test_open_queue_hypothesis_metadata_is_carried_without_secret_fields(tmp_path):
    target = _fixture(tmp_path, actions=[{
        "id": "AQ-H",
        "status": "queued",
        "action": "Compare owner and peer objects",
        "metadata": {
            "endpoint": "https://target.test/api/object",
            "vuln_class": "Authz",
            "hypothesis_id": "H-owner-boundary",
            "expected_learning": "whether ownership changes the response",
            "skill_route": {"skill_id": "triage-validation"},
            "access_token": "must-not-enter-store",
        },
    }])
    result = import_target(tmp_path, target)
    action = TargetStore(tmp_path, target).action("AQ-H")
    assert action["metadata"] == {
        "expected_learning": "whether ownership changes the response",
        "hypothesis_id": "H-owner-boundary",
    }
    assert result["legacy"]["action_metadata"][0]["keys"] == [
        "expected_learning", "hypothesis_id", "skill_route",
    ]
    assert "must-not-enter-store" not in json.dumps(result)


def test_readonly_preview_does_not_create_store_or_locks(tmp_path):
    target = _fixture(tmp_path, actions=[{
        "id": "AQ-1", "status": "queued", "action": "probe",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    result = preview_target(tmp_path, target)
    assert result["mode"] == "readonly-preview"
    assert result["source_counts"]["actions"] == 1
    assert not (tmp_path / "state" / target / "metadata.sqlite3").exists()
    assert not (tmp_path / "state" / target / "locks").exists()


def test_staged_import_publish_and_promote_are_explicit(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[{
        "id": "AQ-1", "status": "queued", "action": "probe",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    staged = tmp_path / "staging-root"
    result = import_target_staged(source, staged, target)
    assert result["mode"] == "staged-import"
    assert result["receipt"]["status"] == "complete"
    assert target_backend(staged, target) == "preview"
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    assert target_backend(published, target) == "preview"
    promoted = promote_target(published, target)
    assert promoted["status"] == "primary"
    assert target_backend(published, target) == "primary"
    store = TargetStore(published, target)
    assert store.page("actions")["items"][0]["id"] == "AQ-1"
    store.create_action(command_id="after-cutover", action_id="AQ-2", intent="record a post-cutover fact",
                        endpoint="https://target.test/api/object", family="Authz", execution_key="AQ-2",
                        actor="operator")
    assert store.page("actions")["total"] == 2
    assert not (source / "state" / target / "metadata.sqlite3").exists()


def test_promote_archives_legacy_domain_metadata_but_keeps_raw_and_reports(tmp_path):
    source = tmp_path / "source"
    target = _fixture(
        source,
        actions=[{
            "id": "AQ-1", "status": "queued", "action": "probe",
            "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
        }],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}")],
    )
    ledger = source / "memory" / "evidence" / target / "ledger.jsonl"
    ledger.write_text(json.dumps(_ledger_row()) + "\n", encoding="utf-8")
    report = source / "reports" / target / "existing.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("existing report\n", encoding="utf-8")
    raw = source / "evidence" / target / "response.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("raw response\n", encoding="utf-8")

    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    promote_target(published, target)

    key = target
    assert not (published / "state" / key / "action_queue.json").exists()
    assert not (published / "memory" / "evidence" / key / "ledger.jsonl").exists()
    archive = published / "state" / key / "legacy-archive.json"
    archive_payload = json.loads(archive.read_text(encoding="utf-8"))
    assert archive_payload["activation_status"] == "active"
    assert archive_payload["files"]
    migration_receipt = json.loads(
        (published / "state" / key / "migration-receipt.json").read_text(encoding="utf-8")
    )
    assert migration_receipt["backend"] == "primary"
    assert migration_receipt["activation_status"] == "active"
    assert migration_receipt["legacy_archive_path"] == "state/target.test/legacy-archive.json"
    assert (published / "evidence" / target / "response.txt").read_text() == "raw response\n"
    assert (published / "reports" / target / "existing.md").read_text() == "existing report\n"


def test_old_domain_writers_fail_closed_after_primary_activation(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    promote_target(published, target)

    assert not hasattr(action_queue, "save_queue")
    assert not hasattr(evidence_ledger, "record_entry")
    assert not hasattr(finding_index, "upsert_finding")


def test_promote_recovers_after_primary_commit_before_archive_activation(tmp_path, monkeypatch):
    import tools.target_migration as migration

    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)

    original = migration._mark_archive_active

    def interrupted(*args, **kwargs):
        raise OSError("simulated post-commit interruption")

    monkeypatch.setattr(migration, "_mark_archive_active", interrupted)
    with pytest.raises(OSError, match="post-commit interruption"):
        promote_target(published, target)
    assert target_backend(published, target) == "primary"

    monkeypatch.setattr(migration, "_mark_archive_active", original)
    recovered = promote_target(published, target)
    assert recovered["status"] == "primary"
    assert recovered["recovered"] is True
    receipt = json.loads((published / "state" / target / "migration-receipt.json").read_text())
    assert receipt["activation_status"] == "active"


def test_promote_stays_idempotent_after_the_archive_is_cleaned_up(tmp_path):
    """A finished cutover must not depend on archive bytes to re-enter."""
    import shutil

    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    promote_target(published, target)

    # Cleanup of historical material is expected after a cutover; it is not damage.
    archive_dir = published / "state" / target / "legacy-archive"
    shutil.rmtree(archive_dir)
    (published / "state" / target / "legacy-archive.json").unlink()

    again = promote_target(published, target)
    assert again["status"] == "primary"
    assert again["recovered"] is True
    assert target_backend(published, target) == "primary"


def test_promote_still_requires_the_archive_for_an_interrupted_activation(tmp_path, monkeypatch):
    """Recovery of an interrupted cutover keeps needing its recovery input."""
    import shutil

    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)

    import tools.target_migration as migration

    def interrupted(*args, **kwargs):
        raise OSError("simulated post-commit interruption")

    monkeypatch.setattr(migration, "_mark_archive_active", interrupted)
    with pytest.raises(OSError, match="post-commit interruption"):
        promote_target(published, target)

    # The receipt still says pending, so the activation is genuinely incomplete
    # and the archive remains the required recovery input.
    monkeypatch.undo()
    shutil.rmtree(published / "state" / target / "legacy-archive")
    with pytest.raises(StoreError, match="legacy archive material is missing"):
        promote_target(published, target)
    assert target_backend(published, target) == "primary"


def test_archive_freeze_interruption_is_pending_and_explicitly_recoverable(tmp_path, monkeypatch):
    from pathlib import Path

    source = tmp_path / "source"
    target = _fixture(source, actions=[{
        "id": "AQ-1", "status": "queued", "action": "probe",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)

    original_unlink = Path.unlink
    removed = []

    def interrupted_unlink(path, *args, **kwargs):
        if path.name in {"action_queue.json", "findings.json", "ledger.jsonl"}:
            removed.append(path)
            if len(removed) == 2:
                raise OSError("simulated archive freeze interruption")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", interrupted_unlink)
    with pytest.raises(OSError, match="archive freeze interruption"):
        promote_target(published, target)

    archive = published / "state" / target / "legacy-archive.json"
    assert json.loads(archive.read_text(encoding="utf-8"))["activation_status"] == "pending"
    with pytest.raises(StoreError, match="backend cutover incomplete"):
        target_backend(published, target)

    monkeypatch.setattr(Path, "unlink", original_unlink)
    restored = restore_legacy_metadata(published, target)
    assert restored["status"] == "legacy"
    assert (published / "state" / target / "action_queue.json").is_file()
    assert (published / "findings" / target / "findings.json").is_file()


def test_damaged_primary_after_cutover_never_falls_back_to_archived_legacy(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[{
        "id": "AQ-1", "status": "queued", "action": "probe",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    promote_target(published, target)

    (published / "state" / target / "metadata.sqlite3").write_bytes(b"damaged")
    with pytest.raises(StoreError, match="target store failure"):
        target_backend(published, target)
    assert not (published / "state" / target / "action_queue.json").exists()


def test_pre_primary_restore_requires_archive_and_removes_preview_fence(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[{
        "id": "AQ-1", "status": "queued", "action": "probe",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)

    # Simulate the documented interruption after the fence/archive, before the
    # SQLite backend role is committed.
    store = TargetStore(published, target, allow_preview=True)
    receipt = json.loads((published / "state" / target / "migration-receipt.json").read_text())
    meta = store.context(limit=1)
    store._create_fence(meta["store_id"], receipt["source_manifest_sha256"])
    from tools.target_migration import _freeze_legacy_metadata
    _freeze_legacy_metadata(
        published,
        target,
        store_id=meta["store_id"],
        source_manifest_sha256=receipt["source_manifest_sha256"],
    )
    with pytest.raises(StoreError, match="backend cutover incomplete"):
        target_backend(published, target)
    restored = restore_legacy_metadata(
        published,
        target,
        source_manifest_sha256=receipt["source_manifest_sha256"],
    )
    assert restored["status"] == "legacy"
    assert target_backend(published, target) == "legacy"
    assert (published / "state" / target / "action_queue.json").is_file()


def test_restore_legacy_metadata_rolls_back_pending_cutover(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[{
        "id": "AQ-1", "status": "queued", "action": "probe",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    promote_target(published, target)
    # Primary activation is irreversible through the legacy path.
    with pytest.raises(StoreError, match="primary activation already committed"):
        restore_legacy_metadata(published, target)


def test_report_artifacts_are_copied_and_left_unregistered_for_explicit_rebinding(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    report = source / "reports" / target / "idor_001.md"
    report.parent.mkdir(parents=True)
    report.write_text("report body\n", encoding="utf-8")
    (report.parent / "INDEX.json").write_text("{}\n", encoding="utf-8")

    preview = preview_target(source, target)
    assert preview["source_counts"]["report_artifacts"] == 2
    staged = tmp_path / "staging-root"
    result = import_target_staged(source, staged, target)
    artifacts = result["legacy"]["report_artifacts"]
    assert {item["path"] for item in artifacts} == {
        f"reports/{target}/idor_001.md", f"reports/{target}/INDEX.json",
    }
    assert all(item["registered"] is False for item in artifacts)
    assert (staged / "reports" / target / "idor_001.md").read_text(encoding="utf-8") == "report body\n"
    assert "reports" in result["sources"]


def test_target_memory_imports_historical_advice_with_source_locations(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    memory = source / "memory" / "goals" / "targets" / f"{target}.json"
    memory.parent.mkdir(parents=True, exist_ok=True)
    memory.write_text(json.dumps({
        "schema_version": 1,
        "target": target,
        "active_goal": "Investigate peer reads",
        "scope_notes": [{"text": "Target-owned lab"}],
        "active_leads": [{"ts": "2026-09-21T00:00:00Z", "text": "recheck ownership"}],
        "dead_ends": [{"ts": "2026-09-21T00:01:00Z", "text": "baseline unchanged"}],
        "facts": {"baseline": {"text": "stable", "evidence_refs": []}},
    }), encoding="utf-8")

    result = import_target_staged(source, tmp_path / "staging-root", target)

    memory_report = result["legacy"]["target_memory"]
    assert memory_report["status"] == "valid"
    assert memory_report["entries"] == 5
    assert memory_report["fields"] == {
        "scope_notes": 1, "active_leads": 1, "dead_ends": 1, "facts": 1, "active_goal": 1,
    }
    assert memory_report["imported_experiences"] == 5
    assert len(memory_report["experience_map"]) == 5
    assert result["imported"]["observations"] == 0
    store = TargetStore(tmp_path / "staging-root", target)
    rows = [store.experience(item["experience_id"]) for item in memory_report["experience_map"]]
    assert {row["kind"] for row in rows} == {"hypothesis", "note"}
    assert all(not row["evidence"] for row in rows)
    assert any("Historical facts[baseline] (unverified): stable" == row["statement"] for row in rows)
    assert all(item["source_path"] == f"memory/goals/targets/{target}.json"
               for item in memory_report["experience_map"])
    assert result["receipt"]["memory_backfill"]["experience_map"] == memory_report["experience_map"]


def test_active_memory_backfill_is_manifest_bound_and_replay_safe(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    memory = source / "memory" / "goals" / "targets" / f"{target}.json"
    memory.parent.mkdir(parents=True, exist_ok=True)
    memory.write_text(json.dumps({"schema_version": 1, "target": target,
                                  "active_leads": [{"text": "compare tenant owners", "ts": "2026-09-01T00:00:00Z"}],
                                  "dead_ends": [{"text": "old denial", "conditions": "same session",
                                                 "reopen_when": "new session"}]}), encoding="utf-8")
    original = migration._import_target_memory
    monkeypatch.setattr(migration, "_import_target_memory", lambda *args: None)
    active = tmp_path / "active"
    import_target_staged(source, active, target)
    monkeypatch.setattr(migration, "_import_target_memory", original)
    promote_target(active, target)
    store = TargetStore(active, target)
    before = store.binding()["revision"]
    first = backfill_target_memory(source, active, target)
    assert first["status"] == "complete"
    assert len(first["experience_map"]) == 2
    assert store.binding()["revision"] == before + 2
    assert store.experience(first["experience_map"][1]["experience_id"])["kind"] == "note"
    assert backfill_target_memory(source, active, target) == first
    assert store.binding()["revision"] == before + 2
    assert migration.main(["--repo-root", str(active), "--target", target,
                           "--backfill-memory-source", str(source), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["experience_map"] == first["experience_map"]
    receipt = json.loads((active / "state" / target / "migration-receipt.json").read_text())
    assert receipt["memory_backfill"] == {key: first[key] for key in
                                           ("source_manifest_sha256", "source_sha256", "experience_map", "quarantined")}
    memory.write_text(memory.read_text().replace("old denial", "changed denial"), encoding="utf-8")
    with pytest.raises(StoreError, match="does not match the source manifest"):
        backfill_target_memory(source, active, target)
    assert store.binding()["revision"] == before + 2


def test_active_memory_backfill_requires_source_in_cutover_manifest(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    active = tmp_path / "active"
    import_target_staged(source, active, target)
    promote_target(active, target)

    with pytest.raises(StoreError, match="source is absent from migration manifest"):
        backfill_target_memory(source, active, target)
    assert TargetStore(active, target).page("experiences")["items"] == []
    receipt = json.loads((active / "state" / target / "migration-receipt.json").read_text())
    assert "memory_backfill" not in receipt


def test_active_memory_backfill_recovers_after_store_write_before_receipt(tmp_path, monkeypatch):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    memory = source / "memory" / "goals" / "targets" / f"{target}.json"
    memory.parent.mkdir(parents=True)
    memory.write_text(json.dumps({"schema_version": 1, "target": target,
                                  "active_leads": [{"text": "compare owner"}, {"text": "compare peer"}]}))
    original = migration._import_target_memory
    monkeypatch.setattr(migration, "_import_target_memory", lambda *args: None)
    active = tmp_path / "active"
    import_target_staged(source, active, target)
    monkeypatch.setattr(migration, "_import_target_memory", original)
    promote_target(active, target)
    store = TargetStore(active, target)
    before = store.binding()["revision"]

    saved = migration.TargetStore.remember
    calls = 0

    def interrupt_mid_import(self, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("interrupted during import")
        return saved(self, **kwargs)

    monkeypatch.setattr(migration.TargetStore, "remember", interrupt_mid_import)
    with pytest.raises(RuntimeError, match="during import"):
        backfill_target_memory(source, active, target)
    assert store.binding()["revision"] == before + 1
    monkeypatch.setattr(migration.TargetStore, "remember", saved)

    def interrupt_after_import(*args):
        original(*args)
        raise RuntimeError("interrupted before receipt publication")

    monkeypatch.setattr(migration, "_import_target_memory", interrupt_after_import)
    with pytest.raises(RuntimeError, match="interrupted"):
        backfill_target_memory(source, active, target)
    assert store.binding()["revision"] == before + 2
    receipt_path = active / "state" / target / "migration-receipt.json"
    assert "memory_backfill" not in json.loads(receipt_path.read_text())

    monkeypatch.setattr(migration, "_import_target_memory", original)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(backfill_target_memory, source, active, target) for _ in range(2)]
        results = [future.result(timeout=10) for future in futures]
    assert results[0] == results[1]
    assert len(results[0]["experience_map"]) == 2
    assert store.binding()["revision"] == before + 2
    assert json.loads(receipt_path.read_text())["memory_backfill"]["experience_map"] == results[0]["experience_map"]


def test_pattern_backfill_preserves_target_history_without_cross_target_recall(tmp_path):
    from tools.experience_recall import build_recall_view

    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    pattern_path = source / "hunt-memory" / "patterns.jsonl"
    pattern_path.parent.mkdir(parents=True)
    base = {"schema_version": 1, "target": target, "vuln_class": "idor", "tech_stack": ["node"]}
    rows = [
        {**base, "ts": "2026-09-01T00:00:00Z", "technique": "owner swap", "outcome": "helped"},
        {**base, "target": "other.test", "ts": "2026-09-01T00:00:01Z", "technique": "other private"},
    ]
    later = {**base, "ts": "2026-09-01T00:00:02Z", "technique": "late intact"}
    pattern_path.write_bytes(("\n".join(json.dumps(row) for row in rows) + "\nnot-json\n42\n").encode()
                             + b"\xff\n" + (json.dumps(later) + "\n").encode())
    backup = pattern_path.with_suffix(".jsonl.1")
    backup.write_text(json.dumps({**base, "ts": "2026-08-01T00:00:00Z",
                                  "technique": "stale claim", "outcome": "false-positive"}) + "\n")
    active = tmp_path / "active"
    import_target_staged(source, active, target)
    promote_target(active, target)
    store = TargetStore(active, target)
    before = store.binding()["revision"]

    result = backfill_target_patterns(source, active, target)
    assert result["status"] == "partial" and len(result["experience_map"]) == 3
    assert result["quarantined"] == [
        {"source_path": "hunt-memory/patterns.jsonl", "line": 3, "reason": "PatternDB row is not JSON"},
        {"source_path": "hunt-memory/patterns.jsonl", "line": 4, "reason": "PatternDB row has no target identity"},
        {"source_path": "hunt-memory/patterns.jsonl", "line": 5, "reason": "PatternDB row is not UTF-8"},
    ]
    assert store.binding()["revision"] == before + 3
    for item in result["experience_map"]:
        line = (source / item["source_path"]).read_bytes().split(b"\n")[item["line"] - 1]
        assert hashlib.sha256(line).hexdigest() == item["source_line_sha256"]
    assert all(store.experience(item["experience_id"])["kind"] == "note"
               for item in result["experience_map"])
    view = build_recall_view(active, target=target, kinds=["note"])
    texts = [entry["text"] for entry in view["target_entries"]]
    assert any("owner swap" in text for text in texts)
    assert any("stale claim" in text for text in texts)
    assert any("late intact" in text for text in texts)
    assert "other private" not in json.dumps(view)
    assert backfill_target_patterns(source, active, target) == result
    assert store.binding()["revision"] == before + 3
    receipt = json.loads((active / "state" / target / "migration-receipt.json").read_text())
    assert receipt["pattern_backfill"]["experience_map"] == result["experience_map"]
    pattern_path.write_bytes(pattern_path.read_bytes() + b"\n")
    with pytest.raises(StoreError, match="does not match the pinned source"):
        backfill_target_patterns(source, active, target)


def test_pattern_backfill_resumes_pending_receipt_after_partial_store_write(tmp_path, monkeypatch):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    path = source / "hunt-memory" / "patterns.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text("\n".join(json.dumps({"schema_version": 1, "target": target,
                                            "ts": f"2026-09-01T00:00:0{index}Z", "vuln_class": "idor",
                                            "technique": f"attempt {index}", "tech_stack": ["node"]})
                              for index in range(2)) + "\n")
    active = tmp_path / "active"
    import_target_staged(source, active, target)
    promote_target(active, target)
    store = TargetStore(active, target)
    before = store.binding()["revision"]
    saved = migration.TargetStore.remember
    calls = 0

    def fail_second(self, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("interrupted")
        return saved(self, **kwargs)

    monkeypatch.setattr(migration.TargetStore, "remember", fail_second)
    with pytest.raises(RuntimeError, match="interrupted"):
        backfill_target_patterns(source, active, target)
    receipt_path = active / "state" / target / "migration-receipt.json"
    assert json.loads(receipt_path.read_text())["pattern_backfill"]["status"] == "pending"
    assert store.binding()["revision"] == before + 1
    monkeypatch.setattr(migration.TargetStore, "remember", saved)
    result = backfill_target_patterns(source, active, target)
    assert result["status"] == "complete" and len(result["experience_map"]) == 2
    assert store.binding()["revision"] == before + 2


def test_memory_import_quarantines_polluted_row_without_losing_valid_advice(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    memory = source / "memory" / "goals" / "targets" / f"{target}.json"
    memory.parent.mkdir(parents=True, exist_ok=True)
    memory.write_text(json.dumps({"schema_version": 1, "target": target,
                                  "active_leads": [{"text": "valid lead"},
                                                   {"text": "{'schema_version': 1, 'echo': True}"}]}), encoding="utf-8")
    result = import_target_staged(source, tmp_path / "stage", target)
    assert result["status"] == "partial"
    assert result["legacy"]["target_memory"]["imported_experiences"] == 1
    assert any(row.get("field") == "active_leads" and row.get("position") == 1
               for row in result["quarantined"])


def test_memory_import_requires_exact_live_observation_and_entry_target(tmp_path):
    target = "target.test"
    source, active = tmp_path / "source", tmp_path / "active"
    store = TargetStore(active, target)
    store.initialize()
    artifact = active / "evidence" / target / "response.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("HTTP 403", encoding="utf-8")
    store.start_attempt(attempt_id="attempt-1", source="native", started_at="2026-09-23T00:00:00Z",
                        actor="operator")
    operation = store.record_execution(
        attempt_id="attempt-1", outcome="complete", actor="operator",
        observations=[{"endpoint": f"https://{target}/api/x", "method": "GET", "family": "authz",
                       "observed_at": "2026-09-23T00:00:00Z", "description": "Peer denied",
                       "artifacts": {"response": artifact.relative_to(active).as_posix()},
                       "state_changing": False}],
    )["entity_id"]
    memory = source / "memory" / "goals" / "targets" / f"{target}.json"
    memory.parent.mkdir(parents=True)
    memory.write_text(json.dumps({"schema_version": 1, "target": target,
                                  "dead_ends": [{"text": "peer read denied", "conditions": "same tenant",
                                                 "reopen_when": "new peer session",
                                                 "evidence_refs": [f"{operation}:0"]},
                                                {"text": "foreign note", "target": "other.test"}]}), encoding="utf-8")
    report = {"legacy": {"target_memory": {"status": "valid"}}, "quarantined": []}
    migration._import_target_memory(report, store, source, target, migration._migration_manifest(source, target))
    mapping = report["legacy"]["target_memory"]["experience_map"]
    assert len(mapping) == 1 and mapping[0]["evidence_status"] == "bound"
    saved = store.experience(mapping[0]["experience_id"])
    assert saved["kind"] == "negative" and saved["evidence"] == [{"operation_id": operation, "step": 0}]
    assert report["quarantined"][0]["reason"] == "historical entry declares another target"


def test_case_private_session_material_is_staged_and_rebound(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    private = {"schema_version": 1, "target": target, "session_id": "sess_a",
               "actor": "user_a", "kind": "bearer", "headers": {"Authorization": "Bearer fixture-secret"}}
    private["content_sha256"] = hashlib.sha256(
        json.dumps(private, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    private_ref = f".private/case-state/{target}/sessions/sess_a-{private['content_sha256'][:16]}.json"
    material = source / private_ref
    material.parent.mkdir(parents=True)
    material.write_text(json.dumps(private))
    material.chmod(0o600)
    (source / "state" / target / "case_state.json").write_text(json.dumps({
        "schema_version": 1, "target": target,
        "actors": {"user_a": {"role": "user"}},
        "sessions": {"sess_a": {"actor": "user_a", "kind": "bearer", "private_ref": private_ref}},
        "objects": {}, "hypotheses": [], "validation_backlog": [],
    }))

    staged = tmp_path / "staging-root"
    result = import_target_staged(source, staged, target)

    assert result["legacy"]["case_context_import"] == {
        "actors": 1, "sessions": 1, "objects": 0, "hypotheses": 0, "quarantined": 0,
    }
    migrated = TargetStore(staged, target).case_state()
    private_ref = migrated["sessions"]["sess_a"]["private_ref"]
    assert private_ref.startswith(f".private/case-state/{target}/")
    assert (staged / private_ref).is_file()
    assert "fixture-secret" not in json.dumps(TargetStore(staged, target).case_state())


def test_preview_marks_corrupt_target_memory_partial_without_creating_store(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    memory = source / "memory" / "goals" / "targets" / f"{target}.json"
    memory.parent.mkdir(parents=True, exist_ok=True)
    memory.write_text("{broken", encoding="utf-8")

    result = preview_target(source, target)

    assert result["status"] == "partial"
    assert any(row["owner"] == "target-memory" for row in result["quarantined"])
    assert not (source / "state" / target / "metadata.sqlite3").exists()


def test_unreferenced_raw_artifact_is_preserved_without_metadata_registration(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    raw = source / "evidence" / target / "orphan-response.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("raw material without a ledger registration\n", encoding="utf-8")

    staged = tmp_path / "staging-root"
    result = import_target_staged(source, staged, target)

    assert result["imported"]["artifacts"] == 0
    assert result["legacy"]["unreferenced_material"]["count"] == 1
    copied = staged / "evidence" / target / "orphan-response.txt"
    assert copied.read_text(encoding="utf-8") == raw.read_text(encoding="utf-8")


def test_published_preview_without_database_is_not_mistaken_for_legacy(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    (published / "state" / target / "metadata.sqlite3").unlink()
    with pytest.raises(StoreError, match="published preview store missing"):
        target_backend(published, target)


def test_promote_rejects_corrupt_database_without_falling_back(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    database = published / "state" / target / "metadata.sqlite3"
    database.write_bytes(b"not sqlite")
    with pytest.raises(StoreError, match="target store failure"):
        promote_target(published, target)
    assert not (published / "state" / target / "legacy-frozen.json").exists()


def test_publish_failure_keeps_private_staging_unpublished(tmp_path, monkeypatch):
    import tools.target_migration as migration

    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    import_target_staged(source, staged, target)
    published = tmp_path / "published-root"

    def interrupted_replace(*_args, **_kwargs):
        raise OSError("simulated publish interruption")

    monkeypatch.setattr(migration.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="simulated publish interruption"):
        publish_preview(staged, published, target)
    assert staged.is_dir() and not published.exists()


def test_fence_written_before_activation_blocks_preview_fallback(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    staged = tmp_path / "staging-root"
    result = import_target_staged(source, staged, target)
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    store = TargetStore(published, target, allow_preview=True)
    store._create_fence(result["receipt"]["store_id"], result["receipt"]["source_manifest_sha256"])
    with pytest.raises(StoreError, match="backend cutover incomplete"):
        target_backend(published, target)
    with pytest.raises(StoreError, match="backend cutover incomplete"):
        promote_target(published, target)


def test_complete_disposition_ledger_clears_quarantine_and_completes_staged_receipt(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[{
        "id": "AQ-terminal", "status": "validated", "action": "historical verdict",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    manifest = migration._migration_manifest(source, target)
    row = {
        "owner": "queue",
        "id": "AQ-terminal",
        "reason": "legacy status validated is a terminal verdict with no unambiguous mapping into the action state machine; intent and verdict preserved",
    }
    items = []
    items.append({
        **{field: row.get(field, "") for field in migration._QUARANTINE_ID_FIELDS},
        "quarantine_id": quarantine_id(row),
        "allowed_decisions": ["preserve_verdict"],
        "decision": "preserve_verdict",
        "operator": "OWNER",
        "decision_ref": "migration-review-1",
    })
    ledger = {
        "schema_version": 1,
        "kind": "target_cutover_quarantine_disposition_ledger",
        "status": "complete",
        "target": target,
        "source_manifest_sha256": manifest["sha256"],
        "quarantine_roster_sha256": migration.quarantine_roster([row])[1],
        "items": items,
    }

    result = import_target_staged(source, tmp_path / "staging", target, disposition_ledger=ledger)

    assert result["status"] == "ready"
    assert result["quarantined"] == []
    assert result["dispositioned_quarantine"]
    assert result["receipt"]["status"] == "complete"
    assert result["receipt"]["disposition_ledger"]["status"] == "complete"
    assert TargetStore(tmp_path / "staging", target).page("actions")["items"] == []

    incomplete_item = {**items[0], "operator": "OWNER", "decision_ref": "PENDING"}
    with pytest.raises(StoreError, match="non-placeholder decision_ref"):
        import_target(source, target, disposition_ledger={**ledger, "items": [incomplete_item]})


def test_missing_disposition_row_keeps_import_partial(tmp_path):
    target = _fixture(tmp_path, actions=[{
        "id": "AQ-terminal", "status": "validated", "action": "historical verdict",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    manifest = migration._migration_manifest(tmp_path, target)
    result = import_target(tmp_path, target, disposition_ledger={
        "target": target,
        "source_manifest_sha256": manifest["sha256"],
        "items": [],
    })
    assert result["status"] == "partial"
    assert result["quarantined"]
    assert result["disposition_ledger"]["missing"]


def test_disposition_ledger_rejects_pending_and_binding_mismatch(tmp_path):
    target = _fixture(tmp_path, actions=[{
        "id": "AQ-terminal", "status": "validated", "action": "historical verdict",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    manifest = migration._migration_manifest(tmp_path, target)
    row = {
        "owner": "queue",
        "id": "AQ-terminal",
        "reason": "legacy status validated is a terminal verdict with no unambiguous mapping into the action state machine; intent and verdict preserved",
    }
    item = {
        **{field: row.get(field, "") for field in migration._QUARANTINE_ID_FIELDS},
        "quarantine_id": quarantine_id(row),
        "decision": "PENDING",
        "decision_ref": "PENDING",
    }
    with pytest.raises(StoreError, match="unsupported quarantine disposition"):
        import_target(tmp_path, target, disposition_ledger={
            "target": target,
            "source_manifest_sha256": manifest["sha256"],
            "items": [item],
        })
    with pytest.raises(StoreError, match="target does not match"):
        import_target(tmp_path, target, disposition_ledger={
            "target": "other.test",
            "source_manifest_sha256": manifest["sha256"],
            "items": [],
        })


def test_disposition_ledger_rejects_placeholder_operator(tmp_path):
    target = _fixture(tmp_path, actions=[{
        "id": "AQ-terminal", "status": "validated", "action": "historical verdict",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])
    manifest = migration._migration_manifest(tmp_path, target)
    row = {
        "owner": "queue",
        "id": "AQ-terminal",
        "reason": "legacy status validated is a terminal verdict with no unambiguous mapping into the action state machine; intent and verdict preserved",
    }
    item = {
        **{field: row.get(field, "") for field in migration._QUARANTINE_ID_FIELDS},
        "quarantine_id": quarantine_id(row),
        "decision": "preserve_verdict",
        "operator": "PENDING",
        "decision_ref": "migration-review-1",
    }
    with pytest.raises(StoreError, match="non-placeholder operator"):
        import_target(tmp_path, target, disposition_ledger={
            "target": target,
            "source_manifest_sha256": manifest["sha256"],
            "items": [item],
        })


_MISSING_CASE = object()


def _fixture(tmp_path, *, actions=(), findings=(), ledger=(), evidence=(), case_state=_MISSING_CASE):
    """Build one isolated legacy tree; every raw file is really written."""
    target = "target.test"
    key = "target.test"
    (tmp_path / "state" / key).mkdir(parents=True, exist_ok=True)
    (tmp_path / "findings" / key).mkdir(parents=True, exist_ok=True)
    (tmp_path / "memory" / "evidence" / key).mkdir(parents=True, exist_ok=True)
    (tmp_path / "state" / key / "action_queue.json").write_text(
        json.dumps({"schema_version": 1, "target": target, "actions": list(actions)}))
    (tmp_path / "findings" / key / "findings.json").write_text(
        json.dumps({"schema_version": 1, "target": target, "findings": list(findings)}))
    (tmp_path / "memory" / "evidence" / key / "ledger.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in ledger))
    if case_state is not _MISSING_CASE:
        (tmp_path / "state" / key / "case_state.json").write_text(
            case_state if isinstance(case_state, str) else json.dumps(case_state))
    for ref, payload in evidence:
        path = tmp_path / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return target


def _ledger_row(**over):
    row = {
        "schema_version": 1,
        "event_id": "ledger:aaaa",
        "target": "target.test",
        "endpoint": "/api/object",
        "raw_endpoint": "https://target.test/api/object",
        "method": "GET",
        "vuln_class": "Authz",
        "result": "tested_finding",
        "ts": "2026-01-01T00:00:00Z",
        "actor": "anonymous",
        "object_scope": "none",
        "variant": "replay",
        "evidence_ref": "evidence/target.test/validation/AQ-9/run/diff.json",
        "notes": "peer token read the same object",
        "state_changing": None,
        "redline_checked": False,
    }
    row.update(over)
    return row


def test_ledger_entry_imports_as_observation_with_raw_hash_and_bound_claim(tmp_path):
    payload = b'{"diff": "peer read"}'
    digest = hashlib.sha256(payload).hexdigest()
    target = _fixture(
        tmp_path,
        findings=[{"id": "F-9", "url": "https://target.test/api/object", "method": "GET",
                   "vuln_class": "Authz", "title": "claim", "summary": "peer read"}],
        ledger=[_ledger_row()],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", payload)],
    )

    result = import_target(tmp_path, target)

    assert result["imported"] == {"actions": 0, "findings": 1, "observations": 1, "artifacts": 1}
    assert result["legacy"]["observations"][0]["result"] == "tested_finding"
    assert result["legacy"]["finding_verdicts"] == [{
        "id": "F-9", "validation_status": "", "report_status": "", "claim_status": "",
        "confidence": "", "severity": "", "claim_revision": "", "source_file": "",
    }]

    (link,) = result["links"]
    store = TargetStore(tmp_path, target)
    expanded = store.execution(link["operation_id"])
    (observation,) = expanded["observations"]
    assert observation["endpoint"] == "https://target.test/api/object"
    assert observation["observed_at"] == "2026-01-01T00:00:00+00:00"
    assert observation["state_changing"] is None and observation["truncated"] == 0
    (artifact,) = observation["artifacts"]
    assert artifact["sha256"] == digest and artifact["ref"].endswith("run/diff.json")
    finding = store.finding("F-9")
    assert finding["evidence"] == [{"operation_id": link["operation_id"], "step": 0}]
    # A migrated claim carries no technical verdict: assessment stays the AI's job.
    assert finding["assessment"] is None


def test_duplicate_quarantine_rows_receive_distinct_disposition_ids(tmp_path):
    target = _fixture(tmp_path, ledger=[_ledger_row(event_id="", evidence_ref="")]*2)

    result = import_target(tmp_path, target)

    rows = [row for row in result["quarantined"] if row["owner"] == "ledger"]
    assert len(rows) == 2
    # Identical rows are told apart by occurrence, not by report position, so
    # the set of identities survives a reordering of the report.
    assert len(set(migration.quarantine_identities(rows))) == 2
    assert migration.quarantine_identities(rows) == migration.quarantine_identities(list(reversed(rows)))
    assert migration.quarantine_roster(rows)[1] == migration.quarantine_roster(list(reversed(rows)))[1]


def test_quarantine_identity_is_independent_of_report_order(tmp_path):
    target = _fixture(tmp_path, actions=[
        {"id": "AQ-1", "status": "validated", "action": "first verdict",
         "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"}},
        {"id": "AQ-2", "status": "rejected", "action": "second verdict",
         "metadata": {"endpoint": "https://target.test/api/thing", "vuln_class": "IDOR"}},
    ])

    rows = import_target(tmp_path, target)["quarantined"]
    assert len(rows) >= 2
    assert migration.quarantine_roster(rows)[1] == migration.quarantine_roster(list(reversed(rows)))[1]
    # Changing a reported fact still changes the identity.
    tampered = [dict(rows[0]), *rows[1:]]
    tampered[0]["reason"] = "different reason"
    assert migration.quarantine_roster(tampered)[1] != migration.quarantine_roster(rows)[1]


def _terminal_verdict_fixture(base):
    """Write one legacy terminal verdict into its own isolated root."""
    return _fixture(base, actions=[{
        "id": "AQ-terminal", "status": "validated", "action": "historical verdict",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])


def _probe_terminal_verdict(tmp_path):
    """Return (target, quarantine rows) for a fresh terminal-verdict root.

    A source root is consumed by an import, so the probe root and every target
    root are built separately and each is imported at most once.
    """
    target = _terminal_verdict_fixture(tmp_path / "probe")
    rows = import_target(tmp_path / "probe", target)["quarantined"]
    return target, rows


def _manifest_of(base, target):
    return migration._migration_manifest(base, target)["sha256"]


def test_disposition_ledger_roster_binding_rejects_a_rebound_decision_table(tmp_path):
    target, rows = _probe_terminal_verdict(tmp_path)
    _terminal_verdict_fixture(tmp_path / "clean")
    digest = _manifest_of(tmp_path / "clean", target)
    item = {
        **{field: rows[0].get(field, "") for field in migration._QUARANTINE_ID_FIELDS},
        "quarantine_id": migration.quarantine_identities(rows)[0],
        "decision": "permanent_quarantine",
        "operator": "OWNER",
        "decision_ref": "audit-1",
    }
    base = {
        "kind": "target_cutover_quarantine_disposition_ledger",
        "status": "complete",
        "target": target,
        "source_manifest_sha256": digest,
        "items": [item],
    }
    # Without a roster digest the payload stays usable for narrow callers.
    _terminal_verdict_fixture(tmp_path / "loose")
    assert import_target(tmp_path / "loose", target, disposition_ledger=base)["status"] == "ready"
    # A roster digest that does not describe this input is refused outright.
    _terminal_verdict_fixture(tmp_path / "stale")
    with pytest.raises(StoreError, match="quarantine roster does not match"):
        import_target(tmp_path / "stale", target, disposition_ledger={**base, "quarantine_roster_sha256": "0" * 64})


def test_operator_review_records_the_request_without_closing_the_gate(tmp_path):
    target, rows = _probe_terminal_verdict(tmp_path)
    _terminal_verdict_fixture(tmp_path / "review")
    digest = _manifest_of(tmp_path / "review", target)
    item = {
        **{field: rows[0].get(field, "") for field in migration._QUARANTINE_ID_FIELDS},
        "quarantine_id": migration.quarantine_identities(rows)[0],
        "decision": "operator_review",
        "operator": "OWNER",
        "decision_ref": "audit-1",
    }
    result = import_target(tmp_path / "review", target, disposition_ledger={
        "target": target, "source_manifest_sha256": digest, "items": [item],
    })
    # The request is recorded, the row stays quarantined, and publish is blocked.
    assert result["dispositioned_quarantine"] == []
    assert len(result["quarantined"]) == 1
    assert result["quarantined"][0]["recorded_decision"] == "operator_review"
    assert result["disposition_ledger"]["open"] == [item["quarantine_id"]]
    assert result["disposition_ledger"]["status"] == "partial"
    assert result["status"] == "partial"


def test_rebind_after_export_verification_is_recorded_but_not_terminal(tmp_path):
    target, rows = _probe_terminal_verdict(tmp_path)
    _terminal_verdict_fixture(tmp_path / "rebind")
    manifest = migration._migration_manifest(tmp_path / "rebind", target)
    item = {
        **{field: rows[0].get(field, "") for field in migration._QUARANTINE_ID_FIELDS},
        "quarantine_id": migration.quarantine_identities(rows)[0],
        "allowed_decisions": ["rebind_after_export_verification", "permanent_quarantine"],
        "decision": "rebind_after_export_verification",
        "operator": "OWNER",
        "decision_ref": "audit-1",
    }
    result = import_target(tmp_path / "rebind", target, disposition_ledger={
        "target": target, "source_manifest_sha256": manifest["sha256"], "items": [item],
    })
    # The decision the generated ledger advertises is accepted, but committing to
    # re-register missing evidence is unfinished work, so it cannot clear publish.
    assert len(result["quarantined"]) == 1
    assert result["dispositioned_quarantine"] == []
    assert result["status"] == "partial"


def test_disposition_ledger_governance_metadata_is_enforced(tmp_path):
    target, rows = _probe_terminal_verdict(tmp_path)
    item = {
        **{field: rows[0].get(field, "") for field in migration._QUARANTINE_ID_FIELDS},
        "quarantine_id": migration.quarantine_identities(rows)[0],
        "decision": "permanent_quarantine",
        "operator": "OWNER",
        "decision_ref": "audit-1",
    }

    def attempt(name, **over):
        _terminal_verdict_fixture(tmp_path / name)
        digest = _manifest_of(tmp_path / name, target)
        payload = {
            "kind": "target_cutover_quarantine_disposition_ledger",
            "status": "complete",
            "target": target,
            "source_manifest_sha256": digest,
            "items": [item],
            **over,
        }
        return import_target(tmp_path / name, target, disposition_ledger=payload)

    with pytest.raises(StoreError, match="is not finalized"):
        attempt("pending", status="pending")
    with pytest.raises(StoreError, match="count does not match"):
        attempt("count", count=99)
    with pytest.raises(StoreError, match="unexpected disposition ledger kind"):
        attempt("kind", kind="something-else")
    # A finalized ledger with matching governance metadata is accepted.
    assert attempt("ok", count=1)["status"] == "ready"


def test_staged_receipt_records_preserved_but_unregistered_report_artifacts(tmp_path):
    source = tmp_path / "source"
    target = _fixture(source, actions=[])
    report = source / "reports" / target / "idor_001.md"
    report.parent.mkdir(parents=True)
    report.write_text("report body\n", encoding="utf-8")

    result = import_target_staged(source, tmp_path / "staging", target)
    preserved = result["receipt"]["unregistered_artifacts"]
    assert preserved["report_artifacts"] == 1
    assert preserved["paths"] == [f"reports/{target}/idor_001.md"]
    assert "explicit re-registration" in preserved["note"]
    # The bytes stay preserved in staging; nothing is registered by inference.
    assert (tmp_path / "staging" / "reports" / target / "idor_001.md").read_text() == "report body\n"


def test_legacy_terminal_action_status_is_quarantined_not_promoted(tmp_path):
    target = _fixture(tmp_path, actions=[{
        "id": "AQ-9", "status": "validated", "action": "Compare object ownership", "priority": 7,
        "evidence": "ledger candidate", "next_question": "re-verify",
        "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"},
    }])

    result = import_target(tmp_path, target)

    assert result["imported"]["actions"] == 0
    assert TargetStore(tmp_path, target).page("actions")["items"] == []
    assert result["legacy"]["action_verdicts"] == [{
        "id": "AQ-9", "status": "validated", "endpoint": "https://target.test/api/object",
        "family": "Authz", "priority": 7, "next_question": "re-verify", "evidence": "ledger candidate",
    }]
    assert any(row["owner"] == "queue" and row["id"] == "AQ-9" and "terminal verdict" in row["reason"]
               for row in result["quarantined"])


def test_open_action_keeps_id_and_resolves_path_endpoint_from_single_origin(tmp_path):
    target = _fixture(
        tmp_path,
        actions=[{"id": "AQ-8", "status": "queued", "action": "probe object", "priority": 3,
                  "metadata": {"endpoint": "/api/object", "vuln_class": "Authz"}}],
        ledger=[_ledger_row()],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}")],
    )

    result = import_target(tmp_path, target)

    assert result["legacy"]["path_endpoint_origin"] == "https://target.test"
    assert result["imported"]["actions"] == 1
    (action,) = TargetStore(tmp_path, target).page("actions")["items"]
    assert action["id"] == "AQ-8" and action["endpoint"] == "https://target.test/api/object"
    assert action["status"] == "ready"


def test_path_endpoint_stays_quarantined_when_more_than_one_origin_was_observed(tmp_path):
    target = _fixture(
        tmp_path,
        actions=[{"id": "AQ-8", "status": "queued", "action": "probe object",
                  "metadata": {"endpoint": "/api/object", "vuln_class": "Authz"}}],
        ledger=[_ledger_row(),
                _ledger_row(event_id="ledger:bbbb", raw_endpoint="http://target.test/api/object",
                            evidence_ref="evidence/target.test/validation/AQ-9/run/other.json")],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}"),
                  ("evidence/target.test/validation/AQ-9/run/other.json", b"{}")],
    )

    result = import_target(tmp_path, target)

    assert result["legacy"]["path_endpoint_origin"] == ""
    assert result["imported"]["actions"] == 0
    assert any(row["owner"] == "queue" and row["id"] == "AQ-8" and row["reason"] == "missing endpoint or family"
               for row in result["quarantined"])


def test_evidence_reference_outside_the_isolated_copy_is_not_reinterpreted(tmp_path):
    target = _fixture(
        tmp_path,
        ledger=[_ledger_row(evidence_ref="/srv/other-host/evidence/target.test/validation/run/diff.json")],
    )

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 0
    assert any(row["owner"] == "ledger" and "outside the declared migration source root" in row["reason"]
               for row in result["quarantined"])
    assert result["legacy"].get("rebased_references") in (None, [])


def test_corrupt_jsonl_reports_the_row_and_accounts_for_the_unread_tail(tmp_path):
    target = _fixture(tmp_path, evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}")])
    ledger = tmp_path / "memory" / "evidence" / target / "ledger.jsonl"
    ledger.write_text(
        json.dumps(_ledger_row()) + "\n"
        + "{not json\n"
        + json.dumps(_ledger_row(event_id="ledger:tail", endpoint="/api/tail")) + "\n"
    )

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 1
    assert any(row.get("line") == 2 and row["owner"] == "ledger" for row in result["quarantined"])
    tail = [row for row in result["quarantined"] if "trusted prefix" in str(row.get("reason"))]
    assert len(tail) == 1 and "2 row(s)" in tail[0]["reason"]


def test_corrupt_queue_json_is_reported_not_read_as_an_empty_queue(tmp_path):
    target = _fixture(tmp_path)
    (tmp_path / "state" / target / "action_queue.json").write_text("{broken")

    result = import_target(tmp_path, target)

    assert result["imported"]["actions"] == 0
    assert any(row["owner"] == "queue" and "invalid action queue JSON" in row["reason"]
               for row in result["quarantined"])
    assert result["status"] == "partial"


def test_cross_target_records_are_reported_and_imported_by_nobody(tmp_path):
    target = _fixture(
        tmp_path,
        actions=[{"id": "AQ-1", "status": "queued", "action": "probe", "priority": 1,
                  "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"}}],
        ledger=[_ledger_row(target="other.test")],
    )
    queue_path = tmp_path / "state" / target / "action_queue.json"
    payload = json.loads(queue_path.read_text())
    payload["target"] = "other.test"
    queue_path.write_text(json.dumps(payload))

    result = import_target(tmp_path, target)

    assert result["imported"] == {"actions": 0, "findings": 0, "observations": 0, "artifacts": 0}
    assert {row["owner"] for row in result["legacy"]["target_conflicts"]} == {"queue", "ledger"}
    reasons = " ".join(str(row["reason"]) for row in result["quarantined"])
    assert "imported by nobody" in reasons and "record declares target other.test" in reasons
    # A conflicting record is not allowed to set the target's single observed origin.
    assert result["legacy"]["observed_origins"] == []


def test_unknown_fields_and_sensitive_metadata_are_reported_without_values(tmp_path):
    target = _fixture(
        tmp_path,
        actions=[{"id": "AQ-1", "status": "queued", "action": "probe", "priority": 1,
                  "future_field": "schema drift",
                  "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz",
                               "access_token": "tok-123"}}],
    )

    result = import_target(tmp_path, target)

    assert result["legacy"]["unknown_fields"]["queue"] == {"future_field": 1}
    assert result["legacy"]["sensitive_metadata"] == [
        {"owner": "queue", "id": "AQ-1", "keys": ["metadata.access_token"]},
    ]
    # The key is reported; the value never leaves the legacy file.
    assert "tok-123" not in json.dumps(result)
    assert result["imported"]["actions"] == 1


def test_private_secret_reference_is_quarantined_and_never_hashed(tmp_path):
    payload = b"session material must never reach the store"
    target = _fixture(
        tmp_path,
        ledger=[_ledger_row(evidence_ref=".private/browser/target.test/run/storage.json")],
        evidence=[(".private/browser/target.test/run/storage.json", payload)],
    )

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 0 and result["imported"]["artifacts"] == 0
    assert any(row["owner"] == "ledger" and "private secret material" in row["reason"]
               for row in result["quarantined"])
    assert payload.decode() not in json.dumps(result)


def test_live_credential_in_free_text_is_quarantined_not_copied(tmp_path):
    target = _fixture(
        tmp_path,
        ledger=[_ledger_row(notes="captured Authorization: Bearer "
                                   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature")],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}")],
    )

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 0
    assert any("live credential material" in str(row.get("reason")) for row in result["quarantined"])


def test_secret_shaped_evidence_file_is_flagged_but_still_a_real_observation(tmp_path):
    target = _fixture(
        tmp_path,
        ledger=[_ledger_row(evidence_ref="evidence/target.test/validation/AQ-9/run/admin_token.txt")],
        evidence=[("evidence/target.test/validation/AQ-9/run/admin_token.txt", b"tok=abc")],
    )

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 1
    (flag,) = result["legacy"]["secret_material_refs"]
    assert flag["ref"].endswith("admin_token.txt") and "content was never copied" in flag["note"]


def test_unreferenced_raw_material_is_listed_without_being_imported(tmp_path):
    target = _fixture(
        tmp_path,
        ledger=[_ledger_row()],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}"),
                  ("evidence/target.test/probe/orphan.json", b"{}")],
    )

    result = import_target(tmp_path, target)

    material = result["legacy"]["unreferenced_material"]
    assert material["count"] == 1
    assert material["sample"] == ["evidence/target.test/probe/orphan.json"]
    assert material["without_referenced_neighbour"] == 1
    assert material["without_referenced_neighbour_sample"] == ["evidence/target.test/probe/orphan.json"]
    store = TargetStore(tmp_path, target)
    operation_id = result["legacy"]["observations"][0]["operation_id"]
    assert [item["ref"] for item in store.execution(
        operation_id)["observations"][0]["artifacts"]] == \
        ["evidence/target.test/validation/AQ-9/run/diff.json"]


def _file_side_projection(*rows):
    """Project raw ledger rows the way the file-side Ledger does."""
    from tools.closure_projection import build_current_cell_projection

    return build_current_cell_projection([dict(row) for row in rows])


def _store_side_projection(tmp_path, target):
    from tools.closure_projection import build_current_cell_projection

    return build_current_cell_projection(TargetStore(tmp_path, target).closure_records()["records"])


def _closed_shape(projection):
    """What a projection closes, compared by semantics rather than by timestamp."""
    return sorted(
        (cell["endpoint"], cell["vuln_class"], cell["result"])
        for cell in projection["closed_cells"]
    )


def _closed_v2_shape(projection):
    return sorted(
        (json.dumps(cell["identity_v2"], sort_keys=True), cell["result"])
        for cell in projection["closed_cells_v2"]
    )


def test_plain_record_still_closes_its_endpoint_cell_after_migration(tmp_path):
    """A record that made no identity claim keeps authoring the endpoint cell.

    This is the migration's closure guarantee: the store's legacy view closes
    exactly the cells the file-side legacy view closed.
    """
    rows = [_ledger_row()]
    target = _fixture(tmp_path, ledger=rows,
                      evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}")])

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 1
    assert result["legacy"]["identity_carry"]["partial_identities_carried"] == 0
    assert TargetStore(tmp_path, target).closure_records()["records"][0]["identity_dimensions"] == {}

    file_side = _file_side_projection(*rows)
    store_side = _store_side_projection(tmp_path, target)
    assert _closed_shape(store_side) == _closed_shape(file_side) == [("/api/object", "Authz", "tested_finding")]
    assert store_side["closed_cells_v2"] == file_side["closed_cells_v2"] == []


def test_terminal_verdict_and_complete_identity_survive_the_import(tmp_path):
    """A migrated record keeps the verdict and identity the Ledger closed with."""
    payload = b'{"diff": "peer read"}'
    row = _ledger_row(
        result="tested_clean",
        identity_status="complete",
        identity_v2={
            "schema_version": 2, "kind": "closure_cell",
            "endpoint": {"schema_version": 2, "kind": "endpoint", "endpoint": "/api/object"},
            "family": "Authz", "technique": "authz",
            "dimensions": {"method": "GET", "actor_role": "anonymous", "object_scope": "none"},
        },
    )
    target = _fixture(tmp_path, ledger=[row],
                      evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", payload)])

    result = import_target(tmp_path, target)

    assert result["legacy"]["identity_carry"] == {
        "records_with_complete_identity": 1, "partial_identities_carried": 0,
        "uncarryable_identity_claims": 0,
        "results_carried": 1, "results_outside_shared_vocabulary": 0,
    }
    store = TargetStore(tmp_path, target)
    (record,) = store.closure_records()["records"]
    assert record["result"] == "tested_clean"
    assert record["identity_dimensions"] == {"method": "GET", "actor_role": "anonymous", "object_scope": "none"}

    store_side = _store_side_projection(tmp_path, target)
    file_side = _file_side_projection(row)
    assert _closed_v2_shape(store_side) == _closed_v2_shape(file_side)
    assert store_side["closed_cells_v2"][0]["identity_v2"] == row["identity_v2"]
    assert store_side["closed_cells"] == file_side["closed_cells"] == []


def test_partial_identity_is_carried_as_facts_and_stays_open(tmp_path):
    """A partial identity keeps its own dimensions; nothing fills the gap.

    The record carries actor/object_scope fields an alias table could map onto
    the missing dimensions; they are deliberately not used, because that would
    close a cell the Ledger left open.
    """
    rows = [_ledger_row(
        result="tested_clean",
        identity_status="incomplete",
        identity_missing_fields=["method", "object_scope"],
        identity_dimensions={"actor_role": "anonymous"},
    )]
    target = _fixture(tmp_path, ledger=rows,
                      evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}")])

    result = import_target(tmp_path, target)

    assert result["legacy"]["identity_carry"] == {
        "records_with_complete_identity": 0, "partial_identities_carried": 1,
        "uncarryable_identity_claims": 0,
        "results_carried": 1, "results_outside_shared_vocabulary": 0,
    }
    record = TargetStore(tmp_path, target).closure_records()["records"][0]
    assert record["identity_dimensions"] == {"actor_role": "anonymous"}

    store_side = _store_side_projection(tmp_path, target)
    file_side = _file_side_projection(*rows)
    assert store_side["closed_cells"] == file_side["closed_cells"] == []
    assert store_side["closed_cells_v2"] == file_side["closed_cells_v2"] == []
    assert store_side["identity_v2_diagnostics"]["incomplete_count"] == 1


def test_identity_verdict_without_its_dimensions_is_quarantined(tmp_path):
    """A conflicting identity verdict cannot be represented, so it is reported.

    Importing it as a plain observation would make the store close a cell the
    Ledger left open, so the record is quarantined instead of flattened.
    """
    rows = [_ledger_row(result="tested_clean", identity_status="conflict",
                        identity_conflicts=["method_mismatch"])]
    target = _fixture(tmp_path, ledger=rows,
                      evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"{}")])

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 0
    assert result["legacy"]["identity_carry"]["uncarryable_identity_claims"] == 1
    assert any(row["owner"] == "ledger" and "would close a cell the Ledger left open" in row["reason"]
               for row in result["quarantined"])
    assert TargetStore(tmp_path, target).closure_records()["records"] == []
    assert _file_side_projection(*rows)["closed_cells"] == []


def test_verdict_outside_the_shared_vocabulary_is_reported_not_improvised(tmp_path):
    payload = b"{}"
    row = _ledger_row(result="looks-promising")
    target = _fixture(tmp_path, ledger=[row],
                      evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", payload)])

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 1
    assert result["legacy"]["identity_carry"] == {
        "records_with_complete_identity": 0, "partial_identities_carried": 0,
        "uncarryable_identity_claims": 0,
        "results_carried": 0, "results_outside_shared_vocabulary": 1,
    }
    store = TargetStore(tmp_path, target)
    assert store.closure_records()["records"][0]["result"] == ""


def test_refused_record_leaves_a_reported_gap_not_a_silent_one(tmp_path):
    """A refused row is not closed later by some other path, and it is listed.

    The parity property the sandbox measurement checks: every cell the store
    does not close corresponds to a refusal the report names.
    """
    rows = [_ledger_row(endpoint="/api/other", raw_endpoint="https://target.test/api/other",
                        evidence_ref="")]
    target = _fixture(tmp_path, ledger=rows)

    result = import_target(tmp_path, target)

    assert result["imported"]["observations"] == 0
    assert result["legacy"]["observations"] == []
    assert any(row["owner"] == "ledger" and "no raw evidence reference" in row["reason"]
               for row in result["quarantined"])
    # The file side did close that cell; the store refuses to close what it
    # could not bind, and the difference is stated rather than hidden.
    assert _closed_shape(_file_side_projection(*rows)) == [("/api/other", "Authz", "tested_finding")]
    assert _closed_shape(_store_side_projection(tmp_path, target)) == []


def _case_payload(*, backlog=(), hypotheses=(), actors=None, sessions=None, objects=None, **over):
    payload = {
        "schema_version": 1,
        "target": "target.test",
        "target_key": "target.test",
        "actors": actors if actors is not None else {},
        "sessions": sessions if sessions is not None else {},
        "objects": objects if objects is not None else {},
        "hypotheses": list(hypotheses),
        # 原样写入：形状错误（比如 dict）也是迁移事实，不能被 helper 修好。
        "validation_backlog": backlog,
    }
    payload.update(over)
    return payload


def test_case_context_is_reported_and_legacy_backlog_is_carried_as_verdicts(tmp_path):
    """Case 只剩上下文事实；旧待办以原裁决进入报告，不生成第二条 action。"""
    target = _fixture(
        tmp_path,
        case_state=_case_payload(
            actors={"user_a": {"role": "user"}, "user_b": {"role": "user"}},
            sessions={"sess_a": {"actor": "user_a"}},
            objects={"order_123": {"type": "order", "object_id": "123"}},
            hypotheses=[
                {"id": "hyp_001", "status": "open", "vuln_class": "IDOR"},
                {"id": "hyp_002", "status": "answered", "vuln_class": "Authz"},
            ],
            backlog=[
                {"id": "val_001", "status": "tested_clean", "endpoint": "/api/object",
                 "vuln_class": "Authz", "runner": "request-diff", "priority": "high",
                 "evidence_ref": "evidence/target.test/validation/AQ-9/run/diff.json"},
                {"id": "val_002", "status": "pending", "endpoint": "/api/other",
                 "runner": "idor-actor-pair", "priority": "medium"},
            ],
        ),
    )

    result = import_target(tmp_path, target)

    assert result["sources"]["case_state"].endswith("state/target.test/case_state.json")
    assert result["legacy"]["case_context"] == {
        "present": True, "actors": 2, "sessions": 1, "objects": 1,
        "hypotheses": 2, "open_hypotheses": 1, "backlog_records": 2, "backlog_shape": "list",
    }
    assert [row["id"] for row in result["legacy"]["case_backlog"]] == ["val_001", "val_002"]
    verdict = result["legacy"]["case_backlog"][0]
    assert verdict["status"] == "tested_clean"
    assert verdict["family"] == "Authz"
    # 家族缺失时按旧 runner 表恢复；表外 runner 不猜。
    assert result["legacy"]["case_backlog"][1]["family"] == "IDOR"
    # 旧裁决冲突搬进报告：Case 不再替 canonical finding owner 裁决。
    assert result["imported"]["actions"] == 0
    assert not TargetStore(tmp_path, target).page("actions")["items"]
    context = TargetStore(tmp_path, target).case_context()
    assert {item["id"] for item in context["actors"]} == {"user_a", "user_b"}
    assert {item["id"] for item in context["sessions"]} == {"sess_a"}
    assert {item["ref"] for item in context["objects"]} == {"order_123"}
    assert {item["id"] for item in context["hypotheses"]} == {"hyp_001", "hyp_002"}
    assert result["legacy"]["case_context_import"] == {
        "actors": 2, "sessions": 1, "objects": 1, "hypotheses": 2, "quarantined": 0,
    }
    assert any(
        row["owner"] == "case-state" and "text similarity" in row["reason"]
        for row in result["quarantined"]
    )


def test_case_backlog_relation_requires_an_explicit_id_never_text_similarity(tmp_path):
    target = _fixture(
        tmp_path,
        actions=[
            {"id": "val_001", "status": "queued", "action": "Replay owner/peer read",
             "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz"}},
            {"id": "AQ-7", "status": "queued", "action": "Replay the same dimension",
             "metadata": {"endpoint": "https://target.test/api/object", "vuln_class": "Authz",
                          "backlog_id": "val_002"}},
        ],
        case_state=_case_payload(backlog=[
            {"id": "val_001", "status": "pending", "endpoint": "https://target.test/api/object",
             "vuln_class": "Authz", "runner": "request-diff"},
            {"id": "val_002", "status": "pending", "endpoint": "https://target.test/api/object",
             "vuln_class": "Authz", "runner": "request-diff"},
            {"id": "val_003", "status": "pending", "endpoint": "https://target.test/api/object",
             "vuln_class": "Authz", "runner": "request-diff"},
        ]),
    )

    result = import_target(tmp_path, target)

    relations = result["legacy"]["case_backlog_relations"]
    assert {row["backlog_id"]: row["action_id"] for row in relations if "action_id" in row} == {
        "val_001": "val_001", "val_002": "AQ-7",
    }
    # val_001 的记录里显式写着同样的 endpoint/家族，但那不是身份：只有旧文件里
    # 写下的相等 id 才算关联，文本相似一律降级为需要显式决定的候选。
    candidates = [row for row in relations if row.get("basis") == "endpoint-candidate"]
    assert [row["backlog_id"] for row in candidates] == ["val_003"]
    assert candidates[0]["action_ids"] == ["val_001", "AQ-7"]
    assert candidates[0]["candidate_family_match"] == ["yes"]
    assert candidates[0]["requires_explicit_decision"] is True
    assert "action_id" not in candidates[0]


def test_endpoint_candidate_survives_an_unknown_family_on_either_side(tmp_path):
    """家族未知不是合并许可也不是丢弃理由：候选照报，标成 unknown 等显式决定。"""
    target = _fixture(
        tmp_path,
        actions=[{"id": "AQ-9", "status": "queued", "action": "Replay the tracked order",
                  "metadata": {"url": "https://target.test/api/object"}}],
        case_state=_case_payload(backlog=[
            {"id": "val_001", "status": "pending", "endpoint": "https://target.test/api/object",
             "vuln_class": "IDOR", "runner": "idor-actor-pair"},
        ]),
    )

    result = import_target(tmp_path, target)

    assert result["legacy"]["case_backlog"][0]["family"] == "IDOR"
    candidates = [row for row in result["legacy"]["case_backlog_relations"]
                  if row.get("basis") == "endpoint-candidate"]
    assert candidates == [{
        "backlog_id": "val_001", "action_ids": ["AQ-9"],
        "candidate_family_match": ["unknown"],
        "basis": "endpoint-candidate", "requires_explicit_decision": True,
    }]


def test_case_backlog_verdict_conflict_with_final_claim_is_reported(tmp_path):
    """旧 Case 的"干净"裁决撞上 canonical 终态 claim：只报告，不改任一方的状态。"""
    finding = {
        "id": "F-1", "url": "https://target.test/api/object", "vuln_class": "Authz",
        "validation_status": "validated",
    }
    target = _fixture(
        tmp_path,
        findings=[finding],
        case_state=_case_payload(backlog=[
            {"id": "val_001", "status": "tested_clean", "endpoint": "https://target.test/api/object",
             "vuln_class": "Authz", "runner": "request-diff"},
            {"id": "val_002", "status": "dead_end", "endpoint": "https://target.test/api/other",
             "vuln_class": "Authz", "runner": "request-diff"},
        ]),
    )

    result = import_target(tmp_path, target)

    conflicts = result["legacy"]["case_backlog_conflicts"]
    assert [row["backlog_id"] for row in conflicts] == ["val_001"]
    assert conflicts[0]["finding_ids"] == ["F-1"]
    assert conflicts[0]["status"] == "tested_clean"
    # 冲突被报告而不是被裁决：canonical finding 行保持原状。
    stored = TargetStore(tmp_path, target).page("findings")["items"]
    assert all(row["id"] != "F-1" for row in stored)


def test_unreadable_case_state_is_reported_not_read_as_empty_context(tmp_path):
    target = _fixture(tmp_path, case_state="{broken")

    result = import_target(tmp_path, target)

    assert result["legacy"]["case_context"]["present"] is False
    assert result["legacy"]["case_backlog"] == []
    assert any(
        row["owner"] == "case-state" and "not reinterpreted as empty context" in row["reason"]
        for row in result["quarantined"]
    )


def test_case_backlog_that_is_not_a_list_is_quarantined_verbatim(tmp_path):
    target = _fixture(tmp_path, case_state=_case_payload(backlog={"val_001": {"status": "pending"}}))

    result = import_target(tmp_path, target)

    assert result["legacy"]["case_context"]["backlog_records"] == 0
    assert result["legacy"]["case_context"]["backlog_shape"] == "not-a-list"
    assert any(
        row["owner"] == "case-state" and "not a list" in row["reason"]
        for row in result["quarantined"]
    )


def test_cross_target_case_state_is_imported_by_nobody(tmp_path):
    target = _fixture(
        tmp_path,
        case_state=_case_payload(backlog=[{"id": "val_001", "status": "pending"}], target="other.test"),
    )

    result = import_target(tmp_path, target)

    assert any(row["owner"] == "case-state" and row["declared_target"] == "other.test"
               for row in result["legacy"]["target_conflicts"])
    assert result["legacy"]["case_context"]["present"] is False
    assert result["legacy"]["case_backlog"] == []
    assert any(row["owner"] == "case-state" and "imported by nobody" in row["reason"]
               for row in result["quarantined"])


def test_staged_import_rebases_a_legacy_absolute_reference_onto_the_copy(tmp_path):
    source = tmp_path / "source"
    absolute = str(source / "evidence" / "target.test" / "validation" / "AQ-9" / "run" / "diff.json")
    target = _fixture(
        source,
        ledger=[_ledger_row(evidence_ref=absolute)],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"peer read")],
    )
    staged = tmp_path / "staging-root"

    result = import_target_staged(source, staged, target)

    assert result["imported"]["observations"] == 1
    (rebased,) = result["legacy"]["rebased_references"]
    assert rebased["original"] == absolute
    assert rebased["rebased"] == "evidence/target.test/validation/AQ-9/run/diff.json"
    assert rebased["source_root_digest"].startswith("source-root:")
    assert not any(row["owner"] == "ledger" for row in result["quarantined"])


def test_staged_import_rejects_a_rebased_reference_with_no_material_in_the_copy(tmp_path):
    source = tmp_path / "source"
    absolute = str(source / "evidence" / "target.test" / "validation" / "AQ-9" / "run" / "diff.json")
    target = _fixture(source, ledger=[_ledger_row(evidence_ref=absolute)])
    staged = tmp_path / "staging-root"

    result = import_target_staged(source, staged, target)

    # The path is under the declared source root, but the copy has no material
    # there: nothing is invented and the row stays quarantined.
    assert result["imported"]["observations"] == 0
    assert any(row["owner"] == "ledger" and "no material in the migration copy" in row["reason"]
               for row in result["quarantined"])


def test_staged_import_does_not_rebase_an_absolute_reference_outside_the_source_root(tmp_path):
    source = tmp_path / "source"
    target = _fixture(
        source,
        ledger=[_ledger_row(evidence_ref="/srv/other-host/evidence/target.test/validation/run/diff.json")],
    )
    staged = tmp_path / "staging-root"

    result = import_target_staged(source, staged, target)

    assert result["imported"]["observations"] == 0
    assert result["legacy"].get("rebased_references") in (None, [])
    assert any(row["owner"] == "ledger" and "outside the declared migration source root" in row["reason"]
               for row in result["quarantined"])


def test_case_object_path_endpoint_is_resolved_against_the_observed_origin(tmp_path):
    target = _fixture(
        tmp_path,
        ledger=[_ledger_row()],
        evidence=[("evidence/target.test/validation/AQ-9/run/diff.json", b"peer read")],
        case_state=_case_payload(
            actors={"owner_a": {"role": "user", "label": "owner a"}},
            objects={"basket-1": {"type": "basket", "object_id": "1", "owner_actor": "owner_a",
                                  "endpoint": "/rest/basket/1", "status": "active", "notes": "owner read"}},
        ),
    )

    result = import_target(tmp_path, target)

    assert result["legacy"]["case_context_import"]["objects"] == 1
    assert not any(row["owner"] == "case-state" and "endpoint" in row["reason"]
                   for row in result["quarantined"])


def test_case_object_path_endpoint_without_an_observed_origin_stays_quarantined(tmp_path):
    target = _fixture(
        tmp_path,
        case_state=_case_payload(
            actors={"owner_a": {"role": "user", "label": "owner a"}},
            objects={"basket-1": {"type": "basket", "object_id": "1", "owner_actor": "owner_a",
                                  "endpoint": "/rest/basket/1", "status": "active"}},
        ),
    )

    result = import_target(tmp_path, target)

    assert result["legacy"]["case_context_import"]["objects"] == 0
    assert any(row["owner"] == "case-state" and "no single origin" in row["reason"]
               for row in result["quarantined"])


def test_manifest_and_copy_agree_on_runtime_locks(tmp_path):
    """A lock the manifest hashes but the copy omits fails promotion; keep them aligned."""
    source = tmp_path / "source"
    target = _fixture(source)
    locks = source / "state" / target / "locks"
    locks.mkdir(parents=True)
    (locks / "action_queue.lock").write_text("", encoding="utf-8")
    dot_locks = source / "findings" / target / ".locks"
    dot_locks.mkdir(parents=True)
    (dot_locks / "findings.lock").write_text("", encoding="utf-8")

    staged = tmp_path / "staging-root"
    result = import_target_staged(source, staged, target)

    manifest_paths = {item["path"] for item in result["receipt"]["source_manifest"]["files"]}
    assert not any("/locks/" in path or "/.locks/" in path for path in manifest_paths)
    # Promotion re-verifies the manifest against the published root; it must not
    # report a lock as a vanished migration input.
    published = tmp_path / "published-root"
    publish_preview(staged, published, target)
    promoted = promote_target(published, target)
    assert promoted["status"] == "primary"


def test_legacy_private_session_without_target_or_digest_imports_without_the_binding(tmp_path):
    """Pre-contract private material is never rewritten, so the record carries no binding."""
    target = _fixture(tmp_path)
    sessions_dir = tmp_path / ".private" / "case-state" / target / "sessions"
    sessions_dir.mkdir(parents=True)
    # A file exactly as the retired writer left it: no target, no content_sha256.
    (sessions_dir / "aabbccddeeff00112233.json").write_text(
        json.dumps({"schema_version": 1, "session_id": "s_legacy", "actor": "owner_a",
                    "kind": "bearer", "header_name": "Authorization", "header_value": "Bearer x",
                    "headers": {"Authorization": "Bearer x"}}),
        encoding="utf-8",
    )
    case_path = tmp_path / "state" / target / "case_state.json"
    case_path.write_text(json.dumps(_case_payload(
        actors={"owner_a": {"role": "user", "label": "owner a"}},
        sessions={"s_legacy": {"actor": "owner_a", "kind": "bearer", "validity": "verified",
                               "private_ref": ".private/case-state/target.test/sessions/aabbccddeeff00112233.json"}},
    )), encoding="utf-8")

    result = import_target(tmp_path, target)

    assert result["legacy"]["case_context_import"]["sessions"] == 1
    assert result["legacy"]["case_context_import"]["quarantined"] == 0
    (dropped,) = result["legacy"]["private_bindings_dropped"]
    assert dropped["kind"] == "session" and "content_sha256" in dropped["reason"]
    # The private file is untouched: migration never rewrites private material.
    assert (sessions_dir / "aabbccddeeff00112233.json").exists()
    assert "content_sha256" not in json.loads(
        (sessions_dir / "aabbccddeeff00112233.json").read_text(encoding="utf-8")
    )
