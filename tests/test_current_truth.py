"""The one read seam for a target's current evidence truth."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

import evidence_ledger
from tools.current_truth import (
    _store_truth,
    current_cell_projection,
    ledger_health_projection,
)
from tools.evidence_ledger import build_summary, ledger_path
from tools.target_paths import target_storage_key
from tools.target_store import SCHEMA_VERSION, StoreError, TargetStore


TARGET = "target.test"
AT = "2026-09-20T01:00:00Z"
FAMILY = "custom-state-transition"


def _write_ledger(root: Path, rows: list[dict], *, tail: str = "") -> Path:
    path = ledger_path(root, TARGET)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows) + tail
    path.write_text(body, encoding="utf-8")
    return path


def _ledger_row(endpoint: str, *, family: str = "Authz", result: str = "tested_finding") -> dict:
    return {
        "event_id": f"evt-{endpoint}",
        "endpoint": endpoint,
        "method": "GET",
        "vuln_class": family,
        "result": result,
        "ts": AT,
        "evidence_ref": "validation/evidence.txt",
    }


def _observation(root: Path, *, endpoint: str) -> dict:
    path = root / ".private" / "validation" / target_storage_key(TARGET) / "response.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('HTTP/1.1 200 OK\r\n\r\n{"owner":"peer"}', encoding="utf-8")
    return {
        "endpoint": endpoint,
        "method": "GET",
        "family": FAMILY,
        "observed_at": AT,
        "description": "Owner object returned in the recorded response",
        "artifacts": {"response": path.relative_to(root).as_posix()},
        "state_changing": False,
        "result": "tested_finding",
    }


def _record(store: TargetStore, root: Path, *, endpoint: str) -> None:
    store.start_attempt(attempt_id="try1", source="native", started_at=AT, actor="operator")
    store.record_execution(
        attempt_id="try1",
        outcome="complete",
        observations=[_observation(root, endpoint=endpoint)],
        actor="operator",
    )


def _cell_endpoints(projection: dict) -> set[str]:
    return {str(cell.get("endpoint") or "") for cell in projection.get("closed_cells") or []}


def test_primary_store_is_the_only_source_even_beside_a_leftover_ledger(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    assert store.backend() == "primary"
    _record(store, tmp_path, endpoint="https://target.test/api/objects?owner=peer")
    # A leftover ledger row must not join the store's answer: two sources for
    # one target would let retired facts author a cell the store never closed.
    _write_ledger(tmp_path, [_ledger_row("/api/leftover")])

    truth = current_cell_projection(tmp_path, TARGET)

    assert truth["source"]["kind"] == "store"
    assert truth["source"]["store_claim"] == "primary"
    assert truth["source"]["status"] == "ready"
    assert truth["source"]["store_id"] == store.closure_records()["store_id"]
    assert truth["source"]["revision"] >= 1
    assert truth["source"]["path_label"] == f"state/{target_storage_key(TARGET)}/metadata.sqlite3"
    # The projection must agree with the record it read, and never with the ledger.
    assert truth["projection"]["closed_cells"] == [
        {
            "endpoint": truth["records"][0]["endpoint"],
            "vuln_class": FAMILY,
            "result": "tested_finding",
            "ts": truth["records"][0]["ts"],
            "evidence_ref": truth["records"][0]["evidence_ref"],
        }
    ]
    assert "/api/leftover" not in _cell_endpoints(truth["projection"])
    assert truth["projection"]["identity_v2_diagnostics"]["closed_count"] == 0
    assert truth["health"] == {
        "status": "ready",
        "source_kind": "store",
        "invalid_count": 0,
        "invalid_rows": [],
        "last_valid_offset": 0,
    }


def test_preview_store_reports_its_claim_and_never_answers(tmp_path):
    _write_ledger(tmp_path, [_ledger_row("/api/legacy")])
    store = TargetStore(tmp_path, TARGET, allow_preview=True)
    store.initialize(allow_legacy=True)
    assert store.backend() == "preview"
    _record(store, tmp_path, endpoint="https://target.test/api/preview-only")

    truth = current_cell_projection(tmp_path, TARGET)

    assert truth["source"]["kind"] == "ledger"
    assert truth["source"]["store_claim"] == "preview"
    assert truth["source"]["status"] == "valid"
    assert truth["source"]["path_label"] == f"memory/evidence/{target_storage_key(TARGET)}/ledger.jsonl"
    assert _cell_endpoints(truth["projection"]) == {"/api/legacy"}
    assert all(
        "preview-only" not in str(cell.get("endpoint") or "")
        for cell in truth["projection"]["closed_cells"]
    )


def test_missing_primary_database_never_reactivates_leftover_ledger(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    _write_ledger(tmp_path, [_ledger_row("/api/legacy")])
    store.path.unlink()
    before = ledger_path(tmp_path, TARGET).read_bytes()
    with pytest.raises(StoreError, match="fenced target store missing"):
        current_cell_projection(tmp_path, TARGET)
    assert ledger_path(tmp_path, TARGET).read_bytes() == before


def test_store_that_cannot_be_read_raises_instead_of_falling_back(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    # A ledger is present, so a silent fallback would produce a plausible answer
    # from a source the target no longer answers from.
    _write_ledger(tmp_path, [_ledger_row("/api/legacy")])
    store.path.chmod(0o644)

    with pytest.raises(StoreError, match="private file permissions"):
        current_cell_projection(tmp_path, TARGET)


def test_store_with_a_foreign_schema_raises_instead_of_falling_back(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE store SET schema_version=99")

    with pytest.raises(StoreError, match="target/schema mismatch"):
        current_cell_projection(tmp_path, TARGET)


def test_store_without_a_role_column_is_reported_not_guessed(tmp_path):
    directory = tmp_path / "state" / target_storage_key(TARGET)
    directory.mkdir(parents=True)
    path = directory / "metadata.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE store (singleton INTEGER PRIMARY KEY CHECK (singleton = 1),"
            " schema_version INTEGER NOT NULL, target TEXT NOT NULL, store_id TEXT NOT NULL,"
            " revision INTEGER NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO store VALUES (1, ?, ?, 'store-id', 0, ?)", (SCHEMA_VERSION, TARGET, AT))
    path.chmod(0o600)

    with pytest.raises(StoreError, match="claims no backend role"):
        current_cell_projection(tmp_path, TARGET)


def test_damaged_ledger_cannot_authorize_a_closure(tmp_path):
    _write_ledger(tmp_path, [_ledger_row("/api/legacy")], tail="{not json}\n")

    truth = current_cell_projection(tmp_path, TARGET)

    assert truth["source"]["kind"] == "ledger"
    assert truth["source"]["status"] == "partial"
    assert truth["health"]["source_kind"] == "ledger"
    assert truth["health"]["status"] == "partial"
    assert truth["health"]["invalid_count"] == 1
    assert truth["projection"]["closed_cells"] == []
    assert truth["projection"]["closed_cells_v2"] == []
    assert truth["projection"]["identity_v2_diagnostics"]["suppressed_closed_count"] == 0
    assert truth["projection"]["identity_v2_diagnostics"]["suppressed_legacy_closed_count"] == 1
    assert truth["projection"]["identity_v2_shadow"] == {
        "status": "unavailable",
        "reason": "ledger_partial",
    }
    # The rows themselves stay readable: damage suppresses authorizations, not facts.
    assert len(truth["records"]) == 1


def test_truncated_store_read_is_damage_too():
    class TruncatedStore:
        """The store's own truncation guard is a 20k-row read; the rule is here."""

        root = Path("/repo")
        path = Path("/repo/state/target.test/metadata.sqlite3")

        def closure_records(self) -> dict:
            return {
                "store_id": "store-id",
                "revision": 7,
                "total": 5,
                "truncated": True,
                "records": [{
                    "event_id": "operation:0",
                    "raw_endpoint": "/api/objects",
                    "endpoint": "/api/objects",
                    "method": "GET",
                    "vuln_class": FAMILY,
                    "result": "tested_finding",
                    "ts": AT,
                    "evidence_ref": "",
                    "identity_dimensions": {},
                }],
            }

    truth = _store_truth(TruncatedStore())

    assert truth["source"]["status"] == "partial"
    assert truth["source"]["truncated"] is True
    assert truth["source"]["store_claim"] == "primary"
    assert truth["projection"]["closed_cells"] == []
    assert truth["projection"]["identity_v2_diagnostics"]["suppressed_legacy_closed_count"] == 1
    assert truth["projection"]["identity_v2_shadow"]["reason"] == "store_partial"


def test_changed_store_artifact_keeps_history_but_cannot_author_closure(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    _record(store, tmp_path, endpoint="https://target.test/api/objects?owner=peer")
    artifact = tmp_path / ".private" / "validation" / target_storage_key(TARGET) / "response.txt"
    artifact.write_text("tampered after registration", encoding="utf-8")

    truth = current_cell_projection(tmp_path, TARGET)

    assert truth["source"]["status"] == "partial"
    assert truth["health"]["invalid_count"] == 1
    assert truth["health"]["invalid_rows"][0]["operation_id"].startswith("operation:")
    assert len(truth["records"]) == 1
    assert truth["projection"]["closed_cells"] == []
    assert truth["projection"]["identity_v2_shadow"] == {
        "status": "unavailable",
        "reason": "store_partial",
    }


def test_revoked_artifact_keeps_history_but_cannot_author_closure(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    _record(store, tmp_path, endpoint="https://target.test/api/objects?owner=peer")
    with sqlite3.connect(store.path) as conn:
        artifact_id = conn.execute("SELECT artifact_id FROM observation_artifacts LIMIT 1").fetchone()[0]
    store.record_artifact_event(
        command_id="revoke-artifact", artifact_id=artifact_id,
        dimension="provenance", state="revoked", reason="source ownership withdrawn", actor="operator")

    truth = current_cell_projection(tmp_path, TARGET)

    assert truth["source"]["status"] == "partial"
    assert truth["health"]["invalid_count"] == 1
    assert "provenance is revoked" in truth["health"]["invalid_rows"][0]["reason"]
    assert len(truth["records"]) == 1
    assert truth["projection"]["closed_cells"] == []


def test_ledger_summary_reuses_the_seam_result_instead_of_reading_again(tmp_path, monkeypatch):
    """A caller holding the truth must not trigger a second read or projection."""
    _write_ledger(tmp_path, [_ledger_row("/api/owned")])
    truth = current_cell_projection(tmp_path, TARGET)

    def forbidden(*args, **kwargs):
        raise AssertionError("build_summary re-read the ledger while holding the truth")

    monkeypatch.setattr(evidence_ledger, "load_entries_diagnostic", forbidden)
    summary = build_summary(
        tmp_path, target=TARGET, focus_endpoints=["/api/owned"], _truth=truth
    )

    assert summary["closed_cells"] == truth["projection"]["closed_cells"]
    assert summary["identity_v2_diagnostics"] == truth["projection"]["identity_v2_diagnostics"]
    assert summary["evidence_source"] == truth["source"]
    assert summary["entry_count"] == len(truth["records"]) == 1
    assert summary["ledger_diagnostics"]["source_kind"] == "ledger"


def test_ledger_summary_without_a_snapshot_reads_the_one_seam(tmp_path, monkeypatch):
    """Direct callers get the same answer through the same source decision."""
    _write_ledger(tmp_path, [_ledger_row("/api/owned")])
    seen: list[tuple] = []
    original = current_cell_projection

    def recording(repo_root, target):
        seen.append((repo_root, target))
        return original(repo_root, target)

    module = sys.modules[current_cell_projection.__module__]
    monkeypatch.setattr(module, "current_cell_projection", recording)
    summary = build_summary(tmp_path, target=TARGET, focus_endpoints=["/api/owned"])

    assert seen and seen[0][1] == TARGET
    assert summary["closed_cells"] == original(tmp_path, TARGET)["projection"]["closed_cells"]
    assert summary["evidence_source"]["kind"] == "ledger"


def test_damaged_ledger_suppression_is_word_for_word_the_seam_rule(tmp_path):
    """The ledger's aggregate must not carry a second, weaker damage rule."""
    _write_ledger(tmp_path, [_ledger_row("/api/owned")], tail="{not json}\n")

    truth = current_cell_projection(tmp_path, TARGET)
    summary = build_summary(tmp_path, target=TARGET, focus_endpoints=["/api/owned"])

    assert summary["closed_cells"] == []
    assert summary["identity_v2_diagnostics"] == truth["projection"]["identity_v2_diagnostics"]
    assert summary["identity_v2_diagnostics"]["suppressed_legacy_closed_count"] == 1
    assert summary["identity_v2_shadow"] == truth["projection"]["identity_v2_shadow"] == {
        "status": "unavailable",
        "reason": "ledger_partial",
    }


def test_closure_consumers_read_the_one_seam_and_never_the_ledger_directly():
    """Surface, Closure and the loop guard must share one source decision."""
    tools = Path(__file__).resolve().parents[1] / "tools"
    for name in ("surface.py", "autopilot_state.py", "autopilot_loop_guard.py"):
        source = (tools / name).read_text()
        assert "load_entries_diagnostic(" not in source, f"{name} reads an evidence source by itself"
        assert "build_current_cell_projection(" not in source, f"{name} re-projects closure cells"
        assert "current_cell_projection(" in source, f"{name} does not consume the truth seam"
    # surface_projection stays file-side on purpose: it fingerprints the legacy
    # ledger *file* as a Surface input, not the target's closure truth. The
    # store becomes a manifest input at cutover, not before.
    projection = (tools / "surface_projection.py").read_text()
    assert "load_entries_diagnostic(" in projection
    # ... but even the file-side reader takes the projection from its one
    # definition instead of through the ledger module.
    assert "from tools.evidence_ledger import build_current_cell_projection" not in projection
    assert "from tools.closure_projection import build_current_cell_projection" in projection

    # The damage rule is stated once, beside the projection it guards.
    damage_def = "def suppress_unauthorized_closures("
    assert damage_def in (tools / "closure_projection.py").read_text()
    for name in ("current_truth.py", "evidence_ledger.py"):
        assert damage_def not in (tools / name).read_text(), f"{name} restates the damage rule"

    import autopilot_loop_guard  # noqa: PLC0415 - module identity is the assertion

    for function in (ledger_health_projection, autopilot_loop_guard._ledger_health_projection):
        assert function.__qualname__ == "ledger_health_projection"
        assert function.__module__.endswith("current_truth")
    assert "def _ledger_health_projection" not in (tools / "autopilot_loop_guard.py").read_text()
