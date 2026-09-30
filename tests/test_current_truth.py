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
    assert truth["projection"]["closed_cells"] == []
    assert truth["records"][0]["result"] == "tested_finding"
    assert "/api/leftover" not in _cell_endpoints(truth["projection"])
    assert truth["projection"]["identity_v2_diagnostics"]["closed_count"] == 0
    assert truth["health"] == {
        "status": "ready",
        "source_kind": "store",
        "invalid_count": 0,
        "invalid_rows": [],
        "last_valid_offset": 0,
    }


def test_preview_store_is_only_available_to_explicit_migration_readers(tmp_path):
    path = _write_ledger(tmp_path, [_ledger_row("/api/legacy")])
    store = TargetStore(tmp_path, TARGET, allow_preview=True)
    store.initialize(allow_legacy=True)
    _record(store, tmp_path, endpoint="https://target.test/api/preview-only")
    before = path.read_bytes()
    with pytest.raises(StoreError, match="runtime store is not active"):
        current_cell_projection(tmp_path, TARGET)
    assert store.page("operations")["total"] == 1
    assert path.read_bytes() == before


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
    directory.mkdir(parents=True, mode=0o700)
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


@pytest.mark.parametrize("tail", ["", "{not json}\n"])
def test_legacy_ledger_does_not_replace_an_uninitialized_store(tmp_path, tail):
    path = _write_ledger(tmp_path, [_ledger_row("/api/legacy")], tail=tail)
    before = path.read_bytes()
    with pytest.raises(StoreError, match="not initialized"):
        current_cell_projection(tmp_path, TARGET)
    assert path.read_bytes() == before
    assert not TargetStore(tmp_path, TARGET).path.exists()


def test_truncated_store_read_is_damage_too():
    class TruncatedStore:
        """The store's own truncation guard is a 20k-row read; the rule is here."""

        root = Path("/repo")
        path = Path("/repo/state/target.test/metadata.sqlite3")

        def closure_records(self, *, verify=False) -> dict:
            assert verify is True
            return {
                "store_id": "store-id",
                "invalid_operations": [],
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
    assert truth["projection"]["identity_v2_diagnostics"]["suppressed_legacy_closed_count"] == 0
    assert truth["projection"]["identity_v2_shadow"]["reason"] == "store_partial"


def test_current_truth_checks_every_operation_on_one_snapshot_and_rechecks_next_read(tmp_path, monkeypatch):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    operation_ids = []
    for index in range(30):
        store.start_attempt(attempt_id=f"try-{index}", source="native", started_at=AT, actor="operator")
        receipt = store.record_execution(attempt_id=f"try-{index}", outcome="complete", actor="operator",
            observations=[_observation(tmp_path, endpoint=f"https://{TARGET}/item-{index}")])
        operation_ids.append(receipt["entity_id"])
    before = store.binding()
    checked, connections = [], []
    verify, connect = store._artifact, sqlite3.connect

    def verified(ref):
        checked.append(ref)
        return verify(ref)

    def connected(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    with monkeypatch.context() as patch:
        patch.setattr(store, "_artifact", verified)
        patch.setattr(sqlite3, "connect", connected)
        truth = _store_truth(store)
    assert len(connections) == 1
    assert checked == [".private/validation/target.test/response.txt"]
    assert {row["event_id"].rsplit(":", 1)[0] for row in truth["records"]} == set(operation_ids)
    assert len(truth["records"]) == 30 and truth["health"]["status"] == "ready"
    assert store.binding() == before
    raw = tmp_path / ".private/validation/target.test/response.txt"
    original = raw.read_bytes()
    raw.write_bytes(b"Changed evidence without metadata revision")
    damaged = _store_truth(store)
    assert damaged["source"]["revision"] == before["revision"]
    assert damaged["health"]["invalid_count"] == 30
    assert damaged["records"] == truth["records"]
    assert damaged["projection"]["closed_cells"] == []
    raw.write_bytes(original)

    events = store._artifact_events
    changed = False

    def invalidate(conn, artifact_id):
        nonlocal changed
        if not changed:
            changed = True
            store.record_artifact_event(command_id="revoke", artifact_id=artifact_id, dimension="provenance",
                                        state="revoked", reason="New review", actor="operator")
        return events(conn, artifact_id)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_artifact_events", invalidate)
        pinned = _store_truth(store)
    assert changed and pinned["source"]["revision"] == before["revision"]
    assert pinned["health"]["status"] == "ready"
    assert _store_truth(store)["health"]["invalid_count"] == 30
    with monkeypatch.context() as patch:
        patch.setattr(store, "_artifact", lambda *args: pytest.fail("truncated prefix must not authorize closure"))
        assert store.closure_records(limit=1, verify=True)["truncated"] is True


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
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    _record(store, tmp_path, endpoint="https://target.test/api/owned")
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
    assert summary["ledger_diagnostics"]["source_kind"] == "store"


def test_ledger_summary_without_a_snapshot_reads_the_one_seam(tmp_path, monkeypatch):
    """Direct callers get the same answer through the same source decision."""
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    _record(store, tmp_path, endpoint="https://target.test/api/owned")
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
    assert summary["evidence_source"]["kind"] == "store"


def test_damaged_store_evidence_suppression_is_word_for_word_the_seam_rule(tmp_path):
    """The ledger's aggregate must not carry a second, weaker damage rule."""
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    _record(store, tmp_path, endpoint="https://target.test/api/owned")
    artifact = tmp_path / ".private" / "validation" / target_storage_key(TARGET) / "response.txt"
    artifact.write_text("changed after registration")

    truth = current_cell_projection(tmp_path, TARGET)
    summary = build_summary(tmp_path, target=TARGET, focus_endpoints=["/api/owned"])

    assert summary["closed_cells"] == []
    assert summary["identity_v2_diagnostics"] == truth["projection"]["identity_v2_diagnostics"]
    assert summary["identity_v2_diagnostics"]["suppressed_legacy_closed_count"] == 0
    assert summary["identity_v2_shadow"] == truth["projection"]["identity_v2_shadow"] == {
        "status": "unavailable",
        "reason": "store_partial",
    }


def test_closure_consumers_read_the_one_seam_and_never_the_ledger_directly():
    """Surface, Closure and the loop guard must share one source decision."""
    tools = Path(__file__).resolve().parents[1] / "tools"
    for name in ("surface.py", "autopilot_state.py", "autopilot_loop_guard.py"):
        source = (tools / name).read_text()
        assert "load_entries_diagnostic(" not in source, f"{name} reads an evidence source by itself"
        assert "build_current_cell_projection(" not in source, f"{name} re-projects closure cells"
        assert "current_cell_projection(" in source, f"{name} does not consume the truth seam"
    projection = (tools / "surface_projection.py").read_text()
    assert "load_entries_diagnostic(" not in projection
    assert "build_current_cell_projection(" not in projection
    assert "current_cell_projection(" in projection

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


def test_local_damage_preserves_independent_closure_without_resurrecting_history(tmp_path):
    from tools.identity_contract import build_closure_cell
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    def save(attempt, path):
        ref = tmp_path / 'evidence' / TARGET / f'{attempt}.txt'
        ref.parent.mkdir(parents=True, exist_ok=True)
        ref.write_text(f'raw {attempt}')
        url = f'https://{TARGET}/{path}'
        key = build_closure_cell(url, 'NewBoundary', {'method': 'GET'}, technique='check').key
        store.start_attempt(attempt_id=attempt, source='native', started_at=AT, actor='operator')
        store.record_execution(attempt_id=attempt, outcome='complete', actor='operator', observations=[{
            'endpoint': url, 'method': 'GET', 'family': 'NewBoundary', 'observed_at': AT,
            'description': 'Recorded boundary', 'state_changing': False, 'result': 'tested_clean',
            'artifacts': {'response': ref.relative_to(tmp_path).as_posix()},
            'identity_status': 'complete', 'identity_technique': 'check',
            'identity_v2': key.to_dict(), 'identity_dimensions': key.dimension_map,
            'detail': {'evidence_role': 'subject'},
        }])
        return ref
    save('old', 'same')
    latest = save('latest', 'same')
    save('independent', 'other')
    assert len(_store_truth(store)['projection']['closed_cells_v2']) == 2
    latest.write_text('changed')
    truth = _store_truth(store)
    assert truth['health']['status'] == 'partial'
    assert [c['endpoint'] for c in truth['projection']['closed_cells_v2']] == [f'https://{TARGET}/other']
    assert truth['projection']['identity_v2_diagnostics']['suppressed_closed_count'] == 1
    assert len(truth['records']) == 3
