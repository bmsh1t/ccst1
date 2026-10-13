"""Focused C6 owner acceptance against synthetic target state only."""
from contextlib import closing
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tools.target_store import ConflictError, StoreError, TargetStore


def _restore_legacy_schema(store, version):
    """Rebuild the validated physical v11/v12/v13 fixture, preserving supported rows."""
    from tools import target_store

    assert version in (11, 12, 13)
    ddl = target_store._SCHEMA
    for introduced, sql in (
        (12, target_store._EXPERIENCE_PROVENANCE_SCHEMA),
        (14, target_store._EXPERIENCE_MATERIAL_SCHEMA),
        (15, target_store._EXPERIENCE_CONDITION_SCHEMA),
        (16, target_store._EXPERIENCE_EXTERNAL_SCHEMA),
    ):
        if version < introduced:
            assert sql in ddl
            ddl = ddl.replace(sql, "")
    if version == 12:
        versions = target_store._EXPERIENCE_PROVENANCE_SCHEMA.split("CREATE TABLE experience_sources")[0]
        ddl = ddl.replace(target_store._EXPERIENCE_PROVENANCE_SCHEMA, versions + """
CREATE TABLE experience_sources (
    experience_id TEXT NOT NULL REFERENCES experiences(id), source_experience_id TEXT NOT NULL,
    source_version INTEGER NOT NULL, purpose TEXT NOT NULL, content_sha256 TEXT NOT NULL,
    PRIMARY KEY (experience_id,source_experience_id,source_version,purpose),
    FOREIGN KEY (source_experience_id,source_version) REFERENCES experience_versions(experience_id,version));
CREATE TABLE experience_links (
    id TEXT PRIMARY KEY, experience_id TEXT REFERENCES experiences(id), target_id TEXT REFERENCES experiences(id),
    relation TEXT, conditions TEXT, rationale TEXT, revision INTEGER);
CREATE INDEX experience_links_target ON experience_links(target_id,relation);
CREATE TABLE experience_link_events (
    id TEXT PRIMARY KEY, link_id TEXT UNIQUE REFERENCES experience_links(id), reason TEXT,
    actor TEXT, revision INTEGER, recorded_at TEXT);
""")
    with closing(sqlite3.connect(store.path)) as conn:
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        retained = {}
        for (table,) in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"):
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
            retained[table] = (columns, conn.execute(f'SELECT * FROM "{table}"').fetchall())
    replacement = store.path.with_name(f"legacy-v{version}.sqlite3")
    with closing(sqlite3.connect(replacement)) as conn, conn:
        conn.executescript(ddl)
        for (table,) in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"):
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
            source_columns, rows = retained[table]
            indexes = [source_columns.index(column) for column in columns]
            conn.executemany(f'INSERT INTO "{table}" VALUES ({",".join("?" for _ in columns)})',
                             [tuple(row[index] for index in indexes) for row in rows])
        conn.execute("UPDATE store SET schema_version=?", (version,))
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("SELECT name FROM sqlite_schema WHERE name LIKE 'experience%external%'").fetchall() == []
    replacement.chmod(0o600)
    replacement.replace(store.path)


def save(store, key, **kwargs):
    values = dict(command_id=key, kind="note", statement=key, conditions="release 1; actor A",
                  reopen_when="", next_intent="", evidence=[], actor="operator")
    values.update(kwargs)
    return store.remember(**values)


def test_corrections_sources_retraction_restart_and_cli(tmp_path):
    store = TargetStore(tmp_path, "target.test")
    store.initialize()
    save(store, "old")
    version = store.experience_version("old")
    source = {key: version[key] for key in ("target", "store_id", "experience_id", "version", "content_sha256")}
    source["purpose"] = "basis"
    save(store, "dependent", sources=[source])
    save(store, "new")
    args = dict(command_id="correct", experience_id="new", target_id="old", relation="supersedes",
                conditions="release 1; actor A", rationale="explicit review", actor="operator",
                expected_revision=store.binding()["revision"])
    receipt = store.link_experience(**args)
    assert store.link_experience(**args)["replayed"]
    assert store.experience("old")["review_state"] == "superseded"
    assert store.experience("dependent")["review_state"] == "needs_review"
    with pytest.raises(ConflictError):
        store.link_experience(**{**args, "rationale": "changed"})
    before = store.binding()
    with pytest.raises(StoreError, match="cycle"):
        store.link_experience(**{**args, "command_id": "cycle", "experience_id": "old", "target_id": "new",
                                 "relation": "depends_on", "expected_revision": before["revision"]})
    assert store.binding() == before
    with pytest.raises(StoreError, match="another target"):
        save(store, "foreign", sources=[{**source, "target": "other.test"}])
    assert store.binding() == before
    store.retract_experience_link(command_id="retract", link_id="correct", reason="new advice withdrawn",
                                  expected_revision=receipt["revision"], actor="operator")
    store = TargetStore(tmp_path, "target.test")
    assert store.experience("old")["review_state"] == "superseded"
    assert store.experience("old")["correction_refs"][0]["retraction_id"] == "retract"
    save(store, "h1", kind="handoff", next_intent="old intent")
    save(store, "h2", kind="handoff", next_intent="")
    assert store.memory_context(limit=1)["current_handoff"]["next_intent"] == ""
    script = Path(__file__).resolve().parents[1] / "tools" / "target_memory.py"
    result = subprocess.run([sys.executable, str(script), "sources", "--target", "target.test",
                             "--repo-root", str(tmp_path), "--id", "old", "--json"],
                            capture_output=True, text=True, check=True)
    assert json.loads(result.stdout)["items"][0]["review_state"] == "superseded"


def test_case_versions_and_explicit_v11_upgrade(tmp_path):
    store = TargetStore(tmp_path, "target.test")
    store.initialize()
    store.upsert_case_actor(command_id="a", actor_id="a", role="user", actor="operator")
    store.upsert_case_actor(command_id="b", actor_id="b", role="user", actor="operator")
    args = dict(hypothesis_id="hyp", vuln_class="custom", why_now="same premise", actor="operator")
    store.remember_hypothesis(command_id="h1", actor_ids=["a"], **args)
    original = store.experience_version("hyp")
    store.remember_hypothesis(command_id="h2", actor_ids=["b"], **args)
    assert store.experience_version("hyp", original["version"])["snapshot"]["actors"][0]["actor_id"] == "a"
    assert store.experience_version("hyp")["snapshot"]["actors"][0]["actor_id"] == "b"
    with pytest.raises(StoreError, match="observations"):
        save(store, "negative", kind="negative", reopen_when="release changes")
    save(store, "handoff", kind="handoff", next_intent="")
    _restore_legacy_schema(store, 11)
    with pytest.raises(StoreError, match="upgrade-schema"):
        store.memory_context()
    backup = tmp_path / "backup"
    backup.mkdir(mode=0o700)
    assert store.upgrade_schema(backup / "v11.sqlite")["status"] == "upgraded"
    assert store.upgrade_schema(backup / "unused.sqlite")["status"] == "already_current"
    assert store.memory_context()["current_handoff"]["next_intent"] == ""
    assert store.experience_version("hyp")["snapshot"]["actors"][0]["actor_id"] == "b"
    with closing(sqlite3.connect(backup / "v11.sqlite")) as conn:
        assert conn.execute("SELECT schema_version FROM store").fetchone()[0] == 11


def test_basis_admission_and_version_bound_links(tmp_path):
    store = TargetStore(tmp_path, "target.test")
    store.initialize()
    for actor in ("a", "b"):
        store.upsert_case_actor(command_id=actor, actor_id=actor, role="user", actor="operator")
    args = dict(hypothesis_id="hyp", vuln_class="custom", why_now="premise", actor="operator")
    store.remember_hypothesis(command_id="h1", actor_ids=["a"], **args)
    first = store.experience_version("hyp")
    source = {key: first[key] for key in ("target", "store_id", "experience_id", "version", "content_sha256")}
    source["purpose"] = "basis"
    save(store, "based", sources=[source])
    save(store, "correction", conditions=first["snapshot"]["conditions"])
    link = dict(command_id="correct-hyp", experience_id="correction", target_id="hyp", relation="supersedes",
                conditions=first["snapshot"]["conditions"], rationale="review", actor="operator",
                expected_revision=store.binding()["revision"])
    store.link_experience(**link)
    before = store.binding()
    with pytest.raises(StoreError, match="basis"):
        save(store, "bad", sources=[source])
    assert store.binding() == before
    store.remember_hypothesis(command_id="h2", actor_ids=["b"], **args)
    current = store.experience("hyp")
    assert current["review_state"] == "advisory"
    assert current["correction_refs"] == []
    assert store.experience("based")["review_state"] == "needs_review"
    with pytest.raises(StoreError, match="basis"):
        save(store, "stale", sources=[source])
    # The exact committed retry remains idempotent after its basis is challenged.
    assert save(store, "based", sources=[source])["replayed"]


def test_artifact_integrity_propagates_and_blocks_new_basis(tmp_path):
    store = TargetStore(tmp_path, "target.test")
    store.initialize()
    path = tmp_path / "evidence" / "target.test" / "evidence.txt"
    path.parent.mkdir(parents=True)
    path.write_text("original evidence")
    store.start_attempt(attempt_id="attempt", source="native", started_at="2026-10-11T00:00:00Z", actor="operator")
    receipt = store.record_execution(attempt_id="attempt", outcome="complete", actor="operator", observations=[{
        "endpoint": "https://target.test/item", "method": "GET", "family": "custom",
        "observed_at": "2026-10-11T00:00:00Z", "description": "synthetic observation",
        "artifacts": {"response": "evidence/target.test/evidence.txt"}, "state_changing": False}])
    save(store, "root", evidence=[{"operation_id": receipt["entity_id"], "step": 0}])
    version = store.experience_version("root")
    source = {key: version[key] for key in ("target", "store_id", "experience_id", "version", "content_sha256")}
    source["purpose"] = "basis"
    save(store, "middle", sources=[source])
    save(store, "leaf")
    store.link_experience(command_id="depends", experience_id="leaf", target_id="middle", relation="depends_on",
                          conditions="release 1; actor A", rationale="explicit dependency", actor="operator",
                          expected_revision=store.binding()["revision"])
    assert store.experience("leaf")["source_health"]
    path.write_text("damaged evidence")
    for key in ("root", "middle", "leaf"):
        assert store.experience(key)["review_state"] == "needs_review"
    before = store.binding()
    with pytest.raises(StoreError, match="basis"):
        save(store, "bad-observation", evidence=[{"operation_id": receipt["entity_id"], "step": 0}])
    with pytest.raises(StoreError, match="basis"):
        save(store, "bad", sources=[source])
    assert store.binding() == before
    assert store.experience("root")["evidence"]
    path.write_text("original evidence")
    store.retract_experience_link(command_id="withdraw", link_id="depends", reason="dependency withdrawn",
                                  actor="operator", expected_revision=store.binding()["revision"])
    assert store.experience("leaf")["review_state"] == "needs_review"


def test_v12_upgrade_binds_existing_link_history(tmp_path):
    store = TargetStore(tmp_path, "target.test")
    store.initialize()
    save(store, "old")
    save(store, "new")
    store.link_experience(command_id="link", experience_id="new", target_id="old", relation="supersedes",
                          conditions="release 1; actor A", rationale="review", actor="operator",
                          expected_revision=store.binding()["revision"])
    old_version = store.experience_version("old")["version"]
    _restore_legacy_schema(store, 12)
    with pytest.raises(StoreError, match="upgrade-schema"):
        store.experience("old")
    backup = tmp_path / "backups"
    backup.mkdir(mode=0o700)
    assert store.upgrade_schema(backup / "v12.sqlite")["status"] == "upgraded"
    historical = store.experience_version("old", old_version)
    assert historical["review_state"] == "superseded"
    assert historical["correction_refs"][0]["target_version"] == old_version
    assert store.upgrade_schema(backup / "unused.sqlite")["status"] == "already_current"


def test_material_sources_claims_and_v13_upgrade(tmp_path):
    store = TargetStore(tmp_path, "target.test")
    store.initialize()
    path = tmp_path / "evidence" / "target.test" / "body.txt"
    path.parent.mkdir(parents=True)
    path.write_text("original bytes")
    store.start_attempt(attempt_id="attempt", source="native", started_at="2026-10-11T00:00:00Z", actor="operator")
    receipt = store.record_execution(attempt_id="attempt", outcome="complete", actor="operator", observations=[{
        "endpoint": "https://target.test/item", "method": "GET", "family": "custom",
        "observed_at": "2026-10-11T00:00:00Z", "description": "synthetic",
        "artifacts": {"response": "evidence/target.test/body.txt"}, "state_changing": False}])
    artifact_id = store._artifact("evidence/target.test/body.txt")["id"]
    source = {**store.experience_entity("artifact", artifact_id), "purpose": "basis"}
    store.upsert_case_actor(command_id="actor", actor_id="actor", role="user", actor="operator")
    claim = {"subject": store.experience_entity("actor", "actor"), "predicate": "uses",
             "object": store.experience_entity("artifact", artifact_id), "conditions": "release 1",
             "timing": "after observation", "source_refs": [{"source": 0}]}
    save(store, "claimed", sources=[source], claims=[claim])
    result = store.experience("claimed")
    assert result["claims"][0]["advisory"] is True
    assert result["claims"][0]["source_refs"][0]["source_record_id"] == artifact_id
    assert result["sources"][0]["health"] == "available"
    refs = [{"operation_id": receipt["entity_id"], "step": 0}]
    before = store.binding()
    with pytest.raises(StoreError, match="basis"):
        save(store, "origin-claim", sources=[{**source, "purpose": "origin"}], claims=[claim])
    with pytest.raises(StoreError, match="version"):
        save(store, "bool-version", sources=[{**source, "version": False}])
    assert store.binding() == before
    with pytest.raises(ConflictError):
        save(store, "foreign-claim", sources=[source], claims=[{**claim, "subject": {**claim["subject"], "store_id": "foreign"}}])
    assert store.binding() == before
    script = Path(__file__).resolve().parents[1] / "tools" / "target_memory.py"
    output = subprocess.run([sys.executable, str(script), "entity", "--target", "target.test", "--repo-root", str(tmp_path),
                             "--owner", "artifact", "--id", artifact_id, "--json"], capture_output=True, text=True, check=True)
    assert json.loads(output.stdout)["content_sha256"] == source["content_sha256"]
    store.record_artifact_event(command_id="revoke", artifact_id=artifact_id,
                                dimension="provenance", state="revoked", reason="fixture withdrawal", actor="operator")
    assert store.experience("claimed")["claims"][0]["object"]["health"] == "revoked"
    before = store.binding()
    with pytest.raises(StoreError, match="basis"):
        save(store, "revoked-observation", evidence=refs,
             claims=[{**claim, "object": claim["subject"], "source_refs": [{"observation": 0}]}])
    with pytest.raises(StoreError, match="endpoint"):
        save(store, "revoked-endpoint", sources=[{**source, "purpose": "origin"}], claims=[claim])
    assert store.binding() == before
    assert save(store, "claimed", sources=[source], claims=[claim])["replayed"]
    path.write_text("changed bytes")
    assert store.experience("claimed")["review_state"] == "needs_review"
    with pytest.raises(StoreError, match="basis"):
        save(store, "bad-material", sources=[source])
    save(store, "origin-material", sources=[{**source, "purpose": "origin"}])
    assert store.experience("origin-material")["review_state"] == "advisory"
    # Exercise the real previous physical schema using only synthetic state.
    other = TargetStore(tmp_path, "upgrade.test")
    other.initialize()
    save(other, "retained")
    _restore_legacy_schema(other, 13)
    backups = tmp_path / "backups14"
    backups.mkdir(mode=0o700)
    assert other.upgrade_schema(backups / "v13.sqlite")["status"] == "upgraded"
    assert other.experience("retained")["statement"] == "retained"
