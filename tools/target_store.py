"""Transactional target facts; no execution, planning or projection imports.

The migration must explicitly create this store in an isolated target copy.
Legacy runtime entry points are not switched by importing this module.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from tools.evidence_identity import (
        CANONICAL_VULN_CLASSES, LEDGER_RESULTS, canonical_endpoint_identity, coverage_family, extract_endpoint_path, normalize_family,
    )
    from tools.target_paths import classify_target, open_target_lock_file, target_storage_key
    from tools.scope_context import url_belongs_to_target
    from tools.target_paths import legacy_target_profile_path, target_raw_artifact_path
    from tools.scope_context import SCHEMA_VERSION as SCOPE_SCHEMA_VERSION, read_scope_source, write_scope_source_locked
except ImportError:  # pragma: no cover - direct tools/ execution
    from evidence_identity import (  # type: ignore
        CANONICAL_VULN_CLASSES, LEDGER_RESULTS, canonical_endpoint_identity, coverage_family, extract_endpoint_path, normalize_family,
    )
    from target_paths import classify_target, open_target_lock_file, target_storage_key  # type: ignore
    from scope_context import url_belongs_to_target  # type: ignore
    from target_paths import legacy_target_profile_path, target_raw_artifact_path  # type: ignore
    from scope_context import SCHEMA_VERSION as SCOPE_SCHEMA_VERSION, read_scope_source, write_scope_source_locked


SCHEMA_VERSION = 11
COMPATIBLE_SCHEMA_VERSIONS = {8, 9, 10, SCHEMA_VERSION}
COVERAGE_REVIEW_STATUSES = ("tested_clean", "tested_finding", "untested", "n_a")
ENDPOINT_KIND_VALUES = (
    "untriaged", "api_endpoint", "page_route", "static_asset", "public_metadata",
    "route_prefix", "realtime_endpoint", "external_chain_context", "unknown",
)
FINAL_ENDPOINT_KIND_SOURCES = frozenset({"ai_triage", "manual", "operator"})
_COVERAGE_REVIEW_SCHEMA = """
CREATE TABLE coverage_reviews (
    id TEXT PRIMARY KEY NOT NULL,
    endpoint TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('endpoint_kind','cell_status')),
    family TEXT REFERENCES coverage_classes(name),
    value TEXT NOT NULL,
    reason TEXT NOT NULL,
    source TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    historical INTEGER NOT NULL CHECK (historical IN (0,1)),
    finding_id TEXT REFERENCES findings(id),
    revision INTEGER NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    CHECK ((kind='endpoint_kind' AND family IS NULL AND finding_id IS NULL
            AND value IN ('untriaged','api_endpoint','page_route','static_asset','public_metadata',
                          'route_prefix','realtime_endpoint','external_chain_context','unknown'))
        OR (kind='cell_status' AND family IS NOT NULL
            AND value IN ('tested_clean','tested_finding','untested','n_a'))),
    CHECK (finding_id IS NULL OR (value='tested_finding' AND historical=0))
);
CREATE INDEX coverage_reviews_subject ON coverage_reviews(endpoint, kind, family, historical, revision DESC);
"""
_SCHEMA = """
CREATE TABLE store (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    target TEXT NOT NULL,
    store_id TEXT NOT NULL,
    backend TEXT NOT NULL CHECK (backend IN ('preview','primary')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at TEXT NOT NULL,
    active_goal TEXT NOT NULL DEFAULT ''
);
CREATE TABLE coverage_classes (name TEXT PRIMARY KEY NOT NULL);
CREATE TABLE actions (
    id TEXT PRIMARY KEY NOT NULL,
    intent TEXT NOT NULL CHECK (length(intent) > 0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (length(metadata_json) <= 32768),
    kind TEXT NOT NULL CHECK (kind IN ('execution','work')),
    endpoint TEXT,
    family TEXT CHECK (length(family) BETWEEN 1 AND 256),
    subject_artifact_id TEXT REFERENCES artifacts(id),
    subject_finding_id TEXT REFERENCES findings(id),
    subject_experience_id TEXT REFERENCES experiences(id),
    execution_key TEXT NOT NULL,
    repeat_of TEXT REFERENCES actions(id),
    repeat_reason TEXT NOT NULL DEFAULT '',
    priority INTEGER,
    status TEXT NOT NULL CHECK (status IN ('ready','claimed','blocked','completed','cancelled')),
    claim_token TEXT,
    claimed_by TEXT,
    reason TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL CHECK (version > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK ((status = 'claimed') = (claim_token IS NOT NULL)),
    CHECK ((status = 'claimed') = (claimed_by IS NOT NULL)),
    CHECK ((kind = 'execution' AND endpoint IS NOT NULL AND family IS NOT NULL
            AND subject_artifact_id IS NULL AND subject_finding_id IS NULL AND subject_experience_id IS NULL)
        OR (kind = 'work' AND family IS NULL
            AND (endpoint IS NOT NULL) + (subject_artifact_id IS NOT NULL)
                + (subject_finding_id IS NOT NULL) + (subject_experience_id IS NOT NULL) <= 1))
);
CREATE INDEX actions_status_id ON actions(status, id);
CREATE UNIQUE INDEX active_execution_key ON actions(execution_key)
    WHERE status IN ('ready','claimed','blocked');
CREATE TABLE attempts (
    id TEXT PRIMARY KEY NOT NULL,
    action_id TEXT REFERENCES actions(id),
    claim_token TEXT,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    CHECK ((action_id IS NULL) = (claim_token IS NULL))
);
CREATE INDEX attempts_action ON attempts(action_id, id);
CREATE TABLE operations (
    id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL REFERENCES attempts(id),
    supersedes TEXT UNIQUE REFERENCES operations(id),
    revision INTEGER NOT NULL UNIQUE,
    outcome TEXT NOT NULL CHECK (outcome IN ('complete','partial','unknown')),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    recorded_at TEXT NOT NULL
);
CREATE UNIQUE INDEX initial_operation ON operations(attempt_id) WHERE supersedes IS NULL;
CREATE INDEX operations_attempt_revision ON operations(attempt_id, revision DESC);
CREATE TABLE observations (
    operation_id TEXT NOT NULL REFERENCES operations(id),
    step INTEGER NOT NULL CHECK (step >= 0),
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    family TEXT NOT NULL CHECK (length(family) BETWEEN 1 AND 256),
    coverage_class TEXT REFERENCES coverage_classes(name),
    observed_at TEXT NOT NULL,
    description TEXT NOT NULL,
    detail_json TEXT NOT NULL CHECK (length(detail_json) <= 32768),
    actor TEXT NOT NULL,
    object_scope TEXT NOT NULL,
    variant TEXT NOT NULL,
    error TEXT NOT NULL,
    truncated INTEGER NOT NULL CHECK (truncated IN (0,1)),
    state_changing INTEGER CHECK (state_changing IN (0,1)),
    redline_checked INTEGER NOT NULL CHECK (redline_checked IN (0,1)),
    result TEXT NOT NULL CHECK (length(result) <= 64),
    identity_status TEXT NOT NULL DEFAULT 'none' CHECK (identity_status IN ('complete','none','incomplete','conflict')),
    identity_technique TEXT NOT NULL DEFAULT '' CHECK (length(identity_technique) <= 256),
    identity_v2 TEXT NOT NULL DEFAULT '{}' CHECK (length(identity_v2) <= 8192),
    identity_dimensions TEXT NOT NULL CHECK (length(identity_dimensions) <= 4096),
    PRIMARY KEY (operation_id, step)
);
CREATE INDEX observations_endpoint_family ON observations(endpoint, family);
CREATE TABLE artifacts (
    id TEXT PRIMARY KEY NOT NULL,
    ref TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    size INTEGER NOT NULL CHECK (size > 0),
    UNIQUE (ref, sha256)
);
CREATE TABLE artifact_events (
    id TEXT PRIMARY KEY NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    dimension TEXT NOT NULL CHECK (dimension IN ('availability','provenance')),
    state TEXT NOT NULL CHECK (state IN ('available','unavailable','trusted','revoked')),
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    revision INTEGER NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL
);
CREATE INDEX artifact_events_latest ON artifact_events(artifact_id, dimension, revision DESC);
CREATE TABLE observation_artifacts (
    operation_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    kind TEXT NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    PRIMARY KEY (operation_id, step, kind),
    FOREIGN KEY (operation_id, step) REFERENCES observations(operation_id, step)
);
CREATE TABLE findings (
    id TEXT PRIMARY KEY NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    family TEXT NOT NULL CHECK (length(family) BETWEEN 1 AND 256),
    title TEXT NOT NULL,
    claim TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX findings_endpoint_family ON findings(endpoint, family);
CREATE TABLE finding_observations (
    finding_id TEXT NOT NULL REFERENCES findings(id),
    operation_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    PRIMARY KEY (finding_id, operation_id, step),
    FOREIGN KEY (operation_id, step) REFERENCES observations(operation_id, step)
);
CREATE TABLE assessments (
    id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    verdict TEXT NOT NULL CHECK (verdict IN ('confirmed','refuted','inconclusive')),
    reason TEXT NOT NULL,
    boundary TEXT NOT NULL,
    impact TEXT NOT NULL,
    assessor TEXT NOT NULL,
    revision INTEGER NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE INDEX assessments_finding_revision ON assessments(finding_id, revision DESC);
CREATE TABLE assessment_observations (
    assessment_id TEXT NOT NULL REFERENCES assessments(id),
    finding_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    PRIMARY KEY (assessment_id, operation_id, step),
    FOREIGN KEY (finding_id, operation_id, step)
        REFERENCES finding_observations(finding_id, operation_id, step)
);
CREATE TABLE delivery_decisions (
    id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    assessment_id TEXT NOT NULL REFERENCES assessments(id),
    destination TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('eligible','ineligible','deferred')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    revision INTEGER NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE INDEX delivery_finding_destination ON delivery_decisions(finding_id, destination, revision DESC);
CREATE TABLE reports (
    id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    assessment_id TEXT NOT NULL REFERENCES assessments(id),
    delivery_id TEXT NOT NULL REFERENCES delivery_decisions(id),
    destination TEXT NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    generated_at TEXT NOT NULL,
    UNIQUE (finding_id, assessment_id, delivery_id, artifact_id)
);
CREATE INDEX reports_finding_revision ON reports(finding_id, generated_at DESC);
CREATE TABLE delivery_events (
    id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    assessment_id TEXT NOT NULL REFERENCES assessments(id),
    delivery_id TEXT NOT NULL REFERENCES delivery_decisions(id),
    report_id TEXT NOT NULL REFERENCES reports(id),
    destination TEXT NOT NULL,
    external_ref TEXT NOT NULL,
    receipt_artifact_id TEXT REFERENCES artifacts(id),
    submitted_at TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    revision INTEGER NOT NULL UNIQUE,
    CHECK (length(external_ref) > 0 OR receipt_artifact_id IS NOT NULL),
    UNIQUE (report_id, destination, external_ref)
);
CREATE INDEX delivery_events_finding_revision ON delivery_events(finding_id, revision DESC);
CREATE TABLE experiences (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('primitive','negative','hypothesis','handoff','note')),
    statement TEXT NOT NULL,
    conditions TEXT NOT NULL,
    reopen_when TEXT NOT NULL,
    next_intent TEXT NOT NULL,
    action_id TEXT REFERENCES actions(id),
    finding_id TEXT REFERENCES findings(id),
    recorded_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX experiences_kind_id ON experiences(kind, id);
CREATE TABLE experience_observations (
    experience_id TEXT NOT NULL REFERENCES experiences(id),
    operation_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    PRIMARY KEY (experience_id, operation_id, step),
    FOREIGN KEY (operation_id, step) REFERENCES observations(operation_id, step)
);
CREATE TABLE case_actors (
    id TEXT PRIMARY KEY NOT NULL,
    role TEXT NOT NULL,
    label TEXT NOT NULL,
    notes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE case_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    actor_id TEXT NOT NULL REFERENCES case_actors(id),
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    validity TEXT NOT NULL,
    last_checked TEXT NOT NULL,
    notes TEXT NOT NULL,
    private_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX case_sessions_actor ON case_sessions(actor_id, id);
CREATE TABLE case_objects (
    ref TEXT PRIMARY KEY NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    owner_actor TEXT REFERENCES case_actors(id),
    endpoint TEXT NOT NULL,
    status TEXT NOT NULL,
    notes TEXT NOT NULL,
    private_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX case_objects_owner ON case_objects(owner_actor, ref);
CREATE TABLE experience_case_context (
    experience_id TEXT PRIMARY KEY NOT NULL REFERENCES experiences(id),
    vuln_class TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    status TEXT NOT NULL,
    why_now TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE experience_case_actors (
    experience_id TEXT NOT NULL REFERENCES experiences(id),
    actor_id TEXT NOT NULL REFERENCES case_actors(id),
    PRIMARY KEY (experience_id, actor_id)
);
CREATE TABLE experience_case_objects (
    experience_id TEXT NOT NULL REFERENCES experiences(id),
    object_ref TEXT NOT NULL REFERENCES case_objects(ref),
    PRIMARY KEY (experience_id, object_ref)
);
CREATE TABLE audit (
    revision INTEGER PRIMARY KEY CHECK (revision > 0),
    command_id TEXT NOT NULL UNIQUE,
    command TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    recorded_at TEXT NOT NULL
);
CREATE TABLE action_completions (
    action_id TEXT PRIMARY KEY NOT NULL REFERENCES actions(id),
    claim_token TEXT NOT NULL REFERENCES audit(command_id),
    action_version INTEGER NOT NULL CHECK (action_version > 0),
    operation_id TEXT REFERENCES operations(id),
    artifact_id TEXT REFERENCES artifacts(id),
    command_id TEXT REFERENCES audit(command_id),
    CHECK ((operation_id IS NOT NULL) + (artifact_id IS NOT NULL) + (command_id IS NOT NULL) = 1)
);
""" + _COVERAGE_REVIEW_SCHEMA


class StoreError(ValueError):
    """Invalid, missing or unreadable canonical state; never an empty result."""


class ConflictError(StoreError):
    """Stale revision, conflicting identity or reuse of an idempotency key."""


class FindingNotFoundError(StoreError):
    """An admitted Store has no finding with the requested ID."""


_ARTIFACT_EVENT_STATES = {
    "availability": frozenset({"available", "unavailable"}),
    "provenance": frozenset({"trusted", "revoked"}),
}
_SENSITIVE_ACTION_KEYS = frozenset({
    "access_token", "api_key", "authorization", "bearer", "client_secret", "cookie",
    "credential", "credentials", "csrf_token", "id_token", "password", "private_key",
    "refresh_token", "secret", "secret_value", "session_cookie", "set_cookie", "token",
})
_ACTION_IDENTITY_FIELDS = ("hypothesis_id", "family", "technique")


def _text(value: Any, field: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()) or "\x00" in value:
        raise StoreError(f"{field} must be {'a' if empty else 'a non-empty'} string without NUL")
    return value.strip()


def _identifier(value: Any, field: str) -> str:
    value = _text(value, field)
    if len(value) > 256 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", value):
        raise StoreError(f"{field} must be a bounded identifier, not a path")
    return value


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(_text(value, "timestamp").replace("Z", "+00:00"))
    except ValueError as exc:
        raise StoreError("timestamp must be ISO-8601 with a timezone") from exc
    if parsed.tzinfo is None:
        raise StoreError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _references(value: Any) -> list[tuple[str, int]]:
    if not isinstance(value, list) or not value:
        raise StoreError("evidence must be a non-empty list of {operation_id, step}")
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"operation_id", "step"}:
            raise StoreError("each evidence reference requires exactly operation_id and step")
        operation = _identifier(item["operation_id"], "operation_id")
        step = item["step"]
        if type(step) is not int or step < 0:
            raise StoreError("evidence step must be a non-negative integer")
        result.append((operation, step))
    if len(set(result)) != len(result):
        raise StoreError("duplicate evidence references")
    return sorted(result)


@contextmanager
def target_switch_lock(repo_root: str | Path, target: str, *, exclusive: bool = False):
    """Coordinate ordinary target mutations with an explicit cutover."""
    root = Path(repo_root).resolve()
    canonical = classify_target(_text(target, "target"))["target"]
    with open_target_lock_file(root, canonical, "target-switch.lock") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def target_cutover_lock(repo_root: str | Path, target: str):
    """Take the target-level exclusive lock while freezing legacy metadata."""
    with target_switch_lock(repo_root, target, exclusive=True):
        yield


@contextmanager
def target_mutation_lock(repo_root: str | Path, target: str):
    """Serialize target writes after acquiring the shared cutover lock."""
    with target_switch_lock(repo_root, target):
        root = Path(repo_root).resolve()
        canonical = classify_target(_text(target, "target"))["target"]
        with open_target_lock_file(root, canonical, "target.lock") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class TargetStore:
    """One target's domain commands and consistent read-only queries.

    Commands return an audit receipt. command_id belongs to one logical command;
    a real new execution always needs a new attempt_id, even for identical bytes.
    """

    def __init__(self, repo_root: str | Path, target: str, *, allow_preview: bool = False):
        if type(allow_preview) is not bool:
            raise StoreError("allow_preview must be boolean")
        self.root = Path(repo_root).resolve()
        self.target = classify_target(_text(target, "target"))["target"]
        self.key = target_storage_key(self.target)
        self.path = self.root / "state" / self.key / "metadata.sqlite3"
        self.fence_path = self.path.parent / "legacy-frozen.json"
        self.allow_preview = allow_preview

    def _read_fence(self) -> dict | None:
        """A durable fence prevents a missing database from reviving old state."""
        if not self.fence_path.exists() and not self.fence_path.is_symlink():
            return None
        if self.fence_path.resolve() != self.fence_path:
            raise StoreError(f"backend fence must not traverse symlinks: {self.fence_path}")
        try:
            fd = os.open(self.fence_path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                    raise StoreError(f"backend fence requires a private regular file: {self.fence_path}")
                raw = handle.read(4097)
            if len(raw) > 4096:
                raise ValueError("backend fence exceeds 4096 bytes")
            fence = json.loads(raw)
            if (not isinstance(fence, dict)
                    or set(fence) != {"schema_version", "target", "store_id", "source_manifest_sha256"}
                    or type(fence["schema_version"]) is not int or fence["schema_version"] != 1
                    or fence["target"] != self.target
                    or not isinstance(fence["store_id"], str)
                    or not re.fullmatch(r"[0-9a-f]{32}", fence["store_id"])
                    or not isinstance(fence["source_manifest_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", fence["source_manifest_sha256"])):
                raise ValueError("invalid backend fence identity or shape")
        except (OSError, ValueError) as exc:
            raise StoreError(f"backend fence unreadable: {self.fence_path}; inspect recovery state: {exc}") from exc
        return fence

    def _check_backend(self, meta) -> str:
        if "backend" not in meta.keys():
            raise StoreError(f"target store claims no backend role: {self.path}; re-run the isolated migration")
        role = meta["backend"]
        if role not in {"preview", "primary"}:
            raise StoreError(f"invalid target backend role: {self.path}")
        fence = self._read_fence()
        if role == "primary" and (fence is None or fence["store_id"] != meta["store_id"]):
            raise StoreError(f"primary store has no matching backend fence: {self.path}; explicit recovery required")
        if role == "preview" and fence is not None:
            raise StoreError(f"backend cutover incomplete: {self.path}; legacy fallback is forbidden")
        return role

    def _create_fence(self, store_id: str, source_manifest_sha256: str | None = None) -> None:
        """Publish the fresh-store fence before committing any domain facts."""
        fence = {"schema_version": 1, "target": self.target, "store_id": store_id,
                 "source_manifest_sha256": source_manifest_sha256 or _digest([])}
        fd = os.open(self.fence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(fence, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        fd = os.open(self.fence_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _check_path(self) -> None:
        if self.path.resolve() != self.path:
            raise StoreError(f"database path must not traverse symlinks: {self.path}")
        if not self.path.is_file():
            raise StoreError(f"target store missing: {self.path}; explicit initialization or migration required")
        if stat.S_IMODE(self.path.parent.stat().st_mode) & 0o077:
            raise StoreError(f"target store directory requires mode 0700: {self.path.parent}")
        if stat.S_IMODE(self.path.stat().st_mode) & 0o077:
            raise StoreError(f"target store requires private file permissions: {self.path}")

    def _prepare_store_directory(self) -> None:
        if self.path.resolve() != self.path:
            raise StoreError(f"database path must not traverse symlinks: {self.path}")
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)

    def initialize(self, *, allow_legacy: bool = False) -> None:
        self._prepare_store_directory()
        with target_switch_lock(self.root, self.target, exclusive=True):
            self._initialize_locked(allow_legacy=allow_legacy)

    def _initialize_locked(self, *, allow_legacy: bool = False) -> None:
        """Create an empty store exclusively; never import or overwrite legacy data.

        ``allow_legacy`` is reserved for the isolated-copy migration path, where
        legacy files exist by definition: the caller asserts it operates on a
        copy, never the live target. Exclusive creation, private file mode and
        the symlink guard all still apply.

        The role the store claims is recorded with the store itself. A store
        created exclusively (no legacy state beside it) is what the target's
        truth is read from, so it is ``primary``. A store created beside legacy
        data is an isolated-copy migration artifact: it is ``preview`` and never
        answers a read until the cutover flips it, because two writable backends
        must not describe one target.
        """
        if type(allow_legacy) is not bool:
            raise StoreError("allow_legacy must be boolean")
        # Domain owners only. Runtime state (session.json) and process locks are
        # explicitly outside the freeze scope (see the cutover contract), so a
        # target holding nothing but runtime state is still new: its first write
        # may claim the role instead of being pinned to the legacy backend.
        memory_dir = Path(os.environ.get("HUNT_MEMORY_DIR") or self.root / "hunt-memory").expanduser()
        legacy = [
            self.path.parent / name
            for name in ("action_queue.json", "case_state.json", "observations.json")
        ] + [
            self.root / "findings" / self.key / "findings.json",
            self.root / "findings" / self.key / "mutation-events.jsonl",
            self.root / "memory" / "evidence" / self.key / "ledger.jsonl",
            self.root / "memory" / "goals" / "targets" / f"{self.key}.json",
            legacy_target_profile_path(memory_dir, self.target),
        ]
        if not allow_legacy and any(path.exists() or path.is_symlink() for path in legacy):
            raise StoreError("legacy target state exists; migrate an isolated copy before cutover")
        if self.path.exists():
            raise FileExistsError(f"target store already exists: {self.path}")
        if self.fence_path.exists() or self.fence_path.is_symlink():
            raise StoreError(f"backend fence already exists: {self.fence_path}; explicit recovery required")
        backend = "preview" if allow_legacy else "primary"
        if self.path.resolve() != self.path:
            raise StoreError(f"database path must not traverse symlinks: {self.path}")
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if stat.S_IMODE(self.path.parent.stat().st_mode) & 0o077:
            if not allow_legacy:
                raise StoreError(f"target store directory requires mode 0700: {self.path.parent}")
            os.chmod(self.path.parent, 0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            store_id = uuid.uuid4().hex
            if backend == "primary":
                self._create_fence(store_id)
                scope_path = self.path.parent / "scope.json"
                if scope_path.exists() or scope_path.is_symlink():
                    read_scope_source(self.root, self.target)
                else:
                    write_scope_source_locked(self.root, self.target, {
                        "schema_version": SCOPE_SCHEMA_VERSION, "root_target": self.target})
            with self._connection(write=True, check=False, lock=False) as conn:
                conn.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
                conn.execute("""INSERT INTO store
                    (singleton,schema_version,target,store_id,backend,revision,created_at)
                    VALUES (1, ?, ?, ?, ?, 0, ?)""",
                             (SCHEMA_VERSION, self.target, store_id, backend, _now()))
                conn.executemany("INSERT INTO coverage_classes VALUES (?)", [(x,) for x in CANONICAL_VULN_CLASSES])
                conn.commit()
                conn.execute("PRAGMA journal_mode=WAL")
        except BaseException:
            # Only this call's exclusively-created, unpublished database is removed.
            # A published fence remains: recovery must not silently revive legacy state.
            self.path.unlink(missing_ok=True)
            raise

    def backend(self) -> str:
        """Report the role this store claims for its target.

        Never guesses. A store whose row cannot be read, or that predates the
        role column, is reported as a broken store instead of being treated as
        whichever backend would read more conveniently.
        """
        with self._connection() as conn:
            meta = conn.execute("SELECT * FROM store WHERE singleton=1").fetchone()
            return str(meta["backend"])

    def binding(self) -> dict[str, Any]:
        """Return the immutable target/store/revision binding for a read view."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT target, store_id, backend, revision FROM store WHERE singleton=1"
            ).fetchone()
            return {
                "target": str(row["target"]),
                "store_id": str(row["store_id"]),
                "backend": str(row["backend"]),
                "revision": int(row["revision"]),
            }

    def command_receipt(self, command_id: str) -> dict | None:
        """Read a committed command receipt without replaying its mutation."""
        command_id = _identifier(command_id, "command_id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM audit WHERE command_id=?", (command_id,)).fetchone()
            return dict(row) if row else None

    @contextmanager
    def _connection(self, *, write: bool = False, check: bool = True, lock: bool = True,
                    foreign_keys: bool = True):
        guard = target_mutation_lock(self.root, self.target) if write and lock else nullcontext()
        with guard:
            self._check_path()
            conn = None
            try:
                conn = sqlite3.connect(self.path.as_uri() + ("?mode=rw" if write else "?mode=ro"),
                                       uri=True, timeout=5, isolation_level=None)
                conn.row_factory = sqlite3.Row
                conn.execute(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")
                conn.execute("PRAGMA synchronous=FULL")
                if not write:
                    conn.execute("PRAGMA query_only=ON")
                if check:
                    conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                    meta = conn.execute("SELECT * FROM store WHERE singleton=1").fetchone()
                    if (not meta or meta["target"] != self.target
                            or meta["schema_version"] not in COMPATIBLE_SCHEMA_VERSIONS):
                        raise StoreError(f"target/schema mismatch in {self.path}; inspect migration state")
                    role = self._check_backend(meta)
                    if write and role == "preview" and not self.allow_preview:
                        raise StoreError("preview store is read-only outside explicit isolated migration")
                yield conn
            except sqlite3.DatabaseError as exc:
                raise StoreError(f"target store failure at {self.path}: {exc}") from exc
            finally:
                if conn is not None:
                    conn.close()  # Any uncommitted transaction is rolled back, including KeyboardInterrupt.

    def _command(self, command: str, command_id: str, entity_id: str, actor: str, material: Any, mutation) -> dict:
        # Mutations also persist these identities; normalizing only the audit
        # would leave claim tokens and receipt references pointing at other IDs.
        if command_id != _identifier(command_id, "command_id") or actor != _text(actor, "actor"):
            raise StoreError("command_id and actor must not have surrounding whitespace")
        digest = _digest(material)
        with self._connection(write=True) as conn:
            existing = conn.execute("SELECT * FROM audit WHERE command_id=?", (command_id,)).fetchone()
            if existing:
                if (existing["command"], existing["entity_id"], existing["actor"], existing["content_sha256"]) != (
                    command, entity_id, actor, digest
                ):
                    raise ConflictError(f"command_id {command_id} was already used for different content")
                return {**dict(existing), "replayed": True}
            revision = conn.execute("SELECT revision FROM store").fetchone()[0] + 1
            now = _now()
            mutation(conn, revision, now)
            conn.execute("UPDATE store SET revision=? WHERE singleton=1", (revision,))
            conn.execute("INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (revision, command_id, command, entity_id, actor, digest, now))
            receipt = dict(conn.execute("SELECT * FROM audit WHERE command_id=?", (command_id,)).fetchone())
            conn.commit()
            return {**receipt, "replayed": False}

    def _endpoint(self, value: Any) -> str:
        value = _text(value, "endpoint")
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or any(ord(char) < 32 or char.isspace() for char in value)
                or not url_belongs_to_target(value, self.target)):
            raise StoreError("endpoint must be an absolute HTTP(S) URL belonging to the target")
        return value

    @staticmethod
    def _method(value: Any) -> str:
        method = _text(value, "method").upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]*", method):
            raise StoreError("invalid observation method")
        return method

    @staticmethod
    def _action_metadata(value: Any) -> tuple[dict[str, Any], str]:
        """Keep AI action context bounded without making it a second owner."""
        if value is None:
            value = {}
        if not isinstance(value, Mapping):
            raise StoreError("action metadata must be an object")
        metadata = dict(value)
        for field in ("last_outcome", "tested_dimensions", "runner_operation_id"):
            if field in metadata:
                raise StoreError(f"action metadata field is Runner-owned: {field}")
        def reject_sensitive(node: Any, path: str) -> None:
            if isinstance(node, Mapping):
                for key, child in node.items():
                    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
                    if normalized in _SENSITIVE_ACTION_KEYS and child not in (None, "", [], {}):
                        raise StoreError(f"action metadata cannot contain sensitive field {path}.{key}")
                    reject_sensitive(child, f"{path}.{key}")
            elif isinstance(node, list):
                for index, child in enumerate(node):
                    reject_sensitive(child, f"{path}[{index}]")
        reject_sensitive(metadata, "metadata")
        try:
            encoded = json.dumps(metadata, sort_keys=True, ensure_ascii=False,
                                 allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise StoreError("action metadata must be JSON serializable") from exc
        if len(encoded.encode("utf-8")) > 32768:
            raise StoreError("action metadata exceeds 32768 bytes")
        return metadata, encoded

    def _validate_action_refs(self, metadata: Mapping[str, Any]) -> None:
        for field in ("evidence_ref", "baseline_ref"):
            ref = str(metadata.get(field) or "").strip()
            if ref:
                self._artifact(ref)
        refs = metadata.get("selected_knowledge_refs")
        if "selected_knowledge_refs" in metadata:
            if not isinstance(refs, list) or any(not isinstance(item, str) or not item.strip() for item in refs):
                raise StoreError("selected_knowledge_refs must be a list of non-empty references")
            cards_root = (self.root / "knowledge" / "cards").resolve()
            if refs and not cards_root.is_dir():
                raise StoreError("selected knowledge reference names a missing card directory")
            for ref in refs:
                path = (self.root / ref).resolve()
                if not path.is_relative_to(cards_root) or not path.is_file():
                    raise StoreError(f"selected knowledge reference is not a target-owned card: {ref}")
        dimension = str(metadata.get("active_dimension") or "").strip()
        if dimension and any(char.isspace() for char in dimension):
            raise StoreError("active_dimension must be a single-dimension label")
        for field in ("max_hypothesis_actions", "max_hypothesis_actions_cap"):
            if field not in metadata:
                continue
            value = metadata[field]
            if type(value) is not int or value < 1:
                raise StoreError(f"{field} must be a positive integer")
        cap = metadata.get("max_hypothesis_actions_cap")
        requested = metadata.get("max_hypothesis_actions")
        if cap is not None and requested is not None and requested > cap:
            raise StoreError("max_hypothesis_actions exceeds the stored action cap")

    def _candidate(self, candidate: Any) -> dict:
        if not isinstance(candidate, dict) or set(candidate) != {"id", "endpoint", "method", "family", "title", "claim"}:
            raise StoreError("candidate requires exactly id, endpoint, method, family, title and claim")
        return {"id": _identifier(candidate["id"], "finding_id"),
                "endpoint": self._endpoint(candidate["endpoint"]), "method": self._method(candidate["method"]),
                "family": normalize_family(candidate["family"]), "title": _text(candidate["title"], "title"),
                "claim": _text(candidate["claim"], "claim")}

    @staticmethod
    def _ensure_finding(conn, claim: dict, now: str) -> None:
        existing = conn.execute("SELECT * FROM findings WHERE id=?", (claim["id"],)).fetchone()
        if existing and any(existing[key] != value for key, value in claim.items()):
            raise ConflictError("finding ID is already bound to a different claim; no implicit overwrite")
        if not existing:
            conn.execute("""INSERT INTO findings (id,endpoint,method,family,title,claim,created_at)
                VALUES (:id,:endpoint,:method,:family,:title,:claim,:created_at)""", {**claim, "created_at": now})

    def create_finding(self, *, command_id: str, finding_id: str, endpoint: str, method: str,
                       family: str, title: str, claim: str, actor: str) -> dict:
        """Save an unassessed claim without inventing execution evidence or a verdict."""
        candidate = self._candidate({"id": finding_id, "endpoint": endpoint, "method": method,
                                     "family": family, "title": title, "claim": claim})

        def mutate(conn, revision, now):
            self._ensure_finding(conn, candidate, now)

        return self._command("create_finding", command_id, candidate["id"], actor, candidate, mutate)

    def create_action(self, *, command_id: str, action_id: str, intent: str,
                      execution_key: str, actor: str, endpoint: str | None = None,
                      family: str | None = None, kind: str = "execution", subject: dict | None = None,
                      priority: int | None = None, repeat_of: str | None = None, repeat_reason: str = "",
                      metadata: Mapping[str, Any] | None = None) -> dict:
        """Create execution intent or explicit non-execution work, never infer it from prose.

        Work subjects name exactly one target, URL, published artifact, finding
        or experience. Only execution actions can own attempts.
        """
        action_id = _identifier(action_id, "action_id")
        subject_artifact = None
        finding_id = experience_id = None
        if kind == "execution":
            if subject is not None:
                raise StoreError("execution actions use endpoint/family, not a work subject")
            endpoint, family = self._endpoint(endpoint), normalize_family(family)
        elif kind == "work":
            if endpoint is not None or family is not None:
                raise StoreError("work actions use a subject, not execution endpoint/family")
            if not isinstance(subject, dict) or len(subject) != 1:
                raise StoreError("work subject requires exactly one target, url, artifact, finding_id or experience_id")
            key, value = next(iter(subject.items()))
            if key == "target":
                if classify_target(_text(value, "subject target"))["target"] != self.target:
                    raise StoreError("work subject belongs to a different target")
            elif key == "url":
                endpoint = self._endpoint(value)
            elif key == "artifact":
                subject_artifact = self._artifact(value)
            elif key == "finding_id":
                finding_id = _identifier(value, "finding_id")
            elif key == "experience_id":
                experience_id = _identifier(value, "experience_id")
            else:
                raise StoreError("unknown work subject kind")
        else:
            raise StoreError("action kind must be execution or work")
        if repeat_of is not None:
            repeat_of = _identifier(repeat_of, "repeat_of")
        repeat_reason = _text(repeat_reason, "repeat_reason", empty=repeat_of is None)
        if repeat_of is None and repeat_reason:
            raise StoreError("repeat_reason requires repeat_of")
        intent, execution_key = _text(intent, "intent"), _text(execution_key, "execution_key")
        metadata_value, metadata_json = self._action_metadata(metadata)
        self._validate_action_refs(metadata_value)
        fields = (intent, metadata_json, kind, endpoint, family, subject_artifact, finding_id, experience_id,
                  execution_key, repeat_of, repeat_reason, priority)
        if priority is not None and (type(priority) is not int or not -(2**63) <= priority < 2**63):
            raise StoreError("priority must be an explicit integer or null")

        def mutate(conn, revision, now):
            previous = conn.execute("SELECT id FROM actions WHERE execution_key=? LIMIT 1", (execution_key,)).fetchone()
            if previous and repeat_of is None:
                raise ConflictError("execution intent already exists; reuse it or explicitly link the repeated action")
            if repeat_of:
                original = conn.execute("SELECT * FROM actions WHERE id=?", (repeat_of,)).fetchone()
                if not original or original["execution_key"] != execution_key or original["status"] not in {"completed", "cancelled"}:
                    raise ConflictError("repeat_of must name a terminal action with the same execution key")
                if original["kind"] != kind:
                    raise ConflictError("repeated intent cannot change its execution/work kind")
            if subject_artifact:
                self._insert_artifact(conn, subject_artifact)
            conn.execute("""INSERT INTO actions
                (id,intent,metadata_json,kind,endpoint,family,subject_artifact_id,subject_finding_id,subject_experience_id,
                 execution_key,repeat_of,repeat_reason,priority,status,version,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'ready',1,?,?)""",
                (action_id, intent, metadata_json, kind, endpoint, family, subject_artifact["id"] if subject_artifact else None,
                 finding_id, experience_id, execution_key, repeat_of, repeat_reason, priority, now, now))

        return self._command("create_action", command_id, action_id, actor, fields, mutate)

    def transition_action(self, *, command_id: str, action_id: str, expected_version: int,
                          status: str, actor: str, reason: str = "", claim_token: str | None = None,
                          completion: dict | None = None,
                          metadata: Mapping[str, Any] | None = None) -> dict:
        action_id = _identifier(action_id, "action_id")
        if type(expected_version) is not int or expected_version < 1:
            raise StoreError("expected_version must be a positive integer")
        if not isinstance(status, str) or status not in {"ready", "claimed", "blocked", "completed", "cancelled"}:
            raise StoreError("invalid action status")
        reason = _text(reason, "reason", empty=status == "claimed")
        if claim_token is not None:
            claim_token = _identifier(claim_token, "claim_token")
        operation_id = result_artifact = receipt_id = None
        if status == "completed":
            if not isinstance(completion, dict) or len(completion) != 1:
                raise StoreError("completion requires exactly one operation_id, artifact or command_id reference")
            key, value = next(iter(completion.items()))
            if key == "operation_id":
                operation_id = _identifier(value, "operation_id")
                self.verify_operation(operation_id)
            elif key == "artifact":
                result_artifact = self._artifact(value)
            elif key == "command_id":
                receipt_id = _identifier(value, "completion command_id")
            else:
                raise StoreError("unknown completion reference kind")
        elif completion is not None:
            raise StoreError("completion reference is only accepted when completing an action")
        metadata_value, metadata_json = self._action_metadata(metadata)
        fields = (expected_version, status, reason, claim_token, operation_id, result_artifact, receipt_id,
                  metadata_json)

        def mutate(conn, revision, now):
            row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if not row or row["version"] != expected_version:
                raise ConflictError(f"action {action_id} missing or version changed; reload before writing")
            if row["status"] in {"completed", "cancelled"}:
                raise ConflictError("terminal actions are immutable; create an explicitly linked new intent")
            try:
                current_metadata = json.loads(row["metadata_json"] or "{}")
            except (TypeError, ValueError) as exc:
                raise StoreError("stored action metadata is corrupt") from exc
            if not isinstance(current_metadata, dict):
                raise StoreError("stored action metadata is not an object")
            self._validate_action_refs(metadata_value)
            for field in ("max_hypothesis_actions_cap",):
                if field in metadata_value and metadata_value[field] != current_metadata.get(field):
                    raise ConflictError(f"action metadata field {field} is immutable after creation")
            conflicts = {
                field: (str(current_metadata.get(field) or "").strip(), str(metadata_value.get(field) or "").strip())
                for field in _ACTION_IDENTITY_FIELDS
                if str(current_metadata.get(field) or "").strip()
                and str(metadata_value.get(field) or "").strip()
                and str(current_metadata.get(field) or "").strip() != str(metadata_value.get(field) or "").strip()
            }
            if conflicts and not str(metadata_value.get("repeat_reason") or "").strip():
                detail = ", ".join(f"{field}: {old!r} -> {new!r}" for field, (old, new) in conflicts.items())
                raise ConflictError(f"action metadata cannot re-identify an existing action ({detail})")
            merged_metadata = {**current_metadata, **metadata_value}
            self._validate_action_refs(merged_metadata)
            _, merged_metadata_json = self._action_metadata(merged_metadata)
            if status == "claimed":
                if row["status"] != "ready":
                    raise ConflictError("only a ready action can be claimed")
                if claim_token is not None:
                    raise StoreError("claim token is assigned by the owner, not the caller")
                cap = merged_metadata.get("max_hypothesis_actions")
                stored_cap = merged_metadata.get("max_hypothesis_actions_cap")
                if stored_cap is not None and (type(stored_cap) is not int or stored_cap < 1):
                    raise StoreError("max_hypothesis_actions_cap must be a positive integer")
                if cap is not None and stored_cap is not None and cap > stored_cap:
                    raise ConflictError("max_hypothesis_actions exceeds the stored action cap")
                hypothesis_id = str(merged_metadata.get("hypothesis_id") or "").strip()
                if cap is not None:
                    if type(cap) is not int or cap < 1:
                        raise StoreError("max_hypothesis_actions must be a positive integer")
                    if hypothesis_id:
                        spent = conn.execute(
                            """SELECT count(*) FROM actions WHERE id<>? AND status IN ('claimed','blocked')
                               AND json_extract(metadata_json, '$.hypothesis_id')=?""",
                            (action_id, hypothesis_id),
                        ).fetchone()[0]
                        if spent + 1 > cap:
                            raise ConflictError("hypothesis action budget is exhausted")
                token = command_id
            else:
                if row["status"] == "claimed" and (row["claim_token"] != claim_token or row["claimed_by"] != actor):
                    raise ConflictError("action is claimed by another command/operator")
                if row["status"] != "claimed" and claim_token is not None:
                    raise ConflictError("unclaimed action does not accept a claim token")
                pending = conn.execute("""SELECT 1 FROM attempts a WHERE a.action_id=?
                    AND NOT EXISTS (SELECT 1 FROM operations o WHERE o.attempt_id=a.id) LIMIT 1""", (action_id,)).fetchone()
                if pending:
                    raise ConflictError("execution outcome unknown; record the attempt before releasing its claim")
                if status == "completed" and row["status"] != "claimed":
                    raise ConflictError("completion requires an explicit claim")
                if status == "completed":
                    if row["kind"] == "execution":
                        if not operation_id or not conn.execute("""SELECT 1 FROM attempts a
                            JOIN operations o ON o.attempt_id=a.id
                            WHERE o.id=? AND a.action_id=? AND a.claim_token=? AND o.outcome='complete'
                            AND NOT EXISTS (SELECT 1 FROM operations n WHERE n.supersedes=o.id)""",
                            (operation_id, action_id, claim_token)).fetchone():
                            raise ConflictError("completion requires a complete observation from this claim")
                    elif operation_id:
                        raise StoreError("work completion requires a produced artifact or domain command receipt")
                    if receipt_id:
                        receipt = conn.execute("""SELECT e.action_id,a.actor,a.revision FROM experiences e
                            JOIN audit a ON a.entity_id=e.id AND a.command='remember'
                            WHERE a.command_id=?""", (receipt_id,)).fetchone()
                        claim_revision = conn.execute("SELECT revision FROM audit WHERE command_id=?", (claim_token,)).fetchone()[0]
                        if (not receipt or receipt["action_id"] != action_id or receipt["actor"] != actor
                                or receipt["revision"] <= claim_revision):
                            raise ConflictError("completion receipt must record work for this action and current claim")
                    if result_artifact:
                        self._insert_artifact(conn, result_artifact)
                    conn.execute("INSERT INTO action_completions VALUES (?,?,?,?,?,?)",
                                 (action_id, claim_token, expected_version, operation_id,
                                  result_artifact["id"] if result_artifact else None, receipt_id))
                token = None
            conn.execute("""UPDATE actions SET metadata_json=?,status=?,claim_token=?,claimed_by=?,reason=?,
                version=version+1,updated_at=? WHERE id=?""",
                         (merged_metadata_json, status, token, actor if token else None, reason, now, action_id))

        return self._command("transition_action", command_id, action_id, actor, fields, mutate)

    def start_attempt(self, *, attempt_id: str, source: str, started_at: str, actor: str,
                      action_id: str | None = None, claim_token: str | None = None) -> dict:
        attempt_id = _identifier(attempt_id, "attempt_id")
        source, started_at = _text(source, "source"), _timestamp(started_at)
        if action_id is not None:
            action_id = _identifier(action_id, "action_id")
            claim_token = _identifier(claim_token, "claim_token")
        elif claim_token is not None:
            raise StoreError("claim_token requires an action_id")
        fields = (action_id, claim_token, source, started_at)

        def mutate(conn, revision, now):
            if action_id:
                action = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
                if not action or (action["status"], action["claim_token"], action["claimed_by"]) != ("claimed", claim_token, actor):
                    raise ConflictError("attempt must bind to the current action claim")
                if action["kind"] != "execution":
                    raise StoreError("only execution actions can own execution attempts")
            conn.execute("INSERT INTO attempts VALUES (?,?,?,?,?)", (attempt_id, *fields))

        return self._command("start_attempt", f"start:{_digest(attempt_id)}", attempt_id, actor, fields, mutate)

    def _artifact(self, ref: Any) -> dict:
        raw = _text(ref, "artifact ref")
        try:
            path = target_raw_artifact_path(self.root, self.target, raw)
        except ValueError as exc:
            raise StoreError(str(exc)) from exc
        digest = hashlib.sha256()
        # Nonblocking open prevents a malicious FIFO from hanging registration.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size == 0:
                raise StoreError(f"artifact must be a non-empty regular file: {path}")
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(handle.fileno())
        version = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if version(before) != version(after) or version(after) != version(path.stat()):
            raise ConflictError(f"artifact changed while hashing: {path}; publish it before registration")
        reference, sha256 = path.relative_to(self.root).as_posix(), digest.hexdigest()
        return {"id": "artifact:" + _digest((reference, sha256)), "ref": reference,
                "sha256": sha256, "size": after.st_size}

    @staticmethod
    def _insert_artifact(conn, artifact: dict) -> None:
        conn.execute("INSERT INTO artifacts VALUES (?,?,?,?) ON CONFLICT(id) DO NOTHING",
                     (artifact["id"], artifact["ref"], artifact["sha256"], artifact["size"]))

    @staticmethod
    def _artifact_events(conn, artifact_id: str) -> dict[str, dict]:
        rows = conn.execute("""SELECT e.* FROM artifact_events e
            JOIN (SELECT dimension,max(revision) AS revision FROM artifact_events
                  WHERE artifact_id=? GROUP BY dimension) latest
              ON latest.dimension=e.dimension AND latest.revision=e.revision
            WHERE e.artifact_id=?""", (artifact_id, artifact_id))
        return {str(row["dimension"]): dict(row) for row in rows}

    def _artifact_status(self, conn, artifact: dict) -> dict:
        events = self._artifact_events(conn, str(artifact["id"]))
        try:
            bytes_valid = self._artifact(artifact["ref"]) == artifact
        except (OSError, ValueError, StoreError):
            bytes_valid = False
        availability = events.get("availability", {}).get("state", "unrecorded")
        provenance = events.get("provenance", {}).get("state", "active")
        available = bytes_valid and availability != "unavailable"
        return {
            "artifact_id": artifact["id"],
            "ref": artifact["ref"],
            "bytes_valid": bytes_valid,
            "availability": availability,
            "provenance": provenance,
            "available": available,
            "authorized": available and provenance != "revoked",
            "events": events,
        }

    def artifact_status(self, artifact_id: str) -> dict:
        """Derive current usability from immutable bytes plus append-only events."""
        artifact_id = _identifier(artifact_id, "artifact_id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if not row:
                raise StoreError(f"artifact missing: {artifact_id}")
            return self._artifact_status(conn, dict(row))

    def record_artifact_event(self, *, command_id: str, artifact_id: str, dimension: str,
                              state: str, reason: str, actor: str) -> dict:
        """Append an availability or provenance fact without rewriting the artifact."""
        artifact_id = _identifier(artifact_id, "artifact_id")
        dimension, state = _text(dimension, "artifact event dimension"), _text(state, "artifact event state")
        reason = _text(reason, "reason")
        if dimension not in _ARTIFACT_EVENT_STATES or state not in _ARTIFACT_EVENT_STATES[dimension]:
            raise StoreError("invalid artifact event dimension/state")
        with self._connection() as conn:
            artifact = conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if not artifact:
                raise StoreError(f"artifact missing: {artifact_id}")
            artifact = dict(artifact)
        if state in {"available", "trusted"}:
            try:
                current = self._artifact(artifact["ref"])
            except (OSError, ValueError) as exc:
                raise StoreError(f"artifact cannot be revalidated: {artifact['ref']}") from exc
            if current != artifact:
                raise StoreError(f"artifact cannot be revalidated: {artifact['ref']}")
        material = (artifact_id, dimension, state, reason)

        def mutate(conn, revision, now):
            if not conn.execute("SELECT 1 FROM artifacts WHERE id=?", (artifact_id,)).fetchone():
                raise StoreError(f"artifact missing: {artifact_id}")
            conn.execute("INSERT INTO artifact_events VALUES (?,?,?,?,?,?,?,?)",
                         (command_id, artifact_id, dimension, state, reason, actor, revision, now))

        return self._command("record_artifact_event", command_id, command_id, actor, material, mutate)

    def _observation(self, raw: Any, outcome: str) -> tuple[dict, list[dict]]:
        required = {"endpoint", "method", "family", "observed_at", "description", "artifacts"}
        optional = {"actor", "object_scope", "variant", "error", "truncated", "state_changing", "redline_checked",
                    "result", "identity_status", "identity_technique", "identity_v2", "identity_dimensions", "detail"}
        if not isinstance(raw, dict) or not required <= raw.keys() or raw.keys() - required - optional:
            raise StoreError("observation has missing or unknown fields")
        fields = {"endpoint": self._endpoint(raw["endpoint"]), "method": self._method(raw["method"]),
                  "family": normalize_family(raw["family"]), "observed_at": _timestamp(raw["observed_at"]),
                  "description": _text(raw["description"], "description"),
                  "detail_json": self._detail(raw.get("detail"))}
        for name in ("actor", "object_scope", "variant", "error"):
            fields[name] = _text(raw.get(name, ""), name, empty=True)
        for name in ("truncated", "redline_checked"):
            if type(raw.get(name, False)) is not bool:
                raise StoreError(f"{name} must be boolean")
            fields[name] = raw.get(name, False)
        fields["state_changing"] = raw.get("state_changing")
        if fields["state_changing"] is not None and type(fields["state_changing"]) is not bool:
            raise StoreError("state_changing must be boolean or null")
        fields["result"] = self._observation_result(raw.get("result", ""))
        status = str(raw.get("identity_status") or "none").strip().lower()
        if status not in {"complete", "none", "incomplete", "conflict"}:
            raise StoreError("identity_status must be complete, none, incomplete or conflict")
        technique = str(raw.get("identity_technique") or "").strip()
        if len(technique) > 256:
            raise StoreError("identity_technique is longer than 256 characters")
        identity_v2 = raw.get("identity_v2")
        if identity_v2 is None:
            identity_v2 = {}
        if not isinstance(identity_v2, Mapping):
            raise StoreError("identity_v2 must be an object")
        try:
            identity_v2_json = json.dumps(dict(identity_v2), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise StoreError("identity_v2 must be JSON serializable") from exc
        if len(identity_v2_json.encode("utf-8")) > 8192:
            raise StoreError("identity_v2 exceeds 8192 bytes")
        if status == "complete" and (not technique or not identity_v2 or raw.get("identity_technique") is None):
            raise StoreError("complete identity requires identity_technique and identity_v2")
        role = json.loads(fields["detail_json"]).get("evidence_role", "unknown")
        if role not in {"subject", "control", "unknown"}:
            raise StoreError("evidence_role must be subject, control or unknown")
        if role == "control" and status != "none":
            raise StoreError("control evidence requires identity_status none")
        fields["identity_status"] = status
        fields["identity_technique"] = technique
        fields["identity_v2"] = identity_v2_json
        fields["identity_dimensions"] = self._identity_dimensions(raw.get("identity_dimensions"))
        if outcome == "complete" and (fields["error"] or fields["truncated"]):
            raise StoreError("incomplete observations require partial or unknown outcome")
        if not isinstance(raw["artifacts"], dict) or not raw["artifacts"]:
            raise StoreError("each observation requires raw artifacts")
        kinds = [(_identifier(kind, "artifact kind"), ref) for kind, ref in raw["artifacts"].items()]
        bindings = [{"kind": kind, **self._artifact(ref)} for kind, ref in sorted(kinds)]
        return fields, bindings

    @staticmethod
    def _observation_result(value: Any) -> str:
        """Admit the shared terminal vocabulary; empty means "no verdict recorded"."""
        result = str(value or "").strip().lower().replace("-", "_")
        if result and result not in LEDGER_RESULTS:
            raise StoreError(f"unknown observation result: {value!r}. Allowed: {', '.join(LEDGER_RESULTS)}")
        return result

    @staticmethod
    def _identity_dimensions(value: Any) -> str:
        """Store authored cell dimensions as facts; the identity contract judges them.

        Structure only: admission must not depend on the canonical taxonomy
        (families stay open), so unknown keys are stored and reported as
        conflicts by the closure derivation instead of being rejected here.
        """
        if value is None:
            return "{}"
        if not isinstance(value, Mapping):
            raise StoreError("identity_dimensions must be an object")
        if len(value) > 16:
            raise StoreError("identity_dimensions accepts at most 16 fields")
        cleaned: dict[str, str] = {}
        for key, item in value.items():
            name = _text(key, "identity dimension name")
            if len(name) > 64:
                raise StoreError("identity dimension name is longer than 64 characters")
            if isinstance(item, (Mapping, list, tuple, set)) or item is None or isinstance(item, bool):
                raise StoreError(f"identity dimension {name} must be a scalar value")
            text = str(item).strip()
            if not text:
                continue
            if len(text) > 256:
                raise StoreError(f"identity dimension {name} is longer than 256 characters")
            cleaned[name] = text
        return json.dumps(cleaned, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _detail(value: Any) -> str:
        if value is None:
            return "{}"
        if not isinstance(value, Mapping):
            raise StoreError("observation detail must be an object")
        if any(not isinstance(key, str) or not key.strip() for key in value):
            raise StoreError("observation detail keys must be non-empty strings")
        try:
            encoded = json.dumps(dict(value), ensure_ascii=True, sort_keys=True,
                                 allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise StoreError("observation detail must be JSON serializable") from exc
        if len(encoded.encode("utf-8")) > 32768:
            raise StoreError("observation detail exceeds 32768 bytes")
        return encoded

    def record_execution(self, *, attempt_id: str, outcome: str, observations: list[dict], actor: str,
                         candidate: dict | None = None, expected_operation: str | None = None) -> dict:
        """Register published files atomically; never execute or assess a vulnerability."""
        attempt_id = _identifier(attempt_id, "attempt_id")
        if not isinstance(outcome, str) or outcome not in {"complete", "partial", "unknown"}:
            raise StoreError("execution outcome must be complete, partial or unknown")
        if not isinstance(observations, list) or (not observations and outcome != "unknown"):
            raise StoreError("observations must be a list; only unknown outcome may have no observations")
        prepared = [self._observation(row, outcome) for row in observations]
        claim = None
        if candidate is not None:
            claim = self._candidate(candidate)
            if not any(all(row[k] == claim[k] for k in ("endpoint", "method", "family")) for row, _ in prepared):
                raise StoreError("candidate must bind an exact observed endpoint, method and family")
        if expected_operation is not None:
            expected_operation = _identifier(expected_operation, "expected_operation")
        material = (attempt_id, outcome, prepared, claim, expected_operation)
        operation_id = "operation:" + _digest(material)

        def mutate(conn, revision, now):
            attempt = conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            if not attempt:
                raise StoreError("attempt missing; retain raw files and explicitly register the execution attempt")
            previous = conn.execute("SELECT id FROM operations WHERE attempt_id=? ORDER BY revision DESC LIMIT 1", (attempt_id,)).fetchone()
            if (previous[0] if previous else None) != expected_operation:
                raise ConflictError("attempt already registered; explicitly reference the prior operation to add evidence")
            if any(row["observed_at"] < attempt["started_at"] for row, _ in prepared):
                raise StoreError("observation predates its execution attempt")
            if attempt["action_id"] and prepared:
                action = conn.execute("SELECT * FROM actions WHERE id=?", (attempt["action_id"],)).fetchone()
                if not any(row["endpoint"] == action["endpoint"] and row["family"] == action["family"] for row, _ in prepared):
                    raise StoreError("execution observations must include the bound action's endpoint and family")
            columns = {str(item[1]) for item in conn.execute("PRAGMA table_info(observations)").fetchall()}
            has_identity_v3 = {"identity_status", "identity_technique", "identity_v2"} <= columns
            if not has_identity_v3 and any(
                row["identity_status"] != "none" or row["identity_technique"] or row["identity_v2"] != "{}"
                for row, _ in prepared
            ):
                raise StoreError("Store schema v11 is required to persist complete observation identity; run explicit upgrade")
            conn.execute("INSERT INTO operations VALUES (?,?,?,?,?,?,?)",
                         (operation_id, attempt_id, expected_operation, revision, outcome, _digest(material), now))
            for step, (row, bindings) in enumerate(prepared):
                if has_identity_v3:
                    conn.execute("""INSERT INTO observations
                    (operation_id,step,endpoint,method,family,coverage_class,observed_at,description,detail_json,
                     actor,object_scope,variant,error,truncated,state_changing,redline_checked,result,
                     identity_status,identity_technique,identity_v2,identity_dimensions)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                             (operation_id, step, row["endpoint"], row["method"], row["family"], coverage_family(row["family"]),
                              row["observed_at"], row["description"], row["detail_json"], row["actor"], row["object_scope"], row["variant"],
                              row["error"], row["truncated"], row["state_changing"], row["redline_checked"],
                              row["result"], row["identity_status"], row["identity_technique"], row["identity_v2"],
                              row["identity_dimensions"]))
                else:
                    conn.execute("""INSERT INTO observations
                    (operation_id,step,endpoint,method,family,coverage_class,observed_at,description,detail_json,
                     actor,object_scope,variant,error,truncated,state_changing,redline_checked,result,identity_dimensions)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                             (operation_id, step, row["endpoint"], row["method"], row["family"], coverage_family(row["family"]),
                              row["observed_at"], row["description"], row["detail_json"], row["actor"], row["object_scope"], row["variant"],
                              row["error"], row["truncated"], row["state_changing"], row["redline_checked"],
                              row["result"], row["identity_dimensions"]))
                for binding in bindings:
                    self._insert_artifact(conn, binding)
                    conn.execute("INSERT INTO observation_artifacts VALUES (?,?,?,?)",
                                 (operation_id, step, binding["kind"], binding["id"]))
            if claim:
                self._ensure_finding(conn, claim, now)
                conn.executemany("INSERT INTO finding_observations VALUES (?,?,?)",
                                 [(claim["id"], operation_id, step) for step in range(len(prepared))])

        return self._command("record_execution", f"record:{_digest(material)}", operation_id, actor, material, mutate)

    def assess(self, *, command_id: str, finding_id: str, verdict: str, reason: str, boundary: str,
               impact: str, evidence: list[dict], actor: str, expected_assessment: str | None) -> dict:
        finding_id = _identifier(finding_id, "finding_id")
        if not isinstance(verdict, str) or verdict not in {"confirmed", "refuted", "inconclusive"}:
            raise StoreError("invalid technical verdict")
        reason = _text(reason, "reason")
        boundary, impact = _text(boundary, "boundary"), _text(impact, "impact", empty=verdict != "confirmed")
        refs = _references(evidence)
        if expected_assessment is not None:
            expected_assessment = _identifier(expected_assessment, "expected_assessment")
        for operation, _ in refs:
            self.verify_operation(operation)
        material = (finding_id, verdict, reason, boundary, impact, refs, expected_assessment)

        def mutate(conn, revision, now):
            previous = conn.execute("SELECT id FROM assessments WHERE finding_id=? ORDER BY revision DESC LIMIT 1", (finding_id,)).fetchone()
            if (previous[0] if previous else None) != expected_assessment:
                raise ConflictError("technical assessment changed; reload before submitting a new judgment")
            for operation, step in refs:
                row = conn.execute("""SELECT o.outcome,b.error,b.truncated,b.state_changing,b.redline_checked
                    FROM finding_observations f JOIN operations o ON o.id=f.operation_id
                    JOIN observations b ON b.operation_id=f.operation_id AND b.step=f.step
                    WHERE f.finding_id=? AND f.operation_id=? AND f.step=?""", (finding_id, operation, step)).fetchone()
                if not row:
                    raise StoreError("assessment evidence is not linked to this finding")
                if verdict == "confirmed" and (row["outcome"] != "complete" or row["error"] or row["truncated"]
                                              or (row["state_changing"] and not row["redline_checked"])):
                    raise StoreError("partial, unknown or unchecked state-changing evidence cannot confirm a finding")
            conn.execute("INSERT INTO assessments VALUES (?,?,?,?,?,?,?,?,?)",
                         (command_id, finding_id, verdict, reason, boundary, impact, actor, revision, now))
            conn.executemany("INSERT INTO assessment_observations VALUES (?,?,?,?)",
                             [(command_id, finding_id, operation, step) for operation, step in refs])

        return self._command("assess", command_id, command_id, actor, material, mutate)

    def decide_delivery(self, *, command_id: str, finding_id: str, assessment_id: str, destination: str,
                        status: str, reason: str, actor: str, expected_decision: str | None) -> dict:
        finding_id, assessment_id = _identifier(finding_id, "finding_id"), _identifier(assessment_id, "assessment_id")
        destination, reason = _text(destination, "destination"), _text(reason, "reason")
        if not isinstance(status, str) or status not in {"eligible", "ineligible", "deferred"}:
            raise StoreError("invalid destination eligibility status")
        if expected_decision is not None:
            expected_decision = _identifier(expected_decision, "expected_decision")
        material = (finding_id, assessment_id, destination, status, reason, expected_decision)

        def mutate(conn, revision, now):
            assessment = conn.execute("SELECT * FROM assessments WHERE finding_id=? ORDER BY revision DESC LIMIT 1", (finding_id,)).fetchone()
            if not assessment or assessment["id"] != assessment_id:
                raise ConflictError("delivery decision must bind the current technical assessment")
            if status == "eligible" and assessment["verdict"] != "confirmed":
                raise StoreError("eligible delivery requires a confirmed technical assessment")
            previous = conn.execute("""SELECT id FROM delivery_decisions WHERE finding_id=? AND destination=?
                ORDER BY revision DESC LIMIT 1""", (finding_id, destination)).fetchone()
            if (previous[0] if previous else None) != expected_decision:
                raise ConflictError("destination decision changed; reload before writing")
            conn.execute("INSERT INTO delivery_decisions VALUES (?,?,?,?,?,?,?,?,?)",
                         (command_id, finding_id, assessment_id, destination, status, reason, actor, revision, now))

        return self._command("decide_delivery", command_id, command_id, actor, material, mutate)

    def register_report(self, *, command_id: str, report_id: str, finding_id: str,
                        assessment_id: str, delivery_id: str, artifact: str,
                        actor: str) -> dict:
        """Register a published report only for the current assessment/delivery."""
        report_id = _identifier(report_id, "report_id")
        finding_id = _identifier(finding_id, "finding_id")
        assessment_id = _identifier(assessment_id, "assessment_id")
        delivery_id = _identifier(delivery_id, "delivery_id")
        artifact_value = self._artifact(artifact)
        current = self.finding(finding_id)
        current_assessment = current.get("assessment") or {}
        current_delivery = next(
            (item for item in current.get("deliveries", []) if item.get("id") == delivery_id),
            None,
        )
        if (current_assessment.get("id") != assessment_id or not current_delivery
                or current_delivery.get("stale") or current_delivery.get("status") != "eligible"):
            raise StoreError("report registration requires the current eligible delivery decision")
        material = (report_id, finding_id, assessment_id, delivery_id, artifact_value)

        def mutate(conn, revision, now):
            finding = conn.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone()
            assessment = conn.execute("SELECT * FROM assessments WHERE id=? AND finding_id=?",
                                      (assessment_id, finding_id)).fetchone()
            delivery = conn.execute("SELECT * FROM delivery_decisions WHERE id=? AND finding_id=? AND assessment_id=?",
                                    (delivery_id, finding_id, assessment_id)).fetchone()
            if not finding or not assessment or not delivery:
                raise ConflictError("report must bind an existing finding, assessment and delivery")
            latest_assessment = conn.execute(
                "SELECT id FROM assessments WHERE finding_id=? ORDER BY revision DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
            latest_delivery = conn.execute(
                "SELECT id,status FROM delivery_decisions WHERE finding_id=? AND destination=? "
                "ORDER BY revision DESC LIMIT 1",
                (finding_id, delivery["destination"]),
            ).fetchone()
            if (not latest_assessment or latest_assessment["id"] != assessment_id
                    or not latest_delivery or latest_delivery["id"] != delivery_id):
                raise ConflictError("report must bind the current assessment and delivery decision")
            if delivery["status"] != "eligible" or latest_delivery["status"] != "eligible":
                raise StoreError("report registration requires an eligible delivery decision")
            self._insert_artifact(conn, artifact_value)
            conn.execute("""INSERT INTO reports
                (id,finding_id,assessment_id,delivery_id,destination,artifact_id,generated_at)
                VALUES (?,?,?,?,?,?,?)""",
                         (report_id, finding_id, assessment_id, delivery_id, delivery["destination"],
                          artifact_value["id"], now))

        return self._command("register_report", command_id, report_id, actor, material, mutate)

    def record_delivery_event(self, *, command_id: str, event_id: str, report_id: str,
                              external_ref: str, submitted_at: str, actor: str,
                              receipt_artifact: str = "") -> dict:
        """Record an explicit external submission; report generation never implies it."""
        event_id = _identifier(event_id, "event_id")
        report_id = _identifier(report_id, "report_id")
        external_ref = _text(external_ref, "external_ref", empty=bool(receipt_artifact))
        submitted_at = _timestamp(submitted_at)
        receipt = self._artifact(receipt_artifact) if receipt_artifact else None
        with self._connection() as conn:
            row = conn.execute("SELECT finding_id FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            raise StoreError(f"report missing: {report_id}")
        finding = self.finding(str(row["finding_id"]))
        report = next((item for item in finding.get("reports", []) if item.get("id") == report_id), None)
        if not report or report.get("stale"):
            raise StoreError("delivery event requires a current eligible report artifact")
        material = (event_id, report_id, external_ref, submitted_at, receipt)

        def mutate(conn, revision, now):
            current = conn.execute("""SELECT r.*, d.status, d.destination FROM reports r
                JOIN delivery_decisions d ON d.id=r.delivery_id WHERE r.id=?""", (report_id,)).fetchone()
            if not current:
                raise ConflictError("delivery event report disappeared")
            latest_assessment = conn.execute(
                "SELECT id FROM assessments WHERE finding_id=? ORDER BY revision DESC LIMIT 1",
                (current["finding_id"],),
            ).fetchone()
            latest_delivery = conn.execute(
                "SELECT id,status FROM delivery_decisions WHERE finding_id=? AND destination=? "
                "ORDER BY revision DESC LIMIT 1",
                (current["finding_id"], current["destination"]),
            ).fetchone()
            if (not latest_assessment or latest_assessment["id"] != current["assessment_id"]
                    or not latest_delivery or latest_delivery["id"] != current["delivery_id"]
                    or latest_delivery["status"] != "eligible"):
                raise ConflictError("delivery event must bind the current eligible report")
            if receipt:
                self._insert_artifact(conn, receipt)
            conn.execute("""INSERT INTO delivery_events
                (id,finding_id,assessment_id,delivery_id,report_id,destination,external_ref,
                 receipt_artifact_id,submitted_at,submitted_by,revision)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                         (event_id, current["finding_id"], current["assessment_id"],
                          current["delivery_id"], report_id, current["destination"], external_ref,
                          receipt["id"] if receipt else None, submitted_at, actor, revision))

        return self._command("record_delivery_event", command_id, event_id, actor, material, mutate)

    def coverage_endpoint(self, value: str) -> str:
        """Validate ownership before projecting an authored review to a path."""
        value = _text(value, "coverage endpoint")
        if not value.startswith("/"):
            value = self._endpoint(value)
        elif value.startswith("//"):
            raise StoreError("coverage endpoint must be a target-relative path, not a network-path URL")
        if any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in value) or "\\" in value:
            raise StoreError("invalid coverage endpoint")
        return extract_endpoint_path(value) or "/"

    @staticmethod
    def _require_coverage_schema(conn) -> None:
        if conn.execute("SELECT schema_version FROM store WHERE singleton=1").fetchone()[0] < 10:
            raise StoreError("coverage review schema upgrade required; run explicit upgrade-schema with a backup")

    def normalize_coverage_review(self, *, endpoint: str, kind: str, value: str,
                                  family: str | None = None, reason: str = "",
                                  source: str = "manual", reviewed_at: str = "",
                                  historical: bool = False, candidate: dict | None = None) -> dict:
        """Validate a review without reading or writing target state."""
        endpoint = self.coverage_endpoint(endpoint)
        if kind == "endpoint_kind":
            if not isinstance(value, str) or value not in ENDPOINT_KIND_VALUES or family is not None:
                raise StoreError("endpoint-kind review requires a valid kind and no family")
        elif kind == "cell_status":
            if not isinstance(value, str) or value not in COVERAGE_REVIEW_STATUSES:
                raise StoreError("cell review requires a valid coverage status")
            family = coverage_family(normalize_family(family))
            if family is None:
                raise StoreError("cell review requires a canonical coverage family")
        else:
            raise StoreError("unknown coverage review kind")
        if not isinstance(source, str) or source not in FINAL_ENDPOINT_KIND_SOURCES | {"legacy_import"}:
            raise StoreError("unknown coverage review source")
        if type(historical) is not bool or (source == "legacy_import" and not historical):
            raise StoreError("legacy coverage reviews must be historical")
        reason = _text(reason, "reason", empty=True)
        reviewed_at = _text(reviewed_at, "reviewed_at", empty=True)
        reviewed_at = _timestamp(reviewed_at) if reviewed_at else ""
        claim = self._candidate(candidate) if candidate is not None else None
        if claim and (historical or kind != "cell_status" or value != "tested_finding"
                      or self.coverage_endpoint(claim["endpoint"]) != endpoint
                      or coverage_family(claim["family"]) != family):
            raise StoreError("coverage finding claim must match the current cell review")
        return {"endpoint": endpoint, "kind": kind, "family": family, "value": value,
                "reason": reason, "source": source, "reviewed_at": reviewed_at,
                "historical": historical, "candidate": claim}

    def record_coverage_review(self, *, command_id: str, endpoint: str, kind: str, value: str,
                               actor: str, family: str | None = None, reason: str = "",
                               source: str = "manual", reviewed_at: str = "",
                               historical: bool = False, candidate: dict | None = None) -> dict:
        """Append an authored review, never an execution or closure verdict."""
        material = self.normalize_coverage_review(
            endpoint=endpoint, kind=kind, value=value, family=family, reason=reason,
            source=source, reviewed_at=reviewed_at, historical=historical, candidate=candidate,
        )
        claim = material["candidate"]

        def mutate(conn, revision, now):
            self._require_coverage_schema(conn)
            if claim:
                existing = conn.execute("SELECT * FROM findings WHERE id=?", (claim["id"],)).fetchone()
                if existing:
                    if any(existing[key] != claim[key] for key in ("endpoint", "method", "family")):
                        raise ConflictError("coverage finding identity changed")
                    # The existing claim is immutable; this review retains the new reason.
                else:
                    self._ensure_finding(conn, claim, now)
            conn.execute("""INSERT INTO coverage_reviews
                (id,endpoint,kind,family,value,reason,source,recorded_by,reviewed_at,
                 historical,finding_id,revision,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (command_id, material["endpoint"], material["kind"], material["family"],
                          material["value"], material["reason"], material["source"], actor,
                          material["reviewed_at"] or ("" if material["historical"] else now), int(material["historical"]),
                          claim["id"] if claim else None, revision, now))

        return self._command("record_coverage_review", command_id, command_id, actor, material, mutate)

    def coverage_review(self, review_id: str) -> dict:
        review_id = _identifier(review_id, "review_id")
        with self._connection() as conn:
            self._require_coverage_schema(conn)
            row = conn.execute("SELECT * FROM coverage_reviews WHERE id=?", (review_id,)).fetchone()
            if row is None:
                raise StoreError(f"coverage review missing: {review_id}")
            return dict(row)

    def coverage_review_page(self, *, endpoint: str | None = None, latest: bool = True,
                             limit: int = 50, cursor: str | None = None) -> dict:
        """Latest authored values or full history, with stable revision-bound pagination."""
        self._require_limit(limit)
        if type(latest) is not bool:
            raise StoreError("latest must be boolean")
        endpoint = self.coverage_endpoint(endpoint) if endpoint is not None else None
        with self._connection() as conn:
            self._require_coverage_schema(conn)
            meta = dict(conn.execute("SELECT * FROM store WHERE singleton=1").fetchone())
            binding = {**self._binding(meta, "coverage_reviews"), "endpoint": endpoint, "latest": latest}
            after = self._cursor_after(binding, cursor)
            conditions, params = [], []
            if endpoint is not None:
                conditions.append("r.endpoint=?")
                params.append(endpoint)
            if latest:
                # Backfilled history must never replace a review authored after cutover.
                conditions.append("""NOT EXISTS (SELECT 1 FROM coverage_reviews n
                    WHERE n.endpoint=r.endpoint AND n.kind=r.kind AND n.family IS r.family
                    AND (n.historical<r.historical OR
                        (n.historical=r.historical AND n.revision>r.revision)))""")
            condition = " AND ".join(conditions) or "1"
            total = conn.execute(f"SELECT count(*) FROM coverage_reviews r WHERE {condition}", params).fetchone()[0]
            remaining = conn.execute(f"SELECT count(*) FROM coverage_reviews r WHERE {condition} AND r.id>?",
                                     (*params, after)).fetchone()[0]
            rows = [dict(row) for row in conn.execute(
                f"SELECT r.* FROM coverage_reviews r WHERE {condition} AND r.id>? ORDER BY r.id LIMIT ?",
                (*params, after, limit))]
            return self._slice(conn, binding, total=total, remaining=remaining, rows=rows, limit=limit)

    def remember(self, *, command_id: str, kind: str, statement: str, conditions: str, reopen_when: str,
                 next_intent: str, evidence: list[dict], actor: str,
                 action_id: str | None = None, finding_id: str | None = None) -> dict:
        if not isinstance(kind, str) or kind not in {"primitive", "negative", "hypothesis", "handoff", "note"}:
            raise StoreError("invalid experience kind")
        statement, conditions = _text(statement, "statement"), _text(conditions, "conditions")
        reopen_when = _text(reopen_when, "reopen_when", empty=kind != "negative")
        next_intent = _text(next_intent, "next_intent", empty=True)
        refs = _references(evidence) if evidence else []
        if not isinstance(evidence, list) or (kind in {"negative", "primitive"} and not refs):
            raise StoreError("negative/primitive experience must cite observations")
        if action_id is not None:
            action_id = _identifier(action_id, "action_id")
        if finding_id is not None:
            finding_id = _identifier(finding_id, "finding_id")
        material = (kind, statement, conditions, reopen_when, next_intent, refs, action_id, finding_id)

        def mutate(conn, revision, now):
            if kind == "note":
                self._require_memory_schema(conn)
            conn.execute("INSERT INTO experiences VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (command_id, kind, statement, conditions, reopen_when, next_intent, action_id, finding_id, actor, now))
            conn.executemany("INSERT INTO experience_observations VALUES (?,?,?)",
                             [(command_id, operation, step) for operation, step in refs])

        return self._command("remember", command_id, command_id, actor, material, mutate)

    @staticmethod
    def _require_memory_schema(conn) -> None:
        version = conn.execute("SELECT schema_version FROM store WHERE singleton=1").fetchone()[0]
        if version < 9:
            raise StoreError("target memory schema upgrade required; run explicit upgrade-memory with a backup")

    def active_goal(self) -> str:
        with self._connection() as conn:
            self._require_memory_schema(conn)
            return str(conn.execute("SELECT active_goal FROM store WHERE singleton=1").fetchone()[0])

    def set_active_goal(self, *, command_id: str, goal: str, actor: str,
                        expected_revision: int | None = None) -> dict:
        goal = _text(goal, "active_goal", empty=True)
        if expected_revision is None:
            with self._connection() as conn:
                receipt = conn.execute("SELECT revision FROM audit WHERE command_id=?", (command_id,)).fetchone()
                # A committed goal command advanced revision exactly once.
                # Reuse its original CAS input; _command still checks identity/content.
                expected_revision = (receipt[0] - 1 if receipt else
                                     conn.execute("SELECT revision FROM store WHERE singleton=1").fetchone()[0])
        if type(expected_revision) is not int or expected_revision < 0:
            raise StoreError("expected_revision must be a non-negative integer")

        def mutate(conn, revision, now):
            self._require_memory_schema(conn)
            if revision != expected_revision + 1:
                raise ConflictError("target goal revision changed; reload before updating")
            conn.execute("UPDATE store SET active_goal=? WHERE singleton=1", (goal,))

        return self._command("set_active_goal", command_id, self.target, actor,
                             (goal, expected_revision), mutate)

    @staticmethod
    def _case_role(value: Any) -> str:
        role = _text(value, "role")
        if role not in {"anonymous", "user", "low_role", "admin_like", "service", "unknown"}:
            raise StoreError("unknown actor role")
        return role

    @staticmethod
    def _case_kind(value: Any) -> str:
        kind = _text(value, "session kind")
        if kind not in {"cookie", "bearer", "browser_state", "api_key", "custom_header", "unknown"}:
            raise StoreError("unknown session kind")
        return kind

    def _private_ref(self, value: Any, field: str = "private_ref") -> str:
        ref = _text(value, field, empty=True)
        if not ref:
            return ""
        path = Path(ref)
        if path.is_absolute() or ".." in path.parts or not ref.startswith(".private/"):
            raise StoreError(f"{field} must be a relative private artifact reference")
        if not ref.startswith(f".private/case-state/{self.key}/"):
            raise StoreError(f"{field} must stay inside this target's private case-state directory")
        return ref

    def _check_private_material(self, ref: str, field: str, identity: tuple[str, str],
                                extra: tuple[tuple[str, Any], ...] = ()) -> None:
        if not ref:
            return
        self._private_ref(ref, field)
        path = (self.root / ref).resolve()
        if path != self.root / ref or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise StoreError(f"private case material unavailable: {ref}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StoreError(f"private case material unreadable: {ref}") from exc
        key, expected = identity
        if not isinstance(payload, dict) or payload.get(key) != expected:
            raise StoreError(f"private case material identity mismatch: {ref}")
        if payload.get("schema_version") != 1 or payload.get("target") != self.target:
            raise StoreError(f"private case material metadata mismatch: {ref}")
        if any(payload.get(name) != value for name, value in extra):
            raise StoreError(f"private case material owner mismatch: {ref}")
        digest = payload.get("content_sha256")
        if not isinstance(digest, str):
            raise StoreError(f"private case material digest missing: {ref}")
        unsigned = dict(payload)
        unsigned.pop("content_sha256", None)
        if _digest(unsigned) != digest or not path.name.endswith(f"-{digest[:16]}.json"):
            raise StoreError(f"private case material digest mismatch: {ref}")

    def upsert_case_actor(self, *, command_id: str, actor_id: str, role: str = "unknown",
                          label: str = "", notes: str = "", actor: str) -> dict:
        actor_id = _identifier(actor_id, "actor_id")
        role, label, notes = self._case_role(role), _text(label, "label", empty=True), _text(notes, "notes", empty=True)
        material = (actor_id, role, label, notes)

        def mutate(conn, revision, now):
            current = conn.execute("SELECT created_at FROM case_actors WHERE id=?", (actor_id,)).fetchone()
            conn.execute("""INSERT INTO case_actors(id,role,label,notes,created_at,last_seen)
                VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET role=excluded.role,
                label=excluded.label,notes=excluded.notes,last_seen=excluded.last_seen""",
                         (actor_id, role, label, notes, current[0] if current else now, now))

        return self._command("upsert_case_actor", command_id, actor_id, actor, material, mutate)

    def upsert_case_session(self, *, command_id: str, session_id: str, actor_id: str,
                            kind: str = "unknown", source: str = "manual", validity: str = "unknown",
                            last_checked: str = "", notes: str = "", private_ref: str = "", actor: str) -> dict:
        session_id = _identifier(session_id, "session_id")
        actor_id = _identifier(actor_id, "actor_id")
        kind, source = self._case_kind(kind), _text(source, "source", empty=True)
        validity, last_checked = _text(validity, "validity", empty=True), _text(last_checked, "last_checked", empty=True)
        notes, private_ref = _text(notes, "notes", empty=True), self._private_ref(private_ref)
        self._check_private_material(private_ref, "private_ref", ("session_id", session_id),
                                     (("actor", actor_id), ("kind", kind)))
        material = (session_id, actor_id, kind, source, validity, last_checked, notes, private_ref)

        def mutate(conn, revision, now):
            if not conn.execute("SELECT 1 FROM case_actors WHERE id=?", (actor_id,)).fetchone():
                raise StoreError(f"actor does not exist: {actor_id}")
            current = conn.execute("SELECT created_at FROM case_sessions WHERE id=?", (session_id,)).fetchone()
            conn.execute("""INSERT INTO case_sessions
                (id,actor_id,kind,source,validity,last_checked,notes,private_ref,created_at,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET actor_id=excluded.actor_id,
                kind=excluded.kind,source=excluded.source,validity=excluded.validity,
                last_checked=excluded.last_checked,notes=excluded.notes,private_ref=excluded.private_ref,
                last_seen=excluded.last_seen""",
                         (session_id, actor_id, kind, source, validity, last_checked, notes, private_ref,
                          current[0] if current else now, now))

        return self._command("upsert_case_session", command_id, session_id, actor, material, mutate)

    def upsert_case_object(self, *, command_id: str, object_ref: str, object_type: str,
                           object_id: str = "", owner_actor: str = "", endpoint: str = "",
                           status: str = "active", notes: str = "", private_ref: str = "", actor: str) -> dict:
        object_ref = _identifier(object_ref, "object_ref")
        object_type = _text(object_type, "object_type")
        object_id, owner_actor = _text(object_id, "object_id", empty=True), _text(owner_actor, "owner_actor", empty=True)
        endpoint = self._endpoint(endpoint) if endpoint else ""
        status, notes, private_ref = _text(status, "status"), _text(notes, "notes", empty=True), self._private_ref(private_ref)
        if owner_actor:
            owner_actor = _identifier(owner_actor, "owner_actor")
        self._check_private_material(private_ref, "private_ref", ("object_ref", object_ref),
                                     (("owner_actor", owner_actor or ""),))
        material = (object_ref, object_type, object_id, owner_actor, endpoint, status, notes, private_ref)

        def mutate(conn, revision, now):
            if owner_actor and not conn.execute("SELECT 1 FROM case_actors WHERE id=?", (owner_actor,)).fetchone():
                raise StoreError(f"actor does not exist: {owner_actor}")
            current = conn.execute("SELECT created_at FROM case_objects WHERE ref=?", (object_ref,)).fetchone()
            conn.execute("""INSERT INTO case_objects
                (ref,object_type,object_id,owner_actor,endpoint,status,notes,private_ref,created_at,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ref) DO UPDATE SET object_type=excluded.object_type,
                object_id=excluded.object_id,owner_actor=excluded.owner_actor,endpoint=excluded.endpoint,
                status=excluded.status,notes=excluded.notes,private_ref=excluded.private_ref,
                last_seen=excluded.last_seen""",
                         (object_ref, object_type, object_id, owner_actor or None, endpoint, status, notes,
                          private_ref, current[0] if current else now, now))

        return self._command("upsert_case_object", command_id, object_ref, actor, material, mutate)

    def remember_hypothesis(self, *, command_id: str, hypothesis_id: str, vuln_class: str,
                            endpoint: str = "", object_ref: str = "", actor_ids: list[str] | None = None,
                            why_now: str = "", status: str = "open", metadata: Mapping[str, Any] | None = None,
                            actor: str) -> dict:
        hypothesis_id = _identifier(hypothesis_id, "hypothesis_id")
        vuln_class = _text(vuln_class, "vuln_class")
        endpoint = self._endpoint(endpoint) if endpoint else ""
        object_ref = _identifier(object_ref, "object_ref") if object_ref else ""
        actor_ids = [_identifier(item, "actor_id") for item in (actor_ids or [])]
        if len(set(actor_ids)) != len(actor_ids):
            raise StoreError("duplicate hypothesis actors")
        why_now, status = _text(why_now, "why_now", empty=True), _text(status, "status")
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, Mapping):
            raise StoreError("hypothesis metadata must be an object")
        try:
            metadata_json = json.dumps(dict(metadata), sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise StoreError("hypothesis metadata must be JSON serializable") from exc
        material = (hypothesis_id, vuln_class, endpoint, object_ref, tuple(actor_ids), why_now, status, metadata_json)

        def mutate(conn, revision, now):
            for actor_id in actor_ids:
                if not conn.execute("SELECT 1 FROM case_actors WHERE id=?", (actor_id,)).fetchone():
                    raise StoreError(f"actor does not exist: {actor_id}")
            if object_ref and not conn.execute("SELECT 1 FROM case_objects WHERE ref=?", (object_ref,)).fetchone():
                raise StoreError(f"object_ref does not exist: {object_ref}")
            existing = conn.execute("SELECT * FROM experiences WHERE id=?", (hypothesis_id,)).fetchone()
            values = (hypothesis_id, "hypothesis", vuln_class, why_now, "", "", None, None, actor, now)
            if existing:
                if any(existing[key] != value for key, value in zip(
                        ("id", "kind", "statement", "conditions", "reopen_when", "next_intent", "action_id", "finding_id", "recorded_by"), values[:-1])):
                    raise ConflictError("hypothesis id is already bound to different content")
                conn.execute("DELETE FROM experience_case_context WHERE experience_id=?", (hypothesis_id,))
                conn.execute("DELETE FROM experience_case_actors WHERE experience_id=?", (hypothesis_id,))
                conn.execute("DELETE FROM experience_case_objects WHERE experience_id=?", (hypothesis_id,))
            else:
                conn.execute("INSERT INTO experiences VALUES (?,?,?,?,?,?,?,?,?,?)", values)
            conn.execute("""INSERT INTO experience_case_context
                (experience_id,vuln_class,endpoint,status,why_now,metadata_json) VALUES (?,?,?,?,?,?)""",
                         (hypothesis_id, vuln_class, endpoint, status, why_now, metadata_json))
            conn.executemany("INSERT INTO experience_case_actors VALUES (?,?)",
                             [(hypothesis_id, item) for item in actor_ids])
            if object_ref:
                conn.execute("INSERT INTO experience_case_objects VALUES (?,?)", (hypothesis_id, object_ref))

        return self._command("remember_hypothesis", command_id, hypothesis_id, actor, material, mutate)

    def case_state(self, *, include_hypotheses: bool = True) -> dict:
        """Read-only Case projection; it has no action or ranking fields."""
        if include_hypotheses:
            context = self.case_context()
        else:
            with self._connection() as conn:
                context = self._case_entities(conn)
        return {
            "schema_version": 1,
            "target": self.target,
            "target_key": self.key,
            "created_at": context["created_at"],
            "updated_at": context["updated_at"],
            "actors": {row["id"]: {k: row[k] for k in ("role", "label", "notes", "created_at", "last_seen")}
                       for row in context["actors"]},
            "sessions": {row["id"]: {k: row[k] for k in ("actor", "kind", "source", "validity", "last_checked", "notes", "private_ref", "created_at", "last_seen")}
                         for row in context["sessions"]},
            "objects": {row["ref"]: {**{k: row[k] for k in ("type", "object_id", "owner_actor", "endpoint", "status", "notes", "private_ref", "created_at", "last_seen")},
                                        "private_marker": "<redacted>" if row.get("private_ref") else ""}
                        for row in context["objects"]},
            **({"hypotheses": context["hypotheses"]} if include_hypotheses else {}),
        }

    def _case_entities(self, conn) -> dict:
        """Read and verify the entity snapshot without materializing hypothesis history."""
        meta = dict(conn.execute("SELECT * FROM store").fetchone())
        actors = [dict(row) for row in conn.execute("SELECT * FROM case_actors ORDER BY id")]
        sessions = [dict(row) for row in conn.execute("""SELECT id,actor_id AS actor,kind,source,validity,
            last_checked,notes,private_ref,created_at,last_seen FROM case_sessions ORDER BY id""")]
        objects = [dict(row) for row in conn.execute("""SELECT ref,object_type AS type,object_id,owner_actor,
            endpoint,status,notes,private_ref,created_at,last_seen FROM case_objects ORDER BY ref""")]
        for item in sessions:
            self._check_private_material(item["private_ref"], "private_ref", ("session_id", item["id"]),
                                         (("actor", item["actor"]), ("kind", item["kind"])))
        for item in objects:
            self._check_private_material(item["private_ref"], "private_ref", ("object_ref", item["ref"]),
                                         (("owner_actor", item["owner_actor"] or ""),))
        authenticated = [item for item in sessions if item["private_ref"] and item["validity"].lower() not in {"invalid", "expired", "revoked"}]
        actor_ids = {item["actor"] for item in authenticated}
        authz_status = "ready" if len(actor_ids) >= 2 else "partial" if actor_ids else "missing"
        return {"target": self.target, "target_key": self.key, "store_id": meta["store_id"],
                "revision": meta["revision"], "created_at": meta["created_at"], "updated_at": meta["created_at"],
                "actors": actors, "sessions": sessions, "objects": objects,
                "authz_coverage": {"status": authz_status, "authenticated_actor_count": len(actor_ids),
                                   "authenticated_session_count": len(authenticated)}}

    def case_object_refs(self) -> set[str]:
        with self._connection() as conn:
            return {item["ref"] for item in self._case_entities(conn)["objects"]}

    def case_summary(self) -> dict:
        with self._connection() as conn:
            context = self._case_entities(conn)
            open_hypotheses = conn.execute("""SELECT COUNT(*) FROM experiences e
                JOIN experience_case_context c ON c.experience_id=e.id
                WHERE e.kind='hypothesis' AND c.status='open'""").fetchone()[0]
        return {
            "target": context["target"], "target_key": context["target_key"],
            "actors": len(context["actors"]), "sessions": len(context["sessions"]),
            "authz_coverage": context["authz_coverage"], "objects": len(context["objects"]),
            "open_hypotheses": open_hypotheses,
            "object_samples": [
                {"object_ref": item["ref"], "type": item["type"], "object_id": item["object_id"],
                 "endpoint": item["endpoint"], "owner_actor": item["owner_actor"],
                 "private_marker": "<redacted>" if item.get("private_ref") else ""}
                for item in context["objects"][:8]
            ],
        }

    def case_context(self) -> dict:
        with self._connection() as conn:
            context = self._case_entities(conn)
            hypothesis_actors: dict[str, list[str]] = {}
            for row in conn.execute("SELECT experience_id,actor_id FROM experience_case_actors ORDER BY experience_id,actor_id"):
                hypothesis_actors.setdefault(row["experience_id"], []).append(row["actor_id"])
            hypothesis_objects: dict[str, str] = {}
            for row in conn.execute("SELECT experience_id,object_ref FROM experience_case_objects ORDER BY experience_id,object_ref"):
                hypothesis_objects.setdefault(row["experience_id"], row["object_ref"])
            hypotheses = []
            for row in conn.execute("""SELECT e.id,c.vuln_class,c.endpoint,c.status,c.why_now,c.metadata_json,e.created_at,
                e.recorded_by FROM experiences e JOIN experience_case_context c ON c.experience_id=e.id
                WHERE e.kind='hypothesis' ORDER BY e.id"""):
                item = dict(row)
                item["actors"] = hypothesis_actors.get(row["id"], [])
                item["object_ref"] = hypothesis_objects.get(row["id"], "")
                try:
                    item["metadata"] = json.loads(item.pop("metadata_json"))
                except (TypeError, ValueError):
                    item["metadata"] = {}
                hypotheses.append(item)
            return {**context, "hypotheses": hypotheses}

    def verify_operation(self, operation_id: str) -> dict:
        """Check current bytes against registered evidence; no semantic trust is conferred."""
        operation_id = _identifier(operation_id, "operation_id")
        with self._connection() as conn:
            return self._verify_operation(conn, operation_id)

    def _verify_operation(self, conn, operation_id: str) -> dict:
        operation = conn.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
        if not operation:
            raise StoreError(f"operation missing: {operation_id}")
        artifacts = [dict(row) for row in conn.execute("""SELECT DISTINCT a.* FROM artifacts a
            JOIN observation_artifacts b ON b.artifact_id=a.id WHERE b.operation_id=?""", (operation_id,))]
        for expected in artifacts:
            self._require_valid_artifact(conn, expected)
        return {"operation_id": operation_id, "artifact_count": len(artifacts), "integrity": "valid",
                "outcome": operation["outcome"], "semantic_verification": False}

    def _require_valid_artifact(self, conn, expected: dict) -> None:
        status = self._artifact_status(conn, expected)
        if not status["bytes_valid"]:
            reason = "changed" if (self.root / expected["ref"]).exists() else "unavailable"
            raise StoreError(f"registered evidence {reason}: {expected['ref']}")
        if status["availability"] == "unavailable":
            raise StoreError(f"registered evidence is explicitly unavailable: {expected['ref']}")
        if status["provenance"] == "revoked":
            raise StoreError(f"registered evidence provenance is revoked: {expected['ref']}")

    def _report_rows(self, conn, rows: list[dict], assessment: dict | None,
                     deliveries: list[dict], *, assessment_valid: bool) -> list[dict]:
        current_delivery = {str(item["destination"]): item for item in deliveries}
        for report in rows:
            status = self._artifact_status(conn, {
                "id": report["artifact_id"], "ref": report["artifact_ref"],
                "sha256": report["artifact_sha256"], "size": report["artifact_size"],
            })
            current = current_delivery.get(str(report["destination"]))
            report["artifact_available"] = status["available"]
            report["artifact_authorized"] = status["authorized"]
            report["stale"] = not (
                assessment_valid
                and assessment
                and report["assessment_id"] == assessment["id"]
                and current
                and current["id"] == report["delivery_id"]
                and current["status"] == "eligible"
                and status["authorized"]
            )
        return rows

    def _delivery_event_rows(self, conn, finding_id: str, reports: list[dict]) -> list[dict]:
        """Return historical submissions without turning them into current eligibility."""
        current_reports = {str(item["id"]): item for item in reports}
        rows = [dict(item) for item in conn.execute("""SELECT e.*, a.ref AS receipt_ref,
                a.sha256 AS receipt_sha256, a.size AS receipt_size
            FROM delivery_events e LEFT JOIN artifacts a ON a.id=e.receipt_artifact_id
            WHERE e.finding_id=? ORDER BY e.revision""", (finding_id,))]
        for event in rows:
            report = current_reports.get(str(event["report_id"]))
            event["current_binding"] = bool(report and not report.get("stale"))
            if not event["receipt_artifact_id"]:
                event["receipt_available"] = None
                event["receipt_authorized"] = None
                continue
            status = self._artifact_status(conn, {
                "id": event["receipt_artifact_id"], "ref": event["receipt_ref"],
                "sha256": event["receipt_sha256"], "size": event["receipt_size"],
            })
            event["receipt_available"] = status["available"]
            event["receipt_authorized"] = status["authorized"]
        return rows

    _PAGE_TABLES = {"actions": "actions", "attempts": "attempts", "operations": "operations",
                    "findings": "findings", "experiences": "experiences"}
    _ACTION_STATES = ("ready", "claimed", "blocked", "completed", "cancelled")

    def _binding(self, meta: dict, kind: str, status: str | None = None) -> dict:
        return {"version": 1, "store_id": meta["store_id"], "target": self.target,
                "revision": meta["revision"], "kind": kind, "status": status}

    @staticmethod
    def _cursor_after(binding: dict, cursor: str | None) -> str:
        """Decode a revision-bound cursor, refusing a changed target/filter/snapshot."""
        if cursor is None:
            return ""
        try:
            if not isinstance(cursor, str) or len(cursor) > 4096:
                raise ValueError("invalid cursor")
            decoded = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
            if not isinstance(decoded, dict) or set(decoded) != {*binding, "after"}:
                raise ValueError("invalid cursor shape")
            after = _identifier(decoded.pop("after"), "cursor position")
        except (ValueError, TypeError, UnicodeError) as exc:
            raise StoreError("malformed page cursor") from exc
        if decoded != binding:
            raise ConflictError("cursor target, filter or snapshot changed; restart the query")
        return after

    @staticmethod
    def _cursor_next(binding: dict, after: str) -> str:
        return base64.urlsafe_b64encode(json.dumps({**binding, "after": after}, sort_keys=True).encode()).decode()

    def _slice(self, conn, binding: dict, *, total: int, remaining: int, rows: list[dict], limit: int) -> dict:
        next_cursor = self._cursor_next(binding, rows[-1]["id"]) if remaining > len(rows) else None
        return {**binding, "order": "id", "items": rows, "total": total, "remaining": remaining - len(rows),
                "has_more": next_cursor is not None, "next_cursor": next_cursor}

    def _page_conn(self, conn, meta: dict, kind: str, *, limit: int = 50,
                   cursor: str | None = None, status: str | None = None) -> dict:
        """Page one table on an already-open snapshot; callers may reuse the connection."""
        binding = self._binding(meta, kind, status)
        after = self._cursor_after(binding, cursor)
        table = self._PAGE_TABLES[kind]
        condition, params = ("status=?", [status]) if status is not None else ("1", [])
        total = conn.execute(f"SELECT count(*) FROM {table} WHERE {condition}", params).fetchone()[0]
        remaining = conn.execute(f"SELECT count(*) FROM {table} WHERE {condition} AND id>?", (*params, after)).fetchone()[0]
        rows = [dict(row) for row in conn.execute(f"SELECT * FROM {table} WHERE {condition} AND id>? ORDER BY id LIMIT ?",
                                                  (*params, after, limit))]
        if kind == "actions":
            for row in rows:
                try:
                    row["metadata"] = json.loads(row.pop("metadata_json") or "{}")
                except (TypeError, ValueError) as exc:
                    raise StoreError("stored action metadata is corrupt") from exc
                if not isinstance(row["metadata"], dict):
                    raise StoreError("stored action metadata is not an object")
        return self._slice(conn, binding, total=total, remaining=remaining, rows=rows, limit=limit)

    def page(self, kind: str, *, limit: int = 50, cursor: str | None = None, status: str | None = None) -> dict:
        """Stable ID order, exact remainder and revision-bound cursor; never refresh state."""
        if not isinstance(kind, str) or kind not in self._PAGE_TABLES:
            raise StoreError("query kind must be actions, attempts, operations, findings or experiences")
        self._require_limit(limit)
        if status is not None and (kind != "actions" or not isinstance(status, str) or status not in self._ACTION_STATES):
            raise StoreError("status filter is only supported for action states")
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            return self._page_conn(conn, meta, kind, limit=limit, cursor=cursor, status=status)

    def action_summary(self, *, limit: int = 5) -> dict:
        """Read bounded nonterminal work and exact counts on one Store snapshot."""
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            self._require_action_metadata(conn)
            counts = dict(conn.execute("""SELECT count(*) AS total,
                count(CASE WHEN status IN ('ready','claimed','blocked') THEN 1 END) AS pending
                FROM actions""").fetchone())
            rows = [dict(row) for row in conn.execute("""SELECT * FROM actions
                WHERE status IN ('ready','claimed','blocked') ORDER BY id LIMIT ?""", (limit,))]
            by_id = {row["id"]: row for row in rows}
            selected = {}
            for name, query in (
                ("next_action", "SELECT * FROM actions WHERE status IN ('ready','claimed') ORDER BY status='claimed' DESC,created_at,id LIMIT 1"),
                ("running_action", "SELECT * FROM actions WHERE status='claimed' ORDER BY id LIMIT 1"),
            ):
                item = conn.execute(query).fetchone()
                if item:
                    selected[name] = by_id.setdefault(item["id"], dict(item))
                else:
                    selected[name] = None
            for row in by_id.values():
                row["metadata"] = json.loads(row.pop("metadata_json"))
            families = [row[0] for row in conn.execute("""WITH values_by_action AS (
                SELECT id,0 AS position,COALESCE(family,
                    CASE WHEN json_type(metadata_json,'$.family')='text'
                         THEN json_extract(metadata_json,'$.family') END) AS value
                    FROM actions WHERE status IN ('ready','claimed')
                UNION ALL SELECT id,1,json_extract(metadata_json,'$.vuln_class') FROM actions
                    WHERE status IN ('ready','claimed') AND json_type(metadata_json,'$.vuln_class')='text'
                ), first_values AS (
                    SELECT *,row_number() OVER (PARTITION BY value ORDER BY id,position) AS occurrence
                    FROM values_by_action WHERE value IS NOT NULL
                ) SELECT value FROM first_values WHERE occurrence=1 ORDER BY id,position""")]
            return {**self._binding(meta, "actions"), "items": rows, "counts": counts,
                    "active_families": families, **selected}

    @staticmethod
    def _require_action_metadata(conn) -> None:
        # Filtered reads must not hide corrupt terminal metadata.
        if conn.execute("""SELECT 1 FROM actions WHERE CASE WHEN json_valid(metadata_json)
                THEN json_type(metadata_json) != 'object' ELSE 1 END LIMIT 1""").fetchone():
            raise StoreError("stored action metadata is corrupt or not an object")

    def action_page(self, *, statuses: tuple[str, ...] | None = None, action_type: str | None = None,
                    limit: int = 50, cursor: str | None = None) -> dict:
        """Filter before paging; explicit history readers may request terminal kinds."""
        self._require_limit(limit)
        if statuses is not None and (not isinstance(statuses, (tuple, list)) or not statuses
                                    or any(value not in self._ACTION_STATES for value in statuses)):
            raise StoreError("statuses must contain action states")
        if action_type is not None:
            action_type = _identifier(action_type, "action type")
        states = sorted(set(statuses)) if statuses is not None else sorted(self._ACTION_STATES)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            self._require_action_metadata(conn)
            binding = {**self._binding(meta, "actions"), "states": states, "action_type": action_type}
            after = self._cursor_after(binding, cursor)
            condition = f"status IN ({','.join('?' for _ in states)})"
            params = list(states)
            if action_type is not None:
                conn.create_function("strip_action_type", 1, str.strip, deterministic=True)
                condition += """ AND strip_action_type(CASE WHEN json_type(metadata_json,'$.action_context.type')='text'
                    THEN json_extract(metadata_json,'$.action_context.type') ELSE kind END)=?"""
                params.append(action_type)
            total = conn.execute(f"SELECT count(*) FROM actions WHERE {condition}", params).fetchone()[0]
            remaining = conn.execute(f"SELECT count(*) FROM actions WHERE {condition} AND id>?", (*params, after)).fetchone()[0]
            rows = [dict(row) for row in conn.execute(f"SELECT * FROM actions WHERE {condition} AND id>? ORDER BY id LIMIT ?",
                                                     (*params, after, limit))]
            for row in rows:
                row["metadata"] = json.loads(row.pop("metadata_json"))
            return self._slice(conn, binding, total=total, remaining=remaining, rows=rows, limit=limit)

    def final_action_endpoints(self) -> list[dict]:
        """Latest recorded terminal action per URL; advisory history, never closure."""
        with self._connection() as conn:
            self._require_action_metadata(conn)
            return [dict(row) for row in conn.execute("""SELECT id,endpoint,status FROM (
                SELECT id,endpoint,status,row_number() OVER (PARTITION BY endpoint ORDER BY id DESC) AS position
                FROM actions WHERE status IN ('blocked','completed','cancelled') AND endpoint IS NOT NULL
                ) WHERE position=1 ORDER BY id""")]

    def experience_page(self, *, kinds: list[str] | None = None, query: str = "",
                        limit: int = 20, cursor: str | None = None) -> dict:
        """Filter before limiting, then page newest experience with exact remainder."""
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store WHERE singleton=1").fetchone())
            return self._experience_page_conn(conn, meta, kinds=kinds, query=query, limit=limit, cursor=cursor)

    def memory_context(self, *, limit: int = 20) -> dict:
        """Read intent, current Case premise/handoff and bounded history on one snapshot.

        This is advisory memory, not Case readiness or authorization; private
        sessions/objects remain exclusively checked by the Case query.
        """
        with self._connection() as conn:
            self._require_memory_schema(conn)
            meta = dict(conn.execute("SELECT * FROM store WHERE singleton=1").fetchone())
            premise = conn.execute("""SELECT c.why_now FROM experiences e
                JOIN experience_case_context c ON c.experience_id=e.id
                WHERE e.kind='hypothesis'
                ORDER BY e.created_at DESC,
                    (SELECT min(a.revision) FROM audit a
                     WHERE a.entity_id=e.id AND a.command='remember_hypothesis') DESC,
                    e.id DESC LIMIT 1""").fetchone()
            page = self._experience_page_conn(conn, meta, limit=limit)
            handoffs = self._experience_page_conn(conn, meta, kinds=["handoff"], limit=1)["items"]
            return {"target": self.target, "store_id": meta["store_id"], "revision": meta["revision"],
                    "created_at": meta["created_at"], "active_goal": meta["active_goal"],
                    "current_hypothesis": premise[0] if premise else "", "experiences": page,
                    "current_handoff": handoffs[0] if handoffs else None}

    def _experience_page_conn(self, conn, meta: dict, *, kinds: list[str] | None = None,
                              query: str = "", limit: int = 20, cursor: str | None = None) -> dict:
        self._require_limit(limit)
        allowed = {"primitive", "negative", "hypothesis", "handoff", "note"}
        if kinds is not None and (not isinstance(kinds, list) or not kinds
                                   or any(not isinstance(kind, str) or kind not in allowed for kind in kinds)):
            raise StoreError("kinds must be a non-empty list of experience kinds")
        selected = sorted(set(kinds)) if kinds is not None else sorted(allowed)
        query = _text(query, "query", empty=True).lower()
        if len(query) > 512:
            raise StoreError("query exceeds 512 characters")
        terms = sorted(set(query.split()))
        binding = {**self._binding(meta, "experiences"), "kinds": selected,
                   "query": " ".join(terms), "order": "created_at_desc,id_desc"}
        after = None
        if cursor is not None:
            try:
                if not isinstance(cursor, str) or len(cursor) > 4096:
                    raise ValueError("invalid cursor")
                decoded = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
                if not isinstance(decoded, dict) or set(decoded) != {*binding, "after"}:
                    raise ValueError("invalid cursor shape")
                position = decoded.pop("after")
                if (not isinstance(position, list) or len(position) != 2
                        or not isinstance(position[0], str) or len(position[0]) > 64):
                    raise ValueError("invalid cursor position")
                after = (position[0], _identifier(position[1], "cursor position"))
            except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
                raise StoreError("malformed experience cursor") from exc
            if decoded != binding:
                raise ConflictError("cursor target, filter or snapshot changed; restart the query")
        predicates = [f"kind IN ({','.join('?' for _ in selected)})"]
        params: list[Any] = list(selected)
        haystack = "lower(statement || ' ' || conditions || ' ' || reopen_when || ' ' || next_intent)"
        if terms:
            predicates.append("(" + " OR ".join(f"instr({haystack}, ?) > 0" for _ in terms) + ")")
            params.extend(terms)
        where = " AND ".join(predicates)
        total = conn.execute(f"SELECT count(*) FROM experiences WHERE {where}", params).fetchone()[0]
        if after is not None:
            predicates.append("(created_at,id) < (?,?)")
            params.extend(after)
        where = " AND ".join(predicates)
        remaining = conn.execute(f"SELECT count(*) FROM experiences WHERE {where}", params).fetchone()[0]
        rows = [dict(row) for row in conn.execute(
            f"SELECT * FROM experiences WHERE {where} ORDER BY created_at DESC,id DESC LIMIT ?",
            (*params, limit))]
        if rows:
            ids = [row["id"] for row in rows]
            refs = conn.execute(
                f"SELECT experience_id,operation_id,step FROM experience_observations "
                f"WHERE experience_id IN ({','.join('?' for _ in ids)}) ORDER BY operation_id,step", ids)
            by_id: dict[str, list[dict]] = {item: [] for item in ids}
            for ref in refs:
                by_id[ref["experience_id"]].append({"operation_id": ref["operation_id"], "step": ref["step"]})
            for row in rows:
                row["evidence"] = by_id[row["id"]]
        has_more = remaining > len(rows)
        next_cursor = None
        if has_more:
            last = rows[-1]
            next_cursor = base64.urlsafe_b64encode(json.dumps(
                {**binding, "after": [last["created_at"], last["id"]]}, sort_keys=True).encode()).decode()
        return {**binding, "items": rows, "total": total,
                "remaining": remaining - len(rows), "has_more": has_more,
                "next_cursor": next_cursor}

    def _require_limit(self, limit: int, maximum: int = 1000) -> None:
        if type(limit) is not int or not 1 <= limit <= maximum:
            raise StoreError(f"limit must be between 1 and {maximum}")

    def _experience_page(self, conn, meta: dict, kinds: tuple[str, ...], *, limit: int, cursor: str | None) -> dict:
        binding = self._binding(meta, "experiences")
        after = self._cursor_after(binding, cursor)
        placeholders = ",".join("?" for _ in kinds)
        total = conn.execute(f"SELECT count(*) FROM experiences WHERE kind IN ({placeholders})", kinds).fetchone()[0]
        remaining = conn.execute(f"SELECT count(*) FROM experiences WHERE kind IN ({placeholders}) AND id>?",
                                 (*kinds, after)).fetchone()[0]
        rows = [dict(row) for row in conn.execute(
            f"SELECT * FROM experiences WHERE kind IN ({placeholders}) AND id>? ORDER BY id LIMIT ?",
            (*kinds, after, limit))]
        return self._slice(conn, binding, total=total, remaining=remaining, rows=rows, limit=limit)

    def context(self, *, limit: int = 20) -> dict:
        """Snapshot-consistent context: actions, open failures, primitives and counts.

        Answers known facts on one read snapshot; never writes, scores ROI or
        manufactures actions from stored experience.
        """
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            actions = self._page_conn(conn, meta, "actions", limit=limit)
            failures = self._experience_page(conn, meta, ("negative",), limit=limit, cursor=None)
            primitives = self._experience_page(conn, meta, ("primitive", "hypothesis"), limit=limit, cursor=None)
            counts = {name: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                      for name, t in self._PAGE_TABLES.items()}
            return {"target": self.target, "store_id": meta["store_id"], "revision": meta["revision"],
                    "counts": counts, "actions": actions, "failures": failures, "primitives": primitives}

    def candidates(self, *, limit: int = 50, cursor: str | None = None) -> dict:
        """Findings as claims plus their current technical/delivery posture; no ranking."""
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            page = self._page_conn(conn, meta, "findings", limit=limit, cursor=cursor)
            for row in page["items"]:
                assessment = conn.execute("SELECT id, verdict FROM assessments WHERE finding_id=? "
                                          "ORDER BY revision DESC LIMIT 1", (row["id"],)).fetchone()
                row["assessment"] = dict(assessment) if assessment else None
            return page

    def finding_page(self, *, limit: int = 50, cursor: str | None = None) -> dict:
        """Return full finding projections from one revision-bound read snapshot."""
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            page = self._page_conn(conn, meta, "findings", limit=limit, cursor=cursor)
            self._finding_projections(conn, page["items"])
            return page

    def _finding_states(self, conn, rows: list[dict]) -> None:
        """Recorded posture only; report existence is not current delivery authority."""
        if not rows:
            return
        by_id = {row["id"]: row for row in rows}
        placeholders = ",".join("?" for _ in by_id)
        for row in rows:
            row.update(assessment=None, report_recorded=False)
        for item in conn.execute(f"""SELECT a.* FROM assessments a
                WHERE a.finding_id IN ({placeholders}) AND a.revision=(
                    SELECT max(x.revision) FROM assessments x WHERE x.finding_id=a.finding_id)""", list(by_id)):
            by_id[item["finding_id"]]["assessment"] = dict(item)
        for item in conn.execute(f"""SELECT f.id, EXISTS(
                SELECT 1 FROM reports r WHERE r.finding_id=f.id) AS recorded
                FROM findings f WHERE f.id IN ({placeholders})""", list(by_id)):
            by_id[item["id"]]["report_recorded"] = bool(item["recorded"])

    def finding_state_page(self, *, limit: int = 50, cursor: str | None = None) -> dict:
        """Page claims and latest recorded posture without expanding evidence history.

        Use finding()/finding_page() or current truth for integrity and delivery
        decisions. These facts neither verify evidence nor authorize delivery.
        """
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            page = self._page_conn(conn, meta, "findings", limit=limit, cursor=cursor)
            self._finding_states(conn, page["items"])
            return page

    def finding_summary(self, *, limit: int = 5) -> dict:
        """Exact posture counts, a bounded preview and stable follow-ups on one snapshot."""
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            counts = dict(conn.execute("""WITH posture AS (
                SELECT f.id, COALESCE(a.verdict, '') AS verdict,
                    EXISTS(SELECT 1 FROM reports r WHERE r.finding_id=f.id) AS reported
                FROM findings f LEFT JOIN assessments a ON a.finding_id=f.id
                    AND a.revision=(SELECT max(x.revision) FROM assessments x WHERE x.finding_id=f.id)
                ) SELECT count(*) AS total,
                    count(CASE WHEN verdict='confirmed' THEN 1 END) AS confirmed,
                    count(CASE WHEN verdict NOT IN ('confirmed','refuted') THEN 1 END) AS pending_validation,
                    count(CASE WHEN verdict='confirmed' AND NOT reported THEN 1 END) AS validated_pending_report,
                    count(CASE WHEN reported THEN 1 END) AS reported,
                    min(CASE WHEN verdict NOT IN ('confirmed','refuted') THEN id END) AS next_validation,
                    min(CASE WHEN verdict='confirmed' AND NOT reported THEN id END) AS next_report
                FROM posture""").fetchone())
            page = self._page_conn(conn, meta, "findings", limit=limit)
            rows = {row["id"]: row for row in page["items"]}
            next_ids = {key: counts.pop(key) for key in ("next_validation", "next_report")}
            for finding_id in next_ids.values():
                if finding_id and finding_id not in rows:
                    rows[finding_id] = dict(conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())
            self._finding_states(conn, list(rows.values()))
            return {**page, "counts": counts,
                    **{key: rows.get(finding_id) for key, finding_id in next_ids.items()}}

    def _finding_projections(self, conn, rows: list[dict]) -> None:
        """Batch one page's relations; acquire each supporting operation once per read."""
        if not rows:
            return
        by_id = {row["id"]: row for row in rows}
        ids = list(by_id)
        placeholders = ",".join("?" for _ in ids)
        for row in rows:
            row.update(assessment=None, deliveries=[], reports=[], evidence=[])
        assessments = {}
        manifests = {}
        for item in conn.execute(f"""SELECT a.* FROM assessments a
                WHERE a.finding_id IN ({placeholders}) AND a.revision=(
                    SELECT max(x.revision) FROM assessments x WHERE x.finding_id=a.finding_id)""", ids):
            assessment = dict(item)
            by_id[item["finding_id"]]["assessment"] = assessment
            assessments[item["id"]] = True
            manifests[item["id"]] = []
        for item in conn.execute(f"""SELECT d.* FROM delivery_decisions d
                WHERE d.finding_id IN ({placeholders}) AND d.revision=(
                    SELECT max(x.revision) FROM delivery_decisions x
                    WHERE x.finding_id=d.finding_id AND x.destination=d.destination)
                ORDER BY d.destination""", ids):
            by_id[item["finding_id"]]["deliveries"].append(dict(item))
        for item in conn.execute(f"""SELECT finding_id,operation_id,step FROM finding_observations
                WHERE finding_id IN ({placeholders}) ORDER BY operation_id,step""", ids):
            by_id[item["finding_id"]]["evidence"].append(
                {"operation_id": item["operation_id"], "step": item["step"]})
        for item in conn.execute(f"""SELECT r.*, a.ref AS artifact_ref,
                a.sha256 AS artifact_sha256, a.size AS artifact_size
                FROM reports r JOIN artifacts a ON a.id=r.artifact_id
                WHERE r.finding_id IN ({placeholders}) ORDER BY r.generated_at""", ids):
            by_id[item["finding_id"]]["reports"].append(dict(item))
        if assessments:
            operation_integrity = {}
            assessment_ids = list(assessments)
            for ref in conn.execute(f"""SELECT ao.assessment_id,ao.operation_id,ao.step,
                    b.kind,a.id AS artifact_id,a.ref,a.sha256
                    FROM assessment_observations ao
                    JOIN observation_artifacts b ON b.operation_id=ao.operation_id AND b.step=ao.step
                    JOIN artifacts a ON a.id=b.artifact_id
                    WHERE ao.assessment_id IN ({','.join('?' for _ in assessment_ids)})
                    ORDER BY ao.operation_id,ao.step,b.kind""", assessment_ids):
                item = dict(ref)
                assessment_id = item.pop("assessment_id")
                item["event_id"] = f"{item['operation_id']}:{item['step']}"
                manifests[assessment_id].append(item)
            for ref in conn.execute(f"""SELECT DISTINCT assessment_id,operation_id
                    FROM assessment_observations
                    WHERE assessment_id IN ({','.join('?' for _ in assessment_ids)})
                    ORDER BY operation_id""", assessment_ids):
                operation_id = ref["operation_id"]
                if operation_id not in operation_integrity:
                    try:
                        self._verify_operation(conn, operation_id)
                    except (OSError, ValueError, StoreError):
                        operation_integrity[operation_id] = False
                    else:
                        operation_integrity[operation_id] = True
                assessments[ref["assessment_id"]] &= operation_integrity[operation_id]
        for row in rows:
            assessment = row["assessment"]
            valid = bool(assessment and assessments[assessment["id"]])
            for delivery in row["deliveries"]:
                delivery["stale"] = not valid or delivery["assessment_id"] != assessment["id"]
            self._report_rows(conn, row["reports"], assessment, row["deliveries"], assessment_valid=valid)
            # Read projections only: destination policy and damaged bytes never
            # rewrite the immutable technical assessment.
            row["technical_conclusion"] = dict(assessment) if assessment else None
            row["evidence_integrity"] = {
                "status": ("valid" if valid else "invalid") if assessment else "unassessed",
                "assessment_id": assessment["id"] if assessment else None,
                "references": manifests[assessment["id"]] if assessment else [],
            }
            row["destination_decision"] = [
                {**delivery, "decision": {"eligible": "accept", "ineligible": "reject",
                                         "deferred": "defer"}[delivery["status"]]}
                for delivery in row["deliveries"]
            ]

    def failures(self, *, limit: int = 50, cursor: str | None = None) -> dict:
        """Conditional negative experiences: what was ruled out and under which premise."""
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            return self._experience_page(conn, meta, ("negative",), limit=limit, cursor=cursor)

    def primitives(self, *, limit: int = 50, cursor: str | None = None) -> dict:
        """Stored primitives/hypotheses; queryable even without a continuation hint, never queued."""
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            return self._experience_page(conn, meta, ("primitive", "hypothesis"), limit=limit, cursor=cursor)

    def execution(self, operation_id: str) -> dict:
        """Expand an operation to ordered observations and raw artifact references."""
        operation_id = _identifier(operation_id, "operation_id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
            if not row:
                raise StoreError(f"operation missing: {operation_id}")
            observations = [dict(item) for item in conn.execute(
                "SELECT * FROM observations WHERE operation_id=? ORDER BY step", (operation_id,))]
            for item in observations:
                try:
                    item["detail"] = json.loads(item.pop("detail_json") or "{}")
                except (TypeError, ValueError) as exc:
                    raise StoreError(f"observation detail is unreadable: {operation_id}:{item['step']}") from exc
                item["artifacts"] = [dict(binding) for binding in conn.execute("""SELECT b.kind,a.ref,a.sha256,a.size
                    FROM observation_artifacts b JOIN artifacts a ON a.id=b.artifact_id
                    WHERE b.operation_id=? AND b.step=? ORDER BY b.kind""", (operation_id, item["step"]))]
            attempt = dict(conn.execute("SELECT * FROM attempts WHERE id=?", (row["attempt_id"],)).fetchone())
            return {**dict(row), "attempt": attempt, "observations": observations}

    def closure_records(self, *, limit: int = 20000, verify: bool = False) -> dict:
        """Canonical evidence records for the one shared closure projection.

        Facts only: authored identity status/key/technique, actor/object scope,
        result and artifact refs. ``closure_projection`` validates these claims;
        Store persistence alone grants no closure authority. Records are
        ordered by observation time, then registration revision and step, so
        equal timestamps do not let hash order decide the latest identity.

        A truncated prefix would change what closes, so truncation is reported
        explicitly rather than silently imposed by a small default. verify=True
        acquires current integrity for all referenced operations on this same
        metadata snapshot; damaged rows remain facts and are returned separately.
        """
        self._require_limit(limit, maximum=20000)
        if type(verify) is not bool:
            raise StoreError("verify must be boolean")
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            total = conn.execute("SELECT count(*) FROM observations").fetchone()[0]
            columns = {str(item[1]) for item in conn.execute("PRAGMA table_info(observations)").fetchall()}
            identity_select = (
                "o.identity_status, o.identity_technique, o.identity_v2, "
                if {"identity_status", "identity_technique", "identity_v2"} <= columns
                else "'none' AS identity_status, '' AS identity_technique, '{}' AS identity_v2, "
            )
            rows = conn.execute(f"""SELECT o.operation_id, o.step, o.endpoint, o.method, o.family, o.observed_at,
                    o.description, o.actor, o.object_scope, o.variant, o.error, o.truncated, o.result,
                    o.state_changing, o.redline_checked, o.detail_json,
                    {identity_select}o.identity_dimensions,
                    p.outcome, p.recorded_at, a.action_id,
                    EXISTS(SELECT 1 FROM operations newer WHERE newer.supersedes=p.id) AS superseded,
                    (SELECT art.ref FROM observation_artifacts b JOIN artifacts art ON art.id=b.artifact_id
                     WHERE b.operation_id=o.operation_id AND b.step=o.step ORDER BY b.kind LIMIT 1) AS evidence_ref
                FROM observations o
                JOIN operations p ON p.id=o.operation_id
                JOIN attempts a ON a.id=p.attempt_id
                ORDER BY o.observed_at, p.revision, o.step LIMIT ?""", (limit + 1,)).fetchall()
            truncated = len(rows) > limit
            records = [self._closure_record(row) for row in rows[:limit]]
            by_event = {record["event_id"]: record for record in records}
            for record in records:
                record.update(schema_version=3, target=self.target, evidence_refs=[])
            for binding in conn.execute("""SELECT b.operation_id,b.step,b.kind,a.id,a.ref,a.sha256
                    FROM observation_artifacts b JOIN artifacts a ON a.id=b.artifact_id
                    ORDER BY b.operation_id,b.step,b.kind"""):
                event_id = f"{binding['operation_id']}:{binding['step']}"
                if event_id in by_event:
                    by_event[event_id]["evidence_refs"].append({
                        name: binding[name] for name in ("kind", "id", "ref", "sha256")
                    })
            invalid_operations = []
            if verify and not truncated:
                # Local to this acquisition: a later read must hash the bytes again.
                checked: dict[str, str] = {}
                failures: dict[str, str] = {}
                for row in conn.execute("""SELECT DISTINCT b.operation_id,a.* FROM observation_artifacts b
                        JOIN artifacts a ON a.id=b.artifact_id
                        WHERE NOT EXISTS(SELECT 1 FROM operations newer WHERE newer.supersedes=b.operation_id)
                        ORDER BY b.operation_id,a.id"""):
                    artifact = dict(row)
                    operation_id = artifact.pop("operation_id")
                    if artifact["id"] not in checked:
                        try:
                            self._require_valid_artifact(conn, artifact)
                            checked[artifact["id"]] = ""
                        except (OSError, ValueError, StoreError) as exc:
                            checked[artifact["id"]] = " ".join(str(exc).split())[:240]
                    if checked[artifact["id"]]:
                        failures.setdefault(operation_id, checked[artifact["id"]])
                invalid_operations = [{"operation_id": key, "reason": value}
                                      for key, value in sorted(failures.items())]
            return {**({"invalid_operations": invalid_operations} if verify else {}), "target": self.target, "store_id": meta["store_id"], "revision": meta["revision"],
                    "records": records, "total": total, "truncated": truncated, "returned": len(records)}

    @staticmethod
    def _closure_record(row) -> dict:
        endpoint = canonical_endpoint_identity(row["endpoint"])
        try:
            dimensions = json.loads(row["identity_dimensions"] or "{}")
        except ValueError:
            dimensions = {}
        try:
            identity_v2 = json.loads(row["identity_v2"] or "{}")
        except ValueError:
            identity_v2 = {}
        return {
            "event_id": f"{row['operation_id']}:{row['step']}",
            "superseded": bool(row["superseded"]),
            "evidence_role": json.loads(row["detail_json"] or "{}").get("evidence_role", "unknown"),
            "raw_endpoint": row["endpoint"],
            "endpoint": endpoint,
            "method": row["method"],
            "vuln_class": row["family"],
            "result": row["result"],
            "ts": row["observed_at"],
            "recorded_at": row["recorded_at"],
            "description": row["description"],
            "actor": row["actor"],
            "object_scope": row["object_scope"],
            "variant": row["variant"],
            "error": row["error"],
            "truncated": bool(row["truncated"]),
            "state_changing": None if row["state_changing"] is None else bool(row["state_changing"]),
            "redline_checked": bool(row["redline_checked"]),
            "outcome": row["outcome"],
            "action_id": row["action_id"] or "",
            "evidence_ref": row["evidence_ref"] or "",
            "identity_status": row["identity_status"] or "none",
            "identity_technique": row["identity_technique"] or "",
            "identity_v2": identity_v2 if isinstance(identity_v2, dict) else {},
            "identity_dimensions": dimensions if isinstance(dimensions, dict) else {},
        }

    def experience(self, experience_id: str) -> dict:
        """Expand conditional experience; references remain facts, never queued work."""
        experience_id = _identifier(experience_id, "experience_id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM experiences WHERE id=?", (experience_id,)).fetchone()
            if not row:
                raise StoreError(f"experience missing: {experience_id}")
            refs = [dict(item) for item in conn.execute("""SELECT operation_id,step FROM experience_observations
                WHERE experience_id=? ORDER BY operation_id,step""", (experience_id,))]
            context = conn.execute("SELECT * FROM experience_case_context WHERE experience_id=?", (experience_id,)).fetchone()
            case = dict(context) if context else None
            if case:
                case["actors"] = [item[0] for item in conn.execute(
                    "SELECT actor_id FROM experience_case_actors WHERE experience_id=? ORDER BY actor_id", (experience_id,))]
                case["object_ref"] = next((item[0] for item in conn.execute(
                    "SELECT object_ref FROM experience_case_objects WHERE experience_id=?", (experience_id,))), "")
                try:
                    case["metadata"] = json.loads(case.pop("metadata_json"))
                except (TypeError, ValueError):
                    case["metadata"] = {}
            return {**dict(row), "evidence": refs, "case": case}

    def action(self, action_id: str) -> dict:
        """Expand a work subject and its recorded completion proof on one snapshot."""
        action_id = _identifier(action_id, "action_id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if not row:
                raise StoreError(f"action missing: {action_id}")
            result = dict(row)
            try:
                result["metadata"] = json.loads(result.pop("metadata_json") or "{}")
            except (TypeError, ValueError) as exc:
                raise StoreError("stored action metadata is corrupt") from exc
            if not isinstance(result["metadata"], dict):
                raise StoreError("stored action metadata is not an object")
            result["subject_artifact"] = None
            if row["subject_artifact_id"]:
                result["subject_artifact"] = dict(conn.execute("SELECT * FROM artifacts WHERE id=?",
                                                               (row["subject_artifact_id"],)).fetchone())
            completion = conn.execute("SELECT * FROM action_completions WHERE action_id=?", (action_id,)).fetchone()
            result["completion"] = dict(completion) if completion else None
            if completion and completion["artifact_id"]:
                result["completion"]["artifact"] = dict(conn.execute("SELECT * FROM artifacts WHERE id=?",
                                                                      (completion["artifact_id"],)).fetchone())
            result["revision"] = conn.execute("SELECT revision FROM store").fetchone()[0]
            return result

    def finding(self, finding_id: str) -> dict:
        """Compose technical truth and destination decisions without conflating them."""
        finding_id = _identifier(finding_id, "finding_id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not row:
                raise FindingNotFoundError(f"finding missing: {finding_id}")
            result = dict(row)
            self._finding_projections(conn, [result])
            assessment_value = result["assessment"]
            if assessment_value:
                assessment_value["evidence"] = [dict(item) for item in conn.execute(
                    "SELECT operation_id,step FROM assessment_observations WHERE assessment_id=? ORDER BY operation_id,step",
                    (assessment_value["id"],),
                )]
            return {**result,
                    "delivery_events": self._delivery_event_rows(conn, finding_id, result["reports"]),
                    "revision": conn.execute("SELECT revision FROM store").fetchone()[0]}

    def backup(self, destination: str | Path) -> Path:
        """Use SQLite's snapshot API; copying just the main WAL database is unsafe."""
        path = Path(destination)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with self._connection() as source:
                target = sqlite3.connect(path)
                try:
                    source.backup(target)
                finally:
                    target.close()
        except BaseException as exc:
            path.unlink(missing_ok=True)
            if isinstance(exc, sqlite3.DatabaseError):
                raise StoreError(f"target store backup failed at {path}: {exc}") from exc
            raise
        return path

    def upgrade_memory_schema(self, backup_path: str | Path) -> dict:
        """Retain the explicit v8-to-v9 entry point for existing callers."""
        return self._upgrade_schema(backup_path, 9)

    def upgrade_schema(self, backup_path: str | Path) -> dict:
        """Upgrade supported primary schemas after verifying an isolated backup."""
        return self._upgrade_schema(backup_path, SCHEMA_VERSION)

    def _upgrade_schema(self, backup_path: str | Path, version: int) -> dict:
        backup_path = Path(backup_path)
        if not backup_path.is_absolute() or backup_path.resolve().is_relative_to(self.path.parent):
            raise StoreError("Store schema backup must be an absolute path outside target state")
        if not backup_path.parent.is_dir() or stat.S_IMODE(backup_path.parent.stat().st_mode) & 0o077:
            raise StoreError("Store schema backup directory must exist and be private")
        with target_switch_lock(self.root, self.target, exclusive=True):
            with self._connection() as conn:
                before = dict(conn.execute("SELECT * FROM store WHERE singleton=1").fetchone())
            if before["backend"] != "primary":
                raise StoreError("Store schema upgrade requires an active primary Store")
            if before["schema_version"] >= version:
                return {"status": "already_current", "target": self.target,
                        "store_id": before["store_id"], "revision": before["revision"], "backup": None}
            if before["schema_version"] not in {8, 9, 10}:
                raise StoreError("Store schema upgrade requires schema v8, v9 or v10")

            backup = self.backup(backup_path)
            try:
                with sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True) as copy:
                    copy.row_factory = sqlite3.Row
                    saved = dict(copy.execute("SELECT * FROM store WHERE singleton=1").fetchone())
                    if any(saved[key] != before[key] for key in ("target", "store_id", "backend", "revision", "schema_version")):
                        raise StoreError("Store schema backup identity or revision changed")
                    if (copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
                            or copy.execute("PRAGMA foreign_key_check").fetchone()):
                        raise StoreError("Store schema backup failed integrity checks")
            except sqlite3.DatabaseError as exc:
                raise StoreError(f"Store schema backup is unreadable: {backup}: {exc}") from exc

            with self._connection(write=True, lock=False, foreign_keys=False) as conn:
                current = conn.execute("SELECT store_id,revision,schema_version FROM store WHERE singleton=1").fetchone()
                if (current["store_id"], current["revision"], current["schema_version"]) != (
                        before["store_id"], before["revision"], before["schema_version"]):
                    raise ConflictError("Store changed after Store schema backup; retry with a new backup path")
                if before["schema_version"] < 9:
                    conn.execute("""CREATE TABLE experiences_next (
                        id TEXT PRIMARY KEY NOT NULL,
                        kind TEXT NOT NULL CHECK (kind IN ('primitive','negative','hypothesis','handoff','note')),
                        statement TEXT NOT NULL,
                        conditions TEXT NOT NULL,
                        reopen_when TEXT NOT NULL,
                        next_intent TEXT NOT NULL,
                        action_id TEXT REFERENCES actions(id),
                        finding_id TEXT REFERENCES findings(id),
                        recorded_by TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )""")
                    conn.execute("INSERT INTO experiences_next SELECT * FROM experiences")
                    conn.execute("DROP TABLE experiences")
                    conn.execute("ALTER TABLE experiences_next RENAME TO experiences")
                    conn.execute("CREATE INDEX experiences_kind_id ON experiences(kind, id)")
                    conn.execute("ALTER TABLE store ADD COLUMN active_goal TEXT NOT NULL DEFAULT ''")
                if before["schema_version"] < 10 and version >= 10:
                    # executescript would commit the open transaction before running DDL.
                    for statement in _COVERAGE_REVIEW_SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                if before["schema_version"] < 11 and version >= 11:
                    conn.execute("ALTER TABLE observations ADD COLUMN identity_status TEXT NOT NULL DEFAULT 'none' CHECK (identity_status IN ('complete','none','incomplete','conflict'))")
                    conn.execute("ALTER TABLE observations ADD COLUMN identity_technique TEXT NOT NULL DEFAULT '' CHECK (length(identity_technique) <= 256)")
                    conn.execute("ALTER TABLE observations ADD COLUMN identity_v2 TEXT NOT NULL DEFAULT '{}' CHECK (length(identity_v2) <= 8192)")
                revision = before["revision"] + 1
                conn.execute("UPDATE store SET schema_version=?,revision=? WHERE singleton=1",
                             (version, revision))
                if conn.execute("PRAGMA foreign_key_check").fetchone():
                    raise StoreError("Store schema upgrade broke a Store reference")
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise StoreError("Store schema upgrade failed integrity check")
                conn.execute("INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (revision, f"schema-upgrade:v{version}:{before['store_id']}",
                              "upgrade_schema", self.target, "schema-upgrade",
                              _digest((before["store_id"], before["schema_version"], version, before["revision"])), _now()))
                conn.commit()
            return {"status": "upgraded", "target": self.target, "store_id": before["store_id"],
                    "revision": revision, "backup": str(backup)}


def target_backend(repo_root: str | Path, target: str) -> str:
    """Read the one backend claim; a missing fenced store is never legacy."""
    store = TargetStore(repo_root, target)
    if store.path.exists() or store.path.is_symlink():
        return store.backend()
    if store._read_fence() is not None:
        raise StoreError(f"fenced target store missing: {store.path}; restore the current store, not legacy state")
    receipt = store.path.parent / "migration-receipt.json"
    if receipt.exists() or receipt.is_symlink():
        raise StoreError(f"published preview store missing: {store.path}; rebuild or restore the migration artifact")
    return "legacy"


def initialize_target_store(repo_root: str | Path, target: str) -> str:
    """Explicitly claim a fresh target for the primary runtime Store.

    This is an operator/orchestrator boundary, never a domain write fallback.
    Existing legacy data is rejected so callers must use the migration path;
    low-level APIs remain legacy-compatible until this function has run.
    """
    store = TargetStore(repo_root, target)
    store._prepare_store_directory()
    with target_switch_lock(repo_root, target, exclusive=True):
        backend = target_backend(repo_root, target)
        if backend == "primary":
            read_scope_source(repo_root, target)
            return backend
        if backend != "legacy":
            raise StoreError(f"cannot initialize a {backend} target as primary")
        store._initialize_locked()
        return "primary"


def runtime_store(repo_root: str | Path, target: str) -> TargetStore:
    """Require the active Store; initialization and legacy import are explicit."""
    store = TargetStore(repo_root, target)
    backend = target_backend(repo_root, target)
    if backend == "legacy":
        raise StoreError("target is not initialized; use explicit init or legacy import first")
    if backend != "primary":
        raise StoreError(f"runtime store is not active: {store.path}")
    return store


def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Initialize, upgrade or query a target Store explicitly.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init", help="claim a fresh target for the primary Store")
    init.add_argument("--store", action="store_true", required=True, help="required explicit Store intent")
    init.add_argument("--target", required=True)
    init.add_argument("--repo-root", default="", help="repository root (defaults to this checkout)")
    upgrade = subparsers.add_parser("upgrade-memory", help="explicit v8-to-v9 memory schema upgrade")
    upgrade.add_argument("--target", required=True)
    upgrade.add_argument("--backup", required=True, help="new absolute backup path outside target state")
    upgrade.add_argument("--repo-root", default="", help="repository root (defaults to this checkout)")
    upgrade_all = subparsers.add_parser("upgrade-schema", help="explicit v8/v9/v10-to-v11 Store schema upgrade")
    upgrade_all.add_argument("--target", required=True)
    upgrade_all.add_argument("--backup", required=True, help="new absolute backup path outside target state")
    upgrade_all.add_argument("--repo-root", default="", help="repository root (defaults to this checkout)")
    findings = subparsers.add_parser("findings", help="read a Finding page or expand one ID")
    selection = findings.add_mutually_exclusive_group()
    selection.add_argument("--id", default=None)
    selection.add_argument("--cursor", default=None)
    findings.add_argument("--limit", type=int, default=10)
    case = subparsers.add_parser("case", help="read full Case context without raw private material")
    for query in (findings, case):
        query.add_argument("--target", required=True)
        query.add_argument("--repo-root", default="", help="repository data root")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve() if args.repo_root else Path(__file__).resolve().parents[1]
    try:
        if args.command == "init":
            result = {"target": TargetStore(repo_root, args.target).target,
                      "backend": initialize_target_store(repo_root, args.target)}
        elif args.command == "upgrade-memory":
            result = TargetStore(repo_root, args.target).upgrade_memory_schema(args.backup)
        elif args.command == "upgrade-schema":
            result = TargetStore(repo_root, args.target).upgrade_schema(args.backup)
        else:
            store = runtime_store(repo_root, args.target)
            if args.command == "case":
                result = store.case_state()
            else:
                result = (store.finding(args.id) if args.id is not None else
                          store.finding_page(limit=args.limit, cursor=args.cursor))
    except (OSError, StoreError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the CLI
    raise SystemExit(_main())
