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
from tempfile import TemporaryDirectory
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from tools import experience_knowledge, experience_history
    from tools.migration_receipts import directory_handle
    from tools.coverage_authoring import coverage_review_drafts
    from tools.experience_contract import ENTITY_FIELDS, CLAIM_PREDICATES, entity_binding, condition_bindings, validity_window, normalize_experience_text
    from tools.evidence_identity import (
        CANONICAL_VULN_CLASSES, LEDGER_RESULTS, canonical_endpoint_identity, coverage_family, extract_endpoint_path, normalize_family,
    )
    from tools.target_paths import classify_target, open_target_lock_file, target_storage_key
    from tools.scope_context import url_belongs_to_target
    from tools.target_paths import legacy_target_profile_path, target_raw_artifact_path
    from tools.scope_context import SCHEMA_VERSION as SCOPE_SCHEMA_VERSION, read_scope_source, write_scope_source_locked
except ImportError:  # pragma: no cover - direct tools/ execution
    import experience_knowledge
    import experience_history
    from migration_receipts import directory_handle
    from coverage_authoring import coverage_review_drafts
    from experience_contract import ENTITY_FIELDS, CLAIM_PREDICATES, entity_binding, condition_bindings, validity_window, normalize_experience_text
    from evidence_identity import (  # type: ignore
        CANONICAL_VULN_CLASSES, LEDGER_RESULTS, canonical_endpoint_identity, coverage_family, extract_endpoint_path, normalize_family,
    )
    from target_paths import classify_target, open_target_lock_file, target_storage_key  # type: ignore
    from scope_context import url_belongs_to_target  # type: ignore
    from target_paths import legacy_target_profile_path, target_raw_artifact_path  # type: ignore
    from scope_context import SCHEMA_VERSION as SCOPE_SCHEMA_VERSION, read_scope_source, write_scope_source_locked


SCHEMA_VERSION = 18
COMPATIBLE_SCHEMA_VERSIONS = {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, SCHEMA_VERSION}
FINDING_DISPOSITIONS = ("active", "withdrawn")
_FINDING_DISPOSITION_SCHEMA = """
CREATE TABLE finding_dispositions (
    id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    status TEXT NOT NULL CHECK (status IN ('active','withdrawn')),
    replacement_id TEXT REFERENCES findings(id),
    previous_id TEXT UNIQUE REFERENCES finding_dispositions(id),
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    revision INTEGER NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL,
    CHECK (replacement_id IS NULL OR (status='withdrawn' AND replacement_id!=finding_id))
);
CREATE INDEX finding_dispositions_latest ON finding_dispositions(finding_id, revision DESC);
"""
COVERAGE_REVIEW_STATUSES = ("tested_clean", "tested_finding", "untested", "n_a")
ENDPOINT_KIND_VALUES = (
    "untriaged", "api_endpoint", "page_route", "static_asset", "public_metadata",
    "route_prefix", "realtime_endpoint", "external_chain_context", "unknown",
)
FINAL_ENDPOINT_KIND_SOURCES = frozenset({"ai_triage", "manual", "operator"})
_EXPERIENCE_PROVENANCE_SCHEMA = """
CREATE TABLE experience_versions (
    experience_id TEXT NOT NULL REFERENCES experiences(id),
    version INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (experience_id, version)
);
CREATE TABLE experience_sources (
    experience_id TEXT NOT NULL REFERENCES experiences(id),
    experience_version INTEGER NOT NULL,
    source_experience_id TEXT NOT NULL,
    source_version INTEGER NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('origin','basis')),
    content_sha256 TEXT NOT NULL,
    PRIMARY KEY (experience_id, experience_version, source_experience_id, source_version, purpose),
    FOREIGN KEY (experience_id, experience_version) REFERENCES experience_versions(experience_id, version),
    FOREIGN KEY (source_experience_id, source_version)
        REFERENCES experience_versions(experience_id, version)
);
CREATE TABLE experience_links (
    id TEXT PRIMARY KEY NOT NULL,
    experience_id TEXT NOT NULL REFERENCES experiences(id),
    target_id TEXT NOT NULL REFERENCES experiences(id),
    experience_version INTEGER NOT NULL,
    target_version INTEGER NOT NULL,
    relation TEXT NOT NULL CHECK (relation IN ('supersedes','refutes','depends_on')),
    conditions TEXT NOT NULL,
    rationale TEXT NOT NULL,
    revision INTEGER NOT NULL,
    CHECK (experience_id != target_id),
    FOREIGN KEY (experience_id, experience_version) REFERENCES experience_versions(experience_id, version),
    FOREIGN KEY (target_id, target_version) REFERENCES experience_versions(experience_id, version)
);
CREATE INDEX experience_links_target ON experience_links(target_id, relation);
CREATE TABLE experience_link_events (
    id TEXT PRIMARY KEY NOT NULL,
    link_id TEXT NOT NULL UNIQUE REFERENCES experience_links(id),
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    revision INTEGER NOT NULL,
    recorded_at TEXT NOT NULL
);
"""
_EXPERIENCE_MATERIAL_SCHEMA = """
CREATE TABLE experience_material_sources (
    experience_id TEXT NOT NULL,
    experience_version INTEGER NOT NULL,
    owner TEXT NOT NULL CHECK(owner IN ('artifact','assessment')),
    record_id TEXT NOT NULL,
    source_version INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK(purpose IN ('origin','basis')),
    artifact_id TEXT REFERENCES artifacts(id),
    assessment_id TEXT REFERENCES assessments(id),
    PRIMARY KEY(experience_id,experience_version,owner,record_id,purpose),
    FOREIGN KEY(experience_id,experience_version) REFERENCES experience_versions(experience_id,version),
    CHECK((owner='artifact' AND artifact_id IS NOT NULL AND artifact_id=record_id AND assessment_id IS NULL)
       OR (owner='assessment' AND assessment_id IS NOT NULL AND assessment_id=record_id AND artifact_id IS NULL))
);
CREATE TABLE experience_claims (
    id TEXT PRIMARY KEY NOT NULL,
    experience_id TEXT NOT NULL,
    experience_version INTEGER NOT NULL,
    predicate TEXT NOT NULL CHECK(predicate IN ('observed_access','uses','produces','requires','enables')),
    conditions TEXT NOT NULL,
    timing TEXT NOT NULL,
    FOREIGN KEY(experience_id,experience_version) REFERENCES experience_versions(experience_id,version)
);
CREATE TABLE experience_claim_endpoints (
    claim_id TEXT NOT NULL REFERENCES experience_claims(id),
    side TEXT NOT NULL CHECK(side IN ('subject','object')),
    owner TEXT NOT NULL CHECK(owner IN ('actor','object','session','action','operation','artifact','experience','assessment')),
    record_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    PRIMARY KEY(claim_id,side)
);
CREATE TABLE experience_claim_sources (
    claim_id TEXT NOT NULL REFERENCES experience_claims(id),
    source_owner TEXT CHECK(source_owner IN ('experience','artifact','assessment')),
    source_record_id TEXT,
    source_version INTEGER,
    source_purpose TEXT CHECK(source_purpose IN ('origin','basis')),
    operation_id TEXT,
    step INTEGER,
    CHECK((source_owner IS NOT NULL AND source_record_id IS NOT NULL AND source_version IS NOT NULL AND source_purpose IS NOT NULL AND operation_id IS NULL AND step IS NULL)
       OR (source_owner IS NULL AND source_record_id IS NULL AND source_version IS NULL AND source_purpose IS NULL AND operation_id IS NOT NULL AND step IS NOT NULL)),
    FOREIGN KEY(operation_id,step) REFERENCES observations(operation_id,step)
);
"""
_EXPERIENCE_CONDITION_SCHEMA = """
CREATE TABLE experience_claim_conditions (
    claim_id TEXT NOT NULL REFERENCES experience_claims(id),
    role TEXT NOT NULL,
    owner TEXT NOT NULL CHECK(owner IN ('actor','object','session','action','operation','artifact','experience','assessment')),
    record_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 0),
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
    PRIMARY KEY(claim_id,role)
);
CREATE TABLE experience_claim_validity (
    claim_id TEXT PRIMARY KEY NOT NULL REFERENCES experience_claims(id),
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL
);
"""
_EXPERIENCE_EXTERNAL_SCHEMA = """
CREATE TABLE experience_external_sources (
    experience_id TEXT NOT NULL,
    experience_version INTEGER NOT NULL,
    owner TEXT NOT NULL CHECK(owner IN ('knowledge','history')),
    record_id TEXT NOT NULL,
    source_version TEXT NOT NULL CHECK(length(source_version)=64),
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
    purpose TEXT NOT NULL CHECK(purpose IN ('origin','basis')) CHECK(owner!='history' OR purpose='origin'),
    PRIMARY KEY(experience_id,experience_version,owner,record_id,source_version,purpose),
    FOREIGN KEY(experience_id,experience_version) REFERENCES experience_versions(experience_id,version)
);
CREATE TABLE experience_claim_external_sources (
    claim_id TEXT NOT NULL REFERENCES experience_claims(id),
    experience_id TEXT NOT NULL,
    experience_version INTEGER NOT NULL,
    source_owner TEXT NOT NULL CHECK(source_owner='knowledge'),
    source_record_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    source_purpose TEXT NOT NULL CHECK(source_purpose='basis'),
    FOREIGN KEY(experience_id,experience_version,source_owner,source_record_id,source_version,source_purpose)
        REFERENCES experience_external_sources(experience_id,experience_version,owner,record_id,source_version,purpose)
);
"""
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
""" + _COVERAGE_REVIEW_SCHEMA + _EXPERIENCE_PROVENANCE_SCHEMA + _EXPERIENCE_MATERIAL_SCHEMA + _EXPERIENCE_CONDITION_SCHEMA + _EXPERIENCE_EXTERNAL_SCHEMA + _FINDING_DISPOSITION_SCHEMA


class StoreError(ValueError):
    """Invalid, missing or unreadable canonical state; never an empty result."""


class ConflictError(StoreError):
    """Stale revision, conflicting identity or reuse of an idempotency key."""


class FindingNotFoundError(StoreError):
    """An admitted Store has no finding with the requested ID."""


def report_attachment_refs(content: bytes) -> tuple[str, ...]:
    """Read the standalone, content-addressed image links emitted by the report tool."""
    refs = {}
    fence = b""
    for line in content.splitlines():
        marker = re.match(rb" {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence:
            if (marker and marker[1][:1] == fence[:1] and len(marker[1]) >= len(fence)
                    and not marker[2].strip()):
                fence = b""
            continue
        if marker and not (marker[1].startswith(b"`") and b"`" in marker[2]):
            fence = marker[1]
            continue
        image = re.fullmatch(rb" {0,3}!\[[^\]\r\n]*\]\((.*)", line)
        if not image:
            continue
        tail = image[1].rstrip()
        target = tail[:-1] if tail.endswith(b")") else tail
        if (target.startswith(b"//") or (re.match(rb"[A-Za-z][A-Za-z0-9+.-]*:", target)
                and not re.match(rb"[A-Za-z]:[/\\]", target))):
            continue
        if not re.search(rb"(?:^|[/\\<])poc_screenshots(?:[/\\>]|$)", target):
            continue
        if not tail.endswith(b")") or not re.fullmatch(
            rb"poc_screenshots/[0-9a-f]{64}(?:\.[^/\\\s().?#%<>:\x00]+)?", target,
        ):
            raise StoreError("invalid managed report attachment; use a content-addressed screenshot link")
        try:
            ref = target.decode("utf-8")
        except UnicodeError as exc:
            raise StoreError("managed report attachment path must be UTF-8") from exc
        if any(char.isspace() for char in ref):
            raise StoreError("managed report attachment path must not contain whitespace")
        refs[ref] = None
    return tuple(refs)


def _report_file_version(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def read_report_asset(path: Path, sha256: str) -> tuple[bytes, tuple[int, ...]]:
    """Capture a nonempty regular report file without following any symlink component."""
    path = Path(os.path.abspath(path))
    try:
        if path != path.resolve():
            raise StoreError(f"report asset path must not contain symlinks: {path}")
        parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = child_fd
            fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or not before.st_size:
                raise StoreError(f"report asset must be a non-empty regular file: {path}")
            # ponytail: one asset in memory; stream if reports gain large binary attachments.
            data = handle.read()
            after = os.fstat(handle.fileno())
        version = _report_file_version(after)
        if (path != path.resolve() or _report_file_version(before) != version
                or _report_file_version(path.stat(follow_symlinks=False)) != version):
            raise ConflictError(f"report asset changed while reading: {path}; retry with stable files")
        if hashlib.sha256(data).hexdigest() != sha256:
            raise StoreError(f"report asset digest mismatch: {path}")
        return data, version
    except (OSError, RuntimeError) as exc:
        raise StoreError(f"report asset unavailable: {path}: {exc}") from exc


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


def validate_cleanup_confirmation(value: Any) -> dict:
    """Validate an authored restoration claim; Store owns its evidence bindings."""
    fields = {"status", "mutation_refs", "restored_state", "verification_basis"}
    if not isinstance(value, dict) or set(value) != fields or value["status"] != "verified":
        raise StoreError("cleanup_confirmation requires status=verified, mutation_refs, restored_state and verification_basis")
    refs = _references(value["mutation_refs"])
    return {
        "status": "verified",
        "mutation_refs": [{"operation_id": operation, "step": step} for operation, step in refs],
        "restored_state": _text(value["restored_state"], "cleanup restored_state"),
        "verification_basis": _text(value["verification_basis"], "cleanup verification_basis"),
    }


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
        coverage_path = self.root / "evidence" / self.key / "coverage_matrix.json"
        if not allow_legacy and (coverage_path.exists() or coverage_path.is_symlink()):
            if coverage_path.resolve() != coverage_path or not coverage_path.is_file():
                raise StoreError(f"coverage source must be a regular non-symlink file: {coverage_path}")
            try:
                coverage = coverage_review_drafts(json.loads(coverage_path.read_bytes()), self.target)
                for endpoint in coverage["endpoints"]:
                    self.coverage_endpoint(endpoint["endpoint"])
                if coverage["quarantined"]:
                    raise ValueError(coverage["quarantined"][0]["reason"])
            except (OSError, ValueError, TypeError) as exc:
                raise StoreError(f"cannot safely classify Coverage source {coverage_path}: {exc}") from exc
            if not coverage["projection"] and any(endpoint["drafts"] for endpoint in coverage["endpoints"]):
                raise StoreError("legacy Coverage author data exists; migrate an isolated copy before cutover")
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

    @staticmethod
    def _recall_binding(conn, expected=None):
        row = conn.execute("SELECT target,store_id,backend,revision,schema_version FROM store WHERE singleton=1").fetchone()
        binding = dict(row)
        if type(binding["revision"]) is not int or binding["revision"] < 0:
            raise StoreError("corrupt Store revision")
        if expected is not None and (not isinstance(expected, dict) or expected != binding
                or type(expected.get("revision")) is not int or type(expected.get("schema_version")) is not int):
            raise ConflictError("recall Store binding changed; reacquire sources")
        return binding

    def recall_delta(self, since_binding, *, include_owner_relations=False):
        """Compute owner changes and their reverse dependency closure from canonical audit."""
        if type(include_owner_relations) is not bool:
            raise StoreError("include_owner_relations must be boolean")
        with self._connection() as conn:
            self._require_provenance_schema(conn)
            binding = self._recall_binding(conn)
            reason = None
            if since_binding is None:
                reason = "missing_binding"
            elif (not isinstance(since_binding, dict) or set(since_binding) != set(binding)
                  or type(since_binding.get("revision")) is not int or since_binding["revision"] < 0
                  or type(since_binding.get("schema_version")) is not int):
                reason = "incompatible_binding"
            elif any(since_binding[key] != binding[key] for key in ("target", "store_id", "backend")):
                reason = "store_replaced"
            elif since_binding["schema_version"] != binding["schema_version"]:
                reason = "schema_changed"
            elif since_binding["revision"] > binding["revision"]:
                reason = "revision_rollback"
            commands = []
            if reason is None:
                since = since_binding["revision"]
                latest = conn.execute("SELECT revision FROM audit ORDER BY revision DESC LIMIT 1").fetchone()
                if ((latest[0] if latest else 0) != binding["revision"]
                        or since and not conn.execute("SELECT 1 FROM audit WHERE revision=?", (since,)).fetchone()):
                    reason = "audit_gap"
                else:
                    commands = list(conn.execute("SELECT * FROM audit WHERE revision>? ORDER BY revision", (since,)))
                    if (len(commands) != binding["revision"] - since
                            or any(row["revision"] != since + index + 1 for index, row in enumerate(commands))):
                        reason = "audit_gap"
            known = {"remember", "remember_hypothesis", "link_experience", "retract_experience_link",
                     "record_artifact_event", "assess", "create_action", "transition_action", "record_execution",
                     "upsert_case_actor", "upsert_case_session", "upsert_case_object", "upgrade_schema",
                     "create_finding", "dispose_finding", "start_attempt", "decide_delivery", "register_report",
                     "record_delivery_event", "record_coverage_review", "set_active_goal"}
            if any(row["command"] not in known for row in commands):
                reason = "unknown_audit_command"
            if any(row["command"] == "upgrade_schema" for row in commands):
                reason = "schema_upgrade"
            if reason:
                # Full acquisition audits the whole Store. The incremental path
                # consumes only new audit rows, not the already accepted history.
                if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok" or conn.execute("PRAGMA foreign_key_check").fetchone():
                    raise StoreError("canonical Store integrity failure; inspect and recover the Store")
                audit_size, audit_max = conn.execute("SELECT count(*),coalesce(max(revision),0) FROM audit").fetchone()
                if audit_size != binding["revision"] or audit_max != binding["revision"]:
                    reason = "audit_gap"
                ids = [row[0] for row in conn.execute("SELECT id FROM experiences ORDER BY created_at DESC,id DESC")]
                owners = ([{"owner": "case", "record_id": "context"}]
                          + [{"owner": "operation", "record_id": row[0]} for row in conn.execute("SELECT id FROM operations ORDER BY id")]
                          + [{"owner": "experience", "record_id": key} for key in ids]) if include_owner_relations else []
                return {"binding": binding, "experience_ids": ids, "owner_keys": owners, "full_acquisition_reason": reason}
            pending, changed = [], set()
            case_changed = False
            for row in commands:
                command, key = row["command"], row["entity_id"]
                entities = {"remember": ("experiences", "id"), "remember_hypothesis": ("experiences", "id"),
                            "create_action": ("actions", "id"), "transition_action": ("actions", "id"),
                            "record_execution": ("operations", "id"), "create_finding": ("findings", "id"),
                            "dispose_finding": ("finding_dispositions", "id"),
                            "start_attempt": ("attempts", "id"), "decide_delivery": ("delivery_decisions", "id"),
                            "register_report": ("reports", "id"), "record_delivery_event": ("delivery_events", "id"),
                            "record_coverage_review": ("coverage_reviews", "id"), "upsert_case_actor": ("case_actors", "id"),
                            "upsert_case_session": ("case_sessions", "id"), "upsert_case_object": ("case_objects", "ref")}
                if command in entities:
                    table, column = entities[command]
                    if not conn.execute(f"SELECT 1 FROM {table} WHERE {column}=?", (key,)).fetchone():
                        raise StoreError(f"audit references a missing {command} entity")
                if command in ("remember", "remember_hypothesis"):
                    pending.append(("experience", key))
                    case_changed |= command == "remember_hypothesis"
                    for link in conn.execute("SELECT experience_id,target_id FROM experience_links WHERE revision=?", (row["revision"],)):
                        pending.extend(("experience", item) for item in link)
                elif command in ("link_experience", "retract_experience_link"):
                    clause, value = ("revision", row["revision"]) if command == "link_experience" else ("id", key)
                    links = list(conn.execute(f"SELECT experience_id,target_id FROM experience_links WHERE {clause}=?", (value,)))
                    if not links:
                        raise StoreError("audit references a missing experience link")
                    for link in links:
                        pending.extend(("experience", item) for item in link)
                elif command == "record_artifact_event":
                    event = conn.execute("SELECT artifact_id FROM artifact_events WHERE id=?", (key,)).fetchone()
                    if event is None:
                        raise StoreError("audit references a missing artifact event")
                    pending.append(("artifact", event[0]))
                elif command == "assess":
                    assessment = conn.execute("SELECT finding_id FROM assessments WHERE id=?", (key,)).fetchone()
                    if assessment is None:
                        raise StoreError("audit references a missing assessment")
                    pending.extend(("assessment", item[0]) for item in conn.execute("SELECT id FROM assessments WHERE finding_id=?", (assessment[0],)))
                elif command in ("create_action", "transition_action"):
                    pending.append(("action", key))
                elif command == "record_execution":
                    pending.append(("operation", key))
                elif command.startswith("upsert_case_"):
                    pending.append((command.removeprefix("upsert_case_"), key))
                    case_changed = True
            while pending:
                owner, key = pending.pop()
                if (owner, key) in changed:
                    continue
                changed.add((owner, key))
                # All versions participate: a changed head also invalidates retained origins.
                for table in ("experience_claim_endpoints", "experience_claim_conditions"):
                    pending.extend(("experience", row[0]) for row in conn.execute(f"""SELECT c.experience_id FROM {table} e
                        JOIN experience_claims c ON c.id=e.claim_id WHERE e.owner=? AND e.record_id=?""", (owner, key)))
                if owner == "experience":
                    pending.extend(("experience", row[0]) for row in conn.execute("SELECT experience_id FROM experience_sources WHERE source_experience_id=?", (key,)))
                    for link in conn.execute("SELECT experience_id,target_id FROM experience_links WHERE experience_id=? OR target_id=?", (key, key)):
                        pending.extend(("experience", item) for item in link)
                if owner in ("artifact", "assessment"):
                    pending.extend(("experience", row[0]) for row in conn.execute("SELECT experience_id FROM experience_material_sources WHERE owner=? AND record_id=?", (owner, key)))
                if owner == "artifact":
                    pending.extend(("operation", row[0]) for row in conn.execute("SELECT DISTINCT operation_id FROM observation_artifacts WHERE artifact_id=?", (key,)))
                    pending.extend(("assessment", row[0]) for row in conn.execute("""SELECT DISTINCT a.assessment_id FROM assessment_observations a
                        JOIN observation_artifacts b ON b.operation_id=a.operation_id AND b.step=a.step WHERE b.artifact_id=?""", (key,)))
                elif owner == "operation":
                    # Observation attachments are immutable across retained Case
                    # versions; their relational links cover historical evidence.
                    pending.extend(("experience", row[0]) for row in conn.execute("SELECT experience_id FROM experience_observations WHERE operation_id=?", (key,)))
                    pending.extend(("assessment", row[0]) for row in conn.execute("SELECT assessment_id FROM assessment_observations WHERE operation_id=?", (key,)))
                    pending.extend(("artifact", row[0]) for row in conn.execute("SELECT artifact_id FROM observation_artifacts WHERE operation_id=?", (key,)))
                elif owner == "action":
                    pending.extend(("operation", row[0]) for row in conn.execute("SELECT o.id FROM operations o JOIN attempts a ON a.id=o.attempt_id WHERE a.action_id=?", (key,)))
                    pending.extend(("experience", row[0]) for row in conn.execute("SELECT id FROM experiences WHERE action_id=?", (key,)))
                elif owner == "actor":
                    pending.extend(("session", row[0]) for row in conn.execute("SELECT id FROM case_sessions WHERE actor_id=?", (key,)))
                    pending.extend(("object", row[0]) for row in conn.execute("SELECT ref FROM case_objects WHERE owner_actor=?", (key,)))
                    pending.extend(("experience", row[0]) for row in conn.execute("SELECT experience_id FROM experience_case_actors WHERE actor_id=?", (key,)))
                elif owner == "object":
                    pending.extend(("experience", row[0]) for row in conn.execute("SELECT experience_id FROM experience_case_objects WHERE object_ref=?", (key,)))
            ids = [key for owner, key in changed if owner == "experience"]
            if ids:
                rows = list(conn.execute(f"SELECT id FROM experiences WHERE id IN ({','.join('?' for _ in ids)}) ORDER BY created_at DESC,id DESC", ids))
                if len(rows) != len(ids):
                    raise StoreError("recall delta references a missing experience")
                ids = [row[0] for row in rows]
            owners = []
            if include_owner_relations:
                if case_changed:
                    owners.append({"owner": "case", "record_id": "context"})
                owners.extend({"owner": owner, "record_id": key} for owner, key in sorted(changed) if owner in ("operation", "experience"))
            return {"binding": binding, "experience_ids": ids, "owner_keys": owners, "full_acquisition_reason": None}

    def _recall_dependencies(self, conn, experience_id):
        """Retain unavailable locators and traverse exact versions, including origins."""
        version = conn.execute("SELECT max(version) FROM experience_versions WHERE experience_id=?", (experience_id,)).fetchone()[0]
        pending, seen, refs = [(experience_id, version)], set(), set()

        def external(owner, record_id):
            if owner in ("artifact", "assessment", "operation", "session", "object", "knowledge", "history"):
                refs.add((owner, record_id))
            if owner == "artifact":
                refs.update(("operation", row[0]) for row in conn.execute("SELECT operation_id FROM observation_artifacts WHERE artifact_id=?", (record_id,)))
            elif owner == "assessment":
                refs.update(("operation", row[0]) for row in conn.execute("SELECT operation_id FROM assessment_observations WHERE assessment_id=?", (record_id,)))

        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            row = conn.execute("SELECT * FROM experience_versions WHERE experience_id=? AND version=?", key).fetchone()
            if row is None:
                raise StoreError("recall dependency retained version is missing")
            try:
                snapshot = json.loads(row["snapshot_json"])
                if not isinstance(snapshot, dict) or _digest(snapshot) != row["content_sha256"]:
                    raise ValueError("retained content mismatch")
                if not isinstance(snapshot.get("evidence"), list):
                    raise ValueError("retained evidence malformed")
            except (TypeError, ValueError) as exc:
                raise StoreError("recall dependency retained version is corrupt") from exc
            for source in conn.execute("SELECT * FROM experience_sources WHERE experience_id=? AND experience_version=?", key):
                retained = conn.execute("SELECT content_sha256 FROM experience_versions WHERE experience_id=? AND version=?", (source["source_experience_id"], source["source_version"])).fetchone()
                if retained is None or retained[0] != source["content_sha256"]:
                    raise StoreError("recall source retained binding is corrupt")
                pending.append((source["source_experience_id"], source["source_version"]))
            pending.extend(tuple(row) for row in conn.execute("SELECT target_id,target_version FROM experience_links WHERE experience_id=? AND experience_version=? AND relation='depends_on'", key))
            tables = ["experience_material_sources"]
            if conn.execute("SELECT schema_version FROM store").fetchone()[0] >= 16:
                tables.append("experience_external_sources")
            for table in tables:
                for source in conn.execute(f"SELECT owner,record_id FROM {table} WHERE experience_id=? AND experience_version=?", key):
                    external(*source)
            for table in ("experience_claim_endpoints", "experience_claim_conditions"):
                for endpoint in conn.execute(f"SELECT e.owner,e.record_id,e.version FROM {table} e JOIN experience_claims c ON c.id=e.claim_id WHERE c.experience_id=? AND c.experience_version=?", key):
                    if endpoint["owner"] == "experience":
                        pending.append((endpoint["record_id"], endpoint["version"]))
                    else:
                        external(endpoint["owner"], endpoint["record_id"])
            for ref in snapshot["evidence"]:
                if (not isinstance(ref, dict) or not isinstance(ref.get("operation_id"), str)
                        or type(ref.get("step")) is not int or ref["step"] < 0
                        or _identifier(ref["operation_id"], "operation_id") != ref["operation_id"]
                        or not conn.execute("SELECT 1 FROM observations WHERE operation_id=? AND step=?",
                                            (ref["operation_id"], ref["step"])).fetchone()):
                    raise StoreError("retained observation binding is corrupt")
                external("operation", ref["operation_id"])
                for artifact in conn.execute("SELECT artifact_id FROM observation_artifacts WHERE operation_id=? AND step=?", (ref["operation_id"], ref["step"])):
                    external("artifact", artifact[0])
        return [{"owner": owner, "record_id": key} for owner, key in sorted(refs)]

    @staticmethod
    def _recall_refs(refs):
        if not isinstance(refs, list):
            raise StoreError("recall refs must be a list of owner/record_id objects")
        result = set()
        allowed = {"artifact", "assessment", "operation", "session", "object", "knowledge", "history", "case"}
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) != {"owner", "record_id"} or not isinstance(ref["owner"], str) or ref["owner"] not in allowed:
                raise StoreError("unsupported recall probe reference")
            key = _identifier(ref["record_id"], "record_id")
            if key != ref["record_id"]:
                raise StoreError("recall probe requires a canonical record_id")
            if ref["owner"] == "case" and key != "context":
                raise StoreError("case probe requires context")
            result.add((ref["owner"], key))
        return sorted(result)

    @staticmethod
    def _recall_file_fence(path):
        """Ephemeral identity only; semantic probes always validate actual bytes."""
        try:
            if path.resolve() != path:
                return {"unavailable": "symlink"}
            info = path.stat(follow_symlinks=False)
            return {"version": _report_file_version(info), "mode": info.st_mode}
        except (OSError, RuntimeError) as exc:
            return {"unavailable": type(exc).__name__}

    def _recall_private_probe(self, row, owner):
        ref = row["private_ref"]
        if not ref:
            return {"status": "available", "sha256": None}, None
        self._private_ref(ref)
        path = self.root / ref
        before = self._recall_file_fence(path)
        material = {"unavailable": before.get("unavailable", "non_regular_file")}
        status = "unavailable"
        try:
            if "version" in before and stat.S_ISREG(before["mode"]):
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if (_report_file_version(opened), opened.st_mode) != (before["version"], before["mode"]):
                        raise ConflictError("private source changed before recall read")
                    sha256 = hashlib.sha256()
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        sha256.update(chunk)
                    if _report_file_version(os.fstat(handle.fileno())) != before["version"]:
                        raise ConflictError("private source changed during recall read")
                material = {"sha256": sha256.hexdigest()}
                try:
                    if owner == "session":
                        self._check_private_material(ref, "private_ref", ("session_id", row["id"]), (("actor", row["actor_id"]), ("kind", row["kind"])))
                    else:
                        self._check_private_material(ref, "private_ref", ("object_ref", row["ref"]), (("owner_actor", row["owner_actor"] or ""),))
                    status = "available"
                except (OSError, StoreError):
                    status = "unavailable"
        except OSError as exc:
            material = {"unavailable": type(exc).__name__}
        if before != self._recall_file_fence(path):
            raise ConflictError("private source changed during recall probe")
        return {"status": status, **material}, before

    def _recall_probe_items(self, conn, refs, captured=None):
        cache, fences = {}, {}

        def artifact_fence(ref):
            try:
                path = target_raw_artifact_path(self.root, self.target, ref)
            except (OSError, ValueError) as exc:
                return {"unavailable": type(exc).__name__}
            return self._recall_file_fence(path)

        def probe(owner, key):
            if (owner, key) in cache:
                return cache[(owner, key)]
            fence = None
            if owner in ("knowledge", "history"):
                capture = (self._capture_history_source(conn, key) if owner == "history"
                           else experience_knowledge.capture_source(self.root, key))
                try:
                    (experience_history if owner == "history" else experience_knowledge).check_capture(capture)
                except (OSError, ValueError) as exc:
                    raise ConflictError("external source changed during recall probe") from exc
                if captured is not None:
                    captured[owner][key] = capture
                hashes = (capture.get("byte_digests", {}) if owner == "history" else
                          {path: hashlib.sha256(raw).hexdigest() for path, (_, raw) in capture["files"].items()})
                value = {"status": capture["status"], "binding": capture.get("binding"), "reason": capture.get("reason"),
                         "bytes": sorted((str(path.relative_to(self.root)), digest) for path, digest in hashes.items())}
                stamps = (capture["files"] if owner == "history" else
                          {path: stamp for path, (stamp, _) in capture["files"].items()})
                fence = {"files": sorted((str(path), stamp) for path, stamp in stamps.items()),
                         "directories": sorted((str(path), stamp) for path, stamp in capture.get("directories", {}).items())}
            elif owner == "case":
                value = {table: [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]
                         for table in ("case_actors", "case_sessions", "case_objects")}
                private = ([("session", row["id"]) for row in value["case_sessions"]]
                           + [("object", row["ref"]) for row in value["case_objects"]])
                value["private"] = [probe(*ref) for ref in private]
                fence = [fences[ref] for ref in private]
            else:
                tables = {"artifact": ("artifacts", "id"), "assessment": ("assessments", "id"),
                          "operation": ("operations", "id"), "session": ("case_sessions", "id"), "object": ("case_objects", "ref")}
                table, column = tables[owner]
                row = conn.execute(f"SELECT * FROM {table} WHERE {column}=?", (key,)).fetchone()
                if row is None:
                    raise StoreError(f"canonical recall source is missing: {owner}:{key}")
                value = {"record": dict(row)}
                if owner == "artifact":
                    actual = {}
                    fence = artifact_fence(row["ref"])
                    status = self._artifact_status(conn, dict(row), byte_capture=actual)
                    if fence != artifact_fence(row["ref"]):
                        raise ConflictError("artifact changed during recall probe")
                    value.update(health=status, bytes=actual)
                    if captured is not None:
                        captured["artifacts"][key] = (dict(row), status, [])
                elif owner == "assessment":
                    if not conn.execute("SELECT 1 FROM findings WHERE id=?", (row["finding_id"],)).fetchone():
                        raise StoreError("canonical assessment finding is missing")
                    value["current"] = conn.execute("SELECT max(revision) FROM assessments WHERE finding_id=?", (row["finding_id"],)).fetchone()[0]
                    artifacts = [item[0] for item in conn.execute("""SELECT DISTINCT b.artifact_id FROM assessment_observations a
                        JOIN observation_artifacts b ON b.operation_id=a.operation_id AND b.step=a.step WHERE a.assessment_id=? ORDER BY b.artifact_id""", (key,))]
                    value["artifacts"] = [probe("artifact", item) for item in artifacts]
                    fence = [fences[("artifact", item)] for item in artifacts]
                elif owner == "operation":
                    attempt = conn.execute("SELECT * FROM attempts WHERE id=?", (row["attempt_id"],)).fetchone()
                    if attempt is None:
                        raise StoreError("canonical operation attempt is missing")
                    if attempt["action_id"] and not conn.execute("SELECT 1 FROM actions WHERE id=?", (attempt["action_id"],)).fetchone():
                        raise StoreError("canonical operation action is missing")
                    value["attempt"] = dict(attempt)
                    value["observations"] = [dict(item) for item in conn.execute("SELECT * FROM observations WHERE operation_id=? ORDER BY step", (key,))]
                    for item in value["observations"]:
                        try:
                            if not isinstance(json.loads(item["detail_json"] or "{}"), dict):
                                raise ValueError("not an object")
                        except (TypeError, ValueError) as exc:
                            raise StoreError("canonical observation detail is corrupt") from exc
                    artifacts = [item[0] for item in conn.execute("SELECT DISTINCT artifact_id FROM observation_artifacts WHERE operation_id=? ORDER BY artifact_id", (key,))]
                    value["artifacts"] = [probe("artifact", item) for item in artifacts]
                    fence = [fences[("artifact", item)] for item in artifacts]
                elif owner in ("session", "object"):
                    if row["actor_id" if owner == "session" else "owner_actor"] and not conn.execute(
                            "SELECT 1 FROM case_actors WHERE id=?", (row["actor_id" if owner == "session" else "owner_actor"],)).fetchone():
                        raise StoreError("canonical Case actor is missing")
                    value["private"], fence = self._recall_private_probe(row, owner)
            cache[(owner, key)] = _digest(value)
            fences[(owner, key)] = _digest(fence)
            return cache[(owner, key)]
        items = [{"ref": {"owner": owner, "record_id": key}, "fingerprint": probe(owner, key)} for owner, key in refs]
        return items, [{"ref": {"owner": owner, "record_id": key}, "fingerprint": fences[(owner, key)]}
                       for owner, key in refs]

    def recall_probe(self, refs, *, expected_binding):
        """Fresh owner byte verification; refs never contain paths or prior health."""
        refs = self._recall_refs(refs)
        with self._connection() as conn:
            if expected_binding is None:
                raise ConflictError("recall requires an exact Store binding")
            binding = self._recall_binding(conn, expected_binding)
            items, fences = self._recall_probe_items(conn, refs)
            return {"binding": binding, "items": items, "fences": fences}

    def recall_rows(self, ids, *, expected_binding):
        """Read page-equivalent bodies, complete dependency locators and stable byte probes."""
        if not isinstance(ids, list):
            raise StoreError("recall ids must be a list")
        ids = list(dict.fromkeys(_identifier(item, "experience_id") for item in ids))
        if len(ids) > 1000:
            raise StoreError("recall ids must contain at most 1000 unique IDs")
        with self._connection() as conn:
            self._require_provenance_schema(conn)
            if expected_binding is None:
                raise ConflictError("recall requires an exact Store binding")
            binding = self._recall_binding(conn, expected_binding)
            rows = [dict(row) for row in conn.execute(f"SELECT * FROM experiences WHERE id IN ({','.join('?' for _ in ids)}) ORDER BY created_at DESC,id DESC", ids)] if ids else []
            if len(rows) != len(ids):
                raise StoreError("one or more recall experience IDs are missing")
            dependencies = {row["id"]: self._recall_dependencies(conn, row["id"]) for row in rows}
            for row in rows:
                retained = conn.execute("SELECT snapshot_json FROM experience_versions WHERE experience_id=? ORDER BY version DESC LIMIT 1", (row["id"],)).fetchone()
                snapshot = json.loads(retained[0])
                if any(snapshot.get(key) != value for key, value in row.items()):
                    raise StoreError("canonical experience head differs from its retained version")
            refs = self._recall_refs([ref for values in dependencies.values() for ref in values])
            captured = {"artifacts": {}, "knowledge": {}, "history": {}}
            probes, fences = self._recall_probe_items(conn, refs, captured)
            self._assemble_experience_rows(conn, rows, captured)
            if (probes, fences) != self._recall_probe_items(conn, refs):
                raise ConflictError("recall source bytes changed while assembling rows; retry")
            return {"binding": binding, "items": rows, "dependencies": dependencies, "probes": probes, "fences": fences}

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

    def _command(self, command: str, command_id: str, entity_id: str, actor: str, material: Any, mutation, *, source_capture=None,
                 expected_store_id: str | None = None) -> dict:
        # Mutations also persist these identities; normalizing only the audit
        # would leave claim tokens and receipt references pointing at other IDs.
        if command_id != _identifier(command_id, "command_id") or actor != _text(actor, "actor"):
            raise StoreError("command_id and actor must not have surrounding whitespace")
        if expected_store_id is not None:
            expected_store_id = _identifier(expected_store_id, "expected_store_id")
        digest = _digest(material)
        knowledge_guard = (experience_knowledge.publication_lock(self.root)
                           if source_capture and any(item["status"] == "available"
                               for item in source_capture["knowledge"].values()) else nullcontext())
        history_guard = (experience_history.receipt_lock(self.root, self.target)
                         if source_capture and any(item["status"] == "available"
                             for item in source_capture["history"].values()) else nullcontext())
        with knowledge_guard, history_guard, self._connection(write=True) as conn:
            store = conn.execute("SELECT store_id,revision FROM store WHERE singleton=1").fetchone()
            if expected_store_id is not None and store["store_id"] != expected_store_id:
                raise ConflictError("Store identity changed; the original command cannot authorize this Store")
            existing = conn.execute("SELECT * FROM audit WHERE command_id=?", (command_id,)).fetchone()
            if existing:
                if (existing["command"], existing["entity_id"], existing["actor"], existing["content_sha256"]) != (
                    command, entity_id, actor, digest
                ):
                    raise ConflictError(f"command_id {command_id} was already used for different content")
                return {**dict(existing), "replayed": True}
            revision = store["revision"] + 1
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
    def _finding_status_sql(schema_version: int, column: str = "findings.id") -> str:
        if schema_version < 18:
            return "'active'"
        return ("COALESCE((SELECT d.status FROM finding_dispositions d "
                f"WHERE d.finding_id={column} ORDER BY d.revision DESC LIMIT 1),'active')")

    @staticmethod
    def _finding_dispositions(conn, rows: list[dict]) -> None:
        for row in rows:
            row["disposition"] = {"id": None, "status": "active", "replacement_id": None}
        if not rows or conn.execute("SELECT schema_version FROM store").fetchone()[0] < 18:
            return
        by_id = {row["id"]: row for row in rows}
        for item in conn.execute(f"""SELECT d.* FROM finding_dispositions d
                WHERE d.finding_id IN ({','.join('?' for _ in by_id)}) AND d.revision=(
                    SELECT max(x.revision) FROM finding_dispositions x WHERE x.finding_id=d.finding_id)""", list(by_id)):
            by_id[item["finding_id"]]["disposition"] = dict(item)

    def _require_active_finding(self, conn, finding_id: str) -> None:
        row = conn.execute("SELECT id FROM findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            raise FindingNotFoundError(f"finding missing: {finding_id}")
        finding = dict(row)
        self._finding_dispositions(conn, [finding])
        if finding["disposition"]["status"] != "active":
            raise ConflictError(f"finding {finding_id} is withdrawn; explicitly reopen it with dispose-finding before new work")

    def _ensure_finding(self, conn, claim: dict, now: str) -> None:
        existing = conn.execute("SELECT * FROM findings WHERE id=?", (claim["id"],)).fetchone()
        if existing and any(existing[key] != value for key, value in claim.items()):
            raise ConflictError("finding ID is already bound to a different claim; no implicit overwrite")
        if existing:
            self._require_active_finding(conn, claim["id"])
        else:
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

    def dispose_finding(self, *, command_id: str, finding_id: str, status: str, reason: str,
                        actor: str, expected_disposition: str | None,
                        replacement_id: str | None = None) -> dict:
        """Withdraw or reopen an unbound claim; never retract evidence or a technical judgment."""
        finding_id = _identifier(finding_id, "finding_id")
        if not isinstance(status, str) or status not in FINDING_DISPOSITIONS:
            raise StoreError("finding disposition must be active or withdrawn")
        reason = _text(reason, "reason")
        if expected_disposition is not None:
            expected_disposition = _identifier(expected_disposition, "expected_disposition")
        if replacement_id is not None:
            replacement_id = _identifier(replacement_id, "replacement_id")
            if status != "withdrawn" or replacement_id == finding_id:
                raise StoreError("replacement_id requires withdrawal and a different Finding")
        material = (finding_id, status, reason, expected_disposition, replacement_id)

        def mutate(conn, revision, now):
            if conn.execute("SELECT schema_version FROM store").fetchone()[0] < 18:
                raise StoreError("Finding disposition requires schema v18; run upgrade-schema with a verified private backup")
            if not conn.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone():
                raise FindingNotFoundError(f"finding missing: {finding_id}")
            previous = conn.execute("SELECT * FROM finding_dispositions WHERE finding_id=? ORDER BY revision DESC LIMIT 1",
                                    (finding_id,)).fetchone()
            if (previous["id"] if previous else None) != expected_disposition:
                raise ConflictError("finding disposition changed; reload before writing")
            if (previous["status"] if previous else "active") == status:
                raise ConflictError("finding already has this disposition; replay its original command or choose a state transition")
            # This owner only repairs unbound claims; assessed/evidence-backed work has its own review contracts.
            for table, column in (("finding_observations", "finding_id"), ("assessments", "finding_id"),
                                  ("actions", "subject_finding_id"), ("coverage_reviews", "finding_id")):
                if conn.execute(f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1", (finding_id,)).fetchone():
                    raise StoreError(f"finding {finding_id} is bound to {table}; dispose-finding only handles unbound candidates")
            if replacement_id:
                self._require_active_finding(conn, replacement_id)
            conn.execute("INSERT INTO finding_dispositions VALUES (?,?,?,?,?,?,?,?,?)",
                         (command_id, finding_id, status, replacement_id, expected_disposition, reason, actor, revision, now))

        return self._command("dispose_finding", command_id, command_id, actor, material, mutate)

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
            if finding_id is not None:
                self._require_active_finding(conn, finding_id)
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
                          metadata: Mapping[str, Any] | None = None,
                          expected_store_id: str | None = None) -> dict:
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
                        for artifact in conn.execute("""SELECT DISTINCT a.id,a.ref FROM artifacts a
                            JOIN observation_artifacts b ON b.artifact_id=a.id
                            WHERE b.operation_id=?""", (operation_id,)):
                            events = self._artifact_events(conn, str(artifact["id"]))
                            if events.get("availability", {}).get("state") == "unavailable":
                                raise StoreError(f"registered evidence is explicitly unavailable: {artifact['ref']}")
                            if events.get("provenance", {}).get("state") == "revoked":
                                raise StoreError(f"registered evidence provenance is revoked: {artifact['ref']}")
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
                        # Same evidence-authority check as the execution branch:
                        # a revoked or explicitly unavailable work output must
                        # not complete a claimed action even though its file
                        # still exists on disk.
                        artifact_events = self._artifact_events(conn, str(result_artifact["id"]))
                        if artifact_events.get("availability", {}).get("state") == "unavailable":
                            raise StoreError(
                                f"work completion artifact is explicitly unavailable: {result_artifact['ref']}")
                        if artifact_events.get("provenance", {}).get("state") == "revoked":
                            raise StoreError(
                                f"work completion artifact provenance is revoked: {result_artifact['ref']}")
                        self._insert_artifact(conn, result_artifact)
                    conn.execute("INSERT INTO action_completions VALUES (?,?,?,?,?,?)",
                                 (action_id, claim_token, expected_version, operation_id,
                                  result_artifact["id"] if result_artifact else None, receipt_id))
                token = None
            conn.execute("""UPDATE actions SET metadata_json=?,status=?,claim_token=?,claimed_by=?,reason=?,
                version=version+1,updated_at=? WHERE id=?""",
                         (merged_metadata_json, status, token, actor if token else None, reason, now, action_id))

        return self._command("transition_action", command_id, action_id, actor, fields, mutate,
                             expected_store_id=expected_store_id)

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

    def _artifact_status(self, conn, artifact: dict, *, byte_capture=None) -> dict:
        events = self._artifact_events(conn, str(artifact["id"]))
        try:
            actual = self._artifact(artifact["ref"])
            bytes_valid = actual == artifact
            if byte_capture is not None:
                byte_capture.update(actual)
        except ConflictError:
            if byte_capture is not None:
                raise
            bytes_valid = False
        except (OSError, ValueError, StoreError) as exc:
            bytes_valid = False
            if byte_capture is not None:
                byte_capture.update(unavailable=type(exc).__name__)
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

    def _report_files(self, artifact: dict) -> list[tuple[Path, tuple[int, ...]]]:
        path = self.root / artifact["ref"]
        content, version = read_report_asset(path, artifact["sha256"])
        files = [(path, version)]
        for ref in report_attachment_refs(content):
            asset = path.parent / ref
            _, version = read_report_asset(asset, asset.name[:64])
            files.append((asset, version))
        return files

    def _check_report_files(self, conn, artifact: dict, files: list[tuple[Path, tuple[int, ...]]]) -> None:
        """Recheck captured file identities and body events without hashing in the write transaction."""
        for path, expected in files:
            try:
                if path != path.resolve() or _report_file_version(path.stat(follow_symlinks=False)) != expected:
                    raise ConflictError(f"report asset changed before commit: {path}; retry with stable files")
            except (OSError, RuntimeError) as exc:
                raise ConflictError(f"report asset unavailable before commit: {path}") from exc
        events = self._artifact_events(conn, artifact["id"])
        if (events.get("availability", {}).get("state") == "unavailable"
                or events.get("provenance", {}).get("state") == "revoked"):
            raise StoreError(f"report artifact is no longer authorized: {artifact['ref']}")

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
        cleanup = json.loads(fields["detail_json"]).get("cleanup_confirmation")
        if cleanup is not None:
            validate_cleanup_confirmation(cleanup)
            if outcome != "complete" or fields["state_changing"] is not False:
                raise StoreError("cleanup confirmation requires a complete, explicitly read-only verification observation")
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
                         candidate: dict | None = None, expected_operation: str | None = None,
                         finding_id: str | None = None) -> dict:
        """Register published files atomically; never execute or assess a vulnerability."""
        attempt_id = _identifier(attempt_id, "attempt_id")
        if not isinstance(outcome, str) or outcome not in {"complete", "partial", "unknown"}:
            raise StoreError("execution outcome must be complete, partial or unknown")
        if not isinstance(observations, list) or (not observations and outcome != "unknown"):
            raise StoreError("observations must be a list; only unknown outcome may have no observations")
        prepared = [self._observation(row, outcome) for row in observations]
        claim = None
        if finding_id is not None:
            finding_id = _identifier(finding_id, "finding_id")
            if candidate is not None:
                raise StoreError("use candidate or existing finding_id, not both")
        if candidate is not None:
            claim = self._candidate(candidate)
            if not any(all(row[k] == claim[k] for k in ("endpoint", "method", "family")) for row, _ in prepared):
                raise StoreError("candidate must bind an exact observed endpoint, method and family")
        if expected_operation is not None:
            expected_operation = _identifier(expected_operation, "expected_operation")
        material = (attempt_id, outcome, prepared, claim, expected_operation)
        if finding_id is not None:
            material += (finding_id,)
        operation_id = "operation:" + _digest(material)

        def mutate(conn, revision, now):
            if finding_id is not None:
                self._require_active_finding(conn, finding_id)
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
                # ponytail: partial trusts the declared attempt association; plan membership needs a persisted plan.
                if not any(row["family"] == action["family"] and
                           (outcome == "partial" or row["endpoint"] == action["endpoint"]) for row, _ in prepared):
                    required = "family" if outcome == "partial" else "endpoint and family"
                    raise StoreError(f"execution observations must include the bound action's {required}")
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
            linked_finding = claim["id"] if claim else finding_id
            if linked_finding:
                conn.executemany("INSERT INTO finding_observations VALUES (?,?,?)",
                                 [(linked_finding, operation_id, step) for step in range(len(prepared))])

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
            self._require_active_finding(conn, finding_id)
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

    def report_cleanup(self, finding_id: str, *, require_verified: bool = True,
                       _capture: list | None = None) -> dict:
        """Read restoration confirmations from this finding's registered observations.

        A confirmation is an authored claim backed by raw verification evidence,
        not proof inferred from a verb, local file deletion or an unbound receipt.
        """
        finding_id = _identifier(finding_id, "finding_id")
        with self._connection() as conn:
            return self._report_cleanup(conn, finding_id, require_verified=require_verified, capture=_capture)

    def _report_cleanup(self, conn, finding_id: str, *, require_verified: bool = True,
                        capture: list | None = None) -> dict:
        if not conn.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone():
            raise FindingNotFoundError(f"finding missing: {finding_id}")
        meta = conn.execute("SELECT store_id,revision FROM store").fetchone()
        rows = [dict(row) for row in conn.execute("""SELECT b.*,o.outcome FROM finding_observations f
            JOIN observations b ON b.operation_id=f.operation_id AND b.step=f.step
            JOIN operations o ON o.id=b.operation_id WHERE f.finding_id=?
            ORDER BY o.revision DESC,b.step DESC""", (finding_id,))]
        mutations = {(row["operation_id"], row["step"]): row for row in rows if row["state_changing"] == 1}
        covered, confirmations, invalid = set(), [], []
        for row in rows if mutations else []:
            if set(mutations) <= covered:
                break
            candidate_files = []
            try:
                confirmation = json.loads(row["detail_json"]).get("cleanup_confirmation")
                if confirmation is None:
                    continue
                confirmation = validate_cleanup_confirmation(confirmation)
                if (row["outcome"] != "complete" or row["error"] or row["truncated"]
                        or row["state_changing"] != 0):
                    raise StoreError("cleanup verification must be complete and explicitly read-only")
                refs = _references(confirmation["mutation_refs"])
                if any(ref not in mutations for ref in refs):
                    raise StoreError("cleanup mutation_refs must identify this finding's state-changing observations")
                if set(refs) <= covered:
                    continue
                if any(datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00"))
                       < datetime.fromisoformat(mutations[ref]["observed_at"].replace("Z", "+00:00"))
                       or (row["operation_id"] == ref[0] and row["step"] <= ref[1]) for ref in refs):
                    raise StoreError("cleanup verification must follow the referenced mutation")
                artifacts = [dict(value) for value in conn.execute("""SELECT a.* FROM observation_artifacts b
                    JOIN artifacts a ON a.id=b.artifact_id WHERE b.operation_id=? AND b.step=?""",
                    (row["operation_id"], row["step"]))]
                if not artifacts:
                    raise StoreError("cleanup verification requires registered raw evidence")
                for artifact in artifacts:
                    path = self.root / artifact["ref"]
                    before = _report_file_version(path.stat(follow_symlinks=False))
                    self._require_valid_artifact(conn, artifact)
                    if before != _report_file_version(path.stat(follow_symlinks=False)):
                        raise ConflictError("cleanup evidence changed during acquisition")
                    candidate_files.append((artifact, [(path, before)]))
            except ConflictError:
                raise
            except (OSError, ValueError, StoreError) as exc:
                invalid.append({"operation_id": row["operation_id"], "step": row["step"], "reason": str(exc)[:240]})
                continue
            if capture is not None:
                capture.extend(candidate_files)
            covered.update(refs)
            confirmations.append({"operation_id": row["operation_id"], "step": row["step"]})
        pending = sorted(set(mutations) - covered)
        result = {
            "required": bool(mutations),
            "status": "pending" if pending else "verified" if mutations else "not_required",
            "store_id": meta["store_id"], "revision": meta["revision"],
            "verification_refs": confirmations,
            "invalid_verification_refs": invalid[:5],
            "pending_mutation_refs": [{"operation_id": operation, "step": step} for operation, step in pending],
        }
        if pending and require_verified:
            raise StoreError("report publication requires evidence-linked cleanup verification for every state-changing observation")
        return result

    def register_report(self, *, command_id: str, report_id: str, finding_id: str,
                        assessment_id: str, delivery_id: str, artifact: str,
                        actor: str) -> dict:
        """Register a published report only for the current assessment/delivery."""
        report_id = _identifier(report_id, "report_id")
        finding_id = _identifier(finding_id, "finding_id")
        assessment_id = _identifier(assessment_id, "assessment_id")
        delivery_id = _identifier(delivery_id, "delivery_id")
        cleanup_files: list = []
        cleanup = self.report_cleanup(finding_id, _capture=cleanup_files)
        artifact_value = self._artifact(artifact)
        report_files = self._report_files(artifact_value)
        current = self.finding(finding_id)
        current_assessment = current.get("assessment") or {}
        current_delivery = next(
            (item for item in current.get("deliveries", []) if item.get("id") == delivery_id),
            None,
        )
        if (current_assessment.get("id") != assessment_id or not current_delivery
                or current_delivery.get("stale") or current_delivery.get("status") != "eligible"):
            raise StoreError("report registration requires the current eligible delivery decision")
        if any(item["id"] == report_id and item["stale"] for item in current["reports"]):
            raise StoreError("registered report is stale or damaged; registration cannot repair it")
        material = (report_id, finding_id, assessment_id, delivery_id, artifact_value)

        def mutate(conn, revision, now):
            if revision - 1 != cleanup["revision"] or conn.execute("SELECT store_id FROM store").fetchone()[0] != cleanup["store_id"]:
                raise ConflictError("cleanup evidence binding changed; retry report registration")
            for evidence_artifact, files in cleanup_files:
                self._check_report_files(conn, evidence_artifact, files)
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
            self._check_report_files(conn, artifact_value, report_files)
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
        artifact_value = {"id": report["artifact_id"], "ref": report["artifact_ref"],
                          "sha256": report["artifact_sha256"], "size": report["artifact_size"]}
        report_files = self._report_files(artifact_value)
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
            self._check_report_files(conn, artifact_value, report_files)
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
                    self._require_active_finding(conn, claim["id"])
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
                 action_id: str | None = None, finding_id: str | None = None,
                 sources: list[dict] | None = None, links: list[dict] | None = None,
                 claims: list[dict] | None = None,
                 expected_revision: int | None = None) -> dict:
        if not isinstance(kind, str) or kind not in {"primitive", "negative", "hypothesis", "handoff", "note"}:
            raise StoreError("invalid experience kind")
        try:
            statement, conditions, reopen_when, next_intent = normalize_experience_text(
                kind, statement, conditions, reopen_when, next_intent)
        except ValueError as exc:
            raise StoreError(str(exc)) from exc
        refs = _references(evidence) if evidence else []
        if not isinstance(evidence, list) or (kind in {"negative", "primitive"} and not refs):
            raise StoreError("negative/primitive experience must cite observations")
        if action_id is not None:
            action_id = _identifier(action_id, "action_id")
        if finding_id is not None:
            finding_id = _identifier(finding_id, "finding_id")
        sources, links = sources if sources is not None else [], links if links is not None else []
        claims = claims if claims is not None else []
        if not isinstance(claims, list) or len(claims) > 100:
            raise StoreError("claims must be a list of at most 100 explicit declarations")
        if not isinstance(sources, list) or not isinstance(links, list):
            raise StoreError("sources and links must be lists")
        if (links or expected_revision is not None) and (type(expected_revision) is not int or expected_revision < 0):
            raise StoreError("explicit links require a non-negative expected_revision")
        material = (kind, statement, conditions, reopen_when, next_intent, refs, action_id, finding_id)
        if sources or links or claims or expected_revision is not None:
            material += (sources, links, expected_revision)
        if claims:
            material += (claims,)

        captured = self._capture_experience_basis(command_id, sources, links, claims, refs)

        def mutate(conn, revision, now):
            self._require_provenance_schema(conn)
            self._check_experience_capture(conn, captured, revision)
            if expected_revision is not None and revision != expected_revision + 1:
                raise ConflictError("experience revision changed; reload before accepting")
            if kind == "note":
                self._require_memory_schema(conn)
            conn.execute("INSERT INTO experiences VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (command_id, kind, statement, conditions, reopen_when, next_intent, action_id, finding_id, actor, now))
            conn.executemany("INSERT INTO experience_observations VALUES (?,?,?)",
                             [(command_id, operation, step) for operation, step in refs])
            self._snapshot_experience(conn, command_id, revision, now)
            for source in sources:
                self._accept_experience_source(conn, command_id, source, revision, captured)
            for index, claim in enumerate(claims):
                self._accept_experience_claim(conn, command_id, revision, index, claim, sources, refs, captured)
            for index, link in enumerate(links):
                self._insert_experience_link(conn, f"{command_id}:link:{index}", command_id, link, revision, captured)

        return self._command("remember", command_id, command_id, actor, material, mutate, source_capture=captured)

    @staticmethod
    def _require_provenance_schema(conn) -> None:
        if conn.execute("SELECT schema_version FROM store").fetchone()[0] < 15:
            raise StoreError("experience provenance requires explicit upgrade-schema --backup PATH")

    @staticmethod
    def _snapshot_experience(conn, experience_id, version, now, *, only_if_missing=False):
        if only_if_missing and conn.execute(
                "SELECT 1 FROM experience_versions WHERE experience_id=?", (experience_id,)).fetchone():
            return
        row = conn.execute("SELECT * FROM experiences WHERE id=?", (experience_id,)).fetchone()
        if not row:
            raise StoreError(f"experience missing: {experience_id}")
        snapshot = dict(row)
        for table, key in (("experience_case_context", "case_context"),
                           ("experience_case_actors", "actors"), ("experience_case_objects", "objects"),
                           ("experience_observations", "evidence")):
            snapshot[key] = [dict(item) for item in conn.execute(
                f"SELECT * FROM {table} WHERE experience_id=? ORDER BY 1,2", (experience_id,))]
        conn.execute("INSERT INTO experience_versions VALUES (?,?,?,?,?)",
                     (experience_id, version, _digest(snapshot), json.dumps(snapshot, sort_keys=True), now))

    def experience_version(self, experience_id: str, version: int | None = None) -> dict:
        """Expand an actual retained version, never reconstruct lost pre-upgrade history."""
        experience_id = _identifier(experience_id, "experience_id")
        if version is not None and (type(version) is not int or version < 0):
            raise StoreError("version must be a non-negative integer")
        with self._connection() as conn:
            self._require_provenance_schema(conn)
            clause, params = ("", (experience_id,)) if version is None else (" AND version=?", (experience_id, version))
            row = conn.execute("SELECT * FROM experience_versions WHERE experience_id=?" + clause
                               + " ORDER BY version DESC LIMIT 1", params).fetchone()
            if not row:
                raise StoreError(f"retained experience version missing: {experience_id}:{version}")
            result = dict(row)
            result["snapshot"] = json.loads(result.pop("snapshot_json"))
            if _digest(result["snapshot"]) != result["content_sha256"]:
                raise StoreError("retained experience version content mismatch")
            node = self._experience_health(conn, [(experience_id, result["version"])])[(experience_id, result["version"])]
            result.update(claims=self._experience_claim_rows(conn, experience_id, result["version"]), sources=node["sources"], source_health=node["health"], review_state=node["review_state"],
                          applicability=node["applicability"],
                          correction_refs=[link for link in node["links"] if link["relation"] != "depends_on"],
                          dependency_refs=[link for link in node["links"] if link["relation"] == "depends_on"])
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            return {**result, "target": meta["target"], "store_id": meta["store_id"]}

    def knowledge_source(self, knowledge_id: str) -> dict:
        """Return the current reviewed publication binding, without a target or purpose."""
        knowledge_id = _identifier(knowledge_id, "knowledge_id")
        capture = experience_knowledge.capture_source(self.root, knowledge_id)
        if capture["status"] != "available":
            raise StoreError(f"knowledge source {knowledge_id}: {capture['status']}: {capture.get('reason', '')}")
        return dict(capture["binding"])

    def history_source(self, imported_experience_id: str, *, full: bool = False) -> dict:
        """Read a same-Store imported origin without importing or repairing anything."""
        experience_id = _identifier(imported_experience_id, "imported_experience_id")
        with self._connection() as conn:
            if not conn.execute("SELECT 1 FROM experiences WHERE id=?", (experience_id,)).fetchone():
                raise StoreError(f"imported experience missing: {experience_id}")
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
        capture = experience_history.capture_source(self.root, self.target, meta["store_id"], experience_id)
        current = self.binding()
        if any(current[key] != meta[key] for key in ("target", "store_id", "revision")):
            raise ConflictError("history source Store changed during capture; reload and retry")
        if capture["status"] != "available":
            if full:
                return {"owner": "history", "record_id": experience_id, "source": None,
                        "source_kind": None, "selector": None, "record": None,
                        "availability": "unavailable", "verification": "unverified",
                        "reason": capture.get("reason", "historical original unavailable")}
            raise StoreError(f"history source {experience_id}: unavailable: {capture.get('reason', '')}")
        return dict(capture["detail"] if full else capture["binding"])

    @staticmethod
    def _require_external_source_schema(conn, owner="knowledge"):
        if conn.execute("SELECT schema_version FROM store").fetchone()[0] < (17 if owner == "history" else 16):
            raise StoreError(f"{owner} experience sources require explicit upgrade-schema --backup PATH")

    def _accept_experience_source(self, conn, experience_id, source, version, captured):
        if isinstance(source, dict) and source.get("owner") in ("knowledge", "history"):
            owner = source["owner"]
            resolver = experience_history if owner == "history" else experience_knowledge
            self._require_external_source_schema(conn, owner)
            try:
                resolver.validate_source(source)
            except ValueError as exc:
                raise StoreError(str(exc)) from exc
            acquisition = captured[owner][source["record_id"]]
            if resolver.source_health(source, acquisition)["status"] != "available":
                raise ConflictError(f"{owner} source is unavailable or changed; reload its binding")
            conn.execute("INSERT INTO experience_external_sources VALUES (?,?,?,?,?,?,?)", (
                experience_id, version, source["owner"], source["record_id"], source["version"],
                source["content_sha256"], source["purpose"]))
            return
        if isinstance(source, dict) and "owner" in source:
            required = {"target", "store_id", "owner", "record_id", "version", "content_sha256", "purpose"}
            if set(source) != required or source.get("owner") not in ("artifact", "assessment"):
                raise StoreError("material source requires an exact artifact/assessment binding and purpose")
            if not isinstance(source["purpose"], str) or source["purpose"] not in {"origin", "basis"}:
                raise StoreError("source purpose must be origin or basis")
            if type(source["version"]) is not int or source["version"] < 0:
                raise StoreError("source version must be a non-negative integer")
            actual = self._experience_entity(conn, source["owner"], source["record_id"])
            if {k: source[k] for k in required - {"purpose"}} != actual:
                raise ConflictError("material source identity/version/content changed")
            health = captured["materials"][(source["owner"], source["record_id"])]
            if source["purpose"] == "basis" and health != "available":
                raise StoreError("basis material is unavailable, revoked or changed")
            conn.execute("INSERT INTO experience_material_sources VALUES (?,?,?,?,?,?,?,?,?)", (
                experience_id, version, source["owner"], source["record_id"], source["version"],
                source["content_sha256"], source["purpose"],
                source["record_id"] if source["owner"] == "artifact" else None,
                source["record_id"] if source["owner"] == "assessment" else None))
            return
        required = {"target", "store_id", "experience_id", "version", "content_sha256", "purpose"}
        if not isinstance(source, dict) or set(source) != required:
            raise StoreError("source requires target/store_id/experience_id/version/content_sha256/purpose")
        meta = conn.execute("SELECT target,store_id FROM store").fetchone()
        if (source["target"], source["store_id"]) != tuple(meta):
            raise StoreError("experience source belongs to another target or Store")
        if (not isinstance(source["purpose"], str) or source["purpose"] not in {"origin", "basis"}
                or type(source["version"]) is not int or source["version"] < 0):
            raise StoreError("invalid source purpose/version")
        row = conn.execute("SELECT * FROM experience_versions WHERE experience_id=? AND version=?",
                           (source["experience_id"], source["version"])).fetchone()
        if not row or row["content_sha256"] != source["content_sha256"]:
            raise ConflictError("source version missing or changed")
        try:
            valid = _digest(json.loads(row["snapshot_json"])) == row["content_sha256"]
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise StoreError("source version is corrupt")
        if source["experience_id"] == experience_id:
            raise StoreError("self source is not allowed")
        if source["purpose"] == "basis":
            self._require_healthy_basis(captured, source["experience_id"], source["version"])
        conn.execute("INSERT INTO experience_sources VALUES (?,?,?,?,?,?)", (
            experience_id, version, source["experience_id"], source["version"], source["purpose"], source["content_sha256"]))

    def _experience_entity(self, conn, owner, record_id):
        tables = {"actor": ("case_actors", "id"), "object": ("case_objects", "ref"),
                  "session": ("case_sessions", "id"), "action": ("actions", "id"),
                  "operation": ("operations", "id"), "artifact": ("artifacts", "id"),
                  "assessment": ("assessments", "id"), "experience": ("experiences", "id")}
        if not isinstance(owner, str) or owner not in tables:
            raise StoreError("unsupported experience entity owner")
        record_id = _identifier(record_id, "record_id")
        table, column = tables[owner]
        row = conn.execute(f"SELECT * FROM {table} WHERE {column}=?", (record_id,)).fetchone()
        if row is None:
            raise StoreError(f"experience entity missing: {owner}:{record_id}")
        meta = dict(conn.execute("SELECT * FROM store").fetchone())
        data = dict(row)
        version = data.get("revision", data.get("version", 0))
        digest = _digest(data)
        if owner == "experience":
            retained = conn.execute("SELECT * FROM experience_versions WHERE experience_id=? ORDER BY version DESC LIMIT 1", (record_id,)).fetchone()
            if retained is None:
                raise StoreError("experience entity has no retained version")
            version, digest = retained["version"], retained["content_sha256"]
        return {"target": meta["target"], "store_id": meta["store_id"], "owner": owner,
                "record_id": record_id, "version": version, "content_sha256": digest}

    def experience_entity(self, owner: str, record_id: str) -> dict:
        """Acquire an exact same-Store identity; labels never resolve entities."""
        with self._connection() as conn:
            self._require_provenance_schema(conn)
            return self._experience_entity(conn, owner, record_id)

    def _material_source_health(self, conn, owner, record_id, artifacts):
        if owner == "artifact":
            rows = conn.execute("SELECT * FROM artifacts WHERE id=?", (record_id,)).fetchall()
        elif owner == "assessment":
            row = conn.execute("SELECT finding_id,revision FROM assessments WHERE id=?", (record_id,)).fetchone()
            if row is None:
                return "unavailable"
            current = conn.execute("SELECT max(revision) FROM assessments WHERE finding_id=?", (row["finding_id"],)).fetchone()[0]
            if current != row["revision"]:
                return "version_changed"
            rows = conn.execute("""SELECT DISTINCT a.* FROM assessment_observations e
                JOIN observation_artifacts o ON o.operation_id=e.operation_id AND o.step=e.step
                JOIN artifacts a ON a.id=o.artifact_id WHERE e.assessment_id=?""", (record_id,)).fetchall()
        else:
            raise StoreError("material source owner must be artifact or assessment")
        if not rows:
            return "unavailable"
        for row in rows:
            artifact = dict(row)
            if artifact["id"] not in artifacts:
                path = self.root / artifact["ref"]
                try:
                    stamp = _report_file_version(path.stat(follow_symlinks=False))
                except OSError:
                    stamp = None
                status = self._artifact_status(conn, artifact)
                if status["authorized"] and (stamp is None or stamp != _report_file_version(path.stat(follow_symlinks=False))):
                    raise ConflictError("material changed while capturing source")
                artifacts[artifact["id"]] = (artifact, status, [(path, stamp)])
            status = artifacts[artifact["id"]][1]
            if not status["authorized"]:
                return "revoked" if status["provenance"] == "revoked" else "unavailable"
        return "available"

    def _accept_experience_claim(self, conn, experience_id, version, index, claim, sources, evidence, captured):
        """Accept advisory subject-to-object assertions, never technical judgments.

        observed_access: subject accessed object; uses: subject uses object;
        produces: subject produces object; requires: subject requires object;
        enables: subject enables object. Conditions and timing are explicit text,
        not inferred equivalence or permission to execute the described action.
        """
        required = {"subject", "predicate", "object", "conditions", "timing", "source_refs"}
        if not isinstance(claim, dict) or not required <= set(claim) or set(claim) - required - {"condition_bindings", "validity"}:
            raise StoreError("claim requires subject/predicate/object/conditions/timing/source_refs")
        if not isinstance(claim["predicate"], str) or claim["predicate"] not in CLAIM_PREDICATES:
            raise StoreError("unsupported claim predicate")
        bound_conditions, validity = self._claim_context(claim)
        conditions, timing = _text(claim["conditions"], "claim conditions"), _text(claim["timing"], "claim timing")
        refs = claim["source_refs"]
        if not isinstance(refs, list) or not refs or len(refs) > 100:
            raise StoreError("claim source_refs must contain 1..100 explicit source or observation indices")
        endpoints = []
        declarations = [(side, claim[side]) for side in ("subject", "object")]
        declarations.extend((f"condition:{role}", value) for role, value in (bound_conditions or {}).items())
        for side, endpoint in declarations:
            if not isinstance(endpoint, dict) or set(endpoint) != set(ENTITY_FIELDS):
                raise StoreError("claim endpoint requires an exact same-Store entity binding")
            if type(endpoint["version"]) is not int or endpoint["version"] < 0:
                raise StoreError("claim endpoint version must be a non-negative integer")
            if endpoint != self._experience_entity(conn, endpoint["owner"], endpoint["record_id"]):
                raise ConflictError("claim endpoint belongs to another Store or changed")
            if endpoint["owner"] == "experience":
                self._require_healthy_basis(captured, endpoint["record_id"], endpoint["version"])
            elif endpoint["owner"] in ("artifact", "assessment") and captured["materials"].get((endpoint["owner"], endpoint["record_id"])) != "available":
                raise StoreError("claim endpoint material is unavailable, revoked or changed")
            endpoints.append((side, endpoint))
        claim_id = f"{experience_id}:claim:{index}"
        conn.execute("INSERT INTO experience_claims VALUES (?,?,?,?,?,?)", (claim_id, experience_id, version, claim["predicate"], conditions, timing))
        for side, endpoint in endpoints:
            table = "experience_claim_conditions" if side.startswith("condition:") else "experience_claim_endpoints"
            role = side.removeprefix("condition:")
            conn.execute(f"INSERT INTO {table} VALUES (?,?,?,?,?,?)", (claim_id, role, endpoint["owner"], endpoint["record_id"], endpoint["version"], endpoint["content_sha256"]))
        if validity is not None:
            conn.execute("INSERT INTO experience_claim_validity VALUES (?,?,?)", (claim_id, validity["from"], validity["until"]))
        for ref in refs:
            if not isinstance(ref, dict) or len(ref) != 1:
                raise StoreError("claim reference requires source or observation index")
            key, value = next(iter(ref.items()))
            if key not in ("source", "observation") or type(value) is not int or value < 0:
                raise StoreError("invalid claim source reference")
            values = sources if key == "source" else evidence
            if value >= len(values):
                raise StoreError("claim source reference is outside accepted evidence")
            if key == "source":
                # Bind the canonical source identity instead of a transient list position.
                source = sources[value]
                if source["purpose"] != "basis":
                    raise StoreError("claim source must be a basis, not an origin")
                if source.get("owner") == "knowledge":
                    conn.execute("INSERT INTO experience_claim_external_sources VALUES (?,?,?,?,?,?,?)", (
                        claim_id, experience_id, version, source["owner"], source["record_id"], source["version"], source["purpose"]))
                else:
                    conn.execute("INSERT INTO experience_claim_sources VALUES (?,?,?,?,?,NULL,NULL)",
                                 (claim_id, source.get("owner", "experience"), source.get("record_id", source.get("experience_id")), source["version"], source["purpose"]))
            else:
                conn.execute("INSERT INTO experience_claim_sources VALUES (?,NULL,NULL,NULL,NULL,?,?)", (claim_id, *evidence[value]))

    @staticmethod
    def _claim_context(claim):
        try:
            bindings = condition_bindings(claim.get("condition_bindings"))
            if bindings is not None and any(set(value) != set(ENTITY_FIELDS)
                                            for value in claim["condition_bindings"].values()):
                raise ValueError("condition bindings require exact entity fields")
            return bindings, validity_window(claim.get("validity"))
        except ValueError as exc:
            raise StoreError(str(exc)) from exc

    def _claim_entity_view(self, conn, endpoint, meta, captured=None):
        binding = entity_binding({**meta, **{key: endpoint[key] for key in ENTITY_FIELDS if key not in meta}})
        current = self._experience_entity(conn, endpoint["owner"], endpoint["record_id"])
        health = "available" if binding == current else "version_changed"
        if health == "available" and endpoint["owner"] in ("artifact", "assessment"):
            health = self._material_source_health(conn, endpoint["owner"], endpoint["record_id"],
                                                  captured["artifacts"] if captured is not None else {})
        elif health == "available" and endpoint["owner"] == "experience":
            key = (endpoint["record_id"], endpoint["version"])
            if self._experience_health(conn, [key], **(captured or {}))[key]["unhealthy"]:
                health = "needs_review"
        return {**binding, "health": health}

    def _experience_claim_rows(self, conn, experience_id, version, captured=None):
        rows = []
        meta = dict(conn.execute("SELECT target,store_id FROM store").fetchone())
        for row in conn.execute("SELECT * FROM experience_claims WHERE experience_id=? AND experience_version=? ORDER BY id", (experience_id, version)):
            claim = dict(row)
            claim["advisory"] = True
            claim["source_refs"] = [dict(ref) for ref in conn.execute("SELECT * FROM experience_claim_sources WHERE claim_id=?", (claim["id"],))]
            if conn.execute("SELECT schema_version FROM store").fetchone()[0] >= 16:
                claim["source_refs"].extend(dict(ref) for ref in conn.execute(
                    "SELECT * FROM experience_claim_external_sources WHERE claim_id=?", (claim["id"],)))
            for endpoint in conn.execute("SELECT * FROM experience_claim_endpoints WHERE claim_id=?", (claim["id"],)):
                claim[endpoint["side"]] = self._claim_entity_view(conn, endpoint, meta, captured)
            bindings = {row["role"]: self._claim_entity_view(conn, row, meta, captured) for row in conn.execute(
                "SELECT * FROM experience_claim_conditions WHERE claim_id=? ORDER BY role", (claim["id"],))}
            claim["condition_bindings"] = bindings or None
            validity = conn.execute("SELECT valid_from,valid_until FROM experience_claim_validity WHERE claim_id=?", (claim["id"],)).fetchone()
            claim["validity"] = validity_window({"from": validity[0], "until": validity[1]}) if validity else None
            rows.append(claim)
        return rows

    @staticmethod
    def _correction_applicability(conn, link):
        """Compare retained declarations, not semantic equivalence or mutable heads."""
        conditions = link["conditions"]
        if conditions.lower() == "unknown":
            raise StoreError("correction requires explicit conditions; unknown is not a scope")
        declared = {}
        for side, key in (("source_conditions", (link["experience_id"], link["experience_version"])),
                          ("target_conditions", (link["target_id"], link["target_version"]))):
            row = conn.execute("SELECT snapshot_json,content_sha256 FROM experience_versions WHERE experience_id=? AND version=?", key).fetchone()
            if row is None:
                raise StoreError("correction endpoint retained version is missing")
            try:
                snapshot = json.loads(row["snapshot_json"])
                if (not isinstance(snapshot, dict) or _digest(snapshot) != row["content_sha256"]
                        or not isinstance(snapshot.get("conditions"), str)):
                    raise ValueError("invalid retained conditions")
            except (TypeError, ValueError) as exc:
                raise StoreError("correction endpoint retained version is corrupt") from exc
            declared[side] = snapshot["conditions"]
        identical = all(value == conditions for value in declared.values())
        return {"conditions": conditions, **declared,
                "comparison": "identical_declarations" if identical else "not_established",
                "effect": "whole_record" if identical else "conditional"}

    def _insert_experience_link(self, conn, link_id, experience_id, link, revision, captured):
        if not isinstance(link, dict) or set(link) != {"target_id", "relation", "conditions", "rationale"}:
            raise StoreError("link requires target_id/relation/conditions/rationale")
        target_id = _identifier(link["target_id"], "target_id")
        relation = link["relation"]
        conditions, rationale = _text(link["conditions"], "conditions"), _text(link["rationale"], "rationale")
        if not isinstance(relation, str) or relation not in {"supersedes", "refutes", "depends_on"} or target_id == experience_id:
            raise StoreError("invalid experience relation or self relation")
        versions = dict(conn.execute("SELECT experience_id,max(version) FROM experience_versions WHERE experience_id IN (?,?) GROUP BY experience_id", (experience_id, target_id)))
        if len(versions) != 2:
            raise StoreError("both relation endpoints must exist in this Store")
        if relation != "depends_on":
            self._correction_applicability(conn, {"conditions": conditions, "experience_id": experience_id,
                "experience_version": versions[experience_id], "target_id": target_id, "target_version": versions[target_id]})
        if relation in {"supersedes", "depends_on"} and conn.execute("""WITH RECURSIVE edges(a,b) AS (
                SELECT experience_id,target_id FROM experience_links WHERE relation IN ('supersedes','depends_on')
                UNION SELECT experience_id,source_experience_id FROM experience_sources WHERE purpose='basis'),
                reach(id) AS (SELECT ? UNION SELECT e.b FROM edges e JOIN reach r ON e.a=r.id)
                SELECT 1 FROM reach WHERE id=?""",
                (target_id, experience_id)).fetchone():
            raise StoreError("experience relation would create a cycle")
        if relation == "depends_on":
            self._require_healthy_basis(captured, target_id, versions[target_id])
        conn.execute("INSERT INTO experience_links VALUES (?,?,?,?,?,?,?,?,?)",
                     (link_id, experience_id, target_id, versions[experience_id], versions[target_id],
                      relation, conditions, rationale, revision))

    def link_experience(self, *, command_id: str, experience_id: str, target_id: str,
                        relation: str, conditions: str, rationale: str, expected_revision: int, actor: str) -> dict:
        experience_id = _identifier(experience_id, "experience_id")
        if type(expected_revision) is not int or expected_revision < 0:
            raise StoreError("expected_revision must be a non-negative integer")
        link = dict(target_id=target_id, relation=relation, conditions=conditions, rationale=rationale)
        captured = self._capture_experience_basis(command_id, [], [link])
        def mutate(conn, revision, now):
            self._require_provenance_schema(conn)
            if revision != expected_revision + 1:
                raise ConflictError("experience revision changed; reload before linking")
            self._check_experience_capture(conn, captured, revision)
            self._insert_experience_link(conn, command_id, experience_id, link, revision, captured)
        return self._command("link_experience", command_id, experience_id, actor,
                             (experience_id, link, expected_revision), mutate, source_capture=captured)

    def retract_experience_link(self, *, command_id: str, link_id: str, reason: str,
                                expected_revision: int, actor: str) -> dict:
        link_id, reason = _identifier(link_id, "link_id"), _text(reason, "reason")
        if type(expected_revision) is not int or expected_revision < 0:
            raise StoreError("expected_revision must be a non-negative integer")
        def mutate(conn, revision, now):
            self._require_provenance_schema(conn)
            if revision != expected_revision + 1:
                raise ConflictError("experience revision changed; reload before retracting")
            conn.execute("INSERT INTO experience_link_events VALUES (?,?,?,?,?,?)",
                         (command_id, link_id, reason, actor, revision, now))
        return self._command("retract_experience_link", command_id, link_id, actor,
                             (link_id, reason, expected_revision), mutate)

    def experience_sources(self, experience_ids: list[str]) -> dict:
        """Batch source bindings and explicit corrections in one read snapshot."""
        if not isinstance(experience_ids, list) or not experience_ids or len(experience_ids) > 1000:
            raise StoreError("experience_ids must contain 1..1000 IDs")
        ids = list(dict.fromkeys(_identifier(item, "experience_id") for item in experience_ids))
        with self._connection() as conn:
            self._require_provenance_schema(conn)
            rows = [dict(row) for row in conn.execute(
                f"SELECT * FROM experiences WHERE id IN ({','.join('?' for _ in ids)})", ids)]
            if len(rows) != len(ids):
                raise StoreError("one or more experience IDs are missing from this Store")
            self._experience_provenance(conn, rows)
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            return {"target": self.target, "store_id": meta["store_id"], "revision": meta["revision"], "items": rows}

    def _capture_experience_basis(self, command_id, sources, links, claims=(), evidence=()):
        """Hash evidence before the write transaction; bind the ensuing owner snapshot."""
        with self._connection() as conn:
            self._require_provenance_schema(conn)
            if conn.execute("SELECT 1 FROM audit WHERE command_id=?", (command_id,)).fetchone():
                return None  # _command checks exact replay content before mutation.
            roots = []
            for source in sources:
                if isinstance(source, dict) and "owner" not in source and source.get("purpose") == "basis":
                    roots.append((_identifier(source.get("experience_id"), "experience_id"), source.get("version")))
            for link in links:
                if isinstance(link, dict) and link.get("relation") == "depends_on":
                    key = _identifier(link.get("target_id"), "target_id")
                    version = conn.execute("SELECT max(version) FROM experience_versions WHERE experience_id=?", (key,)).fetchone()[0]
                    roots.append((key, version))
            endpoints = []
            claim_observations = list(evidence)
            for claim in claims:
                if not isinstance(claim, dict):
                    raise StoreError("claim must be an object")
                bound_conditions, _ = self._claim_context(claim)
                for endpoint in [claim.get("subject"), claim.get("object"), *(bound_conditions or {}).values()]:
                    if not isinstance(endpoint, dict):
                        raise StoreError("claim endpoint requires an exact entity binding")
                    actual = self._experience_entity(conn, endpoint.get("owner"), endpoint.get("record_id"))
                    if endpoint != actual:
                        raise ConflictError("claim endpoint belongs to another Store or changed")
                    endpoints.append(endpoint)
                    if endpoint["owner"] == "experience":
                        roots.append((endpoint["record_id"], endpoint["version"]))
                refs = claim.get("source_refs")
                if not isinstance(refs, list):
                    raise StoreError("claim source_refs must be a list")
                for ref in refs:
                    if isinstance(ref, dict) and "observation" in ref:
                        index = ref["observation"]
                        if type(index) is not int or not 0 <= index < len(evidence):
                            raise StoreError("claim observation reference is outside accepted evidence")
                        # All accepted observations are basis; refs only select claim support.
            for _, version in roots:
                if type(version) is not int or version < 0:
                    raise StoreError("basis requires an existing non-negative version")
            artifacts = {}
            knowledge, history = {}, {}
            health = self._experience_health(conn, roots, artifacts, knowledge, history)
            for source in sources:
                if isinstance(source, dict) and source.get("owner") in ("knowledge", "history"):
                    owner = source["owner"]
                    resolver = experience_history if owner == "history" else experience_knowledge
                    cache = history if owner == "history" else knowledge
                    self._require_external_source_schema(conn, owner)
                    try:
                        resolver.validate_source(source)
                    except ValueError as exc:
                        raise StoreError(str(exc)) from exc
                    record_id = source["record_id"]
                    if record_id not in cache:
                        cache[record_id] = (self._capture_history_source(conn, record_id) if owner == "history"
                                            else experience_knowledge.capture_source(self.root, record_id))
                    diagnostic = resolver.source_health(source, cache[record_id])
                    if diagnostic["status"] != "available":
                        raise StoreError(f"{owner} source {record_id}: {diagnostic['status']}: {diagnostic.get('reason', '')}")
            materials = {}
            for source in [*sources, *endpoints]:
                if isinstance(source, dict) and source.get("owner") in ("artifact", "assessment"):
                    owner, record_id = source.get("owner"), source.get("record_id")
                    self._experience_entity(conn, owner, record_id)
                    materials[(owner, record_id)] = self._material_source_health(conn, owner, record_id, artifacts)
            for operation, step in claim_observations:
                bound = conn.execute("SELECT artifact_id FROM observation_artifacts WHERE operation_id=? AND step=?", (operation, step)).fetchall()
                if not bound or any(self._material_source_health(conn, "artifact", row[0], artifacts) != "available" for row in bound):
                    raise StoreError("observation basis is unavailable or revoked")
            return {"revision": conn.execute("SELECT revision FROM store").fetchone()[0],
                    "health": health, "artifacts": artifacts, "materials": materials, "knowledge": knowledge, "history": history}

    def _capture_history_source(self, conn, record_id):
        if not conn.execute("SELECT 1 FROM experiences WHERE id=?", (record_id,)).fetchone():
            return {"status": "unavailable", "availability": "unavailable", "verification": "unverified",
                    "files": {}, "directories": {}, "reason": "imported experience is missing from this Store"}
        store_id = conn.execute("SELECT store_id FROM store").fetchone()[0]
        return experience_history.capture_source(self.root, self.target, store_id, record_id)

    def _check_experience_capture(self, conn, captured, revision):
        if captured is None or revision != captured["revision"] + 1:
            raise ConflictError("experience sources changed before acceptance; reload and retry")
        for owner, resolver in (("knowledge", experience_knowledge), ("history", experience_history)):
            for acquisition in captured[owner].values():
                if acquisition["status"] == "available":
                    try:
                        resolver.check_capture(acquisition)
                    except (OSError, ValueError) as exc:
                        raise ConflictError(f"{owner} source changed before acceptance: {exc}") from exc
        for artifact, status, files in captured["artifacts"].values():
            if status["authorized"]:
                self._check_report_files(conn, artifact, files)

    @staticmethod
    def _require_healthy_basis(captured, experience_id, version):
        node = captured["health"].get((experience_id, version))
        if not node or node["unhealthy"]:
            raise StoreError(f"basis is unavailable, changed or challenged: {experience_id}:{version}")

    def _experience_health(self, conn, roots, artifacts=None, knowledge=None, history=None):
        """Resolve only the exact reachable versions; retain every broken edge and source."""
        artifacts = {} if artifacts is None else artifacts
        knowledge = {} if knowledge is None else knowledge
        history = {} if history is None else history
        external_sources = conn.execute("SELECT schema_version FROM store").fetchone()[0] >= 16
        nodes, pending, correction_scopes = {}, list(roots), {}
        while pending:
            key = pending.pop()
            if key in nodes:
                continue
            experience_id, version = key
            node = nodes[key] = {"health": [], "edges": [], "sources": [], "links": [], "review_state": "advisory"}
            current = conn.execute("SELECT max(version) FROM experience_versions WHERE experience_id=?", (experience_id,)).fetchone()[0]
            retained = conn.execute("SELECT * FROM experience_versions WHERE experience_id=? AND version=?", key).fetchone()
            snapshot, state = None, "available"
            if retained is None:
                state = "unavailable"
            else:
                try:
                    snapshot = json.loads(retained["snapshot_json"])
                    if not isinstance(snapshot, dict) or _digest(snapshot) != retained["content_sha256"]:
                        state = "corrupt"
                except (TypeError, ValueError):
                    state = "corrupt"
                if state == "available" and current != version:
                    state = "version_changed"
            node["health"].append({"experience_id": experience_id, "version": version, "purpose": "basis", "status": state})
            links = [dict(row) for row in conn.execute("""SELECT l.*, e.id AS retraction_id,
                    e.reason AS retraction_reason FROM experience_links l
                    LEFT JOIN experience_link_events e ON e.link_id=l.id
                    WHERE (l.experience_id=? AND l.experience_version=?) OR (l.target_id=? AND l.target_version=?)
                    ORDER BY l.revision,l.id""", (*key, *key))]
            node["links"] = links
            node["applicability"] = {"conditions": snapshot.get("conditions") if isinstance(snapshot, dict) else None,
                                     "comparison": "not_evaluated", "corrections": []}
            for link in links:
                if link["relation"] != "depends_on":
                    if link["id"] not in correction_scopes:
                        correction_scopes[link["id"]] = self._correction_applicability(conn, link)
                    link["applicability"] = correction_scopes[link["id"]]
                    incoming = (link["target_id"], link["target_version"]) == key
                    node["applicability"]["corrections"].append({"link_id": link["id"], "relation": link["relation"],
                        "direction": "incoming" if incoming else "outgoing", "withdrawn": bool(link["retraction_id"]),
                        **link["applicability"]})
                    if incoming and link["applicability"]["effect"] == "whole_record":
                        if link["relation"] == "supersedes":
                            node["review_state"] = "superseded"
                        elif node["review_state"] != "superseded":
                            node["review_state"] = "disputed"
                if (link["experience_id"], link["experience_version"]) == key and link["relation"] == "depends_on":
                    dependency = (link["target_id"], link["target_version"])
                    node["edges"].append(dependency)
                    pending.append(dependency)
                    if link["retraction_id"]:
                        node["health"].append({"link_id": link["id"], "purpose": "basis", "status": "withdrawn_dependency"})
            for row in conn.execute("SELECT * FROM experience_sources WHERE experience_id=? AND experience_version=?", key):
                source = dict(row)
                dependency = (source["source_experience_id"], source["source_version"])
                node["sources"].append(source)
                pending.append(dependency)
                if source["purpose"] == "basis":
                    node["edges"].append(dependency)
                actual = conn.execute("SELECT content_sha256 FROM experience_versions WHERE experience_id=? AND version=?", dependency).fetchone()
                if actual is None or actual[0] != source["content_sha256"]:
                    node["health"].append({"experience_id": dependency[0], "version": dependency[1],
                                           "purpose": source["purpose"], "status": "corrupt"})
            for row in conn.execute("SELECT * FROM experience_material_sources WHERE experience_id=? AND experience_version=? ORDER BY owner,record_id,purpose", key):
                source = dict(row)
                actual = self._experience_entity(conn, source["owner"], source["record_id"])
                source["health"] = ("version_changed" if actual["version"] != source["source_version"] or actual["content_sha256"] != source["content_sha256"]
                                    else self._material_source_health(conn, source["owner"], source["record_id"], artifacts))
                node["sources"].append(source)
                node["health"].append({"owner": source["owner"], "record_id": source["record_id"], "purpose": source["purpose"], "status": source["health"]})
            if external_sources:
                for row in conn.execute("SELECT * FROM experience_external_sources WHERE experience_id=? AND experience_version=? ORDER BY owner,record_id,source_version,purpose", key):
                    source = dict(row)
                    binding = {"owner": source["owner"], "record_id": source["record_id"],
                               "version": source["source_version"], "content_sha256": source["content_sha256"]}
                    record_id = source["record_id"]
                    cache = history if source["owner"] == "history" else knowledge
                    resolver = experience_history if source["owner"] == "history" else experience_knowledge
                    if record_id not in cache:
                        cache[record_id] = (self._capture_history_source(conn, record_id) if source["owner"] == "history"
                                            else experience_knowledge.capture_source(self.root, record_id))
                    diagnostic = resolver.source_health(binding, cache[record_id])
                    source.update(health=diagnostic["status"], **{k: v for k, v in diagnostic.items() if k != "status"})
                    node["sources"].append(source)
                    node["health"].append({**binding, "purpose": source["purpose"], **diagnostic})
            for endpoint in conn.execute("""SELECT e.* FROM experience_claim_endpoints e
                    JOIN experience_claims c ON c.id=e.claim_id
                    WHERE c.experience_id=? AND c.experience_version=?
                    UNION ALL
                    SELECT e.claim_id,'condition:'||e.role,e.owner,e.record_id,e.version,e.content_sha256
                    FROM experience_claim_conditions e JOIN experience_claims c ON c.id=e.claim_id
                    WHERE c.experience_id=? AND c.experience_version=?""", (*key, *key)):
                actual = self._experience_entity(conn, endpoint["owner"], endpoint["record_id"])
                endpoint_state = "available"
                if actual["version"] != endpoint["version"] or actual["content_sha256"] != endpoint["content_sha256"]:
                    endpoint_state = "version_changed"
                elif endpoint["owner"] in ("artifact", "assessment"):
                    endpoint_state = self._material_source_health(conn, endpoint["owner"], endpoint["record_id"], artifacts)
                if endpoint["owner"] == "experience":
                    dependency = (endpoint["record_id"], endpoint["version"])
                    node["edges"].append(dependency)
                    pending.append(dependency)
                node["health"].append({"claim_id": endpoint["claim_id"], "side": endpoint["side"],
                                       "purpose": "basis", "status": endpoint_state})
            # Evidence is bound by the retained version, never by the mutable Case head.
            if isinstance(snapshot, dict) and state != "corrupt":
                for ref in snapshot.get("evidence", []):
                    bound = list(conn.execute("""SELECT a.* FROM observation_artifacts b JOIN artifacts a ON a.id=b.artifact_id
                        WHERE b.operation_id=? AND b.step=?""", (ref["operation_id"], ref["step"])))
                    if not bound:
                        node["health"].append({**ref, "purpose": "basis", "status": "unavailable"})
                    for row in bound:
                        artifact = dict(row)
                        if artifact["id"] not in artifacts:
                            path = self.root / artifact["ref"]
                            try:
                                stamp = _report_file_version(path.stat(follow_symlinks=False))
                            except OSError:
                                stamp = None
                            status = self._artifact_status(conn, artifact)
                            if status["authorized"] and (stamp is None or stamp != _report_file_version(path.stat(follow_symlinks=False))):
                                raise ConflictError("experience artifact changed while checking sources")
                            artifacts[artifact["id"]] = (artifact, status, [(path, stamp)])
                        status = artifacts[artifact["id"]][1]
                        node["health"].append({"artifact_id": artifact["id"], "purpose": "basis",
                            "status": "available" if status["authorized"] else
                            ("revoked" if status["provenance"] == "revoked" else "unavailable")})
            node["unhealthy"] = node["review_state"] != "advisory" or any(
                item["purpose"] == "basis" and item["status"] != "available" for item in node["health"])
        # Monotone closure: withdrawal never removes a bad dependency or revives advice.
        changed = True
        while changed:
            changed = False
            for node in nodes.values():
                if not node["unhealthy"] and any(nodes[key]["unhealthy"] for key in node["edges"]):
                    node["unhealthy"] = True
                    changed = True
        for node in nodes.values():
            for source in node["sources"]:
                if "owner" in source:
                    continue
                dependency = nodes[(source["source_experience_id"], source["source_version"])]
                source["health"] = (dependency["health"][0]["status"] if dependency["health"][0]["status"] != "available"
                                    else "challenged" if dependency["review_state"] in {"superseded", "disputed"}
                                    else "needs_review" if dependency["unhealthy"] else "available")
                node["health"].append({"experience_id": source["source_experience_id"], "version": source["source_version"],
                                       "purpose": source["purpose"], "status": source["health"]})
            for key in node["edges"]:
                if nodes[key]["unhealthy"]:
                    node["health"].append({"experience_id": key[0], "version": key[1],
                                           "purpose": "basis", "status": "needs_review"})
            if node["unhealthy"] and node["review_state"] == "advisory":
                node["review_state"] = "needs_review"
        return nodes

    def _experience_provenance(self, conn, rows, captured=None):
        self._require_provenance_schema(conn)
        if not rows:
            return
        ids = [row["id"] for row in rows]
        versions = dict(conn.execute(f"SELECT experience_id,max(version) FROM experience_versions WHERE experience_id IN ({','.join('?' for _ in ids)}) GROUP BY experience_id", ids))
        health = self._experience_health(conn, [(key, versions.get(key)) for key in ids], **(captured or {}))
        for row in rows:
            node = health[(row["id"], versions.get(row["id"]))]
            row.update(claims=self._experience_claim_rows(conn, row["id"], versions.get(row["id"]), captured), version=versions.get(row["id"]), sources=node["sources"], source_health=node["health"],
                       correction_refs=[link for link in node["links"] if link["relation"] != "depends_on"],
                       dependency_refs=[link for link in node["links"] if link["relation"] == "depends_on"],
                       review_state=node["review_state"],
                       applicability=node["applicability"])

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
            self._require_provenance_schema(conn)
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
                self._snapshot_experience(conn, hypothesis_id, revision - 1, now, only_if_missing=True)
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
            self._snapshot_experience(conn, hypothesis_id, revision, now)

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
        cleanup_valid = True
        if rows:
            try:
                self._report_cleanup(conn, rows[0]["finding_id"])
            except (OSError, ValueError, StoreError):
                cleanup_valid = False
        for report in rows:
            artifact = {
                "id": report["artifact_id"], "ref": report["artifact_ref"],
                "sha256": report["artifact_sha256"], "size": report["artifact_size"],
            }
            status = self._artifact_status(conn, artifact)
            if status["available"]:
                try:
                    self._report_files(artifact)
                except (OSError, ValueError, StoreError):
                    status["available"] = status["authorized"] = False
            current = current_delivery.get(str(report["destination"]))
            report["artifact_available"] = status["available"]
            report["artifact_authorized"] = status["authorized"]
            report["stale"] = not (
                assessment_valid
                and cleanup_valid
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
        if kind == "findings" and status is not None:
            condition = self._finding_status_sql(meta["schema_version"]) + "=?"
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
        elif kind == "findings":
            self._finding_dispositions(conn, rows)
        return self._slice(conn, binding, total=total, remaining=remaining, rows=rows, limit=limit)

    @staticmethod
    def _require_finding_status(status: str | None) -> None:
        if status is not None and (not isinstance(status, str) or status not in FINDING_DISPOSITIONS):
            raise StoreError("finding status filter must be active or withdrawn")

    def page(self, kind: str, *, limit: int = 50, cursor: str | None = None, status: str | None = None) -> dict:
        """Stable ID order, exact remainder and revision-bound cursor; never refresh state."""
        if not isinstance(kind, str) or kind not in self._PAGE_TABLES:
            raise StoreError("query kind must be actions, attempts, operations, findings or experiences")
        self._require_limit(limit)
        if kind == "findings":
            self._require_finding_status(status)
        elif status is not None and (kind != "actions" or not isinstance(status, str) or status not in self._ACTION_STATES):
            raise StoreError("status filter is only supported for action or Finding states")
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
        self._assemble_experience_rows(conn, rows)
        has_more = remaining > len(rows)
        next_cursor = None
        if has_more:
            last = rows[-1]
            next_cursor = base64.urlsafe_b64encode(json.dumps(
                {**binding, "after": [last["created_at"], last["id"]]}, sort_keys=True).encode()).decode()
        return {**binding, "items": rows, "total": total,
                "remaining": remaining - len(rows), "has_more": has_more,
                "next_cursor": next_cursor}

    def _assemble_experience_rows(self, conn, rows, captured=None):
        """The single body/provenance assembly shared by paging and recall batches."""
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
        self._experience_provenance(conn, rows, captured)

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
        self._experience_provenance(conn, rows)
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
            page = self._page_conn(conn, meta, "findings", limit=limit, cursor=cursor, status="active")
            for row in page["items"]:
                assessment = conn.execute("SELECT id, verdict FROM assessments WHERE finding_id=? "
                                          "ORDER BY revision DESC LIMIT 1", (row["id"],)).fetchone()
                row["assessment"] = dict(assessment) if assessment else None
            return page

    def finding_page(self, *, limit: int = 50, cursor: str | None = None, status: str | None = None) -> dict:
        """Return full finding projections from one revision-bound read snapshot."""
        self._require_limit(limit)
        self._require_finding_status(status)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            page = self._page_conn(conn, meta, "findings", limit=limit, cursor=cursor, status=status)
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

    def finding_state_page(self, *, limit: int = 50, cursor: str | None = None, status: str | None = None) -> dict:
        """Page claims and latest recorded posture without expanding evidence history.

        Use finding()/finding_page() or current truth for integrity and delivery
        decisions. These facts neither verify evidence nor authorize delivery.
        """
        self._require_limit(limit)
        self._require_finding_status(status)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            page = self._page_conn(conn, meta, "findings", limit=limit, cursor=cursor, status=status)
            self._finding_states(conn, page["items"])
            return page

    def finding_summary(self, *, limit: int = 5) -> dict:
        """Exact posture counts, a bounded preview and stable follow-ups on one snapshot."""
        self._require_limit(limit)
        with self._connection() as conn:
            meta = dict(conn.execute("SELECT * FROM store").fetchone())
            disposition = self._finding_status_sql(meta["schema_version"], "f.id")
            counts = dict(conn.execute(f"""WITH posture AS (
                SELECT f.id, COALESCE(a.verdict, '') AS verdict,
                    {disposition} AS disposition,
                    EXISTS(SELECT 1 FROM reports r WHERE r.finding_id=f.id) AS reported
                FROM findings f LEFT JOIN assessments a ON a.finding_id=f.id
                    AND a.revision=(SELECT max(x.revision) FROM assessments x WHERE x.finding_id=f.id)
                ) SELECT count(*) AS total,
                    count(CASE WHEN disposition='active' THEN 1 END) AS active,
                    count(CASE WHEN disposition='withdrawn' THEN 1 END) AS withdrawn,
                    count(CASE WHEN verdict='confirmed' THEN 1 END) AS confirmed,
                    count(CASE WHEN disposition='active' AND verdict NOT IN ('confirmed','refuted') THEN 1 END) AS pending_validation,
                    count(CASE WHEN verdict='confirmed' AND NOT reported THEN 1 END) AS validated_pending_report,
                    count(CASE WHEN reported THEN 1 END) AS reported,
                    min(CASE WHEN disposition='active' AND verdict NOT IN ('confirmed','refuted') THEN id END) AS next_validation,
                    min(CASE WHEN verdict='confirmed' AND NOT reported THEN id END) AS next_report
                FROM posture""").fetchone())
            page = self._page_conn(conn, meta, "findings", limit=limit, status="active")
            rows = {row["id"]: row for row in page["items"]}
            next_ids = {key: counts.pop(key) for key in ("next_validation", "next_report")}
            for finding_id in next_ids.values():
                if finding_id and finding_id not in rows:
                    rows[finding_id] = dict(conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())
                    self._finding_dispositions(conn, [rows[finding_id]])
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
                item["artifacts"] = [dict(binding) for binding in conn.execute("""SELECT b.kind,a.id AS id,a.ref,a.sha256,a.size
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

    def experience_exists(self, experience_id: str) -> bool:
        """Identity-only existence check; never expands sources or takes receipt locks.

        Callers that hold the migration receipt's exclusive directory lock must
        use this instead of ``experience()``: expanding an experience with
        history-origin sources acquires the shared receipt lock on another FD
        and self-deadlocks the exclusive holder.
        """
        experience_id = _identifier(experience_id, "experience_id")
        with self._connection() as conn:
            return conn.execute(
                "SELECT 1 FROM experiences WHERE id=?", (experience_id,)
            ).fetchone() is not None

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
            result = {**dict(row), "evidence": refs, "case": case}
            self._experience_provenance(conn, [result])
            return result

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
            result.update(dict(conn.execute(
                "SELECT target,store_id,revision FROM store WHERE singleton=1").fetchone()))
            return result

    def finding(self, finding_id: str) -> dict:
        """Compose technical truth and destination decisions without conflating them."""
        finding_id = _identifier(finding_id, "finding_id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not row:
                raise FindingNotFoundError(f"finding missing: {finding_id}")
            result = dict(row)
            self._finding_dispositions(conn, [result])
            self._finding_projections(conn, [result])
            assessment_value = result["assessment"]
            if assessment_value:
                assessment_value["evidence"] = [dict(item) for item in conn.execute(
                    "SELECT operation_id,step FROM assessment_observations WHERE assessment_id=? ORDER BY operation_id,step",
                    (assessment_value["id"],),
                )]
            return {**result,
                    "disposition_history": ([dict(item) for item in conn.execute(
                        "SELECT * FROM finding_dispositions WHERE finding_id=? ORDER BY revision", (finding_id,))]
                        if conn.execute("SELECT schema_version FROM store").fetchone()[0] >= 18 else []),
                    "delivery_events": self._delivery_event_rows(conn, finding_id, result["reports"]),
                    "revision": conn.execute("SELECT revision FROM store").fetchone()[0]}

    def backup(self, destination: str | Path) -> Path:
        """Use SQLite's snapshot API; copying just the main WAL database is unsafe."""
        path = Path(destination)
        # Symlink traversal and lexical '..' normalization can name different parents.
        if ".." in path.parts:
            raise StoreError(f"invalid target store backup path: {path}; use a path without '..'")
        try:
            with directory_handle(path.parent) as parent:
                if os.path.lexists(path):
                    raise FileExistsError(f"target store backup already exists: {path}")
                # SQLite opens filenames, not the descriptor reserved by O_EXCL.
                # Keep its writable database private and publish only a closed,
                # durable snapshot; a competing destination is never overwritten.
                with TemporaryDirectory(prefix=".ccst-backup-", dir=path.parent) as staging:
                    snapshot = Path(staging) / "snapshot.sqlite3"
                    fd = os.open(snapshot, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        with self._connection() as source:
                            target = sqlite3.connect(snapshot)
                            try:
                                source.backup(target)
                            finally:
                                target.close()
                        os.fsync(fd)
                        os.link(snapshot, path.name, dst_dir_fd=parent, follow_symlinks=False)
                        os.fsync(parent)
                    finally:
                        os.close(fd)
        except sqlite3.DatabaseError as exc:
            raise StoreError(f"target store backup failed at {path}: {exc}") from exc
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
            if before["schema_version"] not in {8, 9, 10, 11, 12, 13, 14, 15, 16, 17}:
                raise StoreError("Store schema upgrade requires schema v8 through v17")

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
                if before["schema_version"] < 12 and version >= 12:
                    for statement in _EXPERIENCE_PROVENANCE_SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                    for row in conn.execute("SELECT id FROM experiences").fetchall():
                        self._snapshot_experience(conn, row[0], before["revision"], _now())
                if before["schema_version"] == 12 and version >= 13:
                    sources = [dict(row) for row in conn.execute("SELECT * FROM experience_sources")]
                    links = [dict(row) for row in conn.execute("SELECT * FROM experience_links")]
                    events = [tuple(row) for row in conn.execute("SELECT * FROM experience_link_events")]
                    for table in ("experience_link_events", "experience_links", "experience_sources"):
                        conn.execute(f"DROP TABLE {table}")
                    for statement in _EXPERIENCE_PROVENANCE_SCHEMA.split(";"):
                        if statement.strip() and "CREATE TABLE experience_versions" not in statement:
                            conn.execute(statement)
                    for source in sources:
                        retained = conn.execute("SELECT min(version) FROM experience_versions WHERE experience_id=?", (source["experience_id"],)).fetchone()[0]
                        conn.execute("INSERT INTO experience_sources VALUES (?,?,?,?,?,?)", (
                            source["experience_id"], retained, source["source_experience_id"], source["source_version"],
                            source["purpose"], source["content_sha256"]))
                    for link in links:
                        versions = [conn.execute("SELECT max(version) FROM experience_versions WHERE experience_id=? AND version<=?",
                                    (link[key], link["revision"])).fetchone()[0] for key in ("experience_id", "target_id")]
                        if None in versions:
                            raise StoreError("link history is not retained; cannot bind its historical endpoints")
                        conn.execute("INSERT INTO experience_links VALUES (?,?,?,?,?,?,?,?,?)", (
                            link["id"], link["experience_id"], link["target_id"], *versions,
                            link["relation"], link["conditions"], link["rationale"], link["revision"]))
                    conn.executemany("INSERT INTO experience_link_events VALUES (?,?,?,?,?,?)", events)
                if before["schema_version"] < 14 and version >= 14:
                    for statement in _EXPERIENCE_MATERIAL_SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                if before["schema_version"] < 15 and version >= 15:
                    for statement in _EXPERIENCE_CONDITION_SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                if before["schema_version"] < 16 and version >= 16:
                    for statement in _EXPERIENCE_EXTERNAL_SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                if before["schema_version"] == 16 and version >= 17:
                    for table in ("experience_claim_external_sources", "experience_external_sources"):
                        conn.execute(f"ALTER TABLE {table} RENAME TO {table}_v16")
                    for statement in _EXPERIENCE_EXTERNAL_SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                    for table in ("experience_external_sources", "experience_claim_external_sources"):
                        conn.execute(f"INSERT INTO {table} SELECT * FROM {table}_v16")
                    for table in ("experience_claim_external_sources", "experience_external_sources"):
                        conn.execute(f"DROP TABLE {table}_v16")
                if before["schema_version"] < 18 and version >= 18:
                    for statement in _FINDING_DISPOSITION_SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
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
    upgrade_all = subparsers.add_parser("upgrade-schema", help="explicit supported-schema upgrade with backup")
    upgrade_all.add_argument("--target", required=True)
    upgrade_all.add_argument("--backup", required=True, help="new absolute backup path outside target state")
    upgrade_all.add_argument("--repo-root", default="", help="repository root (defaults to this checkout)")
    findings = subparsers.add_parser("findings", help="read a Finding page or expand one ID")
    selection = findings.add_mutually_exclusive_group()
    selection.add_argument("--id", default=None)
    selection.add_argument("--cursor", default=None)
    findings.add_argument("--limit", type=int, default=10)
    findings.add_argument("--status", choices=FINDING_DISPOSITIONS,
                          help="filter before paging; omitted includes withdrawn history")
    case = subparsers.add_parser("case", help="read full Case context without raw private material")
    create_finding = subparsers.add_parser(
        "create-finding",
        help="persist an unassessed Candidate claim; no execution evidence or verdict is invented")
    create_finding.add_argument("--finding-id", required=True)
    create_finding.add_argument("--endpoint", required=True)
    create_finding.add_argument("--method", required=True)
    create_finding.add_argument("--family", required=True)
    create_finding.add_argument("--title", required=True)
    create_finding.add_argument("--claim", required=True)
    create_finding.add_argument("--actor", default="operator")
    create_finding.add_argument("--command-id", default="",
                                help="idempotency key; defaults to create-finding:<finding-id>")
    dispose = subparsers.add_parser("dispose-finding", help="withdraw or reopen an unbound Candidate, preserving its history")
    dispose.add_argument("--finding-id", required=True)
    dispose.add_argument("--status", choices=FINDING_DISPOSITIONS, required=True)
    dispose.add_argument("--reason", required=True)
    dispose.add_argument("--replacement-id", default=None, help="existing active Finding that replaces the mistaken claim")
    dispose.add_argument("--expected-disposition", default=None, help="exact preceding disposition ID; omit only for the first withdrawal")
    dispose.add_argument("--command-id", required=True, help="stable idempotency key for this disposition")
    dispose.add_argument("--actor", default="operator")
    for query in (findings, case, create_finding, dispose):
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
            elif args.command == "create-finding":
                result = store.create_finding(
                    command_id=args.command_id or f"create-finding:{args.finding_id}",
                    finding_id=args.finding_id, endpoint=args.endpoint, method=args.method,
                    family=args.family, title=args.title, claim=args.claim, actor=args.actor)
            elif args.command == "dispose-finding":
                result = store.dispose_finding(
                    command_id=args.command_id, finding_id=args.finding_id, status=args.status,
                    reason=args.reason, actor=args.actor, replacement_id=args.replacement_id,
                    expected_disposition=args.expected_disposition)
            else:
                if args.id is not None and args.status is not None:
                    raise StoreError("--status filters pages; omit it when expanding --id")
                result = (store.finding(args.id) if args.id is not None else
                          store.finding_page(limit=args.limit, cursor=args.cursor, status=args.status))
    except (OSError, StoreError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the CLI
    raise SystemExit(_main())
