"""Import legacy target metadata into an isolated :class:`TargetStore`.

The importer is deliberately explicit: it never writes a live legacy target,
never guesses ambiguous links, and reports every skipped record.  Two legacy
facts are imported without promotion:

* ``action_queue.json`` records whose status maps unambiguously onto the one
  action source; historical terminal statuses stay quarantined because the new
  model only accepts a terminal action that was earned by a bound execution.
* ``ledger.jsonl`` entries become observations with their raw artifact hash;
  a finding is imported as a claim only when one entry matches its exact
  endpoint/method/family, so no link is invented by text similarity.
* ``case_state.json`` is context memory, not an action owner: its actor/session/
  object/hypothesis counts are reported, and its legacy ``validation_backlog``
  records are carried as verdicts plus the explicit-id relations to the one
  action source.  A record is never merged by endpoint/family text similarity,
  and the verdict conflict that Case used to arbitrate against the canonical
  finding owner is reported here instead.

Legacy verdicts (queue statuses, ledger results, finding validation/report
states) are preserved in the report for acceptance comparison instead of being
silently upgraded into assessments.

The report also carries the failure classes data recovery has to survive:
corrupt JSON/JSONL (structured row entries), a record that declares another
target (imported by nobody), provenance that was committed without its raw
material and raw material that has no provenance (both listed, neither
invented), private/secret references (never hashed into the store) and fields
the importer would otherwise drop without a trace.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from memory.schemas import SchemaError, validate_pattern_entry
from memory.target_profile import load_target_profile, target_profile_path
from tools.scope_context import read_scope_source, scope_source_path, write_scope_source_locked
from tools.scope_source import scope_source_from_profile

try:
    from tools.artifact_io import write_json_atomic
    from tools.action_queue import load_legacy_queue
    from tools.evidence_identity import LEDGER_RESULTS, canonical_endpoint_identity
    from tools.evidence_ledger import load_entries_diagnostic
    from tools.finding_index import load_legacy_finding_index, verify_finalized_finding_owner_provenance
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.target_memory import normalize_target_memory, text_is_polluted
    from tools.target_store import StoreError, TargetStore, target_cutover_lock
except ImportError:  # pragma: no cover
    from artifact_io import write_json_atomic
    from action_queue import load_legacy_queue  # type: ignore
    from evidence_identity import LEDGER_RESULTS, canonical_endpoint_identity  # type: ignore
    from evidence_ledger import load_entries_diagnostic  # type: ignore
    from finding_index import (  # type: ignore
        load_legacy_finding_index,
        verify_finalized_finding_owner_provenance,
    )
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from target_memory import normalize_target_memory, text_is_polluted  # type: ignore
    from target_store import StoreError, TargetStore, target_cutover_lock  # type: ignore


# Only one legacy status survives the move into the single action source:
# ``queued`` is genuinely open work.  Everything else is a terminal legacy
# verdict -- ``tested``/``validated``/``reported`` assert an execution the new
# model only accepts with a bound attempt, and ``dead-end``/``n/a`` are
# results, not decisions.  Writing them as ``completed`` would fabricate
# verification; writing them as ``cancelled`` would fabricate an operator
# decision.  They stay quarantined with the verdict preserved in the report.
_OPEN_ACTION_STATUSES = frozenset({"queued"})

# Field vocabulary per legacy owner: the fields the importer maps plus every
# field the current legacy writers emit.  Anything outside the set is reported
# in ``legacy.unknown_fields`` -- silently dropped schema drift is exactly what
# the dry-run has to make visible.  ``metadata`` is excluded on purpose: it is
# an open bag by the legacy owner's own contract.
_QUEUE_ITEM_FIELDS = frozenset({
    "action", "attempts", "command_hint", "created_at", "dedupe_key", "endpoint", "evidence",
    "evidence_type", "family", "id", "metadata", "next_question", "notes", "priority",
    "redline_required", "result", "safety", "schema_version", "source", "source_id", "status",
    "stop_condition", "target", "title", "type", "updated_at", "vuln_class",
})
_MIGRATABLE_ACTION_METADATA = frozenset({
    "activation_required", "active_dimension", "actor", "expected_learning", "hypothesis_id",
    "input_boundary", "kill_condition", "max_hypothesis_actions", "max_hypothesis_actions_cap",
    "method", "object_scope", "risk_tier", "technique", "workflow",
})
_FINDING_FIELDS = frozenset({
    "category", "claim_id", "claim_revision", "claim_source_file", "claim_sources", "claim_status",
    "claim_target", "claimed_report_status", "claimed_severity", "confidence", "evidence_rubric",
    "id", "incomplete_fields", "line_number", "method", "owner_provenance", "queue_sync", "raw",
    "report_file", "report_id", "report_path", "report_status", "runner_operation_id",
    "runner_summary_path", "severity", "source_file", "summary", "template_id", "title", "type",
    "updated_at", "url", "validated_at", "validation_report_path", "validation_status",
    "validation_summary", "validation_summary_sha256", "vuln_class",
})
_LEDGER_FIELDS = frozenset({
    "actor", "browser_observed", "endpoint", "error", "event_id", "evidence_ref", "family",
    "method", "notes", "object_scope", "operation_id", "raw_endpoint", "redline_checked",
    "redline_decision", "replayed", "result", "schema_version", "source", "state_changing",
    "target", "target_key", "truncated", "ts", "variant", "vuln_class", "warnings", "workflow",
})
# Case 侧字段表覆盖旧 owner 写过的全部字段（``add_backlog`` 的完整入参加上
# ``complete_backlog`` 写回的终态字段）。Case 已不拥有这张形状，导入器既不归一化
# 它，也不替它拒绝；只把表外字段报出来，让 schema 漂移可见。
_CASE_STATE_FIELDS = frozenset({
    "actors", "created_at", "hypotheses", "objects", "schema_version", "sessions", "target",
    "target_key", "updated_at", "validation_backlog",
})
_CASE_BACKLOG_FIELDS = frozenset({
    "active_dimension", "baseline_url", "baseline_value", "chain_extensions_if_blocked",
    "classifier", "command_hint", "completed_at", "created_at", "endpoint", "evidence_ref",
    "expect_marker", "family", "finding_id", "hypothesis_id", "id", "intent", "metadata",
    "method", "notes", "object_ref", "owner_actor", "param", "peer_actor", "priority",
    "readiness", "recovery_next_action", "request_spec_ref", "required_evidence", "runner",
    "status", "stop_condition", "target", "updated_at", "variant_value", "vuln_class",
})
# ``tested_clean``/``dead_end`` 是 Case 侧唯一的"关闭"裁决：只有它们才可能和
# canonical finding owner 的终态 claim 冲突。
_CASE_CLEAN_VERDICTS = frozenset({"tested_clean", "dead_end"})
# 旧 runner → 家族：Case 记录没有 vuln_class 时，用它恢复家族身份；表外 runner
# 一律留空，不猜家族。
_CASE_RUNNER_FAMILIES = {
    "authz-public-exposure": "Authz",
    "authz-role-replay": "Authz",
    "idor-actor-pair": "IDOR",
    "marker-replay": "RCE",
    "request-diff": "Authz",
}

# The legacy owner refuses these metadata keys at write time; a file that still
# carries one predates that guard or was edited by hand.  The values are never
# copied anywhere -- the report lists key paths only.
_SENSITIVE_METADATA_KEYS = frozenset({
    "access_token", "api_key", "authorization", "bearer", "client_secret", "cookie",
    "credential", "credentials", "csrf_token", "header_value", "headers", "id_token",
    "password", "private_key", "private_marker", "refresh_token", "secret", "secret_value",
    "session_cookie", "set_cookie",
})

# ``.private`` subtrees that are not target validation material (browser
# storage, spray results, case state).  The store itself refuses refs outside
# ``.private/validation/<key>``; the importer names the reason instead of
# relaying a generic StoreError, and never hashes the file.
_PRIVATE_EVIDENCE_SUBTREE = (".private", "validation")

# High-specificity credential shapes only: a literal bearer token, a JWT, or a
# PEM private key.  Prose such as "owner Bearer replay returns 200" must not
# match -- this text is checked against the live ledger before being trusted.
_LIVE_CREDENTIAL_PATTERNS = (
    re.compile(r"bearer\s+[A-Za-z0-9._-]{20,}", re.I),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\."),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
)

# File names that point at credential material.  Reported for review, not
# quarantined: the store records only ref/sha256/size, and dropping a real
# observation over its evidence file name would lose raw material.
_SECRET_FILE_PATTERN = re.compile(
    r"(^\.env|\.pem$|\.p12$|\.pfx$|\.key$|^id_rsa|^id_ed25519|credential|secret|token|password)",
    re.I,
)

# These are the legacy domain owners that are replaced by TargetStore at
# cutover.  Raw evidence, reports, private material, runtime/session state and
# lock files stay live; only these files are archived and later restorable.
_LEGACY_METADATA_PATHS = (
    ("state/{key}/action_queue.json", "state/action_queue.json"),
    ("state/{key}/case_state.json", "state/case_state.json"),
    ("state/{key}/unsafe_skipped_reviews.json", "state/unsafe_skipped_reviews.json"),
    ("findings/{key}/findings.json", "findings/findings.json"),
    ("findings/{key}/mutation-events.jsonl", "findings/mutation-events.jsonl"),
    ("memory/evidence/{key}/ledger.jsonl", "memory/evidence/ledger.jsonl"),
    ("memory/goals/targets/{key}.json", "memory/goals/targets.json"),
)

_CASE_CONTEXT_PRIVATE_ROOT = ".private/case-state/{key}"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _endpoint(item: dict[str, Any], origin: str) -> str:
    """Absolute endpoint, or "" when a path has no unambiguous origin.

    Legacy path-form endpoints are resolved against the origin observed in the
    target's own evidence; no scheme is invented when that origin is absent or
    more than one origin was observed.
    """
    value = _text(item.get("endpoint") or item.get("url"))
    if value.startswith("/"):
        return f"{origin}{value}" if origin else ""
    return value


def _origin(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""


def _family(item: dict[str, Any]) -> str:
    return _text(item.get("family") or item.get("vuln_class") or item.get("type"))


def _stable_id(*parts: Any) -> str:
    material = "\x1f".join(_text(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


# Quarantine identity is a bounded hash of the reported facts only; report
# position is never part of it, so reordering the report cannot change an ID.
_QUARANTINE_ID_FIELDS = (
    "owner", "reason", "path", "event_id", "id", "endpoint", "evidence_ref",
    "line", "status", "family", "result", "declared_target", "expected_target",
)
# A terminal disposition closes one quarantine item and may clear the gate.
_TERMINAL_DISPOSITION_DECISIONS = frozenset({
    "preserve_verdict", "permanent_quarantine",
})
# Recorded but unfinished intents keep the item open and the gate shut:
# `rebind_after_export_verification` commits to re-registering evidence that is
# still missing, and `operator_review` asks a human to look again.  Neither is a
# completed decision, so neither may unlock publish.
_OPEN_DISPOSITION_DECISIONS = frozenset({
    "rebind_after_export_verification", "operator_review",
})
_DISPOSITION_DECISIONS = _TERMINAL_DISPOSITION_DECISIONS | _OPEN_DISPOSITION_DECISIONS
_PLACEHOLDER_DECISION_REFS = frozenset({"", "pending", "todo", "tbd", "none", "null"})


def _quarantine_material(row: dict[str, Any]) -> str:
    bounded = {field: row.get(field, "") for field in _QUARANTINE_ID_FIELDS}
    return json.dumps(bounded, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def quarantine_id(row: dict[str, Any]) -> str:
    """Return the stable ID used by a migration disposition ledger."""
    return hashlib.sha256(_quarantine_material(row).encode("utf-8")).hexdigest()[:16]


def quarantine_identities(rows: list[dict[str, Any]]) -> list[str]:
    """Identity for each row, independent of where it appears in the report.

    Rows that agree on every bounded field are interchangeable, so the n-th copy
    is identified by its occurrence count inside that identical group rather than
    by its report position.  Permuting the report therefore leaves the identity
    set unchanged, while a changed fact still changes the identity.
    """
    seen: dict[str, int] = {}
    identities: list[str] = []
    for row in rows:
        material = _quarantine_material(row)
        occurrence = seen.get(material, 0)
        seen[material] = occurrence + 1
        if occurrence:
            material = f"{material}\x1f{occurrence}"
        identities.append(hashlib.sha256(material.encode("utf-8")).hexdigest()[:16])
    return identities


def quarantine_roster(rows: list[dict[str, Any]]) -> tuple[list[str], str]:
    """Return the identity list and a digest that binds a decision table to it.

    The digest covers the complete quarantine roster, not the decided subset, so
    a ledger generated for one report cannot be re-bound to a different report
    that happens to share some identities.
    """
    identities = quarantine_identities(rows)
    material = json.dumps(sorted(identities), ensure_ascii=True, separators=(",", ":"))
    return identities, hashlib.sha256(material.encode("utf-8")).hexdigest()


def _load_disposition_ledger(value: Any) -> tuple[dict[str, Any] | None, str]:
    """Load a disposition ledger from a path or an already parsed object."""
    if value in (None, ""):
        return None, ""
    if isinstance(value, dict):
        payload = value
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    else:
        path = Path(value)
        try:
            encoded = path.read_text(encoding="utf-8")
            payload = json.loads(encoded)
        except (OSError, ValueError, TypeError) as exc:
            raise StoreError(f"disposition ledger is unreadable: {path}") from exc
    if not isinstance(payload, dict):
        raise StoreError("disposition ledger must be a JSON object")
    items = payload.get("items")
    if not isinstance(items, list):
        raise StoreError("disposition ledger items must be a list")
    return payload, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _apply_disposition_ledger(
    report: dict[str, Any],
    ledger: dict[str, Any] | None,
    ledger_digest: str,
    canonical: str,
    source_manifest_sha256: str,
) -> None:
    """Validate and apply fact-preserving quarantine decisions."""
    if ledger is None:
        return
    _validate_disposition_binding(ledger, canonical, source_manifest_sha256)
    _validate_disposition_ledger_shape(ledger)

    expected_rows = [dict(row) for row in (report.get("quarantined") or [])]
    expected_ids, roster_digest = quarantine_roster(expected_rows)
    # The roster digest binds this decision table to the exact quarantine set it
    # was generated for.  Without it, a ledger written for one report could be
    # re-bound to another input that happens to share identities.
    declared_roster = _text(ledger.get("quarantine_roster_sha256"))
    if declared_roster and declared_roster != roster_digest:
        raise StoreError("disposition ledger quarantine roster does not match migration input")
    group_of: dict[str, str] = {}
    for row, item_id in zip(expected_rows, expected_ids):
        group_of[item_id] = quarantine_id(row)
    if len(set(expected_ids)) != len(expected_ids):
        raise StoreError("migration produced duplicate quarantine IDs")

    seen: set[str] = set()
    decisions: dict[str, str] = {}
    validated: list[dict[str, Any]] = []
    for item in ledger.get("items", []):
        if not isinstance(item, dict):
            raise StoreError("disposition ledger item must be an object")
        item_id = _text(item.get("quarantine_id"))
        if not item_id or item_id in seen:
            raise StoreError("disposition ledger contains a missing or duplicate quarantine ID")
        if item_id not in group_of:
            raise StoreError(f"disposition ledger references unknown quarantine ID: {item_id}")
        if quarantine_id(item) != group_of[item_id]:
            raise StoreError(f"disposition ledger row does not match quarantine ID: {item_id}")
        decision = _text(item.get("decision")).lower()
        if decision not in _DISPOSITION_DECISIONS:
            raise StoreError(f"unsupported quarantine disposition: {decision or '<empty>'}")
        operator = _text(item.get("operator"))
        if operator.lower() in _PLACEHOLDER_DECISION_REFS:
            raise StoreError("quarantine disposition requires a non-placeholder operator")
        decision_ref = _text(item.get("decision_ref"))
        if decision_ref.lower() in _PLACEHOLDER_DECISION_REFS:
            raise StoreError("quarantine disposition requires a non-placeholder decision_ref")
        allowed = item.get("allowed_decisions")
        if allowed is not None and not isinstance(allowed, list):
            raise StoreError(f"quarantine disposition allowed_decisions must be a list: {item_id}")
        if isinstance(allowed, list) and allowed and decision not in {str(value).strip().lower() for value in allowed}:
            raise StoreError(f"quarantine disposition is not allowed for {item_id}: {decision}")
        seen.add(item_id)
        decisions[item_id] = decision
        validated.append({**item, "quarantine_id": item_id, "decision": decision})

    missing = sorted(set(expected_ids) - seen)
    # Rows the ledger never decided, plus rows whose only decision was a
    # non-terminal `operator_review`, remain quarantined and keep the gate shut.
    open_rows = [
        {**row, "identity": item_id, "recorded_decision": decisions.get(item_id, "")}
        for row, item_id in zip(expected_rows, expected_ids)
        if decisions.get(item_id) not in _TERMINAL_DISPOSITION_DECISIONS
    ]
    metadata = {
        "target": canonical,
        "source_manifest_sha256": source_manifest_sha256,
        "ledger_sha256": ledger_digest,
        "quarantine_roster_sha256": roster_digest,
        "count": len(validated),
        "missing": missing,
        "open": [row["identity"] for row in open_rows],
        "status": "complete" if not missing and not open_rows else "partial",
    }
    report["disposition_ledger"] = metadata
    report["dispositioned_quarantine"] = [
        row for row in validated if row["decision"] in _TERMINAL_DISPOSITION_DECISIONS
    ]
    # `operator_review` is a recorded human-review request, not a decision that
    # closes the item, so those rows stay quarantined and keep the gate closed.
    report["quarantined"] = open_rows
    if metadata["status"] == "complete":
        report["status"] = "ready"


def _validate_disposition_ledger_shape(ledger: dict[str, Any]) -> None:
    """Reject a ledger that contradicts its own governance metadata.

    A payload that declares the cutover ledger format must also satisfy it:
    a declared `kind` requires a finalized `status` and an accurate `count`.
    Bare decision payloads without `kind` stay usable for narrow callers.
    """
    kind = _text(ledger.get("kind"))
    if kind and kind != "target_cutover_quarantine_disposition_ledger":
        raise StoreError(f"unexpected disposition ledger kind: {kind}")
    declared_count = ledger.get("count")
    if declared_count is not None and int(declared_count) != len(ledger.get("items") or []):
        raise StoreError(
            "disposition ledger count does not match its items: "
            f"{declared_count} != {len(ledger.get('items') or [])}"
        )
    if not kind and "status" not in ledger:
        return
    declared_status = _text(ledger.get("status")).lower()
    if declared_status in _PLACEHOLDER_DECISION_REFS:
        raise StoreError(
            "disposition ledger is not finalized; every item requires an explicit "
            f"operator decision (status={declared_status or '<empty>'})"
        )


def _validate_disposition_binding(
    ledger: dict[str, Any] | None,
    canonical: str,
    source_manifest_sha256: str,
    quarantine_roster_sha256: str = "",
) -> None:
    if ledger is None:
        return
    if _text(ledger.get("target")) != canonical:
        raise StoreError("disposition ledger target does not match migration target")
    if _text(ledger.get("source_manifest_sha256")) != source_manifest_sha256:
        raise StoreError("disposition ledger source manifest does not match migration input")
    declared_roster = _text(ledger.get("quarantine_roster_sha256"))
    if declared_roster and quarantine_roster_sha256 and declared_roster != quarantine_roster_sha256:
        raise StoreError("disposition ledger quarantine roster does not match migration input")


_SOURCE_ROOT_DIGEST_PREFIX = "source-root:"


def _rebase_source_absolute_ref(source_root: Path, copy_root: Path, ref: str) -> tuple[str, str]:
    """Rebase a legacy absolute reference onto the migration copy.

    Legacy writers recorded absolute paths (``/root/.../<repo>/evidence/...``)
    because the operator ran in that directory.  The migration contract allows
    resolving an absolute path only after its source ownership is confirmed, so
    the reference is first proven to resolve under ``source_root`` (the
    directory it was authored in) and is then expressed relative to
    ``copy_root``.  The caller accepts the result only if the same relative path
    material actually exists inside the copy, so a rewritten reference can never
    point outside the isolated root.

    Returns ``(rewritten_ref, "")`` on success and ``("", reason)`` otherwise.
    Nothing is guessed: a reference that is not absolute, cannot be resolved,
    does not resolve under the declared source root, or does not exist in the
    copy is rejected exactly as before.
    """
    path = Path(ref)
    if not path.is_absolute():
        return "", "reference is not absolute"
    try:
        resolved = path.resolve()
    except OSError:
        return "", f"absolute reference cannot be resolved: {ref}"
    if not resolved.is_relative_to(source_root):
        return "", f"absolute reference is outside the declared migration source root: {ref}"
    relative = resolved.relative_to(source_root).as_posix()
    if _escapes_root(copy_root, relative):
        return "", f"rebase result escapes the migration copy: {ref}"
    if not _evidence_readable(copy_root, relative):
        return "", f"rebased reference has no material in the migration copy: {relative}"
    return relative, ""


def _rebase_notice(root: Path, original: str, rewritten: str) -> dict[str, str]:
    """Bounded record of a rebase, so the rewrite is auditable and not silent."""
    return {
        "kind": "absolute_reference_rebased",
        "source_root_digest": _SOURCE_ROOT_DIGEST_PREFIX + hashlib.sha256(
            str(root).encode("utf-8")).hexdigest()[:16],
        "original": original,
        "rebased": rewritten,
    }


def _evidence_path(root: Path, ref: str) -> Path:
    path = Path(ref)
    return path if path.is_absolute() else root / path


def _escapes_root(root: Path, ref: str) -> bool:
    try:
        return not _evidence_path(root, ref).resolve().is_relative_to(root)
    except OSError:
        return True


def _unbindable_reason(root: Path, ref: str) -> str:
    """Explain why a raw reference cannot be registered from this copy."""
    if _escapes_root(root, ref):
        return f"evidence reference is outside the isolated copy and is not reinterpreted: {ref}"
    return f"raw evidence is missing or empty: {ref}"


def _evidence_readable(root: Path, ref: str) -> bool:
    try:
        stat = _evidence_path(root, ref).stat()
    except OSError:
        return False
    return stat.st_size > 0


def _scan_unknown_fields(rows: list[Any], known: frozenset[str]) -> dict[str, int]:
    """Count fields outside the legacy owner's vocabulary, per field name."""
    unknown: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in row.keys() - known:
            unknown[str(field)] = unknown.get(str(field), 0) + 1
    return dict(sorted(unknown.items()))


def _sensitive_metadata_paths(value: Any, prefix: str = "metadata") -> list[str]:
    """Key paths of legacy-sensitive metadata; values are deliberately not read."""
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            path = f"{prefix}.{key}"
            if normalized in _SENSITIVE_METADATA_KEYS and child not in (None, "", [], {}):
                paths.append(path)
            paths.extend(_sensitive_metadata_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_sensitive_metadata_paths(child, f"{prefix}[{index}]"))
    return paths


def _live_credential_reason(text: str) -> str:
    if not text:
        return ""
    for pattern in _LIVE_CREDENTIAL_PATTERNS:
        if pattern.search(text):
            return ("free-text notes carry apparent live credential material; "
                    "it is never copied into the store")
    return ""


def _private_ref_reason(root: Path, key: str, ref: str) -> str:
    """Reason for a reference into ``.private`` material the store refuses."""
    if _escapes_root(root, ref):
        return ""
    path = _evidence_path(root, ref).resolve()
    private_root = (root / ".private").resolve()
    if not path.is_relative_to(private_root):
        return ""
    allowed = private_root.joinpath(*_PRIVATE_EVIDENCE_SUBTREE, key)
    if path.is_relative_to(allowed):
        return ""
    return f"private secret material is referenced and never copied into the store: {ref}"


def _secret_file_ref(ref: str) -> bool:
    return bool(_SECRET_FILE_PATTERN.search(Path(ref).name))


def _unread_tail_rows(path: str, offset: int) -> int:
    """Rows after the trusted prefix; they are counted, never parsed.

    Returns -1 when the tail cannot be read at all, so the report never claims
    a count it did not observe.
    """
    try:
        with Path(path).open("rb") as handle:
            handle.seek(max(int(offset), 0))
            return sum(1 for line in handle if line.strip())
    except (OSError, ValueError):
        return -1


def _unreferenced_material(root: Path, key: str, refs: set[str]) -> dict[str, Any]:
    """Raw files under this target's material roots that no ledger row names.

    The mirror image of a half-committed write: the runner published a file but
    the provenance row never landed (or vice versa).  Read-only: nothing is
    deleted, altered or imported -- the counts and bounded samples go into the
    report so the acceptance review sees the gap.  A file is also counted as
    ``without_referenced_neighbour`` when not even its directory is named by a
    provenance row, which is the strictly orphaned class.
    """
    roots = [root / "evidence" / key, root / ".private" / "validation" / key]
    referenced = {str(_evidence_path(root, ref).resolve()) for ref in refs if ref}
    referenced_dirs = {str(Path(item).parent) for item in referenced}
    count = 0
    isolated = 0
    sample: list[str] = []
    isolated_sample: list[str] = []
    for material_root in roots:
        if not material_root.is_dir():
            continue
        for path in sorted(material_root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            resolved = path.resolve()
            if str(resolved) in referenced:
                continue
            relative = path.relative_to(root).as_posix()
            count += 1
            if len(sample) < 20:
                sample.append(relative)
            if str(resolved.parent) not in referenced_dirs:
                isolated += 1
                if len(isolated_sample) < 20:
                    isolated_sample.append(relative)
    return {
        "count": count,
        "sample": sample,
        "without_referenced_neighbour": isolated,
        "without_referenced_neighbour_sample": isolated_sample,
    }


def _carried_identity_dimensions(entry: dict[str, Any]) -> dict[str, str]:
    """Carry the record's own identity dimensions; never a rebuilt identity.

    A complete record carries its key's dimensions.  A record the identity
    contract judged incomplete or conflicted carries the raw dimensions it was
    submitted with, so the shared derivation re-adjudicates the same facts and
    reaches the same verdict.  Nothing is filled in from actor/object_scope
    aliases: rebuilding a partial identity would close a cell the old system
    refused to close, which is laundering.
    """
    payload = (
        entry.get("identity_v2")
        if _text(entry.get("identity_status")) == "complete"
        else None
    )
    source = payload.get("dimensions") if isinstance(payload, dict) else entry.get("identity_dimensions")
    if not isinstance(source, dict):
        return {}
    return {str(key): str(value) for key, value in source.items() if str(value).strip()}


def _ledger_observation(entry: dict[str, Any], origin: str,
                        rebase_root: Path | None = None,
                        copy_root: Path | None = None) -> tuple[dict[str, Any] | None, str]:
    """Map one ledger entry onto the execution-observation contract.

    Every field comes from the raw record; nothing is inferred from the
    entry's verdict.  The verdict itself is carried as the record authored it
    (in the vocabulary the Ledger and Closure share), and the identity
    dimensions the record itself declared -- complete or partial -- so the
    shared derivation re-adjudicates them instead of this import judging them.

    A legacy absolute ``evidence_ref`` is rebased onto the migration source root
    when it provably resolves under it; anything not proven stays rejected.
    """
    endpoint = _text(entry.get("raw_endpoint")) or _text(entry.get("endpoint"))
    if endpoint.startswith("/"):
        endpoint = f"{origin}{endpoint}" if origin else ""
    if not endpoint.startswith(("http://", "https://")):
        return None, "ledger entry has no absolute observed endpoint"
    method = _text(entry.get("method")).upper()
    if not method:
        return None, "ledger entry has no recorded method"
    family = _text(entry.get("vuln_class") or entry.get("family"))
    if not family:
        return None, "ledger entry has no observed family"
    observed_at = _text(entry.get("ts"))
    if not observed_at:
        return None, "ledger entry has no observed timestamp"
    ref = _text(entry.get("evidence_ref"))
    if not ref:
        return None, "ledger entry has no raw evidence reference"
    if rebase_root is not None and copy_root is not None and Path(ref).is_absolute():
        rebased, rebase_reason = _rebase_source_absolute_ref(rebase_root, copy_root, ref)
        if not rebased:
            return None, rebase_reason
        ref = rebased
    reason = _live_credential_reason(_text(entry.get("notes")))
    if reason:
        return None, reason
    raw_result = _text(entry.get("result"))
    result = raw_result if raw_result in LEDGER_RESULTS else ""
    dimensions = _carried_identity_dimensions(entry)
    identity_status = _text(entry.get("identity_status")) or "none"
    identity_v2 = entry.get("identity_v2") if isinstance(entry.get("identity_v2"), dict) else {}
    identity_technique = _text(entry.get("identity_technique"))
    role = _text(entry.get("evidence_role")) or "unknown"
    if identity_status == "complete" and (not identity_technique or not identity_v2 or role != "subject"):
        identity_status = "incomplete"
    return {
        "endpoint": endpoint,
        "method": method,
        "family": family,
        "observed_at": observed_at,
        "description": _text(entry.get("notes")) or f"legacy ledger result={raw_result or 'unknown'}",
        "actor": _text(entry.get("actor")) or "legacy",
        "object_scope": _text(entry.get("object_scope")) or "none",
        "variant": _text(entry.get("variant")) or "legacy",
        "error": _text(entry.get("error")),
        "truncated": bool(entry.get("truncated")),
        "state_changing": entry.get("state_changing"),
        "redline_checked": bool(entry.get("redline_checked")),
        "result": result,
        "detail": {"evidence_role": role},
        "identity_status": identity_status,
        "identity_technique": identity_technique,
        "identity_v2": identity_v2,
        "identity_dimensions": dimensions,
        "artifacts": {"evidence": ref},
    }, ""


def _count_identity_carry(report: dict[str, Any], entry: dict[str, Any], observation: dict[str, Any]) -> None:
    """Report what identity facts an imported record carried into the store."""
    carry = report["legacy"]["identity_carry"]
    status = _text(entry.get("identity_status"))
    if status == "complete":
        carry["records_with_complete_identity"] += 1
    elif status:
        carry["partial_identities_carried"] += 1
    if observation["result"]:
        carry["results_carried"] += 1
    elif _text(entry.get("result")):
        carry["results_outside_shared_vocabulary"] += 1


def _count_uncarryable_claim(report: dict[str, Any], entry: dict[str, Any]) -> None:
    """Count an identity claim the store cannot represent without inventing facts."""
    if _text(entry.get("identity_status")) and not _carried_identity_dimensions(entry):
        report["legacy"]["identity_carry"]["uncarryable_identity_claims"] += 1


def _observation_key(observation: dict[str, Any]) -> tuple[str, str, str]:
    return (observation["endpoint"], observation["method"], observation["family"])


def _finding_key(finding: dict[str, Any], target: str) -> tuple[str, str, str]:
    return (
        _text(finding.get("url") or finding.get("source_url")) or _endpoint(finding, target),
        _text(finding.get("method")).upper(),
        _text(finding.get("vuln_class") or finding.get("type") or finding.get("category")),
    )


def _legacy_verdicts(report: dict[str, Any], finding: dict[str, Any]) -> None:
    report["legacy"]["finding_verdicts"].append({
        "id": _text(finding.get("id")),
        "validation_status": _text(finding.get("validation_status")),
        "report_status": _text(finding.get("report_status")),
        "claim_status": _text(finding.get("claim_status")),
        "confidence": _text(finding.get("confidence")),
        "severity": _text(finding.get("severity")),
        "claim_revision": _text(finding.get("claim_revision")),
        "source_file": _text(finding.get("source_file") or finding.get("claim_source_file")),
    })


def _load_case_state(repo_root: Path, target: str) -> dict[str, Any]:
    """Read the legacy Case file as migration material only.

    Case 已不拥有待办与行动，所以这里既不校验它的形状，也不归一化它：读不出来、
    不是对象、或声明了别的 target，都作为迁移事实上报，由调用方隔离。
    """
    key = target_storage_key(target)
    path = repo_root / "state" / key / "case_state.json"
    result: dict[str, Any] = {
        "path": str(path), "exists": path.is_file(), "payload": {}, "error": "", "declared_target": "",
    }
    if not result["exists"]:
        return result
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result["error"] = " ".join(str(exc).split())[:300]
        return result
    if not isinstance(payload, dict):
        result["error"] = "case state is not a JSON object"
        return result
    result["payload"] = payload
    result["declared_target"] = _text(payload.get("target") or payload.get("target_key"))
    return result


def _legacy_sources(repo_root: Path, target: str) -> dict[str, Any]:
    key = target_storage_key(target)
    queue_path = repo_root / "state" / key / "action_queue.json"
    findings_path = repo_root / "findings" / key / "findings.json"
    ledger = load_entries_diagnostic(repo_root, target)
    case_state = _load_case_state(repo_root, target)
    reports_path = repo_root / "reports" / key
    try:
        queue = load_legacy_queue(repo_root, target)
    except (OSError, ValueError) as exc:
        queue = {"actions": [], "error": str(exc)}
    try:
        findings = load_legacy_finding_index(repo_root / "findings" / key, target=target)
    except (OSError, ValueError) as exc:
        findings = {"findings": [], "error": str(exc)}
    return {
        "queue": queue,
        "findings": findings,
        "ledger": ledger,
        "case_state": case_state,
        "paths": {
            "queue": str(queue_path),
            "findings": str(findings_path),
            "ledger": ledger["path"],
            "case_state": case_state["path"],
            "reports": str(reports_path),
        },
        "reports_path": reports_path,
    }


def _target_memory_disposition(root: Path, canonical: str) -> dict[str, Any]:
    """Describe legacy target-memory retention without inventing Store facts."""
    key = target_storage_key(canonical)
    path = root / "memory" / "goals" / "targets" / f"{key}.json"
    result: dict[str, Any] = {
        "path": str(path),
        "status": "missing",
        "target": canonical,
        "fields": {},
        "entries": 0,
        "disposition": "no legacy target-memory file was present",
    }
    if not path.exists():
        return result
    if path.is_symlink() or not path.is_file():
        result.update({
            "status": "quarantined",
            "disposition": "target-memory path is not a regular file; retained for diagnosis",
        })
        return result
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result.update({
            "status": "quarantined",
            "disposition": "target-memory JSON is unreadable; retained for diagnosis",
            "error": " ".join(str(exc).split())[:240],
        })
        return result
    if not isinstance(payload, dict):
        result.update({
            "status": "quarantined",
            "disposition": "target-memory payload is not an object; retained for diagnosis",
        })
        return result
    declared = _text(payload.get("target"))
    try:
        wrong_target = bool(declared and canonical_target_value(declared) != canonical)
    except ValueError:
        wrong_target = True
    if wrong_target:
        result.update({
            "status": "quarantined",
            "declared_target": declared,
            "disposition": "target-memory declares another target; retained for explicit review",
        })
        return result
    try:
        payload = normalize_target_memory(payload, expected_target=canonical, path=path)
    except ValueError as exc:
        result.update({"status": "quarantined", "disposition": str(exc)[:240]})
        return result
    fields: dict[str, int] = {}
    for field in (
        "scope_notes", "active_leads", "dead_ends", "next_actions", "useful_patterns",
        "session_handoffs", "facts",
    ):
        value = payload.get(field)
        if isinstance(value, dict):
            count = len(value)
        elif isinstance(value, list):
            count = len(value)
        else:
            count = 0
        if count:
            fields[field] = count
    if payload["active_goal"].strip():
        fields["active_goal"] = 1
    total = sum(fields.values())
    result.update({
        "status": "valid",
        "fields": fields,
        "entries": total,
        "disposition": (
            "retained as source material; eligible entries require a manifest-bound Experience import"
        ) if total else "valid target-memory file contains no migratable entries",
    })
    return result


def _import_target_memory(report: dict[str, Any], store: TargetStore, root: Path,
                          canonical: str, manifest: dict[str, Any]) -> None:
    """Import historical advice without promoting unbound claims to evidence."""
    disposition = report["legacy"]["target_memory"]
    if disposition["status"] != "valid":
        return
    relative = f"memory/goals/targets/{target_storage_key(canonical)}.json"
    source = next((item for item in manifest["files"] if item["path"] == relative), None)
    if source is None:
        raise StoreError(f"target-memory source is absent from migration manifest: {relative}")
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise StoreError(f"target-memory source is not a regular file: {path}")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source["sha256"] or len(raw) != source["size"]:
        raise StoreError(f"target-memory source differs from migration manifest: {relative}")
    try:
        memory = normalize_target_memory(json.loads(raw), expected_target=canonical, path=path)
    except (ValueError, UnicodeError) as exc:
        disposition.update(status="quarantined", disposition=f"target-memory structure invalid: {exc}")
        report["quarantined"].append({"owner": "target-memory", "path": relative, "reason": str(exc)})
        return
    store.active_goal()  # A v8 target must be explicitly upgraded before the first imported row.

    rows = [(field, index, item) for field in (
        "scope_notes", "active_leads", "dead_ends", "next_actions", "useful_patterns", "session_handoffs"
    ) for index, item in enumerate(memory[field])]
    rows.extend(("facts", key, item) for key, item in sorted(memory["facts"].items()))
    if memory["active_goal"].strip():
        rows.append(("active_goal", "value", {"text": memory["active_goal"]}))
    mapped = []
    for field, position, item in rows:
        if len(str(position)) > 80:
            report["quarantined"].append({"owner": "target-memory", "path": relative,
                                          "field": field, "position": str(position)[:80],
                                          "reason": "historical source key is oversized"})
            continue
        declared = item.get("target")
        try:
            wrong_target = declared is not None and canonical_target_value(declared) != canonical
        except (TypeError, ValueError):
            wrong_target = True
        if wrong_target:
            report["quarantined"].append({"owner": "target-memory", "path": relative,
                                          "field": field, "position": position,
                                          "reason": "historical entry declares another target"})
            continue
        text = item.get("text") or (item.get("summary") if field == "session_handoffs" else "")
        structured = item.get("structured") or {}
        if not isinstance(structured, dict):
            structured = {}
        if not isinstance(text, str) or not text.strip() or len(text) > 4096 or text_is_polluted(text):
            report["quarantined"].append({"owner": "target-memory", "path": relative,
                                          "field": field, "position": position,
                                          "reason": "empty, oversized or polluted historical text"})
            continue
        conditions = item.get("conditions") or structured.get("conditions") or "unknown"
        reopen = item.get("reopen_when") or structured.get("reopen_when") or ""
        next_intent = item.get("next_intent") or structured.get("next") or ""
        if not all(isinstance(value, str) and len(value) <= 2048
                   for value in (conditions, reopen, next_intent)):
            report["quarantined"].append({"owner": "target-memory", "path": relative,
                                          "field": field, "position": position,
                                          "reason": "historical condition fields are invalid or oversized"})
            continue
        refs = item.get("evidence_refs") or []
        evidence = []
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, str) or ":" not in ref:
                    break
                operation_id, step = ref.rsplit(":", 1)
                if not step.isdecimal():
                    break
                try:
                    operation = store.execution(operation_id)
                    store.verify_operation(operation_id)
                except StoreError:
                    break
                if not any(row["step"] == int(step) for row in operation["observations"]):
                    break
                evidence.append({"operation_id": operation_id, "step": int(step)})
        if not isinstance(refs, list) or len(evidence) != len(refs):
            evidence = []
        kind = {"active_leads": "hypothesis", "next_actions": "handoff",
                "session_handoffs": "handoff"}.get(field, "note")
        if field == "dead_ends" and evidence and conditions != "unknown" and reopen:
            kind = "negative"
        elif field == "useful_patterns" and evidence:
            kind = "primitive"
        if kind not in {"negative", "primitive"}:
            evidence = []
            label = f"{field}[{position}]" if field == "facts" else field
            text = f"Historical {label} (unverified): {text.strip()}"
        command_id = "legacy-memory:" + _stable_id(manifest["sha256"], relative, field, position)
        receipt = store.remember(command_id=command_id, kind=kind, statement=text,
                                 conditions=conditions, reopen_when=reopen, next_intent=next_intent,
                                 evidence=evidence, actor="migration")
        source_id, source_ts = item.get("entry_id"), item.get("ts")
        mapped.append({"experience_id": receipt["entity_id"], "source_path": relative,
                       "field": field, "position": position,
                       "source_id": source_id[:256] if isinstance(source_id, str) else "",
                       "source_ts": source_ts[:64] if isinstance(source_ts, str) else "", "kind": kind,
                       "evidence_status": "bound" if evidence else "unverified",
                       "unbound_reference_count": len(refs) if isinstance(refs, list) and not evidence else 0})
    disposition["source_sha256"] = source["sha256"]
    disposition["source_manifest_sha256"] = manifest["sha256"]
    disposition["experience_map"] = mapped
    disposition["imported_experiences"] = len(mapped)
    disposition["disposition"] = "imported eligible historical entries; original source retained"


def _coverage_review_source(root: Path, canonical: str, manifest: dict) -> dict:
    """Read pinned legacy annotations as historical review inputs, never evidence."""
    relative = f"evidence/{target_storage_key(canonical)}/coverage_matrix.json"
    result = {"status": "missing", "path": relative, "source_sha256": "", "reviews": [],
              "quarantined": [], "retained_default_cells": 0}
    path = root / relative
    source = next((item for item in manifest["files"] if item.get("path") == relative), None)
    if source is None and not path.exists() and not path.is_symlink():
        return result
    if source is None or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise StoreError(f"coverage source must be a regular manifest-bound file: {path}")
    raw = path.read_bytes()
    if len(raw) != source["size"] or hashlib.sha256(raw).hexdigest() != source["sha256"]:
        raise StoreError(f"coverage source differs from migration manifest: {relative}")
    result["source_sha256"] = source["sha256"]

    def quarantine(pointer: str, reason: str) -> None:
        result["quarantined"].append({"owner": "coverage", "path": relative,
                                       "id": pointer, "reason": reason})

    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get("endpoints"), list):
            raise ValueError("coverage matrix must contain an endpoints array")
        if canonical_target_value(payload.get("target", "")) != canonical:
            raise ValueError("coverage matrix declares another target")
        if payload.get("backend") == "primary" or payload.get("store_id") or payload.get("source_snapshot"):
            raise ValueError("Store Coverage projection is not a legacy author source")
    except (ValueError, TypeError) as exc:
        quarantine("/", str(exc))
        result["status"] = "quarantined"
        return result
    store = TargetStore(root, canonical)
    for index, ep in enumerate(payload["endpoints"]):
        pointer = f"/endpoints/{index}"
        if not isinstance(ep, dict):
            quarantine(pointer, "endpoint row must be an object")
            continue
        try:
            store.coverage_endpoint(ep.get("endpoint"))
        except (ValueError, TypeError) as exc:
            quarantine(pointer, str(exc))
            continue
        drafts = []
        if (ep.get("endpoint_kind") not in (None, "", "untriaged")
                or ep.get("kind_source") or ep.get("kind_reason") or ep.get("kind_triaged_at")):
            drafts.append((pointer, {
                "kind": "endpoint_kind", "value": ep.get("endpoint_kind"),
                "source": ep.get("kind_source", "legacy_import"), "reason": ep.get("kind_reason", ""),
                "reviewed_at": ep.get("kind_triaged_at", ""),
            }))
        cells = ep.get("cells", {})
        if not isinstance(cells, dict):
            quarantine(pointer + "/cells", "coverage cells must be an object")
            cells = {}
        for family, cell in cells.items():
            cell_pointer = pointer + "/cells/" + family.replace("~", "~0").replace("/", "~1")
            if not isinstance(cell, dict):
                quarantine(cell_pointer, "coverage cell must be an object")
                continue
            if cell.get("status") == "untested" and not cell.get("reason"):
                result["retained_default_cells"] += 1
                continue
            drafts.append((cell_pointer, {"kind": "cell_status", "family": family,
                           "value": cell.get("status"), "reason": cell.get("reason", ""),
                           "source": "legacy_import"}))
        for source_pointer, draft in drafts:
            try:
                normalized = store.normalize_coverage_review(
                    endpoint=ep.get("endpoint"), historical=True, **draft,
                )
            except (StoreError, ValueError, TypeError) as exc:
                quarantine(source_pointer, str(exc))
                continue
            result["reviews"].append({"source_pointer": source_pointer, "input": normalized})
    result["status"] = "partial" if result["quarantined"] else "valid"
    return result


def _import_coverage_reviews(report: dict, store: TargetStore, root: Path,
                             canonical: str, manifest: dict) -> dict:
    source = _coverage_review_source(root, canonical, manifest)
    mapping = []
    if source["reviews"]:
        store.coverage_review_page(limit=1)  # Refuse old schemas before importing any row.
    for row in source.pop("reviews"):
        review_id = "legacy-coverage:" + _stable_id(source["path"], source["source_sha256"], row["source_pointer"])
        store.record_coverage_review(command_id=review_id, actor="legacy-import", **row["input"])
        mapping.append({"review_id": review_id, "source_pointer": row["source_pointer"]})
    source["review_map"] = mapping
    report["legacy"]["coverage"] = source
    report["quarantined"].extend(source["quarantined"])
    return source


def _report_artifact_inventory(root: Path, key: str) -> list[dict[str, Any]]:
    """Inventory report bytes without treating them as delivery decisions."""
    reports = root / "reports" / key
    if not reports.exists():
        return []
    if reports.is_symlink():
        raise StoreError(f"report artifact directory must not be a symlink: {reports}")
    items: list[dict[str, Any]] = []
    for path in sorted(reports.rglob("*")):
        if path.is_symlink():
            raise StoreError(f"report artifact must not be a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        items.append({
            "path": relative,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "registered": False,
            "note": "preserved as an artifact; report/delivery relation requires explicit re-registration",
        })
    return items


_MIGRATION_COPY_EXCLUDES = ("locks", "metadata.sqlite3", "legacy-frozen.json", "migration-receipt.json")


def _is_migration_input(path: Path, root: Path) -> bool:
    """Whether a path under a target-owned root is a migration input.

    The manifest and the copy step must agree on this set: a file the manifest
    hashes but the copy deliberately omits makes promotion report a vanished
    input, and a file the copy takes but the manifest skips is unaccounted for.
    Runtime locks live under ``locks/`` (and ``.locks/``) directories and are
    process state, not domain facts, so both steps exclude them together.
    """
    relative = path.relative_to(root)
    if any(part in {"locks", ".locks"} for part in relative.parts[:-1]):
        return False
    return path.name not in _MIGRATION_COPY_EXCLUDES


def _migration_manifest(repo_root: Path, target: str) -> dict[str, Any]:
    """Hash the target-owned legacy inputs without creating migration state."""
    key = target_storage_key(target)
    roots = [
        repo_root / "state" / key,
        repo_root / "findings" / key,
        repo_root / "memory" / "evidence" / key,
        repo_root / "memory" / "goals" / "targets" / f"{key}.json",
        repo_root / "reports" / key,
        repo_root / "evidence" / key,
        repo_root / ".private" / "validation" / key,
        repo_root / ".private" / "case-state" / key,
        target_profile_path(repo_root / "hunt-memory", target),
    ]
    files: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            if not path.is_file() or path.is_symlink():
                continue
            if not _is_migration_input(path, repo_root):
                continue
            relative = path.relative_to(repo_root).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            files.append({"path": relative, "size": path.stat().st_size, "sha256": digest})
    files.sort(key=lambda item: item["path"])
    encoded = json.dumps(files, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return {
        "schema_version": 1,
        "target": target,
        "files": files,
        "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    }


def preview_target(repo_root: str | Path, target: str) -> dict[str, Any]:
    """Read-only migration preview; never creates a DB, lock, or cache."""
    root = Path(repo_root).resolve()
    canonical = canonical_target_value(target)
    sources = _legacy_sources(root, canonical)
    report = _empty_report(canonical, sources)
    report["mode"] = "readonly-preview"
    report["scope"] = _migration_scope(root, canonical)
    memory_disposition = _target_memory_disposition(root, canonical)
    report["legacy"]["target_memory"] = memory_disposition
    if memory_disposition.get("status") == "quarantined":
        report["quarantined"].append({
            "owner": "target-memory",
            "path": memory_disposition.get("path", ""),
            "reason": memory_disposition.get("disposition", "target-memory unavailable"),
        })
    report["manifest"] = _migration_manifest(root, canonical)
    coverage = _coverage_review_source(root, canonical, report["manifest"])
    coverage_count = len(coverage.pop("reviews"))
    report["legacy"]["coverage"] = coverage
    report["quarantined"].extend(coverage["quarantined"])
    report["source_counts"] = {
        "actions": len(sources["queue"].get("actions") or []),
        "findings": len(sources["findings"].get("findings") or []),
        "observations": len(sources["ledger"].get("entries") or []),
        "report_artifacts": len(_report_artifact_inventory(root, target_storage_key(canonical))),
        "target_memory_entries": int(memory_disposition.get("entries", 0) or 0),
        "coverage_reviews": coverage_count,
    }
    if (
        sources["queue"].get("error")
        or sources["findings"].get("error")
        or sources["ledger"].get("status") not in {"missing", "valid"}
        or sources["case_state"].get("error")
        or memory_disposition.get("status") == "quarantined"
        or coverage["quarantined"]
    ):
        report["status"] = "partial"
    return report


def _copy_target_inputs(source: Path, destination: Path, target: str) -> None:
    """Copy only target-owned migration inputs into a private staging root."""
    key = target_storage_key(target)
    paths = [
        (source / "state" / key, destination / "state" / key),
        (source / "findings" / key, destination / "findings" / key),
        (source / "memory" / "evidence" / key, destination / "memory" / "evidence" / key),
        (source / "memory" / "goals" / "targets" / f"{key}.json", destination / "memory" / "goals" / "targets" / f"{key}.json"),
        (source / "reports" / key, destination / "reports" / key),
        (source / "evidence" / key, destination / "evidence" / key),
        (source / ".private" / "validation" / key, destination / ".private" / "validation" / key),
        (source / ".private" / "case-state" / key, destination / ".private" / "case-state" / key),
        (target_profile_path(source / "hunt-memory", target),
         target_profile_path(destination / "hunt-memory", target)),
    ]
    def reject_symlink_tree(path: Path) -> None:
        if path.is_symlink():
            raise StoreError(f"source migration input must not be a symlink: {path}")
        if path.is_dir():
            for child in path.iterdir():
                reject_symlink_tree(child)

    def ignore_non_inputs(directory: str, names: list[str]) -> set[str]:
        # Same predicate the manifest uses, so the copied set and the hashed set
        # can never disagree about what a migration input is.
        base = Path(directory)
        return {name for name in names if not _is_migration_input(base / name, source)}

    for origin, copied in paths:
        if not origin.exists():
            continue
        reject_symlink_tree(origin)
        copied.parent.mkdir(parents=True, exist_ok=True)
        if origin.is_dir():
            shutil.copytree(origin, copied, symlinks=False, ignore=ignore_non_inputs)
        else:
            shutil.copy2(origin, copied)


def import_target_staged(
    source_root: str | Path,
    destination_root: str | Path,
    target: str,
    *,
    disposition_ledger: str | Path | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Import into a new private staging root, leaving source untouched."""
    source = Path(source_root).resolve()
    destination = Path(destination_root).resolve()
    if source == destination or source in destination.parents or destination in source.parents:
        raise StoreError("source and destination must be different isolated roots")
    if not source.is_dir():
        raise StoreError(f"source root is not a directory: {source}")
    source_store = source / "state" / target_storage_key(canonical_target_value(target)) / "metadata.sqlite3"
    if source_store.exists():
        raise StoreError("source already contains a target store; export from the current owner before migration")
    if destination.exists():
        raise StoreError(f"destination already exists: {destination}")
    canonical = canonical_target_value(target)
    _migration_scope(source, canonical)
    manifest = _migration_manifest(source, canonical)
    disposition_payload, disposition_digest = _load_disposition_ledger(disposition_ledger)
    _validate_disposition_binding(disposition_payload, canonical, manifest["sha256"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination
    staging.mkdir(mode=0o700)
    try:
        _copy_target_inputs(source, staging, canonical)
        result = import_target(
            staging,
            canonical,
            disposition_ledger=disposition_ledger,
            source_manifest_sha256=manifest["sha256"],
            source_root=source,
        )
        store = TargetStore(staging, canonical, allow_preview=True)
        context = store.context(limit=1)
        receipt = {
            "schema_version": 1,
            "kind": "target_migration_receipt",
            "status": "complete" if result["status"] == "ready" else "partial",
            "target": canonical,
            "store_id": context["store_id"],
            "backend": store.backend(),
            "source_manifest_sha256": manifest["sha256"],
            "source_manifest": manifest,
            "imported": result["imported"],
            "scope_sha256": read_scope_source(staging, canonical)["sha256"],
        }
        memory = result["legacy"]["target_memory"]
        coverage = result["legacy"]["coverage"]
        if coverage.get("source_sha256"):
            receipt["coverage_backfill"] = {"source_manifest_sha256": manifest["sha256"], **coverage}
        if memory.get("source_sha256"):
            receipt["memory_backfill"] = {
                "source_manifest_sha256": manifest["sha256"],
                "source_sha256": memory["source_sha256"],
                "experience_map": memory["experience_map"],
                "quarantined": [row for row in result["quarantined"] if row.get("owner") == "target-memory"],
            }
        if disposition_payload is not None:
            receipt["disposition_ledger"] = result.get("disposition_ledger", {
                "ledger_sha256": disposition_digest,
                "status": "partial",
            })
        # Preserved-but-unregistered material stays a durable cutover fact: the
        # bytes are kept by design, and the receipt must show that no report
        # registration or delivery relation was inferred from their presence.
        artifacts = result.get("legacy", {}).get("report_artifacts") or []
        if artifacts:
            receipt["unregistered_artifacts"] = {
                "report_artifacts": len(artifacts),
                "paths": [str(item.get("path", "")) for item in artifacts],
                "digests_sha256": [
                    f"{item.get('sha256', '')}  {item.get('path', '')}" for item in sorted(
                        artifacts, key=lambda item: str(item.get("path", ""))
                    )
                ],
                "note": "preserved as artifacts; registration requires explicit re-registration",
            }
        receipt_path = staging / "state" / target_storage_key(canonical) / "migration-receipt.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        result["mode"] = "staged-import"
        result["source_manifest"] = manifest
        result["staging_root"] = str(staging)
        result["receipt"] = receipt
        return result
    except BaseException:
        # Keep a failed staging root for explicit diagnosis, never publish it.
        raise


def publish_preview(staging_root: str | Path, destination_root: str | Path, target: str) -> dict[str, Any]:
    """Atomically publish a completed isolated staging root as a preview root."""
    staging = Path(staging_root).resolve()
    destination = Path(destination_root).resolve()
    if destination.exists():
        raise StoreError(f"destination already exists: {destination}")
    canonical = canonical_target_value(target)
    receipt_path = staging / "state" / target_storage_key(canonical) / "migration-receipt.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StoreError(f"migration receipt is unreadable: {receipt_path}") from exc
    if receipt.get("target") != canonical or receipt.get("backend") != "preview" or receipt.get("status") != "complete":
        raise StoreError("preview receipt is incomplete or does not match target")
    if read_scope_source(staging, canonical)["sha256"] != receipt.get("scope_sha256"):
        raise StoreError("preview Scope changed; rebuild the isolated migration")
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging, destination)
    return {"status": "published", "target": canonical, "destination_root": str(destination), "receipt": receipt}


def _store_metadata_unchecked(store: TargetStore) -> dict[str, Any]:
    """Read store identity without applying the fence role check.

    Promotion recovery needs to distinguish a preview DB with a fence from a
    primary DB after an interrupted final transaction.  The normal Store read
    path intentionally rejects the former, so this helper is limited to the
    cutover lock and returns only the immutable identity/role columns.
    """
    try:
        conn = sqlite3.connect(f"file:{store.path}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only=ON")
            row = conn.execute(
                "SELECT target, store_id, backend, revision FROM store WHERE singleton=1"
            ).fetchone()
        finally:
            conn.close()
    except (OSError, sqlite3.DatabaseError) as exc:
        raise StoreError(f"target store failure: {store.path}; explicit recovery required") from exc
    if not row or row[0] != store.target or row[2] not in {"preview", "primary"}:
        raise StoreError(f"target store identity is invalid: {store.path}")
    return {"target": row[0], "store_id": row[1], "backend": row[2], "revision": row[3]}


def _verify_manifest_at_root(root: Path, manifest: dict[str, Any]) -> None:
    """Ensure the published copy still matches the source before freezing it."""
    for item in manifest.get("files", []):
        relative = str(item.get("path") or "")
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise StoreError("migration manifest contains an unsafe relative path")
        path = root / relative
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise StoreError(f"migration input disappeared before promotion: {relative}") from exc
        if len(payload) != int(item.get("size", -1)) or hashlib.sha256(payload).hexdigest() != item.get("sha256"):
            raise StoreError(f"migration input changed before promotion: {relative}")


def _archive_receipt_path(root: Path, key: str) -> Path:
    return root / "state" / key / "legacy-archive.json"


def _freeze_legacy_metadata(
    root: Path,
    canonical: str,
    *,
    store_id: str,
    source_manifest_sha256: str,
) -> dict[str, Any]:
    """Archive migrated legacy owners while the cutover lock is held.

    The archive is a recovery input, not a second live owner.  Copy-and-verify
    is used instead of unlink-first so an interrupted freeze leaves the source
    bytes available for explicit recovery.
    """
    key = target_storage_key(canonical)
    receipt_path = _archive_receipt_path(root, key)
    if receipt_path.is_file():
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StoreError(f"legacy archive receipt is unreadable: {receipt_path}") from exc
        if (
            receipt.get("target") != canonical
            or receipt.get("store_id") != store_id
            or receipt.get("source_manifest_sha256") != source_manifest_sha256
        ):
            raise StoreError("legacy archive receipt does not match the migration identity")
        return receipt

    archive_dir = root / "state" / key / "legacy-archive" / source_manifest_sha256
    archive_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    files: list[dict[str, Any]] = []
    try:
        for template, archive_relative in _LEGACY_METADATA_PATHS:
            relative = template.format(key=key)
            source = root / relative
            if not source.exists():
                continue
            if source.is_symlink() or not source.is_file():
                raise StoreError(f"legacy metadata must be a regular file: {relative}")
            payload = source.read_bytes()
            destination = archive_dir / archive_relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            os.chmod(destination, 0o600)
            if hashlib.sha256(destination.read_bytes()).hexdigest() != hashlib.sha256(payload).hexdigest():
                raise StoreError(f"legacy archive verification failed: {relative}")
            files.append({
                "path": relative,
                "archive_path": destination.relative_to(root).as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        receipt = {
            "schema_version": 1,
            "kind": "legacy_metadata_archive",
            "target": canonical,
            "store_id": store_id,
            "source_manifest_sha256": source_manifest_sha256,
            "activation_status": "pending",
            "files": files,
        }
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(receipt_path, 0o600)
        with receipt_path.open("rb") as handle:
            os.fsync(handle.fileno())
        for item in files:
            original = root / item["path"]
            original.unlink()
            fd = os.open(original.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return receipt
    except BaseException:
        # The archive and any remaining source files are intentionally kept for
        # restore_legacy_metadata()/diagnosis; never delete evidence on failure.
        raise


def _mark_archive_active(root: Path, key: str) -> None:
    path = _archive_receipt_path(root, key)
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["activation_status"] = "active"
    write_json_atomic(path, receipt, ensure_ascii=True)


def _verify_archive_material(root: Path, receipt: dict[str, Any]) -> None:
    for item in receipt.get("files", []):
        archived = root / str(item.get("archive_path") or "")
        if archived.is_symlink() or not archived.is_file():
            raise StoreError(f"legacy archive material is missing: {archived}")
        payload = archived.read_bytes()
        if len(payload) != int(item.get("size", -1)) or hashlib.sha256(payload).hexdigest() != item.get("sha256"):
            raise StoreError(f"legacy archive material failed verification: {archived}")


def _mark_migration_active(root: Path, key: str, archive_path: Path) -> None:
    """Record the committed backend role in the durable migration receipt."""
    path = root / "state" / key / "migration-receipt.json"
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["backend"] = "primary"
    receipt["activation_status"] = "active"
    receipt["legacy_archive_path"] = archive_path.relative_to(root).as_posix()
    write_json_atomic(path, receipt, ensure_ascii=True)


def restore_legacy_metadata(
    repo_root: str | Path,
    target: str,
    *,
    source_manifest_sha256: str = "",
) -> dict[str, Any]:
    """Restore archived legacy owners before primary activation.

    A healthy primary DB, or an unreadable DB whose activation state cannot be
    proven to be pre-primary, is fail-closed.  Removing the fence alone is
    never a rollback operation.
    """
    root = Path(repo_root).resolve()
    canonical = canonical_target_value(target)
    key = target_storage_key(canonical)
    with target_cutover_lock(root, canonical):
        store = TargetStore(root, canonical, allow_preview=True)
        fence = store._read_fence()
        if fence is None:
            raise StoreError("legacy metadata is not fenced; refusing implicit restore")
        archive_path = _archive_receipt_path(root, key)
        try:
            receipt = json.loads(archive_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StoreError("legacy archive receipt is required for explicit restore") from exc
        if store.path.exists():
            meta = _store_metadata_unchecked(store)
            if meta["backend"] != "preview":
                raise StoreError("primary activation already committed; restore through Store backup/export")
        digest = str(source_manifest_sha256 or receipt.get("source_manifest_sha256") or "")
        if (
            receipt.get("target") != canonical
            or receipt.get("store_id") != fence.get("store_id")
            or receipt.get("source_manifest_sha256") != digest
            or receipt.get("activation_status") != "pending"
        ):
            raise StoreError("legacy restore identity or activation state does not match")
        if not store.path.exists() and not digest:
            raise StoreError("source manifest digest is required for restore")

        for item in receipt.get("files", []):
            original = root / str(item.get("path") or "")
            archived = root / str(item.get("archive_path") or "")
            if original.exists() or original.is_symlink():
                if original.is_symlink() or not original.is_file() or hashlib.sha256(original.read_bytes()).hexdigest() != item.get("sha256"):
                    raise StoreError(f"legacy restore would overwrite changed metadata: {original}")
                continue
            if archived.is_symlink() or not archived.is_file():
                raise StoreError(f"legacy archive material is missing: {archived}")
            payload = archived.read_bytes()
            if len(payload) != int(item.get("size", -1)) or hashlib.sha256(payload).hexdigest() != item.get("sha256"):
                raise StoreError(f"legacy archive material failed verification: {archived}")
            original.parent.mkdir(parents=True, exist_ok=True)
            original.write_bytes(payload)
            os.chmod(original, 0o600)

        for suffix in ("metadata.sqlite3", "metadata.sqlite3-wal", "metadata.sqlite3-shm", "migration-receipt.json"):
            (root / "state" / key / suffix).unlink(missing_ok=True)
        store.fence_path.unlink(missing_ok=True)
        archive_path.unlink(missing_ok=True)
        shutil.rmtree(root / "state" / key / "legacy-archive", ignore_errors=True)
        return {"status": "legacy", "target": canonical, "restored": len(receipt.get("files", []))}


def promote_target(repo_root: str | Path, target: str, *, source_manifest_sha256: str = "") -> dict[str, Any]:
    """Explicitly activate a published preview; no caller invokes this implicitly."""
    root = Path(repo_root).resolve()
    canonical = canonical_target_value(target)
    key = target_storage_key(canonical)
    with target_cutover_lock(root, canonical):
        store = TargetStore(root, canonical, allow_preview=True)
        meta = _store_metadata_unchecked(store)
        receipt_path = root / "state" / key / "migration-receipt.json"
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StoreError("completed migration receipt is required before promotion") from exc
        digest = str(source_manifest_sha256 or receipt.get("source_manifest_sha256") or "")
        if digest != receipt.get("source_manifest_sha256") or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise StoreError("source manifest digest does not match migration receipt")
        manifest = receipt.get("source_manifest")
        fence = store._read_fence()
        archive_path = _archive_receipt_path(root, key)
        # Once the fence exists, the legacy files may already have been
        # archived and removed. The archive receipt, rather than the original
        # manifest paths, is the recovery input for an interrupted cutover.
        if meta["backend"] == "preview" and fence is None and isinstance(manifest, dict):
            _verify_manifest_at_root(root, manifest)
        if meta["backend"] == "primary":
            # Recovery for a crash after the SQLite role commit but before the
            # archive/receipt activation markers. The primary role is already
            # durable; only finish the idempotent activation bookkeeping.
            if fence is None or fence.get("store_id") != meta["store_id"] or fence.get("source_manifest_sha256") != digest:
                raise StoreError("primary store activation identity is incomplete")
            # A completed activation is identified by its own durable markers:
            # the role commit, the fence and the receipt all name this store and
            # manifest.  The archive is the recovery input for an *interrupted*
            # cutover, not a runtime dependency of a finished one -- requiring
            # its bytes here would make a cleaned-up archive look like damage and
            # would leave a finished target with no idempotent re-entry.
            if receipt.get("activation_status") == "active":
                return {"status": "primary", "target": canonical, "store_id": meta["store_id"],
                        "source_manifest_sha256": digest, "recovered": True}
            try:
                archive_state = json.loads(archive_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise StoreError("backend cutover incomplete; legacy archive receipt is required") from exc
            if archive_state.get("store_id") != meta["store_id"] or archive_state.get("source_manifest_sha256") != digest:
                raise StoreError("legacy archive receipt does not match the primary store")
            if archive_state.get("activation_status") not in {"pending", "active"}:
                raise StoreError("legacy archive activation state is invalid")
            _verify_archive_material(root, archive_state)
            if archive_state.get("activation_status") == "pending":
                _mark_archive_active(root, key)
            _mark_migration_active(root, key, archive_path)
            return {"status": "primary", "target": canonical, "store_id": meta["store_id"],
                    "source_manifest_sha256": digest, "recovered": True}
        if meta["backend"] != "preview":
            raise StoreError("only a preview store can be promoted")
        if read_scope_source(root, canonical)["sha256"] != receipt.get("scope_sha256"):
            raise StoreError("preview Scope changed; rebuild the isolated migration")
        if fence is not None:
            try:
                archive_state = json.loads(archive_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise StoreError("backend cutover incomplete; restore legacy metadata before retrying promotion") from exc
            if (
                fence.get("store_id") != meta["store_id"]
                or fence.get("source_manifest_sha256") != digest
                or archive_state.get("activation_status") != "pending"
            ):
                raise StoreError("backend cutover incomplete; restore legacy metadata before retrying promotion")
        else:
            store._create_fence(meta["store_id"], digest)
        _freeze_legacy_metadata(
            root,
            canonical,
            store_id=meta["store_id"],
            source_manifest_sha256=digest,
        )
        conn = sqlite3.connect(store.path)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE store SET backend='primary' WHERE singleton=1")
            conn.commit()
        finally:
            conn.close()
        _mark_archive_active(root, key)
        _mark_migration_active(root, key, archive_path)
        return {"status": "primary", "target": canonical, "store_id": meta["store_id"], "source_manifest_sha256": digest}


def _empty_report(canonical: str, sources: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "target": canonical,
        "mode": "isolated-import",
        "status": "ready",
        "sources": sources["paths"],
        "imported": {"actions": 0, "findings": 0, "observations": 0, "artifacts": 0},
        "legacy": {
            "action_statuses": {},
            "ledger_results": {},
            "observations": [],
            "action_verdicts": [],
            "action_metadata": [],
            "finding_verdicts": [],
            "observed_origins": [],
            "path_endpoint_origin": "",
            "target_conflicts": [],
            "unknown_fields": {"queue": {}, "findings": {}, "ledger": {}, "case_state": {}, "case_backlog": {}},
            "case_context": {
                "present": False,
                "actors": 0, "sessions": 0, "objects": 0,
                "hypotheses": 0, "open_hypotheses": 0,
                "backlog_records": 0, "backlog_shape": "absent",
            },
            "case_context_import": {
                "actors": 0, "sessions": 0, "objects": 0, "hypotheses": 0,
                "quarantined": 0,
            },
            "case_backlog": [],
            "case_backlog_relations": [],
            "case_backlog_conflicts": [],
            "sensitive_metadata": [],
            "secret_material_refs": [],
            "identity_carry": {
                "records_with_complete_identity": 0,
                "partial_identities_carried": 0,
                "uncarryable_identity_claims": 0,
                "results_carried": 0,
                "results_outside_shared_vocabulary": 0,
            },
            "unreferenced_material": {
                "count": 0, "sample": [], "without_referenced_neighbour": 0,
                "without_referenced_neighbour_sample": [],
            },
            "report_artifacts": [],
            "target_memory": {
                "path": "",
                "status": "missing",
                "target": canonical,
                "fields": {},
                "entries": 0,
                "disposition": "no legacy target-memory file was present",
            },
        },
        "links": [],
        "quarantined": [],
    }


def _import_ledger(report: dict[str, Any], store: TargetStore, root: Path, canonical: str,
                   entries: list[dict[str, Any]], findings: list[dict[str, Any]],
                   rebase_root: Path | None = None) -> set[str]:
    """Register raw observations, binding a claim only on an exact match.

    Returns the origins seen in the raw records so the caller can resolve a
    legacy path endpoint only when that origin is unambiguous.
    """
    scoped: list[dict[str, Any]] = []
    for entry in entries:
        declared = _text(entry.get("target"))
        if declared and canonical_target_value(declared) != canonical:
            report["legacy"]["target_conflicts"].append({
                "owner": "ledger", "event_id": _text(entry.get("event_id")),
                "declared_target": declared, "expected_target": canonical,
            })
            report["quarantined"].append({
                "owner": "ledger", "event_id": _text(entry.get("event_id")),
                "reason": f"record declares target {declared}, not {canonical}; "
                          "a cross-target record is imported by nobody",
            })
            continue
        scoped.append(entry)
    entries = scoped
    origins = {
        parsed for parsed in (
            _origin(_text(row.get("raw_endpoint")) or _text(row.get("endpoint"))) for row in entries
        ) if parsed
    }
    entry_origin = next(iter(origins)) if len(origins) == 1 else ""
    prepared: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for entry in entries:
        observation, reason = _ledger_observation(entry, entry_origin, rebase_root, root)
        if observation is None:
            _count_uncarryable_claim(report, entry)
            report["quarantined"].append({
                "owner": "ledger", "event_id": _text(entry.get("event_id")), "reason": reason,
                "endpoint": _text(entry.get("raw_endpoint") or entry.get("endpoint")),
                "evidence_ref": _text(entry.get("evidence_ref")), "result": _text(entry.get("result")),
            })
            continue
        original_ref = _text(entry.get("evidence_ref"))
        imported_ref = observation["artifacts"]["evidence"]
        if original_ref != imported_ref:
            report["legacy"].setdefault("rebased_references", []).append(
                _rebase_notice(root, original_ref, imported_ref)
            )
        prepared.setdefault(_observation_key(observation), []).append({"entry": entry, "observation": observation})

    used: set[int] = set()
    pending: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for finding in findings:
        key = _finding_key(finding, canonical)
        _legacy_verdicts(report, finding)
        bucket = prepared.get(key) or []
        if not key[0] or not key[1] or not key[2] or not bucket:
            report["quarantined"].append({
                "owner": "findings", "id": _text(finding.get("id")),
                "reason": "claim has no observation with an exact endpoint/method/family match; preserved for explicit review",
            })
            continue
        pick = next((item for item in bucket if id(item) not in used), None)
        if pick is None:
            report["quarantined"].append({
                "owner": "findings", "id": _text(finding.get("id")),
                "reason": "every exact observation is already bound to another claim; requires an explicit new observation",
            })
            continue
        used.add(id(pick))
        pending.append((finding, pick))

    for key, bucket in prepared.items():
        for item in bucket:
            entry, observation = item["entry"], item["observation"]
            finding = next((f for f, chosen in pending if chosen is item), None)
            ref = observation["artifacts"]["evidence"]
            secret_reason = _private_ref_reason(root, store.key, ref)
            if secret_reason or not _evidence_readable(root, ref):
                report["quarantined"].append({
                    "owner": "ledger", "event_id": _text(entry.get("event_id")),
                    "reason": secret_reason or _unbindable_reason(root, ref),
                    "endpoint": observation["endpoint"], "evidence_ref": ref,
                    "result": _text(entry.get("result")),
                })
                if finding is not None:
                    report["quarantined"].append({
                        "owner": "findings", "id": _text(finding.get("id")),
                        "reason": f"bound observation could not be imported: {ref}",
                    })
                continue
            attempt_id = "migrate:attempt:" + _stable_id(entry.get("event_id"), entry.get("evidence_ref"),
                                                         entry.get("ts"), observation["endpoint"])
            candidate = None
            if finding is not None:
                candidate = {
                    "id": _text(finding.get("id")),
                    "endpoint": observation["endpoint"],
                    "method": observation["method"],
                    "family": observation["family"],
                    "title": _text(finding.get("title")) or _text(finding.get("id")),
                    "claim": _text(finding.get("summary")) or _text(finding.get("title")) or _text(finding.get("id")),
                }
            try:
                store.start_attempt(attempt_id=attempt_id, source="migration:legacy-ledger",
                                    started_at=observation["observed_at"], actor="migration")
                receipt = store.record_execution(
                    attempt_id=attempt_id,
                    outcome="partial" if (observation["error"] or observation["truncated"]) else "complete",
                    observations=[observation], actor="migration", candidate=candidate,
                )
            except (StoreError, ValueError) as exc:
                report["quarantined"].append({
                    "owner": "ledger", "event_id": _text(entry.get("event_id")),
                    "reason": _unbindable_reason(root, ref) if _escapes_root(root, ref)
                              else " ".join(str(exc).split())[:300],
                    "endpoint": observation["endpoint"], "evidence_ref": ref,
                    "result": _text(entry.get("result")),
                })
                if finding is not None:
                    report["quarantined"].append({
                        "owner": "findings", "id": _text(finding.get("id")),
                        "reason": "bound observation was rejected; claim stays quarantined",
                    })
                continue
            operation_id = str(receipt.get("entity_id") or "")
            report["imported"]["observations"] += 1
            report["imported"]["artifacts"] += 1
            # Counted here, not at preparation: the report must describe what
            # the store actually holds, not what was about to be imported.
            _count_identity_carry(report, entry, observation)
            if _secret_file_ref(ref):
                report["legacy"]["secret_material_refs"].append({
                    "owner": "ledger", "event_id": _text(entry.get("event_id")), "ref": ref,
                    "note": "file name indicates credential material; only ref/sha256/size were "
                            "registered, the content was never copied",
                })
            report["legacy"]["observations"].append({
                "event_id": _text(entry.get("event_id")),
                "operation_id": operation_id,
                "result": _text(entry.get("result")),
                "ts": _text(entry.get("ts")),
                "evidence_ref": ref,
            })
            if finding is not None:
                report["imported"]["findings"] += 1
                report["links"].append({
                    "finding_id": _text(finding.get("id")), "operation_id": operation_id, "step": 0,
                    "event_id": _text(entry.get("event_id")),
                })
    return origins


def _import_queue(report: dict[str, Any], store: TargetStore, origin: str, actions: list[Any]) -> None:
    for item in actions:
        if not isinstance(item, dict):
            report["quarantined"].append({"owner": "queue", "reason": "action is not an object"})
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        sensitive = _sensitive_metadata_paths(metadata)
        if sensitive:
            report["legacy"]["sensitive_metadata"].append({
                "owner": "queue", "id": _text(item.get("id")), "keys": sorted(sensitive),
            })
        action_id = _text(item.get("id"))
        raw_endpoint = _text(metadata.get("endpoint") or metadata.get("url"))
        endpoint = _endpoint(metadata, origin)
        family = _family(metadata)
        status = _text(item.get("status"))
        report["legacy"]["action_statuses"][status or "<empty>"] = (
            report["legacy"]["action_statuses"].get(status or "<empty>", 0) + 1
        )
        verdict = {
            "id": action_id, "status": status, "endpoint": endpoint or raw_endpoint,
            "family": family, "priority": item.get("priority"),
            "next_question": _text(item.get("next_question")), "evidence": _text(item.get("evidence")),
        }
        if not action_id:
            report["quarantined"].append({"owner": "queue", "reason": "action has no id"})
            continue
        if status not in _OPEN_ACTION_STATUSES:
            report["legacy"]["action_verdicts"].append(verdict)
            report["quarantined"].append({
                "owner": "queue", "id": action_id,
                "reason": f"legacy status {status or '<empty>'} is a terminal verdict with no unambiguous "
                          "mapping into the action state machine; intent and verdict preserved",
            })
            continue
        if not endpoint or not family:
            report["legacy"]["action_verdicts"].append(verdict)
            report["quarantined"].append({
                "owner": "queue", "id": action_id,
                "reason": "missing endpoint or family" if not endpoint else "missing family",
            })
            continue
        migrated_metadata = {
            key: metadata[key]
            for key in _MIGRATABLE_ACTION_METADATA
            if key in metadata
        }
        reported_metadata = sorted(
            key for key in metadata
            if key in _MIGRATABLE_ACTION_METADATA
            or key in {"baseline_ref", "evidence_ref", "selected_knowledge_refs", "skill_route"}
        )
        try:
            store.create_action(command_id=f"migrate:action:{action_id}", action_id=action_id,
                                intent=_text(item.get("action") or item.get("title") or action_id),
                                endpoint=endpoint, family=family,
                                execution_key=action_id, actor="migration", priority=item.get("priority"),
                                metadata=migrated_metadata)
        except (StoreError, ValueError) as exc:
            report["quarantined"].append({"owner": "queue", "id": action_id, "reason": " ".join(str(exc).split())[:300]})
            continue
        report["imported"]["actions"] += 1
        if reported_metadata:
            report["legacy"].setdefault("action_metadata", []).append({
                "id": action_id,
                "keys": reported_metadata,
                "migrated_keys": sorted(migrated_metadata),
            })


def _family_identity(value: Any) -> str:
    """Normalize a legacy family/class name the way the retired Case owner did."""
    normalized = _text(value).lower().replace("-", "_").replace(" ", "_")
    return {
        "access_control": "authz",
        "authentication_bypass": "authz",
        "authorization": "authz",
        "authorization_bypass": "authz",
    }.get(normalized, normalized)


def _case_context(payload: dict[str, Any], *, present: bool) -> dict[str, Any]:
    """Report Case context counts without judging the file's shape."""
    def count(key: str) -> int:
        value = payload.get(key)
        return len(value) if isinstance(value, dict) else 0

    hypotheses = payload.get("hypotheses") if isinstance(payload.get("hypotheses"), list) else []
    backlog = payload.get("validation_backlog")
    return {
        "present": bool(present),
        "actors": count("actors"),
        "sessions": count("sessions"),
        "objects": count("objects"),
        "hypotheses": len(hypotheses),
        "open_hypotheses": sum(
            1 for item in hypotheses
            if isinstance(item, dict) and _text(item.get("status")).lower() == "open"
        ),
        "backlog_records": len(backlog) if isinstance(backlog, list) else 0,
        "backlog_shape": "list" if isinstance(backlog, list) else ("absent" if backlog is None else "not-a-list"),
    }


def _case_private_ref(root: Path, key: str, value: Any) -> str:
    """Accept only copied, target-owned Case private material."""
    ref = _text(value)
    if not ref:
        return ""
    path = Path(ref)
    if path.is_absolute() or ".." in path.parts or not ref.startswith(".private/case-state/"):
        raise StoreError("case private_ref is outside the target case-state subtree")
    expected_prefix = f".private/case-state/{key}/"
    if not ref.startswith(expected_prefix):
        raise StoreError("case private_ref belongs to another target")
    resolved = (root / ref).resolve()
    if resolved != root / ref or not resolved.is_file():
        raise StoreError(f"case private material is unavailable: {ref}")
    return ref


def _carryable_private_ref(root: Path, ref: str, target: str) -> tuple[str, str]:
    """Return the private reference the Store can carry, or "" plus a reason.

    Private material written before the current contract declares neither its
    target nor a content digest, so the Store cannot verify it and refuses the
    binding.  That material is never rewritten by migration (private user
    material is out of the freeze scope), so the record is imported without the
    binding and the omission is reported instead of being hidden.
    """
    if not ref:
        return "", ""
    try:
        payload = json.loads((root / ref).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ref, ""
    if not isinstance(payload, dict):
        return ref, ""
    if payload.get("target") == target and isinstance(payload.get("content_sha256"), str):
        return ref, ""
    return "", "legacy private material declares no target/content_sha256 and is not rewritten"


def _import_case_context(
    report: dict[str, Any],
    store: TargetStore,
    root: Path,
    canonical: str,
    payload: dict[str, Any],
    origin: str = "",
) -> None:
    """Import Case context facts without importing its retired backlog owner.

    ``origin`` is the single origin observed in the target's own raw material.
    A legacy Case object endpoint recorded in path form (``/rest/basket/1``) is
    resolved against it exactly like a ledger endpoint; when no single origin is
    provable the endpoint stays unresolved and the object is quarantined rather
    than given an invented scheme/host.
    """
    key = store.key
    outcome = report["legacy"].setdefault("case_context_import", {
        "actors": 0, "sessions": 0, "objects": 0, "hypotheses": 0,
        "quarantined": 0,
    })

    actors = payload.get("actors") if isinstance(payload.get("actors"), dict) else {}
    for actor_id, raw in sorted(actors.items()):
        try:
            if not isinstance(raw, dict):
                raise StoreError("actor record is not an object")
            notes = _text(raw.get("notes"))
            if _live_credential_reason(notes):
                raise StoreError("actor notes contain apparent live credential material")
            store.upsert_case_actor(
                command_id=f"migrate:case-actor:{_stable_id(actor_id, raw)}",
                actor_id=_text(actor_id), role=_text(raw.get("role")) or "unknown",
                label=_text(raw.get("label")), notes=notes, actor="migration",
            )
            outcome["actors"] += 1
        except (StoreError, ValueError, TypeError) as exc:
            outcome["quarantined"] += 1
            report["quarantined"].append({
                "owner": "case-state", "kind": "actor", "id": _text(actor_id),
                "reason": " ".join(str(exc).split())[:300],
            })

    sessions = payload.get("sessions") if isinstance(payload.get("sessions"), dict) else {}
    for session_id, raw in sorted(sessions.items()):
        try:
            if not isinstance(raw, dict):
                raise StoreError("session record is not an object")
            notes = _text(raw.get("notes"))
            if _live_credential_reason(notes):
                raise StoreError("session notes contain apparent live credential material")
            private_ref = _case_private_ref(root, key, raw.get("private_ref"))
            private_ref, private_reason = _carryable_private_ref(root, private_ref, canonical)
            if private_reason:
                report["legacy"].setdefault("private_bindings_dropped", []).append({
                    "owner": "case-state", "kind": "session", "id": _text(session_id),
                    "legacy_ref": _text(raw.get("private_ref")), "reason": private_reason,
                })
            store.upsert_case_session(
                command_id=f"migrate:case-session:{_stable_id(session_id, raw)}",
                session_id=_text(session_id), actor_id=_text(raw.get("actor")),
                kind=_text(raw.get("kind")) or "unknown", source=_text(raw.get("source")) or "migration",
                validity=_text(raw.get("validity")) or "unknown",
                last_checked=_text(raw.get("last_checked")), notes=notes,
                private_ref=private_ref, actor="migration",
            )
            outcome["sessions"] += 1
        except (StoreError, ValueError, TypeError) as exc:
            outcome["quarantined"] += 1
            report["quarantined"].append({
                "owner": "case-state", "kind": "session", "id": _text(session_id),
                "reason": " ".join(str(exc).split())[:300],
            })

    objects = payload.get("objects") if isinstance(payload.get("objects"), dict) else {}
    for object_ref, raw in sorted(objects.items()):
        try:
            if not isinstance(raw, dict):
                raise StoreError("object record is not an object")
            notes = _text(raw.get("notes"))
            if _live_credential_reason(notes):
                raise StoreError("object notes contain apparent live credential material")
            private_ref = _case_private_ref(root, key, raw.get("private_ref"))
            private_ref, private_reason = _carryable_private_ref(root, private_ref, canonical)
            if private_reason:
                report["legacy"].setdefault("private_bindings_dropped", []).append({
                    "owner": "case-state", "kind": "object", "id": _text(object_ref),
                    "legacy_ref": _text(raw.get("private_ref")), "reason": private_reason,
                })
            object_endpoint = _text(raw.get("endpoint"))
            if object_endpoint.startswith("/"):
                # Legacy Case objects recorded path-form endpoints.  Resolve
                # against the single observed origin, or leave it empty so the
                # object stays quarantined instead of inventing a host.
                object_endpoint = f"{origin}{object_endpoint}" if origin else ""
                if not object_endpoint:
                    raise StoreError(
                        "case object endpoint is path-form and the target observed no single origin"
                    )
            store.upsert_case_object(
                command_id=f"migrate:case-object:{_stable_id(object_ref, raw)}",
                object_ref=_text(object_ref), object_type=_text(raw.get("type") or raw.get("object_type")) or "unknown",
                object_id=_text(raw.get("object_id")), owner_actor=_text(raw.get("owner_actor")),
                endpoint=object_endpoint, status=_text(raw.get("status")) or "active",
                notes=notes, private_ref=private_ref, actor="migration",
            )
            outcome["objects"] += 1
        except (StoreError, ValueError, TypeError) as exc:
            outcome["quarantined"] += 1
            report["quarantined"].append({
                "owner": "case-state", "kind": "object", "id": _text(object_ref),
                "reason": " ".join(str(exc).split())[:300],
            })

    hypotheses = payload.get("hypotheses") if isinstance(payload.get("hypotheses"), list) else []
    for index, raw in enumerate(hypotheses):
        try:
            if not isinstance(raw, dict):
                raise StoreError("hypothesis record is not an object")
            metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
            sensitive = _sensitive_metadata_paths(metadata)
            if sensitive:
                raise StoreError("hypothesis metadata contains sensitive fields")
            why_now = _text(raw.get("why_now"))
            if _live_credential_reason(why_now):
                raise StoreError("hypothesis rationale contains apparent live credential material")
            store.remember_hypothesis(
                command_id=f"migrate:case-hypothesis:{_stable_id(raw.get('id'), raw)}",
                hypothesis_id=_text(raw.get("id")) or f"legacy-hypothesis-{index + 1}",
                vuln_class=_text(raw.get("vuln_class") or raw.get("family")) or "unknown",
                endpoint=_text(raw.get("endpoint")), object_ref=_text(raw.get("object_ref")),
                actor_ids=[_text(item) for item in raw.get("actors", [])] if isinstance(raw.get("actors"), list) else [],
                why_now=why_now, status=_text(raw.get("status")) or "open", metadata=metadata,
                actor="migration",
            )
            outcome["hypotheses"] += 1
        except (StoreError, ValueError, TypeError) as exc:
            outcome["quarantined"] += 1
            report["quarantined"].append({
                "owner": "case-state", "kind": "hypothesis", "id": _text(raw.get("id")) if isinstance(raw, dict) else "",
                "reason": " ".join(str(exc).split())[:300],
            })


def _backlog_family(record: dict[str, Any]) -> str:
    explicit = _text(record.get("vuln_class") or record.get("family"))
    if explicit:
        return explicit
    return _CASE_RUNNER_FAMILIES.get(_text(record.get("runner")).lower(), "")


def _backlog_endpoint(record: dict[str, Any], origin: str) -> str:
    value = _text(record.get("endpoint") or record.get("baseline_url"))
    if value.startswith("/"):
        return f"{origin}{value}" if origin else ""
    return value


def _queue_backlog_links(actions: list[Any]) -> dict[str, list[str]]:
    """Index the explicit legacy identity carriers, never a text similarity.

    ``action_queue.py``/``validation_runner.py`` 认的显式身份只有三处：
    action 自己的 id、``source_id``、以及 ``metadata.backlog_id``。这里用同一张
    表建索引，所以"有关联"永远是旧文件里写下的相等 id。
    """
    links: dict[str, list[str]] = {}
    for item in actions:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        action_id = _text(item.get("id"))
        if not action_id:
            continue
        carriers = {
            action_id, _text(item.get("source_id")), _text(metadata.get("backlog_id")),
        }
        for carrier in sorted(carriers - {""}):
            bucket = links.setdefault(carrier, [])
            if action_id not in bucket:
                bucket.append(action_id)
    return links


def _endpoint_family_candidates(
    actions: list[Any], endpoint: str, family: str, origin: str,
) -> list[dict[str, Any]]:
    """Actions that merely look like the same dimension: reported, never merged.

    关联判定只看 endpoint 身份；家族是随候选一起报出来的属性（``family_match``），
    不是合并许可。两边都写了家族且不同时，才把明显不同的候选举剔除；任一边家族
    未知时保留下来，因为"未知"正是需要显式决定的东西。
    """
    endpoint_key = canonical_endpoint_identity(endpoint) if endpoint else ""
    if not endpoint_key:
        return []
    family_key = _family_identity(family)
    candidates: list[dict[str, Any]] = []
    for item in actions:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        candidate_endpoint = (
            _text(metadata.get("url")) or _endpoint(metadata, origin) or _text(metadata.get("endpoint"))
        )
        candidate_id = _text(item.get("id"))
        if not candidate_endpoint or not candidate_id:
            continue
        if canonical_endpoint_identity(candidate_endpoint) != endpoint_key:
            continue
        candidate_family = _family_identity(_family(metadata))
        if family_key and candidate_family and candidate_family != family_key:
            continue
        candidates.append({
            "action_id": candidate_id,
            "family_match": "yes" if (family_key and candidate_family == family_key) else "unknown",
        })
    return candidates


def _case_backlog_conflict(
    record: dict[str, Any],
    verdict: dict[str, Any],
    findings: list[dict[str, Any]],
    findings_dir: Path,
    canonical: str,
) -> dict[str, Any] | None:
    """The verdict conflict Case used to arbitrate, now reported by the importer.

    Case 曾把 ``tested_clean``/``dead_end`` 与 canonical finding owner 的终态
    claim 的冲突算成自己的 canonical_conflict。Case 不再裁决它，所以这条判定
    搬到这里：命中即报告，绝不改判任何一方的状态。
    """
    if verdict["status"].lower() not in _CASE_CLEAN_VERDICTS:
        return None
    endpoint_key = canonical_endpoint_identity(verdict["endpoint"]) if verdict["endpoint"] else ""
    family_key = _family_identity(verdict["family"])
    explicit_finding = _text(record.get("finding_id"))
    matches: list[str] = []
    for finding in findings:
        if explicit_finding:
            matched = _text(finding.get("id")) == explicit_finding
        else:
            matched = bool(endpoint_key and family_key) and (
                canonical_endpoint_identity(
                    _text(finding.get("url") or finding.get("endpoint"))
                ) == endpoint_key
                and _family_identity(_family(finding)) == family_key
            )
        if not matched:
            continue
        provenance = verify_finalized_finding_owner_provenance(
            findings_dir, finding, target=canonical
        )
        # 无 owner 凭证的终态声明仍是未决的 canonical claim：允许它在这里被"干净"
        # 覆盖，等于把待修复的凭证问题藏起来。
        if provenance.get("required"):
            matches.append(_text(finding.get("id")))
    if not matches:
        return None
    return {
        "backlog_id": verdict["id"],
        "status": verdict["status"],
        "endpoint": verdict["endpoint"],
        "family": verdict["family"],
        "finding_ids": [item for item in matches[:3] if item],
        "reason": "legacy Case verdict closes a dimension the canonical finding owner still "
                  "holds as a finalized claim; neither verdict is rewritten by the importer",
    }


def _carry_case_backlog(
    report: dict[str, Any],
    *,
    canonical: str,
    backlog: Any,
    queue_actions: list[Any],
    findings: list[dict[str, Any]],
    findings_dir: Path,
    origin: str,
) -> None:
    """Carry legacy Case backlog as reported verdicts, not as merged actions.

    Case 已不是待办的 owner：导入器不归一化它的形状，也不按 endpoint/家族文本
    相似去猜它和哪条 Queue action 是同一件事。只有旧文件里显式写下的相等 id
    构成关联；其余全部隔离并保留原裁决，等一个显式决定（§7.1）。
    """
    if backlog is None:
        return
    if not isinstance(backlog, list):
        report["quarantined"].append({
            "owner": "case-state",
            "reason": f"legacy validation_backlog is {type(backlog).__name__}, not a list; "
                      "its records are not reinterpreted",
        })
        return
    records = [item for item in backlog if isinstance(item, dict)]
    for index, item in enumerate(backlog):
        if not isinstance(item, dict):
            report["quarantined"].append({
                "owner": "case-state", "reason": f"validation_backlog[{index}] is not an object",
            })
    report["legacy"]["unknown_fields"]["case_backlog"] = _scan_unknown_fields(records, _CASE_BACKLOG_FIELDS)
    links = _queue_backlog_links(queue_actions)
    for record in records:
        record_id = _text(record.get("id"))
        endpoint = _backlog_endpoint(record, origin)
        family = _backlog_family(record)
        verdict = {
            "id": record_id,
            "status": _text(record.get("status")),
            "endpoint": endpoint or _text(record.get("endpoint") or record.get("baseline_url")),
            "family": family,
            "runner": _text(record.get("runner")),
            "priority": record.get("priority"),
            "hypothesis_id": _text(record.get("hypothesis_id")),
            "evidence_ref": _text(record.get("evidence_ref")),
        }
        report["legacy"]["case_backlog"].append(verdict)
        if not record_id:
            report["quarantined"].append({
                "owner": "case-state", "reason": "backlog record has no id; its verdict is preserved "
                                                 "in legacy.case_backlog",
                "endpoint": verdict["endpoint"], "status": verdict["status"],
            })
            continue
        bound = links.get(record_id, [])
        if len(bound) == 1:
            report["legacy"]["case_backlog_relations"].append({
                "backlog_id": record_id, "action_id": bound[0], "basis": "explicit-id-in-queue-record",
            })
        elif len(bound) > 1:
            report["legacy"]["case_backlog_relations"].append({
                "backlog_id": record_id, "action_ids": bound, "basis": "explicit-id-matches-several-actions",
            })
            report["quarantined"].append({
                "owner": "case-state", "id": record_id,
                "reason": "the legacy backlog id is carried by several Queue actions; the identity "
                          "stays unresolved until an explicit decision names one",
            })
        else:
            report["quarantined"].append({
                "owner": "case-state", "id": record_id,
                "reason": "no explicit identity link to the one action source; a Case backlog record "
                          "is never merged by endpoint/family text similarity",
                "endpoint": verdict["endpoint"], "family": family, "status": verdict["status"],
            })
            candidates = _endpoint_family_candidates(queue_actions, verdict["endpoint"], family, origin)
            if candidates:
                report["legacy"]["case_backlog_relations"].append({
                    "backlog_id": record_id,
                    "action_ids": [row["action_id"] for row in candidates],
                    "candidate_family_match": sorted({row["family_match"] for row in candidates}),
                    "basis": "endpoint-candidate", "requires_explicit_decision": True,
                })
        conflict = _case_backlog_conflict(record, verdict, findings, findings_dir, canonical)
        if conflict:
            report["legacy"]["case_backlog_conflicts"].append(conflict)


def _migration_scope(root: Path, target: str) -> dict[str, Any]:
    """Scope is an explicit migration input, never inferred from target notes."""
    path = scope_source_path(root, target)
    if path.exists() or path.is_symlink():
        return read_scope_source(root, target)["manifest"]
    memory_dir = root / "hunt-memory"
    profile_path = target_profile_path(memory_dir, target)
    external_memory = os.environ.get("HUNT_MEMORY_DIR")
    if (external_memory and Path(external_memory).expanduser().resolve() != memory_dir.resolve()
            and target_profile_path(Path(external_memory).expanduser(), target).exists()
            and not profile_path.exists()):
        raise StoreError("export the external target Profile into the isolated source hunt-memory before migration")
    if profile_path.resolve() != profile_path:
        raise StoreError(f"Scope Profile must not traverse symlinks: {profile_path}")
    return scope_source_from_profile(load_target_profile(memory_dir, target), target)


def import_target(
    repo_root: str | Path,
    target: str,
    *,
    initialize: bool = False,
    disposition_ledger: str | Path | dict[str, Any] | None = None,
    source_manifest_sha256: str = "",
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Import legacy target metadata into ``repo_root``.

    ``source_root`` is the root the legacy records were written against -- the
    directory the operator ran in.  It is required to resolve a legacy absolute
    ``evidence_ref`` (see ``_rebase_source_absolute_ref``); the unified staging
    path passes the export root explicitly instead of letting the importer infer
    one from the references it is trying to validate.
    """
    root = Path(repo_root).resolve()
    rebase_root = Path(source_root).resolve() if source_root is not None else root
    canonical = canonical_target_value(target)
    scope_manifest = _migration_scope(root, canonical)
    disposition_payload, disposition_digest = _load_disposition_ledger(disposition_ledger)
    expected_manifest = _migration_manifest(root, canonical)
    expected_manifest_sha256 = source_manifest_sha256 or expected_manifest["sha256"]
    _validate_disposition_binding(disposition_payload, canonical, expected_manifest_sha256)
    sources = _legacy_sources(root, canonical)
    report = _empty_report(canonical, sources)
    report["legacy"]["report_artifacts"] = _report_artifact_inventory(root, target_storage_key(canonical))
    report["legacy"]["target_memory"] = _target_memory_disposition(root, canonical)
    if report["legacy"]["target_memory"].get("status") == "quarantined":
        report["quarantined"].append({
            "owner": "target-memory",
            "path": report["legacy"]["target_memory"].get("path", ""),
            "reason": report["legacy"]["target_memory"].get("disposition", "target-memory unavailable"),
        })
    for owner in ("queue", "findings"):
        if "error" in sources[owner]:
            report["quarantined"].append({"owner": owner, "reason": sources[owner]["error"]})
    ledger_status = sources["ledger"].get("status")
    if ledger_status not in {"missing", "valid"}:
        invalid = sources["ledger"].get("invalid_rows") or []
        ledger_path = sources["ledger"].get("path", "")
        for row in invalid:
            report["quarantined"].append({
                "owner": "ledger", "path": ledger_path,
                "line": row.get("line"), "reason": row.get("reason"),
            })
        if sources["ledger"].get("read_error"):
            report["quarantined"].append({
                "owner": "ledger", "path": ledger_path,
                "reason": sources["ledger"]["read_error"],
            })
        remaining = int(sources["ledger"].get("invalid_count") or 0) - len(invalid)
        if remaining > 0:
            report["quarantined"].append({
                "owner": "ledger", "path": ledger_path,
                "reason": f"{remaining} further invalid ledger rows are not listed individually",
            })
        if invalid and not sources["ledger"].get("read_error"):
            # The loader trusts only the prefix before the first invalid row;
            # everything after it is unread.  Count it so the report accounts
            # for every row in the file instead of only the broken one.
            tail = _unread_tail_rows(ledger_path, sources["ledger"].get("last_valid_offset") or 0)
            report["quarantined"].append({
                "owner": "ledger", "path": ledger_path,
                "reason": "rows past the trusted prefix were not read (trusted-prefix rule): "
                          + (f"{tail} row(s)" if tail >= 0 else "tail unreadable"),
            })
        if not invalid and not sources["ledger"].get("read_error"):
            report["quarantined"].append({
                "owner": "ledger", "path": ledger_path, "reason": ledger_status,
            })
    store = TargetStore(root, canonical, allow_preview=True)
    if store.path.exists():
        if not initialize:
            raise StoreError(f"destination already exists: {store.path}; use a fresh isolated copy")
    else:
        # Legacy files exist by definition in the isolated copy this importer
        # operates on; the live-target guard is asserted by the copy assertion.
        store.initialize(allow_legacy=True)
    with target_cutover_lock(root, canonical):
        write_scope_source_locked(root, canonical, scope_manifest)
    report["scope"] = scope_manifest
    entries = [row for row in sources["ledger"].get("entries", []) if isinstance(row, dict)]
    for row in sources["ledger"].get("entries", []):
        if not isinstance(row, dict):
            report["quarantined"].append({"owner": "ledger", "reason": "ledger entry is not an object"})
    findings = [row for row in sources["findings"].get("findings", []) if isinstance(row, dict)]
    for row in sources["findings"].get("findings", []):
        if not isinstance(row, dict):
            report["quarantined"].append({"owner": "findings", "reason": "finding is not an object"})
    report["legacy"]["unknown_fields"] = {
        "queue": _scan_unknown_fields(sources["queue"].get("actions", []), _QUEUE_ITEM_FIELDS),
        "findings": _scan_unknown_fields(sources["findings"].get("findings", []), _FINDING_FIELDS),
        "ledger": _scan_unknown_fields(entries, _LEDGER_FIELDS),
        # case_state / case_backlog 由后面的 Case carry 填充：Case 侧漂移只在
        # 文件真的可读且属于本目标时才扫描。
        "case_state": {},
        "case_backlog": {},
    }
    origins = _import_ledger(report, store, root, canonical, entries, findings, rebase_root)
    # A legacy path endpoint is only resolved when the target's own material
    # shows exactly one origin; otherwise the record stays quarantined.
    report["legacy"]["observed_origins"] = sorted(origins)
    origin = next(iter(origins)) if len(origins) == 1 else ""
    report["legacy"]["path_endpoint_origin"] = origin
    queue_actions = list(sources["queue"].get("actions", []))
    declared_queue_target = _text(sources["queue"].get("target"))
    if declared_queue_target and canonical_target_value(declared_queue_target) != canonical:
        report["legacy"]["target_conflicts"].append({
            "owner": "queue", "declared_target": declared_queue_target, "expected_target": canonical,
        })
        report["quarantined"].append({
            "owner": "queue",
            "reason": f"action queue declares target {declared_queue_target}, not {canonical}; "
                      f"{len(queue_actions)} action(s) are imported by nobody",
        })
        queue_actions = []
    _import_queue(report, store, origin, queue_actions)
    case_state = sources["case_state"]
    case_payload = case_state.get("payload") if isinstance(case_state.get("payload"), dict) else {}
    case_error = _text(case_state.get("error"))
    declared_case_target = _text(case_state.get("declared_target"))
    if case_error:
        report["quarantined"].append({
            "owner": "case-state", "path": _text(case_state.get("path")),
            "reason": f"case state is unreadable and is not reinterpreted as empty context: {case_error}",
        })
    elif declared_case_target and canonical_target_value(declared_case_target) != canonical:
        report["legacy"]["target_conflicts"].append({
            "owner": "case-state", "declared_target": declared_case_target, "expected_target": canonical,
        })
        report["quarantined"].append({
            "owner": "case-state", "path": _text(case_state.get("path")),
            "reason": f"case state declares target {declared_case_target}, not {canonical}; "
                      "its context and legacy backlog records are imported by nobody",
        })
    elif case_state.get("exists"):
        report["legacy"]["unknown_fields"]["case_state"] = _scan_unknown_fields(
            [case_payload], _CASE_STATE_FIELDS
        )
        report["legacy"]["case_context"] = _case_context(case_payload, present=True)
        _import_case_context(report, store, root, canonical, case_payload, origin)
        _carry_case_backlog(
            report, canonical=canonical,
            backlog=case_payload.get("validation_backlog"),
            queue_actions=queue_actions, findings=findings,
            findings_dir=root / "findings" / store.key, origin=origin,
        )
    ledger_refs = {_text(entry.get("evidence_ref")) for entry in entries if isinstance(entry, dict)}
    report["legacy"]["unreferenced_material"] = _unreferenced_material(root, store.key, ledger_refs)
    report["legacy"]["ledger_results"] = {
        result: sum(1 for row in entries if _text(row.get("result")) == result)
        for result in sorted({_text(row.get("result")) for row in entries if _text(row.get("result"))})
    }
    _import_target_memory(report, store, root, canonical, expected_manifest)
    _import_coverage_reviews(report, store, root, canonical, expected_manifest)
    if report["quarantined"]:
        report["status"] = "partial"
    _apply_disposition_ledger(
        report,
        disposition_payload,
        disposition_digest,
        canonical,
        expected_manifest_sha256,
    )
    return report


def backfill_coverage_reviews(source_root: str | Path, repo_root: str | Path, target: str) -> dict:
    """Import annotations from the pinned cutover source without replacing new reviews."""
    source_root, root = Path(source_root).resolve(), Path(repo_root).resolve()
    if source_root == root or source_root in root.parents or root in source_root.parents:
        raise StoreError("coverage backfill source and active target must be separate roots")
    canonical = canonical_target_value(target)
    store = TargetStore(root, canonical)
    store.coverage_review_page(limit=1)
    with _backfill_receipt_lock(root, canonical) as receipt_path:
        receipt, manifest, digest = _load_active_backfill_receipt(store, receipt_path, canonical)
        report = {"legacy": {}, "quarantined": []}
        source = _import_coverage_reviews(report, store, source_root, canonical, manifest)
        if source["status"] == "missing":
            raise StoreError("coverage source is absent from the cutover manifest")
        backfill = {"source_manifest_sha256": digest, **source}
        receipt["coverage_backfill"] = backfill
        _publish_backfill_receipt(receipt_path, receipt)
        return {"target": canonical, "store_id": receipt["store_id"], **backfill,
                "status": "partial" if report["quarantined"] else "complete"}


def backfill_target_memory(source_root: str | Path, repo_root: str | Path, target: str) -> dict[str, Any]:
    """Explicitly import a cutover source's target memory into its active Store."""
    source_root, root = Path(source_root).resolve(), Path(repo_root).resolve()
    if source_root == root or source_root in root.parents or root in source_root.parents:
        raise StoreError("memory backfill source and active target must be separate roots")
    canonical = canonical_target_value(target)
    with _backfill_receipt_lock(root, canonical) as receipt_path:
        return _backfill_target_memory_locked(source_root, root, canonical, receipt_path)


@contextmanager
def _backfill_receipt_lock(root: Path, canonical: str):
    receipt_path = root / "state" / target_storage_key(canonical) / "migration-receipt.json"
    lock_path = receipt_path.with_suffix(".lock")
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise StoreError(f"memory backfill lock is unavailable: {lock_path}") from exc
    with os.fdopen(fd, "r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield receipt_path
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _backfill_target_memory_locked(source_root: Path, root: Path, canonical: str,
                                   receipt_path: Path) -> dict[str, Any]:
    store = TargetStore(root, canonical)
    receipt, manifest, files_digest = _load_active_backfill_receipt(store, receipt_path, canonical)
    relative = f"memory/goals/targets/{target_storage_key(canonical)}.json"
    source = next((item for item in manifest["files"]
                   if isinstance(item, dict) and item.get("path") == relative), None)
    if source is None:
        raise StoreError(f"target-memory source is absent from migration manifest: {relative}")
    existing = receipt.get("memory_backfill")
    if existing is not None:
        path = source_root / relative
        if (not isinstance(existing, dict) or path.is_symlink() or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != source.get("sha256")
                or existing.get("source_sha256") != source.get("sha256")
                or existing.get("source_manifest_sha256") != files_digest
                or not isinstance(existing.get("experience_map"), list)):
            raise StoreError("existing memory backfill does not match the source manifest")
        for item in existing["experience_map"]:
            if not isinstance(item, dict) or not isinstance(item.get("experience_id"), str):
                raise StoreError("existing memory backfill has an invalid experience map")
            store.experience(item["experience_id"])
        quarantined = existing.get("quarantined") or []
        if not isinstance(quarantined, list):
            raise StoreError("existing memory backfill has an invalid quarantine list")
        return {"target": canonical, "status": "partial" if quarantined else "complete",
                "store_id": receipt["store_id"], "source_manifest_sha256": files_digest,
                "source_sha256": existing["source_sha256"],
                "experience_map": existing["experience_map"], "quarantined": quarantined}
    report = {"target": canonical, "status": "ready", "quarantined": [],
              "legacy": {"target_memory": {"status": "valid"}}}
    _import_target_memory(report, store, source_root, canonical, manifest)
    memory = report["legacy"]["target_memory"]
    if memory["status"] != "valid":
        raise StoreError(f"target-memory source is invalid: {memory['disposition']}")
    backfill = {"source_manifest_sha256": files_digest, "source_sha256": memory["source_sha256"],
                "experience_map": memory["experience_map"], "quarantined": report["quarantined"]}
    receipt["memory_backfill"] = backfill
    _publish_backfill_receipt(receipt_path, receipt)
    return {"target": canonical, "status": "partial" if report["quarantined"] else "complete",
            "store_id": receipt["store_id"], **backfill}


def _load_active_backfill_receipt(store: TargetStore, receipt_path: Path,
                                  canonical: str) -> tuple[dict, dict, str]:
    if store.backend() != "primary":
        raise StoreError("historical backfill requires an active primary target Store")
    if receipt_path.is_symlink():
        raise StoreError(f"migration receipt must not be a symlink: {receipt_path}")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StoreError(f"migration receipt is unavailable: {receipt_path}") from exc
    if not isinstance(receipt, dict):
        raise StoreError(f"migration receipt is not an object: {receipt_path}")
    manifest = receipt.get("source_manifest")
    if (receipt.get("target") != canonical or receipt.get("store_id") != store.binding()["store_id"]
            or receipt.get("activation_status") != "active" or not isinstance(manifest, dict)
            or manifest.get("target") != canonical or not isinstance(manifest.get("files"), list)):
        raise StoreError("historical backfill requires the matching active migration receipt")
    files_digest = hashlib.sha256(json.dumps(manifest["files"], ensure_ascii=True, sort_keys=True,
                                           separators=(",", ":")).encode("utf-8")).hexdigest()
    if files_digest != manifest.get("sha256") or files_digest != receipt.get("source_manifest_sha256"):
        raise StoreError("historical backfill source manifest does not match migration receipt")
    return receipt, manifest, files_digest


def _publish_backfill_receipt(receipt_path: Path, receipt: dict) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=receipt_path.parent,
                                         prefix=".memory-backfill-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            json.dump(receipt, handle, ensure_ascii=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(receipt_path)
        directory_fd = os.open(receipt_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def backfill_target_patterns(source_root: str | Path, repo_root: str | Path, target: str) -> dict[str, Any]:
    """Import target-owned rows from a pinned historical PatternDB snapshot."""
    source_root, root = Path(source_root).resolve(), Path(repo_root).resolve()
    if source_root == root or source_root in root.parents or root in source_root.parents:
        raise StoreError("pattern backfill source and active target must be separate roots")
    canonical = canonical_target_value(target)
    with _backfill_receipt_lock(root, canonical) as receipt_path:
        store = TargetStore(root, canonical)
        receipt, _, manifest_digest = _load_active_backfill_receipt(store, receipt_path, canonical)
        base = source_root / "hunt-memory" / "patterns.jsonl"
        paths = [base.with_suffix(base.suffix + f".{index}") for index in (3, 2, 1)] + [base]
        snapshots = []
        for path in paths:
            if path.is_symlink():
                raise StoreError(f"PatternDB source must not be a symlink: {path}")
            if not path.exists():
                continue
            if not path.is_file():
                raise StoreError(f"PatternDB source is not a regular file: {path}")
            raw = path.read_bytes()
            snapshots.append((path.relative_to(source_root).as_posix(), raw))
        if not snapshots:
            raise StoreError(f"PatternDB source is unavailable: {base}")
        files = [{"path": relative, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                 for relative, raw in snapshots]
        existing = receipt.get("pattern_backfill")
        if existing is not None:
            if (not isinstance(existing, dict) or existing.get("source_files") != files
                    or existing.get("source_manifest_sha256") != manifest_digest
                    or existing.get("status") not in {"pending", "complete", "partial"}):
                raise StoreError("existing PatternDB backfill does not match the pinned source")
            if existing["status"] != "pending":
                mapping = existing.get("experience_map")
                if not isinstance(mapping, list):
                    raise StoreError("existing PatternDB backfill has an invalid experience map")
                for item in mapping:
                    if not isinstance(item, dict) or not isinstance(item.get("experience_id"), str):
                        raise StoreError("existing PatternDB backfill has an invalid experience map")
                    store.experience(item["experience_id"])
                return {"target": canonical, "store_id": receipt["store_id"], **existing}
        else:
            existing = {"status": "pending", "source_manifest_sha256": manifest_digest,
                        "source_files": files}
            receipt["pattern_backfill"] = existing
            _publish_backfill_receipt(receipt_path, receipt)

        mapped, quarantined = [], []
        for relative, raw in snapshots:
            for line_number, raw_line in enumerate(raw.split(b"\n"), 1):
                if not raw_line.strip():
                    continue
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeError:
                    quarantined.append({"source_path": relative, "line": line_number,
                                        "reason": "PatternDB row is not UTF-8"})
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    quarantined.append({"source_path": relative, "line": line_number,
                                        "reason": "PatternDB row is not JSON"})
                    continue
                if not isinstance(item, dict) or not isinstance(item.get("target"), str) or not item["target"].strip():
                    quarantined.append({"source_path": relative, "line": line_number,
                                        "reason": "PatternDB row has no target identity"})
                    continue
                if item["target"] != canonical:
                    continue
                try:
                    validate_pattern_entry(item)
                    technique, family = item["technique"], item["vuln_class"]
                    stack, endpoint, notes = item["tech_stack"], item.get("endpoint", ""), item.get("notes", "")
                    conditions = "Historical tech stack: " + (", ".join(stack) or "unknown")
                    if (not isinstance(family, str) or not family.strip() or len(family) > 256
                            or len(technique) > 1024 or text_is_polluted(technique)
                            or any(len(value) > 128 for value in stack) or len(stack) > 16
                            or not isinstance(endpoint, str) or len(endpoint) > 1024
                            or not isinstance(notes, str) or len(notes) > 2048 or text_is_polluted(notes)
                            or len(conditions) > 2048
                            or any("\x00" in value for value in (family, technique, endpoint, notes, *stack))):
                        raise ValueError("PatternDB row contains invalid or polluted experience fields")
                    outcome = item.get("outcome", "unknown")
                    statement = (f"Historical PatternDB (unverified; outcome={outcome}): "
                                 f"{technique} [family={family}; endpoint={endpoint or 'unknown'}]"
                                 + (f"; {notes}" if notes else ""))
                    if len(statement) > 4096:
                        raise ValueError("PatternDB experience statement is oversized")
                except (SchemaError, ValueError, TypeError) as exc:
                    quarantined.append({"source_path": relative, "line": line_number,
                                        "reason": " ".join(str(exc).split())[:240]})
                    continue
                command_id = "legacy-pattern:" + _stable_id(canonical, relative, line_number)
                result = store.remember(command_id=command_id, kind="note", statement=statement,
                                        conditions=conditions,
                                        reopen_when="", next_intent="", evidence=[], actor="migration")
                mapped.append({"experience_id": result["entity_id"], "source_path": relative,
                               "line": line_number, "source_line_sha256": hashlib.sha256(raw_line).hexdigest(),
                               "source_ts": item["ts"], "outcome": outcome})
        existing.update(status="partial" if quarantined else "complete",
                        experience_map=mapped, quarantined=quarantined)
        _publish_backfill_receipt(receipt_path, receipt)
        return {"target": canonical, "store_id": receipt["store_id"], **existing}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview or explicitly stage/publish/promote target migration")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--target", required=True)
    parser.add_argument("--import-source", default="", help="Explicit source root for an isolated staged import")
    parser.add_argument("--destination-root", default="", help="New destination root for staging or publish")
    parser.add_argument("--publish-staging", default="", help="Publish an existing completed staging root")
    parser.add_argument("--disposition-ledger", default="", help="JSON disposition ledger for staged import")
    parser.add_argument("--promote", action="store_true", help="Explicitly activate a published preview as primary")
    parser.add_argument("--restore-legacy", action="store_true", help="Explicitly restore pre-primary legacy metadata from the archive")
    parser.add_argument("--source-manifest-sha256", default="")
    parser.add_argument("--backfill-memory-source", default="", help="Explicit isolated cutover source root for historical target memory")
    parser.add_argument("--backfill-pattern-source", default="", help="Explicit isolated source root for historical PatternDB rows")
    parser.add_argument("--backfill-coverage-source", default="", help="Explicit isolated cutover source root for historical Coverage reviews")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if sum(bool(value) for value in (args.backfill_memory_source, args.backfill_pattern_source, args.backfill_coverage_source, args.restore_legacy,
                                     args.promote, args.publish_staging, args.import_source)) > 1:
        parser.error("choose exactly one migration operation")
    if args.disposition_ledger and not args.import_source:
        parser.error("--disposition-ledger is only applied with --import-source; it was not read")
    try:
        if args.backfill_coverage_source:
            result = backfill_coverage_reviews(args.backfill_coverage_source, args.repo_root, args.target)
        elif args.backfill_memory_source:
            result = backfill_target_memory(args.backfill_memory_source, args.repo_root, args.target)
        elif args.backfill_pattern_source:
            result = backfill_target_patterns(args.backfill_pattern_source, args.repo_root, args.target)
        elif args.restore_legacy:
            result = restore_legacy_metadata(
                args.repo_root,
                args.target,
                source_manifest_sha256=args.source_manifest_sha256,
            )
        elif args.promote:
            result = promote_target(args.repo_root, args.target, source_manifest_sha256=args.source_manifest_sha256)
        elif args.publish_staging:
            if not args.destination_root:
                parser.error("--destination-root is required with --publish-staging")
            result = publish_preview(args.publish_staging, args.destination_root, args.target)
        elif args.import_source:
            if not args.destination_root:
                parser.error("--destination-root is required with --import-source")
            result = import_target_staged(
                args.import_source,
                args.destination_root,
                args.target,
                disposition_ledger=args.disposition_ledger or None,
            )
        else:
            result = preview_target(args.repo_root, args.target)
    except (OSError, ValueError, StoreError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result.get("status") == "partial" else 0


if __name__ == "__main__":
    raise SystemExit(main())
