#!/usr/bin/env python3
"""Deterministic validation runner for Claude-driven security findings.

Validation Runner v1 intentionally stays small:

- request-diff: AI-supplied exact baseline/variant replay across one input dimension.
- record-evidence: register already-executed native observations without replay.
- review-candidate: close/reopen one exact evidence bundle with an explicit receipt.

AI 仍负责选择 hypothesis、解释业务影响、决定是否升级/降级；本工具只负责稳定
执行 replay / diff / evidence bundle / ledger 写入。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.artifact_io import write_json_atomic as _write_json, publish_bytes_create_only
    from tools.browser_evidence import read_target_artifact, read_browser_observation_capture
    from tools.auth_session import AuthSession, add_cli_args, session_from_args
    from tools.contracts import WIRE_FACT_NAMES, WIRE_NEEDLE_FACT_NAMES, artifact_digest_material, runner_operation_id, validate_observed_difference, runner_summary_lane
    from tools.evidence_identity import normalize_actor, normalize_object_scope, normalize_variant
    from tools.response_diff import diff_responses, snapshot_response
    from tools.request_diff import RequestPairError, request_pair_digest, validate_request_pair
    from tools.runner_candidate_review import review_candidate
    from tools.browser_surface import public_url_shape
    from tools.evidence_identity import canonical_endpoint_identity, canonical_vuln_class, normalize_family, exact_endpoint_identity
    from tools.identity_contract import ClosureCellKey
    from tools.private_artifacts import private_artifact_dir, write_private_json, write_private_text
    from tools.target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref
    from tools.scope_context import url_belongs_to_target
    from tools.scope_source import load_scope_context
    from tools.autopilot_continuation import load_execution_scope, resolve_context_file
    from tools.target_store import FindingNotFoundError, StoreError, TargetStore, runtime_store, target_switch_lock, validate_cleanup_confirmation
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_json_atomic as _write_json, publish_bytes_create_only
    from browser_evidence import read_target_artifact, read_browser_observation_capture
    from auth_session import AuthSession, add_cli_args, session_from_args  # type: ignore
    from contracts import WIRE_FACT_NAMES, WIRE_NEEDLE_FACT_NAMES, artifact_digest_material, runner_operation_id, validate_observed_difference, runner_summary_lane  # type: ignore
    from evidence_identity import normalize_actor, normalize_object_scope, normalize_variant  # type: ignore
    from response_diff import diff_responses, snapshot_response  # type: ignore
    from request_diff import RequestPairError, request_pair_digest, validate_request_pair  # type: ignore
    from runner_candidate_review import review_candidate
    from browser_surface import public_url_shape  # type: ignore
    from evidence_identity import canonical_endpoint_identity, canonical_vuln_class, normalize_family, exact_endpoint_identity  # type: ignore
    from identity_contract import ClosureCellKey  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_json, write_private_text  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref  # type: ignore
    from scope_context import url_belongs_to_target  # type: ignore
    from scope_source import load_scope_context  # type: ignore
    from autopilot_continuation import load_execution_scope, resolve_context_file
    from target_store import FindingNotFoundError, StoreError, TargetStore, runtime_store, target_switch_lock, validate_cleanup_confirmation  # type: ignore


SCHEMA_VERSION = 1
MAX_RESPONSE_BYTES = 1024 * 1024


class RequestPreflightError(ValueError):
    """Reject a request pair before any network I/O."""


# Parser/DB error markers. Category-agnostic: any declared fact that names a
# DB/parser error marker (``error_marker_variant_only``) is checked with this,
# regardless of which vulnerability family the AI is testing.
DB_ERROR_MARKER_RE = re.compile(
    r"SQL syntax|sqlite|mysql|mariadb|postgres|postgresql|psql|oracle|ORA-\d+|"
    r"mssql|SQL Server|ODBC|JDBC|PDOException|SequelizeDatabaseError|"
    r"near ['\"][^'\"]+['\"]: syntax error|unterminated quoted string|"
    r"MongoError|CastError|BSON|NoSQL",
    re.I,
)

RUNNER_RESULT_TO_FINDING_STATUS = {
    # validation_runner 只证明候选证据包，不代表 /validate gate 已通过。
    "tested_finding": "candidate",
    "candidate": "candidate",
    "tested_clean": "rejected",
    "dead_end": "rejected",
}

def _request_body_text(body: Any, headers: dict[str, str]) -> str:
    """Serialize a text/JSON body without inventing an input value."""
    if body in (None, ""):
        return ""
    if isinstance(body, str):
        return body
    content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    ).lower()
    if "application/x-www-form-urlencoded" in content_type and isinstance(body, dict):
        return urllib.parse.urlencode(body, doseq=True)
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def _safe_id(value: str, default: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._:-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned[:120] or default


def _default_finding_id(lane: str, url: str, method: str = "", family: str = "") -> str:
    """Derive the default Finding ID from the full finding identity.

    The cleaned path stays as the readable stem, but a short digest over
    method+url+family keeps distinct endpoints (e.g. /a/b vs /a_b, or the
    same path under a different method/class) from colliding into one ID
    while identical identities still derive the same idempotent ID.
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "root"
    suffix = _safe_id(path.replace("/", "_"), "endpoint")
    identity = f"{str(method or '').upper()}|{str(url or '')}|{str(family or '')}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8]
    return f"{lane}-{suffix}-{digest}"


def _bundle_dir(repo_root: Path, target: str, finding_id: str) -> Path:
    target_key = target_storage_key(canonical_target_value(target))
    path = (
        repo_root
        / "evidence"
        / target_key
        / "validation"
        / _safe_id(finding_id, "finding")
        / _run_id()
    )
    path.mkdir(parents=True, exist_ok=False)
    return path


def _private_bundle_dir(repo_root: Path, target: str, bundle: Path) -> Path:
    target_key = target_storage_key(canonical_target_value(target))
    relative = bundle.relative_to(repo_root / "evidence" / target_key / "validation")
    return private_artifact_dir(repo_root, "validation", target_key, str(relative))


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _summary_path(summary: dict[str, Any], repo_root: Path) -> Path | None:
    raw = str(summary.get("summary_path") or "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = repo_root / path
    return path


def _file_sha256(repo_root: Path, ref: str) -> str:
    path = Path(str(ref or ""))
    if not path.is_absolute():
        path = repo_root / path
    try:
        resolved = path.resolve()
        resolved.relative_to(repo_root.resolve())
        data = resolved.read_bytes()
    except (OSError, ValueError):
        return ""
    return hashlib.sha256(data).hexdigest()


def _artifact_bindings(summary: dict[str, Any], repo_root: Path) -> list[dict[str, str]]:
    """Bind every existing runner artifact path to its current content."""
    bindings: dict[tuple[str, str], dict[str, str]] = {}

    def visit(value: Any, *, artifact_map: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                nested_map = artifact_map or key == "artifacts" or key.endswith("_artifacts")
                if nested_map and isinstance(item, str):
                    ref = item.strip()
                    if ref:
                        bindings[(key, ref)] = {
                            "kind": key,
                            "ref": ref,
                            "sha256": _file_sha256(repo_root, ref),
                        }
                else:
                    visit(item, artifact_map=nested_map)
        elif isinstance(value, list):
            for item in value:
                visit(item, artifact_map=artifact_map)

    visit(summary)
    return [bindings[key] for key in sorted(bindings)]


def _runner_operation_id_compat(material: dict[str, Any]) -> str:
    # 已上移 tools/contracts.runner_operation_id（证据消费方不再反向依赖执行器）；
    # 旧私有名保留为兼容导出，tests/历史调用不破坏。
    return runner_operation_id(material)


_artifact_digest_material = artifact_digest_material
_runner_operation_id = _runner_operation_id_compat


def _stable_operation_material(value: Any) -> Any:
    if isinstance(value, dict):
        material = {}
        for key, item in value.items():
            if key in {
                "artifacts",
                "generated_at",
                "operation_id",
                "event_id",
                "summary_path",
                "sync",
                "ledger_record",
                "operation_material",
                "evidence_ref",
            }:
                continue
            if key == "artifact_bindings" and isinstance(item, list):
                material[key] = [
                    {"kind": binding.get("kind"), "sha256": binding.get("sha256")}
                    for binding in item
                    if isinstance(binding, dict)
                ]
            else:
                material[key] = _stable_operation_material(item)
        return material
    if isinstance(value, list):
        return [_stable_operation_material(item) for item in value]
    return value


def _finalize_runner_summary(summary: dict[str, Any], path: Path, repo_root: Path,
                             *, backend_binding: dict[str, str]) -> dict[str, Any]:
    _, current = _runner_backend(repo_root, str(summary["target"]))
    if current != backend_binding:
        raise StoreError("runner backend changed before material publication")
    summary["backend_binding"] = backend_binding
    summary["summary_path"] = _rel(path, repo_root)
    artifact_bindings = _artifact_bindings(summary, repo_root)
    summary["artifact_bindings"] = artifact_bindings
    ledger = summary.get("ledger_record") if isinstance(summary.get("ledger_record"), dict) else {}
    # The ledger row is an output, not an identity authority.  Runner-created
    # rows carry their exact input material in memory; summaries reloaded from
    # disk fall back to the stable internal summary projection.  In both cases,
    # a caller-supplied nested ``ledger_record.operation_id`` is ignored.
    operation_material = ledger.pop("_runner_operation_material", None)
    if not isinstance(operation_material, dict):
        operation_material = _stable_operation_material(summary)
    else:
        operation_material = dict(operation_material)
    operation_material.pop("evidence_ref", None)
    operation_material["artifact_bindings"] = _artifact_digest_material(artifact_bindings)
    summary["operation_material"] = operation_material
    operation_id = _runner_operation_id(operation_material)
    if ledger:
        ledger["operation_id"] = operation_id
        ledger["event_id"] = f"ledger:{hashlib.sha256(operation_id.encode('utf-8')).hexdigest()[:24]}"
    summary["operation_id"] = operation_id
    _write_json(path, summary)
    return summary


def _runner_backend(repo_root: Path, target: str) -> tuple[TargetStore, dict[str, str]]:
    store = runtime_store(repo_root, target)
    binding = store.binding()
    return store, {key: str(binding[key]) for key in ("target", "backend", "store_id")}


@contextmanager
def _runner_admission(repo_root: Path, target: str, *, expected: dict[str, str] | None = None):
    # Hold only the cutover coordination lock across execution, never a DB transaction.
    with target_switch_lock(repo_root, target):
        store, binding = _runner_backend(repo_root, target)
        if expected is not None and binding != expected:
            raise StoreError("runner backend changed; registration cannot switch owner or generation")
        yield store, binding


def _store_candidate(store: TargetStore, finding_id: str) -> dict[str, str] | None:
    if not finding_id:
        return None
    finding = store.finding(finding_id)
    return {
        "id": finding_id,
        "endpoint": str(finding["endpoint"]),
        "method": str(finding["method"]),
        "family": str(finding["family"]),
        "title": str(finding["title"]),
        "claim": str(finding["claim"]),
    }


def _runner_command_context(store: TargetStore, *, action_id: str | None,
                            claim_token: str | None, command_actor: str,
                            endpoint: str, family: str) -> dict[str, str]:
    """Keep the command operator separate from observed HTTP actors."""
    if (action_id is None) != (claim_token is None):
        raise StoreError("runner action_id and claim_token must be supplied together")
    if action_id is None and command_actor == "validation-runner":
        return {}
    context = {"command_actor": command_actor}
    if action_id is not None:
        action = store.action(action_id)
        if action["kind"] != "execution":
            raise StoreError("only execution actions can own execution attempts")
        if (action["endpoint"], action["family"]) != (endpoint, normalize_family(family)):
            raise StoreError("runner endpoint and family must match the bound action")
        context.update(action_id=action_id, claim_token=claim_token)
    return context


def _ensure_primary_finding(store: TargetStore, *, finding_id: str, endpoint: str,
                            method: str, family: str) -> None:
    try:
        store.finding(finding_id)
    except FindingNotFoundError:
        store.create_finding(
            command_id=f"create-finding:{finding_id}", finding_id=finding_id,
            endpoint=endpoint, method=method, family=family,
            title=f"Validation candidate {finding_id}",
            claim="The recorded validation operation requires technical assessment",
            actor="validation-runner",
        )


def _store_observation(run: dict[str, Any], *, repo_root: Path, side: str | None, method: str,
                       family: str, observed_at: str, result: str,
                       incomplete: bool,
                       state_changing: bool | None, redline_checked: bool,
                       observation_lane: bool = False) -> dict[str, Any]:
    if side is None:
        endpoint = str(run.get("url") or "")
        artifacts = dict(run.get("artifacts") or {})
        variant = str(run.get("variant") or "native")
        snapshot = run
        observation = run
    else:
        prefix = f"{side}_"
        endpoint = str(run.get(f"{side}_url") or "")
        artifacts = {
            key.removeprefix(prefix): ref
            for key, ref in (run.get("artifacts") or {}).items()
            if key.startswith(prefix) and isinstance(ref, str) and ref
        }
        variant = side
        snapshot = run.get(side) or {}
        # Old saved summaries retain their recorded side-name semantics on retry.
        # New replays always publish a separate, normalized observation per side.
        observation = run.get(f"{side}_observation") or run
        variant = str(observation.get("variant") or variant)
    # Identity belongs to this observed step, never to its summary or sibling.
    identity_dimensions = observation.get("identity_dimensions") or {}
    identity_v2 = observation.get("identity_v2") or {}
    identity_status = str(observation.get("identity_status") or "none")
    identity_technique = str(observation.get("identity_technique") or "")
    identity_ref = artifacts.get("identity")
    if not identity_ref:
        raise StoreError("runner observation requires its private request identity artifact")
    identity = json.loads((repo_root / identity_ref).read_text(encoding="utf-8"))
    endpoint = identity["requested_url"]
    # The digest-bound identity selects the representation, not mutable summary
    # metadata. Missing markers belong only to historical shape publications.
    representation = identity.get("url_representation", "shape")
    if representation not in ("exact", "shape"):
        raise StoreError("unsupported private request URL representation")
    published_endpoint = run.get("url") if side is None else run.get(f"{side}_url")
    if not isinstance(endpoint, str) or (
        endpoint if representation == "exact" else public_url_shape(endpoint)
    ) != published_endpoint:
        raise StoreError("private request identity does not match the published endpoint shape")
    observed_method = str(run.get("method") or method).strip().upper()
    if "request" not in artifacts:
        raise StoreError(f"primary runner observation is missing {variant} request artifact")
    if not incomplete and "response" not in artifacts:
        raise StoreError(f"primary runner observation is missing {variant} response artifact")
    return {
        "endpoint": endpoint,
        "method": observed_method,
        "family": run["family"] if observation_lane else family,
        "observed_at": run["observed_at"] if observation_lane else observed_at,
        "description": run["description"] if observation_lane else str((run.get("diff") or {}).get("summary") or f"{side} runner observation"),
        "artifacts": artifacts,
        "actor": str(observation.get("actor") or ("unknown" if side is None else "anonymous")),
        "object_scope": str(observation.get("object_scope") or ("unknown" if side is None else "none")),
        "variant": variant,
        "error": str(run["error"].get("type") or "") if isinstance(run.get("error"), dict) else str(run.get("error") or ""),
        "truncated": bool(snapshot.get("truncated") or snapshot.get("body_truncated")),
        "state_changing": run.get("state_changing") if observation_lane else state_changing,
        "redline_checked": run.get("redline_checked", False) if observation_lane else redline_checked,
        "result": result,
        "detail": {
            "evidence_role": str(observation.get("evidence_role") or "unknown"),
            **({"cleanup_confirmation": observation["cleanup_confirmation"]}
               if "cleanup_confirmation" in observation else {}),
            **({key: run[key] for key in ("provenance", "missing") if key in run} if observation_lane else {}),
        },
        "identity_status": identity_status,
        "identity_technique": identity_technique,
        "identity_v2": identity_v2 or {},
        "identity_dimensions": identity_dimensions or {},
    }


def _record_primary_execution(store: TargetStore, *, attempt_id: str, actor: str,
                              started_at: str, result: str, runs: list[dict[str, Any]],
                              method: str, methods: dict[str, str] | None,
                              family: str, native: bool,
                              candidate: dict[str, str] | None,
                              state_changing: bool | None, redline_checked: bool,
                              observed_at: str | None = None,
                              finding_id: str | None = None,
                              expected_operation: str | None = None,
                              observation_outcome: str | None = None) -> dict[str, Any]:
    observations = []
    timestamp = observed_at or started_at
    for run in runs:
        sides = (None,) if native else tuple(
            side for side in ("baseline", "variant")
            if any(str(key).startswith(f"{side}_") for key in (run.get("artifacts") or {}))
        )
        for side in sides:
            observations.append(_store_observation(
                run, repo_root=store.root, side=side, method=(methods or {}).get(side, method), family=family, observed_at=timestamp,
                result=result if result != "partial" else "", incomplete=result == "partial" or observation_outcome in {"partial", "unknown"},
                state_changing=state_changing,
                redline_checked=redline_checked,
                observation_lane=observation_outcome is not None,
            ))
    # A transport failure can happen before any response/request artifact is
    # published. Preserve the attempt as an unknown operation instead of
    # inventing an observation or dropping the externally-unknown outcome.
    outcome = "unknown" if result == "partial" and not observations else (
        "partial" if result == "partial" else "complete"
    )
    if observation_outcome is not None:
        outcome = observation_outcome
    if result == "partial" and candidate and not any(
        (item["endpoint"], item["method"], item["family"]) ==
        (candidate["endpoint"], candidate["method"], candidate["family"])
        for item in observations
    ):
        candidate = None
    return store.record_execution(
        attempt_id=attempt_id, outcome=outcome, observations=observations,
        candidate=candidate, actor=actor, finding_id=finding_id, expected_operation=expected_operation,
    )


def _sync_primary_store(summary: dict[str, Any], *, repo_root: Path, store: TargetStore) -> dict[str, Any]:
    observation_lane = runner_summary_lane(summary) == "native_observation"
    attempt_id = str(summary.get("attempt_id") or "").strip()
    if not attempt_id:
        return {"status": "skipped", "reason": "no primary attempt"}
    result = str(summary.get("result") or "")
    if not observation_lane and result not in {"tested_finding", "tested_clean", "candidate", "dead_end", "partial"}:
        return {"status": "skipped", "reason": "non-execution result"}
    receipt = _record_primary_execution(
        store, attempt_id=attempt_id, actor=summary.get("command_actor", "validation-runner"),
        started_at=str(summary.get("started_at") or summary.get("generated_at") or now_utc()), result=result,
        runs=list(summary.get("runs") or []),
        method=str(summary.get("method") or "GET").upper(),
        methods={
            str(side): str((summary.get("request_pair") or {}).get(side, {}).get("method") or "").upper()
            for side in ("baseline", "variant")
            if isinstance((summary.get("request_pair") or {}).get(side), dict)
        },
        family=str(summary.get("vuln_class") or "runner-observation"),
        native=observation_lane or str(summary.get("lane") or "") == "native_evidence",
        candidate=(_store_candidate(store, str(summary.get("finding_id") or "").strip())
                   if not observation_lane and not summary.get("cleanup_only") and any(run.get("artifacts") for run in (summary.get("runs") or []) if isinstance(run, dict))
                   else None),
        finding_id=summary["finding_id"] if summary.get("cleanup_only") else None,
        state_changing=summary.get("state_changing"),
        redline_checked=bool(summary.get("redline_checked")),
        observed_at=str(summary.get("generated_at") or now_utc()),
        expected_operation=summary.get("expected_operation") if observation_lane else None,
        observation_outcome=summary.get("outcome") if observation_lane else None,
    )
    if observation_lane:
        operation_id = receipt["entity_id"]
        execution = store.execution(operation_id)
        registration_path = (_summary_path(summary, repo_root).parent / "registrations"
                             / f"{operation_id.split(':')[-1]}.json")
        registration = {"schema_version": 1, "summary_sha256": hashlib.sha256(_native_json(summary)).hexdigest(),
                        "receipt": {key: value for key, value in receipt.items() if key != "replayed"}}
        publish_bytes_create_only(registration_path, _native_json(registration))
        return {"status": "deduplicated" if receipt.get("replayed") else "updated",
                "operation_id": operation_id, "receipt": receipt,
                "observation_refs": [f"{operation_id}:{row['step']}" for row in execution["observations"]],
                "registration_receipt": _rel(registration_path, repo_root)}
    summary["store_operation_id"] = str(receipt.get("entity_id") or "")
    return {"status": "deduplicated" if receipt.get("replayed") else "updated",
            "operation_id": summary["store_operation_id"]}


def sync_runner_artifacts(summary: dict[str, Any], *, repo_root: Path) -> dict[str, Any]:
    """Register saved evidence atomically without replaying network actions."""
    observation_lane = runner_summary_lane(summary) == "native_observation"
    if observation_lane:
        summary = {key: value for key, value in summary.items() if key not in {
            "sync", "store_operation_id", "observation_refs", "registration_receipt"}}
    with _runner_admission(
        repo_root, str(summary.get("target") or ""), expected=summary.get("backend_binding"),
    ) as (store, _):
        if str(summary.get("result") or "") == "skeleton":
            return {"status": "skipped", "reason": "skeleton result does not close validation state"}
        if not summary.get("backend_binding"):
            raise StoreError("primary registration requires the execution backend binding")
        try:
            if observation_lane:
                raw, _ = read_target_artifact(repo_root, summary["target"], summary["summary_path"])
                if raw != _native_json(summary):
                    raise StoreError("immutable native observation summary changed")
                if summary.get("browser_capture"):
                    current = read_browser_observation_capture(repo_root, summary["target"], summary["browser_capture"]["capture_summary"])
                    if current["network_source"] != summary["browser_capture"]["network_source"]:
                        raise StoreError("browser capture baseline changed")
            if _artifact_bindings(summary, repo_root) != summary.get("artifact_bindings"):
                raise StoreError("runner artifacts changed after publication; registration refused")
            receipt = _sync_primary_store(summary, repo_root=repo_root, store=store)
            return {"status": receipt.get("status", "updated"), "store": receipt}
        except Exception as exc:
            return {"status": "partial", "store": {"status": "error", "error": " ".join(str(exc).split())[:500]}}


def parse_headers(values: list[str] | None) -> dict[str, str]:
    return AuthSession(values or []).headers_dict()


def _format_request(method: str, url: str, headers: dict[str, str], body: str = "") -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _format_response(status: int, reason: str, headers: dict[str, str], body: str) -> str:
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _request_origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed.scheme.lower(), (parsed.hostname or "").lower().rstrip("."), port or {
        "http": 80,
        "https": 443,
    }.get(parsed.scheme.lower())


def _request_headers(
    session: AuthSession | None,
    url: str,
    headers: dict[str, str] | None,
) -> dict[str, str]:
    merged = session.headers_for_url(url) if session is not None else {}
    merged.update(headers or {})
    return merged


class _TargetRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(
        self,
        target: str,
        *,
        session: AuthSession | None = None,
        sensitive_header_names: set[str] | None = None,
        repo_root: Path = BASE_DIR,
        context_file: str | Path | None = None,
    ) -> None:
        self.target = target
        self.repo_root = repo_root
        self.session = session
        self.context_file = resolve_context_file(context_file, session.context_file if session else None)
        self.sensitive_header_names = {
            str(name).lower() for name in (sensitive_header_names or set())
        }
        self.redirect_chain: list[dict[str, Any]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not url_belongs_to_target(newurl, self.target):
            raise ValueError(f"validation redirect left target scope: {public_url_shape(newurl)}")
        if not load_execution_scope(self.repo_root, self.target, self.context_file).allows_active(newurl):
            raise ValueError(f"validation redirect outside target scope (excluded by saved Scope): {public_url_shape(newurl)}")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and _request_origin(req.full_url) != _request_origin(newurl):
            for store in (redirected.headers, redirected.unredirected_hdrs):
                for name in list(store):
                    if name.lower() in self.sensitive_header_names:
                        store.pop(name, None)
            if self.session is not None and self.session.allows_origin(newurl):
                for name, value in self.session.headers_for_url(newurl).items():
                    redirected.add_header(name, value)
        if redirected is not None and len(self.redirect_chain) < self.max_redirections:
            self.redirect_chain.append({
                "status": int(code),
                "from_url": req.full_url,
                "to_url": redirected.full_url,
            })
        return redirected


def _read_bounded(response: Any, limit: int) -> tuple[bytes, int, bool]:
    raw = response.read(limit + 1)
    observed = len(raw)
    content_length = str(response.headers.get("Content-Length") or "").strip()
    if content_length.isdigit():
        observed = max(observed, int(content_length))
    return raw[:limit], observed, len(raw) > limit or observed > limit


def request_once(
    *,
    target: str,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: Any = "",
    timeout: int = 10,
    max_body_bytes: int = MAX_RESPONSE_BYTES,
    session: AuthSession | None = None,
    repo_root: Path = BASE_DIR,
    context_file: str | Path | None = None,
) -> dict[str, Any]:
    """Replay one HTTP request and return raw evidence fields."""
    if not url_belongs_to_target(url, target):
        raise ValueError(f"validation URL is outside target scope: {public_url_shape(url)}")
    context_file = resolve_context_file(context_file, session.context_file if session else None)
    scope = load_execution_scope(repo_root, target, context_file)
    if not scope.allows_active(url):
        raise RequestPreflightError(f"validation URL excluded by saved Scope: {public_url_shape(url)}")
    if max_body_bytes < 1:
        raise ValueError("max_body_bytes must be positive")
    method_u = str(method or "GET").upper()
    headers = _request_headers(session, url, headers)
    body_text = _request_body_text(body, headers)
    data = body_text.encode("utf-8") if body_text else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method_u)
    request_text = _format_request(method_u, url, headers, body_text)
    redirect_handler = _TargetRedirectHandler(
        target,
        repo_root=repo_root,
        session=session,
        sensitive_header_names={name.lower() for name in headers},
        context_file=context_file,
    )
    started = time.monotonic()
    try:
        opener = urllib.request.build_opener(redirect_handler)
        with opener.open(request, timeout=timeout) as response:
            raw, observed_bytes, truncated = _read_bounded(response, max_body_bytes)
            status = int(response.status)
            reason = str(response.reason or "")
            response_headers = {str(k): str(v) for k, v in response.headers.items()}
            get_url = getattr(response, "geturl", None)
            response_url = get_url() if callable(get_url) else ""
            final_url = str(response_url or url)
    except urllib.error.HTTPError as exc:
        raw, observed_bytes, truncated = _read_bounded(exc, max_body_bytes)
        status = int(exc.code)
        reason = str(exc.reason or "")
        response_headers = {str(k): str(v) for k, v in exc.headers.items()}
        final_url = str(exc.geturl() or url)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if not url_belongs_to_target(final_url, target):
        raise ValueError(f"validation response left target scope: {public_url_shape(final_url)}")
    body_text = raw.decode("utf-8", errors="replace")
    return {
        "url": url,
        "requested_url": url,
        "final_url": final_url,
        "redirect_chain": redirect_handler.redirect_chain,
        "method": method_u,
        "request_text": request_text,
        "status": status,
        "reason": reason,
        "headers": response_headers,
        "body": body_text,
        "elapsed_ms": elapsed_ms,
        "body_retained_bytes": len(raw),
        "body_observed_bytes": observed_bytes,
        "body_truncated": truncated,
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "response_text": _format_response(status, reason, response_headers, body_text),
    }


def _validate_request_facts(
    state_changing: bool | None,
    redline_checked: bool,
) -> bool | None:
    # The red-line rule is about the concrete effect.  The HTTP verb is only
    # recorded evidence and must not create a second gate in the runner.
    if state_changing is True and not redline_checked:
        raise RequestPreflightError(
            "state-changing validation requires --redline-checked before any request"
        )
    return state_changing


def _write_raw_http(
    private_dir: Path,
    prefix: str,
    response: dict[str, Any],
    repo_root: Path,
) -> dict[str, str]:
    request_path = write_private_text(private_dir / f"{prefix}request.txt", response["request_text"])
    response_path = write_private_text(private_dir / f"{prefix}response.txt", response["response_text"])
    identity_path = write_private_json(
        private_dir / f"{prefix}identity.json",
        {
            "url_representation": "exact",
            "requested_url": response.get("requested_url") or response.get("url", ""),
            "final_url": response.get("final_url") or response.get("url", ""),
            "redirect_chain": response.get("redirect_chain") or [],
        },
    )
    return {
        "request": _rel(request_path, repo_root),
        "response": _rel(response_path, repo_root),
        "identity": _rel(identity_path, repo_root),
    }


def _response_snapshot(response: dict[str, Any]) -> dict[str, Any]:
    return snapshot_response(
        response["status"],
        response["headers"],
        response["body"],
        truncated=bool(response.get("body_truncated")),
        observed_bytes=int(response.get("body_observed_bytes", 0) or 0),
    )


def _response_diff(baseline: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    payload = diff_responses(
        baseline_status=baseline["status"],
        baseline_headers=baseline["headers"],
        baseline_body=baseline["body"],
        variant_status=variant["status"],
        variant_headers=variant["headers"],
        variant_body=variant["body"],
    )
    payload["baseline"] = _response_snapshot(baseline)
    payload["variant"] = _response_snapshot(variant)
    return payload


def _merge_request_headers(request: dict[str, Any], extra: dict[str, str] | None) -> dict[str, str]:
    headers = {str(key): str(value) for key, value in (request.get("headers") or {}).items()}
    for key, value in (extra or {}).items():
        existing = next((name for name in headers if name.lower() == key.lower()), None)
        if existing is not None:
            del headers[existing]
        headers[str(key)] = str(value)
    return headers


def _classifier_vuln_class(classifier: str, explicit: str = "") -> str:
    return canonical_vuln_class(explicit or classifier)


def _request_pair_materiality(run: dict[str, Any]) -> bool:
    """Check the explicit threshold predicate; never decide a default outcome."""
    changed = run.get("diff", {}).get("changed", {})
    return bool(
        changed.get("json_count")
        or changed.get("status")
        or changed.get("json_fields")
        or abs(int(run.get("diff", {}).get("body_length", {}).get("delta", 0) or 0)) > 20
    )


def _run_wire_facts(run: dict[str, Any], baseline_body: str, variant_body: str) -> dict[str, bool]:
    """Compute every declarable wire fact for one replay run.

    Category-free by construction: these are predicates over raw observations
    (status codes, body markers, JSON shape, diff numbers). No vulnerability
    class, header vocabulary, or framework assumption participates.
    """
    diff = run.get("diff") if isinstance(run.get("diff"), dict) else {}
    changed = diff.get("changed") or {}
    count = diff.get("json_count") or {}
    base_count = count.get("baseline")
    var_count = count.get("variant")
    count_delta = count.get("delta")
    fields = diff.get("json_fields") or {}
    fields_added = list(fields.get("added") or [])
    fields_removed = list(fields.get("removed") or [])
    body_delta = int((diff.get("body_length") or {}).get("delta", 0) or 0)
    baseline_status = int((run.get("baseline") or {}).get("status") or 0)
    variant_status = int((run.get("variant") or {}).get("status") or 0)

    baseline_marker = bool(DB_ERROR_MARKER_RE.search(str(baseline_body or "")))
    variant_marker = bool(DB_ERROR_MARKER_RE.search(str(variant_body or "")))
    material = _request_pair_materiality(run)
    identical = (
        baseline_status == variant_status
        and baseline_body == variant_body
        and not (run.get("baseline") or {}).get("body_truncated")
        and not (run.get("variant") or {}).get("body_truncated")
    )

    return {
        "error_marker_variant_only": variant_marker and not baseline_marker,
        "count_delta_positive": isinstance(count_delta, int) and count_delta > 0,
        "count_delta_negative": isinstance(count_delta, int) and count_delta < 0,
        "fields_added": bool(fields_added),
        "fields_removed": bool(fields_removed),
        "body_length_delta": abs(body_delta) > 20,
        "status_delta": bool(changed.get("status")),
        "material_diff_any": material,
        "identical_success_pair": (
            200 <= baseline_status < 400
            and 200 <= variant_status < 400
            and identical
        ),
        "both_sides_rejected": (
            baseline_status >= 400 and variant_status >= 400 and identical
        ),
        # Absolute content fact: body bytes differ, no size threshold. A
        # sub-threshold byte delta is still a different object.
        "distinct_bodies": str(baseline_body or "") != str(variant_body or ""),
        # Timing is aggregated across runs in _compute_wire_facts; a single
        # run never claims it on its own.
        "stable_timing_delta": False,
    }


NEEDLE_FACT_RE = re.compile(r"^([a-z_]+)::(.+)$", re.S)


def _needle_fact(name: str, needle: str, runs: list[dict[str, Any]], baseline_bodies: list[str], variant_bodies: list[str]) -> bool:
    """Mechanically verify one needle declaration across all runs.

    ``variant_body_contains``: the needle appears in every variant body.
    ``baseline_body_lacks``: the needle appears in no baseline body AND in
    every variant body (variant-only presence). The needle is the AI's
    judgment of what string proves the point; this function only checks.
    """
    if not runs:
        return False
    if name == "variant_body_contains":
        return all(needle in str(variant or "") for variant in variant_bodies)
    if name == "baseline_body_lacks":
        return (
            all(needle not in str(base or "") for base in baseline_bodies)
            and all(needle in str(variant or "") for variant in variant_bodies)
        )
    return False


def _compute_wire_facts(
    runs: list[dict[str, Any]],
    baseline_bodies: list[str],
    variant_bodies: list[str],
) -> dict[str, bool]:
    """Aggregate per-run facts: a fact holds when it holds in EVERY run.

    ``stable_timing_delta`` is the one cross-run fact: the variant must be
    slower than the baseline in every run (sign stability). Magnitude
    judgment stays with the AI review; the runner only checks the stable
    direction.
    """
    per_run = [
        _run_wire_facts(run, base, var)
        for run, base, var in zip(runs, baseline_bodies, variant_bodies)
    ]
    facts: dict[str, bool] = {}
    for name in WIRE_FACT_NAMES:
        if name == "stable_timing_delta":
            continue
        facts[name] = bool(per_run) and all(item.get(name) for item in per_run)
    timing_stable = False
    if runs:
        deltas: list[int] = []
        for run in runs:
            base_ms = int((run.get("baseline") or {}).get("elapsed_ms") or 0)
            var_ms = int((run.get("variant") or {}).get("elapsed_ms") or 0)
            deltas.append(var_ms - base_ms)
        timing_stable = bool(deltas) and all(delta > 0 for delta in deltas)
    facts["stable_timing_delta"] = timing_stable
    # Needle facts are evaluated at reconciliation time per declared entry
    # (they are parameterized), not precomputed here; _declared_fact_holds
    # routes them to _needle_fact.
    return facts


def _declared_fact_holds(
    declared: str,
    runs: list[dict[str, Any]],
    baseline_bodies: list[str],
    variant_bodies: list[str],
    facts: dict[str, bool],
) -> bool:
    """Resolve one declared expectation entry against the computed facts.

    Plain names look up the aggregated fact; needle entries (name::needle)
    verify their literal substring mechanically across all runs.
    """
    needle_match = NEEDLE_FACT_RE.match(declared)
    if needle_match:
        name, needle = needle_match.group(1), needle_match.group(2)
        if name not in WIRE_NEEDLE_FACT_NAMES:
            return False
        return _needle_fact(name, needle, runs, baseline_bodies, variant_bodies)
    return bool(facts.get(declared))


def _request_pair_spec_view(spec: dict[str, Any]) -> dict[str, Any]:
    def view(request: dict[str, Any]) -> dict[str, Any]:
        return {
            "method": request["method"],
            "url": request["url"],
            "header_names": sorted(str(key).lower() for key in request.get("headers", {})),
            **{key: request[key] for key in ("actor", "object_scope", "variant")},
        }

    return {
        "baseline": view(spec["baseline_request"]),
        "variant": view(spec["variant_request"]),
        "subject_side": spec["subject_side"],
        "active_dimension": spec["active_dimension"],
        "evidence_shape": spec["evidence_shape"],
        "classifier": spec["classifier"],
        "vuln_class": _classifier_vuln_class(spec["classifier"], spec.get("vuln_class", "")),
        "expected_signal": spec.get("expected_signal", ""),
        "expect_auth": bool(spec.get("expect_auth") is True),
    }


def run_request_diff(
    *,
    repo_root: Path,
    target: str,
    request_spec: dict[str, Any],
    timeout: int = 10,
    finding_id: str = "",
    repeat: int | None = None,
    no_ledger: bool = False,
    browser_observed: bool = False,
    state_changing: bool | None = None,
    redline_checked: bool = False,
    identity_v2: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    session: AuthSession | None = None,
    lane: str = "request_diff",
    source: str = "validation-runner:request-diff",
    attempt_id: str | None = None,
    action_id: str | None = None,
    claim_token: str | None = None,
    command_actor: str = "validation-runner",
    context_file: str | Path | None = None,
) -> dict[str, Any]:
    """Replay an AI-selected exact pair and persist shared diff evidence."""
    context_file = resolve_context_file(context_file, session.context_file if session else None)
    scope = load_execution_scope(repo_root, target, context_file)
    with _runner_admission(repo_root, target) as (store, backend_binding):
        try:
            spec = validate_request_pair(request_spec)
        except RequestPairError as exc:
            if not str(exc).startswith("manual_required:") or action_id is not None or claim_token is not None:
                raise
            finding_id = finding_id or "request-diff-manual"
            bundle = _bundle_dir(repo_root, target, finding_id)
            summary = {
                "schema_version": SCHEMA_VERSION,
                "lane": lane,
                "target": canonical_target_value(target),
                "finding_id": finding_id,
                "result": "manual_required",
                "candidate_ready": False,
                "manual_required": str(exc),
                "evidence_shape": "request_diff",
                "classifier": str(request_spec.get("classifier") or "generic") if isinstance(request_spec, dict) else "generic",
            }
            return _finalize_runner_summary(summary, bundle / "summary.json", repo_root, backend_binding=backend_binding)

        baseline = spec["baseline_request"]
        variant = spec["variant_request"]
        effective_state = _validate_request_facts(state_changing, redline_checked)
        if not url_belongs_to_target(baseline["url"], target) or not url_belongs_to_target(variant["url"], target):
            raise RequestPreflightError("request pair contains an off-target URL")
        if not all(scope.allows_active(request["url"]) for request in (baseline, variant)):
            raise RequestPreflightError("request pair contains a URL excluded by saved Scope")
        subject = spec[f"{spec['subject_side']}_request"]
        family = _classifier_vuln_class(spec["classifier"], spec.get("vuln_class", "")) or "runner-observation"
        finding_id = finding_id or _default_finding_id(
            lane, subject["url"], method=subject["method"], family=family)
        observations = {
            side: {**{key: spec[f"{side}_request"][key] for key in ("actor", "object_scope", "variant")},
                   "evidence_role": "subject" if side == spec["subject_side"] else "control"}
            for side in ("baseline", "variant")
        }
        if identity_v2 is not None:
            key = ClosureCellKey.from_dict(identity_v2)
            dimensions = key.dimension_map
            if key.schema_version != 3:
                raise RequestPairError("historical identity requires an explicit v3 replacement")
            if (key.endpoint, key.family) != (exact_endpoint_identity(subject["url"]), family):
                raise RequestPairError("identity_v2 must match the declared subject endpoint and family")
            for dimension, value in (("method", subject["method"]), ("actor_relation", subject["actor"]),
                                     ("object_scope", subject["object_scope"])):
                if dimension in dimensions and dimensions[dimension] != value:
                    raise RequestPairError(f"identity_v2.{dimension} conflicts with the subject observation")
            observations[spec["subject_side"]]["identity_dimensions"] = dimensions
            observations[spec["subject_side"]]["identity_status"] = "complete"
            observations[spec["subject_side"]]["identity_technique"] = key.technique
            observations[spec["subject_side"]]["identity_v2"] = key.to_dict()
            identity_v2 = key.to_dict()
        for side in ("baseline", "variant"):
            observations[side].setdefault("identity_status", "none")
            observations[side].setdefault("identity_technique", "")
            observations[side].setdefault("identity_v2", {})
        try:
            existing = store.finding(finding_id)
        except FindingNotFoundError:
            existing = None
        if existing and (existing["endpoint"], existing["method"], existing["family"]) != (
            subject["url"], subject["method"], family,
        ):
            raise StoreError("declared subject endpoint, method and family must match the existing finding")
        command_context = _runner_command_context(
            store, action_id=action_id, claim_token=claim_token, command_actor=command_actor,
            endpoint=subject["url"], family=family,
        )
        started_at = now_utc()
        attempt_id = attempt_id or f"attempt:{uuid.uuid4().hex}"
        receipt = store.start_attempt(
            attempt_id=attempt_id, source=source, started_at=started_at,
            actor=command_actor, action_id=action_id, claim_token=claim_token,
        )
        if receipt["replayed"]:
            raise StoreError("attempt already started; retry registration from its saved summary or execute with a new attempt_id")
        _ensure_primary_finding(
            store, finding_id=finding_id, endpoint=subject["url"],
            method=subject["method"], family=family,
        )
        bundle = _bundle_dir(repo_root, target, finding_id)
        private_bundle = _private_bundle_dir(repo_root, target, bundle)
        pair_digest = request_pair_digest(spec)
        header_overlay_digest = hashlib.sha256(
            json.dumps(headers or {}, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest() if headers else ""
        auth_session_id = session.session_id() if session is not None else ""
        write_private_json(private_bundle / "inputs.json", spec)
        repeat_count = max(1, int(repeat if repeat is not None else spec["repeat"]))
        runs: list[dict[str, Any]] = []
        baseline_bodies: list[str] = []
        variant_bodies: list[str] = []
        for idx in range(1, repeat_count + 1):
            base_headers = _merge_request_headers(baseline, headers)
            variant_headers = _merge_request_headers(variant, headers)
            prefix = "" if repeat_count == 1 else f"{idx}."
            run: dict[str, Any] = {
                "iteration": idx,
                "baseline_url": baseline["url"],
                "variant_url": variant["url"],
                "active_dimension": spec["active_dimension"],
                "baseline_observation": observations["baseline"],
                "variant_observation": observations["variant"],
                "artifacts": {},
            }
            runs.append(run)
            side = "baseline"
            try:
                base = request_once(
                    repo_root=repo_root,
                    target=target, url=baseline["url"], method=baseline["method"],
                    headers=base_headers, body=baseline["body"], timeout=timeout, session=session,
                    context_file=context_file,
                )
                artifacts = _write_raw_http(private_bundle, f"{prefix}baseline.", base, repo_root)
                run["artifacts"].update({f"baseline_{key}": value for key, value in artifacts.items()})
                run["baseline"] = _response_snapshot(base)
                side = "variant"
                variant_response = request_once(
                    repo_root=repo_root,
                    target=target, url=variant["url"], method=variant["method"],
                    headers=variant_headers, body=variant["body"], timeout=timeout, session=session,
                    context_file=context_file,
                )
                artifacts = _write_raw_http(private_bundle, f"{prefix}variant.", variant_response, repo_root)
                run["artifacts"].update({f"variant_{key}": value for key, value in artifacts.items()})
            except (OSError, urllib.error.URLError, ValueError) as exc:
                run["error"] = {"side": side, "type": type(exc).__name__}
                return _finalize_runner_summary({
                    "schema_version": SCHEMA_VERSION, "lane": lane,
                    "target": canonical_target_value(target), "finding_id": finding_id,
                    "url": subject["url"], "method": subject["method"],
                    "generated_at": now_utc(), "result": "partial", "status": "partial",
                    "candidate_ready": False, "runs": runs, "repeat": repeat_count,
                    "request_pair": _request_pair_spec_view(spec), "request_spec_sha256": pair_digest,
                    "identity_v2": identity_v2,
                    "auth_session_id": auth_session_id,
                    "state_changing": effective_state, "redline_checked": redline_checked,
                    "attempt_id": attempt_id or "",
                    **command_context,
                    "classifier": spec["classifier"], "vuln_class": _classifier_vuln_class(
                        spec["classifier"], spec.get("vuln_class", "")
                    ),
                    "error": run["error"],
                }, bundle / "summary.json", repo_root, backend_binding=backend_binding)
            run.update(_response_diff(base, variant_response))
            baseline_bodies.append(str(base.get("body") or ""))
            variant_bodies.append(str(variant_response.get("body") or ""))

        classifier = spec["classifier"]
        # These predicates only verify explicit declarations; they never select a test.
        wire_facts = _compute_wire_facts(runs, baseline_bodies, variant_bodies)
        declared_expected = list(spec.get("expected") or [])
        if not declared_expected and spec.get("expect_auth") is True:
            # Sugar: expect_auth is the missing-auth declaration expressed as a
            # boolean; expand to its fact form so both spellings reconcile alike.
            declared_expected = ["identical_success_pair"]
        expected_check: dict[str, Any] = {}
        if declared_expected:
            observed = {
                name: _declared_fact_holds(name, runs, baseline_bodies, variant_bodies, wire_facts)
                for name in declared_expected
            }
            unmet = [name for name, holds in observed.items() if not holds]
            candidate_ready = not unmet
            expected_check = {
                "declared": declared_expected,
                "unmet": unmet,
                "observed": observed,
            }
        else:
            candidate_ready = False
        # Intent routing: the AI declares which direction its expectation points
        # (hazard evidence vs. boundary-holds evidence); the runner routes on the
        # declaration mechanically and never infers direction from fact names.
        #   hazard + confirmed  -> tested_finding (a hazard declaration held)
        #   clean   + confirmed -> tested_clean   (a clean declaration held, with
        #                                       expected_check archived as evidence)
        #   either + unmet      -> candidate      (the declaration was wrong — the
        #                           most signal-rich outcome, must reach review)
        declaration_intent = str(spec.get("declaration_intent") or "hazard")
        if candidate_ready:
            # clean-intent confirmation is a mechanically-backed tested_clean;
            # hazard-intent confirmation is a finding candidate as before.
            result = "tested_clean" if declaration_intent == "clean" else "tested_finding"
        else:
            # An undeclared or unmet expectation is unresolved, never an automatic clean.
            result = "candidate"
        vuln_class = _classifier_vuln_class(classifier, spec.get("vuln_class", ""))
        diff_path = bundle / "diff.json"
        _write_json(diff_path, {"runs": runs, "request_pair": _request_pair_spec_view(spec)})
        diff_summaries = [str(run.get("diff", {}).get("summary") or "") for run in runs]
        ledger = None
        summary = {
            "schema_version": SCHEMA_VERSION,
            "lane": lane,
            "target": canonical_target_value(target),
            "finding_id": finding_id,
            "url": subject["url"],
            "method": subject["method"],
            "generated_at": now_utc(),
            "result": result,
            "candidate_ready": candidate_ready,
            "state_changing": effective_state,
            "redline_checked": redline_checked,
            "evidence_shape": spec["evidence_shape"],
            "classifier": classifier,
            "vuln_class": vuln_class,
            "active_dimension": spec["active_dimension"],
            "expected_signal": spec["expected_signal"],
            "request_spec_sha256": pair_digest,
            "header_overlay_sha256": header_overlay_digest,
            "auth_session_id": auth_session_id,
            "identity_v2": identity_v2,
            "identity_status": "complete" if identity_v2 else "none",
            "identity_technique": str(identity_v2.get("technique") or "") if isinstance(identity_v2, dict) else "",
            "request_pair": _request_pair_spec_view(spec),
            "repeat": repeat_count,
            "runs": runs,
            "artifacts": {"diff": _rel(diff_path, repo_root)},
            "ledger_record": ledger,
            "expected_check": expected_check,
            "declaration_intent": declaration_intent,
            "expected_note": spec.get("expected_note", ""),
            "attempt_id": attempt_id or "",
            **command_context,
        }
        summary_path = bundle / "summary.json"
        return _finalize_runner_summary(summary, summary_path, repo_root, backend_binding=backend_binding)


def record_native_evidence(
    *,
    repo_root: Path,
    target: str,
    finding_id: str,
    evidence: dict[str, Any],
    state_changing: bool | None = None,
    redline_checked: bool = False,
    identity_v2: dict[str, Any] | None = None,
    attempt_id: str | None = None,
    action_id: str | None = None,
    claim_token: str | None = None,
    command_actor: str = "validation-runner",
) -> dict[str, Any]:
    """Bind existing raw observations to the same witness as request-diff.

    Result and meaning are explicitly AI-assessed, not inferred from bytes.
    This operation verifies references and records evidence; it executes nothing.
    """
    with _runner_admission(repo_root, target) as (store, backend_binding):
        target = canonical_target_value(target)
        if not isinstance(evidence, dict) or type(evidence.get("schema_version")) is not int or evidence["schema_version"] != SCHEMA_VERSION:
            raise ValueError("native evidence must be a schema-v1 JSON object")

        def required_text(value: Any, field: str) -> str:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"native evidence {field} must be a non-empty string")
            return value.strip()

        try:
            finding = store.finding(finding_id)
        except StoreError as exc:
            raise ValueError("record-evidence requires an existing primary finding") from exc
        for key, expected in (("target", target), ("finding_id", finding_id)):
            if key in evidence and evidence[key] != expected:
                raise ValueError(f"native evidence {key} does not match the selected finding")
        url = required_text(finding.get("url") or finding.get("endpoint"), "canonical finding URL")
        if not url_belongs_to_target(url, target):
            raise ValueError("canonical finding URL is off target")
        method = str(finding.get("method") or "GET").strip().upper()
        vuln_class = normalize_family(finding.get("vuln_class") or finding.get("family") or finding.get("type"))
        identity_status = "none"
        identity_technique = ""
        if identity_v2 is not None:
            try:
                key = ClosureCellKey.from_dict(identity_v2)
            except (TypeError, ValueError, KeyError) as exc:
                raise ValueError(f"native evidence identity_v2 is invalid: {exc}") from exc
            if key.schema_version != 3:
                raise ValueError("historical identity requires an explicit v3 replacement")
            if key.endpoint != exact_endpoint_identity(url) or key.family != vuln_class:
                raise ValueError("native evidence identity_v2 must match the finding endpoint and family")
            if "method" in key.dimension_map and key.dimension_map["method"] != method:
                raise ValueError("native evidence identity_v2.method conflicts with the finding method")
            identity_v2 = key.to_dict()
            identity_status = "complete"
            identity_technique = key.technique
        attempt_id = attempt_id or str(evidence.get("attempt_id") or "").strip()
        if not attempt_id:
            raise ValueError("primary record-evidence requires an explicit attempt_id")
        result = required_text(evidence.get("result"), "result")
        if result not in {*RUNNER_RESULT_TO_FINDING_STATUS, "partial"}:
            raise ValueError("native evidence result must be tested_finding, candidate, tested_clean, dead_end, or partial")
        source = required_text(evidence.get("source"), "source")
        observed_difference = validate_observed_difference(
            required_text(evidence.get("observed_difference"), "observed_difference")
        )
        captured_at = datetime.fromisoformat(required_text(evidence.get("generated_at"), "generated_at").replace("Z", "+00:00"))
        if captured_at.tzinfo is None:
            raise ValueError("native evidence generated_at must be an ISO-8601 timestamp with a timezone")
        effective_state = _validate_request_facts(state_changing, redline_checked)
        cleanup = None
        if "cleanup_confirmation" in evidence:
            cleanup = validate_cleanup_confirmation(evidence["cleanup_confirmation"])
            if effective_state is not False or result != "candidate" or identity_v2 is not None:
                raise ValueError("cleanup evidence requires --no-state-changing, result=candidate and no closure identity")
        raw_runs = evidence.get("runs")
        if not isinstance(raw_runs, list) or not raw_runs:
            raise ValueError("native evidence runs must contain the recorded execution steps")
        if cleanup is not None and len(raw_runs) != 1:
            raise ValueError("cleanup evidence must contain one final read-back verification run")
        runs = []
        anchors = []
        subject_step = evidence.get("subject_step")
        if subject_step is not None and (type(subject_step) is not int or not 0 <= subject_step < len(raw_runs)):
            raise ValueError("native evidence subject_step must be a zero-based run index")
        for index, raw_run in enumerate(raw_runs):
            if not isinstance(raw_run, dict):
                raise ValueError(f"native evidence runs[{index}] must be an object")
            run_url = required_text(raw_run.get("url"), f"runs[{index}].url")
            run_method = required_text(raw_run.get("method"), f"runs[{index}].method").upper()
            if not url_belongs_to_target(run_url, target):
                raise ValueError(f"native evidence runs[{index}].url is off-target")
            if not re.fullmatch(r"[A-Z][A-Z0-9_-]*", run_method):
                raise ValueError(f"native evidence runs[{index}].method is invalid")
            artifacts = raw_run.get("artifacts")
            if not isinstance(artifacts, dict) or "request" not in artifacts:
                raise ValueError(f"native evidence runs[{index}] requires a request artifact")
            if result != "partial" and ("response" not in artifacts or raw_run.get("error") or raw_run.get("body_truncated")):
                raise ValueError("incomplete native evidence requires result=partial, never candidate-ready")
            refs = {}
            for kind, value in artifacts.items():
                ref = target_owned_nonempty_evidence_ref(repo_root, target, value)
                if not ref:
                    raise ValueError(f"native evidence runs[{index}].artifacts.{kind} must reference a non-empty target-owned file")
                refs[kind] = ref
            run = {
                key: raw_run[key]
                for key in ("actor", "object_scope", "variant", "summary", "error", "body_truncated")
                if key in raw_run
            }
            for key, normalize in (("actor", normalize_actor), ("object_scope", normalize_object_scope), ("variant", normalize_variant)):
                if key in run:
                    run[key] = normalize(required_text(run[key], f"runs[{index}].{key}"))
            run.update(url=run_url, method=run_method, artifacts=refs)
            runs.append(run)
            if run_method == method and url == run_url:
                anchors.append(index)
        if cleanup is not None:
            anchors = [0]  # Verification may use a different endpoint/method from the mutation.
        if not anchors:
            raise ValueError("native evidence must include the canonical finding's exact endpoint and method")
        if subject_step is None:
            if len(anchors) != 1:
                raise ValueError("native evidence subject_step is required for ambiguous endpoint/method runs")
            subject_step = anchors[0]
        if subject_step not in anchors:
            raise ValueError("native evidence subject_step must match the finding endpoint and method")
        anchor = runs[subject_step]
        actor = normalize_actor(required_text(anchor.get("actor"), "canonical execution actor"))
        if identity_v2:
            dimensions = identity_v2["dimensions"]
            for dimension, fact in (("actor_relation", actor), ("actor_role", actor),
                                    ("actor", actor), ("object_scope", anchor.get("object_scope"))):
                if dimension in dimensions and dimensions[dimension] != fact:
                    raise ValueError(f"native evidence identity_v2.{dimension} conflicts with the anchor")
        for run in runs:
            subject = run is anchor and cleanup is None
            run.update(evidence_role="subject" if subject else "control",
                       identity_status=identity_status if subject else "none",
                       identity_technique=identity_technique if subject else "",
                       identity_v2=identity_v2 if subject else {},
                       identity_dimensions=identity_v2["dimensions"] if subject and identity_v2 else {})
        if cleanup is not None:
            anchor["cleanup_confirmation"] = cleanup
            # Reject incomplete/foreign mutation references before publishing a witness.
            linked = {(ref["operation_id"], ref["step"]) for ref in finding["evidence"]}
            for ref in cleanup["mutation_refs"]:
                if (ref["operation_id"], ref["step"]) not in linked:
                    raise ValueError("cleanup mutation reference is not linked to this finding")
                operation = store.execution(ref["operation_id"])
                mutation = next((row for row in operation["observations"] if row["step"] == ref["step"]), None)
                if not mutation or mutation["state_changing"] != 1:
                    raise ValueError("cleanup mutation reference must identify a state-changing observation")
                if captured_at < datetime.fromisoformat(mutation["observed_at"].replace("Z", "+00:00")):
                    raise ValueError("cleanup read-back must not predate its mutation")
        command_context = _runner_command_context(
            store, action_id=action_id, claim_token=claim_token, command_actor=command_actor,
            endpoint=url, family=vuln_class,
        )
        store.start_attempt(
            attempt_id=attempt_id, source=source,
            started_at=captured_at.astimezone(timezone.utc).isoformat(), actor=command_actor,
            action_id=action_id, claim_token=claim_token,
        )
        summary = {
            "schema_version": SCHEMA_VERSION,
            "lane": "native_evidence",
            "evidence_shape": "native",
            "assessment_source": "ai",
            "source": source,
            "target": target,
            "finding_id": finding_id,
            "url": url,
            "method": method,
            "vuln_class": vuln_class,
            "generated_at": captured_at.astimezone(timezone.utc).isoformat(),
            "result": result,
            "candidate_ready": result == "tested_finding",
            "observed_difference": observed_difference,
            "state_changing": effective_state,
            "redline_checked": redline_checked,
            "identity_v2": identity_v2,
            "identity_status": identity_status,
            "identity_technique": identity_technique,
            "runs": runs,
            "subject_step": subject_step,
            **({"cleanup_only": True} if cleanup is not None else {}),
            "attempt_id": attempt_id or "",
            **command_context,
        }
        # Bind the internal exact-URL representation to the immutable identity;
        # registration of old unmarked shape artifacts retains legacy semantics.
        identity_dir = private_artifact_dir(repo_root, "validation", target_storage_key(target), "identities")
        for run, raw_run in zip(runs, raw_runs):
            identity = {"url_representation": "exact", "requested_url": raw_run["url"].strip()}
            content = json.dumps(identity, ensure_ascii=False, sort_keys=True) + "\n"
            path = identity_dir / f"{hashlib.sha256(content.encode()).hexdigest()}.json"
            if not path.exists():
                write_private_text(path, content)
            elif path.read_text(encoding="utf-8") != content:
                raise StoreError("private request identity artifact changed")
            run["artifacts"]["identity"] = _rel(path, repo_root)
        bindings = _artifact_bindings(summary, repo_root)
        digests = {(item["kind"], item["ref"]): item["sha256"] for item in bindings}
        for run in runs:
            # Bind each artifact to its execution step, not only to the bundle's
            # unordered set of hashes (order matters for native stateful evidence).
            run["artifact_sha256"] = {
                kind: digests[(kind, ref)] for kind, ref in run["artifacts"].items()
            }
        material = _stable_operation_material(summary)
        material["artifact_bindings"] = _artifact_digest_material(bindings)
        # Re-registering identical material resumes the same operation and path,
        # including a previous partial owner sync; raw observations are not copied.
        operation_id = _runner_operation_id(material)
        summary_path = (
            repo_root / "evidence" / target_storage_key(target)
            / "validation" / _safe_id(finding_id, "finding")
            / f"native-{operation_id.split(':')[-1]}" / "summary.json"
        )
        if result == "partial":
            summary["status"] = "partial"
        summary["ledger_record"] = None
        return _finalize_runner_summary(summary, summary_path, repo_root, backend_binding=backend_binding)


def _native_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _native_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"native observation {field} must be nonempty text without NUL")
    return value.strip()


def _native_timestamp(value: Any, field: str) -> str:
    stamp = datetime.fromisoformat(_native_text(value, field).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError(f"native observation {field} requires a timezone")
    return stamp.astimezone(timezone.utc).isoformat()


def _native_browser_envelope(repo_root: Path, target: str, capture_ref: str, execution: dict) -> tuple[dict, dict]:
    allowed = {"schema_version", "target", "attempt_id", "source", "started_at", "family", "actor",
               "object_scope", "variant", "state_changing", "redline_checked", "description", "steps"}
    if not isinstance(execution, dict) or execution.keys() - allowed:
        raise ValueError("browser execution metadata has unknown fields")
    if "schema_version" in execution and (type(execution["schema_version"]) is not int or execution["schema_version"] != 1):
        raise ValueError("browser execution metadata requires schema_version=1")
    capture = read_browser_observation_capture(repo_root, target, capture_ref)
    scope = load_scope_context(repo_root, target)
    steps = execution.get("steps", [])
    if not isinstance(steps, list):
        raise ValueError("browser execution steps must be a list")
    by_index = {}
    for step in steps:
        if (not isinstance(step, dict) or type(step.get("source_index")) is not int or step["source_index"] < 0
                or step.keys() - {"source_index", "family", "actor", "object_scope", "variant",
                                 "state_changing", "redline_checked", "description"}
                or step["source_index"] in by_index):
            raise ValueError("browser execution steps require unique original source_index and known facts")
        by_index[step["source_index"]] = step
    runs, diagnostics = [], list(capture["diagnostics"])
    for raw in capture["runs"]:
        if not url_belongs_to_target(raw["url"], target) or not scope.allows_active(raw["url"]):
            diagnostics.append({"source_index": raw["source_index"], "error": "out_of_scope; retained in original capture"})
            continue
        facts = {key: execution[key] for key in ("family", "actor", "object_scope", "variant",
                 "state_changing", "redline_checked", "description") if key in execution}
        facts.update({key: value for key, value in by_index.pop(raw["source_index"], {}).items() if key != "source_index"})
        runs.append({**raw, **facts})
    if by_index:
        raise ValueError("browser execution facts refer to missing or excluded source steps")
    if not runs:
        raise ValueError(f"browser capture has no admissible exact timed steps: {diagnostics}")
    incomplete = diagnostics or any(run["missing"] or run["error"] or run["body_truncated"] for run in runs)
    envelope = {key: execution[key] for key in ("target", "attempt_id", "source", "started_at", "family") if key in execution}
    envelope.update(schema_version=1, kind="native-observation", outcome="partial" if incomplete else "complete", runs=runs)
    return envelope, {key: value for key, value in capture.items() if key != "runs"} | {"diagnostics": diagnostics}


def record_native_observation(
    *, repo_root: Path, target: str, attempt_id: str,
    evidence: dict[str, Any] | None = None, browser_capture_ref: str | None = None,
    execution: dict[str, Any] | None = None, expected_operation: str | None = None,
    action_id: str | None = None, claim_token: str | None = None,
    command_actor: str = "validation-runner",
) -> dict[str, Any]:
    """Publish one no-verdict execution snapshot. Sync only registers; it never executes."""
    repo_root = repo_root.resolve()
    target = canonical_target_value(target)
    with _runner_admission(repo_root, target) as (store, binding):
        if not isinstance(attempt_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", attempt_id):
            raise ValueError("record-observation requires a bounded explicit attempt_id")
        command_actor = _native_text(command_actor, "command actor")
        if (action_id is None) != (claim_token is None):
            raise ValueError("action_id and claim_token must be supplied together")
        capture = None
        if browser_capture_ref is not None:
            if evidence is not None or execution is None:
                raise ValueError("browser mode requires execution metadata, never another evidence envelope")
            evidence, capture = _native_browser_envelope(repo_root, target, browser_capture_ref, execution)
        elif execution is not None:
            raise ValueError("execution-json is only for browser capture mode")
        allowed = {"schema_version", "kind", "target", "attempt_id", "source", "started_at", "family", "outcome", "runs"}
        if (not isinstance(evidence, dict) or evidence.keys() - allowed
                or type(evidence.get("schema_version")) is not int or evidence["schema_version"] != 1
                or evidence.get("kind") != "native-observation"):
            raise ValueError("record-observation requires schema=1, kind=native-observation and no Finding/closure/verdict fields")
        for key, value in (("target", target), ("attempt_id", attempt_id)):
            if key in evidence and evidence[key] != value:
                raise ValueError(f"native observation {key} conflicts with command")
        source = _native_text(evidence.get("source"), "source")
        started_at = _native_timestamp(evidence.get("started_at"), "started_at")
        outcome = evidence.get("outcome")
        raw_runs = evidence.get("runs")
        if outcome not in {"complete", "partial", "unknown"} or not isinstance(raw_runs, list):
            raise ValueError("native observation requires outcome complete/partial/unknown and ordered runs")
        if not raw_runs and outcome != "unknown":
            raise ValueError("only a genuinely unknown execution may have zero runs")
        if expected_operation is not None:
            predecessor = store.execution(expected_operation)
            attempt = predecessor["attempt"]
            if (attempt["id"], attempt["source"], attempt["started_at"]) != (attempt_id, source, started_at):
                raise ValueError("predecessor attempt/source/started_at mismatch")
            if action_id is not None and (action_id, claim_token) != (attempt["action_id"], attempt["claim_token"]):
                raise ValueError("supplement cannot replace the original Action/claim association")
            action_id, claim_token = attempt["action_id"], attempt["claim_token"]
        scope = load_scope_context(repo_root, target)
        pending_bytes: dict[Path, bytes] = {}
        runs = []
        artifact_dir = repo_root / ".private" / "validation" / target_storage_key(target) / "native-observations" / "artifacts"
        run_fields = {"url", "method", "family", "observed_at", "description", "artifacts", "actor", "object_scope",
                      "variant", "error", "body_truncated", "state_changing", "redline_checked"}
        browser_fields = {"source_index", "provenance", "missing", "private_request", "private_response"} if capture else set()
        for index, raw in enumerate(raw_runs):
            if not isinstance(raw, dict) or raw.keys() - run_fields - browser_fields:
                raise ValueError(f"native observation run {index} has unknown fields")
            url = exact_endpoint_identity(_native_text(raw.get("url"), f"runs[{index}].url"))
            method = _native_text(raw.get("method"), f"runs[{index}].method").upper()
            if (any(char.isspace() for char in url) or not url_belongs_to_target(url, target)
                    or not scope.allows_active(url) or not re.fullmatch(r"[A-Z][A-Z0-9_-]*", method)):
                raise ValueError(f"native observation run {index} requires an exact target/Scope-owned HTTP URL and method")
            family = raw.get("family", evidence.get("family", None if action_id else "runner-observation"))
            family = normalize_family(_native_text(family, f"runs[{index}].family"))
            observed_at = _native_timestamp(raw.get("observed_at"), f"runs[{index}].observed_at")
            if datetime.fromisoformat(observed_at) < datetime.fromisoformat(started_at):
                raise ValueError("native observation predates its execution attempt")
            state = raw.get("state_changing")
            checked, truncated = raw.get("redline_checked", False), raw.get("body_truncated", False)
            if (state is not None and type(state) is not bool or type(checked) is not bool or type(truncated) is not bool):
                raise ValueError("native execution facts must be boolean (state_changing may be null)")
            _validate_request_facts(state, checked)
            error = raw.get("error", "")
            if not isinstance(error, str):
                raise ValueError("native observation error must be text")
            artifacts = raw.get("artifacts")
            if not isinstance(artifacts, dict):
                raise ValueError("native observation requires raw artifact references")
            refs, hashes = {}, {}
            for kind, value in artifacts.items():
                if not isinstance(kind, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", kind):
                    raise ValueError("invalid artifact kind")
                content, ref = read_target_artifact(repo_root, target, _native_text(value, "artifact ref"))
                refs[kind], hashes[kind] = ref, hashlib.sha256(content).hexdigest()
            if capture:
                for side in ("request", "response"):
                    if "private_" + side in raw:
                        content = _native_json(raw["private_" + side])
                        path = artifact_dir / (hashlib.sha256(content).hexdigest() + ".json")
                        pending_bytes[path] = content
                        refs[side], hashes[side] = _rel(path, repo_root), hashlib.sha256(content).hexdigest()
            if "request" not in refs or outcome == "complete" and ("response" not in refs or error or truncated or raw.get("missing")):
                raise ValueError("missing/truncated/error raw material requires partial/unknown, never complete")
            identity = _native_json({"url_representation": "exact", "requested_url": url})
            path = artifact_dir / (hashlib.sha256(identity).hexdigest() + ".json")
            pending_bytes[path] = identity
            refs["identity"], hashes["identity"] = _rel(path, repo_root), hashlib.sha256(identity).hexdigest()
            run = {"url": url, "method": method, "family": family, "observed_at": observed_at,
                   "description": _native_text(raw.get("description"), f"runs[{index}].description"),
                   "artifacts": refs, "artifact_sha256": hashes, "error": error, "body_truncated": truncated,
                   "state_changing": state, "redline_checked": checked,
                   "actor": normalize_actor(_native_text(raw.get("actor", "unknown"), "HTTP actor")),
                   "object_scope": normalize_object_scope(_native_text(raw.get("object_scope", "unknown"), "object scope")),
                   "variant": normalize_variant(_native_text(raw.get("variant", "replay"), "variant"))}
            if capture:
                run.update(provenance=raw["provenance"], missing=raw["missing"])
            runs.append(run)
        summary = {"schema_version": 1, "kind": "native-observation", "lane": "native_observation",
                   "target": target, "attempt_id": attempt_id, "source": source, "started_at": started_at,
                   "outcome": outcome, "result": "", "runs": runs, "command_actor": command_actor,
                   "expected_operation": expected_operation, "action_id": action_id, "claim_token": claim_token,
                   "backend_binding": binding}
        if capture:
            summary["browser_capture"] = capture
        summary["artifact_bindings"] = sorted(
            [{"kind": kind, "ref": ref, "sha256": run["artifact_sha256"][kind]} for run in runs
             for kind, ref in run["artifacts"].items()], key=lambda item: (item["kind"], item["ref"]))
        # _artifact_bindings deduplicates the same material used by several steps.
        summary["artifact_bindings"] = list({(item["kind"], item["ref"]): item for item in summary["artifact_bindings"]}.values())
        material_id = hashlib.sha256(_native_json(summary)).hexdigest()
        attempt_key = hashlib.sha256(attempt_id.encode()).hexdigest()
        summary_path = repo_root / "evidence" / target_storage_key(target) / "native-observations" / attempt_key / material_id / "summary.json"
        summary["summary_path"] = _rel(summary_path, repo_root)
        command = ["python3", str(repo_root / "tools/validation_runner.py"), "record-observation", "--repo-root", str(repo_root),
                   "--target", target, "--attempt-id", attempt_id, "--summary-json", str(summary_path), "--actor", command_actor, "--json"]
        if expected_operation:
            command += ["--expected-operation", expected_operation]
        summary["registration_retry_command"] = shlex.join(command)
        pending_bytes[summary_path] = _native_json(summary)
        # Reject known byte conflicts before mutating the attempt owner.
        for path, content in pending_bytes.items():
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
                raise ValueError(f"linked immutable native material: {path}")
            if path.exists() and read_target_artifact(repo_root, target, _rel(path, repo_root))[0] != content:
                raise ValueError(f"immutable native material conflict: {path}")
        if expected_operation is None:
            store.start_attempt(attempt_id=attempt_id, source=source, started_at=started_at, actor=command_actor,
                                action_id=action_id, claim_token=claim_token)
        if runs:
            private_artifact_dir(repo_root, "validation", target_storage_key(target), "native-observations/artifacts")
        for path, content in pending_bytes.items():
            publish_bytes_create_only(path, content)
        return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic validation evidence lanes")
    sub = parser.add_subparsers(dest="lane", required=True)

    def add_common(p: argparse.ArgumentParser, *, finding_required: bool = False) -> None:
        p.add_argument("--target", required=True)
        p.add_argument("--finding-id", default="", required=finding_required)
        p.add_argument("--repo-root", default=str(BASE_DIR))
        p.add_argument("--action-id", help="Bind the attempt to this explicitly claimed execution Action")
        p.add_argument("--claim-token", help="Current claim token returned by the Action owner")
        p.add_argument("--actor", default="validation-runner", help="Command operator; must match the Action claimant")
        p.add_argument("--no-sync", action="store_true", help="Do not sync runner result into findings/action_queue state")
        p.add_argument(
            "--identity-v2-json",
            default="",
            help="prebuilt ClosureCellKey v2 JSON carried from the planned test",
        )

    def add_request_facts(p: argparse.ArgumentParser) -> None:
        group = p.add_mutually_exclusive_group()
        group.add_argument("--state-changing", dest="state_changing", action="store_true")
        group.add_argument("--no-state-changing", dest="state_changing", action="store_false")
        p.set_defaults(state_changing=None)
        p.add_argument("--redline-checked", action="store_true", default=False)

    request_diff = sub.add_parser(
        "request-diff",
        help="Replay an AI-supplied exact baseline/variant request pair",
    )
    add_common(request_diff)
    add_cli_args(request_diff, include_context=True)
    request_diff.add_argument("--request-spec", required=True, help="JSON file containing schema-v1 baseline/variant requests")
    request_diff.add_argument("--header", action="append", default=[], help="Header overlay applied to both requests")
    request_diff.add_argument("--timeout", type=int, default=10)
    request_diff.add_argument("--repeat", type=int, default=None)
    request_diff.add_argument("--attempt-id", default="", help="primary Store execution attempt identity")
    request_diff.add_argument("--browser-observed", action="store_true")
    add_request_facts(request_diff)
    request_diff.add_argument("--no-ledger", action="store_true")
    request_diff.add_argument(
        "--json",
        action="store_true",
        help="Print only the summary JSON (same output shape; kept for CLI symmetry with sibling tools)",
    )
    record = sub.add_parser("record-evidence", help="Register already-executed native evidence without sending requests")
    add_common(record, finding_required=True)
    record.add_argument("--evidence-json", required=True, help="Schema-v1 observations with runs[].artifacts, source, generated_at, result and observed_difference")
    record.add_argument("--attempt-id", default="", help="primary Store execution attempt identity")
    add_request_facts(record)
    record.add_argument("--json", action="store_true")

    observation = sub.add_parser("record-observation", help="Register a no-verdict native observation without a Finding or network execution")
    observation.add_argument("--target", required=True)
    observation.add_argument("--repo-root", default=str(BASE_DIR))
    observation.add_argument("--attempt-id", required=True)
    observation.add_argument("--actor", default="validation-runner", help="Registration operator, not the observed HTTP actor")
    inputs = observation.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--evidence-json", help="schema=1 kind=native-observation envelope")
    inputs.add_argument("--browser-capture-ref", help="Target-owned capture summary with an original-byte baseline")
    inputs.add_argument("--summary-json", help="Retry registration of an already published immutable summary only")
    observation.add_argument("--execution-json", help="Original execution source/started_at and declared browser step facts")
    observation.add_argument("--expected-operation", help="Original predecessor for a full-snapshot supplement/retry")
    observation.add_argument("--action-id")
    observation.add_argument("--claim-token")
    observation.add_argument("--json", action="store_true")

    review = sub.add_parser("review-candidate", help="Close or reopen one exact reviewed candidate without changing its Finding")
    review.add_argument("--target", required=True)
    review.add_argument("--repo-root", default=str(BASE_DIR))
    review.add_argument("--summary-json", required=True)
    review.add_argument("--review-id", required=True)
    review.add_argument("--expected-summary-sha256", required=True)
    review.add_argument("--status", required=True, choices=("closed", "open"))
    review.add_argument("--reason", required=True)
    review.add_argument("--expected-review-id")
    review.add_argument("--actor", default="validation-runner")
    review.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    identity_v2: dict[str, Any] | None = None
    if getattr(args, "identity_v2_json", ""):
        try:
            payload = json.loads(args.identity_v2_json)
            try:
                from tools.identity_contract import ClosureCellKey
            except ImportError:  # pragma: no cover - direct tools/ execution
                from identity_contract import ClosureCellKey  # type: ignore
            identity_v2 = ClosureCellKey.from_dict(payload).to_dict()
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            parser.error(f"--identity-v2-json must contain a valid versioned ClosureCellKey: {exc}")
    repo_root = Path(args.repo_root)
    try:
        if args.lane == "review-candidate":
            result = review_candidate(repo_root, args.target, summary_ref=args.summary_json,
                review_id=args.review_id, status=args.status, reason=args.reason, actor=args.actor,
                expected_review_id=args.expected_review_id, expected_summary_sha256=args.expected_summary_sha256)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        with _runner_admission(repo_root, args.target) as (store, _):
            if args.lane == "record-observation":
                if args.summary_json:
                    if args.execution_json:
                        raise ValueError("summary registration retry cannot supply new execution metadata")
                    raw, _ = read_target_artifact(repo_root, args.target, args.summary_json)
                    summary = json.loads(raw.decode("utf-8"))
                    if runner_summary_lane(summary) != "native_observation":
                        raise ValueError("summary-json requires an immutable native observation summary")
                    for key, expected in (("target", canonical_target_value(args.target)), ("attempt_id", args.attempt_id),
                                          ("command_actor", args.actor), ("expected_operation", args.expected_operation)):
                        if summary.get(key) != expected:
                            raise ValueError(f"saved-summary retry must retain original {key}")
                    if (args.action_id is None) != (args.claim_token is None):
                        raise ValueError("action-id/claim-token must be supplied together")
                    if args.action_id is not None and (args.action_id, args.claim_token) != (summary.get("action_id"), summary.get("claim_token")):
                        raise ValueError("saved-summary retry cannot change original claim association")
                else:
                    evidence = json.loads(Path(args.evidence_json).read_text(encoding="utf-8")) if args.evidence_json else None
                    execution = json.loads(Path(args.execution_json).read_text(encoding="utf-8")) if args.execution_json else None
                    summary = record_native_observation(repo_root=repo_root, target=args.target, attempt_id=args.attempt_id,
                        evidence=evidence, browser_capture_ref=args.browser_capture_ref, execution=execution,
                        expected_operation=args.expected_operation, action_id=args.action_id, claim_token=args.claim_token,
                        command_actor=args.actor)
                sync = sync_runner_artifacts(summary, repo_root=repo_root)
                saved = sync.get("store") or {}
                output = {**summary, "sync": sync, "store_operation_id": saved.get("operation_id"),
                          "observation_refs": saved.get("observation_refs", []),
                          "registration_receipt": saved.get("registration_receipt")}
                print(json.dumps(output, ensure_ascii=False, indent=2))
                return 1 if sync["status"] == "partial" or summary["outcome"] != "complete" else 0
            elif args.lane == "request-diff":
                auth_session = session_from_args(args).bind_target(args.target)
                try:
                    request_spec = json.loads(Path(args.request_spec).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    parser.error(f"--request-spec must point to a JSON object: {exc}")
                if not isinstance(request_spec, dict):
                    parser.error("--request-spec must contain a JSON object")
                try:
                    summary = run_request_diff(
                        repo_root=repo_root,
                        target=args.target,
                        request_spec=request_spec,
                        timeout=args.timeout,
                        finding_id=args.finding_id,
                        repeat=args.repeat,
                        no_ledger=args.no_ledger,
                        browser_observed=args.browser_observed,
                        state_changing=args.state_changing,
                        redline_checked=args.redline_checked,
                        identity_v2=identity_v2,
                        headers=parse_headers(args.header),
                        session=auth_session,
                        context_file=args.context_file,
                        attempt_id=args.attempt_id or None,
                        action_id=args.action_id, claim_token=args.claim_token, command_actor=args.actor,
                    )
                except (RequestPairError, RequestPreflightError) as exc:
                    # Invalid input must fail before any network I/O.
                    print(f"request-diff: invalid request spec: {exc}", file=sys.stderr)
                    return 2
            elif args.lane == "record-evidence":
                try:
                    evidence = json.loads(Path(args.evidence_json).read_text(encoding="utf-8"))
                    summary = record_native_evidence(
                        repo_root=repo_root, target=args.target, finding_id=args.finding_id,
                        evidence=evidence, state_changing=args.state_changing,
                        redline_checked=args.redline_checked, identity_v2=identity_v2,
                        attempt_id=args.attempt_id or None,
                        action_id=args.action_id, claim_token=args.claim_token, command_actor=args.actor,
                    )
                except (OSError, ValueError) as exc:
                    parser.error(f"record-evidence: {exc}")
            else:
                raise ValueError(f"unknown lane: {args.lane}")
            if identity_v2 is not None and summary.get("ledger_record") is None:
                summary["identity_v2"] = identity_v2
            if not getattr(args, "no_sync", False):
                summary["sync"] = sync_runner_artifacts(summary, repo_root=repo_root)
                summary_path = _summary_path(summary, repo_root)
                if summary_path is not None:
                    _write_json(summary_path, summary)
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            # --json is accepted for CLI symmetry; the default output is already the
            # machine-readable summary JSON (no human-only trailing block exists).
            return 1 if summary.get("result") == "partial" or (summary.get("sync") or {}).get("status") == "partial" else 0
    except (OSError, ValueError, StoreError) as exc:
        print(f"validation-runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
