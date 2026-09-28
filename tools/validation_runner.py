#!/usr/bin/env python3
"""Deterministic validation runner for Claude-driven security findings.

Validation Runner v1 intentionally stays small:

- request-diff: AI-supplied exact baseline/variant replay across one input dimension.
- record-evidence: register already-executed native observations without replay.

AI 仍负责选择 hypothesis、解释业务影响、决定是否升级/降级；本工具只负责稳定
执行 replay / diff / evidence bundle / ledger 写入。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
    from tools.artifact_io import write_json_atomic as _write_json
    from tools.auth_session import AuthSession, add_cli_args, session_from_args
    from tools.contracts import WIRE_FACT_NAMES, WIRE_NEEDLE_FACT_NAMES, artifact_digest_material, runner_operation_id, validate_observed_difference
    from tools.evidence_ledger import normalize_actor, normalize_object_scope, normalize_variant
    from tools.response_diff import diff_responses, snapshot_response
    from tools.request_diff import RequestPairError, request_pair_digest, validate_request_pair
    from tools.browser_surface import public_url_shape
    from tools.evidence_identity import canonical_vuln_class, normalize_family
    from tools.private_artifacts import private_artifact_dir, write_private_json, write_private_text
    from tools.target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref
    from tools.scope_context import url_belongs_to_target
    from tools.scope_source import load_scope_context
    from tools.target_store import FindingNotFoundError, StoreError, TargetStore, runtime_store, target_switch_lock
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_json_atomic as _write_json
    from auth_session import AuthSession, add_cli_args, session_from_args  # type: ignore
    from contracts import WIRE_FACT_NAMES, WIRE_NEEDLE_FACT_NAMES, artifact_digest_material, runner_operation_id, validate_observed_difference  # type: ignore
    from evidence_ledger import normalize_actor, normalize_object_scope, normalize_variant  # type: ignore
    from response_diff import diff_responses, snapshot_response  # type: ignore
    from request_diff import RequestPairError, request_pair_digest, validate_request_pair  # type: ignore
    from browser_surface import public_url_shape  # type: ignore
    from evidence_identity import canonical_vuln_class, normalize_family  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_json, write_private_text  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref  # type: ignore
    from scope_context import url_belongs_to_target  # type: ignore
    from scope_source import load_scope_context  # type: ignore
    from target_store import FindingNotFoundError, StoreError, TargetStore, runtime_store, target_switch_lock  # type: ignore


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


def _default_finding_id(lane: str, url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "root"
    suffix = _safe_id(path.replace("/", "_"), "endpoint")
    return f"{lane}-{suffix}"


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
    # disk fall back to the stable public summary projection.  In both cases,
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
                       identity_dimensions: dict[str, Any] | None = None) -> dict[str, Any]:
    if side is None:
        endpoint = str(run.get("url") or "")
        artifacts = dict(run.get("artifacts") or {})
        variant = str(run.get("variant") or "native")
        snapshot = run
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
    identity_ref = artifacts.get("identity")
    if not identity_ref:
        raise StoreError("runner observation requires its private request identity artifact")
    identity = json.loads((repo_root / identity_ref).read_text(encoding="utf-8"))
    endpoint = identity["requested_url"]
    if not isinstance(endpoint, str) or public_url_shape(endpoint) != (
        run.get("url") if side is None else run.get(f"{side}_url")
    ):
        raise StoreError("private request identity does not match the published endpoint shape")
    observed_method = str(run.get("method") or method).strip().upper()
    if "request" not in artifacts:
        raise StoreError(f"primary runner observation is missing {variant} request artifact")
    if not incomplete and "response" not in artifacts:
        raise StoreError(f"primary runner observation is missing {variant} response artifact")
    return {
        "endpoint": endpoint,
        "method": observed_method,
        "family": family,
        "observed_at": observed_at,
        "description": str((run.get("diff") or {}).get("summary") or f"{side} runner observation"),
        "artifacts": artifacts,
        "actor": str(run.get("actor") or "anonymous"),
        "object_scope": str(run.get("object_scope") or "none"),
        "variant": variant,
        "error": str(run["error"].get("type") or "") if isinstance(run.get("error"), dict) else str(run.get("error") or ""),
        "truncated": bool(snapshot.get("truncated") or snapshot.get("body_truncated")),
        "state_changing": state_changing,
        "redline_checked": redline_checked,
        "result": result,
        "identity_dimensions": identity_dimensions or {},
    }


def _record_primary_execution(store: TargetStore, *, attempt_id: str, actor: str,
                              started_at: str, result: str, runs: list[dict[str, Any]],
                              method: str, methods: dict[str, str] | None,
                              family: str, native: bool,
                              candidate: dict[str, str] | None,
                              state_changing: bool | None, redline_checked: bool,
                              observed_at: str | None = None,
                              identity_dimensions: dict[str, Any] | None = None) -> dict[str, Any]:
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
                result=result if result != "partial" else "", incomplete=result == "partial",
                state_changing=state_changing,
                redline_checked=redline_checked,
                identity_dimensions=identity_dimensions,
            ))
    # A transport failure can happen before any response/request artifact is
    # published. Preserve the attempt as an unknown operation instead of
    # inventing an observation or dropping the externally-unknown outcome.
    outcome = "unknown" if result == "partial" and not observations else (
        "partial" if result == "partial" else "complete"
    )
    return store.record_execution(
        attempt_id=attempt_id, outcome=outcome, observations=observations,
        candidate=candidate, actor=actor,
    )


def _sync_primary_store(summary: dict[str, Any], *, repo_root: Path, store: TargetStore) -> dict[str, Any]:
    attempt_id = str(summary.get("attempt_id") or "").strip()
    if not attempt_id:
        return {"status": "skipped", "reason": "no primary attempt"}
    result = str(summary.get("result") or "")
    if result not in {"tested_finding", "tested_clean", "candidate", "dead_end", "partial"}:
        return {"status": "skipped", "reason": "non-execution result"}
    receipt = _record_primary_execution(
        store, attempt_id=attempt_id, actor=summary.get("command_actor", "validation-runner"),
        started_at=str(summary.get("generated_at") or now_utc()), result=result,
        runs=list(summary.get("runs") or []),
        method=str(summary.get("method") or "GET").upper(),
        methods={
            str(side): str((summary.get("request_pair") or {}).get(f"{side}_request", {}).get("method") or "").upper()
            for side in ("baseline", "variant")
            if isinstance((summary.get("request_pair") or {}).get(f"{side}_request"), dict)
        },
        family=str(summary.get("vuln_class") or "runner-observation"),
        native=str(summary.get("lane") or "") == "native_evidence",
        candidate=(_store_candidate(store, str(summary.get("finding_id") or "").strip())
                   if any(run.get("artifacts") for run in (summary.get("runs") or []) if isinstance(run, dict))
                   else None),
        state_changing=summary.get("state_changing"),
        redline_checked=bool(summary.get("redline_checked")),
        observed_at=str(summary.get("generated_at") or now_utc()),
        identity_dimensions=(
            summary.get("identity_v2", {}).get("dimensions")
            if isinstance(summary.get("identity_v2"), dict)
            and isinstance(summary.get("identity_v2", {}).get("dimensions"), dict)
            else None
        ),
    )
    summary["store_operation_id"] = str(receipt.get("entity_id") or "")
    return {"status": "deduplicated" if receipt.get("replayed") else "updated",
            "operation_id": summary["store_operation_id"]}


def sync_runner_artifacts(summary: dict[str, Any], *, repo_root: Path) -> dict[str, Any]:
    """Register saved evidence atomically without replaying network actions."""
    with _runner_admission(
        repo_root, str(summary.get("target") or ""), expected=summary.get("backend_binding"),
    ) as (store, _):
        if str(summary.get("result") or "") == "skeleton":
            return {"status": "skipped", "reason": "skeleton result does not close validation state"}
        if not summary.get("backend_binding"):
            raise StoreError("primary registration requires the execution backend binding")
        try:
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
    ) -> None:
        self.target = target
        self.repo_root = repo_root
        self.session = session
        self.sensitive_header_names = {
            str(name).lower() for name in (sensitive_header_names or set())
        }
        self.redirect_chain: list[dict[str, Any]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not url_belongs_to_target(newurl, self.target):
            raise ValueError(f"validation redirect left target scope: {public_url_shape(newurl)}")
        if not load_scope_context(self.repo_root, self.target).allows_active(newurl):
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
) -> dict[str, Any]:
    """Replay one HTTP request and return raw evidence fields."""
    if not url_belongs_to_target(url, target):
        raise ValueError(f"validation URL is outside target scope: {public_url_shape(url)}")
    scope = load_scope_context(repo_root, target)
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
            "url": public_url_shape(request["url"]),
            "header_names": sorted(str(key).lower() for key in request.get("headers", {})),
        }

    return {
        "baseline": view(spec["baseline_request"]),
        "variant": view(spec["variant_request"]),
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
) -> dict[str, Any]:
    """Replay an AI-selected exact pair and persist shared diff evidence."""
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
        scope = load_scope_context(repo_root, target)
        if not all(scope.allows_active(request["url"]) for request in (baseline, variant)):
            raise RequestPreflightError("request pair contains a URL excluded by saved Scope")
        finding_id = finding_id or _default_finding_id(lane, baseline["url"])
        family = _classifier_vuln_class(spec["classifier"], spec.get("vuln_class", "")) or "runner-observation"
        command_context = _runner_command_context(
            store, action_id=action_id, claim_token=claim_token, command_actor=command_actor,
            endpoint=baseline["url"], family=family,
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
            store, finding_id=finding_id, endpoint=baseline["url"],
            method=baseline["method"], family=family,
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
                "baseline_url": public_url_shape(baseline["url"]),
                "variant_url": public_url_shape(variant["url"]),
                "active_dimension": spec["active_dimension"],
                "artifacts": {},
            }
            runs.append(run)
            side = "baseline"
            try:
                base = request_once(
                    repo_root=repo_root,
                    target=target, url=baseline["url"], method=baseline["method"],
                    headers=base_headers, body=baseline["body"], timeout=timeout, session=session,
                )
                artifacts = _write_raw_http(private_bundle, f"{prefix}baseline.", base, repo_root)
                run["artifacts"].update({f"baseline_{key}": value for key, value in artifacts.items()})
                run["baseline"] = _response_snapshot(base)
                side = "variant"
                variant_response = request_once(
                    repo_root=repo_root,
                    target=target, url=variant["url"], method=variant["method"],
                    headers=variant_headers, body=variant["body"], timeout=timeout, session=session,
                )
                artifacts = _write_raw_http(private_bundle, f"{prefix}variant.", variant_response, repo_root)
                run["artifacts"].update({f"variant_{key}": value for key, value in artifacts.items()})
            except (OSError, urllib.error.URLError, ValueError) as exc:
                run["error"] = {"side": side, "type": type(exc).__name__}
                return _finalize_runner_summary({
                    "schema_version": SCHEMA_VERSION, "lane": lane,
                    "target": canonical_target_value(target), "finding_id": finding_id,
                    "url": public_url_shape(baseline["url"]), "method": baseline["method"],
                    "generated_at": now_utc(), "result": "partial", "status": "partial",
                    "candidate_ready": False, "runs": runs, "repeat": repeat_count,
                    "request_pair": _request_pair_spec_view(spec), "request_spec_sha256": pair_digest,
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
            "url": public_url_shape(baseline["url"]),
            "method": baseline["method"],
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
        raw_runs = evidence.get("runs")
        if not isinstance(raw_runs, list) or not raw_runs:
            raise ValueError("native evidence runs must contain the recorded execution steps")
        runs = []
        anchor = None
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
            run.update(url=public_url_shape(run_url), method=run_method, artifacts=refs)
            runs.append(run)
            if run_method == method and url == run_url:
                anchor = run
        if anchor is None:
            raise ValueError("native evidence must include the canonical finding's exact endpoint and method")
        actor = normalize_actor(required_text(anchor.get("actor"), "canonical execution actor"))
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
            "url": public_url_shape(url),
            "method": method,
            "vuln_class": vuln_class,
            "generated_at": captured_at.astimezone(timezone.utc).isoformat(),
            "result": result,
            "candidate_ready": result == "tested_finding",
            "observed_difference": observed_difference,
            "state_changing": effective_state,
            "redline_checked": redline_checked,
            "identity_v2": identity_v2,
            "runs": runs,
            "attempt_id": attempt_id or "",
            **command_context,
        }
        # Exact request identities stay in private, digest-bound artifacts. Public
        # URL shapes cannot identify query values for Store observation binding.
        identity_dir = private_artifact_dir(repo_root, "validation", target_storage_key(target), "identities")
        for run, raw_run in zip(runs, raw_runs):
            identity = {"requested_url": raw_run["url"].strip()}
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
    add_cli_args(request_diff)
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    identity_v2: dict[str, Any] | None = None
    if args.identity_v2_json:
        try:
            payload = json.loads(args.identity_v2_json)
            try:
                from tools.identity_contract import ClosureCellKey
            except ImportError:  # pragma: no cover - direct tools/ execution
                from identity_contract import ClosureCellKey  # type: ignore
            identity_v2 = ClosureCellKey.from_dict(payload).to_dict()
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            parser.error(f"--identity-v2-json must contain a valid ClosureCellKey v2: {exc}")
    repo_root = Path(args.repo_root)
    try:
        with _runner_admission(repo_root, args.target) as (store, _):
            if args.lane == "request-diff":
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
    except StoreError as exc:
        print(f"validation-runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
