#!/usr/bin/env python3
"""Deterministic validation runner for Claude-driven security findings.

Validation Runner v1 intentionally stays small:

- authz-public-exposure: one anonymous/read-only request, sensitive exposure check.
- sqli-result-diff: baseline vs single-variable perturbation, structural diff.
- marker-replay: exact request replay plus inert marker evidence check.
- idor-actor-pair: owner vs peer exact replay plus response diff and evidence gate.
- idor-skeleton: create a two-actor evidence bundle skeleton without guessing sessions.

AI 仍负责选择 hypothesis、解释业务影响、决定是否升级/降级；本工具只负责稳定
执行 replay / diff / evidence bundle / ledger 写入。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.evidence_ledger import record_entry
    from tools.evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence
    from tools.response_diff import diff_responses, snapshot_response
    from tools.target_case_state import complete_backlog, load_case_state
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from evidence_ledger import record_entry  # type: ignore
    from evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence  # type: ignore
    from response_diff import diff_responses, snapshot_response  # type: ignore
    from target_case_state import complete_backlog, load_case_state  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}
PUBLIC_EXPOSURE_MARKERS = {
    "admin": re.compile(r"\badmin(?:istrat(?:or|ion))?\b", re.I),
    "configuration": re.compile(r"\b(application[-_/ ]?)?config(?:uration)?\b|\bsettings\b", re.I),
    "oauth": re.compile(r"\boauth|client[_-]?id|redirect_uri|authorizedredirects\b", re.I),
    "secret-like": re.compile(r"\b(secret|token|api[_-]?key|password|private key)\b", re.I),
    "security-answer": re.compile(r"security(question|answer)|geoStalking.*Security", re.I),
}
SQLI_PROBE_RE = re.compile(
    r"('|--|/\*|\*/|;|\)\)|\b(?:or|and|union|select|where|from|sleep|benchmark|"
    r"waitfor|pg_sleep|information_schema|null|true|false)\b|\$(?:ne|gt|regex|where)\b|\{\s*\"?\$)",
    re.I,
)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    return repo_root / "evidence" / target_key / "validation" / _safe_id(finding_id, "finding")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def parse_headers(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            raise ValueError(f"header must be 'Name: value': {raw!r}")
        name, value = raw.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"header name is empty: {raw!r}")
        headers[name] = value.strip()
    return headers


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


def request_once(
    *,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 10,
) -> dict[str, Any]:
    """Replay one HTTP request and return raw evidence fields."""
    method_u = str(method or "GET").upper()
    headers = dict(headers or {})
    data = body.encode("utf-8") if body else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method_u)
    request_text = _format_request(method_u, url, headers, body)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = int(response.status)
            reason = str(response.reason or "")
            response_headers = {str(k): str(v) for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = int(exc.code)
        reason = str(exc.reason or "")
        response_headers = {str(k): str(v) for k, v in exc.headers.items()}
    body_text = raw.decode("utf-8", errors="replace")
    return {
        "url": url,
        "method": method_u,
        "request_text": request_text,
        "status": status,
        "reason": reason,
        "headers": response_headers,
        "body": body_text,
        "response_text": _format_response(status, reason, response_headers, body_text),
    }


def public_exposure_markers(url: str, body: str) -> list[str]:
    haystack = f"{url}\n{body or ''}"
    return [name for name, pattern in PUBLIC_EXPOSURE_MARKERS.items() if pattern.search(haystack)]


def public_exposure_marker_sources(url: str, body: str) -> dict[str, list[str]]:
    """Return marker names split by path/source so path-only hits do not over-validate.

    Admin/config words in a URL are useful routing signals, but they are not by
    themselves proof that anonymous users received sensitive data.  Keep both
    views so Claude can reason about the lead while the runner only promotes
    body-backed exposure to ``tested_finding``.
    """
    return {
        "url": [name for name, pattern in PUBLIC_EXPOSURE_MARKERS.items() if pattern.search(url or "")],
        "body": [name for name, pattern in PUBLIC_EXPOSURE_MARKERS.items() if pattern.search(body or "")],
    }


def public_exposure_candidate_ready(status: int, marker_sources: dict[str, list[str]]) -> bool:
    """Decide whether anonymous public exposure has enough body-backed evidence."""
    if int(status or 0) != 200:
        return False
    body_markers = set(marker_sources.get("body", []) or [])
    all_markers = body_markers | set(marker_sources.get("url", []) or [])
    if body_markers & {"oauth", "secret-like", "security-answer"}:
        return True
    if "configuration" in body_markers and all_markers & {"admin", "configuration"}:
        return True
    return len(body_markers) >= 2


def looks_like_sqli_probe(value: str) -> bool:
    """Return True when the perturbation is injection-shaped, not ordinary search text."""
    return bool(SQLI_PROBE_RE.search(str(value or "")))


def _is_success_status(status: int) -> bool:
    return 200 <= int(status or 0) < 300


def _is_denied_status(status: int) -> bool:
    return int(status or 0) in {401, 403, 404}


def _actor_context_differs(
    *,
    url: str,
    peer_url: str,
    owner_headers: dict[str, str],
    peer_headers: dict[str, str],
    owner_body: str,
    peer_body: str,
) -> bool:
    """Avoid validating a fake actor diff with two identical request contexts."""
    return (
        url != peer_url
        or owner_headers != peer_headers
        or str(owner_body or "") != str(peer_body or "")
    )


def _case_state_session_header(state: dict[str, Any], actor: str) -> tuple[str, dict[str, str]]:
    invalid = {"invalid", "expired", "revoked"}
    for session_id, session in (state.get("sessions") or {}).items():
        if not isinstance(session, dict) or session.get("actor") != actor:
            continue
        if str(session.get("validity") or "unknown").lower() in invalid:
            continue
        headers = session.get("headers") if isinstance(session.get("headers"), dict) else {}
        normalized = {
            str(name).strip(): str(value).strip()
            for name, value in headers.items()
            if str(name).strip() and str(value).strip()
        }
        name = str(session.get("header_name") or "").strip()
        value = str(session.get("header_value") or "").strip()
        if name and value:
            normalized.setdefault(name, value)
        if normalized:
            return str(session_id), normalized
    raise ValueError(f"case_state session missing for actor: {actor}")


def _case_state_backlog(state: dict[str, Any], backlog_id: str) -> dict[str, Any]:
    for item in state.get("validation_backlog") or []:
        if isinstance(item, dict) and item.get("id") == backlog_id:
            return item
    raise ValueError(f"case_state backlog id not found: {backlog_id}")


def resolve_idor_actor_pair_from_case_state(
    *,
    repo_root: Path,
    target: str,
    backlog_id: str = "",
    owner_actor: str = "",
    peer_actor: str = "",
    object_ref: str = "",
    url: str = "",
    peer_url: str = "",
    owner_headers: dict[str, str] | None = None,
    peer_headers: dict[str, str] | None = None,
    expect_marker: str = "",
) -> dict[str, Any]:
    """Resolve IDOR actor-pair replay material from target case_state.json."""
    state = load_case_state(repo_root, target)
    backlog: dict[str, Any] = _case_state_backlog(state, backlog_id) if backlog_id else {}
    if backlog and backlog.get("runner") != "idor-actor-pair":
        raise ValueError(f"case_state backlog is not idor-actor-pair: {backlog_id}")

    ref = object_ref or str(backlog.get("object_ref") or "")
    if not ref:
        raise ValueError("object_ref is required when using --from-case-state")
    obj = (state.get("objects") or {}).get(ref)
    if not isinstance(obj, dict):
        raise ValueError(f"case_state object_ref not found: {ref}")

    owner = owner_actor or str(backlog.get("owner_actor") or obj.get("owner_actor") or "")
    peer = peer_actor or str(backlog.get("peer_actor") or "")
    if not owner:
        raise ValueError(f"case_state owner actor missing for object_ref: {ref}")
    if not peer:
        raise ValueError("peer_actor is required when using --from-case-state")
    if owner == peer:
        raise ValueError("owner_actor and peer_actor must differ when using --from-case-state")
    if owner not in (state.get("actors") or {}):
        raise ValueError(f"case_state owner actor not found: {owner}")
    if peer not in (state.get("actors") or {}):
        raise ValueError(f"case_state peer actor not found: {peer}")

    owner_session_id, owner_session_header = _case_state_session_header(state, owner)
    peer_session_id, peer_session_header = _case_state_session_header(state, peer)
    merged_owner_headers = {**owner_session_header, **dict(owner_headers or {})}
    merged_peer_headers = {**peer_session_header, **dict(peer_headers or {})}
    endpoint = url or str(backlog.get("endpoint") or obj.get("endpoint") or "")
    if not endpoint:
        raise ValueError(f"case_state endpoint missing for object_ref: {ref}")

    return {
        "url": endpoint,
        "peer_url": peer_url or endpoint,
        "owner_headers": merged_owner_headers,
        "peer_headers": merged_peer_headers,
        "expect_marker": expect_marker or str(obj.get("private_marker") or ""),
        "case_state_ref": {
            "backlog_id": backlog_id,
            "object_ref": ref,
            "owner_actor": owner,
            "peer_actor": peer,
            "owner_session_id": owner_session_id,
            "peer_session_id": peer_session_id,
        },
    }


def _record_ledger_if_needed(
    *,
    repo_root: Path,
    no_ledger: bool,
    target: str,
    endpoint: str,
    method: str,
    vuln_class: str,
    actor: str,
    object_scope: str,
    variant: str,
    result: str,
    source: str,
    evidence_ref: str,
    notes: str,
    browser_observed: bool,
    redline_checked: bool,
    state_changing: bool | None = None,
) -> dict[str, Any] | None:
    if no_ledger:
        return None
    return record_entry(
        repo_root,
        target=target,
        endpoint=endpoint,
        method=method,
        vuln_class=vuln_class,
        actor=actor,
        object_scope=object_scope,
        variant=variant,
        source=source,
        result=result,
        browser_observed=browser_observed,
        replayed=True,
        state_changing=bool(state_changing) if state_changing is not None else method.upper() not in SAFE_METHODS,
        redline_checked=redline_checked,
        evidence_ref=evidence_ref,
        notes=notes,
    )


def run_authz_public_exposure(
    *,
    repo_root: Path,
    target: str,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 10,
    finding_id: str = "",
    no_ledger: bool = False,
    browser_observed: bool = False,
) -> dict[str, Any]:
    finding_id = finding_id or _default_finding_id("authz-public-exposure", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    response = request_once(url=url, method=method, headers=headers, body=body, timeout=timeout)
    request_path = bundle / "baseline.request.txt"
    response_path = bundle / "baseline.response.txt"
    _write_text(request_path, response["request_text"])
    _write_text(response_path, response["response_text"])

    marker_sources = public_exposure_marker_sources(url, response["body"])
    markers = sorted(set(marker_sources["url"]) | set(marker_sources["body"]))
    candidate_ready = public_exposure_candidate_ready(response["status"], marker_sources)
    result = "tested_finding" if candidate_ready else "tested_clean"
    finding = {
        "type": "auth_bypass",
        "url": url,
        "summary": f"{response['status']} {len(response['body'])} {url} markers={','.join(markers)} unauthenticated public exposure",
        "raw": f"anonymous replay returned {response['status']} with markers {markers}",
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding))
    evidence_ref = _rel(response_path, repo_root)
    notes = (
        f"Validation runner authz-public-exposure: anonymous {method.upper()} returned "
        f"{response['status']} with markers={markers or []}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method,
        vuln_class="Authz",
        actor="anonymous",
        object_scope="none",
        variant="unauth_denied",
        result=result,
        source="validation-runner:authz-public-exposure",
        evidence_ref=evidence_ref,
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=True,
    )

    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "authz_public_exposure",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "method": method.upper(),
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "markers": markers,
        "marker_sources": marker_sources,
        "baseline": snapshot_response(response["status"], response["headers"], response["body"]),
        "artifacts": {
            "baseline_request": _rel(request_path, repo_root),
            "baseline_response": _rel(response_path, repo_root),
        },
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "anonymous user can read admin/config-like data",
            "next_action": "If business impact is meaningful, run /validate using this evidence bundle; otherwise downgrade to informational/dead-end.",
            "stop_condition": "No 200 response or no body-backed sensitive/admin/config marker.",
        },
    }
    summary_path = bundle / "summary.json"
    _write_json(summary_path, summary)
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def _replace_query_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    out: list[tuple[str, str]] = []
    for key, old in pairs:
        if key == param:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, old))
    if not replaced:
        out.append((param, value))
    query = urllib.parse.urlencode(out, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def run_sqli_result_diff(
    *,
    repo_root: Path,
    target: str,
    url: str,
    param: str,
    baseline_value: str,
    variant_value: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    no_ledger: bool = False,
    browser_observed: bool = False,
) -> dict[str, Any]:
    if method.upper() != "GET":
        raise ValueError("sqli-result-diff v1 supports GET query parameters only")
    finding_id = finding_id or _default_finding_id("sqli-result-diff", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    repeat = max(1, int(repeat or 1))
    baseline_url = _replace_query_param(url, param, baseline_value)
    variant_url = _replace_query_param(url, param, variant_value)
    runs: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        base = request_once(url=baseline_url, method=method, headers=headers, timeout=timeout)
        variant = request_once(url=variant_url, method=method, headers=headers, timeout=timeout)
        prefix = "" if repeat == 1 else f"{idx}."
        base_req = bundle / f"{prefix}baseline.request.txt"
        base_resp = bundle / f"{prefix}baseline.response.txt"
        var_req = bundle / f"{prefix}variant.request.txt"
        var_resp = bundle / f"{prefix}variant.response.txt"
        _write_text(base_req, base["request_text"])
        _write_text(base_resp, base["response_text"])
        _write_text(var_req, variant["request_text"])
        _write_text(var_resp, variant["response_text"])
        diff = diff_responses(
            baseline_status=base["status"],
            baseline_headers=base["headers"],
            baseline_body=base["body"],
            variant_status=variant["status"],
            variant_headers=variant["headers"],
            variant_body=variant["body"],
        )
        runs.append({
            "iteration": idx,
            "baseline_url": baseline_url,
            "variant_url": variant_url,
            "artifacts": {
                "baseline_request": _rel(base_req, repo_root),
                "baseline_response": _rel(base_resp, repo_root),
                "variant_request": _rel(var_req, repo_root),
                "variant_response": _rel(var_resp, repo_root),
            },
            **diff,
        })

    material = [
        bool(run.get("diff", {}).get("changed", {}).get("json_count"))
        or bool(run.get("diff", {}).get("changed", {}).get("status"))
        or bool(run.get("diff", {}).get("changed", {}).get("json_fields"))
        or abs(int(run.get("diff", {}).get("body_length", {}).get("delta", 0) or 0)) > 20
        for run in runs
    ]
    probe_shape = looks_like_sqli_probe(variant_value)
    candidate_ready = probe_shape and all(material)
    result = "tested_finding" if candidate_ready else "tested_clean"
    diff_summaries = [str(run.get("diff", {}).get("summary") or "") for run in runs]
    finding = {
        "type": "sqli",
        "url": url,
        "summary": (
            f"baseline vs single-variable perturbation on {param}; "
            f"stable differential={candidate_ready}; {'; '.join(diff_summaries)}"
        ),
        "raw": "SQLI-POC-VERIFIED read-only baseline perturbation repeat stable"
        if candidate_ready else "read-only SQLi perturbation did not produce stable material diff",
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding))
    diff_path = bundle / "diff.json"
    _write_json(diff_path, {"runs": runs})
    notes = (
        f"Validation runner SQLi result diff on param={param!r}: "
        f"{'; '.join(diff_summaries[:3])}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method,
        vuln_class="SQLi",
        actor="anonymous",
        object_scope="none",
        variant="replay",
        result=result,
        source="validation-runner:sqli-result-diff",
        evidence_ref=_rel(diff_path, repo_root),
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=True,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "sqli_result_diff",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "method": method.upper(),
        "param": param,
        "baseline_value": baseline_value,
        "variant_value": variant_value,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "probe_shape": probe_shape,
        "repeat": repeat,
        "runs": runs,
        "artifacts": {"diff": _rel(diff_path, repo_root)},
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "single input perturbation changes server-side query result shape",
            "next_action": "If diff is stable and read-only, run /validate or add one minimal DBMS/type confirmation only when needed.",
            "stop_condition": "No stable status/count/field/length difference across repeats, or differences are attributable to WAF/router/cache noise.",
        },
    }
    summary_path = bundle / "summary.json"
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def run_marker_replay(
    *,
    repo_root: Path,
    target: str,
    url: str,
    expect_marker: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    vuln_class: str = "RCE",
    no_ledger: bool = False,
    browser_observed: bool = False,
    state_changing: bool = False,
    redline_checked: bool = True,
) -> dict[str, Any]:
    """Replay an exact request and require an inert marker in every response.

    This lane deliberately does not generate payloads. Claude/operator chooses
    the hypothesis and exact safe marker request; the runner only handles stable
    replay, evidence artifacts, rubric, and ledger output.
    """
    marker = str(expect_marker or "")
    if not marker:
        raise ValueError("expect_marker is required")
    finding_id = finding_id or _default_finding_id("marker-replay", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    repeat = max(1, int(repeat or 1))
    method_u = method.upper()
    runs: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        response = request_once(url=url, method=method_u, headers=headers, body=body, timeout=timeout)
        prefix = "" if repeat == 1 else f"{idx}."
        request_path = bundle / f"{prefix}request.txt"
        response_path = bundle / f"{prefix}response.txt"
        _write_text(request_path, response["request_text"])
        _write_text(response_path, response["response_text"])
        marker_found = marker in response["body"]
        runs.append({
            "iteration": idx,
            "url": url,
            "method": method_u,
            "status": response["status"],
            "marker_found": marker_found,
            "artifacts": {
                "request": _rel(request_path, repo_root),
                "response": _rel(response_path, repo_root),
            },
            "snapshot": snapshot_response(response["status"], response["headers"], response["body"]),
        })

    candidate_ready = all(bool(run["marker_found"]) for run in runs)
    result = "tested_finding" if candidate_ready else "tested_clean"
    finding = {
        "type": vuln_class,
        "url": url,
        "summary": (
            f"exact marker replay for {vuln_class}; marker_present={candidate_ready}; "
            f"repeat={repeat}; method={method_u}"
        ),
        "raw": (
            "rce-poc controlled marker exact request safe proof repeated"
            if candidate_ready
            else "exact marker replay did not show expected inert marker"
        ),
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding, vuln_type=vuln_class))
    summary_path = bundle / "summary.json"
    evidence_ref = _rel(summary_path, repo_root)
    notes = (
        f"Validation runner marker-replay for {vuln_class}: "
        f"marker_present={candidate_ready}, repeat={repeat}, method={method_u}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method_u,
        vuln_class=vuln_class,
        actor="anonymous",
        object_scope="none",
        variant="replay",
        result=result,
        source="validation-runner:marker-replay",
        evidence_ref=evidence_ref,
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=redline_checked,
        state_changing=state_changing,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "marker_replay",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "method": method_u,
        "vuln_class": vuln_class,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "expect_marker": marker,
        "repeat": repeat,
        "runs": runs,
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "exact request causes server-side evaluation/execution observable through an inert marker",
            "next_action": "If marker is stable, use /validate to assess execution context and bounded impact; if absent, refine the hypothesis or downgrade.",
            "stop_condition": "Expected inert marker is absent, unstable across repeats, or only appears in client-side/static reflection without execution context.",
        },
    }
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def run_idor_actor_pair(
    *,
    repo_root: Path,
    target: str,
    url: str,
    method: str = "GET",
    owner_headers: dict[str, str] | None = None,
    peer_headers: dict[str, str] | None = None,
    owner_body: str = "",
    peer_body: str | None = None,
    peer_url: str = "",
    expect_marker: str = "",
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    no_ledger: bool = False,
    browser_observed: bool = False,
    state_changing: bool = False,
    redline_checked: bool = True,
    case_state_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay the same object/action as owner and peer, then preserve the diff.

    The strong finding gate is intentionally conservative:
    - owner must succeed;
    - peer must also succeed;
    - and either the peer response contains an operator-provided private marker
      or the peer body exactly matches the owner body with non-trivial length.

    If peer access is possible but the response is not strong enough, the runner
    records ``candidate`` rather than pretending the issue is clean or proven.
    """
    method_u = method.upper()
    owner_headers = dict(owner_headers or {})
    peer_headers = dict(peer_headers or {})
    peer_url = peer_url or url
    peer_body = owner_body if peer_body is None else peer_body
    if not _actor_context_differs(
        url=url,
        peer_url=peer_url,
        owner_headers=owner_headers,
        peer_headers=peer_headers,
        owner_body=owner_body,
        peer_body=peer_body,
    ):
        raise ValueError("owner and peer request contexts are identical; provide distinct actor headers/body/url")

    finding_id = finding_id or _default_finding_id("idor-actor-pair", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    repeat = max(1, int(repeat or 1))
    marker = str(expect_marker or "")
    runs: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        owner = request_once(url=url, method=method_u, headers=owner_headers, body=owner_body, timeout=timeout)
        peer = request_once(url=peer_url, method=method_u, headers=peer_headers, body=peer_body, timeout=timeout)
        prefix = "" if repeat == 1 else f"{idx}."
        owner_req = bundle / f"{prefix}owner.request.txt"
        owner_resp = bundle / f"{prefix}owner.response.txt"
        peer_req = bundle / f"{prefix}peer.request.txt"
        peer_resp = bundle / f"{prefix}peer.response.txt"
        _write_text(owner_req, owner["request_text"])
        _write_text(owner_resp, owner["response_text"])
        _write_text(peer_req, peer["request_text"])
        _write_text(peer_resp, peer["response_text"])
        diff = diff_responses(
            baseline_status=owner["status"],
            baseline_headers=owner["headers"],
            baseline_body=owner["body"],
            variant_status=peer["status"],
            variant_headers=peer["headers"],
            variant_body=peer["body"],
        )
        marker_found = bool(marker and marker in peer["body"])
        exact_body_match = owner["body"] == peer["body"] and len(str(peer["body"] or "").strip()) >= 20
        owner_success = _is_success_status(owner["status"])
        peer_success = _is_success_status(peer["status"])
        peer_denied = _is_denied_status(peer["status"])
        strong_access = owner_success and peer_success and (marker_found if marker else exact_body_match)
        ambiguous_access = owner_success and peer_success and not strong_access
        runs.append({
            "iteration": idx,
            "owner_url": url,
            "peer_url": peer_url,
            "method": method_u,
            "owner_status": owner["status"],
            "peer_status": peer["status"],
            "owner_success": owner_success,
            "peer_success": peer_success,
            "peer_denied": peer_denied,
            "marker_found": marker_found,
            "exact_body_match": exact_body_match,
            "strong_access": strong_access,
            "ambiguous_access": ambiguous_access,
            "artifacts": {
                "owner_request": _rel(owner_req, repo_root),
                "owner_response": _rel(owner_resp, repo_root),
                "peer_request": _rel(peer_req, repo_root),
                "peer_response": _rel(peer_resp, repo_root),
            },
            **diff,
        })

    candidate_ready = all(bool(run["strong_access"]) for run in runs)
    owner_success_all = all(bool(run["owner_success"]) for run in runs)
    peer_denied_all = all(bool(run["peer_denied"]) or not bool(run["peer_success"]) for run in runs)
    ambiguous_any = any(bool(run["ambiguous_access"]) for run in runs)
    if not owner_success_all:
        result = "dead_end"
    elif candidate_ready:
        result = "tested_finding"
    elif ambiguous_any and not peer_denied_all:
        result = "candidate"
    else:
        result = "tested_clean"

    diff_path = bundle / "diff.json"
    _write_json(diff_path, {"runs": runs})
    finding = {
        "type": "idor",
        "url": url,
        "summary": (
            f"owner vs peer replay result={result}; repeat={repeat}; "
            f"peer_statuses={[run['peer_status'] for run in runs]}"
        ),
        "raw": (
            "owner peer other user response diff exact request private marker verified"
            if candidate_ready
            else "owner peer replay captured; strong private-data marker not proven"
        ),
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding, vuln_type="idor"))
    notes = (
        f"Validation runner IDOR actor pair: result={result}, "
        f"repeat={repeat}, peer_statuses={[run['peer_status'] for run in runs]}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method_u,
        vuln_class="IDOR",
        actor="peer",
        object_scope="peer",
        variant="id_swap",
        result=result,
        source="validation-runner:idor-actor-pair",
        evidence_ref=_rel(diff_path, repo_root),
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=redline_checked,
        state_changing=state_changing,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "idor_actor_pair",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "peer_url": peer_url,
        "method": method_u,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "expect_marker": marker,
        "case_state_ref": case_state_ref or {},
        "repeat": repeat,
        "runs": runs,
        "artifacts": {"diff": _rel(diff_path, repo_root)},
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "server may return an owner object/action result when replayed as peer/lower-role",
            "next_action": "If result is dead_end, refresh the owner baseline/session/object endpoint before treating the lane as tested. If result is candidate, add a known private marker/object field or second object to distinguish public/generic data from IDOR.",
            "stop_condition": "Owner baseline is invalid, peer is consistently denied, actor contexts are unavailable, or peer response lacks a private marker/exact owner-body match.",
        },
    }
    summary_path = bundle / "summary.json"
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def run_idor_skeleton(
    *,
    repo_root: Path,
    target: str,
    endpoint: str,
    finding_id: str = "",
) -> dict[str, Any]:
    finding_id = finding_id or _default_finding_id("idor-skeleton", endpoint)
    bundle = _bundle_dir(repo_root, target, finding_id)
    skeleton = {
        "schema_version": SCHEMA_VERSION,
        "lane": "idor_actor_pair_skeleton",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "endpoint": endpoint,
        "generated_at": now_utc(),
        "result": "skeleton",
        "candidate_ready": False,
        "required_artifacts": {
            "owner_baseline_request": _rel(bundle / "owner.baseline.request.txt", repo_root),
            "owner_baseline_response": _rel(bundle / "owner.baseline.response.txt", repo_root),
            "peer_variant_request": _rel(bundle / "peer.variant.request.txt", repo_root),
            "peer_variant_response": _rel(bundle / "peer.variant.response.txt", repo_root),
            "diff": _rel(bundle / "diff.json", repo_root),
        },
        "ai_next": {
            "hypothesis": "server may trust object id without rebinding it to current actor",
            "next_action": "Capture owner baseline with a test-owned object, replay the same object id as peer/lower-role, then diff status/body/object ownership fields.",
            "stop_condition": "No second actor/session, no test-owned object, or stable 403/404/no sensitive field delta.",
        },
    }
    _write_text(
        bundle / "README.md",
        "# IDOR actor-pair validation skeleton\n\n"
        "Fill the four request/response files with test-owned actor A/B evidence, "
        "then run a response diff and record the ledger entry.\n",
    )
    summary_path = bundle / "summary.json"
    skeleton["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, skeleton)
    return skeleton


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic validation evidence lanes")
    sub = parser.add_subparsers(dest="lane", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--target", required=True)
        p.add_argument("--finding-id", default="")
        p.add_argument("--repo-root", default=str(BASE_DIR))

    authz = sub.add_parser("authz-public-exposure", help="Validate anonymous public admin/config exposure")
    add_common(authz)
    authz.add_argument("--url", required=True)
    authz.add_argument("--method", default="GET")
    authz.add_argument("--header", action="append", default=[])
    authz.add_argument("--body", default="")
    authz.add_argument("--timeout", type=int, default=10)
    authz.add_argument("--browser-observed", action="store_true")
    authz.add_argument("--no-ledger", action="store_true")

    sqli = sub.add_parser("sqli-result-diff", help="Validate read-only SQLi-style result differential")
    add_common(sqli)
    sqli.add_argument("--url", required=True)
    sqli.add_argument("--param", required=True)
    sqli.add_argument("--baseline-value", default="")
    sqli.add_argument("--variant-value", required=True)
    sqli.add_argument("--method", default="GET")
    sqli.add_argument("--header", action="append", default=[])
    sqli.add_argument("--timeout", type=int, default=10)
    sqli.add_argument("--repeat", type=int, default=1)
    sqli.add_argument("--browser-observed", action="store_true")
    sqli.add_argument("--no-ledger", action="store_true")

    marker = sub.add_parser("marker-replay", help="Replay exact request and check for an inert marker")
    add_common(marker)
    marker.add_argument("--url", required=True)
    marker.add_argument("--expect-marker", required=True)
    marker.add_argument("--method", default="GET")
    marker.add_argument("--header", action="append", default=[])
    marker.add_argument("--body", default="")
    marker.add_argument("--timeout", type=int, default=10)
    marker.add_argument("--repeat", type=int, default=1)
    marker.add_argument("--vuln-class", default="RCE")
    marker.add_argument("--browser-observed", action="store_true")
    marker.add_argument("--state-changing", action="store_true")
    marker.add_argument("--redline-checked", action="store_true", default=True)
    marker.add_argument("--no-ledger", action="store_true")

    idor_pair = sub.add_parser("idor-actor-pair", help="Replay owner vs peer actor pair and diff responses")
    add_common(idor_pair)
    idor_pair.add_argument("--url", default="")
    idor_pair.add_argument("--peer-url", default="")
    idor_pair.add_argument("--method", default="GET")
    idor_pair.add_argument("--owner-header", action="append", default=[])
    idor_pair.add_argument("--peer-header", action="append", default=[])
    idor_pair.add_argument("--from-case-state", action="store_true")
    idor_pair.add_argument("--backlog-id", default="")
    idor_pair.add_argument("--owner-actor", default="")
    idor_pair.add_argument("--peer-actor", default="")
    idor_pair.add_argument("--object-ref", default="")
    idor_pair.add_argument("--body", default="")
    idor_pair.add_argument("--owner-body", default=None)
    idor_pair.add_argument("--peer-body", default=None)
    idor_pair.add_argument("--expect-marker", default="")
    idor_pair.add_argument("--timeout", type=int, default=10)
    idor_pair.add_argument("--repeat", type=int, default=1)
    idor_pair.add_argument("--browser-observed", action="store_true")
    idor_pair.add_argument("--state-changing", action="store_true")
    idor_pair.add_argument("--redline-checked", action="store_true", default=True)
    idor_pair.add_argument("--no-ledger", action="store_true")
    idor_pair.add_argument("--complete-case-state", action="store_true", help="Write result back to case_state backlog after replay")

    idor = sub.add_parser("idor-skeleton", help="Create a two-actor IDOR validation skeleton")
    add_common(idor)
    idor.add_argument("--endpoint", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(args.repo_root)
    if args.lane == "authz-public-exposure":
        summary = run_authz_public_exposure(
            repo_root=repo_root,
            target=args.target,
            url=args.url,
            method=args.method,
            headers=parse_headers(args.header),
            body=args.body,
            timeout=args.timeout,
            finding_id=args.finding_id,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
        )
    elif args.lane == "sqli-result-diff":
        summary = run_sqli_result_diff(
            repo_root=repo_root,
            target=args.target,
            url=args.url,
            param=args.param,
            baseline_value=args.baseline_value,
            variant_value=args.variant_value,
            method=args.method,
            headers=parse_headers(args.header),
            timeout=args.timeout,
            finding_id=args.finding_id,
            repeat=args.repeat,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
        )
    elif args.lane == "marker-replay":
        summary = run_marker_replay(
            repo_root=repo_root,
            target=args.target,
            url=args.url,
            expect_marker=args.expect_marker,
            method=args.method,
            headers=parse_headers(args.header),
            body=args.body,
            timeout=args.timeout,
            finding_id=args.finding_id,
            repeat=args.repeat,
            vuln_class=args.vuln_class,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
            state_changing=args.state_changing,
            redline_checked=args.redline_checked,
        )
    elif args.lane == "idor-actor-pair":
        owner_body = args.body if args.owner_body is None else args.owner_body
        peer_body = owner_body if args.peer_body is None else args.peer_body
        owner_headers = parse_headers(args.owner_header)
        peer_headers = parse_headers(args.peer_header)
        url = args.url
        peer_url = args.peer_url
        expect_marker = args.expect_marker
        case_state_ref: dict[str, Any] = {}
        if args.from_case_state:
            resolved = resolve_idor_actor_pair_from_case_state(
                repo_root=repo_root,
                target=args.target,
                backlog_id=args.backlog_id,
                owner_actor=args.owner_actor,
                peer_actor=args.peer_actor,
                object_ref=args.object_ref,
                url=url,
                peer_url=peer_url,
                owner_headers=owner_headers,
                peer_headers=peer_headers,
                expect_marker=expect_marker,
            )
            url = resolved["url"]
            peer_url = resolved["peer_url"]
            owner_headers = resolved["owner_headers"]
            peer_headers = resolved["peer_headers"]
            expect_marker = resolved["expect_marker"]
            case_state_ref = resolved["case_state_ref"]
        if not url:
            raise ValueError("--url is required unless --from-case-state resolves an object endpoint")
        summary = run_idor_actor_pair(
            repo_root=repo_root,
            target=args.target,
            url=url,
            method=args.method,
            owner_headers=owner_headers,
            peer_headers=peer_headers,
            owner_body=owner_body,
            peer_body=peer_body,
            peer_url=peer_url,
            expect_marker=expect_marker,
            timeout=args.timeout,
            finding_id=args.finding_id,
            repeat=args.repeat,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
            state_changing=args.state_changing,
            redline_checked=args.redline_checked,
            case_state_ref=case_state_ref,
        )
        if args.complete_case_state:
            backlog_id = str((case_state_ref or {}).get("backlog_id") or "")
            if not args.from_case_state or not backlog_id:
                raise ValueError("--complete-case-state requires --from-case-state with --backlog-id")
            summary["case_state_write_back"] = complete_backlog(
                repo_root,
                args.target,
                backlog_id=backlog_id,
                result=str(summary.get("result") or "candidate"),
                evidence_ref=str(summary.get("summary_path") or ""),
                notes="auto-written by validation_runner --complete-case-state",
            )
    elif args.lane == "idor-skeleton":
        summary = run_idor_skeleton(
            repo_root=repo_root,
            target=args.target,
            endpoint=args.endpoint,
            finding_id=args.finding_id,
        )
    else:  # pragma: no cover - argparse guards this
        raise ValueError(f"unknown lane: {args.lane}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
