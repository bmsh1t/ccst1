#!/usr/bin/env python3
"""Shared canonical runner-witness verification for validation and reporting."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

try:
    from .closure_resolver import canonical_vuln_class
    from .target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from .validation_runner import _artifact_digest_material, _runner_operation_id
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_resolver import canonical_vuln_class  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from validation_runner import _artifact_digest_material, _runner_operation_id  # type: ignore


BASE_DIR = Path(__file__).resolve().parents[1]
RUNNER_SUMMARY_SCHEMA_VERSION = 1


def _repo_root_for_findings_dir(findings_dir):
    root = Path(findings_dir).expanduser().resolve()
    if root.parent.name == "findings":
        return root.parent.parent
    return BASE_DIR.resolve()


def _resolve_repo_file(value, repo_root):
    raw = str(value or "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path(repo_root) / path
    try:
        path = path.resolve()
        path.relative_to(Path(repo_root).resolve())
    except (OSError, ValueError):
        return None
    return path if path.is_file() else None


def _load_json_file(path):
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _runner_summary_candidates(finding, repo_root):
    """Yield the direct or nested canonical runner summaries for one finding."""
    pending = []
    for value in (
        finding.get("runner_summary"),
        finding.get("runner_summary_path"),
        finding.get("validation_summary"),
    ):
        path = _resolve_repo_file(value, repo_root)
        if path:
            pending.append(path)
    seen = set()
    while pending:
        path = pending.pop(0)
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        payload = _load_json_file(path)
        if not isinstance(payload, dict):
            continue
        yield path, payload
        machine = payload.get("machine_decision")
        nested = machine.get("runner_summary") if isinstance(machine, dict) else None
        for value in (nested, payload.get("runner_summary")):
            child = _resolve_repo_file(value, repo_root)
            if child and str(child) not in seen:
                pending.append(child)


def _runner_class(value):
    canonical = canonical_vuln_class(str(value or ""))
    return canonical or str(value or "").strip().lower().replace("-", "_")


def _endpoint_identity(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        return f"{path}?{parsed.query}" if parsed.query else path
    return raw


def _runner_endpoint_matches(expected, candidate, target):
    if not expected or not candidate:
        return False
    for value in (expected, candidate):
        raw = str(value or "").strip()
        scheme = urlparse(raw).scheme.lower()
        if (scheme in {"http", "https", "ws", "wss"} or raw.startswith("//")) and not url_belongs_to_target(
            raw, target
        ):
            return False
    if _endpoint_identity(expected) == _endpoint_identity(candidate):
        return True

    # Runner summaries use ``public_url_shape`` and intentionally redact query
    # values. Preserve endpoint identity by requiring the same path and
    # ordered parameter names; only an empty runner-side value may differ.
    def shape(value):
        raw = str(value or "").strip()
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            path = parsed.path or "/"
        else:
            parsed = urlparse(f"local://host/{raw.lstrip('/')}")
            path = parsed.path or "/"
        path = path.rstrip("/") or "/"
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        return path, pairs

    try:
        expected_path, expected_pairs = shape(expected)
        candidate_path, candidate_pairs = shape(candidate)
    except ValueError:
        return False
    if expected_path != candidate_path or len(expected_pairs) != len(candidate_pairs):
        return False
    return all(
        expected_name == candidate_name
        and (expected_value == candidate_value or candidate_value == "")
        for (expected_name, expected_value), (candidate_name, candidate_value)
        in zip(expected_pairs, candidate_pairs)
    )


def _runner_ledger_row(repo_root, target, runner, artifact_refs):
    """Return the exact replay row that authorizes a runner summary."""
    record = runner.get("ledger_record")
    if not isinstance(record, dict):
        return None
    operation_id = str(runner.get("operation_id") or "").strip()
    event_id = str(record.get("event_id") or "").strip()
    if not operation_id or not event_id or record.get("replayed") is not True:
        return None
    expected_event = "ledger:" + hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:24]
    if event_id != expected_event or str(record.get("operation_id") or "") != operation_id:
        return None
    ledger_path = (
        Path(repo_root)
        / "memory"
        / "evidence"
        / target_storage_key(target)
        / "ledger.jsonl"
    )
    try:
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for raw in lines:
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(entry, dict) or str(entry.get("event_id") or "") != event_id:
            continue
        if entry.get("replayed") is not True:
            return None
        if canonical_target_value(str(entry.get("target") or "")) != canonical_target_value(target):
            return None
        if str(entry.get("operation_id") or "") != operation_id:
            return None
        if str(entry.get("method") or "GET").upper() != str(runner.get("method") or "GET").upper():
            return None
        if str(entry.get("result") or "") != str(runner.get("result") or ""):
            return None
        if not _runner_endpoint_matches(
            str(runner.get("url") or runner.get("endpoint") or ""),
            str(entry.get("raw_endpoint") or entry.get("endpoint") or ""),
            target,
        ):
            return None
        runner_class = _runner_class(runner.get("vuln_class"))
        entry_class = _runner_class(entry.get("vuln_class"))
        if runner_class and entry_class and runner_class != entry_class:
            return None
        evidence_ref = str(entry.get("evidence_ref") or "").strip()
        if evidence_ref:
            resolved_ref = _resolve_repo_file(evidence_ref, repo_root)
            if resolved_ref is None or str(resolved_ref) not in artifact_refs:
                return None
        return entry
    return None


def canonical_runner_witness(finding, *, findings_dir, target):
    """Validate the immutable runner evidence consumed by validation/reporting."""
    repo_root = _repo_root_for_findings_dir(findings_dir)
    expected_target = canonical_target_value(target or "")
    expected_endpoint = str(finding.get("url") or finding.get("endpoint") or "").strip()
    expected_method = str(finding.get("method") or "GET").strip().upper() or "GET"
    expected_id = str(finding.get("id") or "").strip()
    errors = []
    for summary_path, runner in _runner_summary_candidates(finding, repo_root):
        if runner.get("schema_version") != RUNNER_SUMMARY_SCHEMA_VERSION:
            errors.append("runner schema mismatch")
            continue
        recorded_path = _resolve_repo_file(runner.get("summary_path"), repo_root)
        if recorded_path != summary_path:
            errors.append("runner summary path mismatch")
            continue
        if canonical_target_value(str(runner.get("target") or "")) != expected_target:
            errors.append("runner target mismatch")
            continue
        if str(runner.get("finding_id") or "").strip() != expected_id:
            errors.append("runner finding mismatch")
            continue
        if not _runner_endpoint_matches(
            expected_endpoint,
            str(runner.get("url") or runner.get("endpoint") or runner.get("raw_endpoint") or ""),
            expected_target,
        ):
            errors.append("runner endpoint mismatch")
            continue
        if str(runner.get("method") or "GET").strip().upper() != expected_method:
            errors.append("runner method mismatch")
            continue
        if runner.get("result") != "tested_finding" or runner.get("candidate_ready") is not True:
            errors.append("runner is not a candidate-ready finding")
            continue
        operation_id = str(runner.get("operation_id") or "").strip()
        if not operation_id or str(finding.get("runner_operation_id") or "").strip() != operation_id:
            errors.append("runner operation is not bound to the canonical finding")
            continue
        bindings = runner.get("artifact_bindings")
        if not isinstance(bindings, list) or not bindings:
            errors.append("runner artifacts are missing")
            continue
        kinds = set()
        refs = set()
        valid_bindings = True
        for binding in bindings:
            if not isinstance(binding, dict):
                valid_bindings = False
                break
            kind = str(binding.get("kind") or "").strip().lower()
            artifact = _resolve_repo_file(binding.get("ref"), repo_root)
            digest = str(binding.get("sha256") or "").strip().lower()
            if not kind or artifact is None or not re.fullmatch(r"[0-9a-f]{64}", digest):
                valid_bindings = False
                break
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
                valid_bindings = False
                break
            kinds.add(kind)
            refs.add(str(artifact))
        if not valid_bindings:
            errors.append("runner artifact digest or path mismatch")
            continue
        if not any(kind == "request" or kind.endswith("_request") for kind in kinds):
            errors.append("runner request artifact is missing")
            continue
        if not any(kind == "response" or kind.endswith("_response") for kind in kinds):
            errors.append("runner response artifact is missing")
            continue
        operation_material = runner.get("operation_material")
        if not isinstance(operation_material, dict):
            errors.append("runner operation material is missing")
            continue
        expected_material = _artifact_digest_material(bindings)
        if operation_material.get("artifact_bindings") != expected_material:
            errors.append("runner operation material artifact binding mismatch")
            continue
        if canonical_target_value(str(operation_material.get("target") or "")) != expected_target:
            errors.append("runner operation material target mismatch")
            continue
        if _runner_operation_id(operation_material) != operation_id:
            errors.append("runner operation ID does not match canonical material")
            continue
        ledger = _runner_ledger_row(repo_root, expected_target, runner, refs)
        if ledger is None:
            errors.append("runner ledger replay binding is missing")
            continue
        return {
            "valid": True,
            "summary_path": summary_path,
            "summary": runner,
            "ledger": ledger,
        }
    return {"valid": False, "reason": errors[-1] if errors else "canonical runner summary is missing"}


# Keep the old private name available to callers that imported it directly.
_canonical_runner_witness = canonical_runner_witness
