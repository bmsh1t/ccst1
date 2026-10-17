#!/usr/bin/env python3
"""浏览器 MCP 证据的公共摘要与最近一次捕获读取辅助函数。"""

from __future__ import annotations

import hashlib
import base64
import binascii
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from tools.target_paths import target_storage_key, target_raw_artifact_path
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key, target_raw_artifact_path  # type: ignore


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
BROWSER_FRESHNESS_SECONDS = 24 * 60 * 60


def _target_key(target: str) -> str:
    """返回浏览器 artifact 使用的项目级目标存储键。"""
    return target_storage_key(target)


def snapshot_shape(raw: str) -> str:
    """公共 snapshot 仅保留哈希、长度与 form 形状。"""
    text = str(raw or "")
    forms = []
    for match in re.finditer(r"<form\b(?P<attrs>[^>]*)>", text, re.I):
        attrs = match.group("attrs")
        action = next(iter(re.findall(r"action=[\"']([^\"']+)[\"']", attrs, re.I)), "")
        method = next(iter(re.findall(r"method=[\"']([^\"']+)[\"']", attrs, re.I)), "GET")
        action_path = re.sub(r"\?.*$", "", action)
        forms.append(f'<form action="{action_path}" method="{method.upper()}">')
    encoded = text.encode("utf-8", errors="replace")
    header = f"snapshot_bytes={len(encoded)}\nsnapshot_sha256={hashlib.sha256(encoded).hexdigest()}\n"
    return header + (("\n".join(forms) + "\n") if forms else "")


def console_shape(payload: object) -> dict:
    """将 MCP console 输出压成不含正文的公共摘要。"""
    items = payload if isinstance(payload, list) else []
    return {
        "count": len(items),
        "types": sorted({str(item.get("type") or "") for item in items if isinstance(item, dict)}),
        "sha256": hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }


def _read_summary_from_path(path: str | Path) -> dict:
    candidate = Path(path)
    summary_path = candidate / "summary.json" if candidate.is_dir() else candidate
    if not summary_path.is_file():
        return {}
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def compact_browser_evidence(summary: dict | str | Path | None) -> dict:
    """仅返回 validation 可安全引用的浏览器证据字段。"""
    if not summary:
        return {}
    payload = _read_summary_from_path(summary) if isinstance(summary, (str, Path)) else summary
    if not isinstance(payload, dict) or not payload:
        return {}

    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    compact = {
        "dir": payload.get("evidence_dir") or payload.get("dir") or "",
        "summary_path": payload.get("summary_path") or payload.get("summary") or "",
        "session": payload.get("session") or "",
        "url": payload.get("url") or "",
        "capture_backend": payload.get("capture_backend") or "",
        "request_count": int(counts.get("requests", payload.get("request_count", 0)) or 0),
        "console_count": int(counts.get("console", payload.get("console_count", 0)) or 0),
        "screenshot_path": artifacts.get("screenshot_png") or payload.get("screenshot_path") or "",
        "captured_at": payload.get("captured_at") or "",
        "error": payload.get("error") or "",
    }
    browser_surface = payload.get("browser_surface") if isinstance(payload.get("browser_surface"), dict) else {}
    browser_counts = browser_surface.get("counts") if isinstance(browser_surface.get("counts"), dict) else {}
    browser_artifacts = browser_surface.get("artifacts") if isinstance(browser_surface.get("artifacts"), dict) else {}
    compact.update({
        "browser_xhr_count": int(browser_counts.get("xhr_endpoints", payload.get("browser_xhr_count", 0)) or 0),
        "browser_api_count": int(browser_counts.get("api_endpoints", payload.get("browser_api_count", 0)) or 0),
        "browser_param_count": int(browser_counts.get("browser_params", payload.get("browser_param_count", 0)) or 0),
        "browser_surface_summary": browser_artifacts.get("summary") or payload.get("browser_surface_summary") or "",
    })
    return {key: value for key, value in compact.items() if value not in ("", None)}


def load_last_browser_evidence(target: str, *, evidence_root: str | Path | None = None) -> dict:
    """读取目标最近一次由 MCP 导入的浏览器证据摘要。"""
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    pointer_path = root / _target_key(target) / "browser" / "last-capture.json"
    if not pointer_path.is_file():
        return {}
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(pointer, dict):
        return {}
    summary_path = pointer.get("summary_path")
    return compact_browser_evidence(summary_path or pointer)


def inspect_mcp_browser_readiness(
    repo_root: str | Path,
    target: str,
    *,
    freshness_seconds: int = BROWSER_FRESHNESS_SECONDS,
) -> dict[str, Any]:
    """Validate the importer-owned latest capture without trusting file presence."""
    root = Path(repo_root)
    key = target_storage_key(target)
    pointer_path = root / "evidence" / key / "browser" / "last-capture.json"
    result: dict[str, Any] = {
        "present": False,
        "ready": False,
        "status": "missing",
        "success": False,
        "core_network": False,
        "fresh": False,
        "fingerprint": "",
        "fingerprint_valid": False,
        "auth_required": False,
        "auth_state": "unknown",
        "summary_path": str(pointer_path),
        "reason": "missing browser capture",
    }
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return result
    if not isinstance(pointer, dict):
        result["reason"] = "invalid browser pointer"
        return result
    summary_path = Path(str(pointer.get("summary_path") or ""))
    if not summary_path.is_absolute():
        summary_path = pointer_path.parent / summary_path
    result["summary_path"] = str(summary_path)
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result["reason"] = "missing or invalid browser summary"
        return result
    if not isinstance(summary, dict):
        result["reason"] = "invalid browser summary"
        return result

    result["present"] = True
    result["status"] = str(summary.get("status") or "unknown").strip().lower()
    result["success"] = bool(summary.get("success"))
    counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
    result["core_network"] = int(counts.get("requests", 0) or 0) > 0
    result["fingerprint"] = str(summary.get("network_fingerprint") or "").strip()
    artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
    requests_path = Path(str(artifacts.get("requests_json") or ""))
    try:
        result["fingerprint_valid"] = bool(
            result["fingerprint"]
            and requests_path.is_file()
            and hashlib.sha256(requests_path.read_bytes()).hexdigest() == result["fingerprint"]
        )
    except OSError:
        pass
    private_artifacts = summary.get("private_artifacts") if isinstance(summary.get("private_artifacts"), dict) else {}
    browser_state = (
        private_artifacts.get("browser_state")
        if isinstance(private_artifacts.get("browser_state"), dict)
        else {}
    )
    state_artifact = Path(str(browser_state.get("path") or ""))
    if state_artifact and not state_artifact.is_absolute():
        state_artifact = summary_path.parent / state_artifact
    state_digest = str(browser_state.get("sha256") or "").strip()
    try:
        state_artifact_valid = bool(
            state_artifact.is_file()
            and (
                not state_digest
                or hashlib.sha256(state_artifact.read_bytes()).hexdigest() == state_digest
            )
        )
    except OSError:
        state_artifact_valid = False
    result["auth_required"] = bool(summary.get("auth_required") or summary.get("authenticated"))
    claimed_auth_state = str(summary.get("auth_state") or "").strip().lower()
    result["auth_state"] = (
        "present"
        if state_artifact_valid and claimed_auth_state in {"", "present"}
        else claimed_auth_state
        if claimed_auth_state and claimed_auth_state != "present"
        else "missing"
    )
    try:
        captured_at = datetime.strptime(
            str(summary.get("captured_at") or ""), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        captured_at = None
    result["fresh"] = bool(
        captured_at is not None
        and (datetime.now(timezone.utc) - captured_at).total_seconds() <= freshness_seconds
    )
    result["ready"] = bool(
        result["status"] == "ok"
        and result["success"]
        and result["core_network"]
        and result["fresh"]
        and result["fingerprint_valid"]
        and (not result["auth_required"] or result["auth_state"] == "present")
    )
    failed = []
    if result["status"] != "ok":
        failed.append("status")
    failed.extend(
        name
        for name in ("success", "core_network", "fresh", "fingerprint_valid")
        if not result[name]
    )
    if result["auth_required"] and result["auth_state"] != "present":
        failed.append("missing_state")
    result["reason"] = "ready" if result["ready"] else "browser capture is " + ", ".join(failed or ["not ready"])
    return result


def read_target_artifact(repo_root: str | Path, target: str, reference: str) -> tuple[bytes, str]:
    """Capture a nonempty target-owned regular file with an identity fence."""
    root = Path(repo_root).resolve()
    original = Path(reference)
    original = original if original.is_absolute() else root / original
    path = target_raw_artifact_path(root, target, reference)
    if original.absolute() != path or any(parent.is_symlink() for parent in original.parents):
        raise ValueError(f"linked or noncanonical raw artifact: {reference}")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size == 0:
            raise ValueError(f"raw artifact must be a nonempty regular file: {reference}")
        raw = handle.read()
        after = os.fstat(handle.fileno())
    version = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if version(before) != version(after) or version(after) != version(path.lstat()):
        raise ValueError(f"raw artifact changed during capture: {reference}")
    return raw, path.relative_to(root).as_posix()


def _original_network_items(payload: Any) -> tuple[list, str, str]:
    if isinstance(payload, list):
        return payload, '', 'json'
    if isinstance(payload, dict):
        log = payload.get('log')
        if isinstance(log, dict) and isinstance(log.get('entries'), list):
            return log['entries'], '/log/entries', 'har'
        for key in ('requests', 'networkRequests', 'items', 'entries', 'network', 'data'):
            if isinstance(payload.get(key), list):
                return payload[key], '/'+key, 'json'
        data = payload.get('data')
        if isinstance(data, dict):
            for key in ('requests', 'networkRequests', 'items', 'entries', 'network'):
                if isinstance(data.get(key), list):
                    return data[key], '/data/'+key, 'json'
    raise ValueError('unrecognized original network payload; discovery material is not an experiment')


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f'invalid JSON constant in browser evidence: {value}')


def _body_capture_state(message: dict, *, request: bool) -> str:
    """Do not conflate an explicitly empty body with a body not captured."""
    containers = [message]
    nested = message.get('postData' if request else 'content')
    if isinstance(nested, dict):
        containers.insert(0, nested)
    for container in containers:
        for key in ('text', 'body', 'data', 'postData'):
            if key in container and isinstance(container[key], (str, dict, list)):
                value = container[key]
                if (container.get('encoding') == 'base64' or container.get('base64Encoded') is True
                        or message.get('base64Encoded') is True):
                    if not isinstance(value, str):
                        raise ValueError('base64 browser body must be text')
                    try:
                        base64.b64decode(value, validate=True)
                    except (ValueError, binascii.Error) as exc:
                        raise ValueError('invalid base64 browser body') from exc
                # A structured postData/content object without its actual body
                # is metadata, not a captured body.
                if key == 'postData' and isinstance(value, dict):
                    continue
                return 'explicit_empty' if value == '' else 'captured'
    if (type(message.get('bodySize')) is int and message['bodySize'] == 0
            or request and message.get('hasPostData') is False):
        return 'known_empty'
    return 'missing'


def read_browser_observation_capture(repo_root: str | Path, target: str, capture_ref: str) -> dict:
    """Read original JSON/HAR only; no publishers, Store, discovery defaults or I/O replay."""
    root = Path(repo_root).resolve()
    summary_raw, summary_ref = read_target_artifact(root, target, capture_ref)
    expected_root = root / 'evidence' / target_storage_key(target) / 'browser'
    summary_path = root / summary_ref
    if not summary_path.is_relative_to(expected_root) or summary_path.name != 'summary.json':
        raise ValueError('browser capture ref must identify this target\'s capture summary.json')
    summary = json.loads(summary_raw.decode('utf-8'), parse_constant=_invalid_json_constant)
    if not isinstance(summary, dict) or target_storage_key(summary.get('target', '')) != target_storage_key(target):
        raise ValueError('browser capture target mismatch')
    source = summary.get('network_source')
    if not source:
        private = summary.get('private_artifacts') or {}
        source = private.get('network_har')
        if not source:
            raise ValueError('unverifiable_capture: no original network baseline; old JSON discovery is not raw evidence')
        source = {**source, 'format': 'har'}
    if (not isinstance(source, dict) or not isinstance(source.get('path'), str)
            or not isinstance(source.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', source['sha256'])
            or type(source.get('bytes')) is not int or source['bytes'] <= 0
            or source.get('format') not in {'json', 'har', 'text'}):
        raise ValueError('invalid original network baseline')
    network_raw, network_ref = read_target_artifact(root, target, source['path'])
    if hashlib.sha256(network_raw).hexdigest() != source['sha256'] or len(network_raw) != source['bytes']:
        raise ValueError('original network source changed from its capture baseline')
    if source['format'] == 'text':
        raise ValueError('unverifiable_capture: text network listing is discovery only')
    payload = json.loads(network_raw.decode('utf-8'), parse_constant=_invalid_json_constant)
    items, prefix, actual_format = _original_network_items(payload)
    if actual_format != source['format']:
        raise ValueError('original network format does not match baseline')
    if isinstance(payload, dict) and (payload.get('success') is False or
            str(payload.get('status', '')).lower() in {'error', 'failed', 'failure', 'timeout', 'stale'}):
        raise ValueError('failed original network export is not verified browser evidence')
    runs, diagnostics = [], []
    if summary.get('error'):
        diagnostics.append({'error': 'capture_error', 'description': str(summary['error'])[:400]})
    export_envelopes = [payload] if isinstance(payload, dict) else []
    if isinstance(payload, dict) and isinstance(payload.get('data'), dict):
        export_envelopes.append(payload['data'])
    if any(value.get('error') or value.get('truncated') is True or value.get('body_truncated') is True
           or str(value.get('status', '')).lower() == 'partial' for value in export_envelopes):
        diagnostics.append({'error': 'incomplete_network_export; retained in original capture'})
    for index, item in enumerate(items):
        pointer = f'{prefix}/{index}'
        if not isinstance(item, dict):
            diagnostics.append({'source_index': index, 'pointer': pointer, 'error': 'non-object discovery entry'})
            continue
        request = item.get('request') if isinstance(item.get('request'), dict) else item
        response = item.get('response')
        url = request.get('url') or item.get('requestUrl') or item.get('url')
        method = request.get('method') or item.get('method')
        timestamp = item.get('observed_at') or item.get('startedDateTime') or request.get('observed_at') or item.get('timestamp')
        try:
            if timestamp is None and type(item.get('wallTime')) in (int, float):
                timestamp = datetime.fromtimestamp(item['wallTime'], timezone.utc).isoformat()
            if not isinstance(timestamp, str):
                raise ValueError('missing actual observation time')
            observed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if observed.tzinfo is None:
                raise ValueError('observation time has no timezone')
            if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                raise ValueError('missing exact absolute HTTP URL')
            if not isinstance(method, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', method):
                raise ValueError('missing actual HTTP method')
        except (OSError, ValueError, OverflowError) as exc:
            diagnostics.append({'source_index': index, 'pointer': pointer, 'error': str(exc)})
            continue
        request_state = _body_capture_state(request, request=True)
        missing = []
        if request_state == 'missing':
            missing.append('request.body')
        if not isinstance(request.get('headers'), (dict, list)):
            missing.append('request.headers')
        response_state = 'missing'
        if isinstance(response, dict):
            response_state = _body_capture_state(response, request=False)
            status = response.get('status')
            if response_state == 'missing' and (type(status) is int and status in {204, 304} or method.upper() == 'HEAD'):
                response_state = 'protocol_no_body'
            if type(response.get('status')) is not int or not 100 <= response['status'] <= 599:
                missing.append('response.status')
            if not isinstance(response.get('headers'), (dict, list)):
                missing.append('response.headers')
            if response_state == 'missing':
                missing.append('response.body')
        else:
            missing.append('response')
        response_object = response if isinstance(response, dict) else {}
        error = item.get('error') or item.get('_failureText') or response_object.get('error')
        if error and not isinstance(error, str):
            error = json.dumps(error, ensure_ascii=False, sort_keys=True)
        body_containers = [value for value in (request.get('postData'), response_object.get('content')) if isinstance(value, dict)]
        truncated = any(container.get(key) is True for container in (item, request, response_object, *body_containers)
                        for key in ('truncated', 'body_truncated'))
        provenance = {'source_index': index, 'pointer': pointer, 'format': actual_format,
                      'request_id': item.get('requestId', item.get('id')), 'source_sha256': source['sha256'],
                      'network_ref': network_ref, 'request_body': request_state, 'response_body': response_state}
        run = {'url': url, 'method': method.upper(), 'observed_at': observed.astimezone(timezone.utc).isoformat(),
               'description': str(item.get('description') or f'Browser captured request at {pointer}'),
               'source_index': index, 'provenance': provenance, 'missing': missing,
               'body_truncated': truncated, 'error': error or '',
               'private_request': {'kind': 'browser-original-slice', 'provenance': provenance, 'request': request},
               'artifacts': {'network_source': network_ref, 'capture_summary': summary_ref}}
        if isinstance(response, dict):
            run['private_response'] = {'kind': 'browser-original-slice', 'provenance': provenance, 'response': response}
        runs.append(run)
    return {'runs': runs, 'diagnostics': diagnostics, 'network_source': {**source, 'path': network_ref},
            'capture_summary': summary_ref, 'capture_sha256': hashlib.sha256(summary_raw).hexdigest()}
