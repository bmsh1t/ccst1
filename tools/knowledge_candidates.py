#!/usr/bin/env python3
"""管理可复用经验候选的 staging 与生命周期审计。

这个工具只管理 `knowledge/candidates/` 的候选草稿和追加式状态事件，不读取或
修改 `findings.json`、`memory/patterns.jsonl` 的发现状态。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
CANDIDATES_DIR = BASE_DIR / "knowledge" / "candidates"
LIFECYCLE_PATH = CANDIDATES_DIR / "lifecycle.jsonl"
STATUSES = {"pending", "reviewed", "promoted", "rejected", "superseded"}
TERMINAL_STATUSES = {"promoted", "rejected", "superseded"}
EVENTS = {"staged", "reviewed", "promoted", "rejected", "superseded"}
TARGET_SOURCE = "target-memory"
LOCAL_REF_RE = re.compile(r"^(?P<path>[^#]+)(?:#L(?P<line>[1-9][0-9]*))?$")

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.experience_schema import (
        EXPERIENCE_KINDS,
        normalize_evidence_refs,
        normalize_experience_kind,
        scrub_experience_text,
    )
    from tools.knowledge_audit import audit_repository
    from tools.knowledge_registry import (
        KnowledgeRegistryError,
        REPORT_ID_RE,
        SOURCE_REF_TYPE,
        load_registry,
    )
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from experience_schema import (  # type: ignore
        EXPERIENCE_KINDS,
        normalize_evidence_refs,
        normalize_experience_kind,
        scrub_experience_text,
    )
    from knowledge_audit import audit_repository  # type: ignore
    from knowledge_registry import (  # type: ignore
        KnowledgeRegistryError,
        REPORT_ID_RE,
        SOURCE_REF_TYPE,
        load_registry,
    )
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


CORPUS_SOURCE = SOURCE_REF_TYPE


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _target_memory_path(repo_root: Path | str, target: str) -> Path:
    return Path(repo_root) / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json"


def _relative(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _append_event(event: dict[str, Any], *, path: Path = LIFECYCLE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def _write_text_atomic(path: Path, content: str) -> None:
    """Write a candidate draft without exposing a partial markdown file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
        raise


def _event(
    *,
    candidate_id: str,
    action: str,
    from_status: str | None,
    to_status: str,
    candidate_path: str,
    sources: list[dict[str, Any]] | None = None,
    evidence_refs: list[str] | None = None,
    reviewer: str = "",
    reason: str = "",
    card_id: str = "",
    replacement: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "event_id": f"evt-{uuid.uuid4().hex}",
        "candidate_id": candidate_id,
        "event": action,
        "from_status": from_status,
        "to_status": to_status,
        "candidate_path": candidate_path,
        "reviewer": str(reviewer or "").strip(),
        "reason": scrub_experience_text(reason).strip(),
        "ts": now_utc(),
    }
    if sources is not None:
        payload["sources"] = sources
    if evidence_refs is not None:
        payload["evidence_refs"] = normalize_evidence_refs(evidence_refs)
    if card_id:
        payload["card_id"] = card_id
    if replacement:
        payload["replacement"] = replacement
    return payload


def _validate_local_ref(repo_root: Path, reference: str) -> str | None:
    """Return an error for a missing/unsafe repo-relative evidence ref."""
    match = LOCAL_REF_RE.fullmatch(str(reference or "").strip())
    if not match:
        return f"invalid evidence ref: {reference!r}"
    raw_path = match.group("path")
    path = Path(raw_path)
    if path.is_absolute() or ".." in path.parts:
        return f"evidence ref must be repository-relative: {reference!r}"
    resolved = (repo_root / path).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError:
        return f"evidence ref escapes repository: {reference!r}"
    if not resolved.is_file():
        return f"evidence ref does not exist: {reference!r}"
    return None


def validate_evidence_refs(repo_root: Path | str, references: list[str]) -> list[str]:
    """Validate typed corpus refs or repository-relative evidence refs."""
    repo = Path(repo_root).resolve()
    errors: list[str] = []
    for reference in normalize_evidence_refs(references):
        if reference.startswith("corpus-report:"):
            report_id = reference.removeprefix("corpus-report:").strip()
            if not REPORT_ID_RE.fullmatch(report_id):
                errors.append(
                    f"corpus report reference must use a non-zero decimal ID: {reference!r}"
                )
            continue
        error = _validate_local_ref(repo, reference)
        if error:
            errors.append(error)
    return errors


def _normalize_corpus_report_ids(values: list[Any]) -> list[str]:
    """复用正式 source_refs 的 report ID 约束，拒绝模糊或重复来源。"""
    result: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(values):
        if isinstance(raw, bool):
            raise ValueError(f"source_report_ids[{index}] 必须是非零十进制 ID")
        value = str(raw).strip()
        if not REPORT_ID_RE.fullmatch(value):
            raise ValueError(f"source_report_ids[{index}] 必须是非零十进制 ID")
        if value in seen:
            raise ValueError(f"source_report_ids[{index}] 与前序来源重复: {value}")
        seen.add(value)
        result.append(value)
    if not result:
        raise ValueError("distill candidate requires source_report_ids")
    return result


def _find_target_entry(repo_root: Path, target: str, entry_id: str) -> dict[str, Any]:
    path = _target_memory_path(repo_root, target)
    payload = _read_json(path)
    for field in ("useful_patterns", "dead_ends"):
        for item in payload.get(field, []) or []:
            if isinstance(item, dict) and item.get("entry_id") == entry_id:
                result = dict(item)
                result["_field"] = field
                return result
    raise ValueError(f"target entry not found: {target} / {entry_id}")


def _resolve_sources(
    repo_root: Path,
    source_pairs: list[list[str]],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if not source_pairs:
        raise ValueError("at least one --source TARGET ENTRY_ID is required")
    sources: list[dict[str, Any]] = []
    refs: list[str] = []
    errors: list[str] = []
    for raw_target, entry_id in source_pairs:
        target = canonical_target_value(raw_target)
        try:
            entry = _find_target_entry(repo_root, target, entry_id)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        entry_refs = normalize_evidence_refs(entry.get("evidence_refs", []))
        if not entry_refs:
            errors.append(f"source entry has no evidence_refs: {target} / {entry_id}")
        errors.extend(validate_evidence_refs(repo_root, entry_refs))
        sources.append(
            {
                "type": TARGET_SOURCE,
                "target": target,
                "entry_id": entry_id,
                "kind": entry.get("kind", ""),
                "text": scrub_experience_text(str(entry.get("text", ""))),
            }
        )
        refs.extend(entry_refs)
    if len({item["target"] for item in sources}) < 1:
        errors.append("no valid target-memory source")
    return sources, normalize_evidence_refs(refs), errors


def _candidate_id(
    *,
    kind: str,
    title: str,
    summary: str,
    sources: list[dict[str, Any]],
    evidence_refs: list[str],
    card_id: str,
) -> str:
    payload = {
        "kind": kind,
        "title": title,
        "summary": summary,
        "sources": sources,
        "evidence_refs": evidence_refs,
        "card_id": card_id,
    }
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return f"cand-{digest}"


def _render_candidate(
    *,
    candidate_id: str,
    kind: str,
    title: str,
    summary: str,
    sources: list[dict[str, Any]],
    evidence_refs: list[str],
    card_id: str,
) -> str:
    source_lines = [
        f"- {item['target']} / {item['entry_id']} ({item.get('kind') or 'unspecified'})"
        for item in sources
    ] or ["- none"]
    evidence_lines = [f"- `{ref}`" for ref in evidence_refs] or ["- none"]
    return "\n".join(
        [
            f"# {scrub_experience_text(title)}",
            "",
            "> STAGING CANDIDATE — 未经人工复核，禁止直接作为测试结论。",
            "> 复核通过后只能通过 `/kb promote` 进入正式知识卡。",
            "",
            "## 候选元数据",
            "",
            f"- candidate_id: `{candidate_id}`",
            f"- status: `pending`",
            f"- kind: `{kind}`",
            f"- target card: `{card_id or '待人工决定'}`",
            "",
            "## 来源目标条目",
            "",
            *source_lines,
            "",
            "## Evidence refs",
            "",
            *evidence_lines,
            "",
            "## 可复用经验",
            "",
            scrub_experience_text(summary),
            "",
            "## 审核要求",
            "",
            "- 复核是否跨目标可迁移，并移除目标专属信息。",
            "- 补齐触发信号、最小验证、停止条件和常见误判。",
            "- 只有正式卡已注册且通过 `knowledge_audit.py --strict` 后才能 promote。",
            "",
        ]
    )


def _state_map(path: Path = LIFECYCLE_PATH) -> tuple[dict[str, dict[str, Any]], list[str]]:
    states: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    if not path.is_file():
        return states, errors
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return states, [f"cannot read lifecycle log: {exc}"]
    transitions = {
        "reviewed": ("pending", "reviewed"),
        "promoted": ("reviewed", "promoted"),
        "rejected": ("reviewed", "rejected"),
        "superseded": ("reviewed", "superseded"),
    }
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"lifecycle line {line_no} invalid JSON: {exc}")
            continue
        if not isinstance(item, dict):
            errors.append(f"lifecycle line {line_no} is not an object")
            continue
        candidate_id = str(item.get("candidate_id") or "")
        action = str(item.get("event") or "")
        if not candidate_id or action not in EVENTS:
            errors.append(f"lifecycle line {line_no} has invalid candidate_id/event")
            continue
        current = states.get(candidate_id)
        if action == "staged":
            if current is not None:
                errors.append(f"{candidate_id}: duplicate staged event")
                continue
            if item.get("from_status") is not None or item.get("to_status") != "pending":
                errors.append(f"{candidate_id}: staged must transition null -> pending")
                continue
            states[candidate_id] = dict(item)
            states[candidate_id]["status"] = "pending"
            continue
        if current is None:
            errors.append(f"{candidate_id}: {action} has no staged event")
            continue
        if current.get("status") in TERMINAL_STATUSES:
            errors.append(f"{candidate_id}: transition after terminal status")
            continue
        expected_from, expected_to = transitions[action]
        if current.get("status") != expected_from or item.get("from_status") != expected_from:
            errors.append(
                f"{candidate_id}: {action} requires {expected_from}, got {current.get('status')}"
            )
            continue
        if item.get("to_status") != expected_to:
            errors.append(f"{candidate_id}: {action} has invalid to_status")
            continue
        if item.get("candidate_path") and item.get("candidate_path") != current.get("candidate_path"):
            errors.append(f"{candidate_id}: candidate_path changed during lifecycle")
            continue
        merged = dict(current)
        merged.update(item)
        merged["status"] = expected_to
        states[candidate_id] = merged
    return states, errors


def _validate_state_sources(repo_root: Path, state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sources = state.get("sources") or []
    if not isinstance(sources, list) or not sources:
        return [f"{state.get('candidate_id')}: missing sources"]
    refs = normalize_evidence_refs(state.get("evidence_refs", []))
    errors.extend(validate_evidence_refs(repo_root, refs))
    expected_corpus_refs: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            errors.append(f"{state.get('candidate_id')}: invalid source object")
            continue
        source_type = source.get("type")
        if source_type == TARGET_SOURCE:
            target = str(source.get("target") or "")
            entry_id = str(source.get("entry_id") or "")
            try:
                entry = _find_target_entry(repo_root, target, entry_id)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            entry_refs = normalize_evidence_refs(entry.get("evidence_refs", []))
            if not entry_refs:
                errors.append(f"{target} / {entry_id}: source entry has no evidence_refs")
            if not set(entry_refs).issubset(set(refs)):
                errors.append(f"{state.get('candidate_id')}: source evidence not in event refs")
        elif source_type == CORPUS_SOURCE:
            report_id = str(source.get("report_id") or "").strip()
            if not REPORT_ID_RE.fullmatch(report_id):
                errors.append(
                    f"{state.get('candidate_id')}: corpus report_id must be a non-zero decimal ID"
                )
            else:
                expected_corpus_refs.add(f"corpus-report:{report_id}")
        else:
            errors.append(f"{state.get('candidate_id')}: unknown source type {source_type!r}")
    actual_corpus_refs = {
        reference for reference in refs if reference.startswith("corpus-report:")
    }
    if actual_corpus_refs != expected_corpus_refs:
        errors.append(
            f"{state.get('candidate_id')}: corpus sources/evidence_refs mismatch"
        )
    return errors


def stage_candidate(
    *,
    repo_root: Path | str = BASE_DIR,
    kind: str,
    title: str,
    summary: str,
    source_pairs: list[list[str]],
    card_id: str = "",
    lifecycle_path: Path | None = None,
) -> tuple[str, Path]:
    repo = Path(repo_root).resolve()
    normalized_kind = normalize_experience_kind(kind, default="useful-pattern")
    clean_title = str(title or "").strip()
    clean_summary = str(summary or "").strip()
    if not clean_title or not clean_summary:
        raise ValueError("title and summary are required")
    sources, refs, errors = _resolve_sources(repo, source_pairs)
    if errors:
        raise ValueError("; ".join(dict.fromkeys(errors)))
    candidate_id = _candidate_id(
        kind=normalized_kind,
        title=clean_title,
        summary=clean_summary,
        sources=sources,
        evidence_refs=refs,
        card_id=card_id,
    )
    event_path = lifecycle_path or (repo / "knowledge" / "candidates" / "lifecycle.jsonl")
    states, replay_errors = _state_map(event_path)
    if replay_errors:
        raise ValueError("cannot stage while lifecycle log is invalid: " + "; ".join(replay_errors))
    if candidate_id in states:
        raise ValueError(f"candidate already exists: {candidate_id}")
    candidate_dir = event_path.parent
    candidate_dir.mkdir(parents=True, exist_ok=True)
    candidate_path = candidate_dir / f"{candidate_id}.md"
    if candidate_path.exists():
        raise ValueError(f"candidate file already exists: {candidate_path}")
    _write_text_atomic(
        candidate_path,
        _render_candidate(
            candidate_id=candidate_id,
            kind=normalized_kind,
            title=clean_title,
            summary=clean_summary,
            sources=sources,
            evidence_refs=refs,
            card_id=card_id,
        ),
    )
    try:
        _append_event(
            _event(
                candidate_id=candidate_id,
                action="staged",
                from_status=None,
                to_status="pending",
                candidate_path=_relative(candidate_path, repo),
                sources=sources,
                evidence_refs=refs,
            ),
            path=event_path,
        )
    except Exception:
        try:
            candidate_path.unlink()
        except OSError:
            pass
        raise
    return candidate_id, candidate_path


def register_corpus_candidate(
    candidate_path: Path | str,
    *,
    source_report_ids: list[Any],
    repo_root: Path | str = BASE_DIR,
    lifecycle_path: Path | None = None,
) -> str:
    """Register an existing `/distill` draft without changing its content."""
    repo = Path(repo_root).resolve()
    path = Path(candidate_path).resolve()
    if not path.is_file():
        raise ValueError(f"candidate file does not exist: {path}")
    try:
        relative = path.relative_to(repo).as_posix()
    except ValueError as exc:
        raise ValueError("candidate file must be inside repository") from exc
    ids = _normalize_corpus_report_ids(source_report_ids)
    sources = [{"type": CORPUS_SOURCE, "report_id": item} for item in ids]
    refs = [f"corpus-report:{item}" for item in ids]
    digest = hashlib.sha256(
        json.dumps({"path": relative, "refs": refs}, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    candidate_id = f"cand-{digest}"
    event_path = lifecycle_path or (repo / "knowledge" / "candidates" / "lifecycle.jsonl")
    states, replay_errors = _state_map(event_path)
    if replay_errors:
        raise ValueError("cannot register while lifecycle log is invalid")
    if candidate_id in states:
        return candidate_id
    _append_event(
        _event(
            candidate_id=candidate_id,
            action="staged",
            from_status=None,
            to_status="pending",
            candidate_path=relative,
            sources=sources,
            evidence_refs=refs,
        ),
        path=event_path,
    )
    return candidate_id


def _transition(
    candidate_id: str,
    *,
    action: str,
    reviewer: str,
    reason: str,
    repo_root: Path | str,
    lifecycle_path: Path | None = None,
    card_id: str = "",
    replacement: str = "",
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    event_path = lifecycle_path or (repo / "knowledge" / "candidates" / "lifecycle.jsonl")
    states, errors = _state_map(event_path)
    if errors:
        raise ValueError("cannot transition invalid lifecycle: " + "; ".join(errors))
    state = states.get(candidate_id)
    if state is None:
        raise ValueError(f"candidate not found: {candidate_id}")
    current = state.get("status")
    expected = {"reviewed": "pending", "promoted": "reviewed", "rejected": "reviewed", "superseded": "reviewed"}
    if action not in expected or current != expected[action]:
        raise ValueError(f"{candidate_id}: {action} requires {expected.get(action)}, got {current}")
    if not reviewer.strip() or not reason.strip():
        raise ValueError("reviewer and reason are required")
    if action == "superseded" and not replacement.strip():
        raise ValueError("superseded requires replacement candidate/card")
    refs = normalize_evidence_refs(evidence_refs)
    errors = validate_evidence_refs(repo, refs)
    if errors:
        raise ValueError("; ".join(errors))
    if action == "promoted":
        if not card_id.strip():
            raise ValueError("promoted requires card_id")
        try:
            registry = load_registry(repo)
            card_path = registry.card_paths().get(card_id)
        except KnowledgeRegistryError as exc:
            raise ValueError(str(exc)) from exc
        if not card_path or not (repo / card_path).is_file():
            raise ValueError(f"registered card does not exist: {card_id}")
        report = audit_repository(repo)
        if report.errors or report.warnings:
            raise ValueError("knowledge audit must pass before promotion")
        governance_path = repo / "knowledge" / "governance" / "events.jsonl"
        if governance_path.is_file():
            try:
                from tools.knowledge_lifecycle import audit_lifecycle
            except ImportError:  # pragma: no cover - direct tools/ execution
                from knowledge_lifecycle import audit_lifecycle  # type: ignore
            lifecycle = audit_lifecycle(repo, events_path=governance_path)
            formal_state = lifecycle.get("states", {}).get(card_id, {})
            if not lifecycle.get("ok") or formal_state.get("status") != "active":
                raise ValueError(
                    f"formal card governance is not active for {card_id}: "
                    + "; ".join(lifecycle.get("errors", []))
                )
    payload = _event(
        candidate_id=candidate_id,
        action=action,
        from_status=current,
        to_status=action,
        candidate_path=str(state.get("candidate_path") or ""),
        reviewer=reviewer,
        reason=reason,
        card_id=card_id,
        replacement=replacement,
        evidence_refs=None,
    )
    if refs:
        payload["review_evidence_refs"] = refs
    _append_event(payload, path=event_path)
    return payload


def audit_candidates(
    *,
    repo_root: Path | str = BASE_DIR,
    lifecycle_path: Path | None = None,
    strict: bool = False,
    source_mode: str = "if-present",
    corpus_dir: Path | str | None = None,
) -> dict[str, Any]:
    if source_mode not in {"off", "if-present", "required"}:
        raise ValueError(f"unsupported source_mode: {source_mode}")
    repo = Path(repo_root).resolve()
    event_path = lifecycle_path or (repo / "knowledge" / "candidates" / "lifecycle.jsonl")
    states, errors = _state_map(event_path)
    registered_paths = {
        str(state.get("candidate_path") or "")
        for state in states.values()
    }
    candidate_dir = event_path.parent
    if candidate_dir.is_dir():
        for candidate_file in sorted(candidate_dir.glob("*.md")):
            relative = _relative(candidate_file, repo)
            if relative not in registered_paths:
                errors.append(f"orphan candidate file is not staged: {relative}")
    corpus_path = Path(corpus_dir) if corpus_dir is not None else repo / "distill" / "corpus"
    if not corpus_path.is_absolute():
        corpus_path = repo / corpus_path
    source_state: dict[str, Any] = {
        "mode": source_mode,
        "status": "off" if source_mode == "off" else "unavailable",
        "reason": "source resolution disabled" if source_mode == "off" else "",
    }
    skipped: list[dict[str, str]] = []
    if source_mode != "off":
        try:
            from tools.case_corpus import corpus_status as get_corpus_status
        except ImportError:  # pragma: no cover - direct tools/ execution
            from case_corpus import corpus_status as get_corpus_status  # type: ignore
        source_state = get_corpus_status(corpus_dir=corpus_path)
        source_state["mode"] = source_mode
        if source_state.get("status") == "unavailable":
            skipped.append(
                {
                    "check": "source-resolution",
                    "reason": source_state.get("reason", "corpus unavailable"),
                }
            )
            if source_mode == "required":
                errors.append("required source resolution needs an available case corpus")
        elif source_state.get("status") in {"stale", "invalid"}:
            errors.append(
                f"source corpus is {source_state.get('status')}: {source_state.get('reason', '')}"
            )
    for candidate_id, state in states.items():
        candidate_path = repo / str(state.get("candidate_path") or "")
        if not candidate_path.is_file():
            errors.append(f"{candidate_id}: candidate file missing")
        errors.extend(_validate_state_sources(repo, state))
        if source_mode != "off":
            for source in state.get("sources") or []:
                if not isinstance(source, dict) or source.get("type") != CORPUS_SOURCE:
                    continue
                report_id = str(source.get("report_id") or "").strip()
                if source_state.get("status") != "available":
                    continue
                try:
                    from tools.case_corpus import CaseCorpusError, get_case
                except ImportError:  # pragma: no cover - direct tools/ execution
                    from case_corpus import CaseCorpusError, get_case  # type: ignore
                try:
                    resolved = get_case(report_id, corpus_dir=corpus_path)
                except CaseCorpusError as exc:
                    errors.append(f"{candidate_id}: invalid corpus report {report_id!r}: {exc}")
                    continue
                if resolved.get("status") == "not-found":
                    errors.append(f"{candidate_id}: dangling corpus report {report_id}")
                elif resolved.get("status") != "ok":
                    errors.append(
                        f"{candidate_id}: corpus report {report_id} cannot resolve: {resolved.get('reason', '')}"
                    )
        if state.get("status") == "promoted":
            if not state.get("card_id"):
                errors.append(f"{candidate_id}: promoted candidate missing card_id")
            else:
                try:
                    registry = load_registry(repo)
                    card_path = registry.card_paths().get(str(state["card_id"]))
                    if not card_path or not (repo / card_path).is_file():
                        errors.append(f"{candidate_id}: promoted card is not registered or missing")
                except KnowledgeRegistryError as exc:
                    errors.append(str(exc))
            governance_path = repo / "knowledge" / "governance" / "events.jsonl"
            if governance_path.is_file():
                try:
                    from tools.knowledge_lifecycle import audit_lifecycle
                except ImportError:  # pragma: no cover - direct tools/ execution
                    from knowledge_lifecycle import audit_lifecycle  # type: ignore
                lifecycle = audit_lifecycle(repo, events_path=governance_path)
                formal_state = lifecycle.get("states", {}).get(str(state.get("card_id") or ""), {})
                if not lifecycle.get("ok") or formal_state.get("status") != "active":
                    errors.append(
                        f"{candidate_id}: formal card governance is not active"
                    )
    if any(state.get("status") == "promoted" for state in states.values()):
        if source_mode == "if-present" and corpus_dir is None:
            # 保持旧的可注入 audit_repository(repo_root) 测试/调用契约；默认模式本身相同。
            report = audit_repository(repo)
        else:
            report = audit_repository(repo, source_mode=source_mode, corpus_dir=corpus_path)
        if report.errors or (strict and report.warnings):
            errors.append("knowledge audit is not clean for promoted candidates")
    result = {
        "lifecycle_path": _relative(event_path, repo),
        "candidate_count": len(states),
        "statuses": {status: sum(item.get("status") == status for item in states.values()) for status in STATUSES},
        "source_resolution": source_state,
        "skipped": skipped,
        "errors": list(dict.fromkeys(errors)),
    }
    result["ok"] = not result["errors"]
    return result


def _cmd_stage(args: argparse.Namespace) -> int:
    try:
        candidate_id, path = stage_candidate(
            kind=args.kind,
            title=args.title,
            summary=args.summary,
            source_pairs=args.source,
        )
    except ValueError as exc:
        print(f"[stage] {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"candidate_id": candidate_id, "status": "pending", "path": _relative(path, BASE_DIR)}, ensure_ascii=False, indent=2))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    states, errors = _state_map()
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    selected = states.values()
    if args.candidate:
        selected = [states[args.candidate]] if args.candidate in states else []
    for state in selected:
        print(f"{state['candidate_id']}\t{state.get('status')}\t{state.get('candidate_path')}")
    return 0 if not args.candidate or selected else 1


def _cmd_transition(args: argparse.Namespace, action: str) -> int:
    try:
        payload = _transition(
            args.candidate_id,
            action=action,
            reviewer=args.reviewer,
            reason=args.reason,
            card_id=getattr(args, "card_id", ""),
            replacement=getattr(args, "replacement", ""),
            evidence_refs=getattr(args, "evidence_ref", []),
            repo_root=BASE_DIR,
        )
    except ValueError as exc:
        print(f"[{action}] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    result = audit_candidates(
        strict=args.strict,
        source_mode=args.source_mode,
        corpus_dir=args.corpus_dir,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stage and audit reusable knowledge candidates.")
    sub = parser.add_subparsers(dest="command", required=True)

    stage = sub.add_parser("stage", help="stage a candidate from target-memory entries")
    stage.add_argument("--kind", required=True, choices=EXPERIENCE_KINDS)
    stage.add_argument("--title", required=True)
    stage.add_argument("--summary", required=True)
    stage.add_argument("--source", nargs=2, action="append", required=True, metavar=("TARGET", "ENTRY_ID"))
    stage.set_defaults(func=_cmd_stage)

    list_parser = sub.add_parser("list", help="list candidate states")
    list_parser.add_argument("candidate", nargs="?")
    list_parser.set_defaults(func=_cmd_list)

    show = sub.add_parser("show", help="show one candidate state")
    show.add_argument("candidate")
    show.set_defaults(func=lambda args: _cmd_list(argparse.Namespace(candidate=args.candidate)))

    for name, action in (("review", "reviewed"), ("promote", "promoted"), ("reject", "rejected"), ("supersede", "superseded")):
        item = sub.add_parser(name)
        item.add_argument("candidate_id")
        item.add_argument("--reviewer", required=True)
        item.add_argument("--reason", required=True)
        item.add_argument("--evidence-ref", action="append", default=[])
        if action == "promoted":
            item.add_argument("--card-id", required=True)
        if action == "superseded":
            item.add_argument("--replacement", required=True)
        item.set_defaults(func=lambda args, a=action: _cmd_transition(args, a))

    audit = sub.add_parser("audit", help="audit lifecycle and promoted cards")
    audit.add_argument("--strict", action="store_true")
    audit.add_argument(
        "--source-mode",
        choices=("off", "if-present", "required"),
        default="if-present",
    )
    audit.add_argument("--corpus-dir", type=Path, default=None)
    audit.set_defaults(func=_cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
