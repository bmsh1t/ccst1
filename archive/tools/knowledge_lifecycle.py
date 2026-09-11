#!/usr/bin/env python3
"""正式知识卡的 append-only 治理日志、状态 replay 与质量审计。

候选生命周期由 ``knowledge_candidates.py`` 独立拥有；本模块只记录正式卡的
adopt/review/merge/supersede/retire/restore。工具验证事件结构和证据完整性，
不替 AI 决定卡片的真实增量价值。
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import uuid
from typing import Any, Iterable

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_EVENTS_PATH = BASE_DIR / "knowledge" / "governance" / "events.jsonl"
SCHEMA_VERSION = 1
EVENTS = {"adopted", "reviewed", "merged", "superseded", "retired", "restored"}
ACTIVE_STATUS = "active"
TERMINAL_STATUS = {"retired", "superseded"}
MATURITY = {"draft", "tested", "proven"}
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REF_RE = re.compile(r"^(?P<path>[^#]+?)(?:#L(?P<line>[1-9][0-9]*))?$")

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.knowledge_registry import (
        KnowledgeRegistryError,
        load_registry,
        parse_knowledge_document,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_registry import (  # type: ignore
        KnowledgeRegistryError,
        load_registry,
        parse_knowledge_document,
    )


class KnowledgeLifecycleError(RuntimeError):
    """治理日志或状态机不满足正式卡契约。"""


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _relative(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return str(path)


def _events_path(repo_root: Path | str, events_path: Path | str | None) -> Path:
    return Path(events_path) if events_path is not None else Path(repo_root) / "knowledge" / "governance" / "events.jsonl"


def _valid_repo_ref(repo: Path, value: str) -> bool:
    match = REF_RE.fullmatch(value.strip())
    if not match:
        return False
    target = Path(match.group("path"))
    if target.is_absolute() or ".." in target.parts or not target.as_posix() == match.group("path"):
        return False
    return (repo / target).is_file()


def _valid_card_path(repo: Path, value: str) -> bool:
    """允许终态卡把正文移入 archive 后仍能 replay 历史事件。"""
    if _valid_repo_ref(repo, value):
        return True
    target = Path(value)
    if target.is_absolute() or not target.name.endswith(".md"):
        return False
    card_id = target.stem
    return any(
        (repo / relative).is_file()
        for relative in (
            f"knowledge/archive/cards/{card_id}.md",
            f"knowledge/archive/{card_id}.md",
            f"knowledge/archive/distilled/{card_id}.md",
        )
    )


def _normalize_refs(repo: Path, values: Iterable[str] | None) -> tuple[list[str], list[str]]:
    refs: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    for raw in values or ():
        value = str(raw or "").strip()
        if not value or value in seen:
            if not value:
                errors.append("evidence_refs cannot contain empty values")
            continue
        seen.add(value)
        if not _valid_repo_ref(repo, value):
            errors.append(f"evidence ref is not a repo-relative existing file: {value}")
        refs.append(value)
    return refs, errors


def _event_payload(
    *,
    card_id: str,
    event: str,
    from_status: str | None,
    to_status: str,
    from_maturity: str | None,
    to_maturity: str,
    card_path: str,
    reviewer: str,
    reason: str,
    model_profile: str = "",
    evidence_refs: Iterable[str] | None = None,
    replacement_card_id: str = "",
    reverts_event_id: str = "",
    evaluation_kind: str = "",
    success_criteria: str = "",
    event_id: str | None = None,
    ts: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id or f"kg-{uuid.uuid4().hex}",
        "card_id": card_id,
        "event": event,
        "from_status": from_status,
        "to_status": to_status,
        "from_maturity": from_maturity,
        "to_maturity": to_maturity,
        "card_path": card_path,
        "reviewer": reviewer,
        "reason": reason,
        "model_profile": model_profile,
        "evidence_refs": list(evidence_refs or ()),
        "replacement_card_id": replacement_card_id,
        "reverts_event_id": reverts_event_id,
        "evaluation_kind": evaluation_kind,
        "success_criteria": success_criteria,
        "ts": ts or now_utc(),
    }


def _read_events(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], []
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [], [f"cannot read governance log: {exc}"]
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}:L{line_number}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(value, dict):
            errors.append(f"{path}:L{line_number}: event must be an object")
            continue
        event_id = str(value.get("event_id") or "")
        if event_id and event_id in seen:
            errors.append(f"duplicate event_id: {event_id}")
        if event_id:
            seen.add(event_id)
        events.append(value)
    return events, errors


def _validate_common_event(repo: Path, event: dict[str, Any], index: int) -> list[str]:
    errors: list[str] = []
    prefix = f"event[{index}]"
    if event.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{prefix}: schema_version must be {SCHEMA_VERSION}")
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip():
        errors.append(f"{prefix}: event_id is required")
    card_id = event.get("card_id")
    if not isinstance(card_id, str) or not ID_RE.fullmatch(card_id):
        errors.append(f"{prefix}: card_id must use lowercase kebab-case")
    action = event.get("event")
    if action not in EVENTS:
        errors.append(f"{prefix}: unsupported event {action!r}")
    if event.get("to_status") not in {ACTIVE_STATUS, *TERMINAL_STATUS}:
        errors.append(f"{prefix}: invalid to_status")
    if event.get("to_maturity") not in MATURITY:
        errors.append(f"{prefix}: invalid to_maturity")
    if not isinstance(event.get("ts"), str) or not event.get("ts", "").strip():
        errors.append(f"{prefix}: ts is required")
    if not str(event.get("reviewer") or "").strip():
        errors.append(f"{prefix}: reviewer is required")
    if not str(event.get("reason") or "").strip():
        errors.append(f"{prefix}: reason is required")
    card_path = event.get("card_path")
    if card_path:
        if not isinstance(card_path, str) or not _valid_card_path(repo, card_path):
            errors.append(f"{prefix}: card_path must point to an existing repo-relative file")
    elif action != "restored":
        errors.append(f"{prefix}: card_path is required")
    refs = event.get("evidence_refs", [])
    if not isinstance(refs, list) or any(not isinstance(item, str) for item in refs):
        errors.append(f"{prefix}: evidence_refs must be a string list")
    else:
        _, ref_errors = _normalize_refs(repo, refs)
        errors.extend(f"{prefix}: {item}" for item in ref_errors)
    if action in {"merged", "superseded"}:
        replacement = event.get("replacement_card_id")
        if not isinstance(replacement, str) or not ID_RE.fullmatch(replacement):
            errors.append(f"{prefix}: replacement_card_id is required")
    if action == "restored" and not str(event.get("reverts_event_id") or "").strip():
        errors.append(f"{prefix}: restored requires reverts_event_id")
    if action == "reviewed" and event.get("to_maturity") in {"tested", "proven"}:
        if not event.get("evidence_refs"):
            errors.append(f"{prefix}: tested/proven review requires evidence_refs")
        if not str(event.get("model_profile") or "").strip():
            errors.append(f"{prefix}: tested/proven review requires model_profile")
    if action == "reviewed" and event.get("to_maturity") == "proven":
        if not str(event.get("evaluation_kind") or "").strip():
            errors.append(f"{prefix}: proven review requires evaluation_kind")
        if not str(event.get("success_criteria") or "").strip():
            errors.append(f"{prefix}: proven review requires success_criteria")
    if action == "adopted" and event.get("to_maturity") != "draft":
        errors.append(f"{prefix}: adopted events cannot claim tested/proven maturity")
    if action == "adopted" and (
        event.get("from_status") is not None
        or event.get("to_status") != ACTIVE_STATUS
        or event.get("from_maturity") is not None
    ):
        errors.append(f"{prefix}: adopted must transition null -> active with no prior maturity")
    if action == "reviewed" and (
        event.get("from_status") != ACTIVE_STATUS
        or event.get("to_status") != ACTIVE_STATUS
    ):
        errors.append(f"{prefix}: reviewed must transition active -> active")
    return errors


def _frontmatter(repo: Path, card_path: str) -> tuple[dict[str, Any] | None, str | None]:
    path = repo / card_path
    try:
        parsed = parse_knowledge_document(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        return None, str(exc)
    if parsed.frontmatter_error:
        return None, parsed.frontmatter_error
    if parsed.metadata is None:
        return None, "card frontmatter missing"
    return parsed.metadata, None


def replay_events(
    repo_root: Path | str = BASE_DIR,
    *,
    events_path: Path | str | None = None,
    events: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """重放日志，返回 card_id -> latest state 和可诊断错误。"""
    repo = Path(repo_root).resolve()
    path = _events_path(repo, events_path)
    loaded, read_errors = _read_events(path) if events is None else (events, [])
    states: dict[str, dict[str, Any]] = {}
    all_errors = list(read_errors)
    event_ids: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(loaded):
        all_errors.extend(_validate_common_event(repo, item, index))
        event_id = str(item.get("event_id") or "")
        if event_id in event_ids:
            continue
        event_ids[event_id] = item
        card_id = str(item.get("card_id") or "")
        action = item.get("event")
        current = states.get(card_id)
        if action == "adopted":
            if current is not None:
                all_errors.append(f"{card_id}: duplicate adoption")
                continue
            card_path = str(item.get("card_path") or "")
            if not card_path:
                all_errors.append(f"{card_id}: adopted card_path is required")
                continue
            metadata, metadata_error = _frontmatter(repo, card_path)
            if metadata_error:
                all_errors.append(f"{card_id}: {metadata_error}")
            elif metadata and metadata.get("id") != card_id:
                all_errors.append(f"{card_id}: adopted card frontmatter id mismatch")
            states[card_id] = {
                "card_id": card_id,
                "status": ACTIVE_STATUS,
                "maturity": "draft",
                "card_path": card_path,
                "last_event_id": event_id,
                "last_event": action,
                "replacement_card_id": "",
            }
            continue
        if current is None:
            all_errors.append(f"{card_id}: {action} has no adopted state")
            continue
        expected_from = current["status"]
        if item.get("from_status") != expected_from:
            all_errors.append(
                f"{card_id}: {action} from_status={item.get('from_status')!r} does not match {expected_from!r}"
            )
            continue
        if action == "reviewed":
            if expected_from != ACTIVE_STATUS or item.get("to_status") != ACTIVE_STATUS:
                all_errors.append(f"{card_id}: reviewed requires active -> active")
                continue
            if item.get("from_maturity") != current["maturity"]:
                all_errors.append(f"{card_id}: reviewed from_maturity mismatch")
                continue
            current.update(
                {
                    "maturity": item.get("to_maturity"),
                    "last_event_id": event_id,
                    "last_event": action,
                    "review_event": item,
                }
            )
        elif action in {"merged", "superseded"}:
            if expected_from != ACTIVE_STATUS or item.get("to_status") != "superseded":
                all_errors.append(f"{card_id}: {action} requires active -> superseded")
                continue
            current.update(
                {
                    "status": "superseded",
                    "last_event_id": event_id,
                    "last_event": action,
                    "replacement_card_id": item.get("replacement_card_id", ""),
                }
            )
        elif action == "retired":
            if expected_from != ACTIVE_STATUS or item.get("to_status") != "retired":
                all_errors.append(f"{card_id}: retired requires active -> retired")
                continue
            current.update({"status": "retired", "last_event_id": event_id, "last_event": action})
        elif action == "restored":
            if expected_from not in TERMINAL_STATUS or item.get("to_status") != ACTIVE_STATUS:
                all_errors.append(f"{card_id}: restored requires retired/superseded -> active")
                continue
            reverted = event_ids.get(str(item.get("reverts_event_id") or ""))
            if not reverted or reverted.get("card_id") != card_id:
                all_errors.append(f"{card_id}: restored reverts_event_id is unknown or points to another card")
                continue
            current.update({"status": ACTIVE_STATUS, "last_event_id": event_id, "last_event": action})
        else:
            all_errors.append(f"{card_id}: unsupported transition {action!r}")
    return states, list(dict.fromkeys(all_errors))


def _append_checked(
    repo_root: Path,
    event: dict[str, Any],
    *,
    events_path: Path,
) -> dict[str, Any]:
    events, read_errors = _read_events(events_path)
    if read_errors:
        raise KnowledgeLifecycleError("cannot append to invalid governance log: " + "; ".join(read_errors))
    _, replay_errors = replay_events(repo_root, events=events)
    if replay_errors:
        raise KnowledgeLifecycleError("cannot append to invalid governance state: " + "; ".join(replay_errors))
    _, candidate_errors = replay_events(repo_root, events=events + [event])
    if candidate_errors:
        raise KnowledgeLifecycleError("invalid governance transition: " + "; ".join(candidate_errors))
    events_path.parent.mkdir(parents=True, exist_ok=True)
    with events_path.open("a", encoding="utf-8") as handle:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return event


def bootstrap_cards(
    repo_root: Path | str = BASE_DIR,
    *,
    events_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    repo = Path(repo_root).resolve()
    path = _events_path(repo, events_path)
    registry = load_registry(repo)
    existing, read_errors = _read_events(path)
    if read_errors:
        raise KnowledgeLifecycleError("cannot bootstrap invalid log: " + "; ".join(read_errors))
    states, replay_errors = replay_events(repo, events=existing)
    if replay_errors:
        raise KnowledgeLifecycleError("cannot bootstrap invalid state: " + "; ".join(replay_errors))
    created: list[dict[str, Any]] = []
    for entry in sorted(registry.by_kind("card"), key=lambda item: str(item.get("id"))):
        card_id = str(entry.get("id") or "")
        if card_id in states:
            continue
        card_path = str(entry.get("file") or "")
        metadata, metadata_error = _frontmatter(repo, card_path)
        if metadata_error:
            raise KnowledgeLifecycleError(f"{card_id}: {metadata_error}")
        observed = str((metadata or {}).get("maturity") or "draft")
        if observed not in MATURITY:
            raise KnowledgeLifecycleError(f"{card_id}: invalid frontmatter maturity {observed!r}")
        reason = "bootstrap existing active card"
        if observed != "draft":
            reason = f"bootstrap conservative downgrade from {observed}; no formal review evidence"
        event = _event_payload(
            card_id=card_id,
            event="adopted",
            from_status=None,
            to_status=ACTIVE_STATUS,
            from_maturity=None,
            to_maturity="draft",
            card_path=card_path,
            reviewer="bootstrap",
            reason=reason,
            event_id=f"kg-adopt-{card_id}",
        )
        created.append(_append_checked(repo, event, events_path=path))
        states[card_id] = {"card_id": card_id}
    return created


def _current_state(repo: Path, card_id: str, path: Path) -> dict[str, Any]:
    states, errors = replay_events(repo, events_path=path)
    if errors:
        raise KnowledgeLifecycleError("invalid governance state: " + "; ".join(errors))
    state = states.get(card_id)
    if state is None:
        raise KnowledgeLifecycleError(f"card has no governance state: {card_id}")
    return state


def review_card(
    card_id: str,
    *,
    repo_root: Path | str = BASE_DIR,
    maturity: str | None = None,
    reviewer: str,
    reason: str,
    model_profile: str = "",
    evidence_refs: Iterable[str] | None = None,
    evaluation_kind: str = "",
    success_criteria: str = "",
    events_path: Path | str | None = None,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    path = _events_path(repo, events_path)
    state = _current_state(repo, card_id, path)
    target = maturity or str(state["maturity"])
    if target not in MATURITY:
        raise KnowledgeLifecycleError(f"invalid maturity: {target}")
    refs, ref_errors = _normalize_refs(repo, evidence_refs)
    if ref_errors:
        raise KnowledgeLifecycleError("; ".join(ref_errors))
    event = _event_payload(
        card_id=card_id,
        event="reviewed",
        from_status=ACTIVE_STATUS,
        to_status=ACTIVE_STATUS,
        from_maturity=str(state["maturity"]),
        to_maturity=target,
        card_path=str(state["card_path"]),
        reviewer=reviewer,
        reason=reason,
        model_profile=model_profile,
        evidence_refs=refs,
        evaluation_kind=evaluation_kind,
        success_criteria=success_criteria,
    )
    return _append_checked(repo, event, events_path=path)


def retire_card(
    card_id: str,
    *,
    repo_root: Path | str = BASE_DIR,
    reviewer: str,
    reason: str,
    events_path: Path | str | None = None,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    path = _events_path(repo, events_path)
    state = _current_state(repo, card_id, path)
    event = _event_payload(
        card_id=card_id,
        event="retired",
        from_status=ACTIVE_STATUS,
        to_status="retired",
        from_maturity=str(state["maturity"]),
        to_maturity=str(state["maturity"]),
        card_path=str(state["card_path"]),
        reviewer=reviewer,
        reason=reason,
    )
    return _append_checked(repo, event, events_path=path)


def supersede_card(
    card_id: str,
    replacement_card_id: str,
    *,
    repo_root: Path | str = BASE_DIR,
    reviewer: str,
    reason: str,
    events_path: Path | str | None = None,
    merged: bool = False,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    path = _events_path(repo, events_path)
    state = _current_state(repo, card_id, path)
    registry = load_registry(repo)
    replacement_path = registry.card_paths().get(replacement_card_id)
    if not replacement_path or not (repo / replacement_path).is_file():
        raise KnowledgeLifecycleError(f"replacement card is not active/registered: {replacement_card_id}")
    replacement_state = _current_state(repo, replacement_card_id, path)
    if replacement_state.get("status") != ACTIVE_STATUS:
        raise KnowledgeLifecycleError(
            f"replacement card governance is not active: {replacement_card_id}"
        )
    event = _event_payload(
        card_id=card_id,
        event="merged" if merged else "superseded",
        from_status=ACTIVE_STATUS,
        to_status="superseded",
        from_maturity=str(state["maturity"]),
        to_maturity=str(state["maturity"]),
        card_path=str(state["card_path"]),
        reviewer=reviewer,
        reason=reason,
        replacement_card_id=replacement_card_id,
    )
    return _append_checked(repo, event, events_path=path)


def restore_card(
    card_id: str,
    *,
    reverts_event_id: str,
    repo_root: Path | str = BASE_DIR,
    reviewer: str,
    reason: str,
    events_path: Path | str | None = None,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    path = _events_path(repo, events_path)
    state = _current_state(repo, card_id, path)
    event = _event_payload(
        card_id=card_id,
        event="restored",
        from_status=str(state["status"]),
        to_status=ACTIVE_STATUS,
        from_maturity=str(state["maturity"]),
        to_maturity=str(state["maturity"]),
        card_path=str(state["card_path"]),
        reviewer=reviewer,
        reason=reason,
        reverts_event_id=reverts_event_id,
    )
    return _append_checked(repo, event, events_path=path)


def _archive_exists(repo: Path, card_id: str) -> bool:
    return any(
        (repo / relative).is_file()
        for relative in (
            f"knowledge/archive/cards/{card_id}.md",
            f"knowledge/archive/{card_id}.md",
            f"knowledge/archive/distilled/{card_id}.md",
        )
    )


def audit_lifecycle(
    repo_root: Path | str = BASE_DIR,
    *,
    events_path: Path | str | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    del strict  # advisory 当前不改变 hard gate；保留参数供 CLI/未来策略使用。
    repo = Path(repo_root).resolve()
    path = _events_path(repo, events_path)
    states, replay_errors = replay_events(repo, events_path=path)
    errors = list(replay_errors)
    advisories: list[dict[str, str]] = []
    try:
        registry = load_registry(repo)
        active_cards = {
            str(item.get("id")): item
            for item in registry.by_kind("card")
            if isinstance(item.get("id"), str)
        }
    except KnowledgeRegistryError as exc:
        active_cards = {}
        errors.append(str(exc))

    for card_id, entry in active_cards.items():
        state = states.get(card_id)
        if state is None:
            errors.append(f"active card missing adopted governance event: {card_id}")
            continue
        if state.get("status") != ACTIVE_STATUS:
            errors.append(f"active registry card has terminal governance status: {card_id}")
        expected_path = str(entry.get("file") or "")
        if state.get("card_path") != expected_path:
            errors.append(f"{card_id}: governance card_path differs from registry")
        metadata, metadata_error = _frontmatter(repo, expected_path)
        if metadata_error:
            errors.append(f"{card_id}: {metadata_error}")
        elif metadata and metadata.get("maturity") != state.get("maturity"):
            errors.append(
                f"{card_id}: frontmatter maturity {metadata.get('maturity')!r} != governance {state.get('maturity')!r}"
            )
        if state.get("maturity") in {"tested", "proven"} and state.get("last_event") != "reviewed":
            errors.append(f"{card_id}: tested/proven card lacks latest reviewed evidence")

    for card_id, state in states.items():
        if state.get("status") == ACTIVE_STATUS and card_id not in active_cards:
            errors.append(f"governance active card is not registered: {card_id}")
        if state.get("status") in TERMINAL_STATUS:
            if card_id in active_cards:
                errors.append(f"terminal card remains in active registry: {card_id}")
            if not _archive_exists(repo, card_id):
                errors.append(f"{card_id}: terminal card archive is missing")
            replacement = str(state.get("replacement_card_id") or "")
            if state.get("status") == "superseded" and replacement not in active_cards:
                errors.append(f"{card_id}: replacement card is not active: {replacement}")

    result = {
        "events_path": _relative(path, repo),
        "event_count": sum(1 for _ in _read_events(path)[0]) if path.is_file() else 0,
        "card_count": len(states),
        "active_count": sum(state.get("status") == ACTIVE_STATUS for state in states.values()),
        "errors": list(dict.fromkeys(errors)),
        "advisories": advisories,
        "states": states,
    }
    result["ok"] = not result["errors"]
    return result


def _print(value: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        if isinstance(value, dict) and "errors" in value:
            print(f"Knowledge lifecycle: events={value.get('event_count', 0)} cards={value.get('card_count', 0)} errors={len(value['errors'])}")
            for error in value["errors"]:
                print(f"[ERROR] {error}")
        else:
            print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=BASE_DIR)
    parser.add_argument("--events-path", type=Path, default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("bootstrap", "audit"):
        item = sub.add_parser(name)
        item.add_argument("--json", action="store_true")
        if name == "audit":
            item.add_argument("--strict", action="store_true")
    show = sub.add_parser("show")
    show.add_argument("card_id")
    show.add_argument("--json", action="store_true")
    review = sub.add_parser("review")
    review.add_argument("card_id")
    review.add_argument("--maturity", choices=sorted(MATURITY))
    review.add_argument("--reviewer", required=True)
    review.add_argument("--reason", required=True)
    review.add_argument("--model-profile", default="")
    review.add_argument("--evidence-ref", action="append", default=[])
    review.add_argument("--evaluation-kind", default="")
    review.add_argument("--success-criteria", default="")
    review.add_argument("--json", action="store_true")
    for name, action in (("retire", "retired"), ("restore", "restored"), ("supersede", "superseded"), ("merge", "merged")):
        item = sub.add_parser(name)
        item.add_argument("card_id")
        item.add_argument("--reviewer", required=True)
        item.add_argument("--reason", required=True)
        if action in {"superseded", "merged"}:
            item.add_argument("--replacement", required=True)
        if action == "restored":
            item.add_argument("--reverts-event-id", required=True)
        item.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo_root).resolve()
    path = _events_path(repo, args.events_path)
    try:
        if args.command == "bootstrap":
            value = {"created": bootstrap_cards(repo, events_path=path), "path": _relative(path, repo)}
            _print(value, args.json)
            return 0
        if args.command == "audit":
            value = audit_lifecycle(repo, events_path=path, strict=args.strict)
            _print(value, args.json)
            return 0 if value["ok"] else 1
        if args.command == "show":
            states, errors = replay_events(repo, events_path=path)
            if errors:
                raise KnowledgeLifecycleError("; ".join(errors))
            value = states.get(args.card_id, {"status": "not-found", "card_id": args.card_id})
            _print(value, args.json)
            return 0 if value.get("status") != "not-found" else 1
        if args.command == "review":
            value = review_card(
                args.card_id,
                repo_root=repo,
                maturity=args.maturity,
                reviewer=args.reviewer,
                reason=args.reason,
                model_profile=args.model_profile,
                evidence_refs=args.evidence_ref,
                evaluation_kind=args.evaluation_kind,
                success_criteria=args.success_criteria,
                events_path=path,
            )
        elif args.command == "retire":
            value = retire_card(args.card_id, repo_root=repo, reviewer=args.reviewer, reason=args.reason, events_path=path)
        elif args.command in {"supersede", "merge"}:
            value = supersede_card(
                args.card_id,
                args.replacement,
                repo_root=repo,
                reviewer=args.reviewer,
                reason=args.reason,
                events_path=path,
                merged=args.command == "merge",
            )
        elif args.command == "restore":
            value = restore_card(
                args.card_id,
                repo_root=repo,
                reverts_event_id=args.reverts_event_id,
                reviewer=args.reviewer,
                reason=args.reason,
                events_path=path,
            )
        else:
            return 2
        _print(value, args.json)
        return 0
    except (KnowledgeLifecycleError, KnowledgeRegistryError, OSError, ValueError) as exc:
        print(f"knowledge lifecycle failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
