#!/usr/bin/env python3
"""One-shot migration of legacy target state into the current owner schemas.

The command is intentionally boring: it discovers the handful of historical
shapes still accepted by the runtime, asks each existing owner to normalize its
data, and emits a reviewable report.  Reads are the default; ``--apply`` is the
only mode that writes or renames anything.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from tools.action_queue import (
        ACTIVE_STATUSES,
        ACTIVATION_REQUIRED_FIELDS,
        DEPTH_CONTRACT_VERSION,
        _ensure_active_action_ids,
        load_queue,
        queue_mutation_lock,
        save_queue,
    )
    from tools.runtime_state import (
        DEPRECATED_FIELDS,
        LEGACY_FIELD_RENAMES,
        load_runtime_state,
        state_path,
        update_runtime_state,
    )
    from tools.target_memory import (
        TARGET_MEMORY_LIST_FIELDS,
        TARGET_MEMORY_SKILL_FIELDS,
        TARGET_MEMORY_STRING_FIELDS,
        normalize_target_memory,
        now_utc as memory_now_utc,
        read_json as read_memory_json,
        target_memory_mutation_lock,
        write_json as write_memory_json,
    )
    from tools.target_paths import (
        canonical_target_value,
        migrate_legacy_list_storage,
        target_storage_key,
    )
    from tools.finding_index import load_finding_index
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import (  # type: ignore
        ACTIVE_STATUSES,
        ACTIVATION_REQUIRED_FIELDS,
        DEPTH_CONTRACT_VERSION,
        _ensure_active_action_ids,
        load_queue,
        queue_mutation_lock,
        save_queue,
    )
    from finding_index import load_finding_index  # type: ignore
    from runtime_state import (  # type: ignore
        DEPRECATED_FIELDS,
        LEGACY_FIELD_RENAMES,
        load_runtime_state,
        state_path,
        update_runtime_state,
    )
    from target_memory import (  # type: ignore
        TARGET_MEMORY_LIST_FIELDS,
        TARGET_MEMORY_SKILL_FIELDS,
        TARGET_MEMORY_STRING_FIELDS,
        normalize_target_memory,
        now_utc as memory_now_utc,
        read_json as read_memory_json,
        target_memory_mutation_lock,
        write_json as write_memory_json,
    )
    from target_paths import (  # type: ignore
        canonical_target_value,
        migrate_legacy_list_storage,
        target_storage_key,
    )


BASE_DIR = Path(__file__).resolve().parents[1]
REPORT_SCHEMA_VERSION = 1
SOURCE_REF_KINDS = {"endpoints", "js-intel", "waf-plan"}


def _relative_path(repo: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except (OSError, ValueError):
        return str(path)


def _entry(owner: str, path: Path | str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {"owner": owner, "path": str(path), "reason": reason}
    result.update(extra)
    return result


def _read_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except OSError as exc:
        return None, str(exc)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"


def _write_json_atomic(path: Path, payload: Any) -> None:
    """Write a migrated projection without exposing a partial JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".migrating",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def _mark_changed(report: dict[str, Any], path: Path, repo: Path) -> None:
    relative = _relative_path(repo, path)
    if relative not in report["changed_paths"]:
        report["changed_paths"].append(relative)


def _queue_migration(repo: Path, target: str, report: dict[str, Any], apply: bool) -> None:
    path = repo / "state" / target_storage_key(target) / "action_queue.json"
    if not path.is_file():
        report["canonical"].append(_entry("action_queue", _relative_path(repo, path), "missing"))
        return

    raw, error = _read_json(path)
    if error:
        report["invalid"].append(_entry("action_queue", _relative_path(repo, path), error))
        return
    if not isinstance(raw, dict):
        report["invalid"].append(_entry("action_queue", _relative_path(repo, path), "queue must be an object"))
        return
    version = raw.get("schema_version", 1)
    if isinstance(version, bool) or not isinstance(version, int):
        report["invalid"].append(_entry("action_queue", _relative_path(repo, path), "schema_version must be an integer"))
        return
    if version > 1:
        report["needs_review"].append(_entry("action_queue", _relative_path(repo, path), "queue schema is newer than this migrator"))
        return
    actions = raw.get("actions", [])
    if not isinstance(actions, list) or any(not isinstance(item, dict) for item in actions):
        report["invalid"].append(_entry("action_queue", _relative_path(repo, path), "actions must be a list of objects"))
        return
    recorded_target = str(raw.get("target") or "").strip()
    if recorded_target and canonical_target_value(recorded_target) != target:
        report["invalid"].append(_entry("action_queue", _relative_path(repo, path), "target does not match requested target"))
        return

    missing_ids = sum(
        1
        for item in actions
        if not str(item.get("id") or "").strip()
        and str(item.get("status") or "queued") in ACTIVE_STATUSES
    )
    for index, item in enumerate(actions):
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if str(item.get("status") or "queued") not in ACTIVE_STATUSES:
            continue
        if not (
            metadata.get("activation_required") is True
            or metadata.get("depth_contract_version") == DEPTH_CONTRACT_VERSION
        ):
            continue
        missing_activation = [
            "depth_contract_version"
            if metadata.get("depth_contract_version") != DEPTH_CONTRACT_VERSION
            else "",
            *[
                field
                for field in ACTIVATION_REQUIRED_FIELDS
                if not str(metadata.get(field) or "").strip()
            ],
        ]
        route = metadata.get("skill_route")
        if not isinstance(route, dict) or not all(
            str(route.get(field) or "").strip()
            for field in ("skill_id", "skill_path")
        ) or not isinstance(route.get("required_dimensions") if isinstance(route, dict) else None, list) or not (
            route.get("required_dimensions") if isinstance(route, dict) else []
        ):
            missing_activation.append("skill_route")
        for field in ("endpoint", "method", "evidence_ref", "baseline_ref", "risk_tier"):
            if not str(metadata.get(field) or "").strip():
                missing_activation.append(field)
        cap = metadata.get("max_hypothesis_actions")
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
            missing_activation.append("max_hypothesis_actions")
        missing_activation = [field for field in missing_activation if field]
        if missing_activation:
            report["needs_review"].append(
                _entry(
                    "action_queue",
                    f"{_relative_path(repo, path)}:actions[{index}]",
                    "active action requires AI activation metadata; migrator will not invent decision fields",
                    action_id=str(item.get("id") or ""),
                    missing_fields=missing_activation,
                    repair_action=(
                        "refresh checkpoint and re-ingest the action, then claim it with "
                        "complete depth_contract_version=1 activation metadata"
                    ),
                )
            )
    changes: list[str] = []
    if version != 1:
        changes.append("schema_version=1")
    if not recorded_target:
        changes.append("target")
    if missing_ids:
        changes.append(f"active_ids={missing_ids}")
    if not changes:
        report["canonical"].append(_entry("action_queue", _relative_path(repo, path), "canonical"))
        return

    item = _entry("action_queue", _relative_path(repo, path), "legacy queue normalization", changes=changes)
    report["migratable"].append(item)
    if not apply:
        return

    with queue_mutation_lock(repo, target):
        queue = load_queue(repo, target)
        queue.setdefault("schema_version", 1)
        queue["target"] = target
        _ensure_active_action_ids(queue)
        save_queue(repo, target, queue)
    _mark_changed(report, path, repo)


def _finding_migration(repo: Path, target: str, report: dict[str, Any], apply: bool) -> None:
    path = repo / "findings" / target_storage_key(target) / "findings.json"
    if not path.is_file():
        report["canonical"].append(_entry("finding_index", _relative_path(repo, path), "missing"))
        return
    raw, error = _read_json(path)
    if error:
        report["invalid"].append(_entry("finding_index", _relative_path(repo, path), error))
        return
    if isinstance(raw, list):
        report["migratable"].append(_entry("finding_index", _relative_path(repo, path), "legacy list payload"))
        if apply:
            load_finding_index(path.parent, migrate_legacy=True)
            _mark_changed(report, path, repo)
        return
    if not isinstance(raw, dict):
        report["invalid"].append(_entry("finding_index", _relative_path(repo, path), "finding index must be an object or legacy list"))
        return
    if raw.get("schema_version") == 1 and isinstance(raw.get("findings"), list):
        report["canonical"].append(_entry("finding_index", _relative_path(repo, path), "canonical"))
        return
    report["needs_review"].append(_entry("finding_index", _relative_path(repo, path), "object shape is not a known canonical or legacy format"))


def _runtime_migration(repo: Path, target: str, report: dict[str, Any], apply: bool) -> None:
    path = state_path(repo, target)
    if not path.is_file():
        report["canonical"].append(_entry("runtime_state", _relative_path(repo, path), "missing"))
        return
    raw, error = _read_json(path)
    if error:
        report["invalid"].append(_entry("runtime_state", _relative_path(repo, path), error))
        return
    if not isinstance(raw, dict):
        report["invalid"].append(_entry("runtime_state", _relative_path(repo, path), "runtime state must be an object"))
        return
    version = raw.get("schema_version", 1)
    if isinstance(version, bool) or not isinstance(version, int):
        report["invalid"].append(_entry("runtime_state", _relative_path(repo, path), "schema_version must be an integer"))
        return
    if version > 2:
        report["needs_review"].append(_entry("runtime_state", _relative_path(repo, path), "runtime schema is newer than this migrator"))
        return
    recorded_target = str(raw.get("target") or "").strip()
    if recorded_target and canonical_target_value(recorded_target) != target:
        report["invalid"].append(_entry("runtime_state", _relative_path(repo, path), "target does not match requested target"))
        return
    legacy_fields = sorted(set(raw) & (set(DEPRECATED_FIELDS) | set(LEGACY_FIELD_RENAMES)))
    needs_target = not recorded_target or raw.get("storage_key") != target_storage_key(target)
    if version == 2 and not legacy_fields and not needs_target:
        report["canonical"].append(_entry("runtime_state", _relative_path(repo, path), "canonical"))
        return

    report["migratable"].append(
        _entry(
            "runtime_state",
            _relative_path(repo, path),
            "v1 to v2 normalization",
            dropped_fields=legacy_fields,
        )
    )
    if apply:
        # The runtime owner performs the rename, whitelist, target binding and
        # atomic write. No migration-specific state shape is introduced here.
        load_runtime_state(repo, target)
        update_runtime_state(repo, target)
        _mark_changed(report, path, repo)


def _memory_migration(repo: Path, target: str, report: dict[str, Any], apply: bool) -> None:
    path = repo / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json"
    if not path.is_file():
        report["canonical"].append(_entry("target_memory", _relative_path(repo, path), "missing"))
        return
    raw, error = _read_json(path)
    if error:
        report["invalid"].append(_entry("target_memory", _relative_path(repo, path), error))
        return
    try:
        normalized = normalize_target_memory(raw, expected_target=target, path=path)
    except ValueError as exc:
        report["invalid"].append(_entry("target_memory", _relative_path(repo, path), str(exc)))
        return

    default_fields = [
        field
        for field in (*TARGET_MEMORY_LIST_FIELDS, *TARGET_MEMORY_STRING_FIELDS, *TARGET_MEMORY_SKILL_FIELDS)
        if field not in raw
    ]
    changes = list(default_fields)
    if raw.get("target") != normalized.get("target"):
        changes.append("target")
    for timestamp in ("created_at", "updated_at"):
        if timestamp not in raw:
            changes.append(timestamp)
    if not changes:
        report["canonical"].append(_entry("target_memory", _relative_path(repo, path), "canonical"))
        return

    report["migratable"].append(_entry("target_memory", _relative_path(repo, path), "fill canonical defaults", changes=changes))
    if not apply:
        return
    with target_memory_mutation_lock(path):
        current = normalize_target_memory(read_memory_json(path), expected_target=target, path=path)
        now = memory_now_utc()
        current.setdefault("created_at", now)
        current.setdefault("updated_at", now)
        write_memory_json(path, current)
    _mark_changed(report, path, repo)


def _valid_source_refs(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(ref, dict)
        and str(ref.get("kind") or "").strip().lower() in SOURCE_REF_KINDS
        and str(ref.get("path") or "").strip()
        for ref in value
    )


def _typed_source_refs(payload: dict[str, Any]) -> list[dict[str, str]]:
    bindings = payload.get("source_bindings")
    if not isinstance(bindings, list):
        return []
    refs: list[dict[str, str]] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            return []
        kind = str(binding.get("kind") or "").strip().lower()
        path = str(binding.get("path") or "").strip()
        if kind not in SOURCE_REF_KINDS or not path:
            return []
        refs.append({"kind": kind, "path": path})
    return refs


def _source_ref_is_target_owned(repo: Path, target: str, path_value: str) -> bool:
    candidate = Path(path_value).expanduser()
    if not candidate.is_absolute():
        candidate = repo / candidate
    try:
        relative = candidate.resolve().relative_to(repo.resolve())
    except (OSError, ValueError):
        return False
    return target_storage_key(target) in relative.parts and candidate.is_file()


def _source_refs_are_owned(repo: Path, target: str, refs: Any) -> bool:
    return _valid_source_refs(refs) and all(
        _source_ref_is_target_owned(repo, target, str(ref.get("path") or ""))
        for ref in refs
    )


def _walk_source_paths(value: Any, location: str = "") -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        if "source_paths" in value:
            found.append((location or "<root>", value))
        for key, child in value.items():
            child_location = f"{location}.{key}" if location else str(key)
            found.extend(_walk_source_paths(child, child_location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_walk_source_paths(child, f"{location}[{index}]"))
    return found


def _source_paths_migration(repo: Path, target: str, report: dict[str, Any], apply: bool) -> None:
    state_dir = repo / "state" / target_storage_key(target)
    if not state_dir.is_dir():
        return
    for path in sorted(state_dir.rglob("*.json")):
        if path.name == "action_queue.json" or not path.is_file():
            continue
        raw, error = _read_json(path)
        if error or not isinstance(raw, (dict, list)):
            continue
        for location, container in _walk_source_paths(raw):
            source_paths = container.get("source_paths")
            if source_paths in (None, []):
                continue
            if not isinstance(source_paths, list) or any(not isinstance(item, str) or not item.strip() for item in source_paths):
                report["invalid"].append(_entry("source_refs", f"{_relative_path(repo, path)}:{location}", "source_paths must be a list of non-empty strings"))
                continue
            refs = container.get("source_refs")
            if refs not in (None, []) and not _valid_source_refs(refs):
                report["invalid"].append(_entry("source_refs", f"{_relative_path(repo, path)}:{location}", "source_refs contains an unknown kind or empty path"))
                continue
            if _source_refs_are_owned(repo, target, refs):
                report["canonical"].append(_entry("source_refs", f"{_relative_path(repo, path)}:{location}", "typed source_refs already present"))
                continue
            if refs not in (None, []):
                report["needs_review"].append(
                    _entry(
                        "source_refs",
                        f"{_relative_path(repo, path)}:{location}",
                        "existing source_refs are malformed or not target-owned",
                    )
                )
                continue
            typed = _typed_source_refs(container)
            if not typed:
                report["needs_review"].append(_entry("source_refs", f"{_relative_path(repo, path)}:{location}", "source_paths has no unambiguous kind; no command flag is inferred"))
                continue
            if any(not _source_ref_is_target_owned(repo, target, ref["path"]) for ref in typed):
                report["needs_review"].append(
                    _entry(
                        "source_refs",
                        f"{_relative_path(repo, path)}:{location}",
                        "typed source binding is missing, outside the repository, or not target-owned",
                    )
                )
                continue

            report["migratable"].append(_entry("source_refs", f"{_relative_path(repo, path)}:{location}", "promote typed source_bindings", source_refs=typed))
            if apply:
                container["source_refs"] = typed[:3]
                _write_json_atomic(path, raw)
                _mark_changed(report, path, repo)


def _list_storage_migration(repo: Path, target: str, report: dict[str, Any], apply: bool) -> dict[str, Any]:
    try:
        info = migrate_legacy_list_storage(repo, target, apply=apply)
    except (OSError, ValueError, TypeError) as exc:
        report["invalid"].append(_entry("target_paths", target, str(exc)))
        return {}
    status = str(info.get("status") or "")
    if status in {"migrated", "would_migrate"}:
        report["migratable"].append(_entry("target_paths", f"state/{info.get('old_key', '')}", status, new_key=info.get("new_key", "")))
        if apply:
            for migrated in info.get("migrated", []):
                _mark_changed(report, Path(migrated), repo)
        if info.get("skipped"):
            report["needs_review"].append(
                _entry(
                    "target_paths",
                    f"state/{info.get('old_key', '')}",
                    "canonical destination already exists; legacy directory was not merged",
                    skipped=info.get("skipped", []),
                )
            )
    elif status == "owner_unverified":
        report["needs_review"].append(_entry("target_paths", f"state/{info.get('old_key', '')}", "legacy list owner is not proven", new_key=info.get("new_key", "")))
    else:
        report["canonical"].append(_entry("target_paths", target, status or "canonical"))
    return info


def migrate_legacy_state(repo_root: str | Path, target: str, *, apply: bool = False) -> dict[str, Any]:
    """Return a deterministic migration report for one target.

    The report is safe to run repeatedly.  ``apply=False`` never calls a
    mutating owner and never creates lock files outside already-existing owner
    directories (the list owner itself performs a read-only check).
    """
    repo = Path(repo_root).resolve()
    if not str(target or "").strip():
        raise ValueError("target is required")
    resolved_target = canonical_target_value(str(target))
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": resolved_target,
        "target_key": target_storage_key(resolved_target),
        "apply": bool(apply),
        "canonical": [],
        "migratable": [],
        "needs_review": [],
        "invalid": [],
        "changed_paths": [],
    }

    list_info = _list_storage_migration(repo, resolved_target, report, apply)
    list_has_pending_move = str(list_info.get("status") or "") == "would_migrate"
    # A dry-run must not pretend that a legacy stem directory is already the
    # canonical state key. After --apply the owner has moved it, so normal
    # owner inspection resumes on the digest key in the same invocation.
    if not list_has_pending_move:
        _queue_migration(repo, resolved_target, report, apply)
        _runtime_migration(repo, resolved_target, report, apply)
        _source_paths_migration(repo, resolved_target, report, apply)
    _finding_migration(repo, resolved_target, report, apply)
    _memory_migration(repo, resolved_target, report, apply)
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--target", required=True)
    parser.add_argument("--apply", action="store_true", help="write canonical state; default is dry-run")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = migrate_legacy_state(args.repo_root, args.target, apply=args.apply)
    except (OSError, ValueError, TypeError) as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
