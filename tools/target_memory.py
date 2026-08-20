#!/usr/bin/env python3
"""目标记忆层读写工具。

这个工具只维护当前目标、目标线索和会话交接摘要，不替代已有的
`hunt-memory`、`findings`、`state` 等运行时数据。
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.experience_schema import (
        EXPERIENCE_KINDS,
        make_entry_id,
        normalize_evidence_refs,
        normalize_experience_kind,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from experience_schema import (  # type: ignore
        EXPERIENCE_KINDS,
        make_entry_id,
        normalize_evidence_refs,
        normalize_experience_kind,
    )

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key

SCHEMA_VERSION = 1
BASE_DIR = Path(__file__).resolve().parents[1]
GOALS_DIR = BASE_DIR / "memory" / "goals"
ACTIVE_PATH = GOALS_DIR / "active.json"
TARGETS_DIR = GOALS_DIR / "targets"
SESSIONS_DIR = GOALS_DIR / "sessions"
TARGET_MEMORY_LIST_FIELDS = (
    "scope_notes",
    "active_leads",
    "dead_ends",
    "next_actions",
    "useful_patterns",
    "session_handoffs",
)
TARGET_MEMORY_STRING_FIELDS = (
    "mode",
    "phase",
    "active_goal",
    "current_hypothesis",
)
TARGET_MEMORY_SKILL_FIELDS = ("selected_skills", "knowledge_focus")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path, default: dict | None = None) -> dict:
    if not path.is_file():
        return default or {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read target memory {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid target memory JSON {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"target memory {path} must contain one object")
    return payload


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


@contextmanager
def target_memory_mutation_lock(path: Path):
    """Serialize one target's target-memory read/modify/write sequence."""
    path = Path(path)
    lock_path = path.parent / ".locks" / f"{path.name}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def write_handoff_file(sessions_dir: Path, target_key: str, content: str) -> Path:
    """Create one handoff file without replacing an existing handoff."""
    sessions_dir = Path(sessions_dir)
    sessions_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    for index in range(1000):
        suffix = "" if index == 0 else f"-{index}"
        path = sessions_dir / f"{stamp}-{target_key}{suffix}.md"
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            return path
        except FileExistsError:
            continue
        except Exception:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise
    raise FileExistsError(f"unable to allocate unique handoff file in {sessions_dir}")


def target_memory_path(target: str) -> Path:
    return TARGETS_DIR / f"{target_storage_key(target)}.json"


def display_path(path: Path) -> str:
    """优先显示仓库相对路径；外部测试路径则显示绝对路径。"""
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def load_active() -> dict:
    return load_active_file(ACTIVE_PATH)


def normalize_target_memory(
    payload: dict,
    *,
    expected_target: str | None = None,
    path: Path | None = None,
) -> dict:
    """Validate and lazily normalize one target-memory object.

    Missing optional fields are filled in memory only; reads never rewrite the
    source file. This keeps legacy v1 files readable without hiding malformed
    containers or cross-target data.
    """
    location = f" {path}" if path is not None else ""
    if not isinstance(payload, dict):
        raise ValueError(f"invalid target memory{location}: expected an object")
    version = payload.get("schema_version", SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise ValueError(f"invalid target memory{location}: unsupported schema_version")
    raw_target = payload.get("target")
    if not isinstance(raw_target, str) or not raw_target.strip():
        raise ValueError(f"invalid target memory{location}: target is required")
    target = canonical_target_value(raw_target)
    if expected_target is not None:
        resolved_expected = canonical_target_value(expected_target)
        if target != resolved_expected:
            raise ValueError(
                f"invalid target memory{location}: target {target!r} does not match {resolved_expected!r}"
            )

    normalized = dict(payload)
    normalized["schema_version"] = SCHEMA_VERSION
    normalized["target"] = target
    for field in TARGET_MEMORY_LIST_FIELDS:
        value = normalized.get(field, [])
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ValueError(f"invalid target memory{location}: {field} must be a list of objects")
        normalized[field] = value
    for field in TARGET_MEMORY_STRING_FIELDS:
        value = normalized.get(field, "")
        if not isinstance(value, str):
            raise ValueError(f"invalid target memory{location}: {field} must be a string")
        normalized[field] = value
    for field in TARGET_MEMORY_SKILL_FIELDS:
        value = normalized.get(field, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"invalid target memory{location}: {field} must be a list of strings")
        normalized[field] = value
    return normalized


def load_target_memory_file(path: Path, *, expected_target: str | None = None) -> dict:
    """Load one target-memory file, returning ``{}`` only when it is missing."""
    path = Path(path)
    if not path.is_file():
        return {}
    return normalize_target_memory(
        read_json(path), expected_target=expected_target, path=path
    )


def new_target_memory(target: str) -> dict:
    canonical_target = canonical_target_value(target)
    ts = now_utc()
    return {
        "schema_version": SCHEMA_VERSION,
        "target": canonical_target,
        "created_at": ts,
        "updated_at": ts,
        "mode": "hunt",
        "phase": "unknown",
        "scope_notes": [],
        "active_leads": [],
        "dead_ends": [],
        "next_actions": [],
        "useful_patterns": [],
        "session_handoffs": [],
    }


def load_goal_memory(repo_root: str | Path, target: str) -> dict:
    """Load the target-memory projection used by CLI coordinators."""
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    goals_dir = repo / "memory" / "goals"
    active_path = goals_dir / "active.json"
    target_path = goals_dir / "targets" / f"{target_storage_key(resolved_target)}.json"
    active = {}
    if active_path.is_file():
        active = load_active_file(active_path)
    target_memory = load_target_memory_file(target_path, expected_target=resolved_target)
    active_target = canonical_target_value(str(active.get("target", "") or ""))
    active_matches = bool(active_target and active_target == resolved_target)
    return {
        "active": active if active_matches else {},
        "raw_active": active,
        "target": target_memory,
        "active_matches": active_matches,
    }


def load_active_file(path: Path) -> dict:
    """Load and validate an active-target pointer from an arbitrary repo root."""
    path = Path(path)
    if not path.is_file():
        return {}
    payload = read_json(path)
    version = payload.get("schema_version", SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise ValueError(f"invalid active target memory {path}: unsupported schema_version")
    target = payload.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValueError(f"invalid active target memory {path}: target is required")
    normalized = dict(payload)
    normalized["schema_version"] = SCHEMA_VERSION
    normalized["target"] = canonical_target_value(target)
    for field in TARGET_MEMORY_STRING_FIELDS:
        if field in normalized and not isinstance(normalized[field], str):
            raise ValueError(f"invalid active target memory {path}: {field} must be a string")
    for field in TARGET_MEMORY_SKILL_FIELDS:
        value = normalized.get(field, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"invalid active target memory {path}: {field} must be a list of strings")
    return normalized


def load_target_memory(target: str) -> dict:
    canonical_target = canonical_target_value(target)
    path = target_memory_path(canonical_target)
    payload = load_target_memory_file(path, expected_target=canonical_target)
    return payload or new_target_memory(canonical_target)


def _save_target_memory_unlocked(payload: dict) -> Path:
    payload = normalize_target_memory(payload)
    payload["updated_at"] = now_utc()
    path = target_memory_path(payload["target"])
    write_json(path, payload)
    return path


def set_active(args: argparse.Namespace) -> str:
    canonical_target = canonical_target_value(args.target)
    path = target_memory_path(canonical_target)
    with target_memory_mutation_lock(path):
        target_memory = load_target_memory(canonical_target)
        target_memory["mode"] = args.mode
        target_memory["phase"] = args.phase
        if args.goal:
            target_memory["active_goal"] = args.goal
        if args.hypothesis:
            target_memory["current_hypothesis"] = args.hypothesis
        if args.skill:
            target_memory["selected_skills"] = args.skill
        if args.knowledge:
            target_memory["knowledge_focus"] = args.knowledge
        target_path = _save_target_memory_unlocked(target_memory)

        active = {
            "schema_version": SCHEMA_VERSION,
            "target": canonical_target,
            "mode": args.mode,
            "phase": args.phase,
            "active_goal": args.goal or target_memory.get("active_goal", ""),
            "current_hypothesis": args.hypothesis or target_memory.get("current_hypothesis", ""),
            "selected_skills": args.skill or target_memory.get("selected_skills", []),
            "knowledge_focus": args.knowledge or target_memory.get("knowledge_focus", []),
            "target_memory_path": display_path(target_path),
            "updated_at": now_utc(),
        }
        write_json(ACTIVE_PATH, active)
    return format_summary("TARGET SET", active, target_memory)


def resolve_target(explicit_target: str | None) -> str:
    if explicit_target:
        return canonical_target_value(explicit_target)
    active = load_active()
    target = active.get("target")
    if not target:
        raise SystemExit("No active target. Run: python3 tools/target_memory.py set <target>")
    return canonical_target_value(target)


def append_entry(args: argparse.Namespace, field: str, label: str) -> str:
    target = resolve_target(args.target)
    path = target_memory_path(target)
    with target_memory_mutation_lock(path):
        target_memory = load_target_memory(target)
        entry = {
            "ts": now_utc(),
            "text": " ".join(args.text).strip(),
        }
        if not entry["text"]:
            raise SystemExit(f"{label} text is required")
        if field in {"useful_patterns", "dead_ends"}:
            default_kind = "dead-end" if field == "dead_ends" else "useful-pattern"
            evidence_refs = normalize_evidence_refs(getattr(args, "evidence_ref", []))
            entry["entry_id"] = make_entry_id(
                target=target,
                field=field,
                text=entry["text"],
                evidence_refs=evidence_refs,
            )
            entry["kind"] = normalize_experience_kind(
                getattr(args, "kind", None), default=default_kind
            )
            entry["evidence_refs"] = evidence_refs
        target_memory.setdefault(field, []).append(entry)
        _save_target_memory_unlocked(target_memory)
    suffix = f" [{entry['entry_id']}]" if entry.get("entry_id") else ""
    return f"{label} saved for {target}{suffix}: {entry['text']}"


def write_handoff(args: argparse.Namespace) -> str:
    target = resolve_target(args.target)
    summary = " ".join(args.summary).strip()
    if not summary:
        raise SystemExit("handoff summary is required")
    path = target_memory_path(target)
    with target_memory_mutation_lock(path):
        target_memory = load_target_memory(target)
        ts = now_utc()
        next_actions = target_memory.get("next_actions", [])[-5:]
        active_leads = target_memory.get("active_leads", [])[-5:]
        dead_ends = target_memory.get("dead_ends", [])[-5:]

        lines = [
            f"# Target Handoff: {target}",
            "",
            f"- Time: {ts}",
            f"- Mode: {target_memory.get('mode', 'hunt')}",
            f"- Phase: {target_memory.get('phase', 'unknown')}",
            "",
            "## Summary",
            summary,
            "",
            "## Active Leads",
            *format_entries(active_leads),
            "",
            "## Next Actions",
            *format_entries(next_actions),
            "",
            "## Recent Dead Ends",
            *format_entries(dead_ends),
            "",
        ]
        session_path = write_handoff_file(
            SESSIONS_DIR,
            target_storage_key(target),
            "\n".join(lines),
        )

        target_memory.setdefault("session_handoffs", []).append(
            {"ts": ts, "path": display_path(session_path), "summary": summary}
        )
        try:
            _save_target_memory_unlocked(target_memory)
        except Exception:
            session_path.unlink(missing_ok=True)
            raise
    return f"Handoff written: {display_path(session_path)}"


def format_entries(entries: list[dict]) -> list[str]:
    if not entries:
        return ["- None"]
    return [f"- {item.get('text', '').strip()}" for item in entries if item.get("text")]


def format_summary(title: str, active: dict, target_memory: dict) -> str:
    return "\n".join(
        [
            title,
            "=" * len(title),
            f"Target: {active.get('target') or target_memory.get('target', '')}",
            f"Mode: {active.get('mode') or target_memory.get('mode', '')}",
            f"Phase: {active.get('phase') or target_memory.get('phase', '')}",
            f"Goal: {active.get('active_goal') or target_memory.get('active_goal', '')}",
            f"Hypothesis: {active.get('current_hypothesis') or target_memory.get('current_hypothesis', '')}",
            f"Active leads: {len(target_memory.get('active_leads', []))}",
            f"Next actions: {len(target_memory.get('next_actions', []))}",
            f"Dead ends: {len(target_memory.get('dead_ends', []))}",
            f"Memory: {display_path(target_memory_path(target_memory.get('target', '')))}",
        ]
    )


def show(args: argparse.Namespace) -> str:
    active = load_active()
    target = args.target or active.get("target")
    if not target:
        return "No active target. Run: python3 tools/target_memory.py set <target>"
    target_memory = load_target_memory(target)
    return format_summary("TARGET MEMORY", active, target_memory)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage Claude CLI target memory.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    show_parser = subparsers.add_parser("show", help="show active target memory")
    show_parser.add_argument("target", nargs="?", help="target to show; defaults to active target")
    show_parser.set_defaults(func=show)

    set_parser = subparsers.add_parser("set", help="set active target")
    set_parser.add_argument("target")
    set_parser.add_argument("--mode", default="hunt")
    set_parser.add_argument("--phase", default="recon")
    set_parser.add_argument("--goal", default="")
    set_parser.add_argument("--hypothesis", default="")
    set_parser.add_argument("--skill", action="append", default=[])
    set_parser.add_argument("--knowledge", action="append", default=[])
    set_parser.set_defaults(func=set_active)

    for name, field, help_text in (
        ("note", "scope_notes", "append target note"),
        ("lead", "active_leads", "append active lead"),
        ("next", "next_actions", "append next action"),
        ("dead-end", "dead_ends", "append dead end"),
        ("pattern", "useful_patterns", "append useful target pattern"),
    ):
        item_parser = subparsers.add_parser(name, help=help_text)
        item_parser.add_argument("text", nargs="+")
        item_parser.add_argument("--target", default=None)
        if name in {"pattern", "dead-end"}:
            item_parser.add_argument(
                "--kind",
                choices=EXPERIENCE_KINDS,
                default=None,
                help="experience kind; defaults to pattern/dead-end based on the command",
            )
            item_parser.add_argument(
                "--evidence-ref",
                action="append",
                default=[],
                help="repository-relative evidence reference; repeatable",
            )
        item_parser.set_defaults(func=lambda args, f=field, n=name.upper(): append_entry(args, f, n))

    handoff_parser = subparsers.add_parser("handoff", help="write session handoff markdown")
    handoff_parser.add_argument("summary", nargs="+")
    handoff_parser.add_argument("--target", default=None)
    handoff_parser.set_defaults(func=write_handoff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        print(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"target memory command failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
