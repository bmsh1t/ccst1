#!/usr/bin/env python3
"""目标记忆层读写工具。

这个工具只维护当前目标、目标线索和会话交接摘要，不替代已有的
`hunt-memory`、`findings`、`state` 等运行时数据。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

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


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path, default: dict | None = None) -> dict:
    if not path.is_file():
        return default or {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default or {}
    return payload if isinstance(payload, dict) else (default or {})


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def target_memory_path(target: str) -> Path:
    return TARGETS_DIR / f"{target_storage_key(target)}.json"


def display_path(path: Path) -> str:
    """优先显示仓库相对路径；外部测试路径则显示绝对路径。"""
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def load_active() -> dict:
    return read_json(ACTIVE_PATH)


def load_target_memory(target: str) -> dict:
    canonical_target = canonical_target_value(target)
    path = target_memory_path(canonical_target)
    payload = read_json(path)
    if payload:
        return payload
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


def save_target_memory(payload: dict) -> Path:
    payload["updated_at"] = now_utc()
    path = target_memory_path(payload["target"])
    write_json(path, payload)
    return path


def set_active(args: argparse.Namespace) -> str:
    canonical_target = canonical_target_value(args.target)
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
    target_path = save_target_memory(target_memory)

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
    target_memory = load_target_memory(target)
    entry = {
        "ts": now_utc(),
        "text": " ".join(args.text).strip(),
    }
    if not entry["text"]:
        raise SystemExit(f"{label} text is required")
    target_memory.setdefault(field, []).append(entry)
    save_target_memory(target_memory)
    return f"{label} saved for {target}: {entry['text']}"


def write_handoff(args: argparse.Namespace) -> str:
    target = resolve_target(args.target)
    target_memory = load_target_memory(target)
    summary = " ".join(args.summary).strip()
    if not summary:
        raise SystemExit("handoff summary is required")

    ts = now_utc()
    stamp = ts.replace(":", "").replace("-", "").replace("Z", "Z")
    session_path = SESSIONS_DIR / f"{stamp}-{target_storage_key(target)}.md"
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
    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text("\n".join(lines), encoding="utf-8")

    target_memory.setdefault("session_handoffs", []).append(
        {"ts": ts, "path": display_path(session_path), "summary": summary}
    )
    save_target_memory(target_memory)
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
        item_parser.set_defaults(func=lambda args, f=field, n=name.upper(): append_entry(args, f, n))

    handoff_parser = subparsers.add_parser("handoff", help="write session handoff markdown")
    handoff_parser.add_argument("summary", nargs="+")
    handoff_parser.add_argument("--target", default=None)
    handoff_parser.set_defaults(func=write_handoff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(args.func(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
