#!/usr/bin/env python3
"""Store 目标经验与显式目标选择接口；旧文件仅供历史检查和导入。"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.experience_schema import EXPERIENCE_KINDS
except ImportError:  # pragma: no cover - direct tools/ execution
    from experience_schema import EXPERIENCE_KINDS  # type: ignore

try:
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.target_store import StoreError, runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key
    from target_store import StoreError, runtime_store  # type: ignore

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
OPERATION_REF_HELP = (
    "OPERATION_ID:STEP from an existing execution receipt; STEP is a zero-based "
    "observation index (e.g. OPERATION_ID:0), not a file path; repeatable"
)

# text 字段的污染特征：曾有两处写入方把结构化 proposal 整体 str() 后存进 text
# （checkpoint 的 _dedupe 与 surface 的回灌链，2026-09-15 治理）。特征锚定
# 结构外壳本身（schema_version 键的字面量），不做语义猜测。
POLLUTED_TEXT_MARKERS = ("{'schema_version'", '{"schema_version"')


def text_is_polluted(text: object) -> bool:
    """True 当 text 含已序列化结构外壳（嵌套污染的存量形态）。

    读入口据此返回空（不把残缺文本伪装成正常记忆透传给下游）；
    写入口据此拒绝写入。两者都 import 本函数——单一判据 owner。
    """
    raw = str(text or "")
    return any(marker in raw for marker in POLLUTED_TEXT_MARKERS)


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


def target_memory_path(target: str, repo_root: Path | None = None) -> Path:
    directory = Path(repo_root) / "memory/goals/targets" if repo_root is not None else TARGETS_DIR
    return directory / f"{target_storage_key(target)}.json"


def display_path(path: Path, repo_root: Path | None = None) -> str:
    """优先显示仓库相对路径；外部测试路径则显示绝对路径。"""
    try:
        return str(path.relative_to(repo_root or BASE_DIR))
    except ValueError:
        return str(path)


def load_active(repo_root: Path | None = None) -> dict:
    return load_active_file(Path(repo_root) / "memory/goals/active.json" if repo_root is not None else ACTIVE_PATH)


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
    facts = normalized.get("facts")
    if facts is None:
        facts = {}
    if not isinstance(facts, dict) or any(
        not isinstance(value, dict) for value in facts.values()
    ):
        raise ValueError(f"invalid target memory{location}: facts must be a keyed map of objects")
    normalized["facts"] = facts
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
        "facts": {},
    }


def load_goal_memory(repo_root: str | Path, target: str, *, experience_limit: int = 20) -> dict:
    """Load the target-memory projection used by CLI coordinators.

    Primary targets keep mutable experience in TargetStore.  The legacy JSON
    shape remains a read projection for callers, but archived JSON is never
    consulted after cutover.
    """
    if type(experience_limit) is not int or not 1 <= experience_limit <= 1000:
        raise ValueError("experience_limit must be between 1 and 1000")
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    goals_dir = repo / "memory" / "goals"
    active_path = goals_dir / "active.json"
    active = {}
    if active_path.is_file():
        active = load_active_file(active_path)
    active_target = canonical_target_value(str(active.get("target", "") or ""))
    active_matches = bool(active_target and active_target == resolved_target)
    store = runtime_store(repo, resolved_target)
    selected = ({key: active[key] for key in ("schema_version", "target", "updated_at") if key in active}
                if active_matches else {})
    context = store.memory_context(limit=experience_limit)
    page = context["experiences"]
    rows = page["items"]

    fields = {
        "scope_notes": [],
        "active_leads": [],
        "dead_ends": [],
        "next_actions": [],
        "useful_patterns": [],
        "session_handoffs": [],
    }
    kind_to_field = {
        "note": "scope_notes",
        "hypothesis": "active_leads",
        "negative": "dead_ends",
        "primitive": "useful_patterns",
        "handoff": "session_handoffs",
    }
    recent_entries = []
    for row in sorted(rows, key=lambda item: (str(item.get("created_at") or ""), str(item.get("id") or ""))):
        field = kind_to_field.get(str(row.get("kind") or ""))
        if not field:
            continue
        structured = {
            key: row[key]
            for key in ("conditions", "reopen_when", "next_intent")
            if str(row.get(key) or "").strip()
        }
        entry = {
            "ts": row.get("created_at", ""),
            "text": str(row.get("statement") or "").strip(),
            "entry_id": row.get("id", ""),
            "kind": row.get("kind", ""),
            "recorded_by": row.get("recorded_by", ""),
            "evidence_refs": [
                f"{item.get('operation_id')}:{item.get('step')}"
                for item in row.get("evidence", [])
                if isinstance(item, dict)
            ],
            "structured": structured or None,
        }
        fields[field].append(entry)
        recent_entries.append(entry)
        if row["kind"] == "handoff" and row.get("next_intent"):
            fields["next_actions"].append(entry)
    created_at = context.get("created_at", "")
    target_memory = {
        "schema_version": SCHEMA_VERSION,
        "target": resolved_target,
        "created_at": created_at,
        "updated_at": rows[0].get("created_at", created_at) if rows else created_at,
        "mode": "hunt",
        "phase": "unknown",
        "active_goal": context["active_goal"],
        "current_hypothesis": context["current_hypothesis"],
        **fields,
        "facts": {},
    }
    return {
        "active": selected,
        "raw_active": active,
        "target": target_memory,
        "recent_entries": list(reversed(recent_entries)),
        "active_matches": active_matches,
        "source": {
            "kind": "store",
            "store_id": context.get("store_id", ""),
            "revision": context.get("revision", 0),
            "experience_window": {
                **{key: page[key] for key in ("total", "remaining", "has_more", "next_cursor")},
                "recall_command": shlex.join([
                    "python3", "tools/experience_recall.py", "--repo-root", str(repo.resolve()),
                    "--target", resolved_target, "--limit", str(experience_limit),
                ]),
            },
        },
        "active_path": str(active_path),
        "target_path": str(store.path),
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


def load_target_memory(target: str, repo_root: Path | None = None) -> dict:
    return load_goal_memory(repo_root or BASE_DIR, target)["target"]


class TargetSelectionError(StoreError):
    """The goal commit succeeded, but publishing the target pointer failed."""

    def __init__(self, target: str, receipt: dict, cause: OSError):
        super().__init__(f"goal committed: {json.dumps(receipt, sort_keys=True)}; target selection failed: {cause}")
        self.target = target
        self.receipt = receipt


def set_active(args: argparse.Namespace) -> str | dict:
    repo_root = getattr(args, "repo_root", None)
    canonical_target = canonical_target_value(args.target)
    store = runtime_store(repo_root or BASE_DIR, canonical_target)
    retired = ("mode", "phase", "hypothesis", "skill", "knowledge")
    supplied = [name for name in retired if getattr(args, name, None) not in (None, [])]
    if supplied:
        raise StoreError("retired target-memory flags are not Store fields: " + ", ".join(supplied))
    goal = getattr(args, "goal", None)
    receipt = None
    if goal is not None:
        receipt = store.set_active_goal(
            command_id=getattr(args, "command_id", None) or f"goal:{uuid.uuid4().hex}",
            goal=goal, actor="operator", expected_revision=getattr(args, "expected_revision", None),
        )
    active = {"schema_version": SCHEMA_VERSION, "target": canonical_target,
              "updated_at": now_utc()}
    try:
        active_path = Path(repo_root) / "memory/goals/active.json" if repo_root is not None else ACTIVE_PATH
        write_json(active_path, active)
    except OSError as exc:
        if receipt is not None:
            raise TargetSelectionError(canonical_target, receipt, exc) from exc
        raise
    if getattr(args, "json", False):
        return {"target": canonical_target, "receipt": receipt, "selection_status": "selected"}
    projection = load_goal_memory(repo_root or BASE_DIR, canonical_target)
    result = format_summary("TARGET SET", active, projection["target"], memory_path=store.path,
                            repo_root=repo_root)
    return result + (f"\nGoal receipt: {json.dumps(receipt, sort_keys=True)}" if receipt else "")


def resolve_target(explicit_target: str | None, repo_root: Path | None = None) -> str:
    if explicit_target:
        return canonical_target_value(explicit_target)
    active = load_active(repo_root)
    target = active.get("target")
    if not target:
        raise SystemExit("No active target. Run: python3 tools/target_memory.py set <target>")
    return canonical_target_value(target)


def _operation_refs(values: list[str]) -> list[dict]:
    refs = []
    for value in values:
        operation_id, separator, step = value.rpartition(":")
        if not separator or not operation_id or not step.isdigit():
            raise StoreError(f"--operation-ref must be {OPERATION_REF_HELP}")
        refs.append({"operation_id": operation_id, "step": int(step)})
    return refs


def append_entry(args: argparse.Namespace, field: str, label: str) -> str | dict:
    repo_root = getattr(args, "repo_root", None)
    target = resolve_target(args.target, repo_root)
    store = runtime_store(repo_root or BASE_DIR, target)
    structured_raw = str(getattr(args, "structured_json", "") or "")
    structured: dict = {}
    if structured_raw:
        try:
            structured = json.loads(structured_raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--structured-json must be valid JSON: {exc}") from exc
        if not isinstance(structured, dict):
            raise SystemExit("--structured-json must be a JSON object")
        required = {"hypothesis", "evidence_ref", "next", "stop_condition"}
        missing = required - set(structured)
        if missing:
            raise SystemExit(
                "--structured-json requires all of: " + ", ".join(sorted(required))
            )
    if structured or getattr(args, "kind", None) is not None:
        raise StoreError("legacy --structured-json/--kind is not a Store write; use explicit condition fields")
    if getattr(args, "evidence_ref", []):
        raise StoreError("legacy path evidence refs cannot establish Store observations; use --operation-ref")
    statement = " ".join(args.text).strip() or str(structured.get("hypothesis") or "").strip()
    if not statement:
        raise StoreError(f"{label} text is required")
    kind = {"scope_notes": "note", "active_leads": "hypothesis", "next_actions": "handoff",
            "dead_ends": "negative", "useful_patterns": "primitive"}[field]
    evidence = _operation_refs(getattr(args, "operation_ref", []) or [])
    conditions = getattr(args, "conditions", None) or "unknown"
    reopen_when = getattr(args, "reopen_when", None) or ""
    next_intent = (getattr(args, "next_intent", None) or str(structured.get("next") or "")
                   or (statement if field == "next_actions" else ""))
    if kind == "negative" and (conditions == "unknown" or not reopen_when or not evidence):
        raise StoreError(
            "dead-end requires --conditions, --reopen-when and --operation-ref OPERATION_ID:STEP. "
            "Use an existing execution receipt and zero-based step (e.g. OPERATION_ID:0). "
            "Without registered evidence, save an advisory note: "
            "python3 tools/target_memory.py note --target TARGET 'Unverified observation'. "
            "Run: python3 tools/target_memory.py dead-end --help"
        )
    if kind in {"negative", "primitive"} and not evidence:
        raise StoreError(
            f"{label} requires --operation-ref {OPERATION_REF_HELP}. "
            "Without registered evidence, use note --target TARGET 'Unverified observation'."
        )
    receipt = store.remember(
        command_id=getattr(args, "command_id", None) or f"memory:{uuid.uuid4().hex}",
        kind=kind, statement=statement, conditions=conditions,
        reopen_when=reopen_when, next_intent=next_intent,
        evidence=evidence, actor=getattr(args, "actor", "operator"),
    )
    if getattr(args, "json", False):
        return {"target": target, "receipt": receipt}
    return f"{label} saved for {target} [{receipt['entity_id']}]: {statement}"


FACT_KEY_RE = None  # compiled lazily to keep import-time cost unchanged


def _fact_key_is_valid(key: str) -> bool:
    """Fact keys are slug-like so the keyed map stays greppable and safe."""
    global FACT_KEY_RE
    if FACT_KEY_RE is None:
        import re

        FACT_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
    return bool(FACT_KEY_RE.match(key))


def upsert_fact(args: argparse.Namespace) -> str | dict:
    """Append an advisory Store note, retaining earlier statements."""
    repo_root = getattr(args, "repo_root", None)
    key = args.key.strip()
    text = " ".join(args.text).strip()
    if not key:
        raise SystemExit("fact --key is required")
    if not _fact_key_is_valid(key):
        raise SystemExit(
            "fact key must match ^[a-z0-9][a-z0-9._-]{0,79}$ "
            "(lowercase slug, dots/dashes/underscores allowed)"
        )
    if not text:
        raise SystemExit("fact text is required")
    target = resolve_target(args.target, repo_root)
    store = runtime_store(repo_root or BASE_DIR, target)
    if getattr(args, "evidence_ref", []):
        raise StoreError("legacy path evidence refs cannot establish Store observations; use --operation-ref")
    receipt = store.remember(
        command_id=getattr(args, "command_id", None) or f"memory:{uuid.uuid4().hex}",
        kind="note", statement=f"{key}: {text}", conditions=getattr(args, "conditions", None) or "unknown",
        reopen_when="", next_intent="", evidence=_operation_refs(getattr(args, "operation_ref", []) or []),
        actor=getattr(args, "actor", "operator"),
    )
    if getattr(args, "json", False):
        return {"target": target, "receipt": receipt}
    return f"FACT recorded as note for {target} [{receipt['entity_id']}]: {key}: {text}"


def facts_digest(target_memory: dict, *, limit: int | None = None) -> list[str]:
    """Render the keyed fact map as bounded display lines."""
    facts = target_memory.get("facts") or {}
    if not isinstance(facts, dict):
        return []
    lines = []
    for key in sorted(facts):
        item = facts.get(key) or {}
        text = str(item.get("text", "")).strip()
        if not text:
            continue
        lines.append(f"- {key}: {text}")
        if limit is not None and len(lines) >= limit:
            break
    return lines


def write_handoff(args: argparse.Namespace) -> str | dict:
    repo_root = getattr(args, "repo_root", None)
    target = resolve_target(args.target, repo_root)
    summary = " ".join(args.summary).strip()
    if not summary:
        raise SystemExit("handoff summary is required")
    store = runtime_store(repo_root or BASE_DIR, target)
    receipt = store.remember(
        command_id=getattr(args, "command_id", None) or f"memory:{uuid.uuid4().hex}",
        kind="handoff", statement=summary, conditions=getattr(args, "conditions", None) or "unknown",
        reopen_when="", next_intent=getattr(args, "next_intent", None) or "",
        evidence=[], actor=getattr(args, "actor", "operator"),
    )
    if getattr(args, "json", False):
        return {"target": target, "receipt": receipt}
    return f"Handoff saved for {target} [{receipt['entity_id']}]"


def format_entries(entries: list[dict]) -> list[str]:
    if not entries:
        return ["- None"]
    return [f"- {item.get('text', '').strip()}" for item in entries if item.get("text")]


def format_summary(title: str, active: dict, target_memory: dict,
                   *, memory_path: Path | None = None, repo_root: Path | None = None) -> str:
    path = memory_path or target_memory_path(target_memory.get("target", ""), repo_root)
    lines = [
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
        f"Memory: {display_path(path, repo_root)}",
    ]
    fact_lines = facts_digest(target_memory)
    if fact_lines:
        lines.append("Facts:")
        lines.extend(fact_lines)
    return "\n".join(lines)


def show(args: argparse.Namespace) -> str | dict:
    repo_root = getattr(args, "repo_root", None)
    active = load_active(repo_root)
    target = args.target or active.get("target")
    if not target:
        if getattr(args, "json", False):
            raise StoreError("No active target. Run: python3 tools/target_memory.py set <target>")
        return "No active target. Run: python3 tools/target_memory.py set <target>"
    projection = load_goal_memory(repo_root or BASE_DIR, target)
    if getattr(args, "json", False):
        return projection
    target_memory = projection["target"] or new_target_memory(target)
    summary = format_summary("TARGET MEMORY", projection["active"], target_memory,
                             memory_path=Path(projection["target_path"]) if projection.get("source") else None,
                             repo_root=repo_root)
    if projection.get("source", {}).get("kind") != "store":
        return summary
    lines = [summary]
    entries = projection.get("recent_entries", [])
    if entries:
        lines.append("Recent experience:")
        for entry in entries:
            lines.append(f"- ({entry['kind']}) [{entry['entry_id']}] {entry['text']}")
            for key in ("conditions", "reopen_when", "next_intent"):
                value = (entry.get("structured") or {}).get(key)
                if value:
                    lines.append(f"  {key}: {value}")
            if entry.get("evidence_refs"):
                lines.append(f"  evidence: {', '.join(entry['evidence_refs'])}")
            lines.append(f"  recorded_by: {entry['recorded_by']}")
    window = projection["source"]["experience_window"]
    if window["has_more"]:
        lines.append(f"More target experiences: {window['remaining']}")
        lines.append(f"Next cursor: {window['next_cursor']}")
        lines.append(f"Next page: {window['recall_command']} --cursor {shlex.quote(window['next_cursor'])}")
    lines.append(f"Expand: {window['recall_command']} --id EXPERIENCE_ID")
    return "\n".join(lines)


class MemoryArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(f"{message}\n{self.format_usage().strip()}\nRun: {self.prog} --help")


def build_parser() -> argparse.ArgumentParser:
    parser = MemoryArgumentParser(
        description="Read and save target experience in an explicitly initialized Store.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples (TARGET must already be initialized):\n"
            "  python3 tools/target_memory.py show TARGET\n"
            "  python3 tools/target_memory.py set TARGET --goal 'Review ownership boundary'\n"
            "  python3 tools/target_memory.py note --target TARGET 'Unverified routing note'\n"
            "  python3 tools/target_memory.py handoff --target TARGET 'Resume from saved evidence'\n"
            "Use dead-end --help or pattern --help for evidence-backed experience.\n"
            "For a fresh target only: python3 tools/target_store.py init --store --target TARGET\n"
            "Use --repo-root ROOT on isolated checkouts; reads and memory writes never initialize a Store."
        ),
    )
    parser.add_argument("--repo-root", type=Path, default=None, help="repository data root")
    parser.add_argument("--json", action="store_true", help="emit structured results and errors")
    subparsers = parser.add_subparsers(dest="command", required=True)

    show_parser = subparsers.add_parser("show", help="show active target memory")
    show_parser.add_argument("target", nargs="?", help="target to show; defaults to active target")
    show_parser.set_defaults(func=show)

    set_parser = subparsers.add_parser("set", help="select an initialized target; optionally update its goal")
    set_parser.add_argument("target", help="required positional TARGET (set does not use --target)")
    set_parser.add_argument("--mode", default=None, help=argparse.SUPPRESS)
    set_parser.add_argument("--phase", default=None, help=argparse.SUPPRESS)
    set_parser.add_argument("--goal", default=None, help="explicit goal update; omitted leaves the goal unchanged")
    set_parser.add_argument("--expected-revision", type=int, default=None)
    set_parser.add_argument("--command-id", default=None)
    set_parser.add_argument("--hypothesis", default=None, help=argparse.SUPPRESS)
    set_parser.add_argument("--skill", action="append", default=None, help=argparse.SUPPRESS)
    set_parser.add_argument("--knowledge", action="append", default=None, help=argparse.SUPPRESS)
    set_parser.set_defaults(func=set_active)

    for name, field, help_text in (
        ("note", "scope_notes", "save an advisory note; no execution evidence required"),
        ("lead", "active_leads", "save an advisory hypothesis"),
        ("next", "next_actions", "save next intent as a handoff; does not create an Action"),
        ("dead-end", "dead_ends", "save a negative result with conditions, reopening criteria and evidence"),
        ("pattern", "useful_patterns", "save a reusable primitive with registered execution evidence"),
    ):
        example = f"python3 tools/target_memory.py {name} --target TARGET"
        if name == "dead-end":
            example += " --conditions 'same tenant; JSON; release 1' --reopen-when 'role or release changes'"
        if name in {"dead-end", "pattern"}:
            example += " --operation-ref OPERATION_ID:0"
        item_parser = subparsers.add_parser(
            name, help=help_text, description=help_text,
            epilog=f"Example: {example} 'Observation or intent'. Evidence refs must already exist in the target Store.",
        )
        item_parser.add_argument("text", nargs="*", help="observation or intent text")
        item_parser.add_argument("--target", default=None, help="explicit target; otherwise use selected target")
        item_parser.add_argument("--conditions", default=None, help="identity, representation and deployment; required for dead-end")
        item_parser.add_argument("--reopen-when", default=None, help="changes that invalidate this negative; required for dead-end")
        item_parser.add_argument("--next-intent", default=None, help="advisory continuation, not an executed action")
        item_parser.add_argument("--operation-ref", action="append", default=[], help=OPERATION_REF_HELP)
        item_parser.add_argument("--command-id", default=None)
        item_parser.add_argument("--actor", default="operator")
        if name in {"lead", "next"}:
            item_parser.add_argument(
                "--structured-json",
                default="",
                help=argparse.SUPPRESS,
            )
        if name in {"pattern", "dead-end"}:
            item_parser.add_argument(
                "--kind",
                choices=EXPERIENCE_KINDS,
                default=None,
                help=argparse.SUPPRESS,
            )
            item_parser.add_argument(
                "--evidence-ref",
                action="append",
                default=[],
                help=argparse.SUPPRESS,
            )
        item_parser.set_defaults(func=lambda args, f=field, n=name.upper(): append_entry(args, f, n))

    handoff_parser = subparsers.add_parser("handoff", help="save target handoff experience")
    handoff_parser.add_argument("summary", nargs="+")
    handoff_parser.add_argument("--target", default=None)
    handoff_parser.add_argument("--conditions", default=None)
    handoff_parser.add_argument("--next-intent", default=None)
    handoff_parser.add_argument("--command-id", default=None)
    handoff_parser.add_argument("--actor", default="operator")
    handoff_parser.set_defaults(func=write_handoff)

    fact_parser = subparsers.add_parser(
        "fact", help="append a keyed advisory note; preserves earlier notes"
    )
    fact_parser.add_argument("--key", required=True, help="stable fact key, e.g. cdn-filtering-502")
    fact_parser.add_argument("text", nargs="+", help="fact summary text")
    fact_parser.add_argument("--target", default=None)
    fact_parser.add_argument("--conditions", default=None)
    fact_parser.add_argument("--operation-ref", action="append", default=[], help=OPERATION_REF_HELP)
    fact_parser.add_argument("--command-id", default=None)
    fact_parser.add_argument("--actor", default="operator")
    fact_parser.add_argument(
        "--evidence-ref",
        action="append",
        default=[],
        help=argparse.SUPPRESS,
    )
    fact_parser.set_defaults(func=upsert_fact)

    for subparser in subparsers.choices.values():
        subparser.add_argument("--repo-root", type=Path, default=argparse.SUPPRESS,
                               help="repository data root")
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                               help="emit structured results and errors")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in argv
    try:
        args = parser.parse_args(argv)
        json_output = args.json
        result = args.func(args)
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result)
    except (OSError, ValueError, SystemExit) as exc:
        if isinstance(exc, SystemExit) and not isinstance(exc.code, str):
            raise  # argparse --help keeps its normal exit behavior.
        if json_output:
            error = {"error": str(exc)}
            if isinstance(exc, TargetSelectionError):
                error.update(target=exc.target, receipt=exc.receipt, selection_status="failed")
            print(json.dumps(error, ensure_ascii=False))
        else:
            print(f"target memory command failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
