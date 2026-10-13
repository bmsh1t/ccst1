"""Shared validation for legacy target-memory documents; no runtime owner imports."""
from __future__ import annotations

from pathlib import Path

try:
    from tools.target_paths import canonical_target_value
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value

SCHEMA_VERSION = 1
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

POLLUTED_TEXT_MARKERS = ("{'schema_version'", '{"schema_version"')


def text_is_polluted(text: object) -> bool:
    """True 当 text 含已序列化结构外壳（嵌套污染的存量形态）。

    读入口据此返回空（不把残缺文本伪装成正常记忆透传给下游）；
    写入口据此拒绝写入。两者都 import 本函数——单一判据 owner。
    """
    raw = str(text or "")
    return any(marker in raw for marker in POLLUTED_TEXT_MARKERS)


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


