#!/usr/bin/env python3
"""目标经验条目的共享规范化工具。

目标记忆、checkpoint 写回和候选 staging 都会写/读经验条目；这里集中维护
经验类型、证据引用规范和稳定 ID，避免每个入口各自解释同一份 JSON。
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable


EXPERIENCE_KINDS = (
    "useful-pattern",
    "tool-choice",
    "validation-technique",
    "dead-end",
)

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def normalize_experience_kind(value: str | None, *, default: str) -> str:
    """Normalize an experience kind and fail early for unsupported values."""
    candidate = str(value or default).strip().lower().replace("_", "-")
    aliases = {"pattern": "useful-pattern", "useful-patterns": "useful-pattern"}
    candidate = aliases.get(candidate, candidate)
    if candidate not in EXPERIENCE_KINDS:
        raise ValueError(
            f"unknown experience kind {value!r}; allowed: {', '.join(EXPERIENCE_KINDS)}"
        )
    return candidate


def normalize_evidence_refs(values: Iterable[str] | None) -> list[str]:
    """Trim, de-duplicate and preserve the order of evidence references."""
    result: list[str] = []
    seen: set[str] = set()
    for raw in values or ():
        value = str(raw or "").strip()
        if value and value not in seen:
            result.append(value)
            seen.add(value)
    return result


def make_entry_id(
    *,
    target: str,
    field: str,
    text: str,
    evidence_refs: Iterable[str] | None = None,
) -> str:
    """Return a stable ID for one target-memory experience entry."""
    payload = {
        "target": str(target).strip().lower(),
        "field": str(field).strip(),
        "text": str(text).strip(),
        "evidence_refs": normalize_evidence_refs(evidence_refs),
    }
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return f"tm-{digest}"


def scrub_experience_text(value: str) -> str:
    """Keep candidate summaries free of obvious email/token values."""
    text = str(value or "")
    text = _EMAIL_RE.sub("[email-redacted]", text)
    return _TOKEN_RE.sub("[token-redacted]", text)
