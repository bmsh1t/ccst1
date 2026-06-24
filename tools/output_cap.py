#!/usr/bin/env python3
"""
output_cap.py — tool return-size cap with overflow logging (P5-B11).

Why: Large recon outputs (200KB+ httpx tables, full surface summaries)
silently overflow the LLM's per-tool budget, causing truncated reasoning
or skipped context. This module gives every dispatcher tool a cheap
"cap & log" helper.

API:
    DEFAULT_CAP_BYTES = 50_000     # ~12k tokens
    cap(payload, *, max_bytes=...) -> str
    cap_dict(d, *, max_bytes=...) -> dict      # caps str leaves recursively
    log_overflow(tool, original_bytes, capped_bytes, *, path=None) -> None

Boundary safety:
    - cap() never breaks mid-multibyte UTF-8 character: it truncates at
      the closest line boundary at-or-before max_bytes, else at-or-before
      the nearest UTF-8 character boundary.
    - cap_dict() walks dicts/lists recursively but only caps str leaves;
      structural keys are preserved as-is.

Overflow events go to hunt-memory/overflow_events.jsonl, one JSON object
per truncated payload, so operators can see which tools blow the budget
most often.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


DEFAULT_CAP_BYTES = 50_000
DEFAULT_MARKER = "\n[…OUTPUT TRUNCATED…]"


def default_overflow_log_path(repo_root: Path | str | None = None) -> Path:
    repo = Path(repo_root) if repo_root else BASE_DIR
    return repo / "hunt-memory" / "overflow_events.jsonl"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_truncate_bytes(payload: str, max_bytes: int) -> str:
    """Truncate a string to max_bytes without breaking multi-byte chars.

    Prefers truncating at the nearest line boundary at-or-before max_bytes
    so the LLM gets clean lines. Falls back to the nearest UTF-8 character
    boundary if no newline is available in the head slice.
    """
    if max_bytes <= 0:
        return ""
    raw = payload.encode("utf-8")
    if len(raw) <= max_bytes:
        return payload

    # Try line boundary first (always prefer; LLM input is more useful when
    # truncated at a clean line, even if a few bytes get sacrificed)
    head = raw[:max_bytes]
    last_nl = head.rfind(b"\n")
    if last_nl >= 0:
        head = head[:last_nl]
        return head.decode("utf-8", errors="ignore")

    # Fall back to UTF-8 char boundary via errors='ignore' semantics
    return head.decode("utf-8", errors="ignore")


def cap(
    payload: str,
    *,
    max_bytes: int = DEFAULT_CAP_BYTES,
    marker: str = DEFAULT_MARKER,
) -> str:
    """Cap a single string payload; append marker on truncation."""
    if not isinstance(payload, str):
        # Defensive: callers may hand us non-str by mistake; coerce
        payload = str(payload)
    if max_bytes <= 0:
        return ""
    raw_len = len(payload.encode("utf-8"))
    if raw_len <= max_bytes:
        return payload
    head = _safe_truncate_bytes(payload, max_bytes - len(marker.encode("utf-8")))
    return head + marker


def _walk_and_cap(node: Any, *, max_bytes: int, marker: str,
                  overflow_keys: list[str], path_prefix: str = "") -> Any:
    if isinstance(node, str):
        if len(node.encode("utf-8")) > max_bytes:
            overflow_keys.append(path_prefix or "<root>")
            return cap(node, max_bytes=max_bytes, marker=marker)
        return node
    if isinstance(node, dict):
        out: dict = {}
        for k, v in node.items():
            sub = f"{path_prefix}.{k}" if path_prefix else str(k)
            out[k] = _walk_and_cap(v, max_bytes=max_bytes, marker=marker,
                                   overflow_keys=overflow_keys, path_prefix=sub)
        return out
    if isinstance(node, list):
        return [_walk_and_cap(v, max_bytes=max_bytes, marker=marker,
                              overflow_keys=overflow_keys,
                              path_prefix=f"{path_prefix}[{i}]")
                for i, v in enumerate(node)]
    return node


def cap_dict(
    d: dict,
    *,
    max_bytes: int = DEFAULT_CAP_BYTES,
    marker: str = DEFAULT_MARKER,
) -> dict:
    """Recursively cap all str leaves of a dict.

    Returns a NEW dict; does not mutate input.
    """
    if not isinstance(d, dict):
        raise TypeError(f"cap_dict expects dict, got {type(d).__name__}")
    keys: list[str] = []
    return _walk_and_cap(d, max_bytes=max_bytes, marker=marker,
                         overflow_keys=keys)


def log_overflow(
    tool: str,
    *,
    original_bytes: int,
    capped_bytes: int,
    path: Path | str | None = None,
) -> dict:
    """Append a single overflow event to the overflow log JSONL.

    Best-effort: errors are swallowed and an empty dict returned, since
    overflow logging must not break a tool call.
    """
    target_path = Path(path) if path else default_overflow_log_path()
    record = {
        "ts": _utc_now(),
        "tool": str(tool or ""),
        "original_bytes": int(original_bytes),
        "capped_bytes": int(capped_bytes),
        "marker_appended": True,
    }
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        line = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(str(target_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.write(fd, line)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return record
    except Exception:
        return {}


def cap_with_log(
    payload: str,
    *,
    tool: str,
    max_bytes: int = DEFAULT_CAP_BYTES,
    marker: str = DEFAULT_MARKER,
    log_path: Path | str | None = None,
) -> str:
    """Convenience: cap a string AND log overflow when triggered.

    Use this in dispatcher tool returns where you want the cap + audit log
    in one call.
    """
    original_bytes = len(payload.encode("utf-8")) if isinstance(payload, str) else 0
    capped = cap(payload, max_bytes=max_bytes, marker=marker)
    capped_bytes = len(capped.encode("utf-8"))
    if capped_bytes < original_bytes:
        log_overflow(tool, original_bytes=original_bytes,
                     capped_bytes=capped_bytes, path=log_path)
    return capped
