#!/usr/bin/env python3
"""One read seam for the target's current evidence truth.

Consumers that ask "what does this target's evidence currently close" read this
module instead of choosing a source themselves. Normal queries require an active
Store; legacy ledger inspection and import have explicit historical readers.

Known operation-local damage suppresses its reduced current closures without
resurrecting older evidence. Unknown identity or truncated input suppresses all
closures. Raw records remain available with explicit health diagnostics.
"""

from __future__ import annotations

from pathlib import Path

try:
    from tools.closure_projection import (
        build_current_cell_projection,
        derive_identity_fields,
        suppress_unauthorized_closures,
    )
    from tools.target_store import TargetStore, runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_projection import (  # type: ignore
        build_current_cell_projection,
        derive_identity_fields,
        suppress_unauthorized_closures,
    )
    from target_store import TargetStore, runtime_store  # type: ignore


DAMAGED_STATUSES = frozenset({"partial", "unreadable"})


def ledger_health_projection(diagnostic: dict) -> dict:
    """Keep Ledger damage visible without serializing raw rows or paths."""
    if not isinstance(diagnostic, dict):
        return {}
    status = str(diagnostic.get("status") or "missing").strip().lower()
    health = {
        "status": status,
        "invalid_count": int(diagnostic.get("invalid_count", 0) or 0),
        "invalid_rows": [
            item for item in (diagnostic.get("invalid_rows") or [])[:5]
            if isinstance(item, dict)
        ],
        "last_valid_offset": int(diagnostic.get("last_valid_offset", 0) or 0),
    }
    if status == "unreadable" and diagnostic.get("read_error"):
        health["read_error"] = " ".join(str(diagnostic["read_error"]).split())[:240]
    return health


def _path_label(repo_root: Path, path: Path) -> str:
    """Label a source file for reports without ever leaking an absolute path."""
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.name


def _store_truth(store: TargetStore) -> dict:
    reading = store.closure_records(verify=True)
    records = list(reading.get("records") or [])
    truncated = bool(reading.get("truncated"))
    invalid_operations = reading["invalid_operations"]
    invalid_ids = {item["operation_id"] for item in invalid_operations}
    for record in records:
        if record.get("superseded") or record.get("identity_status") != "complete":
            continue
        identity = record.get("identity_v2") or {}
        if identity.get("schema_version") != 3:
            continue  # Historical identity is not current closure authority.
        checked = derive_identity_fields(dict(record))
        operation_id = record["event_id"].rsplit(":", 1)[0]
        if checked.get("identity_status") == "conflict" and operation_id not in invalid_ids:
            invalid_operations.append({"operation_id": operation_id, "reason": "invalid current identity"})
            invalid_ids.add(operation_id)
    status = "partial" if truncated or invalid_operations else "ready"
    projection = build_current_cell_projection(records)
    invalid_event_ids: set[str] | None = set()
    if status == "partial":
        damaged = [record for record in records
                   if str(record.get("event_id") or "").rsplit(":", 1)[0] in invalid_ids]
        # Scope damage to whole operations, including controls on which their
        # subjects depend. Unknown identities or incomplete snapshots remain
        # global failures; they cannot establish an independent unaffected set.
        scoped = not truncated and bool(damaged) and all(
            record.get("evidence_role") == "control"
            or derive_identity_fields(dict(record)).get("identity_status") == "complete"
            for record in damaged
        ) and invalid_ids <= {
            str(record["event_id"]).rsplit(":", 1)[0] for record in damaged
        }
        invalid_event_ids = {record["event_id"] for record in damaged} if scoped else None
        projection = suppress_unauthorized_closures(
            projection, reason=f"store_{status}",
            invalid_event_ids=invalid_event_ids,
        )
    health = {
        "status": status,
        "source_kind": "store",
        "invalid_count": len(invalid_operations),
        "invalid_rows": invalid_operations[:5],
        "last_valid_offset": 0,
    }
    return {
        "source": {
            "kind": "store",
            "status": status,
            "path_label": _path_label(store.root, store.path),
            "store_id": str(reading.get("store_id") or ""),
            "revision": int(reading.get("revision") or 0),
            "truncated": truncated,
            "store_claim": "primary",
        },
        "health": health,
        "records": records,
        "projection": projection,
        "invalid_event_ids": sorted(invalid_event_ids) if invalid_event_ids is not None else None,
    }


def current_cell_projection(repo_root: str | Path, target: str, *, _store: TargetStore | None = None) -> dict:
    """Read one Store snapshot and suppress closures backed by damaged evidence."""
    if _store is not None:
        # Reuse a live owner handle, never previously acquired truth or health.
        expected = TargetStore(repo_root, target)
        if _store.path != expected.path or _store.target != expected.target or _store.allow_preview:
            raise ValueError("current truth Store does not match the selected runtime target")
    return _store_truth(_store if _store is not None else runtime_store(repo_root, target))
