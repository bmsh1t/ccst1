#!/usr/bin/env python3
"""One read seam for the target's current evidence truth.

Consumers that ask "what does this target's evidence currently close" read this
module instead of choosing a source themselves. Normal queries require an active
Store; legacy ledger inspection and import have explicit historical readers.

The damage rule (unreadable evidence authorizes nothing) is applied here for
every source, using the one definition in ``closure_projection``: ``closed_cells``
/``closed_cells_v2`` are emptied and the counts are reported under
``identity_v2_diagnostics.suppressed_closed_count`` and
``suppressed_legacy_closed_count``.  Every consumer therefore fails closed on the
same input, and the reason string names the source kind.
"""

from __future__ import annotations

from pathlib import Path

try:
    from tools.closure_projection import (
        build_current_cell_projection,
        suppress_unauthorized_closures,
    )
    from tools.target_store import TargetStore, runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_projection import (  # type: ignore
        build_current_cell_projection,
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
    status = "partial" if truncated or invalid_operations else "ready"
    projection = build_current_cell_projection(records)
    if status == "partial":
        # A truncated prefix would change what closes, so it is damage like any
        # other integrity failure: reported in full, but never allowed to
        # authorize a closure.
        projection = suppress_unauthorized_closures(projection, reason=f"store_{status}")
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
    }


def current_cell_projection(repo_root: str | Path, target: str) -> dict:
    """Read one Store snapshot and suppress closures backed by damaged evidence."""
    return _store_truth(runtime_store(repo_root, target))
