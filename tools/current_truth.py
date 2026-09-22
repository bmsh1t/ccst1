#!/usr/bin/env python3
"""One read seam for the target's current evidence truth.

Consumers that ask "what does this target's evidence currently close" read this
module instead of choosing a source themselves.  The two sources are exclusive:
the per-target store while it holds the ``primary`` role, otherwise the legacy
evidence ledger.  They are never unioned — retired facts and current facts must
not both author one closure cell.

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
    from tools.evidence_ledger import ledger_path, load_entries_diagnostic
    from tools.target_store import StoreError, TargetStore, target_backend
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_projection import (  # type: ignore
        build_current_cell_projection,
        suppress_unauthorized_closures,
    )
    from evidence_ledger import ledger_path, load_entries_diagnostic  # type: ignore
    from target_store import StoreError, TargetStore, target_backend  # type: ignore


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
    reading = store.closure_records()
    records = list(reading.get("records") or [])
    truncated = bool(reading.get("truncated"))
    invalid_operations = []
    if not truncated:
        verify_operation = getattr(store, "verify_operation", None)
        operation_ids = {
            str(event_id).rsplit(":", 1)[0]
            for event_id in (row.get("event_id") for row in records if isinstance(row, dict))
            if ":" in str(event_id or "")
        }
        for operation_id in sorted(operation_ids):
            try:
                if verify_operation is not None:
                    verify_operation(operation_id)
            except (OSError, ValueError, StoreError) as exc:
                # The rows remain historical facts, but damaged raw material
                # cannot authorize a current closure.
                invalid_operations.append({
                    "operation_id": operation_id,
                    "reason": " ".join(str(exc).split())[:240],
                })
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


def _ledger_truth(store: TargetStore, *, store_claim: str = "") -> dict:
    diagnostic = load_entries_diagnostic(store.root, store.target)
    records = list(diagnostic.get("entries") or [])
    status = str(diagnostic.get("status") or "missing").strip().lower()
    projection = build_current_cell_projection(records)
    if status in DAMAGED_STATUSES:
        projection = suppress_unauthorized_closures(projection, reason=f"ledger_{status}")
    return {
        "source": {
            "kind": "ledger",
            "status": status,
            "path_label": _path_label(store.root, ledger_path(store.root, store.target)),
            "store_id": "",
            "revision": 0,
            "truncated": False,
            "store_claim": store_claim,
        },
        "health": {**ledger_health_projection(diagnostic), "source_kind": "ledger"},
        "records": records,
        "projection": projection,
    }


def current_cell_projection(repo_root: str | Path, target: str) -> dict:
    """Return the target's one closure result and the source that authored it.

    ``records`` are the canonical rows the projection was built from, so callers
    that also need the raw facts (recent outcomes, terminals) read the same
    rows the closure verdict read.  ``health`` carries the source's damage
    status plus ``source_kind``; the reason vocabulary is unchanged, so a
    damaged ledger still reports ``ledger_partial``.

    A store that exists but cannot be read (missing role, foreign schema,
    loose permissions, unreadable file) raises instead of falling back to the
    ledger: answering from a source the target left would be a silent lie, and
    a ``preview`` store is reported at the same time — it is a migration
    artifact beside live legacy data, so it never answers a read.
    """
    store = TargetStore(repo_root, target)
    role = target_backend(repo_root, target)
    if role == "legacy":
        return _ledger_truth(store)
    if role == "primary":
        return _store_truth(store)
    return _ledger_truth(store, store_claim=role)
