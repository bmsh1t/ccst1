#!/usr/bin/env python3
"""Single closure-cell projection over canonical evidence records.

Both producers feed this module: the legacy evidence ledger (file-side entries)
and the per-target store (durable observations).  Coverage and Closure consume
its result, so "what closes a cell" is defined once — here — instead of being
re-derived by each consumer.
"""

from __future__ import annotations

from typing import Any, Mapping

try:
    from tools.evidence_identity import (
        CLOSED_LEDGER_RESULTS,
        LEDGER_RESULTS,
        canonical_endpoint_identity,
        observation_supports_coverage,
    )
    from tools.identity_contract import ClosureCellKey, build_closure_cell
except ImportError:  # pragma: no cover - direct tools/ execution
    from evidence_identity import (  # type: ignore
        CLOSED_LEDGER_RESULTS,
        LEDGER_RESULTS,
        canonical_endpoint_identity,
        observation_supports_coverage,
    )
    from identity_contract import ClosureCellKey, build_closure_cell  # type: ignore


def _entry_closure_identity(entry: Mapping[str, Any]) -> ClosureCellKey | None:
    if str(entry.get("identity_status") or "") != "complete":
        return None
    payload = entry.get("identity_v2")
    if not isinstance(payload, Mapping):
        return None
    try:
        return ClosureCellKey.from_dict(payload)
    except (TypeError, ValueError, KeyError):
        return None


def identity_fact_conflicts(key: ClosureCellKey | None, record: Mapping[str, Any]) -> tuple[str, ...]:
    """Reject a planned identity key that disagrees with the record's own facts."""
    if key is None:
        return ()
    conflicts: list[str] = []
    if str(record.get("endpoint") or "") and key.endpoint != str(record.get("endpoint") or ""):
        conflicts.append("endpoint_mismatch")
    if str(record.get("vuln_class") or "") and key.family != str(record.get("vuln_class") or ""):
        conflicts.append("family_mismatch")
    dimensions = key.dimension_map
    method = str(record.get("method") or "").upper()
    if "method" in dimensions and method and dimensions["method"] != method:
        conflicts.append("method_mismatch")
    return tuple(sorted(set(conflicts)))


def derive_identity_fields(record: dict) -> dict:
    """Derive identity_status/identity_v2 for a record that carries raw dimensions.

    Producers that persist their own identity status (the legacy Ledger writer)
    are left untouched: the derivation only fills records that carry
    ``identity_dimensions``/``identity_v2`` without a stored status, so the store
    can stay a fact store and this module stays the single derivation.
    """
    if "identity_status" in record:
        return record
    payload = record.get("identity_v2")
    if isinstance(payload, Mapping):
        try:
            key = ClosureCellKey.from_dict(payload)
        except (TypeError, ValueError, KeyError):
            record["identity_status"] = "conflict"
            record["identity_conflicts"] = ["unreadable_identity_v2"]
            return record
        conflicts = identity_fact_conflicts(key, record)
        record["identity_status"] = "conflict" if conflicts else "complete"
        record["identity_missing_fields"] = []
        record["identity_conflicts"] = list(conflicts)
        if not conflicts:
            record["identity_v2"] = key.to_dict()
        return record
    dimensions = record.get("identity_dimensions")
    if not isinstance(dimensions, Mapping) or not dimensions:
        # No dimensions means no identity claim: the record stays legacy-style
        # and may author the endpoint-level cell the old view closed.
        return record
    result = build_closure_cell(str(record.get("endpoint") or ""), str(record.get("vuln_class") or ""), dimensions)
    conflicts = tuple(sorted(set((*result.conflicts, *identity_fact_conflicts(result.key, record)))))
    record["identity_status"] = (
        "complete"
        if result.complete and not conflicts
        else "conflict"
        if conflicts
        else "incomplete"
    )
    record["identity_missing_fields"] = list(result.missing_fields)
    record["identity_conflicts"] = list(conflicts)
    if result.key is not None and not conflicts:
        record["identity_v2"] = result.key.to_dict()
    return record


def _replaced_identity_event_ids(entries: list[dict]) -> set[str]:
    return {
        str(replacement.get("event_id") or "")
        for entry in entries
        for replacement in [entry.get("identity_replacement")]
        if str(entry.get("identity_status") or "") == "complete"
        and isinstance(replacement, Mapping)
        and str(replacement.get("event_id") or "")
    }


def _project_v2_cells(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """Project only complete v2 identities; legacy rows never enter this view."""
    replaced_event_ids = _replaced_identity_event_ids(entries)
    current: dict[str, tuple[int, ClosureCellKey, dict]] = {}
    for sequence, entry in enumerate(entries):
        if str(entry.get("event_id") or "") in replaced_event_ids:
            continue
        key = _entry_closure_identity(entry)
        if key is None or str(entry.get("result") or "") not in LEDGER_RESULTS:
            continue
        current[key.identity_key] = (sequence, key, entry)

    closed: list[dict] = []
    open_candidates: list[dict] = []
    for _identity_key, (_sequence, key, entry) in current.items():
        result = str(entry.get("result") or "")
        if result == "candidate":
            open_candidates.append(entry)
        if result in {"lead", "signal", "candidate"}:
            continue
        if result not in CLOSED_LEDGER_RESULTS:
            continue
        if not observation_supports_coverage(entry):
            continue
        closed.append({
            "identity_v2": key.to_dict(),
            "endpoint": key.endpoint,
            "vuln_class": key.family,
            "dimensions": key.dimension_map,
            "result": result,
            "ts": str(entry.get("ts") or ""),
            "evidence_ref": str(entry.get("evidence_ref") or ""),
        })
    return closed, sorted(
        open_candidates,
        key=lambda item: str(item.get("ts") or ""),
        reverse=True,
    )[:10]


def _project_identity_follow_ups(entries: list[dict], replaced_event_ids: set[str]) -> list[dict]:
    rows = [
        entry
        for entry in entries
        if str(entry.get("identity_status") or "") in {"conflict", "follow_up_required"}
        and isinstance(entry.get("identity_follow_up_action"), Mapping)
        and str(entry.get("event_id") or "") not in replaced_event_ids
    ]
    return [
        {
            **dict(entry["identity_follow_up_action"]),
            "ts": str(entry.get("ts") or ""),
            "event_id": str(entry.get("event_id") or ""),
        }
        for entry in sorted(rows, key=lambda item: str(item.get("ts") or ""), reverse=True)[:10]
    ]


def _identity_shadow_diff(closed_cells: list[dict], closed_cells_v2: list[dict]) -> dict[str, Any]:
    legacy_keys = {
        (str(cell.get("endpoint") or ""), str(cell.get("vuln_class") or ""))
        for cell in closed_cells
    }
    v2_keys = {
        (str(cell.get("endpoint") or ""), str(cell.get("vuln_class") or ""))
        for cell in closed_cells_v2
    }
    legacy_only = [
        {"endpoint": endpoint, "vuln_class": family}
        for endpoint, family in sorted(legacy_keys - v2_keys)
    ]
    v2_only = [
        cell
        for cell in closed_cells_v2
        if (str(cell.get("endpoint") or ""), str(cell.get("vuln_class") or ""))
        in v2_keys - legacy_keys
    ]
    scope_mismatches = [
        {
            "endpoint": endpoint,
            "vuln_class": family,
            "legacy_scope": "endpoint_family",
            "v2_cells": [
                cell["identity_v2"]
                for cell in closed_cells_v2
                if str(cell.get("endpoint") or "") == endpoint
                and str(cell.get("vuln_class") or "") == family
            ],
        }
        for endpoint, family in sorted(legacy_keys & v2_keys)
    ]
    return {
        "status": "compared",
        "different": bool(legacy_only or v2_only or scope_mismatches),
        "legacy_closed_count": len(closed_cells),
        "v2_closed_count": len(closed_cells_v2),
        "legacy_only": legacy_only,
        "v2_only": v2_only,
        "scope_mismatches": scope_mismatches,
    }


def _project_legacy_cells(
    entries: list[dict],
    *,
    include_identity_rows: bool,
) -> tuple[list[dict], list[dict]]:
    current_by_evidence_key: dict[tuple[str, str, str, str, str, str], tuple[int, dict]] = {}
    for sequence, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        if not include_identity_rows and "identity_status" in entry:
            continue
        result = str(entry.get("result") or "")
        if result not in LEDGER_RESULTS:
            continue
        endpoint = canonical_endpoint_identity(
            str(entry.get("raw_endpoint") or entry.get("endpoint") or "")
        )
        vuln_class = str(entry.get("vuln_class") or "").strip()
        if not endpoint or not vuln_class:
            continue
        evidence_key = (
            endpoint,
            vuln_class,
            str(entry.get("method") or "GET").strip().upper(),
            str(entry.get("actor") or "owner").strip(),
            str(entry.get("object_scope") or "unknown").strip(),
            str(entry.get("variant") or "baseline").strip(),
        )
        current_by_evidence_key[evidence_key] = (sequence, entry)

    current_by_closure_key: dict[tuple[str, str], list[tuple[int, dict]]] = {}
    for evidence_key, current in current_by_evidence_key.items():
        current_by_closure_key.setdefault(evidence_key[:2], []).append(current)

    closed_cells: list[dict] = []
    open_candidates: list[dict] = []
    for (endpoint, vuln_class), current_rows in current_by_closure_key.items():
        open_rows = [
            item for item in current_rows
            if str(item[1].get("result") or "") in {"lead", "signal", "candidate"}
        ]
        open_candidates.extend(
            entry for _sequence, entry in open_rows
            if str(entry.get("result") or "") == "candidate"
        )
        if open_rows or any(not observation_supports_coverage(entry) for _, entry in current_rows):
            continue
        terminal_rows = [
            item for item in current_rows
            if str(item[1].get("result") or "") in CLOSED_LEDGER_RESULTS
        ]
        if not terminal_rows:
            continue
        _sequence, latest = max(terminal_rows, key=lambda item: item[0])
        closed_cells.append({
            "endpoint": endpoint,
            "vuln_class": vuln_class,
            "result": str(latest.get("result") or ""),
            "ts": str(latest.get("ts") or ""),
            "evidence_ref": str(latest.get("evidence_ref") or ""),
        })
    return closed_cells, open_candidates


def suppress_unauthorized_closures(projection: dict, *, reason: str) -> dict:
    """Empty closure authorizations that damaged input cannot support.

    Evidence that cannot be read in full must not authorize a closure, so
    ``closed_cells``/``closed_cells_v2`` are emptied while the counts stay
    visible: ``suppressed_closed_count`` keeps its established meaning (complete
    v2 identities) and ``suppressed_legacy_closed_count`` counts the
    endpoint×family cells that were emptied.  The rows themselves stay
    readable — damage suppresses authorizations, not facts.  This lives beside
    the projection definition so every source applies the same rule once.
    """
    legacy_cells = list(projection.get("closed_cells") or [])
    suppressed = dict(projection)
    suppressed["closed_cells"] = []
    suppressed["closed_cells_v2"] = []
    diagnostics = dict(suppressed.get("identity_v2_diagnostics") or {})
    diagnostics["suppressed_closed_count"] = int(diagnostics.get("closed_count", 0) or 0)
    diagnostics["suppressed_legacy_closed_count"] = len(legacy_cells)
    diagnostics["closed_count"] = 0
    suppressed["identity_v2_diagnostics"] = diagnostics
    suppressed["identity_v2_shadow"] = {"status": "unavailable", "reason": reason}
    return suppressed


def build_current_cell_projection(entries: list[dict]) -> dict:
    """Project current evidence identities and retain a v2 closure projection.

    ``closed_cells`` remains the legacy endpoint projection for old readers.
    ``closed_cells_v2`` is the only projection allowed to close a complete
    family-aware identity.  Records that carry raw ``identity_dimensions`` but
    no stored status are derived here, so producers only supply facts.  Caller
    records are copied, never edited in place.
    """
    entries = [derive_identity_fields(dict(entry)) if isinstance(entry, dict) else entry for entry in entries]
    closed_cells, open_candidates = _project_legacy_cells(
        entries,
        include_identity_rows=False,
    )
    shadow_legacy_cells, _shadow_candidates = _project_legacy_cells(
        entries,
        include_identity_rows=True,
    )
    closed_cells_v2, open_candidates_v2 = _project_v2_cells(entries)
    replaced_event_ids = _replaced_identity_event_ids(entries)
    identity_v2_incomplete = sum(
        1
        for entry in entries
        if str(entry.get("identity_status") or "") in {"incomplete", "follow_up_required", "conflict"}
        and str(entry.get("event_id") or "") not in replaced_event_ids
    )
    identity_v2_follow_ups = _project_identity_follow_ups(entries, replaced_event_ids)
    return {
        "closed_cells": closed_cells,
        "closed_cells_v2": closed_cells_v2,
        "open_candidates": sorted(
            open_candidates,
            key=lambda item: str(item.get("ts") or ""),
            reverse=True,
        )[:10],
        "open_candidates_v2": open_candidates_v2,
        "identity_v2_follow_up_actions": identity_v2_follow_ups,
        "identity_v2_diagnostics": {
            "incomplete_count": identity_v2_incomplete,
            "closed_count": len(closed_cells_v2),
            "follow_up_count": len(identity_v2_follow_ups),
            "replacement_count": len(replaced_event_ids),
        },
        "identity_v2_shadow": _identity_shadow_diff(shadow_legacy_cells, closed_cells_v2),
    }
