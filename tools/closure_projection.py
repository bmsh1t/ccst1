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
        exact_endpoint_identity,
        observation_supports_coverage,
    )
    from tools.identity_contract import ClosureCellKey
except ImportError:  # pragma: no cover - direct tools/ execution
    from evidence_identity import (  # type: ignore
        CLOSED_LEDGER_RESULTS,
        LEDGER_RESULTS,
        canonical_endpoint_identity,
        exact_endpoint_identity,
        observation_supports_coverage,
    )
    from identity_contract import ClosureCellKey  # type: ignore


def _entry_closure_identity(entry: Mapping[str, Any]) -> ClosureCellKey | None:
    if entry.get("identity_status") != "complete" or entry.get("evidence_role") != "subject":
        return None
    try:
        key = ClosureCellKey.from_dict(entry.get("identity_v2"))
    except (TypeError, ValueError, KeyError):
        return None
    return None if key.schema_version != 3 or identity_fact_conflicts(key, entry) else key


def identity_fact_conflicts(key: ClosureCellKey | None, record: Mapping[str, Any]) -> tuple[str, ...]:
    """Reject an identity key that disagrees with its own recorded facts."""
    if key is None:
        return ()
    conflicts: list[str] = []
    if key.schema_version != 3:
        conflicts.append("legacy_identity_requires_explicit_replacement")
    try:
        endpoint = exact_endpoint_identity(str(record.get("raw_endpoint") or record.get("endpoint") or ""))
    except ValueError:
        endpoint = ""
    if key.endpoint != endpoint:
        conflicts.append("endpoint_mismatch")
    if key.family != str(record.get("vuln_class") or ""):
        conflicts.append("family_mismatch")
    raw = str(record.get("identity_technique") or "").strip().lower().replace("-", "_").replace(" ", "_")
    if "_".join(part for part in raw.split("_") if part) != key.technique:
        conflicts.append("technique_mismatch")
    dimensions = key.dimension_map
    if "identity_dimensions" in record and record["identity_dimensions"] != dimensions:
        conflicts.append("declared_conditions_mismatch")
    if not record.get("method"):
        conflicts.append("method_missing")
    for dimension, fact in (("method", str(record.get("method") or "").upper()),
                            ("actor_relation", record.get("actor")),
                            ("actor_role", record.get("actor")),
                            ("actor", record.get("actor")),
                            ("object_scope", record.get("object_scope"))):
        if dimension in dimensions and fact and dimensions[dimension] != fact:
            conflicts.append(f"{dimension}_mismatch")
    return tuple(sorted(set(conflicts)))


def derive_identity_fields(record: dict) -> dict:
    """Validate recorded identity claims without upgrading legacy evidence."""
    if "identity_status" not in record:
        record["identity_status"] = "incomplete"
        record["identity_missing_fields"] = ["identity_status"]
        return record
    if record.get("identity_status") != "complete":
        return record
    try:
        key = ClosureCellKey.from_dict(record.get("identity_v2"))
    except (TypeError, ValueError, KeyError):
        conflicts = ["unreadable_identity_v2"]
    else:
        conflicts = list(identity_fact_conflicts(key, record))
    if record.get("evidence_role") != "subject":
        conflicts.append("subject_role_required")
    if conflicts:
        record["identity_status"] = "conflict"
        record["identity_conflicts"] = sorted(set(conflicts))
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
    """Project complete current identities; legacy rows cannot authorize closure."""
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
            "event_id": str(entry.get("event_id") or ""),
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
        if not include_identity_rows and str(entry.get("identity_status") or "none") != "none":
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


def suppress_unauthorized_closures(
    projection: dict, *, reason: str, invalid_event_ids: set[str] | None = None,
) -> dict:
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
    # Filter the reduced current result, never the input history: removing a
    # damaged latest observation first would resurrect an older conclusion.
    for field in ("closed_cells", "closed_cells_v2"):
        suppressed[field] = [cell for cell in projection.get(field, [])
                             if invalid_event_ids is not None
                             and cell.get("event_id") not in invalid_event_ids]
    diagnostics = dict(suppressed.get("identity_v2_diagnostics") or {})
    diagnostics["suppressed_closed_count"] = len(projection.get("closed_cells_v2", [])) - len(suppressed["closed_cells_v2"])
    diagnostics["suppressed_legacy_closed_count"] = len(legacy_cells) - len(suppressed["closed_cells"])
    diagnostics["closed_count"] = len(suppressed["closed_cells_v2"])
    suppressed["identity_v2_diagnostics"] = diagnostics
    suppressed["identity_v2_shadow"] = {"status": "unavailable", "reason": reason}
    return suppressed


def build_current_cell_projection(entries: list[dict]) -> dict:
    """Project current evidence identities and retain a v2 closure projection.

    ``closed_cells`` is retained only as an audit projection for old readers;
    ``closed_cells_v2`` is the only projection allowed to close a complete
    family-aware identity.  Legacy records never gain identity authority during reads.  Caller
    records are copied, never edited in place.
    """
    # Registration succession is an owner fact, independent of the replacement's
    # readability or observation count. History never regains authority because
    # its successor has invalid identity or missing evidence.
    entries = [derive_identity_fields(dict(entry)) if isinstance(entry, dict) else entry
               for entry in entries if not isinstance(entry, dict) or not entry.get("superseded")]
    _legacy_cells, open_candidates = _project_legacy_cells(
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
        "closed_cells": [],
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
        "legacy_closed_cells_audit": _legacy_cells,
    }
