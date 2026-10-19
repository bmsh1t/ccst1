#!/usr/bin/env python3
"""Pure operational metrics over the Context Pack's acquired evidence snapshot."""

from __future__ import annotations


def derive_operational_metrics(truth: dict) -> dict:
    """Describe recorded facts, not inferred safety, replay or stopping success."""
    rows = [row for row in truth["records"] if not row.get("superseded")]
    total = len(rows)
    mutations = [row for row in rows if row.get("state_changing") is True]
    complete = sum(
        row.get("evidence_role") in {"subject", "control"}
        and all(str(row.get(field) or "").strip().lower() not in {"", "unknown"}
                for field in ("actor", "object_scope", "result", "evidence_ref"))
        for row in rows
    )
    bound = sum(bool(row.get("evidence_refs")) for row in rows)
    return {
        "schema_version": 1,
        "source": dict(truth["source"]),
        "health": dict(truth["health"]),
        "status": "partial" if truth["source"]["status"] != "ready" else "ready" if total else "empty",
        "scope": "acquired non-superseded observations; truncated input is not a full-target count",
        "evidence_records": total,
        "state_changing_records": len(mutations),
        "state_change_unknown_records": sum(row.get("state_changing") is None for row in rows),
        "unchecked_state_changing_records": sum(row.get("redline_checked") is not True for row in mutations),
        "field_completeness_rate": round(complete / total, 4) if total else None,
        "artifact_reference_rate": round(bound / total, 4) if total else None,
        "unsafe_action_rate": None,
        "replayability_rate": None,
        "stop_compliance_rate": None,
        "unavailable_reason": "No recorded safety outcome, semantic replay result or stop-decision audit in this snapshot.",
    }
