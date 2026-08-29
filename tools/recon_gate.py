#!/usr/bin/env python3
"""Build the small, evidence-aware gate stored in the Recon manifest."""

from __future__ import annotations

import glob
from pathlib import Path


_PARTIAL_STATUSES = frozenset({"partial", "error", "failed", "failure", "incomplete"})
_BLOCKED_STATUSES = frozenset({"blocked", "skipped", "unavailable", "not_run"})
_COMPLETE_STATUSES = frozenset({"ok", "success", "success_zero", "success-zero", "completed"})


def _bounded_metadata(note: str) -> dict:
    """Parse compact bounded-sampling fields from the manifest note."""
    values: dict[str, object] = {}
    for part in str(note or "").split(";"):
        key, separator, raw = part.strip().partition("=")
        if not separator or key not in {"input_total", "selected", "remaining", "continuation", "closure_blocking"}:
            continue
        raw = raw.strip()
        if key in {"input_total", "selected", "remaining"}:
            try:
                values[key] = max(0, int(raw))
            except ValueError:
                continue
        elif key == "closure_blocking":
            values[key] = raw.lower() in {"1", "true", "yes", "on"}
        else:
            values[key] = raw
    if not {"input_total", "selected", "remaining"}.issubset(values):
        return {}
    values.setdefault("continuation", "")
    values.setdefault("closure_blocking", int(values["remaining"]) > 0)
    return values


def artifact_exists(repo_root: str | Path, artifact: str) -> bool:
    """Return whether a manifest artifact reference currently resolves.

    Zero-byte result files are valid evidence for successful zero-result phases;
    wildcard references are valid when at least one matching path exists.
    """
    reference = str(artifact or "").strip()
    if not reference:
        return False
    path = Path(reference)
    if path.is_absolute():
        return False
    root = Path(repo_root)
    if any(char in reference for char in "*?["):
        return any(Path(item).exists() for item in glob.glob(str(root / reference)))
    return (root / path).exists()


def artifact_binding(repo_root: str | Path, artifact: str) -> dict:
    """Return a small generation binding for one concrete artifact."""
    reference = str(artifact or "").strip()
    if not reference or any(char in reference for char in "*?["):
        return {}
    path = Path(reference)
    if path.is_absolute():
        return {}
    try:
        stat = (Path(repo_root) / path).stat()
    except OSError:
        return {}
    return {
        "st_dev": stat.st_dev,
        "st_ino": stat.st_ino,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def build_phase_gate(
    repo_root: str | Path,
    *,
    phase: str,
    status: str,
    artifact: str,
    bounded: dict | None = None,
) -> dict:
    """Map execution status to the bounded phase-gate contract."""
    normalized_status = str(status or "").strip().lower()
    has_artifact = artifact_exists(repo_root, artifact)
    if normalized_status in _BLOCKED_STATUSES:
        gate_status = "blocked"
    elif normalized_status in _PARTIAL_STATUSES or not has_artifact:
        gate_status = "partial"
    elif normalized_status in _COMPLETE_STATUSES:
        gate_status = "complete"
    else:
        gate_status = "partial"

    evidence_refs = [str(artifact).strip()] if has_artifact and str(artifact).strip() else []
    coverage_gaps: list[str] = []
    if not has_artifact:
        coverage_gaps.append(f"missing_artifact:{str(artifact or '').strip() or phase}")
    if normalized_status not in _COMPLETE_STATUSES:
        coverage_gaps.append(f"phase_status:{normalized_status or 'unknown'}")

    if gate_status == "complete":
        next_focus = "Review the referenced evidence and choose the next highest-information uncovered action."
    elif gate_status == "blocked":
        next_focus = f"Resolve or explicitly defer the {phase} gap before declaring it complete."
    else:
        next_focus = f"Resume or repair the incomplete {phase} phase from its preserved evidence."

    gate = {
        "status": gate_status,
        "evidence_refs": evidence_refs,
        "coverage_gaps": coverage_gaps,
        "next_focus": next_focus,
    }
    binding = artifact_binding(repo_root, artifact)
    if binding:
        gate["artifact_binding"] = binding
    if isinstance(bounded, dict) and bounded:
        gate["bounded"] = {
            "input_total": int(bounded.get("input_total", 0) or 0),
            "selected": int(bounded.get("selected", 0) or 0),
            "remaining": int(bounded.get("remaining", 0) or 0),
            "continuation": str(bounded.get("continuation") or ""),
            "closure_blocking": bool(bounded.get("closure_blocking")),
        }
        if gate["bounded"]["remaining"] > 0:
            coverage_gaps.append(f"remaining_input:{gate['bounded']['remaining']}")
    return gate


def gate_from_record(repo_root: str | Path, record: dict) -> dict:
    """Rebuild the gate from current status and artifact ownership.

    Persisted gates are historical hints only: artifacts can disappear or be
    replaced after a manifest row was written, so trusting the embedded value
    could turn an incomplete phase into a false completion.
    """
    gate = build_phase_gate(
        repo_root,
        phase=str(record.get("phase") or "unknown"),
        status=str(record.get("status") or "unknown"),
        artifact=str(record.get("artifact") or ""),
        bounded=_bounded_metadata(str(record.get("note") or "")),
    )
    persisted = record.get("gate") if isinstance(record.get("gate"), dict) else {}
    persisted_binding = persisted.get("artifact_binding")
    current_binding = gate.get("artifact_binding")
    if persisted_binding and persisted_binding != current_binding:
        gate["status"] = "partial"
        gaps = list(gate.get("coverage_gaps") or [])
        if "artifact_changed_since_record" not in gaps:
            gaps.append("artifact_changed_since_record")
        gate["coverage_gaps"] = gaps
        gate["next_focus"] = "Reconcile the changed artifact generation before declaring this phase complete."
    return gate
