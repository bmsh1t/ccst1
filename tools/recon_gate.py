#!/usr/bin/env python3
"""Build the small, evidence-aware gate stored in the Recon manifest."""

from __future__ import annotations

import glob
from pathlib import Path


_PARTIAL_STATUSES = frozenset({"partial", "error", "failed", "failure", "incomplete"})
_BLOCKED_STATUSES = frozenset({"blocked", "skipped", "unavailable", "not_run"})
_COMPLETE_STATUSES = frozenset({"ok", "success", "success_zero", "success-zero", "completed"})


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


def build_phase_gate(
    repo_root: str | Path,
    *,
    phase: str,
    status: str,
    artifact: str,
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

    return {
        "status": gate_status,
        "evidence_refs": evidence_refs,
        "coverage_gaps": coverage_gaps,
        "next_focus": next_focus,
    }


def gate_from_record(repo_root: str | Path, record: dict) -> dict:
    """Rebuild the gate from current status and artifact ownership.

    Persisted gates are historical hints only: artifacts can disappear or be
    replaced after a manifest row was written, so trusting the embedded value
    could turn an incomplete phase into a false completion.
    """
    return build_phase_gate(
        repo_root,
        phase=str(record.get("phase") or "unknown"),
        status=str(record.get("status") or "unknown"),
        artifact=str(record.get("artifact") or ""),
    )
