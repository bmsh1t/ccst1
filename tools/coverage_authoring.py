"""Pure legacy Coverage draft classification shared by initialization and import."""

from __future__ import annotations

import re

try:
    from tools.target_paths import canonical_target_value
except ImportError:  # direct tools/ execution
    from target_paths import canonical_target_value


STRUCTURAL_NA_MARKERS = {
    "static_asset": "static asset;",
    "public_metadata": "standard/public metadata;",
    "route_prefix": "route prefix/container;",
    "minified_js_property_chain": "minified JS property-chain artifact;",
}


def is_structural_na(cell: dict) -> bool:
    """Only the controlled Coverage writer grants identity-free N/A."""
    marker = STRUCTURAL_NA_MARKERS.get(str(cell.get("structural_code") or ""))
    return bool(
        marker and cell.get("status") == "n_a"
        and cell.get("structural_source") == "coverage:endpoint_kind"
        and cell.get("structural_marker") == marker
        and str(cell.get("reason") or "").startswith(marker)
    )


def coverage_review_drafts(payload: object, target: str) -> dict:
    """Classify author input without Store I/O or inferring execution evidence."""
    if not isinstance(payload, dict) or not isinstance(payload.get("endpoints"), list):
        raise ValueError("coverage matrix must contain an endpoints array")
    if canonical_target_value(payload.get("target", "")) != target:
        raise ValueError("coverage matrix declares another target")
    result = {"projection": False, "endpoints": [], "quarantined": [], "retained_default_cells": 0}
    if any(key in payload for key in ("backend", "store_id", "source_snapshot")):
        snapshot = payload.get("source_snapshot")
        binding = snapshot.get("store") if isinstance(snapshot, dict) else None
        if (payload.get("backend") != "primary" or not isinstance(binding, dict)
                or not isinstance(payload.get("store_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", payload["store_id"])
                or type(payload.get("store_revision")) is not int or payload["store_revision"] < 0
                or any(binding.get(key) != value for key, value in (
                    ("target", target), ("backend", "primary"),
                    ("store_id", payload["store_id"]), ("revision", payload["store_revision"])))):
            raise ValueError("unknown or inconsistent Store Coverage projection")
        result["projection"] = True

    def quarantine(pointer: str, reason: str) -> None:
        result["quarantined"].append({"id": pointer, "reason": reason})

    for index, ep in enumerate(payload["endpoints"]):
        pointer = f"/endpoints/{index}"
        if not isinstance(ep, dict):
            quarantine(pointer, "endpoint row must be an object")
            continue
        drafts = []
        authored_kind = any(ep.get(key) for key in ("kind_source", "kind_reason", "kind_triaged_at"))
        kind = ep.get("endpoint_kind")
        if authored_kind or (kind not in (None, "", "untriaged")
                             and (not isinstance(kind, str) or kind not in STRUCTURAL_NA_MARKERS)):
            drafts.append((pointer, {
                "kind": "endpoint_kind", "value": kind,
                "source": ep.get("kind_source", "legacy_import"), "reason": ep.get("kind_reason", ""),
                "reviewed_at": ep.get("kind_triaged_at", ""),
            }))
        cells = ep.get("cells", {})
        if not isinstance(cells, dict):
            quarantine(pointer + "/cells", "coverage cells must be an object")
            cells = {}
        for family, cell in cells.items():
            cell_pointer = pointer + "/cells/" + str(family).replace("~", "~0").replace("/", "~1")
            if not isinstance(family, str) or not isinstance(cell, dict):
                quarantine(cell_pointer, "coverage cell must have a string family and object value")
                continue
            if (cell.get("status") == "untested" and not cell.get("reason")) or is_structural_na(cell):
                result["retained_default_cells"] += 1
                continue
            drafts.append((cell_pointer, {"kind": "cell_status", "family": family,
                           "value": cell.get("status"), "reason": cell.get("reason", ""),
                           "source": "legacy_import"}))
        result["endpoints"].append({"pointer": pointer, "endpoint": ep.get("endpoint"), "drafts": drafts})
    return result
