"""Small, bounded budget projections for deep evidence-driven lanes."""

from __future__ import annotations

import math
from typing import Any


def project_budget(
    base: int,
    *,
    minimum: int = 1,
    maximum: int | None = None,
    url_count: int = 0,
    parameter_count: int = 0,
    response_variance: int = 0,
    high_value_evidence: int = 0,
    adaptive: bool = False,
) -> dict[str, Any]:
    """Return a deterministic, bounded budget projection.

    ``adaptive`` is opt-in so normal/legacy calls retain their exact budget.
    Signals are deliberately coarse: the AI still owns hypothesis selection;
    this helper only prevents a broad, high-signal surface from being cut off
    by a small single-call budget.
    """
    try:
        base = int(base)
        minimum = int(minimum)
        maximum = base * 4 if maximum is None else int(maximum)
        signals = {
            "url_count": max(0, int(url_count)),
            "parameter_count": max(0, int(parameter_count)),
            "response_variance": max(0, int(response_variance)),
            "high_value_evidence": max(0, int(high_value_evidence)),
        }
    except (TypeError, ValueError) as exc:
        raise ValueError("budget inputs must be integers") from exc
    if base < 1 or minimum < 1 or maximum < 1:
        raise ValueError("budget bounds must be positive")
    if minimum > maximum:
        raise ValueError("minimum budget cannot exceed maximum budget")
    if base > maximum:
        raise ValueError("base budget cannot exceed maximum budget")

    extra = 0
    reasons: list[str] = []
    if adaptive:
        url_extra = math.ceil(signals["url_count"] / 8)
        parameter_extra = math.ceil(signals["parameter_count"] / 6)
        variance_extra = min(signals["response_variance"], 5) * 2
        evidence_extra = min(signals["high_value_evidence"], 4) * 4
        extra = min(maximum - base, url_extra + parameter_extra + variance_extra + evidence_extra)
        if url_extra:
            reasons.append("broad URL surface")
        if parameter_extra:
            reasons.append("parameter density")
        if variance_extra:
            reasons.append("response variance")
        if evidence_extra:
            reasons.append("high-value evidence")

    budget = max(minimum, min(maximum, base + extra))
    return {
        "budget": budget,
        "base": base,
        "maximum": maximum,
        "adaptive": bool(adaptive),
        "signals": signals,
        "reasons": reasons,
        "partial_on_exhaustion": True,
    }
