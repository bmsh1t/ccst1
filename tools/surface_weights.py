#!/usr/bin/env python3
"""
surface_weights.py — value-class weight table for surface ranking.

Purpose:
    Power-law payout distribution in bug bounty means ~80% of paid bugs
    live on ~20% of attack surface. This module captures that 20% as
    URL path patterns, and returns a multiplier used by surface.py to
    amplify the additive score for high-value paths.

Design notes:
    - This is a soft bias, not a hard filter. Low-weight paths still
      get scored and ranked; they simply rank lower vs. high-weight peers.
    - Weights multiply. A path matching N patterns gets product of N
      multipliers, capped at MAX_WEIGHT.
    - Patterns are matched case-insensitively against the full URL path
      (path + query, as surface.py passes it).
    - Adding/removing a pattern requires only a row edit. Keep the table
      short and high-signal.
"""

from __future__ import annotations

import re

MAX_WEIGHT = 10.0

# Each entry: (compiled_pattern, multiplier, short_label)
# Order is informational only; matching is independent per row.
_WEIGHT_TABLE: list[tuple[re.Pattern, float, str]] = [
    # admin / internal context — payout ×10 historically
    (re.compile(r"/(?:admin|internal|staff|console|backoffice)\b", re.I), 5.0, "admin"),
    # billing / payment / payout — direct financial impact
    (re.compile(r"/(?:billing|payment|payout|invoice|charge|refund|subscription)\b", re.I), 5.0, "billing"),
    # auth flows — ATO surface
    (re.compile(r"/(?:oauth|saml|sso|token|session)\b", re.I), 4.0, "auth"),
    # /auth path itself but NOT /author or /authorize-as-prefix-only matches
    (re.compile(r"/auth(?:[/?]|$)", re.I), 4.0, "auth"),
    # webhook / callback — server-side fetch / SSRF temptation
    (re.compile(r"/(?:webhook|callback|integration|hook)\b", re.I), 4.0, "webhook"),
    # file handling — upload / download / render
    (re.compile(r"/(?:upload|import|export|download|attachment|render|preview)\b", re.I), 3.5, "file"),
    # multi-tenant boundaries
    (re.compile(r"/(?:tenant|org|organization|workspace|customer|account)s?/", re.I), 3.0, "tenant"),
    # GraphQL surface
    (re.compile(r"/graphql\b", re.I), 2.5, "graphql"),
    # versioned API surface (authenticated APIs concentrate here)
    (re.compile(r"/api/v\d+/", re.I), 2.0, "api_v"),
    # low-value paths — actively de-prioritize
    # Bare numeric SPA/page routes are often crawl artifacts. Resource-scoped
    # IDs such as /orders/123 keep their normal value through other patterns.
    (re.compile(r"^/\d{1,8}/?$", re.I), 0.2, "bare-numeric"),
    (re.compile(r"/(?:blog|marketing|landing|press|legal|static)(?:/|$)", re.I), 0.2, "low"),
    (re.compile(r"/docs(?!/api)", re.I), 0.3, "docs"),
]


def value_weight(path: str) -> float:
    """Return the value-class weight multiplier for a URL path.

    Weight is the product of all matching pattern multipliers, capped at
    MAX_WEIGHT. Returns 1.0 when nothing matches (i.e. no opinion).

    Args:
        path: URL path, optionally with query string. Examples:
            "/api/v2/admin/billing"     -> 5.0 * 5.0 * 2.0 = 50, capped 10.0
            "/blog/post-1"              -> 0.2
            "/api/v3/orders/123"        -> 2.0
            "/"                         -> 1.0
            "/admin/users"              -> 5.0

    Returns:
        Multiplier in [0.0, MAX_WEIGHT]. 1.0 means "no opinion".
    """
    if not path:
        return 1.0
    weight = 1.0
    for pattern, multiplier, _label in _WEIGHT_TABLE:
        if pattern.search(path):
            weight *= multiplier
    if weight > MAX_WEIGHT:
        return MAX_WEIGHT
    return weight


def weight_label(path: str) -> str:
    """Return a short, human-readable description of which value classes hit.

    Used for score_breakdown display. Returns empty string when no class
    matches (caller should not record a breakdown entry in that case).
    """
    if not path:
        return ""
    labels: list[str] = []
    for pattern, _multiplier, label in _WEIGHT_TABLE:
        if pattern.search(path) and label not in labels:
            labels.append(label)
    if not labels:
        return ""
    return "value-class: " + "+".join(labels)


__all__ = ["value_weight", "weight_label", "MAX_WEIGHT"]
