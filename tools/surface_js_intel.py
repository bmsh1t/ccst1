#!/usr/bin/env python3
"""Helpers for feeding js-reader output into the surface review pack."""

from __future__ import annotations

import json
from pathlib import Path


EMPTY_JS_INTEL = {
    "available": False,
    "endpoints": [],
    "leads": [],
    "graphql_operations": [],
}

_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def load_js_intel_hypotheses(findings_dir: Path) -> dict:
    """Load js-reader hypotheses, if present, for surface review."""
    hypotheses_path = findings_dir / "js_intel" / "hypotheses.json"
    if not hypotheses_path.is_file():
        return dict(EMPTY_JS_INTEL)

    try:
        payload = json.loads(hypotheses_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return dict(EMPTY_JS_INTEL)
    if not isinstance(payload, dict):
        return dict(EMPTY_JS_INTEL)

    endpoints = [
        item for item in payload.get("endpoints", [])
        if isinstance(item, dict) and item.get("path")
    ]
    leads = payload.get("attack_surface_leads", payload.get("ranked_leads", []))
    leads = [item for item in leads if isinstance(item, dict)]
    graphql_ops = [
        item for item in payload.get("graphql_operations", [])
        if isinstance(item, dict)
    ]

    return {
        "available": True,
        "endpoints": endpoints,
        "leads": leads,
        "graphql_operations": graphql_ops,
    }


def _endpoint_to_url(endpoint_path: str, default_host: str) -> str:
    if endpoint_path.startswith(("http://", "https://", "ws://", "wss://")):
        return endpoint_path
    prefix = "" if endpoint_path.startswith("/") else "/"
    if default_host:
        return default_host.rstrip("/") + prefix + endpoint_path
    return prefix + endpoint_path


def build_js_intel_urls(js_intel: dict, default_host: str) -> dict[str, list[dict]]:
    """Map js-reader endpoint hypotheses to rankable URLs."""
    urls: dict[str, list[dict]] = {}
    for endpoint in js_intel.get("endpoints", []):
        endpoint_path = str(endpoint.get("path", "")).strip()
        if not endpoint_path:
            continue
        urls.setdefault(_endpoint_to_url(endpoint_path, default_host), []).append(endpoint)
    return urls


def js_intel_counts(js_intel: dict) -> dict:
    """Return compact js-reader counters for formatted surface output."""
    return {
        "endpoint_count": len(js_intel.get("endpoints", [])),
        "lead_count": len(js_intel.get("leads", [])),
        "graphql_count": len(js_intel.get("graphql_operations", [])),
    }


def build_js_lead_hints(js_intel: dict) -> list[dict]:
    """Return compact actionable JS-reader workflow leads for surface/autopilot views."""
    leads = []
    for item in js_intel.get("leads", []):
        title = str(item.get("title", "") or "").strip()
        next_action = str(item.get("next_action", "") or "").strip()
        if not title or not next_action:
            continue
        leads.append({
            "source": "js_intel",
            "title": title,
            "category": str(item.get("category", "") or "other").strip().lower(),
            "priority": str(item.get("priority", "") or "medium").strip().lower(),
            "next_action": next_action,
            "rationale": str(item.get("rationale", "") or "").strip(),
            "evidence": str(item.get("evidence", "") or "").strip(),
        })

    leads.sort(
        key=lambda item: (
            _PRIORITY_ORDER.get(item["priority"], 3),
            item["category"],
            item["title"],
        )
    )
    return leads[:5]
