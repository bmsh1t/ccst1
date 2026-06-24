#!/usr/bin/env python3
"""Helpers for feeding source_intel output into surface ranking."""

from __future__ import annotations

import json
from pathlib import Path


EMPTY_SOURCE_INTEL = {
    "available": False,
    "hypotheses": [],
    "routes": [],
    "graphql_operations": [],
}

_SOURCE_PRIORITY = {
    "auth-bypass": "high",
    "idor": "high",
    "business-logic": "high",
    "graphql": "medium",
    "websocket": "high",
    "oauth": "high",
    "ssrf": "medium",
    "upload": "medium",
    "webhook": "medium",
    "framework-intel": "medium",
    "csrf": "low",
}
_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def load_source_intel_hypotheses(findings_dir: Path) -> dict:
    """Load source_intel hypotheses and routes, if present, for surface ranking."""
    source_dir = findings_dir / "source_intel"
    hypotheses_path = source_dir / "hypotheses.jsonl"
    routes_path = source_dir / "routes.json"

    hypotheses = []
    if hypotheses_path.is_file():
        try:
            for line in hypotheses_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if isinstance(item, dict) and item.get("candidate"):
                    hypotheses.append(item)
        except (OSError, json.JSONDecodeError):
            hypotheses = []

    routes = []
    graphql_operations = []
    if routes_path.is_file():
        try:
            payload = json.loads(routes_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict):
            routes = [
                item for item in payload.get("routes", [])
                if isinstance(item, dict) and item.get("route")
            ]
            graphql_operations = [
                item for item in payload.get("graphql_operations", [])
                if isinstance(item, dict)
            ]

    if not hypotheses and not routes and not graphql_operations:
        return dict(EMPTY_SOURCE_INTEL)

    return {
        "available": True,
        "hypotheses": hypotheses,
        "routes": routes,
        "graphql_operations": graphql_operations,
    }


def _endpoint_to_url(endpoint_path: str, default_host: str) -> str:
    if endpoint_path.startswith(("http://", "https://", "ws://", "wss://")):
        return endpoint_path
    prefix = "" if endpoint_path.startswith("/") else "/"
    if default_host:
        return default_host.rstrip("/") + prefix + endpoint_path
    return prefix + endpoint_path


def build_source_intel_urls(source_intel: dict, default_host: str, known_urls: list[str] | None = None) -> dict[str, list[dict]]:
    """Map source_intel route/hypothesis output to rankable URLs."""
    known_urls = known_urls or []
    urls: dict[str, list[dict]] = {}
    graphql_urls = []

    for route in source_intel.get("routes", []):
        route_value = str(route.get("route", "")).strip()
        if not route_value:
            continue
        url = _endpoint_to_url(route_value, default_host)
        if "graphql" in url.lower():
            graphql_urls.append(url)

    for url in known_urls:
        if "graphql" in str(url).lower():
            graphql_urls.append(str(url))

    dedup_graphql_urls = []
    seen_graphql = set()
    for url in graphql_urls:
        if not url or url in seen_graphql:
            continue
        seen_graphql.add(url)
        dedup_graphql_urls.append(url)

    for hypothesis in source_intel.get("hypotheses", []):
        candidate = str(hypothesis.get("candidate", "")).strip()
        if not candidate:
            continue
        if candidate.startswith(("http://", "https://", "ws://", "wss://")) or candidate.startswith("/"):
            url = _endpoint_to_url(candidate, default_host)
            urls.setdefault(url, []).append(hypothesis)
            continue
        if hypothesis.get("type") == "business-logic":
            for url in dedup_graphql_urls:
                urls.setdefault(url, []).append(hypothesis)

    return urls


def source_intel_counts(source_intel: dict) -> dict:
    """Return compact source_intel counters for formatted surface output."""
    return {
        "hypothesis_count": len(source_intel.get("hypotheses", [])),
        "route_count": len(source_intel.get("routes", [])),
        "graphql_count": len(source_intel.get("graphql_operations", [])),
    }


def build_source_lead_hints(source_intel: dict) -> list[dict]:
    """Return compact actionable source-intel leads for surface/autopilot views."""
    leads = []
    for item in source_intel.get("hypotheses", []):
        candidate = str(item.get("candidate", "") or "").strip()
        vuln_type = str(item.get("type", "") or "other").strip().lower()
        reason = str(item.get("reason", "") or "").strip()
        if not candidate:
            continue
        next_action = reason or f"verify {candidate} with a focused {vuln_type} test"
        leads.append({
            "source": "source_intel",
            "title": candidate,
            "category": vuln_type,
            "priority": _SOURCE_PRIORITY.get(vuln_type, "medium"),
            "next_action": next_action,
            "rationale": reason,
            "evidence": str(item.get("source", "") or "").strip(),
        })

    leads.sort(
        key=lambda item: (
            _PRIORITY_ORDER.get(item["priority"], 3),
            item["category"],
            item["title"],
        )
    )
    return leads[:5]
