#!/usr/bin/env python3
"""Helpers for feeding source_intel output into the surface review pack."""

from __future__ import annotations

import json
from pathlib import Path

try:
    from tools.target_paths import resolve_target_url
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import resolve_target_url  # type: ignore


EMPTY_SOURCE_INTEL = {
    "available": False,
    "signals": [],
    "routes": [],
    "graphql_operations": [],
}


def load_source_intel(findings_dir: Path) -> dict:
    """Read source observations; old generated prose never controls selection."""
    source_dir = findings_dir / "source_intel"
    routes_path = source_dir / "routes.json"
    try:
        payload = json.loads(routes_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    routes = [item for item in payload.get("routes", []) if isinstance(item, dict) and item.get("route")]
    # Recover exact route facts from legacy caches, not their predicted classes.
    if not routes_path.is_file():
        legacy_path = source_dir / "hypotheses.jsonl"
        try:
            for line in legacy_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                candidate = str(item.get("candidate") or "") if isinstance(item, dict) else ""
                if candidate.startswith(("/", "http://", "https://", "ws://", "wss://")):
                    routes.append({"route": candidate, "method": str(item.get("method") or ""), "source": str(legacy_path)})
        except (OSError, json.JSONDecodeError):
            pass
    operations = [item for item in payload.get("graphql_operations", []) if isinstance(item, dict)]
    signals = [item for item in payload.get("signals", []) if isinstance(item, dict)]
    return {
        "available": bool(routes or operations or signals),
        "routes": routes,
        "graphql_operations": operations,
        "signals": signals,
    }


def _endpoint_to_url(endpoint_path: str, default_host: str) -> str:
    return resolve_target_url(endpoint_path, default_host)


def build_source_intel_urls(source_intel: dict, default_host: str) -> dict[str, list[dict]]:
    """Make every extracted route discoverable without a class/keyword gate."""
    urls: dict[str, list[dict]] = {}
    for route in source_intel.get("routes", []):
        if not isinstance(route, dict):
            continue
        value = str(route.get("route") or "").strip()
        if not value.startswith(("/", "http://", "https://", "ws://", "wss://")):
            continue
        url = _endpoint_to_url(value, default_host)
        if url:
            urls.setdefault(url, []).append(route)
    return urls


def source_intel_counts(source_intel: dict) -> dict:
    """Return compact source_intel counters for formatted surface output."""
    return {
        "signal_count": len(source_intel.get("signals", [])),
        "route_count": len(source_intel.get("routes", [])),
        "graphql_count": len(source_intel.get("graphql_operations", [])),
    }


