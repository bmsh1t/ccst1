"""Shared helpers for canonical target typing and on-disk storage keys."""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse


def canonical_target_value(target: str) -> str:
    """Return the normalized runtime target string used for state lookups."""
    value = (target or "").strip()
    if not value:
        return value

    try:
        return classify_target(value)["target"]
    except ValueError:
        return value


def classify_target(target: str) -> dict:
    """Classify a target as domain, IP, CIDR, or readable host list."""
    value = (target or "").strip()
    if not value:
        return {"kind": "domain", "target": value}

    if os.path.isfile(value):
        return {"kind": "list", "target": os.path.abspath(value)}

    # URL-form targets should share the same state/recon key as the equivalent
    # host or host:port. This keeps `/autopilot http://127.0.0.1:3002` from
    # creating a separate `http:_127...` tree that later tools cannot resume.
    if "://" in value:
        parsed = urlparse(value)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return {"kind": "domain", "target": value}
        try:
            port = parsed.port
        except ValueError:
            port = None
        value = f"{host}:{port}" if port is not None else host

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        network = None
    else:
        if "/" in value:
            return {"kind": "cidr", "target": str(network)}

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    else:
        return {"kind": "ip", "target": str(address)}

    # host:port form — local lab targets like 127.0.0.1:3000 or app.test:8080.
    # Must precede the strict-digits check below, which would otherwise reject
    # all-numeric host:port strings as "invalid IP/CIDR".
    if value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if host and port.isdigit() and 1 <= int(port) <= 65535:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if re.fullmatch(r"[A-Za-z0-9.\-]+", host):
                    return {"kind": "domain", "target": value}
            else:
                return {"kind": "ip", "target": value}

    if re.fullmatch(r"[0-9./:]+", value):
        raise ValueError("invalid IP/CIDR target")

    return {"kind": "domain", "target": value}


def target_storage_key(target: str) -> str:
    """Return the canonical on-disk storage key for a target."""
    target_info = classify_target(target)
    normalized_target = target_info["target"]
    if target_info["kind"] == "list":
        basename = os.path.basename(normalized_target)
        stem = os.path.splitext(basename)[0] or basename.strip(".") or "scope-list"
        return re.sub(r"[^A-Za-z0-9._-]+", "_", stem)
    if target_info["kind"] == "cidr":
        return normalized_target.replace("/", "_")
    return re.sub(r"[^A-Za-z0-9._:-]+", "_", normalized_target).strip("._-") or "unknown-target"


def _host_port(value: str) -> tuple[str, int | None]:
    """Parse a host[:port] or URL-ish value into normalized host/port."""
    candidate = (value or "").strip()
    if not candidate:
        return "", None
    try:
        parsed = urlparse(candidate if "://" in candidate or candidate.startswith("//") else f"//{candidate}")
    except ValueError:
        return candidate.split(":")[0].lower().strip("."), None
    try:
        port = parsed.port
    except ValueError:
        port = None
    return (parsed.hostname or "").lower().strip("."), port


def target_list_entries(path: str) -> list[str]:
    """Return normalized primary domains from a readable batch list."""
    entries = []
    seen = set()
    try:
        lines = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return []
    with lines:
        for raw in lines:
            value = raw.strip().strip("\ufeff").rstrip("/").lower()
            if not value or value.startswith("#"):
                continue
            if value.startswith("*."):
                value = value[2:]
            if value and value not in seen:
                seen.add(value)
                entries.append(value)
    return entries


def url_belongs_to_target(url: str, target: str, *, allow_subdomains: bool = True) -> bool:
    """Return whether a URL should be treated as direct target-owned evidence.

    Discovery may keep third-party URLs as chain context, but direct finding
    queues should use this check before treating an embedded URL as evidence
    for the current target.
    """
    raw_url = (url or "").strip()
    if not raw_url or raw_url.startswith("/"):
        return True

    target_info = classify_target(canonical_target_value(target))
    if target_info["kind"] == "list":
        for listed_target in target_list_entries(target_info["target"]):
            # Primary-domain lists are intentionally one level deep. A line
            # resolving to another local file is not a root target and must
            # not recurse into nested or self-referential lists.
            if classify_target(canonical_target_value(listed_target))["kind"] == "list":
                continue
            if url_belongs_to_target(
                raw_url,
                listed_target,
                allow_subdomains=allow_subdomains,
            ):
                return True
        return False

    url_host, url_port = _host_port(raw_url)
    if not url_host:
        return True

    if target_info["kind"] == "cidr":
        try:
            return ipaddress.ip_address(url_host) in ipaddress.ip_network(target_info["target"], strict=False)
        except ValueError:
            return False

    target_host, target_port = _host_port(target_info["target"])
    if not target_host:
        return True

    host_matches = url_host == target_host
    if allow_subdomains and not host_matches:
        host_matches = url_host.endswith("." + target_host)
    if not host_matches:
        return False
    if target_port is not None and url_port != target_port:
        return False
    return True
