#!/usr/bin/env python3
"""Run one bounded, read-only verification pass over Host pivot candidates.

Candidate generation remains evidence-only.  This helper consumes the derived
candidate view, probes only target-owned hosts, and appends compact response
observations.  It never promotes a candidate to a finding or changes scope.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import ssl
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from memory.target_profile import default_memory_dir, load_target_profile  # noqa: E402
from tools.scope_context import ScopeContext, ScopeContextError  # noqa: E402
from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # noqa: E402


SCHEMA_VERSION = 1
DEFAULT_LIMIT = 8
DEFAULT_MAX_PROBES = 24
DEFAULT_TIMEOUT = 5.0
MAX_BODY_BYTES = 4096
VERIFY_SIGNALS = frozenset({"shared-ip", "cname", "subject-cn", "subject-an", "san", "origin-candidate"})
OUTPUT_PATH = Path("exposure/host_collision_observations.jsonl")
SUMMARY_PATH = Path("exposure/host_collision_summary.json")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _host_port(value: object) -> tuple[str, int | None]:
    if not isinstance(value, str) or not value.strip():
        return "", None
    raw = value.strip()
    candidate = raw if "://" in raw or raw.startswith("//") else f"//{raw}"
    try:
        parsed = urlsplit(candidate if "://" in candidate else f"https:{candidate}")
        host = (parsed.hostname or "").strip(".").lower()
        if not host:
            return "", None
        return host, parsed.port
    except (ValueError, UnicodeError):
        return "", None


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def _scope_checker(repo_root: Path, target: str):
    try:
        profile = load_target_profile(default_memory_dir(repo_root), target)
    except ValueError:
        return False
    snapshot = profile.get("scope_snapshot", {}) if isinstance(profile, dict) else {}
    if profile is not None and not isinstance(snapshot, dict):
        return False
    if not isinstance(snapshot, dict):
        snapshot = {}
    try:
        context = ScopeContext(
            root_target=target,
            in_scope=[v for v in snapshot.get("in_scope", []) if isinstance(v, str)],
            out_of_scope=[v for v in snapshot.get("out_of_scope", []) if isinstance(v, str)],
        )
    except ScopeContextError:
        return False
    return context


def _in_scope(host: str, target: str, context) -> bool:
    if not host:
        return False
    if context is False:
        return False
    value = f"https://{host}"
    if context is not None and context.allows_active(value):
        return True
    return url_belongs_to_target(value, target)


def _schemes(recon_dir: Path, hosts: set[str]) -> dict[str, list[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    source = recon_dir / "live" / "httpx_full.txt"
    if source.is_file():
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            token = line.strip().split()[0] if line.strip() else ""
            try:
                parsed = urlsplit(token)
            except ValueError:
                continue
            host = (parsed.hostname or "").strip(".").lower()
            if host in hosts and parsed.scheme.lower() in {"http", "https"}:
                found[host].add(parsed.scheme.lower())
    return {host: sorted(values, key=lambda value: (value != "https", value)) for host, values in found.items()}


def _candidate_key(row: dict) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def select_candidates(rows: list[dict], target: str, context, *, limit: int = DEFAULT_LIMIT) -> list[dict]:
    selected = []
    for row in rows:
        signals = {str(value).lower() for value in row.get("signals", []) if isinstance(value, str)}
        if not signals & VERIFY_SIGNALS:
            continue
        hosts = []
        for value in [row.get("value"), *(row.get("related") or [])]:
            host, port = _host_port(value)
            if not host or not _in_scope(host, target, context):
                continue
            entry = (host, port)
            if entry not in hosts:
                hosts.append(entry)
        if not hosts:
            continue
        selected.append({"row": row, "hosts": sorted(hosts), "score": (len(hosts) > 1, len(signals), _candidate_key(row))})
    selected.sort(key=lambda item: (-int(item["score"][0]), -int(item["score"][1]), str(item["score"][2])))
    return selected[: max(0, limit)]


def _probe(
    host: str,
    *,
    scheme: str,
    port: int | None = None,
    connect_host: str | None = None,
    host_header: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """GET `/` without following redirects or retaining response bodies."""
    target_port = port or (443 if scheme == "https" else 80)
    address = connect_host or host
    sock = None
    try:
        sock = socket.create_connection((address, target_port), timeout=timeout)
        if scheme == "https":
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=host_header or host)
        request_host = host_header or host
        if port and port not in {80, 443}:
            request_host = f"{request_host}:{port}"
        request = (
            f"GET / HTTP/1.1\r\nHost: {request_host}\r\n"
            "User-Agent: ccst-recon-host-verify/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        sock.sendall(request)
        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        body = response.read(MAX_BODY_BYTES + 1)
        return {
            "status": response.status,
            "content_type": response.getheader("Content-Type", ""),
            "location": response.getheader("Location", ""),
            "body_bytes": min(len(body), MAX_BODY_BYTES),
            "body_truncated": len(body) > MAX_BODY_BYTES,
            "body_sha256": hashlib.sha256(body[:MAX_BODY_BYTES]).hexdigest(),
        }
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return {"status": None, "error": type(exc).__name__.lower()}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _fingerprint(result: dict) -> tuple:
    return (
        result.get("status"),
        result.get("content_type", ""),
        result.get("location", ""),
        result.get("body_bytes", 0),
        result.get("body_sha256", ""),
    )


def verify(
    repo_root: str | Path,
    target: str,
    *,
    limit: int = DEFAULT_LIMIT,
    max_probes: int = DEFAULT_MAX_PROBES,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    repo = Path(repo_root).resolve()
    resolved = canonical_target_value(target)
    recon_dir = repo / "recon" / target_storage_key(resolved)
    exposure = recon_dir / "exposure"
    candidate_path = exposure / "host_pivot_candidates.jsonl"
    output_path = recon_dir / OUTPUT_PATH
    summary_path = recon_dir / SUMMARY_PATH
    context = _scope_checker(repo, resolved)
    rows = _read_jsonl(candidate_path)
    selected = select_candidates(rows, resolved, context, limit=limit)
    seen_keys = {
        str(item.get("candidate_key"))
        for item in _read_jsonl(output_path)
        if item.get("candidate_key")
    }
    host_set = {host for item in selected for host, _port in item["hosts"]}
    scheme_map = _schemes(recon_dir, host_set)
    observations = []
    probes = 0
    skipped_existing = 0
    for item in selected:
        row = item["row"]
        key = _candidate_key(row)
        if key in seen_keys:
            skipped_existing += 1
            continue
        results = []
        candidate_hosts = [host for host, _port in item["hosts"] if not _is_ip(host)]
        for host, port in item["hosts"]:
            if probes >= max_probes:
                break
            schemes = scheme_map.get(host) or ["https"]
            scheme = schemes[0]
            request_host = host
            probe_kwargs = {"scheme": scheme, "port": port, "timeout": timeout}
            if _is_ip(host) and candidate_hosts:
                # An explicitly in-scope IP can be used as a connection target
                # while retaining the candidate hostname for Host and SNI.
                request_host = candidate_hosts[0]
                probe_kwargs.update(
                    connect_host=host,
                    host_header=request_host,
                )
            result = _probe(request_host, **probe_kwargs)
            probes += 1
            entry = {"host": request_host, "port": port, "scheme": scheme, "result": result}
            if request_host != host:
                entry.update({"connect_host": host, "host_header": request_host, "sni": request_host})
            results.append(entry)
        if not results:
            continue
        fingerprints = {_fingerprint(entry["result"]) for entry in results}
        statuses = [entry["result"].get("status") for entry in results]
        if all(status is None for status in statuses):
            outcome = "unavailable"
        elif any(status is None for status in statuses):
            outcome = "partial"
        elif len(results) == 1:
            outcome = "host_observed"
        else:
            outcome = "response_difference" if len(fingerprints) > 1 else "no_response_difference"
        observations.append({
            "schema_version": SCHEMA_VERSION,
            "kind": "host-collision-observation",
            "observed_at": _now(),
            "target": resolved,
            "candidate_key": key,
            "signals": sorted(str(value) for value in row.get("signals", []) if isinstance(value, str)),
            "candidate": {"value": row.get("value", ""), "related": row.get("related", [])},
            "request_mode": "hostname-baseline",
            "outcome": outcome,
            "probes": results,
        })
    if observations:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as handle:
            for item in observations:
                handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    counts = defaultdict(int)
    for item in observations:
        counts[item["outcome"]] += 1
    summary = {
        "schema_version": SCHEMA_VERSION,
        "kind": "host-collision-summary",
        "target": resolved,
        "status": "complete" if observations or not selected else "partial",
        "candidate_count": len(rows),
        "selected_count": len(selected),
        "skipped_existing": skipped_existing,
        "observation_count": len(observations),
        "probe_count": probes,
        "outcome_counts": dict(sorted(counts.items())),
        "max_candidates": limit,
        "max_probes": max_probes,
        "artifact": str(OUTPUT_PATH),
        "note": "Observations are read-only response differences; they are not findings or scope expansion.",
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded read-only Host collision verification")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--target", required=True)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--max-probes", type=int, default=DEFAULT_MAX_PROBES)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    if args.limit < 0 or args.max_probes < 0 or args.timeout <= 0:
        parser.error("limit/max-probes must be non-negative and timeout must be positive")
    print(json.dumps(verify(args.repo_root, args.target, limit=args.limit, max_probes=args.max_probes, timeout=args.timeout), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
