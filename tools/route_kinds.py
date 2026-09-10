#!/usr/bin/env python3
"""Route-kind observation layer: classify endpoints by live response facts.

This module records WHAT A GET RETURNED, never what to test. The output is a
per-endpoint observation label (route_kind) plus the raw facts behind it:

    client_route   GET returned the SPA fallback shell (same body as `/`)
    json_api       GET 2xx with a JSON content type
    auth_gate      GET 401/403 (auth boundary held for anonymous GET)
    http_redirect  GET 3xx with a Location header
    http_error     GET 5xx
    static_asset   GET 2xx with a static content type (css/js/img/font/pdf)
    html_page      GET 2xx text/html distinct from the SPA shell
    unknown        no probe result available (missing/erroring probe)

Priority order when several sources observed the same endpoint:
browser/XHR observation > scanner probe > this layer's own GET probe.
Nothing here excludes an endpoint from any queue; consumers attach
route_kind as evidence so the AI sees the fact (e.g. a client_route with
POST untested) and decides.

Observations are idempotent and append-only per target: re-running merges
new probes, keeps prior browser-backed facts, and records probe time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import urllib.request
from pathlib import Path

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key  # type: ignore

SCHEMA_VERSION = 1
DEFAULT_TIMEOUT = 8.0
BODY_CAP = 262144  # cap the bytes hashed/kept per probe
SPA_SHELL_RATIO = 0.98

STATIC_CONTENT_RE = re.compile(
    r"\b(?:text/css|javascript|image/|font/|application/(?:pdf|octet-stream|x-font))",
    re.I,
)
JSON_CONTENT_RE = re.compile(r"\b(?:json|graphql)", re.I)


def _get(url: str, timeout: float) -> dict:
    """One bounded GET; return raw facts, never a judgment."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 route-kind-probe", "Accept": "*/*"},
        method="GET",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(BODY_CAP)
            return {
                "status": int(response.status),
                "content_type": str(response.headers.get("Content-Type", "")),
                "location": str(response.headers.get("Location", "")),
                "body_length": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "probe_seconds": round(time.time() - started, 3),
                "probe_error": "",
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(BODY_CAP)
        except Exception:
            body = b""
        return {
            "status": int(exc.code),
            "content_type": str(exc.headers.get("Content-Type", "")) if exc.headers else "",
            "location": str(exc.headers.get("Location", "")) if exc.headers else "",
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "probe_seconds": round(time.time() - started, 3),
            "probe_error": "",
        }
    except Exception as exc:  # network failure: record, do not guess
        return {
            "status": 0,
            "content_type": "",
            "location": "",
            "body_length": 0,
            "body_sha256": "",
            "probe_seconds": round(time.time() - started, 3),
            "probe_error": str(exc)[:200],
        }


def _spa_shell_facts(timeout: float, scheme_host: str) -> dict:
    """Probe `/` once to learn the SPA fallback shell signature."""
    return _get(f"{scheme_host}/", timeout)


def classify_route_kind(probe: dict, shell: dict) -> str:
    """Map raw probe facts to one observation label. Pure function."""
    status = int(probe.get("status") or 0)
    if status == 0:
        return "unknown"
    if status in (401, 403):
        return "auth_gate"
    if status >= 500:
        return "http_error"
    if 300 <= status < 400:
        return "http_redirect"
    if status < 300:
        body_sha = str(probe.get("body_sha256") or "")
        shell_sha = str(shell.get("body_sha256") or "")
        if body_sha and shell_sha and body_sha == shell_sha:
            return "client_route"
        shell_len = int(shell.get("body_length") or 0)
        probe_len = int(probe.get("body_length") or 0)
        if (
            body_sha
            and shell_len
            and probe_len
            and min(shell_len, probe_len) / max(shell_len, probe_len) >= SPA_SHELL_RATIO
        ):
            return "client_route"
        content_type = str(probe.get("content_type") or "")
        if JSON_CONTENT_RE.search(content_type):
            return "json_api"
        if STATIC_CONTENT_RE.search(content_type):
            return "static_asset"
        return "html_page"
    return "unknown"


def _merge_url(raw: str, scheme_host: str) -> str:
    url = raw.strip()
    if not url:
        return ""
    if url.startswith(("http://", "https://")):
        return url
    if url.startswith("/"):
        return f"{scheme_host}{url}"
    return ""


def _load_endpoint_urls(repo_root: Path, target: str, limit: int) -> list[str]:
    """Candidate endpoints from the Active URL view and surface index; no ranking."""
    storage_key = target_storage_key(target)
    urls: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str) -> None:
        if candidate and candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)

    urls_file = repo_root / "recon" / storage_key / "urls" / "all.txt"
    if urls_file.is_file():
        for line in urls_file.read_text(encoding="utf-8", errors="replace").splitlines():
            url = line.strip().split()[0] if line.strip() else ""
            if url.startswith(("http://", "https://")):
                _add(url)
    # The surface index carries JS/browser-discovered endpoints (e.g. SPA
    # client routes) that never enter the Active URL list; probe them too.
    index_file = repo_root / "recon" / storage_key / "surface" / "index.jsonl"
    if index_file.is_file():
        for line in index_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or not row.get("target_owned"):
                continue
            url = str(row.get("url") or "")
            if url.startswith(("http://", "https://")):
                _add(url)
    return urls[:limit]


def observation_path(repo_root: Path, target: str) -> Path:
    return repo_root / "recon" / target_storage_key(target) / "route_kinds.json"


def load_observations(repo_root: Path, target: str) -> dict:
    path = observation_path(repo_root, target)
    if not path.is_file():
        return {"schema_version": SCHEMA_VERSION, "target": target, "endpoints": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": SCHEMA_VERSION, "target": target, "endpoints": {}}
    if not isinstance(data, dict) or not isinstance(data.get("endpoints"), dict):
        return {"schema_version": SCHEMA_VERSION, "target": target, "endpoints": {}}
    return data


def _observation_rank(source: str) -> int:
    """Browser/XHR facts outrank scanner probes; scanner outranks our GET."""
    order = {"browser_xhr": 3, "browser_api": 3, "scanner": 2, "route_probe": 1}
    return order.get(source, 0)


def record_observation(
    observations: dict,
    endpoint: str,
    probe: dict,
    route_kind: str,
    source: str,
) -> None:
    """Merge one observation; a higher-ranked source never gets overwritten."""
    endpoints = observations.setdefault("endpoints", {})
    existing = endpoints.get(endpoint)
    if not isinstance(existing, dict) or _observation_rank(source) > _observation_rank(
        str(existing.get("source") or "")
    ):
        endpoints[endpoint] = {
            "route_kind": route_kind,
            "source": source,
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "facts": {
                "status": int(probe.get("status") or 0),
                "content_type": str(probe.get("content_type") or ""),
                "body_length": int(probe.get("body_length") or 0),
                "body_sha256": str(probe.get("body_sha256") or ""),
                "probe_error": str(probe.get("probe_error") or ""),
            },
        }
    elif _observation_rank(source) == _observation_rank(str(existing.get("source") or "")):
        # Same rank: refresh facts, keep the label stable.
        existing["facts"] = {
            "status": int(probe.get("status") or 0),
            "content_type": str(probe.get("content_type") or ""),
            "body_length": int(probe.get("body_length") or 0),
            "body_sha256": str(probe.get("body_sha256") or ""),
            "probe_error": str(probe.get("probe_error") or ""),
        }
        existing["route_kind"] = route_kind
        existing["observed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ingest_ffuf_results(repo_root: Path, target: str, observations: dict) -> int:
    """Fold ffuf probe facts (status/length/content-type) into observations."""
    path = (
        repo_root
        / "recon"
        / target_storage_key(target)
        / "dirs"
        / "ffuf_results.jsonl.gz"
    )
    if not path.is_file():
        return 0
    import gzip

    count = 0
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = str(row.get("url") or "")
                if not url:
                    continue
                endpoint = url.split("?")[0]
                probe = {
                    "status": int(row.get("status") or 0),
                    "content_type": str(row.get("content-type") or ""),
                    "location": str(row.get("redirectlocation") or ""),
                    "body_length": int(row.get("length") or 0),
                    "body_sha256": "",
                    "probe_seconds": 0,
                    "probe_error": "",
                }
                route_kind = classify_route_kind(probe, {"body_sha256": "", "body_length": 0})
                record_observation(observations, endpoint, probe, route_kind, "scanner")
                count += 1
    except OSError:
        return 0
    return count


def probe_endpoints(
    repo_root: Path,
    target: str,
    urls: list[str],
    timeout: float,
    observations: dict,
) -> int:
    """GET-probe endpoints that have no observation yet; read-only method."""
    endpoints = observations.setdefault("endpoints", {})
    shell: dict = {}
    shell_endpoint = ""
    count = 0
    for url in urls:
        endpoint = url.split("?")[0]
        if endpoint in endpoints:
            continue
        if not shell or shell_endpoint != url.rsplit("/", 1)[0]:
            scheme_host = url.rsplit("/", 1)[0] if url.count("/") <= 2 else "/".join(url.split("/")[:3])
            shell = _spa_shell_facts(timeout, scheme_host)
            shell_endpoint = scheme_host
        probe = _get(url, timeout)
        route_kind = classify_route_kind(probe, shell)
        record_observation(observations, endpoint, probe, route_kind, "route_probe")
        count += 1
    return count


def save_observations(repo_root: Path, target: str, observations: dict) -> Path:
    observations["schema_version"] = SCHEMA_VERSION
    observations["target"] = target
    observations["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = observation_path(repo_root, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(observations, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Route-kind observation layer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_probe = sub.add_parser("probe", help="GET-probe endpoints lacking observations")
    p_probe.add_argument("--target", required=True)
    p_probe.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    p_probe.add_argument("--limit", type=int, default=200)
    p_probe.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p_probe.add_argument("--json", action="store_true")

    p_show = sub.add_parser("show", help="print current observations")
    p_show.add_argument("--target", required=True)
    p_show.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    p_show.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()

    if args.cmd == "show":
        data = load_observations(repo_root, args.target)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            for endpoint, item in sorted(data.get("endpoints", {}).items()):
                print(f"{item.get('route_kind'):14} {endpoint}")
        return 0

    if args.cmd == "probe":
        observations = load_observations(repo_root, args.target)
        ingested = ingest_ffuf_results(repo_root, args.target, observations)
        urls = _load_endpoint_urls(repo_root, args.target, args.limit)
        probed = probe_endpoints(repo_root, args.target, urls, args.timeout, observations)
        save_observations(repo_root, args.target, observations)
        if args.json:
            print(
                json.dumps(
                    {
                        "target": args.target,
                        "ffuf_observations": ingested,
                        "new_probes": probed,
                        "total_endpoints": len(observations.get("endpoints", {})),
                    }
                )
            )
        else:
            print(
                f"[route_kinds] ffuf facts merged={ingested} new probes={probed} "
                f"total={len(observations.get('endpoints', {}))}"
            )
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
