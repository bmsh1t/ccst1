#!/usr/bin/env python3
"""
sibling_generator.py — sibling-endpoint probe queue for lateral application.

Purpose:
    When a primary finding emerges (e.g. IDOR on /api/v1/orders/123), a
    senior hunter immediately asks: "what sibling endpoints share this
    pattern?" — /api/v1/invoices/{id}, /api/v1/exports/{id}, etc.
    Lateral application turns one paying finding into 3-5 with marginal
    additional work.

    This tool extracts the path template from a finding endpoint, scans
    the cached recon URL list for sibling resources under the same
    prefix, and writes a probe queue the agent picks up via the next
    working_hypothesis cycle.

Design notes:
    - Probes are QUEUED, not executed. The agent decides when (and
      whether) to run each probe.
    - Cap queue size at 20 siblings per finding (Risk R-D).
    - Free-text rationale per sibling — never a fixed enum.
    - Discoverable via the Question -> Tool Reference table in
      commands/autopilot.md (Phase 3 R5 / Contract 6).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore

DEFAULT_MAX_SIBLINGS = 20


@dataclass
class PathTemplate:
    """Extracted path template from a finding URL."""

    prefix: str = ""           # e.g. /api/v1
    resource: str = ""         # e.g. orders
    suffix: str = ""           # e.g. /{id}  (parameterized tail)
    full_template: str = ""    # e.g. /api/v1/{resource}/{id}
    raw_path: str = ""         # original input path


def _is_id_segment(seg: str) -> bool:
    """Heuristic: numeric, UUID-like, or dash-bearing-digit-heavy → likely an ID.

    Conservative rules (favor 'resource' over 'ID' when ambiguous):
      - all digits                                                → ID
      - UUID format (8-4-4-4-12 hex)                              → ID
      - contains a dash AND has digits                            → ID (UUID-ish)
      - ≥8 chars, mostly digits (>50% are digits)                 → ID
    Resource-name-like (e.g. 'orders', 'resource0', 'v2', 'users') → NOT ID.
    """
    if not seg:
        return False
    if seg.isdigit():
        return True
    if re.fullmatch(r"[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}", seg):
        return True
    if "-" in seg and any(c.isdigit() for c in seg):
        return True
    if len(seg) >= 8:
        digits = sum(1 for c in seg if c.isdigit())
        if digits >= len(seg) / 2:
            return True
    return False


def extract_template(endpoint: str) -> PathTemplate:
    """Extract a (prefix, resource, suffix) template from a URL or path.

    Examples:
        "/api/v1/orders/123"            -> prefix="/api/v1", resource="orders", suffix="/{id}"
        "/api/v2/users/abc-123/orders"  -> prefix="/api/v2/users/{id}", resource="orders", suffix=""
        "/orders"                        -> prefix="", resource="orders", suffix=""
        "https://host/api/v1/foo"       -> stripped to /api/v1/foo, prefix="/api/v1", resource="foo"

    For nested resources (e.g. /api/v2/users/abc/orders), the LAST
    non-ID segment is treated as the resource and any preceding ID is
    abstracted into the prefix as "{id}".
    """
    if not endpoint:
        return PathTemplate()
    parsed = urlparse(endpoint) if "://" in endpoint else None
    raw_path = parsed.path if parsed else endpoint
    raw_path = raw_path.split("?", 1)[0].split("#", 1)[0]
    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path
    segments = [s for s in raw_path.split("/") if s]
    if not segments:
        return PathTemplate(raw_path=raw_path)

    # Build prefix segments (everything up to and including the last
    # non-ID resource segment). Trailing ID-like segments become the suffix.
    template_segments: list[str] = []
    last_resource_idx = -1
    for idx, seg in enumerate(segments):
        if _is_id_segment(seg):
            template_segments.append("{id}")
        else:
            template_segments.append(seg)
            last_resource_idx = idx

    if last_resource_idx < 0:
        return PathTemplate(raw_path=raw_path, full_template="/" + "/".join(template_segments))

    resource = template_segments[last_resource_idx]
    prefix_segments = template_segments[:last_resource_idx]
    suffix_segments = template_segments[last_resource_idx + 1:]

    prefix = "/" + "/".join(prefix_segments) if prefix_segments else ""
    suffix = ("/" + "/".join(suffix_segments)) if suffix_segments else ""
    full_template = (prefix or "") + "/" + resource + suffix
    return PathTemplate(
        prefix=prefix,
        resource=resource,
        suffix=suffix,
        full_template=full_template,
        raw_path=raw_path,
    )


def _candidate_paths(all_urls: list[str]) -> list[str]:
    """Project URLs to paths, deduped, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in all_urls:
        if not raw:
            continue
        if "://" in raw:
            try:
                parsed = urlparse(raw)
                path = parsed.path or "/"
            except ValueError:
                continue
        else:
            path = raw
        path = path.split("?", 1)[0].split("#", 1)[0]
        if not path.startswith("/"):
            path = "/" + path
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def find_siblings(
    template: PathTemplate,
    all_urls: list[str],
    max_count: int = DEFAULT_MAX_SIBLINGS,
) -> list[dict]:
    """Find sibling endpoints sharing the same prefix + ID-bearing suffix shape.

    A sibling is a URL whose extracted template has:
      - the SAME prefix as the input template
      - a DIFFERENT resource segment
      - a compatible suffix shape (either same suffix, or both empty)

    Returns up to max_count siblings as dicts:
      {endpoint, method_to_test, rationale, queued_at}
    """
    if not template.resource:
        return []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    candidate_paths = _candidate_paths(all_urls)
    seen_resources: set[str] = {template.resource}
    siblings: list[dict] = []

    for path in candidate_paths:
        cand = extract_template(path)
        if not cand.resource:
            continue
        if cand.resource in seen_resources:
            continue
        if cand.prefix != template.prefix:
            continue
        # Suffix compatibility: same suffix or both empty
        if cand.suffix and template.suffix:
            if cand.suffix != template.suffix:
                continue
        elif cand.suffix or template.suffix:
            # one has ID-bearing tail, the other doesn't — skip
            continue
        seen_resources.add(cand.resource)
        siblings.append({
            "endpoint": path,
            "method_to_test": "GET",
            "rationale": (
                f"same prefix '{template.prefix}' as primary finding; "
                f"resource={cand.resource} (vs {template.resource})"
            ),
            "queued_at": now,
        })
        if len(siblings) >= max_count:
            break
    return siblings


def _load_all_urls(target: str, repo_root: Path) -> list[str]:
    """Read recon URL list for the target. Tries new and legacy layouts."""
    candidates = [
        repo_root / "recon" / target / "urls" / "all.txt",
        repo_root / "recon" / target / "urls.txt",
    ]
    for path in candidates:
        if path.is_file():
            try:
                return [
                    line.strip()
                    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if line.strip()
                ]
            except OSError:
                continue
    return []


def queue_sibling_probes(
    target: str,
    finding: dict,
    repo_root: Path | str | None = None,
    max_count: int = DEFAULT_MAX_SIBLINGS,
) -> Path:
    """Generate sibling probes for a finding; write the queue file.

    finding dict must include at least 'id' and 'endpoint' (or 'url').
    The repo's recon/<target>/urls/all.txt is used as the resource pool.
    Returns the path to the written queue file.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    endpoint = str(finding.get("endpoint") or finding.get("url") or "")
    finding_id = str(finding.get("id") or "anonymous")

    template = extract_template(endpoint)
    all_urls = _load_all_urls(target_key, repo)
    siblings = find_siblings(template, all_urls, max_count=max_count)

    payload = {
        "target": resolved_target,
        "source_finding_id": finding_id,
        "source_endpoint": endpoint,
        "extracted_template": template.full_template,
        "extracted_resource": template.resource,
        "extracted_prefix": template.prefix,
        "extracted_suffix": template.suffix,
        "siblings": siblings,
        "queued_count": len(siblings),
        "executed_count": 0,
    }

    out_dir = repo / "evidence" / target_key / "probes" / "queue"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"siblings_{finding_id}.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate sibling-endpoint probe queue for a finding. "
            "Probes are queued only — execution is up to the agent."
        )
    )
    parser.add_argument("--target", required=True, help="target domain")
    parser.add_argument("--finding-id", required=True, help="primary finding identifier")
    parser.add_argument("--endpoint", required=True, help="primary finding endpoint or URL")
    parser.add_argument(
        "--max-count",
        type=int,
        default=DEFAULT_MAX_SIBLINGS,
        help=f"queue size cap (default {DEFAULT_MAX_SIBLINGS})",
    )
    parser.add_argument(
        "--repo-root",
        default=str(BASE_DIR),
        help="repository root (default: parent of this file)",
    )
    args = parser.parse_args(argv)

    finding = {"id": args.finding_id, "endpoint": args.endpoint}
    out = queue_sibling_probes(
        args.target, finding, repo_root=args.repo_root, max_count=args.max_count
    )
    print(f"sibling probe queue written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
