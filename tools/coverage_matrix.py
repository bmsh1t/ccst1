#!/usr/bin/env python3
"""
coverage_matrix.py — (endpoint x vuln_class) coverage state for the hunt.

Purpose:
    A senior hunter does NOT finish a run while obvious high-value
    test combinations remain untouched. The coverage matrix captures
    this as state: for each endpoint × vuln class pair, the cell is
    either tested-clean, tested-with-finding, untested, or N/A. The
    Finish Condition F3 invariant (commands/autopilot.md) blocks
    `finish` while any high-weight cell remains untested without an
    N/A reason.

    This tool is NOT auto-invoked. Claude consults it via the
    Question -> Tool Reference table when its working_hypothesis
    asks "which high-value cells remain untested?".

Design notes:
    - Schema per design.md Contract 4 (Phase 3): endpoints array
      with nested cells per vuln class.
    - Only endpoints with value_weight >= 1.0 enter the matrix
      (Risk R-E: avoid bloat on huge recon outputs).
    - rebuild operates incrementally — re-runs preserve operator
      annotations (n_a reasons, etc.) unless --force-clean is set.
    - All cell values are typed enums INTERNALLY (4 statuses) but
      the cell shape is data, NOT a Claude-facing options[] menu.
      Claude reads `find-gaps` output which is just (endpoint,
      vuln_class) tuples — no "pick one of these statuses" prompt.

VULN_CLASSES taxonomy (15 entries, ordering is stable — append-only
on extension; positional consumers may rely on the prefix):

    NOTE: the three groups below are CONCEPTUAL organisation for human
    comprehension — they do NOT reflect tuple order. The actual enum
    order is preserved as: original 10 first (IDOR..JWT), 5 new
    appended (SQLi..CSRF). See `VULN_CLASSES = (...)` for the
    canonical positional layout.

    Group 1 — Authn/Authz/identity surface (5):
      IDOR     — direct object reference horizontal/vertical
      Authz    — broader access control (admin endpoints, role bypass)
      OAuth    — OAuth/OIDC flows (state, redirect_uri, scope confusion)
      JWT      — token-level (alg=none, kid injection, weak secret)
      CSRF     — session-riding; standalone is often rejected — submit
                 chained (CSRF -> state-change -> account compromise)

    Group 2 — Input injection family (5):
      XSS      — reflected/stored/DOM; includes prototype-pollution
                 -> XSS chains where impact is JS execution
      SQLi     — error-based / boolean-blind / time-based / OOB;
                 covers all DBMS variants
      XXE      — classic + blind/OOB; both general & parameter entities
      RCE      — umbrella: OS command injection, deserialisation,
                 SSTI -> RCE escalation, file upload -> exec, etc.
      Path     — Path Traversal / LFI / RFI variants. Single-token
                 name kept for symmetry with JWT/RCE/XXE; if you find
                 LFI or RFI, mark as Path. Burp/Nuclei may tag
                 differently — normalise here.

    Group 3 — Server-side & API (5):
      SSRF     — outbound request forge, includes blind SSRF + OOB
      Race     — TOCTOU, double-spend, parallel state mutation
      GraphQL  — introspection, deep-nested queries, alias DoS, batch
                 abuse, mutation IDOR (overlaps with IDOR but tagged
                 separately because the discovery surface is distinct)
      Upload   — file upload bypass (extension/MIME/content), often
                 chains to RCE via webshell
      Webhook  — incoming webhook abuse (HMAC bypass, replay, spoof)

    Intentionally NOT in this enum (out of scope for this PR; obvious
    next candidates if the matrix grows): SSTI as its own class
    (currently subsumed under RCE), NoSQLi, OpenRedirect, Prototype
    Pollution as a primary class (currently rolled into XSS when the
    impact path is JS exec), Deserialisation (under RCE), CRLF
    injection, HTTP smuggling.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.surface_weights import value_weight
except ImportError:  # pragma: no cover - top-level tools/ import
    from surface_weights import value_weight  # type: ignore

VULN_CLASSES = (
    "IDOR", "SSRF", "XSS", "Race", "Authz",
    "GraphQL", "OAuth", "Upload", "Webhook", "JWT",
    "SQLi", "XXE", "RCE", "Path", "CSRF",
)

# Operator-side aliases. The KEY is the lowercased form of an alias
# the operator might type; the VALUE is the canonical name from
# VULN_CLASSES that gets stored on disk. This is intentionally
# curated (not Levenshtein-fuzzy) so behaviour is predictable.
#
# Aliases also include the canonical names lowercased so case-folding
# alone resolves correctly without a separate code path.
VULN_CLASS_ALIASES = {
    # Case-insensitive matches for the canonical names
    **{vc.lower(): vc for vc in VULN_CLASSES},
    # Path traversal family
    "lfi": "Path",
    "rfi": "Path",
    "pathtraversal": "Path",
    "path-traversal": "Path",
    "path_traversal": "Path",
    "directory-traversal": "Path",
    "directorytraversal": "Path",
    # RCE umbrella
    "oscommand": "RCE",
    "os-command": "RCE",
    "cmdinjection": "RCE",
    "cmd-injection": "RCE",
    "commandinjection": "RCE",
    "command-injection": "RCE",
    "deser": "RCE",
    "deserialization": "RCE",
    "unserialize": "RCE",
    "ssti": "RCE",
    "template-injection": "RCE",
    "templateinjection": "RCE",
    # XSS variants
    "xss-dom": "XSS",
    "dom-xss": "XSS",
    "domxss": "XSS",
    "prototype-pollution": "XSS",
    "prototypepollution": "XSS",
    "pp": "XSS",
    # SQLi variants
    "sql-injection": "SQLi",
    "sqlinjection": "SQLi",
    "sqlblind": "SQLi",
    "sqli-blind": "SQLi",
    "sqli-time": "SQLi",
    "blindsqli": "SQLi",
    # CSRF variants
    "csrf-token": "CSRF",
    "xsrf": "CSRF",
    # XXE variants
    "xxe-blind": "XXE",
    "xml-injection": "XXE",
    "xmlinjection": "XXE",
    "xinclude": "XXE",
}


def normalize_vuln_class(name: str) -> str:
    """Resolve operator-typed vuln_class to its canonical form.

    Accepts canonical names case-insensitively and a curated alias
    set (LFI/RFI -> Path, OSCommand -> RCE, etc. — see
    `VULN_CLASS_ALIASES`). Returns the canonical name (the form
    stored on disk).

    Raises `ValueError` on unrecognised input with a message that
    lists the canonical names so the operator can pick the right one.
    """
    if name in VULN_CLASSES:
        return name
    key = name.strip().lower()
    if key in VULN_CLASS_ALIASES:
        return VULN_CLASS_ALIASES[key]
    raise ValueError(
        f"unknown vuln_class: {name!r}. "
        f"Canonical names: {', '.join(VULN_CLASSES)}. "
        f"Aliases like 'lfi'->'Path', 'ssti'->'RCE', 'sql-injection'->'SQLi' "
        f"are also accepted (case-insensitive)."
    )

STATUS_VALUES = ("tested_clean", "tested_finding", "untested", "n_a")

DEFAULT_MIN_WEIGHT = 3.0


def _matrix_path(repo_root: Path, target: str) -> Path:
    return repo_root / "evidence" / target / "coverage_matrix.json"


def _empty_matrix(target: str) -> dict:
    return {
        "target": target,
        "vuln_classes": list(VULN_CLASSES),
        "endpoints": [],
        "summary": {
            "total_cells": 0,
            "tested_clean": 0,
            "tested_finding": 0,
            "untested": 0,
            "n_a": 0,
            "high_value_gaps_count": 0,
        },
        "last_updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def load_matrix(target: str, repo_root: Path | str | None = None) -> dict:
    """Load the matrix for a target. Returns an empty shell when absent."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    path = _matrix_path(repo, target)
    if not path.is_file():
        return _empty_matrix(target)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_matrix(target)
    if not isinstance(data, dict) or "endpoints" not in data:
        return _empty_matrix(target)
    return data


def save_matrix(target: str, matrix: dict, repo_root: Path | str | None = None) -> Path:
    """Persist matrix; recompute summary at save time.

    Mutates the input dict in place so the caller sees the freshly
    computed `summary` and updated `last_updated` immediately after
    return — required by the CLI `rebuild` stdout path which reads
    `matrix["summary"]` to print cell counts. A prior shallow-copy
    implementation caused stdout to report a stale summary while the
    on-disk file was correct.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    matrix["last_updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    matrix["summary"] = _compute_summary(matrix)
    path = _matrix_path(repo, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    return path


def _compute_summary(matrix: dict) -> dict:
    counts = {status: 0 for status in STATUS_VALUES}
    total = 0
    high_gaps = 0
    for ep in matrix.get("endpoints", []):
        weight = float(ep.get("weight", 1.0) or 1.0)
        for cell in ep.get("cells", {}).values():
            total += 1
            status = cell.get("status", "untested")
            if status in counts:
                counts[status] += 1
            if status == "untested" and weight >= DEFAULT_MIN_WEIGHT:
                high_gaps += 1
    return {
        "total_cells": total,
        **counts,
        "high_value_gaps_count": high_gaps,
    }


def _canonicalize_endpoint(url: str) -> str:
    """Project a raw URL to a canonical endpoint key (no query string)."""
    if not url:
        return ""
    if "://" in url:
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
        except ValueError:
            return ""
    else:
        path = url
    return path.split("?", 1)[0].split("#", 1)[0]


def _empty_cells() -> dict[str, dict]:
    return {vc: {"status": "untested"} for vc in VULN_CLASSES}


def _ensure_endpoint(matrix: dict, endpoint: str, weight: float) -> dict:
    """Return the endpoint entry dict; create if missing."""
    for ep in matrix.get("endpoints", []):
        if ep.get("endpoint") == endpoint:
            return ep
    new_ep = {
        "endpoint": endpoint,
        "weight": weight,
        "cells": _empty_cells(),
    }
    matrix.setdefault("endpoints", []).append(new_ep)
    return new_ep


def rebuild_matrix(
    target: str,
    repo_root: Path | str | None = None,
    *,
    force_clean: bool = False,
    min_weight_to_include: float = 1.0,
) -> dict:
    """Populate the matrix from cached recon URLs + findings.

    Two endpoint sources are scanned:
      1. recon/<target>/urls/all.txt — bulk discovery surface, gated
         by `min_weight_to_include` (default 1.0) to avoid bloat from
         marketing/CDN URLs.
      2. findings/<target>/findings.json — endpoints discovered
         through working_hypothesis exploration that may not have
         appeared in bulk recon (e.g. WordPress REST API paths,
         /wp-json/* endpoints surfaced via JS inspection). These
         endpoints are added to the matrix REGARDLESS of recon
         presence; their value_weight is computed at insertion time
         and they bypass the min_weight_to_include filter (because a
         finding by definition makes the endpoint relevant).

    For an endpoint discovered through Claude's hypothesis-driven
    workflow to land in the matrix on rebuild, it must either:
      (a) be in recon/<target>/urls/all.txt (auto-collected), OR
      (b) be referenced from findings/<target>/findings.json with
          {"endpoint": "/path", "vuln_class": "..."}.
    Operators using `mark_cell` for ad-hoc cells should ALSO append a
    matching entry to findings.json so the cell survives a rebuild.

    Operator annotations (n_a reasons) are preserved unless
    force_clean=True. Recon URLs below min_weight_to_include are
    skipped to avoid bloat (Risk R-E).
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    matrix = _empty_matrix(target) if force_clean else load_matrix(target, repo)
    if "endpoints" not in matrix:
        matrix["endpoints"] = []
    matrix["vuln_classes"] = list(VULN_CLASSES)

    # Index existing cells by endpoint for preservation
    existing = {ep.get("endpoint"): ep for ep in matrix.get("endpoints", [])}

    # Collect URLs from recon
    urls_path = repo / "recon" / target / "urls" / "all.txt"
    urls: list[str] = []
    if urls_path.is_file():
        try:
            urls = [
                line.strip()
                for line in urls_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
        except OSError:
            urls = []

    # Build endpoint set with weights
    seen: dict[str, float] = {}
    for raw in urls:
        path = _canonicalize_endpoint(raw)
        if not path:
            continue
        weight = value_weight(path)
        if weight < min_weight_to_include:
            continue
        if path not in seen or weight > seen[path]:
            seen[path] = weight

    # Merge: keep existing cells, add new endpoints with untested cells
    new_endpoints: list[dict] = []
    for endpoint, weight in seen.items():
        if endpoint in existing:
            ep = existing[endpoint]
            ep["weight"] = max(float(ep.get("weight", weight) or weight), weight)
            cells = ep.get("cells") or {}
            for vc in VULN_CLASSES:
                cells.setdefault(vc, {"status": "untested"})
            ep["cells"] = cells
            new_endpoints.append(ep)
        else:
            new_endpoints.append({
                "endpoint": endpoint,
                "weight": weight,
                "cells": _empty_cells(),
            })

    # Apply findings: mark cells as tested_finding
    findings_path = repo / "findings" / target / "findings.json"
    if findings_path.is_file():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(findings, dict):
                findings = findings.get("findings", [])
            for finding in findings or []:
                ep_path = _canonicalize_endpoint(str(finding.get("endpoint") or finding.get("url") or ""))
                vc = str(finding.get("vuln_class") or finding.get("class") or "").strip()
                if not ep_path or vc not in VULN_CLASSES:
                    continue
                # ensure endpoint exists in matrix even if recon missed it
                for ep in new_endpoints:
                    if ep["endpoint"] == ep_path:
                        ep["cells"][vc] = {
                            "status": "tested_finding",
                            "evidence_ref": f"findings/{target}/findings.json#{finding.get('id', '')}",
                        }
                        break
                else:
                    ep = {
                        "endpoint": ep_path,
                        "weight": value_weight(ep_path),
                        "cells": _empty_cells(),
                    }
                    ep["cells"][vc] = {
                        "status": "tested_finding",
                        "evidence_ref": f"findings/{target}/findings.json#{finding.get('id', '')}",
                    }
                    new_endpoints.append(ep)
        except (OSError, json.JSONDecodeError):
            pass

    # Apply scanner_pass.json: mark cells `tested_clean` only when scanner
    # exercised them and no higher-precedence status (tested_finding > n_a)
    # already applies. Per task 05-16-b4-scanner-matrix-feedback (R2/R3).
    _apply_scanner_pass(target, repo, new_endpoints)

    matrix["endpoints"] = new_endpoints
    return matrix


def _apply_scanner_pass(
    target: str,
    repo: Path,
    endpoints: list[dict],
) -> None:
    """Mark cells tested_clean when scanner_pass.json says the scanner
    exercised (endpoint, vuln_class) but the cell is still untested.

    Cell-state precedence (highest to lowest):
        tested_finding > tested_clean > n_a > untested
    """
    sp_path = repo / "findings" / target / "scanner_pass.json"
    if not sp_path.is_file():
        return
    try:
        payload = json.loads(sp_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    rows = payload.get("endpoints", [])
    if not isinstance(rows, list):
        return

    # Build {endpoint: ep_dict} index for quick lookup
    ep_index = {ep.get("endpoint"): ep for ep in endpoints}

    scanned_at = str(payload.get("scanned_at") or "")
    scanner_version = str(payload.get("scanner_version") or "")

    for row in rows:
        if not isinstance(row, dict):
            continue
        endpoint_raw = str(row.get("endpoint") or "")
        endpoint = _canonicalize_endpoint(endpoint_raw)
        vc_raw = str(row.get("vuln_class") or "").strip()
        if not endpoint or not vc_raw:
            continue
        try:
            vc = normalize_vuln_class(vc_raw)
        except ValueError:
            # Per AC: unknown vuln_class → log warning, do not crash, leave cell untested
            print(
                f"[coverage_matrix] scanner_pass: unknown vuln_class={vc_raw!r} "
                f"(endpoint={endpoint!r}) — leaving cell untested",
                file=sys.stderr,
            )
            continue
        module = str(row.get("module") or "")

        if endpoint not in ep_index:
            # Endpoint not in matrix yet — add it so the tested_clean mark survives
            new_ep = {
                "endpoint": endpoint,
                "weight": value_weight(endpoint),
                "cells": _empty_cells(),
            }
            endpoints.append(new_ep)
            ep_index[endpoint] = new_ep

        ep = ep_index[endpoint]
        cells = ep.setdefault("cells", _empty_cells())
        current = cells.get(vc, {"status": "untested"})
        cur_status = current.get("status", "untested")
        # Precedence: tested_finding and n_a stay; otherwise upgrade to tested_clean
        if cur_status in ("tested_finding", "n_a"):
            continue
        cells[vc] = {
            "status": "tested_clean",
            "evidence_ref": (
                f"findings/{target}/scanner_pass.json#{module}"
                if module else f"findings/{target}/scanner_pass.json"
            ),
            "scanned_at": scanned_at,
            "scanner_version": scanner_version,
        }


def find_high_value_gaps(
    target: str,
    repo_root: Path | str | None = None,
    min_weight: float = DEFAULT_MIN_WEIGHT,
) -> list[dict]:
    """Return (endpoint, vuln_class) cells with status=untested AND weight >= min_weight."""
    matrix = load_matrix(target, repo_root)
    gaps: list[dict] = []
    for ep in matrix.get("endpoints", []):
        weight = float(ep.get("weight", 1.0) or 1.0)
        if weight < min_weight:
            continue
        for vc, cell in (ep.get("cells") or {}).items():
            if cell.get("status") == "untested":
                gaps.append({
                    "endpoint": ep.get("endpoint", ""),
                    "vuln_class": vc,
                    "weight": weight,
                })
    return gaps


def mark_cell(
    target: str,
    endpoint: str,
    vuln_class: str,
    status: str,
    *,
    reason: str = "",
    repo_root: Path | str | None = None,
    write_finding: bool = False,
) -> dict:
    """Mark a cell. Raises ValueError on invalid vuln_class/status.

    `vuln_class` is normalised through `normalize_vuln_class()` so
    operators may pass aliases (`lfi`, `ssti`, `sql-injection`) or
    any case variant (`sqli`, `SQLI`) — the canonical name is what
    gets stored on disk.

    When `write_finding=True` AND status indicates a finding
    (`tested_finding`), append a matching entry to
    `findings/<target>/findings.json`. This keeps the cell durable
    across `rebuild_matrix` re-runs: without the findings.json entry,
    a `force_clean` rebuild that the endpoint is not in recon would
    drop the cell.
    """
    vuln_class = normalize_vuln_class(vuln_class)
    if status not in STATUS_VALUES:
        raise ValueError(f"unknown status: {status}")
    matrix = load_matrix(target, repo_root)
    endpoint = _canonicalize_endpoint(endpoint)
    weight = value_weight(endpoint)
    ep = _ensure_endpoint(matrix, endpoint, weight)
    cell = {"status": status}
    if reason:
        cell["reason"] = reason
    ep["cells"][vuln_class] = cell
    save_matrix(target, matrix, repo_root)

    if write_finding and status == "tested_finding":
        _append_finding(target, endpoint, vuln_class, reason, repo_root)

    return cell


def _append_finding(
    target: str,
    endpoint: str,
    vuln_class: str,
    reason: str,
    repo_root: Path | str | None = None,
) -> None:
    """Append an entry to findings/<target>/findings.json so the cell
    survives a future `rebuild_matrix` call. Generates a stable id
    from (endpoint, vuln_class). Idempotent — duplicate entries are
    skipped on the (endpoint, vuln_class) key.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    findings_dir = repo / "findings" / target
    findings_dir.mkdir(parents=True, exist_ok=True)
    findings_path = findings_dir / "findings.json"

    existing: list[dict] = []
    if findings_path.is_file():
        try:
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                existing = data
            elif isinstance(data, dict):
                existing = list(data.get("findings", []))
        except (OSError, json.JSONDecodeError):
            existing = []

    finding_id = f"M-{vuln_class}-{abs(hash(endpoint)) % 10_000_000}"
    for item in existing:
        if (item.get("endpoint") == endpoint
                and item.get("vuln_class") == vuln_class):
            return  # idempotent

    existing.append({
        "id": finding_id,
        "endpoint": endpoint,
        "vuln_class": vuln_class,
        "reason": reason,
        "source": "mark_cell",
    })
    findings_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Coverage matrix for (endpoint x vuln_class) state."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rebuild = sub.add_parser("rebuild", help="rebuild matrix from recon + findings")
    p_rebuild.add_argument("--target", required=True)
    p_rebuild.add_argument("--repo-root", default=str(BASE_DIR))
    p_rebuild.add_argument("--force-clean", action="store_true")
    p_rebuild.add_argument("--min-weight-to-include", type=float, default=1.0)

    p_gaps = sub.add_parser("find-gaps", help="list high-value untested cells")
    p_gaps.add_argument("--target", required=True)
    p_gaps.add_argument("--repo-root", default=str(BASE_DIR))
    p_gaps.add_argument("--min-weight", type=float, default=DEFAULT_MIN_WEIGHT)

    p_mark = sub.add_parser("mark", help="mark a specific cell")
    p_mark.add_argument("--target", required=True)
    p_mark.add_argument("--endpoint", required=True)
    p_mark.add_argument("--vuln-class", required=True)
    p_mark.add_argument("--status", required=True, choices=list(STATUS_VALUES))
    p_mark.add_argument("--reason", default="")
    p_mark.add_argument("--repo-root", default=str(BASE_DIR))
    p_mark.add_argument(
        "--write-finding",
        action="store_true",
        help=(
            "Also append an entry to findings/<target>/findings.json so "
            "the cell survives `rebuild` (only takes effect when "
            "--status tested_finding)."
        ),
    )

    args = parser.parse_args(argv)

    if args.cmd == "rebuild":
        matrix = rebuild_matrix(
            args.target,
            repo_root=args.repo_root,
            force_clean=args.force_clean,
            min_weight_to_include=args.min_weight_to_include,
        )
        out = save_matrix(args.target, matrix, args.repo_root)
        summary = matrix["summary"]
        print(f"coverage_matrix written: {out}")
        print(
            f"  endpoints={len(matrix['endpoints'])}  cells={summary['total_cells']}  "
            f"untested={summary['untested']}  high_value_gaps={summary['high_value_gaps_count']}"
        )
        return 0

    if args.cmd == "find-gaps":
        gaps = find_high_value_gaps(args.target, args.repo_root, args.min_weight)
        print(json.dumps(gaps, indent=2))
        return 0

    if args.cmd == "mark":
        cell = mark_cell(
            args.target,
            args.endpoint,
            args.vuln_class,
            args.status,
            reason=args.reason,
            repo_root=args.repo_root,
            write_finding=args.write_finding,
        )
        print(json.dumps(cell, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
