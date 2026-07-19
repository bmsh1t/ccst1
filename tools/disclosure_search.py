#!/usr/bin/env python3
"""
disclosure_search.py — horizontal pattern transfer from HackerOne hacktivity.

Purpose:
    Senior hunters check what's already been paid on a target (and on
    similar targets) before testing — most "first finding" wins come
    from spotting a published pattern and applying it to a sibling
    endpoint the original reporter missed. This module mines HackerOne
    Hacktivity for two query shapes:

      (a) same-target reports — what THIS target has already paid on
      (b) similar-target reports — what tech-stack peers paid on,
          ready for pattern transfer

    Output is a markdown document the agent consults via the
    Question -> Tool advisory table. The module does NOT auto-spawn;
    invocation is up to Claude's working_hypothesis reasoning.

Design notes:
    - Uses the existing HackerOne MCP client (mcp/hackerone-mcp/server.py).
      Loaded via importlib because the folder name has a hyphen.
    - 72-hour cache to avoid re-querying GraphQL on every run.
    - Gracefully no-ops to "no reports found" sections when MCP is
      unreachable or returns empty — never crashes.
    - Output schema per design.md Contract 1 (free-text seeds, NOT a
      fixed taxonomy — preserves C1 anti-options[] discipline).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore

CACHE_DIR_NAME = "state/disclosure_cache"
DEFAULT_CACHE_TTL_HOURS = 72

# Internal enum on the cache payload + render line. Three distinct
# coverage states surfaced after both same- and similar-target searches
# complete. Pilot 2026-05-15 (baronpa.com) showed the previous
# undifferentiated "no reports" message conflated three causes; Claude
# could not tell whether the path was exhausted, transient, or simply
# not applicable. The status is data, NOT a Claude-facing options[] menu.
COVERAGE_STATUS_VALUES = ("mcp_unavailable", "no_mcp_coverage", "covered")
DEFAULT_COVERAGE_STATUS = "covered"


# ─────────────────────────────────────────────────────────────────────────────
# Disclosed-pattern dedup against hunt-memory/patterns.jsonl
# Per task 05-16-b7-disclosed-pattern-dedup.
# ─────────────────────────────────────────────────────────────────────────────

# Title → canonical vuln_class inference. Matches are substring (case-
# insensitive) against the disclosed report title. Order matters: the first
# matching token wins (so we put more-specific tokens first).
_TITLE_TO_VULN_CLASS: list[tuple[str, str]] = [
    # SSRF before SQLi to avoid "SQL" matching "ssrf" titles by accident
    ("server-side request forgery", "SSRF"),
    ("ssrf", "SSRF"),
    ("sql injection", "SQLi"),
    ("sqli", "SQLi"),
    ("sql ", "SQLi"),
    ("idor", "IDOR"),
    ("insecure direct object", "IDOR"),
    ("broken object level", "IDOR"),
    ("authorization", "Authz"),
    ("authz", "Authz"),
    ("auth bypass", "Authz"),
    ("access control", "Authz"),
    ("privilege escalation", "Authz"),
    ("graphql", "GraphQL"),
    ("oauth", "OAuth"),
    ("open redirect", "OAuth"),
    ("file upload", "Upload"),
    ("arbitrary file upload", "Upload"),
    ("upload", "Upload"),
    ("webhook", "Webhook"),
    ("jwt", "JWT"),
    ("json web token", "JWT"),
    ("xxe", "XXE"),
    ("xml external entity", "XXE"),
    ("rce", "RCE"),
    ("remote code execution", "RCE"),
    ("command injection", "RCE"),
    ("template injection", "RCE"),
    ("ssti", "RCE"),
    ("deserialization", "RCE"),
    ("path traversal", "Path"),
    ("directory traversal", "Path"),
    ("lfi", "Path"),
    ("local file", "Path"),
    ("csrf", "CSRF"),
    ("cross-site request forgery", "CSRF"),
    ("race condition", "Race"),
    ("race ", "Race"),
    # XSS goes last so SSRF/CSRF/XXE tokens are matched first
    ("xss", "XSS"),
    ("cross-site scripting", "XSS"),
    ("reflected scripting", "XSS"),
    ("stored scripting", "XSS"),
]


def _infer_vuln_class_from_title(title: str) -> str:
    """Best-effort canonical vuln_class from a disclosed report title.

    Returns "" when nothing recognisable matches. Caller should treat empty
    string as "skip dedup for this report".
    """
    if not title:
        return ""
    text = title.lower()
    for token, vc in _TITLE_TO_VULN_CLASS:
        if token in text:
            return vc
    return ""


def _format_pattern_ref(pattern: dict) -> str:
    """Render a short pattern reference for inline dedup tags.

    Uses (technique, target) as the surfaced id since patterns.jsonl does not
    carry a stable numeric id today. Truncates long technique names so the
    inline tag stays readable inside a markdown table.
    """
    technique = (pattern.get("technique") or "").strip() or "pattern"
    technique_short = technique[:60]
    src = (pattern.get("target") or "").strip()
    if src:
        return f"{technique_short}@{src}"
    return technique_short


def _dedup_against_local(
    *,
    reports: list["DisclosedReport"],
    target: str,
    tech_stack: list[str],
    repo_root: Path,
) -> tuple[list[tuple["DisclosedReport", str]], dict[str, int]]:
    """Dedup disclosed reports against hunt-memory/patterns.jsonl.

    Returns:
        - List of (report, dedup_ref) tuples in input order. `dedup_ref` is
          the rendered pattern reference (empty string if no match).
        - Stats dict {"matched": M, "total": N, "same_target_matched": A,
          "similar_target_matched": B}.

    Same-target match: pattern has the same `target` AND same vuln_class.
    Similar-target match: pattern has overlapping tech_stack AND same
    vuln_class (and is not a same-target match).
    """
    # Lazy import to avoid hard-binding tests on hunt-memory layout
    try:
        from memory.pattern_db import PatternDB
    except Exception:
        # If pattern_db is unavailable, dedup as no-op
        return [(r, "") for r in reports], {"matched": 0, "total": len(reports),
                                            "same_target_matched": 0,
                                            "similar_target_matched": 0}

    patterns_path = repo_root / "hunt-memory" / "patterns.jsonl"
    if not patterns_path.is_file():
        return [(r, "") for r in reports], {
            "matched": 0, "total": len(reports),
            "same_target_matched": 0, "similar_target_matched": 0,
        }
    try:
        db = PatternDB(patterns_path)
    except Exception:
        return [(r, "") for r in reports], {
            "matched": 0, "total": len(reports),
            "same_target_matched": 0, "similar_target_matched": 0,
        }

    # Cache match() results by vuln_class so 1000-entry patterns.jsonl + 100
    # disclosed reports stays well under C3's 5s budget.
    vc_cache: dict[str, list[dict]] = {}

    def patterns_for_class(vc: str) -> list[dict]:
        if vc not in vc_cache:
            try:
                vc_cache[vc] = db.match(vuln_class=vc)
            except Exception:
                vc_cache[vc] = []
        return vc_cache[vc]

    same_matches = 0
    similar_matches = 0
    out: list[tuple["DisclosedReport", str]] = []
    tech_lower = {t.lower() for t in (tech_stack or [])}
    for report in reports:
        vc = _infer_vuln_class_from_title(report.title)
        if not vc:
            out.append((report, ""))
            continue
        candidates = patterns_for_class(vc)
        # Prefer same-target match, fall back to tech-overlap match.
        chosen: dict | None = None
        match_kind = ""
        for p in candidates:
            if (p.get("target") or "").lower() == target.lower():
                chosen = p
                match_kind = "same"
                break
        if chosen is None and tech_lower:
            for p in candidates:
                p_tech = {t.lower() for t in (p.get("tech_stack") or [])}
                if tech_lower & p_tech:
                    chosen = p
                    match_kind = "similar"
                    break
        if chosen is None:
            out.append((report, ""))
            continue
        if match_kind == "same":
            same_matches += 1
        else:
            similar_matches += 1
        out.append((report, _format_pattern_ref(chosen)))

    stats = {
        "matched": same_matches + similar_matches,
        "total": len(reports),
        "same_target_matched": same_matches,
        "similar_target_matched": similar_matches,
    }
    return out, stats


def _format_dedup_header(
    same_stats: dict[str, int],
    similar_stats: dict[str, int],
) -> str:
    total = same_stats["total"] + similar_stats["total"]
    matched = same_stats["matched"] + similar_stats["matched"]
    lines = [
        f"**Pattern dedup**: {matched} of {total} disclosed patterns match local hunt memory.",
        f"- Same-target dedup: {same_stats['same_target_matched']} of {same_stats['total']}",
        f"- Similar-target dedup: {similar_stats['similar_target_matched']} of {similar_stats['total']}",
    ]
    return "\n".join(lines)


def _load_h1_client():
    """Dynamically load mcp/hackerone-mcp/server.py.

    The folder name 'hackerone-mcp' contains a hyphen, which is not a
    valid Python module identifier. Use importlib.spec_from_file_location
    to load it as a synthetic module. Returns None when not available.
    """
    server_path = BASE_DIR / "mcp" / "hackerone-mcp" / "server.py"
    if not server_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_h1_mcp_server", server_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


@dataclass
class DisclosedReport:
    """One disclosed HackerOne report — minimal projection."""
    title: str = ""
    severity: str = ""
    disclosed_at: str = ""
    url: str = ""
    state: str = ""
    program: str = ""
    program_name: str = ""

    @classmethod
    def from_h1(cls, item: dict) -> "DisclosedReport":
        return cls(
            title=str(item.get("title", "") or ""),
            severity=str(item.get("severity", "") or "unknown"),
            disclosed_at=str(item.get("disclosed_at", "") or "")[:10],
            url=str(item.get("url", "") or ""),
            state=str(item.get("state", "") or ""),
            program=str(item.get("program", "") or ""),
            program_name=str(item.get("program_name", "") or ""),
        )


def _cache_path(repo_root: Path, target: str) -> Path:
    safe_target = target_storage_key(target).replace(":", "_")
    return repo_root / CACHE_DIR_NAME / f"{safe_target}.json"


def _load_cache(repo_root: Path, target: str, ttl_hours: float) -> dict | None:
    path = _cache_path(repo_root, target)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    age_sec = time.time() - float(payload.get("cached_at_ts", 0))
    if age_sec > ttl_hours * 3600:
        return None
    return payload


def _save_cache(repo_root: Path, target: str, payload: dict) -> None:
    path = _cache_path(repo_root, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {**payload, "cached_at_ts": time.time()}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def search_same_target(
    target: str,
    h1_client=None,
    limit: int = 15,
) -> list[DisclosedReport]:
    """Return disclosed reports filed against the SAME target program.

    The HackerOne MCP search supports a 'program' handle filter. We
    naively try the target's apex domain as a program handle (e.g.
    'baronpa' for 'baronpa.com'). If the program lookup yields nothing,
    we fall back to a keyword search on the target string itself.
    """
    if h1_client is None:
        h1_client = _load_h1_client()
    if h1_client is None:
        return []
    program_handle = target.split(".")[0]
    out: list[DisclosedReport] = []
    try:
        results = h1_client.search_disclosed_reports(
            program=program_handle, limit=limit
        )
        out = [DisclosedReport.from_h1(item) for item in results]
    except Exception:
        out = []
    if not out:
        try:
            results = h1_client.search_disclosed_reports(
                keyword=target, limit=limit
            )
            out = [DisclosedReport.from_h1(item) for item in results]
        except Exception:
            out = []
    return out


def search_similar_targets(
    target: str,
    tech_stack: list[str] | None = None,
    vertical: str = "",
    h1_client=None,
    limit: int = 15,
) -> list[DisclosedReport]:
    """Return disclosed reports against SIMILAR targets.

    Search the hacktivity by tech-stack keyword (most discriminating)
    and merge with vertical-keyword search when available. De-dupes by
    report URL. Excludes the same-target program so callers can clearly
    separate (a) and (b) buckets per PRD R1.
    """
    if h1_client is None:
        h1_client = _load_h1_client()
    if h1_client is None:
        return []
    same_program = target.split(".")[0]
    seen: set[str] = set()
    out: list[DisclosedReport] = []
    keywords: list[str] = []
    if tech_stack:
        keywords.extend(t for t in tech_stack if t)
    if vertical:
        keywords.append(vertical)
    for kw in keywords[:5]:
        try:
            results = h1_client.search_disclosed_reports(
                keyword=kw, limit=limit
            )
        except Exception:
            continue
        for item in results:
            url = str(item.get("url", "") or "")
            program = str(item.get("program", "") or "")
            if not url or url in seen or program == same_program:
                continue
            seen.add(url)
            out.append(DisclosedReport.from_h1(item))
    return out[:limit]


def synthesize_hypothesis_seeds(
    same: list[DisclosedReport],
    similar: list[DisclosedReport],
    coverage_status: str = DEFAULT_COVERAGE_STATUS,
) -> list[str]:
    """Produce free-text hypothesis seeds from the two report buckets.

    PRD R1 + C1: seeds are free text, NOT a fixed taxonomy. The
    generator looks at observed patterns (recurring titles, common
    severities, repeating programs) and emits English sentences. The
    output is NEVER a `[choose one of these]` style menu — Claude
    treats each seed as a starting prompt for a working_hypothesis,
    free to ignore or rewrite.

    `coverage_status` (PR-13) selects the FACTUAL fallback sentence
    when both buckets are empty. The fallback states what the search
    returned and never instructs Claude where to pivot — Claude forms
    its own working_hypothesis from the fact.
    """
    seeds: list[str] = []
    if same:
        for report in same[:3]:
            if not report.title:
                continue
            seeds.append(
                f"Same target previously paid {report.severity} on "
                f"'{report.title[:120]}' ({report.disclosed_at}). "
                f"Consider whether sibling endpoints share that pattern."
            )
    if similar:
        title_counts: dict[str, int] = {}
        for report in similar:
            key = report.title.lower().split(":")[0][:60]
            if key:
                title_counts[key] = title_counts.get(key, 0) + 1
        recurring = sorted(title_counts.items(), key=lambda kv: -kv[1])[:3]
        for key, count in recurring:
            if count < 2:
                continue
            seeds.append(
                f"{count} similar-target reports share pattern '{key}...'. "
                f"This is industry-recurring; map to the current target's "
                f"endpoints with that shape."
            )
        if not recurring or recurring[0][1] < 2:
            for report in similar[:2]:
                if not report.title:
                    continue
                seeds.append(
                    f"Similar target {report.program} paid on "
                    f"'{report.title[:120]}'. Pattern may transfer if the "
                    f"target stack overlaps."
                )
    if not seeds:
        if coverage_status == "mcp_unavailable":
            seeds.append(
                "HackerOne MCP is not connected. Disclosed-pattern data is "
                "unavailable for this run."
            )
        elif coverage_status == "no_mcp_coverage":
            seeds.append(
                "HackerOne MCP returned no records for this target program "
                "handle. The target may not be on a public bug-bounty "
                "platform, or its program may have no disclosed reports yet."
            )
        else:
            seeds.append(
                "No same-target or similar-target reports surfaced. Treat the "
                "absence as a green field — no published pattern to copy."
            )
    return seeds


def render_disclosed_patterns_md(
    target: str,
    same: list[DisclosedReport],
    similar: list[DisclosedReport],
    seeds: list[str],
    coverage_status: str = DEFAULT_COVERAGE_STATUS,
    *,
    same_dedup: list[tuple["DisclosedReport", str]] | None = None,
    similar_dedup: list[tuple["DisclosedReport", str]] | None = None,
    dedup_header: str = "",
) -> str:
    """Render the disclosed_patterns.md document per Contract 1.

    `coverage_status` is rendered as a single header line so Claude can
    distinguish "MCP unavailable" from "MCP returned no rows for this
    target" from "covered" without parsing the body. The status values
    are a fixed internal enum (see `COVERAGE_STATUS_VALUES`); they are
    NOT a Claude-facing menu — Claude reads the line as a fact and
    forms its own hypothesis.

    Dedup metadata (task 05-16-b7-disclosed-pattern-dedup):
      - `same_dedup` / `similar_dedup`: lists of (report, dedup_ref)
        tuples. When `dedup_ref` is non-empty, the row is tagged inline
        with `[DEDUP: matches local pattern <ref>]`.
      - `dedup_header`: header summary section "Pattern dedup: M of N..."
        rendered between the coverage line and the same-target table.
      - When `coverage_status == 'mcp_unavailable'`, dedup is omitted
        regardless of these inputs (per task C4).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build quick-lookup maps so the inline tag rendering stays O(1)
    same_tag_map: dict[int, str] = {}
    similar_tag_map: dict[int, str] = {}
    show_dedup = coverage_status != "mcp_unavailable"
    if show_dedup:
        if same_dedup:
            for idx, (_, ref) in enumerate(same_dedup):
                if ref:
                    same_tag_map[idx] = ref
        if similar_dedup:
            for idx, (_, ref) in enumerate(similar_dedup):
                if ref:
                    similar_tag_map[idx] = ref

    lines: list[str] = []
    lines.append(f"# Disclosed Patterns — {target}")
    lines.append("")
    lines.append(f"_Last updated: {now}_")
    lines.append(
        f"_Same-target reports: {len(same)} | "
        f"Similar-target reports: {len(similar)} | "
        f"Hypothesis seeds: {len(seeds)}_"
    )
    lines.append(f"_MCP coverage: {coverage_status}_")
    lines.append("")
    if show_dedup and dedup_header:
        lines.append(dedup_header)
        lines.append("")
    lines.append(
        "> Horizontal pattern transfer from HackerOne hacktivity. These are "
        "NOT findings on this target — they are starting points for "
        "working_hypothesis generation."
    )
    lines.append("")

    lines.append("## Same-target reports")
    lines.append("")
    if same:
        lines.append("| Date | Severity | State | Title | URL |")
        lines.append("|---|---|---|---|---|")
        for idx, report in enumerate(same):
            title = (report.title or "").replace("|", "\\|")
            tag = same_tag_map.get(idx, "")
            tag_suffix = f" [DEDUP: matches local pattern {tag}]" if tag else ""
            lines.append(
                f"| {report.disclosed_at} | {report.severity} | "
                f"{report.state} | {title[:80]}{tag_suffix} | {report.url} |"
            )
    else:
        lines.append("_No same-target reports surfaced from HackerOne._")
    lines.append("")

    lines.append("## Similar-target reports (matched by tech stack / industry)")
    lines.append("")
    if similar:
        lines.append("| Program | Severity | Date | Title | URL |")
        lines.append("|---|---|---|---|---|")
        for idx, report in enumerate(similar):
            title = (report.title or "").replace("|", "\\|")
            program_disp = report.program_name or report.program
            tag = similar_tag_map.get(idx, "")
            tag_suffix = f" [DEDUP: matches local pattern {tag}]" if tag else ""
            lines.append(
                f"| {program_disp} | {report.severity} | "
                f"{report.disclosed_at} | {title[:80]}{tag_suffix} | {report.url} |"
            )
    else:
        lines.append("_No similar-target reports surfaced (no tech-stack hint or empty results)._")
    lines.append("")

    lines.append("## Inferred hypothesis seeds")
    lines.append("")
    for idx, seed in enumerate(seeds, 1):
        lines.append(f"{idx}. {seed}")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _load_tech_stack_hint(repo_root: Path, target: str) -> list[str]:
    try:
        from tools.technology_inventory import component_labels, load_or_build_inventory
    except ImportError:  # pragma: no cover - direct tools/ execution
        from technology_inventory import component_labels, load_or_build_inventory
    try:
        inventory = load_or_build_inventory(repo_root, target)
    except (OSError, ValueError):
        return []
    return component_labels(inventory, include_versions=False, limit=10)


def write_disclosed_patterns(
    target: str,
    repo_root: Path | str | None = None,
    *,
    output_path: Path | str | None = None,
    cache_ttl_hours: float = DEFAULT_CACHE_TTL_HOURS,
    no_mcp: bool = False,
) -> Path:
    """Run the full pipeline; write evidence/<target>/disclosed_patterns.md."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)

    h1_client = None if no_mcp else _load_h1_client()
    cache = _load_cache(repo, resolved_target, cache_ttl_hours) if not no_mcp else None

    if cache:
        same = [DisclosedReport(**item) for item in cache.get("same", [])]
        similar = [DisclosedReport(**item) for item in cache.get("similar", [])]
        coverage_status = cache.get("coverage_status")
        if coverage_status not in COVERAGE_STATUS_VALUES:
            # Backward-compat for caches written before PR-13: derive a
            # status from the cached buckets so old caches don't crash.
            coverage_status = "covered" if (same or similar) else "no_mcp_coverage"
    else:
        tech_stack = _load_tech_stack_hint(repo, target_key)
        same = search_same_target(resolved_target, h1_client=h1_client)
        similar = search_similar_targets(
            resolved_target, tech_stack=tech_stack, h1_client=h1_client
        )
        if h1_client is None:
            coverage_status = "mcp_unavailable"
        elif not same and not similar:
            coverage_status = "no_mcp_coverage"
        else:
            coverage_status = "covered"
        if not no_mcp:
            _save_cache(repo, resolved_target, {
                "target": resolved_target,
                "same": [vars(r) for r in same],
                "similar": [vars(r) for r in similar],
                "coverage_status": coverage_status,
            })

    seeds = synthesize_hypothesis_seeds(same, similar, coverage_status)

    # B7: dedup against hunt-memory/patterns.jsonl before render. Skip when
    # MCP is unavailable — there is nothing to dedup against anyway.
    if coverage_status != "mcp_unavailable":
        tech_stack_for_dedup = _load_tech_stack_hint(repo, target_key)
        same_dedup, same_stats = _dedup_against_local(
            reports=same, target=resolved_target,
            tech_stack=tech_stack_for_dedup, repo_root=repo,
        )
        similar_dedup, similar_stats = _dedup_against_local(
            reports=similar, target=resolved_target,
            tech_stack=tech_stack_for_dedup, repo_root=repo,
        )
        dedup_header = _format_dedup_header(same_stats, similar_stats)
    else:
        same_dedup = None
        similar_dedup = None
        dedup_header = ""

    md = render_disclosed_patterns_md(
        resolved_target, same, similar, seeds, coverage_status,
        same_dedup=same_dedup, similar_dedup=similar_dedup,
        dedup_header=dedup_header,
    )

    if output_path is None:
        out_dir = repo / "evidence" / target_key
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / "disclosed_patterns.md"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")
    return output_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="HackerOne disclosed-pattern horizontal transfer for a target."
    )
    parser.add_argument("--target", required=True, help="target domain (e.g. example.com)")
    parser.add_argument(
        "--cache-ttl-hours",
        type=float,
        default=DEFAULT_CACHE_TTL_HOURS,
        help=f"cache time-to-live in hours (default: {DEFAULT_CACHE_TTL_HOURS})",
    )
    parser.add_argument(
        "--no-mcp",
        action="store_true",
        help="skip HackerOne MCP; produces an empty-shape document",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="output path (default: evidence/<target>/disclosed_patterns.md)",
    )
    parser.add_argument(
        "--repo-root",
        default=str(BASE_DIR),
        help="repository root (default: parent of this file)",
    )
    args = parser.parse_args(argv)

    out = write_disclosed_patterns(
        args.target,
        repo_root=args.repo_root,
        output_path=args.output,
        cache_ttl_hours=args.cache_ttl_hours,
        no_mcp=args.no_mcp,
    )
    print(f"disclosed_patterns written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
