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
import shlex
import sys
import time
from dataclasses import dataclass
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
    repo_root: Path | str = BASE_DIR,
) -> str:
    """Render the disclosed_patterns.md document per Contract 1.

    `coverage_status` is rendered as a single header line so Claude can
    distinguish "MCP unavailable" from "MCP returned no rows for this
    target" from "covered" without parsing the body. The status values
    are a fixed internal enum (see `COVERAGE_STATUS_VALUES`); they are
    NOT a Claude-facing menu — Claude reads the line as a fact and
    forms its own hypothesis.

    Local experience is queried explicitly through the Store recall command;
    title/category similarity does not establish duplicate evidence.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

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
        for report in same:
            title = (report.title or "").replace("|", "\\|")
            lines.append(
                f"| {report.disclosed_at} | {report.severity} | "
                f"{report.state} | {title[:80]} | {report.url} |"
            )
    else:
        lines.append("_No same-target reports surfaced from HackerOne._")
    lines.append("")

    lines.append("## Similar-target reports (matched by tech stack / industry)")
    lines.append("")
    if similar:
        lines.append("| Program | Severity | Date | Title | URL |")
        lines.append("|---|---|---|---|---|")
        for report in similar:
            title = (report.title or "").replace("|", "\\|")
            program_disp = report.program_name or report.program
            lines.append(
                f"| {program_disp} | {report.severity} | "
                f"{report.disclosed_at} | {title[:80]} | {report.url} |"
            )
    else:
        lines.append("_No similar-target reports surfaced (no tech-stack hint or empty results)._")
    lines.append("")

    lines.append("## Target memory")
    lines.append("")
    lines.append("Compare these reports with saved target experience and reviewed knowledge:")
    lines.append("")
    lines.append("```bash")
    lines.append(shlex.join([
        "python3", "tools/experience_recall.py", "--repo-root", str(Path(repo_root).resolve()),
        "--target", target,
    ]))
    lines.append("```")
    lines.append("Title or vulnerability-class similarity alone does not establish a duplicate.")
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
        if h1_client is None:
            same, similar = [], []
            coverage_status = "mcp_unavailable"
        else:
            tech_stack = _load_tech_stack_hint(repo, target_key)
            same = search_same_target(resolved_target, h1_client=h1_client)
            similar = search_similar_targets(
                resolved_target, tech_stack=tech_stack, h1_client=h1_client
            )
            coverage_status = "covered" if same or similar else "no_mcp_coverage"
        if not no_mcp:
            _save_cache(repo, resolved_target, {
                "target": resolved_target,
                "same": [vars(r) for r in same],
                "similar": [vars(r) for r in similar],
                "coverage_status": coverage_status,
            })

    seeds = synthesize_hypothesis_seeds(same, similar, coverage_status)

    md = render_disclosed_patterns_md(
        resolved_target, same, similar, seeds, coverage_status, repo_root=repo,
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
