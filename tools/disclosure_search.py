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
    - Query failures preserve the last complete successful cache; partial
      live reports and stale cached material remain explicitly distinguishable.
    - Report tables preserve source metadata; hypothesis generation stays
      with Claude rather than being inferred from report titles.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import shlex
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.artifact_io import write_text_atomic
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_text_atomic
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
        if not isinstance(item, dict):
            raise ValueError("report must be an object")
        for name in cls.__dataclass_fields__:
            if item.get(name) is not None and not isinstance(item[name], str):
                raise ValueError(f"report.{name} must be a string or null")
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


def _parse_reports(items) -> list[DisclosedReport]:
    if not isinstance(items, list):
        raise ValueError("reports must be a list")
    return [DisclosedReport.from_h1(item) for item in items]


def _diagnostic(identity: str, error: Exception) -> str:
    return " ".join(f"{identity}: {type(error).__name__}: {error}".split())[:500]


def _load_cache(repo_root: Path, target: str) -> dict | None:
    try:
        payload = json.loads(_cache_path(repo_root, target).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(payload, dict):
        raise ValueError("cache root must be an object")
    if "target" in payload and payload["target"] != target:
        raise ValueError("cache target does not match requested target")
    _parse_reports(payload.get("same"))
    _parse_reports(payload.get("similar"))
    timestamp = payload.get("cached_at_ts")
    if isinstance(timestamp, bool) or not isinstance(timestamp, (str, int, float)):
        raise ValueError("cache cached_at_ts must be a numeric timestamp")
    timestamp = float(timestamp)
    if not math.isfinite(timestamp):
        raise ValueError("cache cached_at_ts must be finite")
    datetime.fromtimestamp(timestamp, timezone.utc)
    coverage = payload.get("coverage_status")
    if coverage == "mcp_unavailable":
        raise ValueError("cache records an unavailable query, not a successful snapshot")
    if "coverage_status" not in payload:
        payload["coverage_status"] = "covered" if payload["same"] or payload["similar"] else "no_mcp_coverage"
    elif coverage not in COVERAGE_STATUS_VALUES:
        raise ValueError("cache coverage_status must record a complete successful query")
    return payload


def _save_cache(repo_root: Path, target: str, payload: dict) -> None:
    payload = {**payload, "cached_at_ts": payload.get("cached_at_ts", time.time())}
    write_text_atomic(_cache_path(repo_root, target), json.dumps(payload, indent=2))


@dataclass
class QueryResult:
    reports: list[DisclosedReport] = field(default_factory=list)
    successes: int = 0
    errors: list[str] = field(default_factory=list)


def _query_reports(h1_client, identity: str, **kwargs) -> QueryResult:
    # A failed request contributes no rows, but independent requests still run.
    try:
        reports = _parse_reports(h1_client.search_disclosed_reports(**kwargs))
        return QueryResult(reports, 1)
    except Exception as error:
        return QueryResult(errors=[_diagnostic(identity, error)])


def search_same_target(target: str, h1_client=None, limit: int = 15) -> QueryResult:
    """Try the program handle, then the target keyword if no reports surfaced."""
    if h1_client is None:
        h1_client = _load_h1_client()
    program_handle = target.split(".")[0]
    result = _query_reports(h1_client, f"same program={program_handle}", program=program_handle, limit=limit)
    if not result.reports:
        fallback = _query_reports(h1_client, f"same keyword={target}", keyword=target, limit=limit)
        result.reports = fallback.reports
        result.successes += fallback.successes
        result.errors.extend(fallback.errors)
    return result


def search_similar_targets(
    target: str,
    tech_stack: list[str] | None = None,
    vertical: str = "",
    h1_client=None,
    limit: int = 15,
) -> QueryResult:
    """Query up to five keywords; dedupe URLs and exclude the same program."""
    if h1_client is None:
        h1_client = _load_h1_client()
    same_program = target.split(".")[0]
    seen: set[str] = set()
    result = QueryResult()
    keywords = [value for value in (tech_stack or []) if value]
    if vertical:
        keywords.append(vertical)
    for keyword in keywords[:5]:
        query = _query_reports(h1_client, f"similar keyword={keyword}", keyword=keyword, limit=limit)
        result.successes += query.successes
        result.errors.extend(query.errors)
        for report in query.reports:
            if not report.url or report.url in seen or report.program == same_program:
                continue
            seen.add(report.url)
            result.reports.append(report)
    result.reports = result.reports[:limit]
    return result


def render_disclosed_patterns_md(
    target: str,
    same: list[DisclosedReport],
    similar: list[DisclosedReport],
    coverage_status: str = DEFAULT_COVERAGE_STATUS,
    *,
    repo_root: Path | str = BASE_DIR,
    query_status: str | None = None,
    material_source: str = "live",
    material_queried_at: float | None = None,
    material_stale: bool = False,
    diagnostics: list[str] | None = None,
) -> str:
    """Render the disclosed_patterns.md document per Contract 1.

    `coverage_status` is rendered as a single header line so Claude can
    distinguish "MCP unavailable" from "MCP returned no rows for this
    target" from "covered" without parsing the body. The status values
    use `COVERAGE_STATUS_VALUES` for complete material; partial live
    material has a render-only partial value. Query status and material age
    remain separate facts, not a Claude-facing menu.

    Local experience is queried explicitly through the Store recall command;
    title/category similarity does not establish duplicate evidence.
    """
    now = datetime.fromtimestamp(time.time(), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append(f"# Disclosed Patterns — {target}")
    lines.append("")
    lines.append(f"_Generated at: {now}_")
    if query_status is not None:
        lines.append(f"_Query status: {query_status}_")
        lines.append(f"_Material source: {material_source}_")
        queried_at = (
            datetime.fromtimestamp(material_queried_at, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if material_queried_at is not None else "unknown"
        )
        subset = " (successful subset only)" if query_status == "partial" and material_source == "live" else ""
        lines.append(f"_Material queried at: {queried_at}{subset}_")
        lines.append(f"_Material stale: {'yes' if material_stale else 'no'}_")
    lines.append(
        f"_Same-target reports: {len(same)} | "
        f"Similar-target reports: {len(similar)}_"
    )
    lines.append(f"_MCP coverage: {coverage_status}_")
    if query_status == "skipped":
        lines.append("_MCP explicitly skipped; cache was not read._")
    elif material_source == "none":
        lines.append("_No usable disclosure material available; this is not a successful zero-result query._")
    elif query_status == "complete" and not same and not similar:
        lines.append("_All executed queries succeeded with zero reports._")
    if diagnostics:
        lines.extend(["", "## Query / cache diagnostics", ""])
        lines.extend(f"- {diagnostic}" for diagnostic in diagnostics)
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
    if not math.isfinite(cache_ttl_hours):
        raise ValueError("cache TTL must be finite")
    repo = Path(repo_root) if repo_root else BASE_DIR
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)

    cache = None
    diagnostics: list[str] = []
    same, similar = [], []
    coverage_status = "mcp_unavailable"
    query_status = "skipped" if no_mcp else "unavailable"
    source, queried_at, stale = "none", None, False
    if not no_mcp:
        try:
            cache = _load_cache(repo, resolved_target)
        except (OSError, ValueError, TypeError, OverflowError) as error:
            diagnostics.append(_diagnostic("cache", error))
        if cache is not None:
            queried_at = float(cache["cached_at_ts"])
            stale = cache_ttl_hours <= 0 or time.time() - queried_at > cache_ttl_hours * 3600
        if cache is not None and not stale:
            query_status = "cached"
        else:
            h1_client = _load_h1_client()
            if h1_client is None:
                diagnostics.append("client: Unavailable: HackerOne client could not be loaded")
            else:
                tech_stack = _load_tech_stack_hint(repo, target_key)
                same_result = search_same_target(resolved_target, h1_client=h1_client)
                similar_result = search_similar_targets(
                    resolved_target, tech_stack=tech_stack, h1_client=h1_client,
                )
                same, similar = same_result.reports, similar_result.reports
                errors = same_result.errors + similar_result.errors
                diagnostics.extend(errors)
                successes = same_result.successes + similar_result.successes
                query_status = "partial" if errors and successes else "unavailable" if errors else "complete"
                if query_status == "complete" or same or similar:
                    source, queried_at, stale = "live", time.time(), False
                    coverage_status = "partial" if errors else "covered" if same or similar else "no_mcp_coverage"
                if query_status == "complete":
                    _save_cache(repo, resolved_target, {
                        "target": resolved_target,
                        "same": [vars(report) for report in same],
                        "similar": [vars(report) for report in similar],
                        "coverage_status": coverage_status,
                        "cached_at_ts": queried_at,
                    })
        if source != "live" and cache is not None:
            same, similar = _parse_reports(cache["same"]), _parse_reports(cache["similar"])
            coverage_status = cache["coverage_status"]
            source = "cache"

    md = render_disclosed_patterns_md(
        resolved_target, same, similar, coverage_status, repo_root=repo,
        query_status=query_status, material_source=source, material_queried_at=queried_at,
        material_stale=stale, diagnostics=diagnostics,
    )
    output_path = Path(output_path) if output_path is not None else repo / "evidence" / target_key / "disclosed_patterns.md"
    write_text_atomic(output_path, md)
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
