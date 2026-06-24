#!/usr/bin/env python3
"""
fresh_code.py — 90-day code-freshness signals for a target.

Purpose:
    Bug density in newly-shipped code is ~10x higher than in mature
    code. Senior hunters know this and prioritize "what changed
    recently" before testing legacy paths. This tool surfaces three
    signals:

      (a) New subdomains in the last 90 days (Certificate Transparency
          log via crt.sh)
      (b) Changelog / blog / status entries (best-effort fetch of
          common paths)
      (c) GitHub org recent commit activity (last 90 days)

    Output is `evidence/<target>/fresh_code.md`. The tool is NOT
    auto-invoked; Claude calls it when working_hypothesis matches the
    "what new attack surface appeared recently?" question in the
    Q->Tool table.

Design notes:
    - Pure HTTP, no MCP dependency.
    - 30s timeout per external call (Risk R-B).
    - GitHub uses GITHUB_TOKEN if present; degrades cleanly when
      rate-limited (Risk R-C).
    - Each section may be empty — output document still lists all 3
      headers (anchor-driven, not data-driven).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

CT_TIMEOUT_SEC = 30
WEB_TIMEOUT_SEC = 15
GITHUB_TIMEOUT_SEC = 20
USER_AGENT = "claude-bb-fresh-code/1.0"

COMMON_CHANGELOG_PATHS = (
    "/changelog",
    "/changelog.html",
    "/changelog/",
    "/blog",
    "/blog/",
    "/news",
    "/news/",
    "/status",
    "/whats-new",
    "/what-s-new",
    "/release-notes",
)


def _http_get(url: str, timeout: int, extra_headers: dict | None = None) -> tuple[int, bytes]:
    """Plain GET with timeout. Returns (status, body). Catches all errors → (0, b'')."""
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:
            body = b""
        return exc.code, body
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return 0, b""


def fetch_ct_log_subdomains(target: str, days: int = 90) -> dict:
    """Fetch new subdomains in last `days` from crt.sh JSON API.

    Returns dict with:
      - subdomains: list of {name, cert_date}
      - status: "ok" | "empty" | "error: <reason>"
    """
    if not target:
        return {"subdomains": [], "status": "error: empty target"}
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    status, body = _http_get(url, CT_TIMEOUT_SEC)
    if status != 200 or not body:
        return {"subdomains": [], "status": f"error: crt.sh returned {status}"}
    try:
        data = json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {"subdomains": [], "status": "error: crt.sh response not JSON"}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date()
    seen: dict[str, str] = {}
    for row in data if isinstance(data, list) else []:
        not_before = str(row.get("not_before", ""))[:10]
        if not not_before:
            continue
        try:
            cert_date = datetime.strptime(not_before, "%Y-%m-%d").date()
        except ValueError:
            continue
        if cert_date < cutoff:
            continue
        names_blob = str(row.get("name_value", "")) or str(row.get("common_name", ""))
        for raw_name in names_blob.split("\n"):
            name = raw_name.strip().lower()
            if not name or "*" in name or " " in name:
                continue
            if not name.endswith(target.lower()):
                continue
            # earliest cert date wins
            existing = seen.get(name)
            if existing is None or not_before < existing:
                seen[name] = not_before
    subdomains = sorted(
        ({"name": n, "cert_date": d} for n, d in seen.items()),
        key=lambda item: item["cert_date"],
        reverse=True,
    )
    return {
        "subdomains": subdomains,
        "status": "ok" if subdomains else "empty",
    }


def fetch_changelog_highlights(target: str, days: int = 90) -> dict:
    """Best-effort fetch of common changelog paths.

    Returns dict with:
      - highlights: list of {url, snippet}
      - status: "ok" | "empty" | "error: <reason>"
    """
    if not target:
        return {"highlights": [], "status": "error: empty target"}
    highlights: list[dict] = []
    for path in COMMON_CHANGELOG_PATHS:
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}{path}"
            status, body = _http_get(url, WEB_TIMEOUT_SEC)
            if status != 200 or not body:
                continue
            text = body.decode("utf-8", errors="ignore")
            # Extract any visible date-prefixed lines or h2/h3 headings
            snippets = _extract_changelog_snippets(text, days)
            if not snippets:
                continue
            for snippet in snippets[:3]:
                highlights.append({"url": url, "snippet": snippet})
            break  # success on this path; try the next path
    return {
        "highlights": highlights,
        "status": "ok" if highlights else "empty",
    }


def _extract_changelog_snippets(html: str, days: int) -> list[str]:
    """Pull date-prefixed headings or h2/h3 text from changelog HTML."""
    out: list[str] = []
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=days)

    # h2 / h3 with date-ish content
    heading_re = re.compile(r"<h[23][^>]*>(.{1,200}?)</h[23]>", re.IGNORECASE | re.DOTALL)
    for match in heading_re.findall(text):
        plain = re.sub(r"<[^>]+>", "", match).strip()
        if not plain:
            continue
        # Try to find a date in the heading
        date_match = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", plain)
        if date_match:
            try:
                y, m, d = map(int, date_match.groups())
                if datetime(y, m, d, tzinfo=timezone.utc).date() < cutoff:
                    continue
            except ValueError:
                pass
        out.append(plain[:200])
        if len(out) >= 5:
            break
    return out


def fetch_github_org_activity(org: str, days: int = 90) -> dict:
    """Fetch GitHub org's repos and count commits in last `days`.

    Returns dict with:
      - repos: list of {repo, recent_commits, last_commit_date}
      - status: "ok" | "empty" | "no_org" | "rate_limited" | "error: <reason>"
    """
    if not org:
        return {"repos": [], "status": "no_org"}
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Fetch first page of repos for the org (max 30)
    repos_url = f"https://api.github.com/orgs/{org}/repos?per_page=30&sort=pushed"
    status, body = _http_get(repos_url, GITHUB_TIMEOUT_SEC, headers)
    if status == 403:
        return {"repos": [], "status": "rate_limited"}
    if status == 404:
        return {"repos": [], "status": "no_org"}
    if status != 200 or not body:
        return {"repos": [], "status": f"error: github returned {status}"}
    try:
        repos = json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {"repos": [], "status": "error: github response not JSON"}
    if not isinstance(repos, list):
        return {"repos": [], "status": "empty"}

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out: list[dict] = []
    for repo in repos[:10]:  # cap to avoid rate limit
        name = str(repo.get("name", "")).strip()
        pushed_at = str(repo.get("pushed_at", ""))
        if not name:
            continue
        try:
            last_push = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        except ValueError:
            last_push = None
        if last_push and last_push < cutoff:
            continue
        # Count commits in window
        full_name = repo.get("full_name", f"{org}/{name}")
        since_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        commits_url = f"https://api.github.com/repos/{full_name}/commits?since={since_iso}&per_page=100"
        cs, cb = _http_get(commits_url, GITHUB_TIMEOUT_SEC, headers)
        if cs == 403:
            return {"repos": out, "status": "rate_limited"}
        if cs != 200:
            continue
        try:
            commits = json.loads(cb.decode("utf-8", errors="ignore"))
        except json.JSONDecodeError:
            commits = []
        count = len(commits) if isinstance(commits, list) else 0
        if count == 0:
            continue
        out.append({
            "repo": name,
            "full_name": full_name,
            "recent_commits": count,
            "last_commit_date": pushed_at[:10],
        })
    return {
        "repos": out,
        "status": "ok" if out else "empty",
    }


def _detect_github_org(target: str, repo_root: Path) -> str:
    """Best-effort: look in business_model.md / intelligence.md for a github.com org."""
    pattern = re.compile(r"github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})", re.IGNORECASE)
    for filename in ("business_model.md", "intelligence.md"):
        path = repo_root / "evidence" / target / filename
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        match = pattern.search(text)
        if match:
            org = match.group(1)
            if org.lower() not in {"orgs", "topics", "search", "explore"}:
                return org
    return ""


def render_fresh_code_md(
    target: str,
    ct: dict,
    changelog: dict,
    github: dict,
) -> str:
    """Render the fresh_code.md document. Always emits all 3 section headers."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append(f"# Fresh Code (last 90 days) — {target}")
    lines.append("")
    lines.append(f"_Last updated: {now}_")
    lines.append("")
    lines.append(
        "> 90-day code-freshness signals. Recent code carries ~10x higher "
        "bug density than mature code; prioritize what changed."
    )
    lines.append("")

    ct_subs = ct.get("subdomains", [])
    lines.append(f"## New subdomains (CT log, {len(ct_subs)} entries)")
    lines.append("")
    if ct_subs:
        for entry in ct_subs[:30]:
            lines.append(f"- `{entry['name']}` (cert {entry['cert_date']})")
    else:
        status = ct.get("status", "empty")
        if status.startswith("error"):
            lines.append(f"_CT log unavailable: {status[7:]}; retry later._")
        else:
            lines.append("_No new subdomains in CT log for last 90 days._")
    lines.append("")

    cl_hl = changelog.get("highlights", [])
    lines.append(f"## Changelog highlights ({len(cl_hl)} entries)")
    lines.append("")
    if cl_hl:
        for entry in cl_hl[:15]:
            url = entry.get("url", "")
            snippet = entry.get("snippet", "").replace("\n", " ")[:200]
            lines.append(f"- {snippet} ([source]({url}))")
    else:
        lines.append("_No accessible changelog / blog / status / what's-new pages found._")
    lines.append("")

    gh_repos = github.get("repos", [])
    gh_status = github.get("status", "")
    lines.append(f"## GitHub recent activity ({len(gh_repos)} entries)")
    lines.append("")
    if gh_repos:
        for entry in gh_repos[:10]:
            lines.append(
                f"- `{entry['full_name']}`: {entry['recent_commits']} "
                f"commits in last 90d (last push {entry['last_commit_date']})"
            )
    elif gh_status == "no_org":
        lines.append("_No public GitHub org known for this target._")
    elif gh_status == "rate_limited":
        lines.append("_Public GitHub API rate limit hit; retry later (or set GITHUB_TOKEN env)._")
    else:
        lines.append("_No recent GitHub org activity found in the last 90 days._")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_fresh_code(
    target: str,
    repo_root: Path | str | None = None,
    *,
    days: int = 90,
    skip_github: bool = False,
    skip_network: bool = False,
    output_path: Path | str | None = None,
) -> Path:
    """Run the 3 fetches and write evidence/<target>/fresh_code.md."""
    repo = Path(repo_root) if repo_root else BASE_DIR

    if skip_network:
        ct = {"subdomains": [], "status": "empty"}
        changelog = {"highlights": [], "status": "empty"}
        github = {"repos": [], "status": "no_org"}
    else:
        ct = fetch_ct_log_subdomains(target, days)
        changelog = fetch_changelog_highlights(target, days)
        if skip_github:
            github = {"repos": [], "status": "no_org"}
        else:
            org = _detect_github_org(target, repo)
            github = fetch_github_org_activity(org, days) if org else {"repos": [], "status": "no_org"}

    md = render_fresh_code_md(target, ct, changelog, github)

    if output_path is None:
        out_dir = repo / "evidence" / target
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / "fresh_code.md"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")
    return output_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="90-day code-freshness signals (CT log + changelog + GitHub)."
    )
    parser.add_argument("--target", required=True, help="target domain")
    parser.add_argument("--days", type=int, default=90, help="lookback window (default 90)")
    parser.add_argument("--no-github", action="store_true", help="skip GitHub fetch")
    parser.add_argument("--no-network", action="store_true", help="produce empty-shape document")
    parser.add_argument("--output", default=None, help="output path")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    args = parser.parse_args(argv)

    out = write_fresh_code(
        args.target,
        repo_root=args.repo_root,
        days=args.days,
        skip_github=args.no_github,
        skip_network=args.no_network,
        output_path=args.output,
    )
    print(f"fresh_code written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
