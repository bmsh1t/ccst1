#!/usr/bin/env python3
"""
intelligence_extractor.py — extract non-vulnerability intelligence from recon
artifacts.

Purpose:
    Senior hunters collect ~80% of their working knowledge as
    NON-finding intelligence: employee emails, internal hostnames,
    webhook URL formats, customer names, internal API path
    conventions, source code snippets, etc. These are not bugs,
    but they are AMMO for the next hypothesis.

    This module mines the cached recon / JS / source artifacts for
    such intelligence and writes a structured markdown file the
    agent can consult during a hunt.

Design notes:
    - Pure extractor — no vulnerability judgments, no scoring.
    - Idempotent — re-running overwrites the file with current state.
    - Deterministic — same input always produces same output (sorted).
    - Resilient — missing input files degrade gracefully (skip silently).
    - Each extracted item records its source file path for traceability.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
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


MANAGED_SECTION_PREFIX = "ccst:intelligence"

# Each extractor: (category_name, compiled_regex, value_group_index_or_full)
# Order matters only for output ordering.
EXTRACTORS: list[tuple[str, re.Pattern, int]] = [
    # Emails — most useful for SSO probing, OSINT pivots
    ("emails", re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"), 0),
    # Internal / staging / dev hostnames
    (
        "internal_hostnames",
        re.compile(
            r"\b(?:internal|intranet|staging|dev|stage|qa|test|preprod|admin)"
            r"[A-Za-z0-9.-]*\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            re.IGNORECASE,
        ),
        0,
    ),
    # Webhook / callback URL patterns
    (
        "webhook_urls",
        re.compile(
            r"https?://[A-Za-z0-9.-]+/(?:webhook|hook|callback|notify)/[A-Za-z0-9_/-]+",
            re.IGNORECASE,
        ),
        0,
    ),
    # API key / token prefixes (DO NOT capture the full secret value —
    # we record the prefix family as evidence "secrets exist here, go look")
    (
        "secret_prefixes",
        re.compile(
            r"\b(?:sk_live|sk_test|pk_live|pk_test|AKIA[A-Z0-9]{4,}|"
            r"ghp_[A-Za-z0-9]{4,}|gho_[A-Za-z0-9]{4,}|xox[bao]-[A-Za-z0-9-]{4,}|"
            r"AIza[A-Za-z0-9_-]{4,})"
        ),
        0,
    ),
    # Customer / organization mentions in JSON-like contexts
    (
        "customer_mentions",
        re.compile(
            r'"(?:customer(?:_id|_name|Name|Id)?|client(?:Name|Id)?|tenant(?:_id|Id)?)"\s*:\s*"([^"]+)"'
        ),
        1,
    ),
    # Internal API path patterns — useful as hypothesis seeds for hidden routes
    (
        "internal_api_paths",
        re.compile(r"(?:^|[\"'\s,])(/(?:internal|admin|_internal|_admin|staff)/[A-Za-z0-9_/-]+)"),
        1,
    ),
    # Employee / dev handles — GitHub/Slack-style @handle in comments,
    # commit messages, or release notes
    (
        "employee_handles",
        re.compile(r'(?:^|[\s,"\'])(@[A-Za-z][A-Za-z0-9-]{2,38})\b'),
        1,
    ),
]


@dataclass
class IntelligenceCorpus:
    """In-memory collection of extracted intelligence across all sources."""

    items: dict[str, dict[str, set[str]]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(set)))

    def add(self, category: str, value: str, source: str) -> None:
        value = value.strip()
        if not value:
            return
        # Skip noise common in marketing/copy
        if category == "emails" and value.lower() in {"name@example.com", "you@example.com", "user@example.com"}:
            return
        self.items[category][value].add(source)

    def counts(self) -> dict[str, int]:
        return {cat: len(values) for cat, values in self.items.items()}

    def categories(self) -> list[str]:
        return [cat for cat, _re, _idx in EXTRACTORS if cat in self.items]


def _iter_text_files(root: Path) -> list[Path]:
    """Return all text-like files under root, with size cap to skip huge artifacts."""
    if not root.exists():
        return []
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_size > 5_000_000:
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".tar"}:
            continue
        out.append(path)
    return out


def _scan_file(path: Path, corpus: IntelligenceCorpus, source_label: str) -> None:
    """Apply every extractor to file contents and feed corpus."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    for category, pattern, group_idx in EXTRACTORS:
        for match in pattern.finditer(text):
            try:
                value = match.group(group_idx) if group_idx else match.group(0)
            except IndexError:
                value = match.group(0)
            corpus.add(category, value, source_label)


def extract_intelligence(
    target: str,
    repo_root: Path | str | None = None,
) -> IntelligenceCorpus:
    """Mine all known recon artifact locations for a target.

    Args:
        target: target domain or storage key (path-safe identifier).
        repo_root: project root containing recon/, findings/, evidence/.

    Returns:
        IntelligenceCorpus with extracted items grouped by category.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    target_key = target_storage_key(target)
    corpus = IntelligenceCorpus()

    candidate_roots = [
        ("recon", repo / "recon" / target_key),
        ("js_intel", repo / "findings" / target_key / "js_intel"),
        ("source_intel", repo / "findings" / target_key / "source_intel"),
        ("findings", repo / "findings" / target_key),
    ]

    for label, root in candidate_roots:
        for file in _iter_text_files(root):
            try:
                rel = str(file.relative_to(repo))
            except ValueError:
                rel = str(file)
            _scan_file(file, corpus, f"{label}:{rel}")

    return corpus


def render_markdown(target: str, corpus: IntelligenceCorpus) -> str:
    """Render an IntelligenceCorpus as a human-readable markdown document."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = corpus.counts()
    total = sum(counts.values())

    lines: list[str] = []
    lines.append(f"# Intelligence — {target}")
    lines.append("")
    lines.append(f"_Last updated: {now}_")
    lines.append(f"_Total items: {total} across {len(counts)} categories_")
    lines.append("")
    lines.append(
        "> Non-vulnerability intelligence harvested from cached recon, JS, and "
        "source artifacts. These are NOT findings — they are ammunition for "
        "the next hypothesis."
    )
    lines.append("")

    if total == 0:
        lines.append("_No intelligence items extracted yet — run recon / JS / source enrichment first._")
        return "\n".join(lines) + "\n"

    pretty = {
        "emails": "Emails",
        "internal_hostnames": "Internal / Staging Hostnames",
        "webhook_urls": "Webhook / Callback URLs",
        "secret_prefixes": "Secret Prefixes (look for the full value at source)",
        "customer_mentions": "Customer / Tenant Mentions",
        "internal_api_paths": "Internal API Path Patterns",
        "employee_handles": "Employee / Dev Handles",
    }

    for category, _pattern, _idx in EXTRACTORS:
        items = corpus.items.get(category)
        if not items:
            continue
        heading = pretty.get(category, category.replace("_", " ").title())
        lines.append(f"## {heading} ({len(items)})")
        lines.append("")
        for value in sorted(items.keys(), key=str.lower):
            sources = sorted(items[value])
            shown_sources = sources[:3]
            more = f" (+{len(sources)-3} more)" if len(sources) > 3 else ""
            sources_str = "; ".join(shown_sources) + more
            lines.append(f"- `{value}` — {sources_str}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def merge_managed_section(
    existing: str,
    section_id: str,
    content: str,
    *,
    legacy_heading_prefix: str = "",
    replace_legacy_intelligence_document: bool = False,
) -> str:
    """把一个受管 section 幂等写入 intelligence.md 文本。

    旧版 extractor 会覆盖整个文档，identity intel 则无 marker 追加在尾部。
    迁移时保留 identity tail；后续重跑只替换对应 section，避免重复或互相覆盖。
    """
    section_id = re.sub(r"[^a-z0-9_-]+", "-", section_id.lower()).strip("-")
    start = f"<!-- {MANAGED_SECTION_PREFIX}:{section_id}:start -->"
    end = f"<!-- {MANAGED_SECTION_PREFIX}:{section_id}:end -->"
    block = f"{start}\n{content.rstrip()}\n{end}\n"
    current = existing or ""

    start_at = current.find(start)
    end_at = current.find(end, start_at + len(start)) if start_at >= 0 else -1
    if start_at >= 0 and end_at >= 0:
        end_at += len(end)
        merged = current[:start_at].rstrip() + "\n\n" + block + current[end_at:].lstrip("\n")
        return merged.strip() + "\n"

    if replace_legacy_intelligence_document and current.lstrip().startswith("# Intelligence —"):
        identity = re.search(r"(?m)^# Identity Intel\b", current)
        tail = current[identity.start():].strip() if identity else ""
        return (block + ("\n" + tail + "\n" if tail else "")).strip() + "\n"

    if legacy_heading_prefix:
        legacy = re.search(rf"(?m)^{re.escape(legacy_heading_prefix)}\b", current)
        if legacy:
            # 旧 identity section 到下一个一级标题或 managed section 为止；
            # 不能为了迁移旧格式而删除其后的 operator/其他 producer 内容。
            tail = current[legacy.end():]
            boundary = re.search(
                rf"(?m)^(?:# (?!#)|<!-- {re.escape(MANAGED_SECTION_PREFIX)}:[^>]+:start -->)",
                tail,
            )
            legacy_end = legacy.end() + boundary.start() if boundary else len(current)
            current = (
                current[:legacy.start()].rstrip()
                + "\n\n"
                + current[legacy_end:].lstrip("\n")
            ).strip()

    if current.strip():
        return current.rstrip() + "\n\n" + block
    return block


def write_intelligence(
    target: str,
    repo_root: Path | str | None = None,
    output_path: Path | str | None = None,
) -> Path:
    """Run extraction and write intelligence.md. Returns the written path."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    corpus = extract_intelligence(resolved_target, repo)
    if output_path is None:
        out_dir = repo / "evidence" / target_key
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / "intelligence.md"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

    rendered = render_markdown(resolved_target, corpus)
    existing = output_path.read_text(encoding="utf-8", errors="replace") if output_path.is_file() else ""
    output_path.write_text(
        merge_managed_section(
            existing,
            "local-extractor",
            rendered,
            replace_legacy_intelligence_document=True,
        ),
        encoding="utf-8",
    )
    return output_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract non-vulnerability intelligence for a target.",
    )
    parser.add_argument("target", help="target domain (e.g. example.com)")
    parser.add_argument(
        "--repo-root",
        default=str(BASE_DIR),
        help="repository root containing recon/, findings/, evidence/",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="output path (default: evidence/<target>/intelligence.md)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit raw extraction counts as JSON to stdout (still writes md)",
    )
    args = parser.parse_args(argv)

    out = write_intelligence(args.target, args.repo_root, args.output)
    if args.json:
        corpus = extract_intelligence(args.target, args.repo_root)
        print(json.dumps({"output": str(out), "counts": corpus.counts()}, indent=2))
    else:
        print(f"intelligence written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
