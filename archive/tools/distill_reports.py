#!/usr/bin/env python3
"""
distill_reports.py — corpus-scoped knowledge distillation from disclosed reports.

Purpose:
    Turn a large corpus of disclosed HackerOne reports into a small set of
    *knowledge-card candidates* that are worth teaching Claude. This is the
    deterministic half of the `/distill` workflow: it fetches the dataset,
    pre-filters and normalizes reports into scoring batches, and later ingests
    Claude's two-round scoring output into a human-review staging area.

    THIS TOOL NEVER CALLS AN LLM. The two-round value/skill scoring is Claude's
    job (see commands/distill.md + tools/distill_rubrics/*.md). The tool only
    moves and shapes data deterministically, exactly like the rest of tools/.

Scope boundary:
    - `disclosure_search.py` is TARGET-scoped: "what did THIS target / its peers
      already pay on?" — live, small-N, per-hunt intel.
    - `distill_reports.py` is CORPUS-scoped: "across the whole disclosed corpus,
      what reusable thinking is worth a knowledge card?" — offline, large-N,
      reproducible. The two do not overlap and are not merged.

Data source:
    HuggingFace dataset `Hacker0x01/hackerone_disclosed_reports`. Its rows JSON
    viewer is currently broken, so we pull the parquet files directly and parse
    them with a lazily-imported pyarrow (optional dependency). If pyarrow is not
    installed the tool prints an install hint and exits cleanly — it never
    crashes the caller.

Usage:
    python3 tools/distill_reports.py --fetch
    python3 tools/distill_reports.py --prepare --batch-size 25 --max 500
    python3 tools/distill_reports.py --ingest scored_candidates.json

Privacy / red-line discipline:
    - Raw dataset parquet is cached under distill/cache/ which is gitignored.
    - Normalization keeps only a whitelist of technical fields; reporter/team
      PII, profile URLs, and structured_scope blobs are dropped.
    - Ingested candidates store DISTILLED THINKING (原理 / 触发信号 / 发散问题 /
      停止条件), never raw report bodies, payloads, credentials, or PII. Long
      token-like strings and emails are scrubbed as a backstop.
    - Candidates land in knowledge/candidates/ (a review queue), never directly
      in knowledge/cards/. Human promotion via /kb promote is the only path in.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.knowledge_candidates import register_corpus_candidate
    from tools.knowledge_registry import SOURCE_REF_CORPUS, SOURCE_REF_TYPE
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_candidates import register_corpus_candidate  # type: ignore
    from knowledge_registry import SOURCE_REF_CORPUS, SOURCE_REF_TYPE  # type: ignore

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

CACHE_DIR = REPO_ROOT / "distill" / "cache"
WORK_DIR = REPO_ROOT / "distill" / "work"
CANDIDATES_DIR = REPO_ROOT / "knowledge" / "candidates"
CARDS_DIR = REPO_ROOT / "knowledge" / "cards"

# HuggingFace parquet resolve URLs (rows JSON viewer is broken for this dataset).
HF_REPO = "Hacker0x01/hackerone_disclosed_reports"
HF_PARQUET_FILES = (
    "data/train-00000-of-00001.parquet",
    "data/test-00000-of-00001.parquet",
)
HF_RESOLVE = "https://huggingface.co/datasets/{repo}/resolve/main/{path}"

# Only these fields survive normalization. Everything else (reporter, team,
# profile_picture_urls, structured_scope, vote metadata beyond count) is PII or
# noise for a distillation prompt and is intentionally dropped.
WHITELIST_FIELDS = (
    "id",
    "title",
    "vulnerability_information",
    "substate",
    "weakness",
    "has_bounty",
    "vote_count",
)

# HackerOne redaction placeholder, e.g. {F123456} or {FXXXXXX}.
PLACEHOLDER_RE = re.compile(r"\{F[0-9A-Za-z]+\}")
# Backstop scrubbers for the ingest path (candidates should already be clean).
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")

# Candidate JSON -> card section mapping. Keys are the fields Claude emits in
# round 2; values are the human-facing card headers (aligned to card-template).
CARD_SECTIONS = (
    ("applies_when", "适用场景"),
    ("trigger_signals", "触发信号"),
    ("divergent_questions", "发散问题"),
    ("recommended_actions", "推荐动作"),
    ("related_skills", "关联 Skills"),
    ("stop_conditions", "停止条件"),
    ("validation_requirements", "检查要求"),
    ("promotable_experience", "可晋升经验"),
)


# --------------------------------------------------------------------------- #
# Pure helpers (no pyarrow, no network) — the testable core.
# --------------------------------------------------------------------------- #
def _weakness_name(weakness: Any) -> str:
    """weakness is a dict like {'name': 'IDOR', ...} or None."""
    if isinstance(weakness, dict):
        name = weakness.get("name")
        if isinstance(name, str):
            return name.strip()
    if isinstance(weakness, str):
        return weakness.strip()
    return ""


def is_placeholder_only(text: str) -> bool:
    """True if the text is empty or contains nothing but redaction placeholders."""
    if not text or not text.strip():
        return True
    stripped = PLACEHOLDER_RE.sub("", text)
    return not stripped.strip()


def passes_prefilter(report: dict) -> bool:
    """Cheap deterministic gate before the report reaches the scoring prompt.

    Drops reports with no usable vulnerability_information — the article's rubric
    explicitly scores these as "丢弃，信息不足", so we never spend a scoring slot
    on them.
    """
    info = report.get("vulnerability_information")
    if not isinstance(info, str):
        return False
    return not is_placeholder_only(info)


def normalize_report(report: dict) -> dict:
    """Project a raw dataset row down to the whitelisted technical fields."""
    out: dict[str, Any] = {}
    for field in WHITELIST_FIELDS:
        if field == "weakness":
            out["weakness"] = _weakness_name(report.get("weakness"))
        elif field in report:
            out[field] = report.get(field)
    # Normalize a couple of shapes the scoring prompt relies on.
    if "has_bounty" not in out and "has_bounty?" in report:
        out["has_bounty"] = report.get("has_bounty?")
    return out


def dedupe_by_id(reports: Iterable[dict]) -> list[dict]:
    """Keep the first occurrence of each id; drop rows without an id."""
    seen: set = set()
    out: list[dict] = []
    for report in reports:
        rid = report.get("id")
        if rid is None or rid in seen:
            continue
        seen.add(rid)
        out.append(report)
    return out


def prepare_reports(
    rows: Iterable[dict],
    *,
    max_reports: int | None = None,
    substates: set[str] | None = None,
) -> list[dict]:
    """Full deterministic prepare pipeline: prefilter -> substate -> dedupe -> normalize -> cap."""
    kept: list[dict] = []
    for row in rows:
        if not passes_prefilter(row):
            continue
        if substates:
            state = str(row.get("substate") or "").strip().lower()
            if state not in substates:
                continue
        kept.append(row)
    kept = dedupe_by_id(kept)
    normalized = [normalize_report(r) for r in kept]
    if max_reports is not None and max_reports >= 0:
        normalized = normalized[:max_reports]
    return normalized


def batch_reports(reports: list[dict], size: int) -> list[list[dict]]:
    """Chunk normalized reports into scoring batches of `size`."""
    if size <= 0:
        raise ValueError("batch size must be positive")
    return [reports[i : i + size] for i in range(0, len(reports), size)]


def scrub_text(text: str) -> str:
    """Backstop redaction for anything that reaches a saved candidate card."""
    if not isinstance(text, str):
        return ""
    text = EMAIL_RE.sub("[email-redacted]", text)
    text = TOKEN_RE.sub("[token-redacted]", text)
    return text


def _slug(text: str, fallback: str = "candidate") -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[^\w一-鿿]+", "-", text).strip("-")
    return text[:60] or fallback


def _bullet_block(value: Any) -> str:
    if isinstance(value, list):
        items = [scrub_text(str(v)).strip() for v in value if str(v).strip()]
    elif value:
        items = [scrub_text(str(value)).strip()]
    else:
        items = []
    if not items:
        return "- （待补充）"
    return "\n".join(f"- {item}" for item in items)


def candidate_to_card_md(candidate: dict) -> str:
    """Render a scored candidate into a knowledge-card draft (template-aligned)."""
    title = scrub_text(str(candidate.get("card_title") or candidate.get("knowledge_point") or "未命名候选卡"))
    source_ids = candidate.get("source_report_ids") or []
    if isinstance(source_ids, (int, str)):
        source_ids = [source_ids]
    provenance = ", ".join(str(s) for s in source_ids) if source_ids else "n/a"

    lines = [
        f"# {title}",
        "",
        "> STAGING CANDIDATE — 由 /distill 蒸馏，未经人工复核，禁止直接用于测试。",
        "> 复核通过后经 /kb promote 迁入 knowledge/cards/。",
        "",
        "## 蒸馏元数据",
        "",
        f"- 来源报告: {provenance}",
        f"- value_score: {candidate.get('value_score', 'n/a')}",
        f"- verdict: {scrub_text(str(candidate.get('verdict', 'n/a')))}",
        f"- category: {scrub_text(str(candidate.get('category', 'n/a')))}",
        f"- worth_skill: {candidate.get('worth_skill', 'n/a')}",
        "",
        "## 来源引用（source_refs）",
        "",
    ]
    for source_id in source_ids:
        lines.extend(
            [
                f"- type: {SOURCE_REF_TYPE}",
                f"  corpus: {SOURCE_REF_CORPUS}",
                f'  id: "{scrub_text(str(source_id))}"',
            ]
        )
    if not source_ids:
        lines.append("- （待补充）")
    lines.append("")
    for key, header in CARD_SECTIONS:
        lines.append(f"## {header}")
        lines.append("")
        lines.append(_bullet_block(candidate.get(key)))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _assert_safe_output_dir(out_dir: Path) -> None:
    """Refuse to write candidates directly into the promoted cards directory."""
    out_resolved = out_dir.resolve()
    if out_resolved == CARDS_DIR.resolve() or CARDS_DIR.resolve() in out_resolved.parents:
        raise ValueError(
            "refusing to write distilled candidates into knowledge/cards/; "
            "candidates must land in a staging dir and be promoted via /kb promote"
        )


def ingest_candidates(
    candidates: list[dict],
    out_dir: Path | str = CANDIDATES_DIR,
    *,
    keep_rejected: bool = False,
    register_lifecycle: bool | None = None,
    lifecycle_path: Path | str | None = None,
    repo_root: Path | str | None = None,
) -> list[Path]:
    """Write scored candidates into the staging review queue as card drafts.

    Only candidates with worth_skill truthy are written unless keep_rejected is
    set. Returns the list of written paths.
    """
    out_dir = Path(out_dir)
    _assert_safe_output_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    should_register = register_lifecycle
    if should_register is None:
        should_register = out_dir.resolve() == CANDIDATES_DIR.resolve()
    resolved_repo = Path(repo_root or REPO_ROOT).resolve()
    resolved_lifecycle = Path(lifecycle_path).resolve() if lifecycle_path else None

    written: list[Path] = []
    for idx, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            continue
        if not candidate.get("worth_skill") and not keep_rejected:
            continue
        slug = _slug(str(candidate.get("card_title") or candidate.get("knowledge_point") or ""))
        path = out_dir / f"{slug}.md"
        suffix = 0
        while path.exists():
            suffix += 1
            path = out_dir / f"{slug}-{suffix}.md"
        path.write_text(candidate_to_card_md(candidate), encoding="utf-8")
        if should_register:
            try:
                register_corpus_candidate(
                    path,
                    source_report_ids=candidate.get("source_report_ids") or [],
                    repo_root=resolved_repo,
                    lifecycle_path=resolved_lifecycle,
                )
            except (OSError, ValueError) as exc:
                try:
                    path.unlink()
                except OSError:
                    pass
                raise ValueError(f"failed to register candidate {path.name}: {exc}") from exc
        written.append(path)
    return written


# --------------------------------------------------------------------------- #
# I/O boundary: parquet reading (lazy pyarrow) + network fetch.
# --------------------------------------------------------------------------- #
def load_parquet_rows(path: Path) -> list[dict]:
    """Read a parquet file into a list of dict rows. Lazily imports pyarrow."""
    try:
        import pyarrow.parquet as pq  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "pyarrow is required to read the dataset parquet files.\n"
            "Install it (optional /distill dependency):\n"
            "    pip install pyarrow"
        ) from exc
    table = pq.read_table(path)
    return table.to_pylist()


def fetch_dataset(cache_dir: Path = CACHE_DIR) -> list[Path]:
    """Download the dataset parquet files into the (gitignored) cache dir."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    downloaded: list[Path] = []
    for rel in HF_PARQUET_FILES:
        url = HF_RESOLVE.format(repo=HF_REPO, path=rel)
        dest = cache_dir / Path(rel).name
        print(f"[fetch] {url} -> {dest}")
        urllib.request.urlretrieve(url, dest)  # noqa: S310 - fixed HF host
        downloaded.append(dest)
    return downloaded


def load_cached_rows(cache_dir: Path = CACHE_DIR) -> list[dict]:
    """Load all cached parquet rows (train + test)."""
    rows: list[dict] = []
    for parquet in sorted(cache_dir.glob("*.parquet")):
        rows.extend(load_parquet_rows(parquet))
    return rows


def write_batches(
    reports: list[dict],
    work_dir: Path = WORK_DIR,
    size: int = 25,
) -> dict:
    """Write scoring batches as JSONL + a manifest. Returns the manifest dict."""
    work_dir.mkdir(parents=True, exist_ok=True)
    for stale in work_dir.glob("batch_*.jsonl"):
        stale.unlink()
    batches = batch_reports(reports, size)
    batch_files: list[str] = []
    for i, batch in enumerate(batches):
        name = f"batch_{i:03d}.jsonl"
        (work_dir / name).write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in batch) + "\n",
            encoding="utf-8",
        )
        batch_files.append(name)
    manifest = {
        "total_reports": len(reports),
        "batch_size": size,
        "batch_count": len(batches),
        "batch_files": batch_files,
        "rubrics": [
            "tools/distill_rubrics/round1_value.md",
            "tools/distill_rubrics/round2_skill.md",
        ],
    }
    (work_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _cmd_fetch(args: argparse.Namespace) -> int:
    try:
        paths = fetch_dataset()
    except Exception as exc:  # noqa: BLE001 - report cleanly, never crash caller
        print(f"[fetch] failed: {exc}", file=sys.stderr)
        return 1
    print(f"[fetch] cached {len(paths)} parquet file(s) under {CACHE_DIR}")
    return 0


def _cmd_prepare(args: argparse.Namespace) -> int:
    try:
        rows = load_cached_rows()
    except RuntimeError as exc:  # pyarrow missing
        print(str(exc), file=sys.stderr)
        return 2
    if not rows:
        print(
            f"[prepare] no cached parquet under {CACHE_DIR}. Run `--fetch` first.",
            file=sys.stderr,
        )
        return 1
    substates = None
    if args.substate:
        substates = {s.strip().lower() for s in args.substate.split(",") if s.strip()}
    reports = prepare_reports(rows, max_reports=args.max, substates=substates)
    manifest = write_batches(reports, size=args.batch_size)
    print(
        f"[prepare] {manifest['total_reports']} reports -> "
        f"{manifest['batch_count']} batch(es) of {manifest['batch_size']} in {WORK_DIR}"
    )
    print(f"[prepare] score each batch with: {', '.join(manifest['rubrics'])}")
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    src = Path(args.ingest)
    if not src.is_file():
        print(f"[ingest] no such file: {src}", file=sys.stderr)
        return 1
    try:
        payload = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[ingest] invalid JSON: {exc}", file=sys.stderr)
        return 1
    if isinstance(payload, dict):
        candidates = payload.get("candidates") or payload.get("detailed_evaluations") or [payload]
    elif isinstance(payload, list):
        candidates = payload
    else:
        print("[ingest] unexpected JSON shape", file=sys.stderr)
        return 1
    try:
        written = ingest_candidates(candidates, keep_rejected=args.keep_rejected)
    except ValueError as exc:
        print(f"[ingest] {exc}", file=sys.stderr)
        return 1
    print(f"[ingest] wrote {len(written)} candidate card(s) to {CANDIDATES_DIR}")
    for path in written:
        print(f"         {path.relative_to(REPO_ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Corpus-scoped knowledge distillation from disclosed reports."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Download dataset parquet into distill/cache/.")
    group.add_argument("--prepare", action="store_true", help="Pre-filter + normalize + batch cached reports.")
    group.add_argument("--ingest", metavar="SCORED.json", help="Write Claude's scored candidates into staging.")
    parser.add_argument("--batch-size", type=int, default=25, help="Reports per scoring batch (prepare).")
    parser.add_argument("--max", type=int, default=None, help="Cap number of reports prepared.")
    parser.add_argument("--substate", default="", help="Comma list of substates to keep, e.g. resolved.")
    parser.add_argument("--keep-rejected", action="store_true", help="Also write worth_skill=false candidates (ingest).")
    args = parser.parse_args(argv)

    if args.fetch:
        return _cmd_fetch(args)
    if args.prepare:
        return _cmd_prepare(args)
    return _cmd_ingest(args)


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
