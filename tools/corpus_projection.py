#!/usr/bin/env python3
"""Disclosed-report corpus projection (whitelist + normalize).

从 distill_reports.py 迁出的活函数族：case_corpus.py 的案例数据规范化依赖这些
（knowledge 案例查询链路 /kb cases 在用）。原文件的 corpus 蒸馏/scoring/ingest
管线已随 09-11-simple-efficient-refactor 零-B 归档。
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


WHITELIST_FIELDS = (
    "id",
    "title",
    "vulnerability_information",
    "substate",
    "weakness",
    "has_bounty",
    "vote_count",
)


def _weakness_name(weakness: Any) -> str:
    """weakness is a dict like {'name': 'IDOR', ...} or None."""
    if isinstance(weakness, dict):
        name = weakness.get("name")
        if isinstance(name, str):
            return name.strip()
    if isinstance(weakness, str):
        return weakness.strip()
    return ""


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


