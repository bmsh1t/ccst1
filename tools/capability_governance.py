#!/usr/bin/env python3
"""Compose read-only Skill and knowledge governance checks."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.context_pack import (
        SKILL_CATALOG,
        SKILL_PATHS,
        SKILL_ROUTE_MODES,
        SKILL_TEST_DIMENSIONS,
    )
    from tools.knowledge_audit import audit_repository
    from tools.knowledge_candidates import audit_candidates
    from tools.knowledge_lifecycle import audit_lifecycle
    from tools.knowledge_registry import KnowledgeRegistryError, load_registry
    from tools.knowledge_value_review import audit_matrix
except ImportError:  # pragma: no cover - direct tools/ execution
    from context_pack import (  # type: ignore
        SKILL_CATALOG,
        SKILL_PATHS,
        SKILL_ROUTE_MODES,
        SKILL_TEST_DIMENSIONS,
    )
    from knowledge_audit import audit_repository  # type: ignore
    from knowledge_candidates import audit_candidates  # type: ignore
    from knowledge_lifecycle import audit_lifecycle  # type: ignore
    from knowledge_registry import KnowledgeRegistryError, load_registry  # type: ignore
    from knowledge_value_review import audit_matrix  # type: ignore


def audit_skill_catalog(repo_root: Path | str = BASE_DIR) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    disk_paths = sorted(
        path.relative_to(repo).as_posix()
        for path in (repo / "skills").glob("*/SKILL.md")
    )
    catalog_paths: list[str] = []
    errors: list[str] = []

    for skill_id, entry in SKILL_CATALOG.items():
        if not isinstance(entry, dict):
            errors.append(f"{skill_id}: catalog entry must be an object")
            continue
        path = str(entry.get("path") or "")
        route_mode = entry.get("route_mode")
        catalog_paths.append(path)
        if path != f"skills/{skill_id}/SKILL.md":
            errors.append(f"{skill_id}: path must match the Skill ID")
        if route_mode not in SKILL_ROUTE_MODES:
            errors.append(f"{skill_id}: invalid route_mode {route_mode!r}")
        dimensions = entry.get("required_dimensions", [])
        if route_mode == "primary" and (
            not isinstance(dimensions, list)
            or not dimensions
            or any(not isinstance(value, str) or not value.strip() for value in dimensions)
            or len(dimensions) != len(set(dimensions))
        ):
            errors.append(f"{skill_id}: primary Skill requires unique test dimensions")

    duplicate_paths = sorted(
        path for path in set(catalog_paths) if catalog_paths.count(path) > 1
    )
    if duplicate_paths:
        errors.append(f"duplicate Skill catalog paths: {duplicate_paths}")
    if set(catalog_paths) != set(disk_paths):
        errors.append(
            "Skill catalog/path mismatch: "
            f"missing={sorted(set(disk_paths) - set(catalog_paths))} "
            f"extra={sorted(set(catalog_paths) - set(disk_paths))}"
        )

    expected_primary = {
        skill_id: str(entry.get("path") or "")
        for skill_id, entry in SKILL_CATALOG.items()
        if isinstance(entry, dict) and entry.get("route_mode") == "primary"
    }
    expected_dimensions = {
        skill_id: list(entry.get("required_dimensions") or [])
        for skill_id, entry in SKILL_CATALOG.items()
        if isinstance(entry, dict) and entry.get("route_mode") == "primary"
    }
    if SKILL_PATHS != expected_primary:
        errors.append("SKILL_PATHS differs from primary Skill catalog entries")
    if SKILL_TEST_DIMENSIONS != expected_dimensions:
        errors.append("SKILL_TEST_DIMENSIONS differs from primary Skill catalog entries")

    return {
        "ok": not errors,
        "errors": errors,
        "catalog_count": len(SKILL_CATALOG),
        "disk_count": len(disk_paths),
        "primary_count": len(expected_primary),
        "route_modes": {
            mode: sorted(
                skill_id
                for skill_id, entry in SKILL_CATALOG.items()
                if isinstance(entry, dict) and entry.get("route_mode") == mode
            )
            for mode in sorted(SKILL_ROUTE_MODES)
        },
    }


def trigger_collisions(repo_root: Path | str = BASE_DIR) -> list[dict[str, Any]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for capability in load_registry(repo_root).capabilities:
        capability_id = capability.get("id")
        if not isinstance(capability_id, str) or not capability_id:
            continue
        for raw_trigger in capability.get("triggers") or []:
            trigger = " ".join(str(raw_trigger).strip().casefold().split())
            if trigger:
                grouped[trigger].add(capability_id)
    return [
        {"trigger": trigger, "capability_ids": sorted(capability_ids)}
        for trigger, capability_ids in sorted(grouped.items())
        if len(capability_ids) > 1
    ]


def audit_governance(
    repo_root: Path | str = BASE_DIR,
    *,
    strict: bool = False,
    source_mode: str = "if-present",
    corpus_dir: Path | str | None = None,
    matrix_path: Path | str | None = None,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    knowledge = audit_repository(
        repo,
        source_mode=source_mode,
        corpus_dir=corpus_dir,
    ).to_dict()
    knowledge["ok"] = knowledge["errors"] == 0 and (
        not strict or knowledge["warnings"] == 0
    )
    lifecycle = audit_lifecycle(repo, strict=strict)
    lifecycle.pop("states", None)
    sections = {
        "knowledge": knowledge,
        "lifecycle": lifecycle,
        "candidates": audit_candidates(
            repo_root=repo,
            strict=strict,
            source_mode=source_mode,
            corpus_dir=corpus_dir,
        ),
        "value_review": audit_matrix(
            repo,
            matrix_path=matrix_path
            or repo / "knowledge" / "governance" / "value-review.json",
        ),
        "skills": audit_skill_catalog(repo),
    }
    try:
        collisions = trigger_collisions(repo)
        collision_error = ""
    except KnowledgeRegistryError as exc:
        collisions = []
        collision_error = str(exc)
    return {
        "ok": all(section.get("ok") is True for section in sections.values()),
        "sections": sections,
        "advisories": {
            "trigger_collisions": collisions,
            "trigger_collision_error": collision_error,
        },
    }


def format_report(result: dict[str, Any]) -> str:
    lines = [f"Capability governance: {'PASS' if result.get('ok') else 'FAIL'}"]
    for name, section in result.get("sections", {}).items():
        details = ""
        if name == "knowledge":
            details = (
                f" capabilities={section.get('capabilities', 0)}"
                f" documents={section.get('documents', 0)}"
                f" errors={section.get('errors', 0)}"
                f" warnings={section.get('warnings', 0)}"
            )
        elif name == "lifecycle":
            details = (
                f" events={section.get('event_count', 0)}"
                f" active={section.get('active_count', 0)}"
                f" errors={len(section.get('errors', []))}"
            )
        elif name == "candidates":
            details = (
                f" candidates={section.get('candidate_count', 0)}"
                f" errors={len(section.get('errors', []))}"
            )
        elif name == "value_review":
            details = (
                f" cards={section.get('cards', 0)}/{section.get('registry_cards', 0)}"
                f" errors={len(section.get('errors', []))}"
            )
        elif name == "skills":
            details = (
                f" catalog={section.get('catalog_count', 0)}"
                f" disk={section.get('disk_count', 0)}"
                f" primary={section.get('primary_count', 0)}"
                f" errors={len(section.get('errors', []))}"
            )
        lines.append(f"[{'PASS' if section.get('ok') else 'FAIL'}] {name}:{details}")
        errors = section.get("errors", [])
        if isinstance(errors, list):
            lines.extend(f"  - {error}" for error in errors)
    for collision in result.get("advisories", {}).get("trigger_collisions", []):
        lines.append(
            "[ADVISORY] trigger collision "
            f"{collision['trigger']}: {', '.join(collision['capability_ids'])}"
        )
    collision_error = result.get("advisories", {}).get("trigger_collision_error")
    if collision_error:
        lines.append(f"[ADVISORY] trigger collision projection unavailable: {collision_error}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=BASE_DIR)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--source-mode",
        choices=("off", "if-present", "required"),
        default="if-present",
    )
    parser.add_argument("--corpus-dir", type=Path, default=None)
    parser.add_argument("--matrix-path", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = audit_governance(
        args.repo_root,
        strict=args.strict,
        source_mode=args.source_mode,
        corpus_dir=args.corpus_dir,
        matrix_path=args.matrix_path,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(format_report(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
