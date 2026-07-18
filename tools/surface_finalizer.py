#!/usr/bin/env python3
"""Recon 成功后的非致命 Surface 派生视图收尾器。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from tools.surface import build_surface_review
    from tools.target_paths import canonical_target_value
except ImportError:  # pragma: no cover - direct tools/ execution
    from surface import build_surface_review  # type: ignore
    from target_paths import canonical_target_value  # type: ignore


def finalize_surface(repo_root: str | Path, target: str) -> dict:
    """完整刷新 exact index/ranking/projection；失败由调用方决定是否非致命。"""
    resolved = canonical_target_value(target)
    ranked = build_surface_review(repo_root, resolved, refresh=True)
    stats = ranked.get("stats") or {}
    projection = ranked.get("surface_projection") or {}
    return {
        "status": "ok",
        "target": resolved,
        "projection_status": str(projection.get("status") or "missing"),
        "projection_path": str(projection.get("path") or ""),
        "total_candidates": int(stats.get("total_candidates", 0) or 0),
        "p1": int(stats.get("p1", 0) or 0),
        "p2": int(stats.get("p2", 0) or 0),
        "review_pool": int(stats.get("review_pool", 0) or 0),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Finalize derived surface index and projection")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--target", required=True)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = finalize_surface(args.repo_root, args.target)
    except (OSError, RuntimeError, ValueError) as exc:
        payload = {
            "status": "error",
            "target": canonical_target_value(args.target),
            "error": str(exc),
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        else:
            print(f"surface_finalizer: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    else:
        print(
            "surface finalizer: "
            f"candidates={payload['total_candidates']} review_pool={payload['review_pool']} "
            f"projection={payload['projection_status']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
