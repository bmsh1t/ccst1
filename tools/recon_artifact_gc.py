#!/usr/bin/env python3
"""引用感知的 Recon raw 归档清理。

默认只报告候选文件。只有现有 Autopilot closure 明确允许宣称耗尽时，
``--apply`` 才会删除 raw union/collector 归档；Active URL 视图永不删除。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from tools.autopilot_state import build_autopilot_state, load_closure_projection
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_state import build_autopilot_state, load_closure_projection  # type: ignore
    from target_paths import target_storage_key  # type: ignore


RAW_SOURCE_NAMES = ("gau", "wayback", "waymore", "katana")
LARGE_RAW_REFERENCE_NAMES = {"intel.json", "intel.json.gz"}


def _candidate_paths(repo_root: Path, target: str) -> list[Path]:
    recon_dir = repo_root / "recon" / target_storage_key(target)
    raw_dir = recon_dir / "urls" / "raw"
    candidates = sorted(path for path in raw_dir.glob("*") if path.is_file())
    for name in RAW_SOURCE_NAMES:
        for suffix in (".txt", ".txt.gz"):
            path = recon_dir / "urls" / f"{name}{suffix}"
            if path.is_file():
                candidates.append(path)
    return list(dict.fromkeys(candidates))


def _reference_roots(repo_root: Path, target: str) -> list[Path]:
    key = target_storage_key(target)
    return [
        repo_root / "state" / key,
        repo_root / "findings" / key,
        repo_root / "evidence" / key,
    ]


def _string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _string_values(child)


def _referenced_paths(repo_root: Path, target: str, candidates: list[Path]) -> set[Path]:
    """Find explicit raw path references without scanning the raw corpus itself."""
    relative_tokens = {
        path: path.relative_to(repo_root).as_posix().encode("utf-8")
        for path in candidates
    }
    referenced: set[Path] = set()
    for root in _reference_roots(repo_root, target):
        if not root.is_dir():
            continue
        for source in root.rglob("*"):
            if not source.is_file() or source.name in LARGE_RAW_REFERENCE_NAMES:
                continue
            try:
                stat = source.stat()
                payload = source.read_bytes()
            except OSError as exc:
                raise RuntimeError(f"cannot read reference source {source}: {exc}") from exc
            structured_values = None
            if source.suffix.lower() in {".json", ".jsonl"}:
                if stat.st_size > 16 * 1024 * 1024:
                    raise RuntimeError(f"reference source is too large to verify safely: {source}")
                try:
                    if source.suffix.lower() == ".jsonl":
                        structured_values = []
                        for line_number, line in enumerate(payload.decode("utf-8").splitlines(), 1):
                            if not line.strip():
                                continue
                            try:
                                structured_values.append(json.loads(line))
                            except json.JSONDecodeError as exc:
                                raise RuntimeError(
                                    f"invalid JSONL reference source {source}:{line_number}: {exc.msg}"
                                ) from exc
                    else:
                        structured_values = [json.loads(payload.decode("utf-8"))]
                except UnicodeDecodeError as exc:
                    raise RuntimeError(f"invalid UTF-8 reference source {source}") from exc
                except json.JSONDecodeError as exc:
                    raise RuntimeError(f"invalid JSON reference source {source}: {exc.msg}") from exc
            for path, token in relative_tokens.items():
                if structured_values is not None and any(
                    token.decode("utf-8") in value
                    for value in _string_values(structured_values)
                ):
                    referenced.add(path)
                elif token in payload:
                    referenced.add(path)
    return referenced


def collect_gc_plan(repo_root: str | Path, target: str) -> dict:
    repo = Path(repo_root).resolve()
    candidates = _candidate_paths(repo, target)
    state = build_autopilot_state(str(repo), target, bounded=False)
    if str(state.get("next_action") or "") == "error":
        raise RuntimeError("autopilot state is unreadable; refusing raw cleanup")
    closure = load_closure_projection(
        str(repo), state, max_lanes_reached=False, apply_round_guard=True
    )
    if str(closure.get("verdict") or "") == "error":
        raise RuntimeError("closure projection is unreadable; refusing raw cleanup")
    referenced = _referenced_paths(repo, target, candidates)
    removable = [path for path in candidates if path not in referenced]
    bindings = {}
    for path in candidates:
        stat = path.stat()
        bindings[str(path.relative_to(repo))] = {
            "size": int(stat.st_size),
            "mtime_ns": int(stat.st_mtime_ns),
        }
    return {
        "schema_version": 1,
        "target": str(target),
        "closure": {
            "verdict": closure.get("verdict"),
            "can_claim_exhausted": bool(closure.get("can_claim_exhausted")),
            "reasons": list(closure.get("reasons") or [])[:3],
        },
        "candidate_count": len(candidates),
        "referenced_count": len(referenced),
        "bindings": bindings,
        "removable": [str(path.relative_to(repo)) for path in removable],
    }


def apply_gc_plan(repo_root: str | Path, plan: dict) -> int:
    if not bool((plan.get("closure") or {}).get("can_claim_exhausted")):
        raise RuntimeError(
            "closure is not exhausted; run only after all target work is closed"
        )
    repo = Path(repo_root).resolve()
    recon_dir = repo / "recon" / target_storage_key(str(plan.get("target") or ""))
    raw_dir = (recon_dir / "urls" / "raw").resolve()
    legacy_sources = {
        (recon_dir / "urls" / f"{name}{suffix}").resolve()
        for name in RAW_SOURCE_NAMES
        for suffix in (".txt", ".txt.gz")
    }
    removed = 0
    for relative in plan.get("removable") or []:
        path = (repo / str(relative)).resolve()
        if not path.is_file() or (
            not path.is_relative_to(raw_dir) and path not in legacy_sources
        ):
            continue
        binding = (plan.get("bindings") or {}).get(str(relative))
        if isinstance(binding, dict):
            stat = path.stat()
            if stat.st_size != int(binding.get("size", -1)) or stat.st_mtime_ns != int(
                binding.get("mtime_ns", -1)
            ):
                raise RuntimeError(f"raw artifact changed after dry-run: {relative}")
        path.unlink()
        removed += 1
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--target", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan = collect_gc_plan(args.repo_root, args.target)
        if args.apply:
            plan["removed_count"] = apply_gc_plan(args.repo_root, plan)
            plan["mode"] = "apply"
        else:
            plan["mode"] = "dry-run"
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        if args.apply and not plan["closure"]["can_claim_exhausted"]:
            return 2
        return 0
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
