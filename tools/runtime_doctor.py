from __future__ import annotations

import argparse
import filecmp
import json
import shutil
from pathlib import Path

KIND_ORDER = ("commands", "agents", "skills")
RUNTIME_SUBDIRS = {
    "commands": Path("commands"),
    "agents": Path("agents") / "claude-bug-bounty",
    "skills": Path("skills"),
}

DISABLED_COMMAND_PREFIX = ".disabled."


def _repo_root(path: str | Path | None = None) -> Path:
    return Path(path).resolve() if path else Path(__file__).resolve().parents[1]


def _runtime_root(path: str | Path | None = None) -> Path:
    return Path(path).expanduser().resolve() if path else (Path.home() / ".claude").resolve()


def _repo_files(repo_root: Path, kind: str) -> dict[str, Path]:
    base = repo_root / kind
    if kind == "skills":
        files = {
            str(path.relative_to(base)): path
            for path in sorted(base.glob("*/SKILL.md"))
        }
        files.update({
            str(path.relative_to(base)): path
            for path in sorted(base.glob("*.md"))
        })
        return files
    return {
        path.name: path
        for path in sorted(base.glob("*.md"))
    }


def _runtime_files(runtime_root: Path, kind: str) -> dict[str, Path]:
    base = runtime_root / RUNTIME_SUBDIRS[kind]
    if kind == "skills":
        files = {
            str(path.relative_to(base)): path
            for path in sorted(base.glob("*/SKILL.md"))
        }
        files.update({
            str(path.relative_to(base)): path
            for path in sorted(base.glob("*.md"))
        })
        return files
    return {
        path.name: path
        for path in sorted(base.glob("*.md"))
    }


def _disabled_command_name(relative_path: str) -> str:
    return f"{DISABLED_COMMAND_PREFIX}{relative_path}"


def _intentional_disabled_runtime_files(runtime_files: dict[str, Path], kind: str) -> dict[str, Path]:
    if kind != "commands":
        return {}
    return {
        name[len(DISABLED_COMMAND_PREFIX):]: path
        for name, path in runtime_files.items()
        if name.startswith(DISABLED_COMMAND_PREFIX) and name.endswith(".md")
    }


def compare_kind(repo_root: Path, runtime_root: Path, kind: str) -> dict:
    repo_files = _repo_files(repo_root, kind)
    runtime_files = _runtime_files(runtime_root, kind)
    if kind == "skills":
        runtime_files = {
            rel_path: path
            for rel_path, path in runtime_files.items()
            if rel_path in repo_files
        }
    disabled_runtime_files = _intentional_disabled_runtime_files(runtime_files, kind)
    items: list[dict[str, str]] = []
    matched_runtime_paths: set[Path] = set()

    for rel_path, src in repo_files.items():
        dst = runtime_files.get(rel_path)
        disabled_dst = disabled_runtime_files.get(rel_path)
        status = "missing"
        effective_dst = runtime_root / RUNTIME_SUBDIRS[kind] / rel_path

        if dst and filecmp.cmp(src, dst, shallow=False):
            status = "ok"
            effective_dst = dst
        elif dst:
            status = "diff"
            effective_dst = dst
        elif disabled_dst and filecmp.cmp(src, disabled_dst, shallow=False):
            status = "ok"
            effective_dst = disabled_dst
        elif disabled_dst:
            status = "diff"
            effective_dst = disabled_dst

        if dst:
            matched_runtime_paths.add(dst.resolve())
        elif disabled_dst:
            matched_runtime_paths.add(disabled_dst.resolve())

        items.append(
            {
                "kind": kind,
                "status": status,
                "repo_path": str(src),
                "runtime_path": str(effective_dst),
                "relative_path": rel_path,
            }
        )

    for rel_path, dst in runtime_files.items():
        if dst.resolve() in matched_runtime_paths:
            continue
        if rel_path not in repo_files:
            items.append(
                {
                    "kind": kind,
                    "status": "extra",
                    "repo_path": str(repo_root / kind / rel_path),
                    "runtime_path": str(dst),
                    "relative_path": rel_path,
                }
            )

    counts = {name: 0 for name in ("ok", "diff", "missing", "extra")}
    for item in items:
        counts[item["status"]] += 1

    return {"kind": kind, "counts": counts, "items": items}


def compare_runtime(
    repo_root: str | Path | None = None,
    runtime_root: str | Path | None = None,
    kinds: list[str] | None = None,
) -> dict:
    resolved_repo = _repo_root(repo_root)
    resolved_runtime = _runtime_root(runtime_root)
    selected_kinds = [kind for kind in (kinds or list(KIND_ORDER)) if kind in KIND_ORDER]
    results = [compare_kind(resolved_repo, resolved_runtime, kind) for kind in selected_kinds]
    drift = sum(
        result["counts"]["diff"] + result["counts"]["missing"] + result["counts"]["extra"]
        for result in results
    )
    return {
        "repo_root": str(resolved_repo),
        "runtime_root": str(resolved_runtime),
        "kinds": results,
        "drift_count": drift,
        "clean": drift == 0,
    }


def sync_runtime(
    repo_root: str | Path | None = None,
    runtime_root: str | Path | None = None,
    kinds: list[str] | None = None,
    *,
    prune: bool = False,
) -> dict[str, list[str]]:
    resolved_repo = _repo_root(repo_root)
    resolved_runtime = _runtime_root(runtime_root)
    copied: list[str] = []
    removed: list[str] = []

    for kind in kinds or list(KIND_ORDER):
        if kind not in KIND_ORDER:
            continue
        repo_files = _repo_files(resolved_repo, kind)
        runtime_files = _runtime_files(resolved_runtime, kind)
        if kind == "skills":
            runtime_files = {
                rel_path: path
                for rel_path, path in runtime_files.items()
                if rel_path in repo_files
            }
        disabled_runtime_files = _intentional_disabled_runtime_files(runtime_files, kind)
        for rel_path, src in repo_files.items():
            disabled_dst = disabled_runtime_files.get(rel_path)
            if disabled_dst and not (resolved_runtime / RUNTIME_SUBDIRS[kind] / rel_path).exists():
                dst = disabled_dst
            else:
                dst = resolved_runtime / RUNTIME_SUBDIRS[kind] / rel_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(str(dst))
        if prune:
            for rel_path, dst in runtime_files.items():
                if kind == "commands" and rel_path.startswith(DISABLED_COMMAND_PREFIX):
                    enabled_name = rel_path[len(DISABLED_COMMAND_PREFIX):]
                    if enabled_name in repo_files:
                        continue
                if rel_path in repo_files:
                    continue
                dst.unlink(missing_ok=True)
                removed.append(str(dst))

    return {"copied": copied, "removed": removed}


def format_report(payload: dict) -> str:
    has_runtime_extras = any(result["counts"]["extra"] > 0 for result in payload["kinds"])
    lines = [
        "RUNTIME DOCTOR",
        "═══════════════════════════════════════",
        f"Repo: {payload['repo_root']}",
        f"Runtime: {payload['runtime_root']}",
        f"Overall drift: {payload['drift_count']}",
    ]

    for result in payload["kinds"]:
        counts = result["counts"]
        lines.append(
            f"{result['kind']}: ok={counts['ok']} diff={counts['diff']} "
            f"missing={counts['missing']} extra={counts['extra']}"
        )
        drift_items = [item for item in result["items"] if item["status"] != "ok"]
        for item in drift_items[:12]:
            lines.append(
                f"  - {item['status'].upper():7} {item['relative_path']} -> {item['runtime_path']}"
            )
        if len(drift_items) > 12:
            lines.append(f"  - ... {len(drift_items) - 12} more")

    if payload["clean"]:
        lines.append("Status: runtime is in sync.")
    else:
        sync_args = "--sync --prune" if has_runtime_extras else "--sync"
        kind_arg = ",".join(result["kind"] for result in payload["kinds"])
        lines.append(
            f"Hint: run `python3 tools/runtime_doctor.py {sync_args} --kind {kind_arg}` "
            "to refresh Claude CLI runtime files."
        )
    return "\n".join(lines)


def _parse_kinds(raw: str | None) -> list[str]:
    if not raw:
        return list(KIND_ORDER)
    values = [item.strip() for item in raw.split(",") if item.strip()]
    return [item for item in values if item in KIND_ORDER] or list(KIND_ORDER)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare repo runtime files with Claude CLI installed runtime files.",
    )
    parser.add_argument("--repo-root", default=None, help="Override repo root (defaults to current project root).")
    parser.add_argument("--runtime-root", default=None, help="Override Claude runtime root (defaults to ~/.claude).")
    parser.add_argument(
        "--kind",
        default="commands,agents,skills",
        help="Comma-separated kinds to inspect: commands,agents,skills",
    )
    parser.add_argument("--sync", action="store_true", help="Copy repo files into the Claude runtime paths.")
    parser.add_argument("--prune", action="store_true", help="When syncing, also remove runtime-only extras for the selected kinds.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable text.")
    parser.add_argument("--fail-on-drift", action="store_true", help="Exit non-zero when drift is found.")
    args = parser.parse_args()

    kinds = _parse_kinds(args.kind)
    if args.sync:
        changes = sync_runtime(args.repo_root, args.runtime_root, kinds=kinds, prune=args.prune)
        if not args.json:
            print(
                f"Synced {len(changes['copied'])} file(s). "
                f"Removed {len(changes['removed'])} stale runtime file(s)."
            )

    payload = compare_runtime(args.repo_root, args.runtime_root, kinds=kinds)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(format_report(payload))
    if args.fail_on_drift and not payload["clean"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
