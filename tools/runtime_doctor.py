from __future__ import annotations

import argparse
import filecmp
import hashlib
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
# `agents/`、`commands/` 中可能保留本地设计补丁；它们不是 Claude runtime
# 可加载资产。只过滤 repo source，runtime 中曾被误同步的同名文件仍应显示
# 为 extra，并可由 `--sync --prune` 清理。
NON_RUNTIME_MARKDOWN_SUFFIXES = (".patch.md",)
AUTOPILOT_MANIFEST_START = "<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST"
AUTOPILOT_MANIFEST_END = "AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->"


def _repo_root(path: str | Path | None = None) -> Path:
    return Path(path).resolve() if path else Path(__file__).resolve().parents[1]


def _runtime_root(path: str | Path | None = None) -> Path:
    return Path(path).expanduser().resolve() if path else (Path.home() / ".claude").resolve()


def load_critical_runtime_manifest(repo_root: str | Path | None = None) -> dict:
    """Load the versioned Autopilot manifest embedded in its runtime command."""
    path = _repo_root(repo_root) / "commands" / "autopilot.md"
    try:
        text = path.read_text(encoding="utf-8")
        raw = text.split(AUTOPILOT_MANIFEST_START, 1)[1].split(AUTOPILOT_MANIFEST_END, 1)[0]
        payload = json.loads(raw.strip())
        if not isinstance(payload, dict) or int(payload.get("schema_version", 0)) < 1:
            raise ValueError("manifest schema_version must be positive")
        paths = []
        for item in payload.get("paths") or []:
            if not isinstance(item, dict):
                raise ValueError("manifest paths must be objects")
            kind = str(item.get("kind") or "").strip()
            relative_path = str(item.get("relative_path") or "").strip()
            relative = Path(relative_path)
            if kind not in KIND_ORDER or not relative_path or relative.is_absolute() or ".." in relative.parts:
                raise ValueError("manifest path is invalid")
            paths.append({"kind": kind, "relative_path": relative_path})
        if not paths:
            raise ValueError("manifest paths are required")
        raw_mcp_contracts = payload.get("mcp_contracts") or []
        if not isinstance(raw_mcp_contracts, list):
            raise ValueError("manifest mcp_contracts must be a list")
        mcp_contracts = [
            str(item).strip()
            for item in raw_mcp_contracts
            if str(item).strip()
        ]
        if any("hackerone" in item.lower() for item in mcp_contracts):
            raise ValueError("HackerOne MCP is outside the Autopilot critical manifest")
        canonical = {
            "schema_version": int(payload["schema_version"]),
            "paths": paths,
            "mcp_contracts": mcp_contracts,
        }
        encoded = json.dumps(canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return {
            **canonical,
            "status": "valid",
            "sha256": f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}",
        }
    except (IndexError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return {
            "schema_version": 0,
            "status": "missing" if not path.is_file() else "invalid",
            "sha256": "",
            "paths": [],
            "mcp_contracts": [],
            "error": " ".join(str(exc).split())[:300],
        }


def _is_runtime_markdown_source(path: Path) -> bool:
    """排除明确的本地开发补丁，不隐藏普通 runtime Markdown。"""
    name = path.name.lower()
    return not any(name.endswith(suffix) for suffix in NON_RUNTIME_MARKDOWN_SUFFIXES)


def _repo_files(repo_root: Path, kind: str) -> dict[str, Path]:
    base = repo_root / kind
    if not base.is_dir():
        return {}
    if kind == "skills":
        files: dict[str, Path] = {}
        for skill_dir in sorted(path for path in base.iterdir() if path.is_dir()):
            files.update({
                str(path.relative_to(base)): path
                for path in sorted(skill_dir.rglob("*"))
                if path.is_file()
            })
        files.update({
            str(path.relative_to(base)): path
            for path in sorted(base.glob("*.md"))
        })
        return files
    return {
        path.name: path
        for path in sorted(base.glob("*.md"))
        if _is_runtime_markdown_source(path)
    }


def _runtime_files(
    runtime_root: Path,
    kind: str,
    *,
    repo_files: dict[str, Path] | None = None,
) -> dict[str, Path]:
    base = runtime_root / RUNTIME_SUBDIRS[kind]
    if kind == "skills":
        managed_files = repo_files or {}
        managed_roots = {
            Path(relative_path).parts[0]
            for relative_path in managed_files
            if len(Path(relative_path).parts) > 1
        }
        shared_files = {
            relative_path
            for relative_path in managed_files
            if len(Path(relative_path).parts) == 1
        }
        files: dict[str, Path] = {}
        for root_name in sorted(managed_roots):
            skill_dir = base / root_name
            if not skill_dir.is_dir():
                continue
            files.update({
                str(path.relative_to(base)): path
                for path in sorted(skill_dir.rglob("*"))
                if path.is_file()
            })
        for relative_path in sorted(shared_files):
            path = base / relative_path
            if path.is_file():
                files[relative_path] = path
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
    runtime_files = _runtime_files(runtime_root, kind, repo_files=repo_files)
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
    manifest = load_critical_runtime_manifest(resolved_repo)
    selected = set(selected_kinds)
    critical_paths = {
        (item["kind"], item["relative_path"])
        for item in manifest["paths"]
        if item["kind"] in selected
    }
    seen: set[tuple[str, str]] = set()
    critical_drift: list[dict[str, str]] = []
    missing_critical: list[dict[str, str]] = []
    advisory_drift: list[dict[str, str]] = []
    for result in results:
        for item in result["items"]:
            key = (item["kind"], item["relative_path"])
            seen.add(key)
            if item["status"] == "ok":
                continue
            projection = {
                "kind": item["kind"],
                "status": item["status"],
                "relative_path": item["relative_path"],
            }
            if key not in critical_paths:
                advisory_drift.append(projection)
            elif item["status"] in {"missing", "extra"}:
                projection["status"] = "missing"
                missing_critical.append(projection)
            else:
                critical_drift.append(projection)
    synthetic_missing = sorted(critical_paths - seen)
    for kind, relative_path in synthetic_missing:
        missing_critical.append({
            "kind": kind,
            "status": "missing",
            "relative_path": relative_path,
        })
    if manifest["status"] != "valid":
        missing_critical.insert(0, {
            "kind": "commands",
            "status": f"manifest_{manifest['status']}",
            "relative_path": "autopilot.md",
        })
    unobserved_drift = len(synthetic_missing) + int(manifest["status"] != "valid")
    full_drift = drift + unobserved_drift
    return {
        "repo_root": str(resolved_repo),
        "runtime_root": str(resolved_runtime),
        "kinds": results,
        "drift_count": full_drift,
        "clean": full_drift == 0,
        "critical_manifest": manifest,
        "critical_drift": critical_drift,
        "missing_critical": missing_critical,
        "advisory_drift": advisory_drift,
        "critical_drift_count": len(critical_drift) + len(missing_critical),
        "advisory_drift_count": len(advisory_drift),
        "critical_clean": not critical_drift and not missing_critical,
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
        runtime_files = _runtime_files(resolved_runtime, kind, repo_files=repo_files)
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
        (
            f"Autopilot critical drift: {payload.get('critical_drift_count', 0)} "
            f"(advisory={payload.get('advisory_drift_count', 0)}, "
            f"manifest={payload.get('critical_manifest', {}).get('sha256', '') or 'invalid'})"
        ),
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
    parser.add_argument(
        "--fail-on-critical-drift",
        action="store_true",
        help="Exit non-zero only when Autopilot critical runtime drift is found.",
    )
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
    if args.fail_on_critical_drift and not payload["critical_clean"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
