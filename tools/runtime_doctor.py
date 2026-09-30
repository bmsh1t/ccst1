from __future__ import annotations

import argparse
import filecmp
import fcntl
import hashlib
import json
import os
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
    if path:
        return Path(path).expanduser().resolve()
    # 环境覆盖（测试隔离，审计 F6）：让干净环境/CI 能指向一个准备好的
    # 临时 runtime，而不是依赖开发者真实 ~/.claude 安装。生产缺省不变。
    override = os.environ.get("CCST_RUNTIME_ROOT", "")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".claude").resolve()


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
        manifest = runtime_root / ".ccst-installed.json"
        if manifest.is_file():
            for relative_path, record in json.loads(manifest.read_text()).items():
                if record.get("kind") != "skills":
                    continue
                path = runtime_root / relative_path
                if not path.resolve().is_relative_to(base.resolve()):
                    raise ValueError("invalid installed skill path")
                if path.is_file():
                    files[path.relative_to(base).as_posix()] = path
        return files
    return {
        path.name: path
        for path in sorted(base.glob("*.md"))
    }


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
    try:
        from tools.artifact_io import write_text_atomic
    except ImportError:  # direct script execution
        from artifact_io import write_text_atomic

    resolved_repo = _repo_root(repo_root)
    resolved_runtime = _runtime_root(runtime_root)
    resolved_runtime.mkdir(parents=True, exist_ok=True)
    manifest = resolved_runtime / ".ccst-installed.json"
    lock_path = resolved_runtime / ".ccst-install.lock"
    if manifest.is_symlink() or lock_path.is_symlink():
        raise ValueError("runtime ownership metadata must not be a symlink")
    copied, removed, conflicts = [], [], []
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        owned = json.loads(manifest.read_text()) if manifest.exists() else {}
        if not isinstance(owned, dict):
            raise ValueError("invalid runtime ownership manifest")
        for rel, record in owned.items():
            path = Path(rel)
            if (path.is_absolute() or ".." in path.parts or not isinstance(record, dict)
                    or record.get("kind") not in KIND_ORDER
                    or not path.is_relative_to(RUNTIME_SUBDIRS[record["kind"]])
                    or not isinstance(record.get("sha256"), str)):
                raise ValueError("invalid runtime ownership entry")

        selected = [kind for kind in kinds or list(KIND_ORDER) if kind in KIND_ORDER]
        # A missing source tree is not an intentionally empty release. Check all
        # selected owners before publishing or deleting even the first file.
        for kind in selected:
            if any(record["kind"] == kind for record in owned.values()) and not (resolved_repo / kind).is_dir():
                raise ValueError(f"runtime source directory missing: {kind}")
        critical = load_critical_runtime_manifest(resolved_repo)
        owns_autopilot = any(key in owned for key in
                            ("commands/autopilot.md", "commands/.disabled.autopilot.md"))
        if owns_autopilot and critical["status"] != "valid":
            raise ValueError("runtime source critical manifest is missing or invalid")
        if critical["status"] == "valid":
            for entry in critical["paths"]:
                source = resolved_repo / entry["kind"] / entry["relative_path"]
                base = resolved_repo / entry["kind"]
                if (source.is_symlink() or not source.resolve().is_relative_to(base.resolve())
                        or not source.is_file()):
                    raise ValueError(f"required runtime source missing or unsafe: {source}")
                source.read_bytes()  # All required sources must be readable before mutation.

        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        def safe(path):
            return (not path.is_symlink()
                    and path.resolve().is_relative_to(resolved_runtime)
                    and all(not parent.is_symlink() for parent in path.parents
                            if parent != resolved_runtime and parent.is_relative_to(resolved_runtime)))

        source_files = {kind: _repo_files(resolved_repo, kind) for kind in selected}
        for key, record in list(owned.items()):
            if record["kind"] != "commands" or "commands" not in selected:
                continue
            current = resolved_runtime / key
            alternative_name = (current.name[len(DISABLED_COMMAND_PREFIX):]
                                if current.name.startswith(DISABLED_COMMAND_PREFIX)
                                else DISABLED_COMMAND_PREFIX + current.name)
            alternative = current.with_name(alternative_name)
            if not current.exists() and safe(alternative) and alternative.is_file():
                alternative_key = alternative.relative_to(resolved_runtime).as_posix()
                if alternative_key not in owned:
                    owned[alternative_key] = record
                    del owned[key]

        for kind in selected:
            sources = source_files[kind]
            desired = set()
            for rel, src in sources.items():
                dst = resolved_runtime / RUNTIME_SUBDIRS[kind] / rel
                original_key = dst.relative_to(resolved_runtime).as_posix()
                disabled = dst.with_name(DISABLED_COMMAND_PREFIX + dst.name)
                if kind == "commands" and not dst.exists() and disabled.is_file():
                    dst = disabled
                key = dst.relative_to(resolved_runtime).as_posix()
                desired.add(key)
                previous = owned.get(key) or owned.get(original_key)
                expected = digest(src)
                if (not safe(dst) or (dst.exists() and (not dst.is_file()
                        or (digest(dst) != expected
                            and (not previous or digest(dst) != previous["sha256"]))))):
                    conflicts.append(str(dst))
                    continue
                dst.parent.mkdir(parents=True, exist_ok=True)
                # Atomic publication, with the manifest retaining the prior hash
                # until publication succeeds. Interrupted retries adopt exact bytes.
                if not dst.exists() or digest(dst) != expected:
                    import tempfile
                    fd, temporary = tempfile.mkstemp(dir=dst.parent, prefix=".ccst-")
                    os.close(fd)
                    try:
                        shutil.copy2(src, temporary)
                        os.replace(temporary, dst)
                    finally:
                        Path(temporary).unlink(missing_ok=True)
                owned[key] = {"kind": kind, "sha256": expected}
                if key != original_key:
                    owned.pop(original_key, None)
                copied.append(str(dst))
            if prune:
                for key, record in list(owned.items()):
                    if record["kind"] != kind or key in desired:
                        continue
                    dst = resolved_runtime / key
                    if not safe(dst) or (dst.exists() and (not dst.is_file() or digest(dst) != record["sha256"])):
                        conflicts.append(str(dst))
                        continue
                    dst.unlink(missing_ok=True)
                    owned.pop(key)
                    removed.append(str(dst))
        write_text_atomic(manifest, json.dumps(owned, sort_keys=True, indent=2) + "\n")
    return {"copied": copied, "removed": removed, "conflicts": conflicts}


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
    changes = {"conflicts": []}
    if args.sync:
        changes = sync_runtime(args.repo_root, args.runtime_root, kinds=kinds, prune=args.prune)
        if not args.json:
            print(
                f"Synced {len(changes['copied'])} file(s). "
                f"Removed {len(changes['removed'])} stale runtime file(s)."
            )

    payload = compare_runtime(args.repo_root, args.runtime_root, kinds=kinds)
    if args.sync:
        payload["sync"] = changes
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(format_report(payload))
    if changes["conflicts"]:
        if not args.json:
            print("Preserved conflicting files: " + ", ".join(changes["conflicts"]))
        return 1
    if args.fail_on_drift and not payload["clean"]:
        return 1
    if args.fail_on_critical_drift and not payload["critical_clean"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
