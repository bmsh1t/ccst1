from __future__ import annotations

import argparse
import filecmp
import fcntl
import hashlib
import json
import shlex
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path

try:
    from tools.artifact_io import write_text_atomic
    from tools.skill_reference_contract import CORE_SKILL_NAME, CORE_SKILL_PATH, KNOWN_ENTRY_NAMES
except ImportError:  # direct script execution; keep the installer standard-library-only
    from artifact_io import write_text_atomic
    from skill_reference_contract import CORE_SKILL_NAME, CORE_SKILL_PATH, KNOWN_ENTRY_NAMES

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
ENTRY_MIGRATION_RECORD = ".ccst-entry-migration.json"


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
            owned = json.loads(manifest.read_text())
            if not isinstance(owned, dict):
                raise ValueError("invalid runtime ownership manifest")
            for relative_path, record in owned.items():
                if not isinstance(record, dict):
                    raise ValueError("invalid runtime ownership entry")
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
    entry_issues = []
    migration_record = resolved_runtime / ENTRY_MIGRATION_RECORD
    migration_pending = _file_hash(migration_record, resolved_runtime) is not None
    if migration_pending:
        entry_issues.append({"kind": "runtime", "status": "entry_migration_pending",
                             "relative_path": ENTRY_MIGRATION_RECORD})
    if "skills" in selected:
        source_entries = _skill_entries(resolved_repo)
        runtime_entries = _skill_entries(resolved_runtime, allow_external_links=True)
        forward = any(CORE_SKILL_NAME in entry["known_identities"] for entry in source_entries)
        if forward or any(CORE_SKILL_NAME in entry["known_identities"] for entry in runtime_entries):
            expected = {entry["path"]: entry["identity"] for entry in source_entries if entry["known_identities"]}
            if forward and [(e["path"], e["identity"]) for e in source_entries] != [(CORE_SKILL_PATH, CORE_SKILL_NAME)]:
                entry_issues.append({"kind": "skills", "status": "source_entry_set_invalid",
                                     "relative_path": CORE_SKILL_PATH.removeprefix("skills/")})
            receipt = resolved_runtime / ".ccst-installed.json"
            owned = json.loads(receipt.read_text()) if receipt.is_file() else {}
            # compare_kind already applied the read-side object-shape contract.
            # An interrupted ordinary upgrade can leave matching payload bytes
            # with an older receipt. Preserve legacy missing/hashless receipts
            # and the commands/agents-only read contract.
            core_owner = owned.get(CORE_SKILL_PATH, {})
            managed_install = (core_owner.get("kind") == "skills"
                               and isinstance(core_owner.get("sha256"), str))
            for result in results:
                for item in result["items"]:
                    if item["status"] != "ok":
                        continue
                    path = Path(item["runtime_path"])
                    key = path.relative_to(resolved_runtime).as_posix()
                    owner = owned.get(key)
                    if owner is None and item["kind"] == "commands":
                        alternative = _command_alternative(key)
                        if not (resolved_runtime / alternative).exists():
                            owner = owned.get(alternative)
                    if owner is None:
                        if not managed_install:
                            continue
                        reason = "ownership receipt is missing for installed resource"
                    elif (owner.get("kind") != item["kind"]
                          or not isinstance(owner.get("sha256"), str)):
                        continue
                    elif _file_hash(path, resolved_runtime) == owner["sha256"]:
                        continue
                    else:
                        reason = "ownership receipt differs from installed bytes"
                    item.update(status="diff", reason=reason)
                    result["counts"]["ok"] -= 1
                    result["counts"]["diff"] += 1
                    drift += 1
                    projection = {key: item[key] for key in ("kind", "status", "relative_path", "reason")}
                    destination = critical_drift if (item["kind"], item["relative_path"]) in critical_paths else advisory_drift
                    destination.append(projection)
            for entry in runtime_entries:
                if not entry["known_identities"]:
                    continue
                owner = owned.get(entry["path"], {})
                if (expected.get(entry["path"]) != entry["identity"] or owner.get("kind") != "skills"
                        or owner.get("sha256") != entry["sha256"]):
                    entry_issues.append({"kind": "skills", "status": "entry_conflict",
                        "relative_path": entry["path"].removeprefix("skills/"),
                        "root": str(resolved_runtime), "identity": entry["identity"],
                        "ownership": "receipt" if owner else "unowned",
                        "current_sha256": entry["sha256"], "receipt_sha256": owner.get("sha256"),
                        "action": "inspect before sync", "reason": "retired, duplicate, modified or unowned native entry"})
            present = {entry["path"] for entry in runtime_entries}
            for path in sorted(set(expected) - present):
                entry_issues.append({"kind": "skills", "status": "entry_missing",
                                     "relative_path": path.removeprefix("skills/")})
    critical_drift.extend(entry_issues)
    unobserved_drift = len(synthetic_missing) + int(manifest["status"] != "valid") + len(entry_issues)
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
        "entry_migration": {"status": "pending" if migration_pending else "required" if entry_issues else "none",
                            "record": str(migration_record) if migration_pending else None,
                            "issues": entry_issues},
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2) + "\n"


def _safe_path(path: Path, root: Path) -> bool:
    return (path.is_relative_to(root) and path.resolve().is_relative_to(root)
            and not path.is_symlink()
            and all(not parent.is_symlink() and (not parent.exists() or parent.is_dir()) for parent in path.parents
                    if parent != root and parent.is_relative_to(root)))


def _file_hash(path: Path, root: Path) -> str | None:
    if not _safe_path(path, root):
        raise ValueError(f"unsafe runtime/source path: {path}")
    if not path.exists():
        return None
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"not a regular runtime/source file: {path}")
    return _sha256(path.read_bytes())


def _owned_receipt(raw: str | None) -> dict:
    owned = json.loads(raw) if raw is not None else {}
    if not isinstance(owned, dict):
        raise ValueError("invalid runtime ownership manifest")
    for rel, record in owned.items():
        path = Path(rel)
        if (path.is_absolute() or rel != path.as_posix() or ".." in path.parts
                or not isinstance(record, dict) or record.get("kind") not in KIND_ORDER
                or not path.is_relative_to(RUNTIME_SUBDIRS[record["kind"]])
                or not isinstance(record.get("sha256"), str)):
            raise ValueError("invalid runtime ownership entry")
    return owned


def _skill_identity(body: str, path: Path) -> str:
    """Read the name scalar without a YAML dependency; ambiguous YAML fails closed."""
    lines = body.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line.strip() == "---":
                raise ValueError(f"cannot inspect Skill frontmatter after a preamble: {path}")
            break
        return path.parent.name
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration as exc:
        raise ValueError(f"cannot inspect unterminated Skill frontmatter: {path}") from exc

    def scalar(value):
        value = re.sub(r"\s+#.*$", "", value).strip()
        if value.startswith('"'):
            decoded = json.loads(value)
        elif value.startswith("'") and value.endswith("'"):
            decoded = value[1:-1].replace("''", "'")
        elif value and value[0] not in "|>&*!{[?%" and not value.startswith("'"):
            decoded = value
        else:
            raise ValueError(f"cannot reliably inspect Skill name syntax: {path}")
        if not isinstance(decoded, str) or not decoded:
            raise ValueError(f"cannot reliably inspect Skill name: {path}")
        return decoded

    names = []
    for line in lines[1:end]:
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"cannot reliably inspect Skill frontmatter: {path}")
        key = scalar(key)
        if key == "<<":
            raise ValueError(f"cannot inspect merged Skill identity: {path}")
        if key == "name":
            names.append(scalar(value))
    if len(names) != 1:
        raise ValueError(f"Skill frontmatter must have one inspectable name: {path}")
    return names[0]


def _skill_entries(root: Path, *, allow_external_links: bool = False) -> list[dict]:
    """Inspect identities, allowing read-only external runtime Skill links.

    Repo sources and managed destinations stay link-free. Runtime discovery may
    read linked third-party entries, but never hide a renamed CCST identity or
    treat a linked known entry as receipt-owned.
    """
    base = root / "skills"
    if not _safe_path(base, root):
        raise ValueError(f"cannot inspect linked Skill tree: {base}")
    if not base.exists():
        return []
    if not base.is_dir():
        raise ValueError(f"Skill tree is not a directory: {base}")
    entries = []

    def onerror(error):
        raise error

    for current, dirs, files in os.walk(base, followlinks=allow_external_links, onerror=onerror):
        directory = Path(current)
        if allow_external_links:
            # Inspect each logical alias, including its entry, but stop an
            # ancestor link from recursively expanding the same directory.
            if directory.resolve() in {parent.resolve() for parent in directory.parents
                                       if parent.is_relative_to(base)}:
                dirs.clear()
        else:
            for name in dirs:
                if (directory / name).is_symlink():
                    raise ValueError(f"cannot completely inspect linked Skill directory: {directory / name}")
        if "SKILL.md" not in files:
            continue
        path = directory / "SKILL.md"
        linked = not _safe_path(path, root)
        if allow_external_links and linked:
            def signature(value):
                return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                before = os.fstat(handle.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError(f"not a regular linked Skill entry: {path}")
                raw = handle.read()
                after = os.fstat(handle.fileno())
            if signature(before) != signature(after) or signature(after) != signature(path.stat()):
                raise ValueError(f"linked Skill changed during discovery: {path}")
            digest = _sha256(raw)
        else:
            digest = _file_hash(path, root)
            raw = path.read_bytes()
            if _sha256(raw) != digest:
                raise ValueError(f"Skill changed during discovery: {path}")
        body = raw.decode("utf-8").replace("\r\n", "\n")
        identity = _skill_identity(body, path)
        known = sorted({identity, path.parent.name} & KNOWN_ENTRY_NAMES)
        if linked and known:
            raise ValueError(f"linked CCST Skill entry conflicts with managed discovery: {path} (identity={identity})")
        entries.append({"path": path.relative_to(root).as_posix(), "identity": identity,
                        "known_identities": known, "sha256": digest})
    return sorted(entries, key=lambda item: item["path"])


def _capture_runtime_sources(repo: Path, selected: list[str]) -> dict:
    sources = {}
    for kind in selected:
        for relative, path in _repo_files(repo, kind).items():
            digest = _file_hash(path, repo)
            if digest is None:
                raise ValueError(f"runtime source disappeared: {path}")
            sources[f"{kind}/{relative}"] = {
                "kind": kind, "relative": relative, "sha256": digest,
                "mode": stat.S_IMODE(path.stat().st_mode),
            }
    return sources


def _release_binding(repo: Path, sources: dict) -> dict:
    # Bind the executable checkout and native Skill files, not historical method manifests,
    # tests, journals or target data.
    checkout = {}
    paths = [repo / "AGENTS.md", repo / "CLAUDE.md", repo / "install.sh"]
    for directory, patterns in (("rules", ("*.md",)), ("docs", ("*.md",)),
                                ("bin", ("*.mjs",)), ("mcp-servers", ("*.py", "*.ps1", "*.toml", "*.lock")),
                                ("tools", ("*.py", "*.sh")), ("memory", ("*.py",)),
                                ("knowledge", ("*.md", "*.json", "*.yaml", "*.yml"))):
        for pattern in patterns:
            paths.extend(
                path for path in (repo / directory).rglob(pattern)
                if ".history" not in path.parts
                and not path.is_relative_to(repo / "knowledge" / "methods" / "clown")
                and path != repo / "knowledge" / "clown-hot-method-manifest.json"
            )
    for path in sorted(set(paths)):
        digest = _file_hash(path, repo)
        if digest is not None:
            checkout[path.relative_to(repo).as_posix()] = {"sha256": digest, "mode": stat.S_IMODE(path.stat().st_mode)}
    executor_root = Path(__file__).resolve().parent
    executor = {name: _sha256((executor_root / name).read_bytes()) for name in
                ("runtime_doctor.py", "artifact_io.py", "skill_reference_contract.py")}
    return {
        "source_sha256": _sha256(_json_text(checkout).encode()),
        "source_scope": ["AGENTS.md", "CLAUDE.md", "install.sh", "rules/**/*.md", "docs/**/*.md",
                         "bin/**/*.mjs", "mcp-servers/**/*.{py,ps1,toml,lock}", "tools/**/*.py", "tools/**/*.sh",
                         "memory/**/*.py", "knowledge/**/*.{md,json,yaml,yml} excluding .history, methods/clown and clown-hot-method-manifest.json"],
        "executor_sha256": _sha256(_json_text(executor).encode()),
        "native_sha256": _sha256(_json_text(sources).encode()),
    }


def _command_alternative(key: str) -> str:
    path = Path(key)
    name = (path.name[len(DISABLED_COMMAND_PREFIX):] if path.name.startswith(DISABLED_COMMAND_PREFIX)
            else DISABLED_COMMAND_PREFIX + path.name)
    return path.with_name(name).as_posix()


def _prepare_sync_plan(runtime: Path, owned: dict, sources: dict, selected: list[str],
                       prune: bool, *, entry_cutover: bool) -> tuple[list[dict], dict, list[dict]]:
    locations = {key: key for key in owned}
    for key, record in owned.items():
        if record["kind"] == "commands" and "commands" in selected:
            alternative = _command_alternative(key)
            if (not (runtime / key).exists() and alternative not in owned
                    and _safe_path(runtime / alternative, runtime) and (runtime / alternative).is_file()):
                locations[key] = alternative
    previous = {location: key for key, location in locations.items()}
    after = {locations[key]: record for key, record in owned.items()}
    operations, conflicts, desired = [], [], set()

    def add(key, kind, source, owner_key):
        expected = sources[source]["sha256"] if source else None
        prior = owned.get(owner_key) if owner_key else None
        reason = ""
        current = None
        try:
            current = _file_hash(runtime / key, runtime)
            if current is not None:
                if prior and current != prior["sha256"] and (entry_cutover or current != expected):
                    reason = "locally modified receipt-owned file"
                elif not prior and (current != expected or
                                    (entry_cutover and Path(key).name == "SKILL.md")):
                    reason = "unowned entry/file; exact bytes alone do not establish entry ownership"
        except (OSError, ValueError) as exc:
            reason = str(exc)
        operation = {"path": key, "kind": kind, "action": "write" if source else "remove",
                     "source": source, "ownership_key": owner_key,
                     "before_sha256": current, "after_sha256": expected}
        operations.append(operation)
        if reason:
            conflicts.append({"root": str(runtime), "path": key, "identity": Path(key).parent.name,
                              "ownership": "receipt" if prior else "unowned", "current_sha256": current,
                              "receipt_sha256": prior["sha256"] if prior else None,
                              "action": operation["action"], "reason": reason})

    for source, info in sorted(sources.items()):
        key = (RUNTIME_SUBDIRS[info["kind"]] / info["relative"]).as_posix()
        if info["kind"] == "commands" and not (runtime / key).exists():
            disabled = _command_alternative(key)
            if (runtime / disabled).exists() or (runtime / disabled).is_symlink():
                key = disabled
        desired.add(key)
        add(key, info["kind"], source, previous.get(key))
        after[key] = {"kind": info["kind"], "sha256": info["sha256"]}
    if prune:
        for original, key in locations.items():
            if owned[original]["kind"] in selected and key not in desired:
                add(key, owned[original]["kind"], None, original)
                after.pop(key, None)
    # Non-entry resources first; retire only owned entries; publish entries last.
    operations.sort(key=lambda op: (0 if Path(op["path"]).name != "SKILL.md"
                                    else 1 if op["action"] == "remove" else 2, op["path"]))
    return operations, after, conflicts


def _validate_entry_record(record: dict, header: dict, sources: dict) -> None:
    required = {*header, "phase", "before_receipt", "before_receipt_sha256", "after_receipt",
                "after_receipt_sha256", "operations"}
    if not isinstance(record, dict) or set(record) != required or any(record.get(k) != v for k, v in header.items()):
        raise ValueError("entry migration record does not match this fixed source/root/executor/mode")
    if record["phase"] not in {"payload", "receipt"}:
        raise ValueError("invalid entry migration publication phase")
    before_raw, after_raw = record["before_receipt"], record["after_receipt"]
    if ((before_raw is not None and not isinstance(before_raw, str)) or not isinstance(after_raw, str)
            or record["before_receipt_sha256"] != (_sha256(before_raw.encode()) if before_raw is not None else None)
            or record["after_receipt_sha256"] != _sha256(after_raw.encode())
            or not isinstance(record["operations"], list)):
        raise ValueError("invalid entry migration receipt binding")
    owned = _owned_receipt(before_raw)
    seen_paths, seen_sources, seen_owners = set(), set(), set()
    expected_after = {}
    for op in record["operations"]:
        if not isinstance(op, dict) or set(op) != {"path", "kind", "action", "source", "ownership_key", "before_sha256", "after_sha256"}:
            raise ValueError("invalid entry migration operation")
        key, kind, source, owner_key = op["path"], op["kind"], op["source"], op["ownership_key"]
        if (not isinstance(key, str) or key != Path(key).as_posix() or ".." in Path(key).parts
                or kind not in KIND_ORDER or not Path(key).is_relative_to(RUNTIME_SUBDIRS[kind]) or key in seen_paths):
            raise ValueError("invalid entry migration operation path")
        seen_paths.add(key)
        prior = owned.get(owner_key) if isinstance(owner_key, str) else None
        if owner_key is not None:
            if (not prior or owner_key in seen_owners or prior["kind"] != kind
                    or key not in {owner_key, _command_alternative(owner_key) if kind == "commands" else owner_key}
                    or op["before_sha256"] not in (None, prior["sha256"])):
                raise ValueError("invalid entry migration ownership binding")
            seen_owners.add(owner_key)
        if source is not None:
            if not isinstance(source, str) or source not in sources or source in seen_sources:
                raise ValueError("invalid entry migration source binding")
            info = sources[source]
            canonical = (RUNTIME_SUBDIRS[info["kind"]] / info["relative"]).as_posix()
            if (kind != info["kind"] or op["action"] != "write" or op["after_sha256"] != info["sha256"]
                    or key not in {canonical, _command_alternative(canonical) if kind == "commands" else canonical}
                    or (not prior and op["before_sha256"] not in (None, info["sha256"]))
                    or (not prior and Path(key).name == "SKILL.md" and op["before_sha256"] is not None)):
                raise ValueError("invalid entry migration desired file")
            seen_sources.add(source)
            expected_after[key] = {"kind": kind, "sha256": info["sha256"]}
        elif op["action"] != "remove" or not prior or op["after_sha256"] is not None:
            raise ValueError("invalid entry migration retirement")
    if seen_sources != set(sources) or seen_owners != set(owned) or after_raw != _json_text(expected_after):
        raise ValueError("incomplete entry migration operation/receipt set")


def _check_known_entries(runtime: Path, operations: list[dict]) -> list[dict]:
    planned = {op["path"]: op for op in operations}
    conflicts = []
    for entry in _skill_entries(runtime, allow_external_links=True):
        if not entry["known_identities"]:
            continue
        op = planned.get(entry["path"])
        if op and entry["sha256"] in {op["before_sha256"], op["after_sha256"]}:
            continue
        conflicts.append({"root": str(runtime), **entry, "ownership": "unowned/unplanned",
                          "current_sha256": entry["sha256"], "receipt_sha256": None,
                          "action": "preserve", "reason": "unplanned retired or duplicate native entry"})
    return conflicts


def _verify_sync_state(runtime: Path, operations: list[dict], *, complete: bool) -> None:
    for op in operations:
        allowed = {op["after_sha256"]} if complete else {op["before_sha256"], op["after_sha256"]}
        if _file_hash(runtime / op["path"], runtime) not in allowed:
            raise ValueError(f"runtime file outside recorded {'after' if complete else 'before/after'} state: {op['path']}")


def _publish_runtime_source(source: Path, destination: Path, expected: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".ccst-")
    os.close(fd)
    try:
        shutil.copy2(source, temporary)
        if _sha256(Path(temporary).read_bytes()) != expected:
            raise ValueError(f"runtime source changed during publication: {source}")
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_runtime(
    repo_root: str | Path | None = None,
    runtime_root: str | Path | None = None,
    kinds: list[str] | None = None,
    *,
    prune: bool = False,
) -> dict:
    """Preflight the whole batch; entry cutovers resume only a bound same-version plan."""
    repo, runtime = _repo_root(repo_root), _runtime_root(runtime_root)
    runtime.mkdir(parents=True, exist_ok=True)
    manifest, lock_path, journal = (runtime / name for name in
                                   (".ccst-installed.json", ".ccst-install.lock", ENTRY_MIGRATION_RECORD))
    for path in (manifest, lock_path, journal):
        if not _safe_path(path, runtime):
            raise ValueError("runtime ownership metadata must not be a symlink")
    selected = [kind for kind in KIND_ORDER if kind in (kinds or KIND_ORDER)]
    result = {"copied": [], "removed": [], "conflicts": [], "conflict_details": [], "status": "rejected"}
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        raw = manifest.read_text() if manifest.exists() else None
        owned = _owned_receipt(raw)
        for kind in selected:
            if any(record["kind"] == kind for record in owned.values()) and not (repo / kind).is_dir():
                raise ValueError(f"runtime source directory missing: {kind}")
        critical = load_critical_runtime_manifest(repo)
        owns_autopilot = any(key in owned for key in ("commands/autopilot.md", "commands/.disabled.autopilot.md"))
        if owns_autopilot and critical["status"] != "valid":
            raise ValueError("runtime source critical manifest is missing or invalid")
        if critical["status"] == "valid":
            for entry in critical["paths"]:
                path = repo / entry["kind"] / entry["relative_path"]
                if _file_hash(path, repo) is None:
                    raise ValueError(f"required runtime source missing or unsafe: {path}")
        source_entries = _skill_entries(repo)
        runtime_entries = _skill_entries(runtime, allow_external_links=True)
        forward = any(CORE_SKILL_NAME in entry["known_identities"] for entry in source_entries)
        if forward and [(e["path"], e["identity"]) for e in source_entries] != [(CORE_SKILL_PATH, CORE_SKILL_NAME)]:
            raise ValueError("source candidate must contain only skills/src-hunter/SKILL.md; mixed entry release refused")
        expected_entries = [{"path": e["path"], "identity": e["identity"]} for e in source_entries if e["known_identities"]]
        current_entries = [{"path": e["path"], "identity": e["identity"]} for e in runtime_entries if e["known_identities"]]
        has_core = any(CORE_SKILL_NAME in e["known_identities"] for e in runtime_entries) or CORE_SKILL_PATH in owned
        cutover = journal.exists() or (forward and (current_entries != expected_entries or CORE_SKILL_PATH not in owned)) or (not forward and has_core)
        if cutover and (selected != list(KIND_ORDER) or not prune):
            raise ValueError("entry migration requires --kind commands,agents,skills --sync --prune")
        sources = _capture_runtime_sources(repo, selected)
        if "skills" in selected and any(sources.get(e["path"], {}).get("sha256") != e["sha256"] for e in source_entries):
            raise ValueError("native source entries changed during preflight")
        binding = _release_binding(repo, sources) if cutover else None
        if cutover and not expected_entries:
            raise ValueError("entry migration requires a fixed native entry set")
        header = {"schema_version": 1, "profile": "src-hunter-single-entry",
                  "direction": "forward" if forward else "reverse", "repo_root": str(repo),
                  "runtime_root": str(runtime), "kinds": selected, "prune": prune,
                  "source": binding, "expected_entries": expected_entries}
        if journal.exists():
            record = json.loads(journal.read_text())
            _validate_entry_record(record, header, sources)
            raw_hash = _sha256(raw.encode()) if raw is not None else None
            if raw_hash not in {record["before_receipt_sha256"], record["after_receipt_sha256"]}:
                raise ValueError("runtime receipt is outside the recorded before/after state")
            operations = record["operations"]
            after_raw = record["after_receipt"]
            conflicts = _check_known_entries(runtime, operations)
            receipt_phase = (record["phase"] == "receipt" or
                             (raw_hash == record["after_receipt_sha256"]
                              and raw_hash != record["before_receipt_sha256"]))
            _verify_sync_state(runtime, operations, complete=receipt_phase)
        else:
            operations, after, conflicts = _prepare_sync_plan(runtime, owned, sources, selected, prune,
                                                             entry_cutover=cutover)
            after_raw = _json_text(after)
            if "skills" in selected and (forward or cutover):
                conflicts.extend(_check_known_entries(runtime, operations))
            record = {**header, "phase": "payload", "before_receipt": raw,
                      "before_receipt_sha256": _sha256(raw.encode()) if raw is not None else None,
                      "after_receipt": after_raw, "after_receipt_sha256": _sha256(after_raw.encode()),
                      "operations": operations}
            receipt_phase = False
        if conflicts:
            result["conflict_details"] = conflicts
            result["conflicts"] = sorted({str(runtime / item["path"]) for item in conflicts})
            return result
        if cutover:
            _validate_entry_record(record, header, sources)
        # Recheck source/receipt after preflight and before publishing the record.
        def check_source():
            if (_capture_runtime_sources(repo, selected) != sources
                    or (cutover and _release_binding(repo, sources) != binding)):
                raise ValueError("source candidate changed; keep the recorded version for recovery")
        check_source()
        if (manifest.read_text() if manifest.exists() else None) != raw:
            raise ValueError("runtime receipt changed during preflight")
        if cutover and not journal.exists():
            write_text_atomic(journal, _json_text(record))
        def verify_entries():
            if cutover or forward:
                actual = [{"path": e["path"], "identity": e["identity"]}
                          for e in _skill_entries(runtime, allow_external_links=True) if e["known_identities"]]
                if actual != expected_entries:
                    raise ValueError("runtime native entry set differs from the fixed candidate")
        try:
            if not receipt_phase:
                for op in operations:
                    destination = runtime / op["path"]
                    current = _file_hash(destination, runtime)
                    if current not in {op["before_sha256"], op["after_sha256"]}:
                        raise ValueError(f"runtime changed after preflight: {destination}")
                    if op["action"] == "remove":
                        destination.unlink(missing_ok=True)
                        result["removed"].append(str(destination))
                    else:
                        if current != op["after_sha256"]:
                            _publish_runtime_source(repo / op["source"], destination, op["after_sha256"])
                        result["copied"].append(str(destination))
            _verify_sync_state(runtime, operations, complete=True)
            verify_entries()
            check_source()
            if (manifest.read_text() if manifest.exists() else None) != raw:
                raise ValueError("runtime receipt changed before publication")
            # Persist a fixed after-state decision before receipt publication.
            # This also distinguishes commit when before/after receipt bytes match.
            if cutover and record["phase"] != "receipt":
                record["phase"] = "receipt"
                write_text_atomic(journal, _json_text(record))
            if raw != after_raw:
                write_text_atomic(manifest, after_raw)
            if manifest.read_text() != after_raw:
                raise ValueError("runtime receipt publication verification failed")
            _verify_sync_state(runtime, operations, complete=True)
            verify_entries()
            if cutover:
                journal.unlink()
        except (OSError, ValueError) as exc:
            result.update(status="partial", error=str(exc), recovery_record=str(journal) if cutover else None)
            return result
        result.update(status="complete", entry_migration="complete" if cutover else "not_required")
        if cutover:
            result.update(release=binding, native_entries=expected_entries, direction=header["direction"])
    return result


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
                + (f" ({item['reason']})" if item.get("reason") else "")
            )
        if len(drift_items) > 12:
            lines.append(f"  - ... {len(drift_items) - 12} more")

    if payload["clean"]:
        lines.append("Status: runtime is in sync.")
    else:
        entry_migration = payload.get("entry_migration", {}).get("status") in {"pending", "required"}
        sync_args = "--sync --prune" if has_runtime_extras or entry_migration else "--sync"
        kind_arg = ",".join(KIND_ORDER if entry_migration else [result["kind"] for result in payload["kinds"]])
        # Carry the exact roots that were checked: a copied hint without them
        # would modify the default checkout and ~/.claude instead of the
        # isolated installation the operator just inspected.
        root_args = " ".join(
            f"{flag} {shlex.quote(str(payload[key]))}"
            for flag, key in (("--repo-root", "repo_root"), ("--runtime-root", "runtime_root"))
            if payload.get(key)
        )
        lines.append(
            f"Hint: run `python3 tools/runtime_doctor.py {sync_args} {root_args} --kind {kind_arg}` "
            "to refresh the inspected Claude CLI runtime files."
        )
        if entry_migration:
            lines.append("Entry migration is not ready. Preserve conflicts; pending recovery requires the same fixed source and executor.")
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
        try:
            changes = sync_runtime(args.repo_root, args.runtime_root, kinds=kinds, prune=args.prune)
        except (OSError, ValueError) as exc:
            pending = _runtime_root(args.runtime_root) / ENTRY_MIGRATION_RECORD
            error = {"status": "partial" if pending.exists() else "rejected", "error": str(exc),
                     "recovery_record": str(pending) if pending.exists() else None}
            print(json.dumps(error) if args.json else f"Runtime sync {error['status']}: {exc}")
            return 1
        if not args.json:
            print(
                f"Synced {len(changes['copied'])} file(s). "
                f"Removed {len(changes['removed'])} stale runtime file(s)."
            )
            if changes["status"] == "partial":
                print(f"Runtime sync partial: {changes['error']}; recovery record: {changes['recovery_record']}")

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
    if changes.get("status") == "partial":
        return 1
    if args.fail_on_drift and not payload["clean"]:
        return 1
    if args.fail_on_critical_drift and not payload["critical_clean"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
