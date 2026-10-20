"""Method discovery, captured reads and explicit local file recovery."""

from __future__ import annotations

import argparse
import fcntl
import stat
import tempfile
from contextlib import contextmanager
import hashlib
import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

try:
    from tools.skill_reference_contract import CORE_SKILL_PATH, LEGACY_SKILL_READ_PATHS
except ImportError:  # direct tools/ execution
    from skill_reference_contract import CORE_SKILL_PATH, LEGACY_SKILL_READ_PATHS

BASE_DIR = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = Path("knowledge/clown-hot-method-manifest.json")
MANIFEST_SCHEMA = "ccst-hot-method/1"
MANIFEST_V2 = "ccst-hot-method/2"
METHOD_ROOT = "knowledge/methods/clown"
HISTORY = METHOD_ROOT + "/.history"
SCOPES = {"method", "index", "governance_reference", "entry_reference"}
VALID_ROLES = frozenset({"entry", "shortlist", "method"})
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ENTRY_MIGRATION_PROFILE = "src-hunter-single-entry"
ENTRY_MIGRATION_FILES = (
    "README.md", "skills/src-hunter/SKILL.md", "skills/src-hunter/知识库/README.md",
    "references/researcher-blackbox-whitebox.md",
)
RULES_MIGRATION_PROFILE = "6k-rules-originals"
RULE_ORIGINALS = {
    "S50": "dig-scope-workflow.md", "S51": "src-value-hunting.md",
    "S52": "researcher-blackbox-whitebox.md", "S53": "hunt-iter.md",
    "S56": "skill-as-boost.md", "S57": "anti-over-moralization.md",
    "S58": "security-research-context.md", "S59": "desktop-task-folder.md",
    "S60": "playwright-browser-mcp.md", "S61": "vuln-report-format.md",
    "S62": "cors-vuln-report-priority.md",
}
RULE_ADAPTER = "references/ccst-runtime-adapter.md"
RULE_INDEX = "skills/src-hunter/知识库/README.md"
RULE_INDEX_LINKS = {
    "需要开场索引时读完整 `打穿短表.md`": "SRC 进站先读完整 `打穿短表.md` 作开场索引",
    "当前项目 Scope/Auth、执行、证据和停止规则优先；历史 rules 映射到方法根 `references/`，不读取个人配置，也不导入永久类别禁令。":
        "完整 rules 位于方法根 `references/`，环境/工程差异只认 `references/ccst-runtime-adapter.md`；Scope/Auth、真实执行和证据 owner 保持。",
    "方法准入完整来源：`references/vuln-report-format.md`；正式报告由当前 `rules/reporting.md` 和 assessment/delivery/report owners 决定。":
        "正式 SRC 正文及方法准入只读完整 `references/vuln-report-format.md`；assessment/delivery/report owners 承接技术、资格及发布绑定。",
    "仅用于方法准入对照；本库不替 C Finding 定级或决定报告发布。":
        "主导默认 SRC 正文并用于方法准入；发布绑定经现有 CCST owner，本库不覆写 Finding 技术裁决。",
}
# V1 rules approvals bind this exact base set. New approvals also bind the
# candidate's actual rule consumers; keep the historical set unchanged.
RULE_RUNTIME_ASSETS = frozenset(LEGACY_SKILL_READ_PATHS.values()) | {
    "CLAUDE.md", "rules/README.md", "rules/hunting.md", "rules/campaign.md",
    "rules/reporting.md", "skills/runtime-protocol.md", "commands/report.md",
    "agents/report-writer.md", "docs/architecture-contract.md", "docs/resin-proxy.md", "skills/README.md",
    "commands/hunt.md",
}
_S01_DISPOSITIONS = (
    "keep full source reference under methods; root skills/src-hunting remains sole native entry; repair only host/path instructions",
    "S01 is the source of root skills/src-hunter/SKILL.md; keep full source reference under methods; nine specialist methods are internal modules",
)


class HotMethodError(ValueError):
    """Raised when a source manifest cannot be trusted."""


def _manifest_path(repo_root: Path | str) -> Path:
    return Path(repo_root) / MANIFEST_RELATIVE


def _validate_relative_path(value: object, *, index: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HotMethodError(f"entry {index}: path must be non-empty text")
    path = value.strip().replace("\\", "/")
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts or path.startswith("/"):
        raise HotMethodError(f"entry {index}: path must stay below the source root")
    if path in {".", ""} or any(part in {"", "."} for part in path.split("/")):
        raise HotMethodError(f"entry {index}: invalid path component")
    return path


def _parse_manifest(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HotMethodError(f"manifest unreadable: {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") not in {MANIFEST_SCHEMA, MANIFEST_V2}:
        raise HotMethodError("unsupported method manifest")
    source_id = payload.get("source_id")
    if not isinstance(source_id, str) or not source_id.strip():
        raise HotMethodError("manifest source_id must be non-empty text")
    root_env = payload.get("root_env")
    if not isinstance(root_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", root_env):
        raise HotMethodError("manifest root_env must be an uppercase environment name")
    bundled_root = payload.get("bundled_root")
    if bundled_root is not None:
        bundled_root = _validate_relative_path(bundled_root, index=-1)
    elif not isinstance(payload.get("default_root"), str) or not payload["default_root"].strip():
        raise HotMethodError("manifest requires bundled_root or an explicit default_root")
    if not isinstance(payload.get("entries"), list) or not payload["entries"]:
        raise HotMethodError("manifest entries must be a non-empty list")
    contexts = payload.get("context_files", [])
    if not isinstance(contexts, list):
        raise HotMethodError("manifest context_files must be a list")
    seen: set[str] = set()
    groups: dict[str, list[dict[str, str]]] = {}
    for key, records in (("entries", payload["entries"]), ("context_files", contexts)):
        entries = []
        for index, raw in enumerate(records):
            if not isinstance(raw, dict):
                raise HotMethodError(f"{key}[{index}] must be an object")
            relative = _validate_relative_path(raw.get("path"), index=index)
            digest = raw.get("sha256")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                raise HotMethodError(f"{key}[{index}].sha256 must be a SHA256 digest")
            role = raw.get("role") if key == "entries" else "context"
            if key == "entries" and role not in VALID_ROLES:
                raise HotMethodError(f"invalid method role: {role!r}")
            if relative in seen:
                raise HotMethodError(f"manifest contains duplicate path: {relative}")
            seen.add(relative)
            entry = {**raw, "path": relative, "sha256": digest.lower(), "role": role}
            if "source_path" in raw:
                entry["source_path"] = _validate_relative_path(raw["source_path"], index=index)
            entries.append(entry)
        groups[key] = entries
    if payload["schema"] == MANIFEST_V2:
        _validate_v2(payload, groups)
    return {
        **payload, "schema": payload["schema"], "source_id": source_id.strip(),
        "bundled_root": bundled_root, "default_root": payload.get("default_root"),
        "root_env": root_env, "manifest_path": str(path), **groups,
    }


def _safe_source_path(root: Path, relative: str) -> Path:
    root_resolved = root.resolve(strict=False)
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise HotMethodError(f"manifest path escapes source root: {relative}") from exc
    return candidate


def _resolve_source_root(
    manifest: dict[str, Any], repo_root: Path, environ: dict[str, str],
) -> Path:
    override = environ.get(manifest["root_env"])
    if override is None and manifest["bundled_root"]:
        if manifest["schema"] == MANIFEST_V2:
            return repo_root / manifest["bundled_root"]
        return _safe_source_path(repo_root, manifest["bundled_root"])
    value = override if override is not None else manifest["default_root"]
    root = Path(str(value or "")).expanduser()
    if not value or not root.is_absolute():
        raise HotMethodError("external method source root must be an absolute path")
    return root


def _build_hot_method_projection(
    repo_root: Path | str = BASE_DIR, *, focus: str = "",
    environ: dict[str, str] | None = None, include_catalog: bool = False,
    diagnostics: bool = False,
) -> dict[str, Any]:
    """Verify sources without selecting a route, ranking methods or copying bodies."""
    repo = _repo(repo_root)
    result: dict[str, Any] = {
        "source_id": "", "root": "", "manifest_path": str(_manifest_path(repo)),
        "focus": focus, "hot_methods": [], "bodies_read": False,
        "summary": {"total": 0, "ready": 0, "missing": 0, "changed": 0},
    }
    try:
        manifest, manifest_bytes = _capture_manifest(repo)
        environment = os.environ if environ is None else environ
        root = _resolve_source_root(manifest, repo, environment)
    except HotMethodError as exc:
        return {**result, "status": "invalid_manifest", "error": str(exc)}
    if _pending_exists(repo):
        return {**result, "status": "pending_update", "pending": _current_state(repo)["pending"]}
    if manifest["schema"] == MANIFEST_V2 and manifest["root_env"] in environment:
        return {**result, "status": "origin_only", "source_id": manifest["source_id"],
                "root": str(root), "manifest_sha256": _digest(manifest_bytes),
                "origins": _origin_health(repo, manifest, environment)}
    command = ["python3", str(repo / "tools/hot_method.py"), "--repo-root", str(repo)]
    manifest_sha256 = _digest(manifest_bytes)
    records = []
    for entry in [*manifest["entries"], *manifest["context_files"]]:
        relative = (entry.get("source_path", entry["path"])
                    if manifest["root_env"] in environment else entry["path"])
        item = {**entry, "path": relative, "status": "missing", "usable": False,
                "actual_sha256": None,
                "read_command": shlex.join([*command, "--read", entry["path"],
                                             "--expected-manifest", manifest_sha256, "--json"])}
        try:
            path = root / relative if manifest["schema"] == MANIFEST_V2 else _safe_source_path(root, relative)
            if not path.is_file():
                item["error"] = "source file missing"
            else:
                actual = _digest(_read_absolute(path)[0])
                item["actual_sha256"] = actual
                item["status"] = "ready" if actual == entry["sha256"] else "changed"
                item["usable"] = item["status"] == "ready"
                if not item["usable"]:
                    item["error"] = "sha256 does not match manifest"
        except (OSError, HotMethodError) as exc:
            item["error"] = str(exc)
        records.append(item)
    methods = [item for item in records if item["role"] != "context"]
    counts = {key: sum(item["status"] == key for item in methods)
              for key in ("ready", "missing", "changed")}
    context_counts = {key: sum(item["status"] == key for item in records if item["role"] == "context")
                      for key in ("ready", "missing", "changed")}
    status = ("missing" if any(item["status"] == "missing" for item in records)
              else "changed" if any(item["status"] == "changed" for item in records) else "ready")
    if manifest["schema"] == MANIFEST_V2:
        origins = _origin_health(repo, manifest, environment)
        result["origins"] = origins
        if any(item["status"] != "ready" for item in origins):
            status = "changed" if any(item["status"] == "changed" for item in origins) else "missing"
        try:
            _validate_revision(repo, manifest, manifest_bytes, local_identity=False)
            result["revision_status"] = "ready"
            result["revision_validation"] = "published_content"
        except (OSError, HotMethodError) as exc:
            result.update(revision_status="invalid", revision_error=str(exc))
            if status == "ready":
                status = "invalid_manifest"
        if status != "ready":
            for item in records:
                item["usable"] = False
                item.setdefault("error", f"method set is {status}; not a successful captured read")
    by_path = {entry["path"]: item for entry, item in
               zip([*manifest["entries"], *manifest["context_files"]], records)}
    guide = by_path.get("README.md", {})
    index = by_path.get("skills/src-hunter/知识库/README.md", {})
    result.update({
        "schema": manifest["schema"], "manifest_sha256": manifest_sha256,
        "revision_ref": manifest.get("revision_ref"),
        "status": status, "source_id": manifest["source_id"], "root": str(root),
        "root_env": manifest["root_env"],
        "summary": {"total": len(methods), **counts, "context": context_counts,
                    "usable": sum(item["usable"] for item in methods)},
        "discovery": {
            "guide": str(repo / "knowledge/methods/clown/README.md"),
            "index": str(root / "skills/src-hunter/知识库/README.md"),
            "guide_read_command": guide.get("read_command"),
            "guide_status": guide.get("status", "unversioned"),
            "index_read_command": index.get("read_command"),
            "index_status": index.get("status", "missing"),
            "catalog_command": shlex.join([*command, "--catalog", "--json"]),
        },
        "catalog_complete": include_catalog,
        "catalog_order": "manifest_order_not_ranked",
    })
    if include_catalog:
        result["hot_methods"] = [
            {key: item[key] for key in ("path", "role", "status", "usable", "sha256",
                                        "actual_sha256", "origin_refs", "maintenance_scope",
                                        "read_command") if key in item} for item in methods
        ]
    if diagnostics:
        result["entries"] = records
    else:
        result["source_issues"] = [
            {key: item[key] for key in ("path", "status", "error")}
            for item in records if not item["usable"]
        ]
    return result



def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise HotMethodError(f"{label}: non-empty canonical text required")
    return value


def _hash(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise HotMethodError("expected lowercase SHA256")
    return value


def _relative(value: object) -> str:
    result = _validate_relative_path(value, index=-1)
    if result != value or "\x00" in result:
        raise HotMethodError("noncanonical path")
    return result


def _transaction_id(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise HotMethodError("invalid transaction_id")
    return value


def _validate_v2(payload: dict, groups: dict) -> None:
    if payload.get("bundled_root") != METHOD_ROOT:
        raise HotMethodError("v2 bundled_root must name the checkout method root")
    if payload.get("root_env") != "CCST_CLOWN_SNAPSHOT":
        raise HotMethodError("v2 root_env must be CCST_CLOWN_SNAPSHOT")
    revision = _relative(payload.get("revision_ref"))
    if not revision.startswith(".history/receipts/") or not revision.endswith(".json"):
        raise HotMethodError("invalid revision_ref")
    _transaction_id(revision.removeprefix(".history/receipts/").removesuffix(".json"))
    origins = payload.get("origins")
    if not isinstance(origins, list) or not origins:
        raise HotMethodError("v2 origins required")
    ids = set()
    for origin in origins:
        if not isinstance(origin, dict):
            raise HotMethodError("origin must be an object")
        identity = _text(origin.get("id"), "origin.id")
        if identity in ids:
            raise HotMethodError("duplicate origin ID")
        ids.add(identity)
        _relative(origin.get("source_path"))
        digest = _hash(origin.get("origin_sha256"))
        if origin.get("archive_path") != ".history/blobs/" + digest:
            raise HotMethodError("origin archive must bind its immutable blob")
        _text(origin.get("disposition"), "origin.disposition")
        if not isinstance(origin.get("defects"), list) or not all(isinstance(x, str) for x in origin["defects"]):
            raise HotMethodError("origin defects must be a list of text")
        if not isinstance(origin.get("consumers"), list) or not origin["consumers"]:
            raise HotMethodError("origin consumers required")
        for consumer in origin["consumers"]:
            _relative(_text(consumer, "consumer").split("#", 1)[0])
    for entry in [*groups["entries"], *groups["context_files"]]:
        if entry["path"].startswith(".history/") or any(x.startswith(".hot-") for x in Path(entry["path"]).parts):
            raise HotMethodError("recovery names are not active methods")
        if entry.get("maintenance_scope") not in SCOPES:
            raise HotMethodError("invalid maintenance_scope")
        refs = entry.get("origin_refs")
        if not isinstance(refs, list) or not refs or any(not isinstance(x, str) or x not in ids for x in refs):
            raise HotMethodError("entry has unbound origin_refs")
        if len(set(refs)) != len(refs):
            raise HotMethodError("duplicate origin_refs")


def _identity(info: os.stat_result) -> dict:
    return {"dev": info.st_dev, "ino": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid}


@contextmanager
def _directory(path: Path):
    """Pin every component; never resolve away a symlink or a '..'."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    chain = []
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            current /= part
            info = os.fstat(fd)
            chain.append((current, info.st_dev, info.st_ino))
        yield fd
        for component, dev, ino in chain:
            info = component.lstat()
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (dev, ino):
                raise HotMethodError(f"directory identity conflict: {component}")
    finally:
        os.close(fd)


def _read_at(parent: int, name: str, *, metadata: bool = False) -> tuple[bytes, dict]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise HotMethodError(f"not a regular file: {name}")
        if metadata and os.listxattr(handle.fileno()):
            raise HotMethodError(f"unsupported ACL/xattr: {name}")
        raw = handle.read()
        after = os.fstat(handle.fileno())
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        def signature(info):
            return (_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if signature(before) != signature(after) or signature(before) != signature(current):
            raise HotMethodError(f"changed during read: {name}")
        return raw, _identity(before)


def _read_absolute(path: Path) -> tuple[bytes, dict]:
    with _directory(path.parent) as parent:
        return _read_at(parent, path.name)


class _MethodFiles:
    """Descriptor-bound access for this checkout's method publication journal."""

    def __init__(self, repo: Path, directories: dict | None = None):
        self.repo = repo
        self.directories = dict(directories or {})

    @contextmanager
    def parent(self, path: str):
        path = _relative(path)
        with _directory(self.repo) as root:
            fd = os.dup(root)
            prefix = ""
            try:
                root_info = os.fstat(root)
                self._bind("", root_info)
                for component in Path(path).parts[:-1]:
                    prefix = prefix + "/" + component if prefix else component
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                    self._bind(prefix, os.fstat(fd))
                yield fd, Path(path).name
            finally:
                os.close(fd)

    def _bind(self, path: str, info: os.stat_result) -> None:
        identity = [info.st_dev, info.st_ino]
        if path in self.directories and self.directories[path] != identity:
            raise HotMethodError(f"parent directory identity conflict: {path}")
        self.directories[path] = identity

    def read(self, path: str, *, metadata: bool = False) -> tuple[bytes, dict]:
        with self.parent(path) as (fd, name):
            return _read_at(fd, name, metadata=metadata)

    def optional(self, path: str) -> tuple[bytes, dict] | None:
        try:
            return self.read(path)
        except FileNotFoundError:
            return None

    def sync(self, path: str) -> None:
        with self.parent(path) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise HotMethodError(f"not regular: {path}")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)

    def mkdir(self, path: str) -> None:
        with self.parent(path) as (parent, name):
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                self._bind(path, os.fstat(child))
                os.fsync(child)
                os.fsync(parent)
            finally:
                os.close(child)

    def create(self, path: str, raw: bytes, metadata: dict | None = None) -> dict:
        """Create-only complete bytes, including exact retry of visible sync failures."""
        existing = self.optional(path)
        if existing is not None:
            if existing[0] != raw or (metadata is not None and any(existing[1][k] != metadata[k] for k in ("mode", "uid", "gid"))):
                raise HotMethodError(f"create-only conflict: {path}")
            self.sync(path)
            return existing[1]
        with self.parent(path) as (parent, name):
            temporary = ".hot-prepare-" + next(tempfile._get_candidate_names())
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    if metadata is not None:
                        os.fchown(handle.fileno(), metadata["uid"], metadata["gid"])
                        os.fchmod(handle.fileno(), metadata["mode"])
                    os.fsync(handle.fileno())
                    identity = _identity(os.fstat(handle.fileno()))
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.fsync(parent)
            finally:
                os.unlink(temporary, dir_fd=parent)
            return identity

    def link(self, source: str, destination: str, identity: dict) -> None:
        existing = self.optional(destination)
        if existing is not None:
            if existing[1] != identity:
                raise HotMethodError(f"alias identity conflict: {destination}")
            self.sync(destination)
            return
        if self.read(source)[1] != identity:
            raise HotMethodError(f"source identity conflict: {source}")
        with self.parent(source) as (src, sn), self.parent(destination) as (dst, dn):
            os.link(sn, dn, src_dir_fd=src, dst_dir_fd=dst, follow_symlinks=False)
            os.fsync(dst)


@contextmanager
def _knowledge_lock(repo: Path, *, exclusive: bool = False):
    with _directory(repo / "knowledge") as fd:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


def _repo(value: Path | str) -> Path:
    if ".." in Path(value).parts:
        raise HotMethodError("repo root must not contain '..'")
    return Path(os.path.abspath(value))


def _capture_manifest(repo: Path) -> tuple[dict, bytes]:
    raw, _ = _read_absolute(_manifest_path(repo))
    return _parse_manifest(raw, _manifest_path(repo)), raw


def load_manifest(repo_root: Path | str = BASE_DIR) -> dict[str, Any]:
    try:
        repo = _repo(repo_root)
        with _knowledge_lock(repo):
            if _pending_exists(repo):
                raise HotMethodError("pending_update: explicit recover required")
            return _capture_manifest(repo)[0]
    except OSError as exc:
        raise HotMethodError(f"manifest unreadable: {exc}") from exc


def _pending_exists(repo: Path) -> bool:
    return _MethodFiles(repo).optional(HISTORY + "/pending.json") is not None


def _record(files: _MethodFiles, path: str) -> dict | None:
    item = files.optional(path)
    if item is None:
        return None
    try:
        value = json.loads(item[0])
    except (ValueError, UnicodeError) as exc:
        raise HotMethodError(f"corrupt journal: {path}") from exc
    if not isinstance(value, dict):
        raise HotMethodError(f"journal object required: {path}")
    return value


def _current_state(repo: Path) -> dict:
    state = {"manifest_sha256": None, "health": "unknown", "pending": {"present": "unknown"}}
    try:
        files = _MethodFiles(repo)
        pending = _record(files, HISTORY + "/pending.json")
        state["pending"] = {"present": pending is not None, "transaction_id": pending.get("transaction_id") if pending else None}
        raw, _ = files.read(str(MANIFEST_RELATIVE))
        _parse_manifest(raw, _manifest_path(repo))
        state["manifest_sha256"] = _digest(raw)
        state["health"] = "pending" if pending else "unverified"
    except (OSError, ValueError) as exc:
        state["error"] = str(exc)
    return state


def _origin_health(repo: Path, manifest: dict, environ: dict) -> list[dict]:
    results = []
    external = manifest["root_env"] in environ
    root = _resolve_source_root(manifest, repo, environ)
    for origin in manifest["origins"]:
        item = {**origin, "status": "missing", "source_only": True,
                "source_incomplete": bool(origin["defects"])}
        try:
            raw, _ = _read_absolute(root / (origin["source_path"] if external else origin["archive_path"]))
            item["actual_sha256"] = _digest(raw)
            item["status"] = "ready" if _digest(raw) == origin["origin_sha256"] else "changed"
            for consumer in origin["consumers"]:
                _read_absolute(repo / consumer.split("#", 1)[0])
        except (OSError, HotMethodError) as exc:
            item["error"] = str(exc)
            item["status"] = "missing"
        results.append(item)
    return results


def build_hot_method_projection(repo_root: Path | str = BASE_DIR, *, focus: str = "",
                                environ: dict[str, str] | None = None,
                                include_catalog: bool = False, diagnostics: bool = False) -> dict[str, Any]:
    try:
        repo = _repo(repo_root)
        with _knowledge_lock(repo):
            return _build_hot_method_projection(repo, focus=focus, environ=environ,
                                                include_catalog=include_catalog, diagnostics=diagnostics)
    except (OSError, HotMethodError) as exc:
        return {"source_id": "", "root": "", "manifest_path": str(_manifest_path(repo_root)),
                "focus": focus, "hot_methods": [], "bodies_read": False,
                "summary": {"total": 0, "ready": 0, "missing": 0, "changed": 0},
                "status": "invalid_manifest", "error": str(exc)}


def read_methods(repo_root: Path | str, paths: list[str], *, expected_manifest: str,
                 environ: dict[str, str] | None = None) -> dict:
    repo = _repo(repo_root)
    environment = os.environ if environ is None else environ
    with _knowledge_lock(repo):
        if _pending_exists(repo):
            raise HotMethodError("pending_update: explicit recover required")
        manifest, raw = _capture_manifest(repo)
        if _hash(expected_manifest) != _digest(raw):
            raise HotMethodError("manifest CAS conflict; fetch a fresh catalog")
        if manifest["schema"] == MANIFEST_V2 and manifest["root_env"] in environment:
            raise HotMethodError("origin_only: use --origin, not active method read")
        root = _resolve_source_root(manifest, repo, environment)
        entries = {x["path"]: x for x in manifest["entries"] + manifest["context_files"]}
        if not isinstance(paths, list) or not paths:
            raise HotMethodError("read requires selected paths")
        selected = list(dict.fromkeys([*paths, *[x["path"] for x in manifest["context_files"]]]))
        bodies = []
        for path in selected:
            path = _relative(path)
            if path not in entries:
                raise HotMethodError(f"not in catalog: {path}")
            entry = entries[path]
            relative = entry.get("source_path", path) if manifest["root_env"] in environment else path
            body, _ = _read_absolute(root / relative)
            if _digest(body) != entry["sha256"]:
                raise HotMethodError(f"changed: {path}")
            bodies.append({**entry, "content": body.decode("utf-8"), "actual_sha256": _digest(body)})
        review = None
        review_sources = []
        if manifest["schema"] == MANIFEST_V2:
            review = _validate_revision(repo, manifest, raw, local_identity=False)["review"]
            health = _origin_health(repo, manifest, environment)
            if any(x["status"] != "ready" for x in health):
                raise HotMethodError("method origins unavailable or changed")
            review_sources = [{**source, "status": "private_source_unavailable"
                               if source["kind"] == "private" else "origin_bytes_verified"}
                              for source in review["sources"]]
        else:
            health = []
        if _read_absolute(_manifest_path(repo))[0] != raw:
            raise HotMethodError("manifest changed during read")
        return {"status": "ready", "manifest_sha256": _digest(raw), "revision_ref": manifest.get("revision_ref"),
                "files": bodies, "origins": health, "source_only": False, "bodies_read": True,
                "review": review, "review_source_status": review_sources,
                "revision_validation": "published_content" if review else "unversioned",
                "review_status": "recorded_declaration_not_authenticated" if review else "unversioned"}


def read_origin(repo_root: Path | str, source_id: str, *, environ: dict[str, str] | None = None) -> dict:
    repo = _repo(repo_root)
    environment = os.environ if environ is None else environ
    with _knowledge_lock(repo):
        if _pending_exists(repo):
            raise HotMethodError("pending_update: explicit recover required")
        manifest, raw = _capture_manifest(repo)
        if manifest["schema"] != MANIFEST_V2:
            raise HotMethodError("v1 has no immutable origin records")
        origin = next((x for x in manifest["origins"] if x["id"] == source_id), None)
        if origin is None:
            raise HotMethodError("unknown origin ID")
        external = manifest["root_env"] in environment
        root = _resolve_source_root(manifest, repo, environment)
        body, _ = _read_absolute(root / (origin["source_path"] if external else origin["archive_path"]))
        if _digest(body) != origin["origin_sha256"]:
            raise HotMethodError("changed origin")
        return {"status": "origin_only" if external else "ready", "source_only": True,
                "manifest_sha256": _digest(raw), "origin": origin, "content": body.decode("utf-8")}

def _journal_path(kind: str, transaction_id: str) -> str:
    return f"{HISTORY}/{kind}/{transaction_id}.json"


def _decision(transaction: dict, mode: str) -> dict:
    return {"schema_version": 1, "transaction_id": transaction["transaction_id"],
            "transaction_sha256": _digest(_json_bytes(transaction)), "mode": mode}


def _receipt(transaction: dict, mode: str) -> dict:
    return {**_decision(transaction, mode), "decision_sha256": _digest(_json_bytes(_decision(transaction, mode))),
            "outcome": "applied" if mode == "complete" else "restored",
            "manifest_sha256": transaction["after_manifest"] if mode == "complete" else transaction["before_manifest"],
            "request_sha256": transaction["request_sha256"], "review": transaction["request"]["update"]["review"]}


def _load_transaction(files: _MethodFiles, identity: str, *, local_identity: bool = True
                      ) -> tuple[dict | None, dict | None, dict | None, dict | None]:
    transaction = _record(files, _journal_path("transactions", identity))
    decision = _record(files, _journal_path("decisions", identity))
    receipt = _record(files, _journal_path("receipts", identity))
    pending = _record(files, HISTORY + "/pending.json")
    if transaction is None:
        if decision is not None or receipt is not None or (pending and pending.get("transaction_id") == identity):
            raise HotMethodError("journal refers to missing transaction")
        return None, None, None, pending
    if (type(transaction.get("schema_version")) is not int or transaction["schema_version"] not in {1, 2}
            or transaction.get("transaction_id") != identity
            or _digest(_json_bytes(transaction.get("request"))) != transaction.get("request_sha256")
            or not isinstance(transaction.get("files"), list) or not transaction["files"]
            or not isinstance(transaction.get("directories"), dict)):
        raise HotMethodError("invalid transaction binding")
    _recorded_request(transaction["request"])
    if transaction["schema_version"] == 2 and not (
            {"entry_migration", "rules_migration"} & transaction["request"].keys()):
        raise HotMethodError("transaction v2 requires a runtime-bound migration")
    if (transaction["request"]["update"]["transaction_id"] != identity
            or transaction["request"]["update"]["expected_manifest"] != transaction["before_manifest"]):
        raise HotMethodError("transaction request identity/before manifest conflict")
    for field in ("before_manifest", "after_manifest"):
        _hash(transaction.get(field))
    for path, value in transaction["directories"].items():
        if path:
            _relative(path)
        if (not isinstance(value, list) or len(value) != 2
                or any(type(part) is not int or part < 0 for part in value)):
            raise HotMethodError("invalid transaction directory identity")
    names = set()
    # Terminal readers verify the same immutable journal bytes in their current
    # checkout. Mutation/recovery always retains the recorded local identities.
    bound_files = _MethodFiles(files.repo, transaction["directories"]) if local_identity else files
    for number, item in enumerate(transaction["files"]):
        if not isinstance(item, dict):
            raise HotMethodError("invalid transaction file")
        path = _relative(item.get("path"))
        if path != str(MANIFEST_RELATIVE) and not path.startswith(METHOD_ROOT + "/"):
            raise HotMethodError("transaction file outside owner")
        witness = f"{HISTORY}/witnesses/{identity}/{number}"
        key = _digest(path.encode())[:24]
        expected_names = {
            "before_witness": witness + "-before" if item.get("before") is not None else None,
            "after_witness": witness + "-after",
            "alias": str(Path(path).parent / f".hot-{identity}-{key}-replace"),
            "slot": str(Path(path).parent / f".hot-{identity}-{key}-slot") if item.get("before") is None else None,
        }
        if any(item.get(field) != name for field, name in expected_names.items()):
            raise HotMethodError("transaction recovery name binding conflict")
        for field in ("path", "after_witness", "before_witness", "slot", "alias"):
            value = item.get(field)
            if value is not None:
                value = _relative(value)
                if value in names:
                    raise HotMethodError("transaction name collision")
                names.add(value)
        for side in ("before", "after"):
            binding = item.get(side)
            if binding is None and side == "before":
                continue
            if not isinstance(binding, dict) or set(binding) != {"sha256", "identity"}:
                raise HotMethodError("invalid transaction identity")
            recorded = binding["identity"]
            if (not isinstance(recorded, dict) or set(recorded) != {"dev", "ino", "mode", "uid", "gid"}
                    or any(type(value) is not int or value < 0 for value in recorded.values())
                    or recorded["mode"] > 0o7777):
                raise HotMethodError("invalid transaction file identity")
            digest = _hash(binding["sha256"])
            if _digest(files.read(HISTORY + "/blobs/" + digest)[0]) != digest:
                raise HotMethodError("damaged immutable transaction blob")
            _verify_witness(bound_files, item, side, local_identity=local_identity)
    candidate = transaction["request"]["update"]["manifest"]
    _parse_manifest(_json_bytes(candidate), MANIFEST_RELATIVE)
    if _digest(_json_bytes(candidate)) != transaction["after_manifest"]:
        raise HotMethodError("transaction after manifest binding conflict")
    for origin in candidate["origins"]:
        body, _ = bound_files.read(METHOD_ROOT + "/" + origin["archive_path"])
        if _digest(body) != origin["origin_sha256"]:
            raise HotMethodError("damaged transaction origin blob")
    if transaction["files"][-1]["path"] != str(MANIFEST_RELATIVE):
        raise HotMethodError("manifest must publish last")
    if "rules_migration" in transaction["request"] or transaction["schema_version"] == 2:
        _migration_approval(files, transaction)
    if decision is not None:
        if decision.get("mode") not in {"complete", "restore"} or decision != _decision(transaction, decision["mode"]):
            raise HotMethodError("decision transaction conflict")
    if receipt is not None:
        if decision is None or receipt != _receipt(transaction, decision["mode"]):
            raise HotMethodError("receipt transaction/decision conflict")
    if pending and pending.get("transaction_id") == identity:
        if pending != {"schema_version": 1, "transaction_id": identity,
                       "transaction_sha256": _digest(_json_bytes(transaction))}:
            raise HotMethodError("pending transaction conflict")
    if decision and receipt is None and pending is None:
        raise HotMethodError("decision without pending or receipt")
    return transaction, decision, receipt, pending


def _validate_revision(repo: Path, manifest: dict, raw: bytes, *, local_identity: bool = True) -> dict:
    """Readers may validate portable content; apply's preflight stays checkout-bound."""
    identity = manifest["revision_ref"].removeprefix(".history/receipts/").removesuffix(".json")
    transaction, _, receipt, _ = _load_transaction(_MethodFiles(repo), identity, local_identity=local_identity)
    if transaction is None or receipt is None or receipt["outcome"] != "applied" or receipt["manifest_sha256"] != _digest(raw):
        raise HotMethodError("manifest revision has no matching applied receipt")
    return receipt


def _validate_update(update: object, expected_manifest: str | None, *, locator: str) -> None:
    """Transport paths and persisted opaque refs have distinct validation rules."""
    validate_locator = _relative if locator == "content_path" else _hash
    if not isinstance(update, dict) or update.get("schema_version") != 1:
        raise HotMethodError("UPDATE_JSON schema_version=1 required")
    if set(update) - {"schema_version", "transaction_id", "expected_manifest", "manifest", "files", "origin_materials", "review"}:
        raise HotMethodError("unknown update field")
    _transaction_id(update.get("transaction_id"))
    expected = _hash(update.get("expected_manifest"))
    if expected_manifest is not None and _hash(expected_manifest) != expected:
        raise HotMethodError("conflicting expected manifest inputs")
    manifest = _parse_manifest(_json_bytes(update.get("manifest")), MANIFEST_RELATIVE)
    if manifest["schema"] != MANIFEST_V2:
        raise HotMethodError("after manifest must be v2")
    if manifest["revision_ref"] != f".history/receipts/{update['transaction_id']}.json":
        raise HotMethodError("revision_ref must bind this transaction")
    files = update.get("files")
    if not isinstance(files, list) or not files:
        raise HotMethodError("non-empty update files required")
    seen = set()
    for item in files:
        if not isinstance(item, dict):
            raise HotMethodError("update file must be an object")
        if set(item) - {"path", "before_sha256", "after_sha256", locator, "mode", "uid", "gid"}:
            raise HotMethodError("unknown update file field")
        path = _relative(item.get("path"))
        if path in seen or path.startswith(".history/") or any(x.startswith(".hot-") for x in Path(path).parts):
            raise HotMethodError("duplicate or reserved update path")
        seen.add(path)
        _hash(item.get("after_sha256"))
        if item.get("before_sha256") is not None:
            _hash(item["before_sha256"])
        validate_locator(item.get(locator))
    review = update.get("review")
    if not isinstance(review, dict):
        raise HotMethodError("review declaration required")
    if set(review) != {"reviewer", "reason", "three_questions", "admission", "sources"}:
        raise HotMethodError("invalid review fields")
    reviewer = review.get("reviewer")
    if not isinstance(reviewer, dict) or reviewer.get("kind") != "main_session":
        raise HotMethodError("reviewer must declare main_session, not human review")
    if set(reviewer) != {"kind", "session_id"}:
        raise HotMethodError("invalid reviewer fields")
    _text(reviewer.get("session_id"), "reviewer.session_id")
    _text(review.get("reason"), "review.reason")
    questions = review.get("three_questions")
    if not isinstance(questions, list) or len(questions) != 3:
        raise HotMethodError("three question review bases required")
    for value in questions:
        _text(value, "question basis")
    if not isinstance(review.get("admission"), list) or not review["admission"]:
        raise HotMethodError("byte-bound admission references required")
    for item in review["admission"]:
        if not isinstance(item, dict):
            raise HotMethodError("invalid admission reference")
        if set(item) != {"path", "sha256"}:
            raise HotMethodError("invalid admission fields")
        _relative(item.get("path"))
        _hash(item.get("sha256"))
    if not isinstance(review.get("sources"), list) or not review["sources"]:
        raise HotMethodError("source bases required")
    for source in review["sources"]:
        if not isinstance(source, dict) or source.get("kind") not in {"origin", "private"}:
            raise HotMethodError("invalid source kind")
        expected = {"kind", "id", "sha256"} | ({locator} if source["kind"] == "private" else set())
        if set(source) != expected:
            raise HotMethodError("invalid source fields")
        _text(source.get("id"), "source.id")
        _hash(source.get("sha256"))
        if source["kind"] == "private":
            validate_locator(source.get(locator))
    materials = update.get("origin_materials", [])
    if not isinstance(materials, list):
        raise HotMethodError("origin_materials must be a list")
    for item in materials:
        if not isinstance(item, dict) or set(item) != {"id", locator}:
            raise HotMethodError("invalid origin material fields")
        _text(item["id"], "origin material ID")
        validate_locator(item[locator])


def _migration_marker(value: object, *, locator: str, profile: str = ENTRY_MIGRATION_PROFILE) -> None:
    if (not isinstance(value, dict)
            or set(value) != {"schema_version", "profile", "direction", "approval"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["profile"] != profile
            or value["direction"] not in ({"forward", "reverse"} if profile == ENTRY_MIGRATION_PROFILE else {"forward"})):
        raise HotMethodError("unsupported migration profile/version/direction")
    approval = value["approval"]
    if not isinstance(approval, dict) or set(approval) != {"sha256", locator}:
        raise HotMethodError("entry migration requires byte-bound approval material")
    _hash(approval["sha256"])
    (_relative if locator == "content_path" else _hash)(approval[locator])


def _recorded_request(request: object) -> None:
    if (not isinstance(request, dict)
            or set(request) not in ({"bootstrap", "update"}, {"bootstrap", "update", "entry_migration"},
                                   {"bootstrap", "update", "rules_migration"})
            or type(request["bootstrap"]) is not bool):
        raise HotMethodError("invalid recorded request envelope")
    _validate_update(request["update"], None, locator="content_ref")
    if "entry_migration" in request:
        if request["bootstrap"]:
            raise HotMethodError("entry migration cannot bootstrap")
        _migration_marker(request["entry_migration"], locator="content_ref")
    if "rules_migration" in request:
        if request["bootstrap"]:
            raise HotMethodError("rules import cannot bootstrap")
        _migration_marker(request["rules_migration"], locator="content_ref", profile=RULES_MIGRATION_PROFILE)


def _request(update: object, expected_manifest: str | None, bootstrap: bool,
             *, entry_migration: dict | None = None, rules_migration: dict | None = None) -> dict:
    if entry_migration is not None and rules_migration is not None:
        raise HotMethodError("migration profiles cannot be combined")
    _validate_update(update, expected_manifest, locator="content_path")
    public = json.loads(_json_bytes(update))
    materials = public.get("origin_materials", [])
    # Transport locators can contain target-private identities. Persist only opaque
    # bindings; recovery needs immutable blobs, never the original input pathname.
    for item in [*public["files"], *materials, *public["review"]["sources"]]:
        if "content_path" in item:
            item["content_ref"] = _digest(item.pop("content_path").encode("utf-8"))
    request = {"bootstrap": bool(bootstrap), "update": public}
    for key, value, profile in (("entry_migration", entry_migration, ENTRY_MIGRATION_PROFILE),
                                ("rules_migration", rules_migration, RULES_MIGRATION_PROFILE)):
        if value is None:
            continue
        if bootstrap:
            raise HotMethodError("migration cannot bootstrap")
        _migration_marker(value, locator="content_path", profile=profile)
        marker = json.loads(_json_bytes(value))
        marker["approval"]["content_ref"] = _digest(marker["approval"].pop("content_path").encode("utf-8"))
        request[key] = marker
    return request


def _entry_navigation_body(raw: bytes, direction: str) -> bytes:
    """Only these contextual navigation tokens may change, never method prose."""
    replacements = [
        (f"{prefix}`skills/src-hunting/SKILL.md`", f"{prefix}`{CORE_SKILL_PATH}`")
        for prefix in ("repository ", "native ", "仓库根 ")
    ] + [
        (f"skills/{name}/SKILL.md", path)
        for name, path in LEGACY_SKILL_READ_PATHS.items() if name != "src-hunting"
    ]
    body = raw.decode("utf-8")
    for old, new in replacements:
        if direction == "reverse":
            old, new = new, old
        body = body.replace(old, new)
    if body.encode("utf-8") == raw:
        raise HotMethodError("entry migration requires an actual navigation change")
    return body.encode("utf-8")


def _entry_origins(origins: list[dict], direction: str) -> list[dict]:
    """Change only three current consumer/disposition records; freeze originals."""
    result = json.loads(_json_bytes(origins))
    if len(result) != 62 or not {"S01", "S56", "S61"} <= {o["id"] for o in result}:
        raise HotMethodError("entry migration requires the complete 62-origin source set")
    paths = {f"skills/{name}/SKILL.md": path for name, path in LEGACY_SKILL_READ_PATHS.items()}
    if direction == "reverse":
        paths = {new: old for old, new in paths.items()}
    for origin in result:
        if origin["id"] == "S01":
            old, new = _S01_DISPOSITIONS if direction == "forward" else _S01_DISPOSITIONS[::-1]
            source = METHOD_ROOT + "/skills/src-hunter/SKILL.md"
            expected = [source] if direction == "forward" else [source, CORE_SKILL_PATH]
            if origin["disposition"] != old or origin["consumers"] != expected:
                raise HotMethodError("S01 entry disposition/consumer is outside the migration profile")
            origin["disposition"] = new
            origin["consumers"] = [source, CORE_SKILL_PATH] if direction == "forward" else [source]
        elif origin["id"] in {"S56", "S61"}:
            origin["consumers"] = [paths.get(path, path) for path in origin["consumers"]]
            for old, new in paths.items():
                origin["disposition"] = origin["disposition"].replace(old, new)
            old, new = ("src-hunting", "src-hunter") if direction == "forward" else ("src-hunter", "src-hunting")
            if origin["id"] == "S56":
                origin["disposition"] = origin["disposition"].replace(old, new)
    return result


def _entry_native_paths(direction: str) -> set[str]:
    return (set(LEGACY_SKILL_READ_PATHS.values()) if direction == "forward"
            else {f"skills/{name}/SKILL.md" for name in LEGACY_SKILL_READ_PATHS})


def _rules_runtime_paths(candidate: dict) -> set[str]:
    governed = {METHOD_ROOT + "/" + item["path"]
                for item in candidate["entries"] + candidate["context_files"]}
    consumers = {_relative(consumer.split("#", 1)[0])
                 for origin in candidate["origins"] if origin["id"] in RULE_ORIGINALS
                 for consumer in origin["consumers"]}
    return set(RULE_RUNTIME_ASSETS) | (consumers - governed)


def _check_entry_migration(files: _MethodFiles, before_raw: bytes, update: dict, marker: dict) -> bytes:
    before = json.loads(before_raw)
    if before["schema"] != MANIFEST_V2 or update.get("origin_materials"):
        raise HotMethodError("entry migration requires v2 without new origin materials")
    changed = {item["path"]: item for item in update["files"]}
    if set(changed) != set(ENTRY_MIGRATION_FILES):
        raise HotMethodError("entry migration permits exactly the four navigation files")
    candidate = json.loads(before_raw)
    candidate["revision_ref"] = f".history/receipts/{update['transaction_id']}.json"
    candidate["origins"] = _entry_origins(before["origins"], marker["direction"])
    found = set()
    for entry in candidate["entries"] + candidate["context_files"]:
        if entry["path"] in changed:
            found.add(entry["path"])
            entry["sha256"] = changed[entry["path"]]["after_sha256"]
    if found != set(changed) or candidate != update["manifest"]:
        raise HotMethodError("entry migration cannot change origin identity, defects or other manifest fields")
    inputs = _MethodFiles(files.repo)
    for path, item in changed.items():
        old, _ = files.read(METHOD_ROOT + "/" + path)
        new, _ = inputs.read(item["content_path"])
        if new != _entry_navigation_body(old, marker["direction"]):
            raise HotMethodError(f"entry migration cannot rewrite method/governance prose: {path}")
    approval_raw, _ = inputs.read(marker["approval"]["content_path"])
    if _digest(approval_raw) != marker["approval"]["sha256"]:
        raise HotMethodError("entry migration approval material changed")
    approval = json.loads(approval_raw)
    expected_paths = _entry_native_paths(marker["direction"])
    native = {path: _digest(_read_absolute(files.repo / path)[0]) for path in sorted(expected_paths)}
    expected = {
        "schema_version": 1, "profile": ENTRY_MIGRATION_PROFILE, "direction": marker["direction"],
        "expected_manifest": _digest(before_raw), "after_manifest": _digest(_json_bytes(candidate)),
        "files": [{k: item[k] for k in ("path", "before_sha256", "after_sha256")} for item in update["files"]],
        "native_assets": native,
    }
    if not isinstance(approval, dict) or set(approval) != {*expected, "authorization"}:
        raise HotMethodError("invalid entry migration approval binding")
    _text(approval["authorization"], "approval authorization declaration")
    if any(approval[key] != value for key, value in expected.items()):
        raise HotMethodError("entry migration approval does not bind this candidate/version")
    for origin in candidate["origins"]:
        for consumer in origin["consumers"]:
            _read_absolute(files.repo / consumer.split("#", 1)[0])
    return approval_raw


def _check_rules_migration(files: _MethodFiles, before_raw: bytes, update: dict, marker: dict) -> bytes:
    """Import only the eleven archived originals; never grant arbitrary rule editing."""
    before = json.loads(before_raw)
    if before["schema"] != MANIFEST_V2 or update.get("origin_materials") or len(before["origins"]) != 62:
        raise HotMethodError("rules import requires the existing v2 62-origin source set")
    old_entries = {e["path"]: e for e in before["entries"] + before["context_files"]}
    if RULE_ADAPTER in old_entries:
        raise HotMethodError("rules are already integrated; a new governance review is required")
    changed = {item["path"]: item for item in update["files"]}
    required = {"README.md", RULE_ADAPTER}
    candidate = json.loads(before_raw)
    candidate["revision_ref"] = f".history/receipts/{update['transaction_id']}.json"
    origins = {o["id"]: o for o in candidate["origins"]}
    if not set(RULE_ORIGINALS) <= origins.keys():
        raise HotMethodError("rules import requires all eleven source identities")
    entries = {e["path"]: e for e in candidate["entries"]}
    inputs = _MethodFiles(files.repo)
    for identity, name in RULE_ORIGINALS.items():
        origin = origins[identity]
        if origin["source_path"] != "rules/" + name:
            raise HotMethodError("rule source filename does not match its stable identity")
        path = "references/" + name
        archived, _ = files.read(METHOD_ROOT + "/" + origin["archive_path"])
        if _digest(archived) != origin["origin_sha256"]:
            raise HotMethodError("rule origin archive changed")
        entry = entries.get(path)
        if entry is None:
            if path in old_entries:
                raise HotMethodError("rule path conflicts with an existing context")
            entry = {"id": identity, "path": path, "role": "method", "source_path": origin["source_path"],
                     "origin_refs": [identity], "maintenance_scope": "governance_reference"}
            candidate["entries"].append(entry)
        if old_entries.get(path, {}).get("sha256") != origin["origin_sha256"]:
            required.add(path)
            item = changed.get(path)
            if item is None or inputs.read(item["content_path"])[0] != archived:
                raise HotMethodError(f"rules import requires exact original bytes: {path}")
        entry["sha256"] = origin["origin_sha256"]
        origin["consumers"] = list(dict.fromkeys([METHOD_ROOT + "/" + path, *origin["consumers"],
                                                "rules/README.md"]))
        origin["disposition"] = ("Complete original rule is active; environment and engineering interfaces are owned by "
                                 + RULE_ADAPTER + "; ordinary A cannot edit governance.")
    # Permit exact navigation updates, never changes to the method inventory.
    if RULE_INDEX in old_entries:
        old_index, _ = files.read(METHOD_ROOT + "/" + RULE_INDEX)
        index = old_index.decode("utf-8")
        for old, new in RULE_INDEX_LINKS.items():
            index = index.replace(old, new)
        if index.encode("utf-8") != old_index:
            required.add(RULE_INDEX)
            item = changed.get(RULE_INDEX)
            if item is None or inputs.read(item["content_path"])[0] != index.encode("utf-8"):
                raise HotMethodError("rules import permits only exact rule-owner navigation in the index")
    if set(changed) != required:
        raise HotMethodError("rules import permits only original restoration, guide, exact index links and runtime adapter")
    candidate["context_files"].append({"id": "ccst-rules-runtime-adapter", "path": RULE_ADAPTER,
        "origin_refs": list(RULE_ORIGINALS), "maintenance_scope": "governance_reference",
        "sha256": changed[RULE_ADAPTER]["after_sha256"]})
    for context in candidate["entries"] + candidate["context_files"]:
        if context["path"] in {"README.md", RULE_INDEX} and context["path"] in changed:
            context["sha256"] = changed[context["path"]]["after_sha256"]
    if candidate != update["manifest"]:
        raise HotMethodError("rules import cannot change other methods, origin identity, defects or metadata")
    approval_raw, _ = inputs.read(marker["approval"]["content_path"])
    if _digest(approval_raw) != marker["approval"]["sha256"]:
        raise HotMethodError("rules import approval material changed")
    approval = json.loads(approval_raw)
    expected = {
        "schema_version": 1, "profile": RULES_MIGRATION_PROFILE, "direction": "forward",
        "expected_manifest": _digest(before_raw), "after_manifest": _digest(_json_bytes(candidate)),
        "files": [{k: item[k] for k in ("path", "before_sha256", "after_sha256")} for item in update["files"]],
        "runtime_assets": {path: _digest(_read_absolute(files.repo / path)[0])
                           for path in sorted(_rules_runtime_paths(candidate))},
    }
    if not isinstance(approval, dict) or set(approval) != {*expected, "authorization"}:
        raise HotMethodError("invalid rules import approval binding")
    _text(approval["authorization"], "approval authorization declaration")
    if any(approval[key] != value for key, value in expected.items()):
        raise HotMethodError("rules import approval does not bind this candidate/version")
    for origin in candidate["origins"]:
        for consumer in origin["consumers"]:
            relative = consumer.split("#", 1)[0]
            # New rules are published by this transaction, not prepared in the live tree.
            if not (relative.startswith(METHOD_ROOT + "/") and relative[len(METHOD_ROOT) + 1:] in changed):
                _read_absolute(files.repo / relative)
    return approval_raw


def _migration_approval(files: _MethodFiles, transaction: dict) -> dict:
    request = transaction["request"]
    if "entry_migration" in request:
        marker = request["entry_migration"]
        label, asset_key = "entry migration", "native_assets"
        paths = _entry_native_paths(marker["direction"])
    else:
        marker = request["rules_migration"]
        label, asset_key = "rules import", "runtime_assets"
        paths = (RULE_RUNTIME_ASSETS if transaction["schema_version"] == 1
                 else _rules_runtime_paths(request["update"]["manifest"]))
    digest = marker["approval"]["sha256"]
    raw, _ = files.read(HISTORY + "/blobs/" + digest)
    if _digest(raw) != digest:
        raise HotMethodError(f"{label} approval blob changed")
    approval = json.loads(raw)
    assets = approval.get(asset_key) if isinstance(approval, dict) else None
    if (not isinstance(assets, dict) or set(assets) != paths
            or approval.get("expected_manifest") != transaction["before_manifest"]
            or approval.get("after_manifest") != transaction["after_manifest"]):
        raise HotMethodError(f"{label} recorded approval binding conflict")
    if transaction["schema_version"] == 2:
        expected = {
            "schema_version": 1, "profile": marker["profile"], "direction": marker["direction"],
            "expected_manifest": transaction["before_manifest"], "after_manifest": transaction["after_manifest"],
            "files": [{k: item[k] for k in ("path", "before_sha256", "after_sha256")}
                      for item in request["update"]["files"]],
        }
        if set(approval) != {*expected, asset_key, "authorization"} or any(
                approval.get(key) != value for key, value in expected.items()):
            raise HotMethodError(f"{label} recorded approval binding conflict")
        _text(approval["authorization"], "approval authorization declaration")
    for digest in assets.values():
        _hash(digest)
    return approval


def _check_migration_runtime(files: _MethodFiles, transaction: dict) -> None:
    request = transaction["request"]
    if "entry_migration" in request:
        if transaction["schema_version"] == 1:
            raise HotMethodError("legacy entry migration lacks a persisted runtime binding; complete refused")
        label, asset_key = "entry migration", "native_assets"
    elif "rules_migration" in request:
        label, asset_key = "rules import", "runtime_assets"
    else:
        return
    assets = _migration_approval(files, transaction)[asset_key]
    if asset_key == "runtime_assets" and set(assets) != _rules_runtime_paths(request["update"]["manifest"]):
        raise HotMethodError("rules import approval does not bind all runtime consumers; complete refused")
    for path, digest in assets.items():
        if _digest(_read_absolute(files.repo / path)[0]) != digest:
            raise HotMethodError(f"{label} runtime consumer changed: {path}")


def _verify_witness(files: _MethodFiles, item: dict, side: str, *, local_identity: bool = True) -> None:
    binding = item[side]
    if binding is None:
        return
    body, identity = files.read(item[side + "_witness"], metadata=local_identity)
    if (local_identity and identity != binding["identity"]) or _digest(body) != binding["sha256"]:
        raise HotMethodError(f"{side} witness conflict: {item['path']}")
    blob = files.read(HISTORY + "/blobs/" + binding["sha256"])
    if blob[0] != body or blob[1]["ino"] == identity["ino"] and blob[1]["dev"] == identity["dev"]:
        raise HotMethodError("blob must be independent of live/witness inode")


def _position(files: _MethodFiles, item: dict, *, desired: str | None = None) -> str:
    for side in ("before", "after"):
        _verify_witness(files, item, side)
    current = files.optional(item["path"])
    position = None
    if item["before"] is None:
        slot = files.optional(item["slot"])
        if current is None and slot is not None and slot[1] == item["after"]["identity"] and _digest(slot[0]) == item["after"]["sha256"]:
            position = "before"
        elif slot is None and current is not None and current[1] == item["after"]["identity"] and _digest(current[0]) == item["after"]["sha256"]:
            position = "after"
        else:
            raise HotMethodError(f"new-file slot conflict: {item['path']}")
    else:
        if current is None:
            raise HotMethodError(f"existing file deleted: {item['path']}")
        for side in ("before", "after"):
            if current[1] == item[side]["identity"] and _digest(current[0]) == item[side]["sha256"]:
                position = side
                break
        if position is None:
            raise HotMethodError(f"third-state file conflict: {item['path']}")
    alias = files.optional(item["alias"])
    if alias is not None:
        sides = (desired,) if desired is not None and position != desired else ("before", "after")
        if item["before"] is None or not any(
                alias[1] == item[side]["identity"] and _digest(alias[0]) == item[side]["sha256"]
                for side in sides):
            raise HotMethodError(f"replacement alias conflict: {item['path']}")
    return position


def _barriers(files: _MethodFiles, transaction: dict) -> None:
    """Repeat visible preparation barriers before any recovery mutation."""
    for key in ("entry_migration", "rules_migration"):
        if key in transaction["request"] and (transaction["schema_version"] == 2 or key == "rules_migration"):
            approval = transaction["request"][key]["approval"]
            files.sync(HISTORY + "/blobs/" + approval["sha256"])
    for item in transaction["files"]:
        _position(files, item)
        for side in ("before", "after"):
            if item[side] is not None:
                files.sync(HISTORY + "/blobs/" + item[side]["sha256"])
                files.sync(item[side + "_witness"])
        if item["slot"] and files.optional(item["slot"]) is not None:
            files.sync(item["slot"])
    for origin in transaction["request"]["update"]["manifest"]["origins"]:
        files.sync(METHOD_ROOT + "/" + origin["archive_path"])
    # Newly created directories also need their own and their parent's barriers.
    for directory in sorted(transaction["directories"], key=lambda x: x.count("/"), reverse=True):
        if directory:
            with files.parent(directory + "/.barrier") as (fd, _):
                os.fsync(fd)
            with files.parent(directory) as (fd, _):
                os.fsync(fd)
    files.sync(_journal_path("transactions", transaction["transaction_id"]))


def _publish_item(files: _MethodFiles, item: dict, desired: str) -> None:
    current = _position(files, item, desired=desired)
    if current == desired:
        if item["before"] is not None or desired == "after":
            files.sync(item["path"])
        else:
            files.sync(item["slot"])
        return
    if item["before"] is None:
        source, destination = (item["slot"], item["path"]) if desired == "after" else (item["path"], item["slot"])
        with files.parent(source) as (parent, src):
            dst = Path(destination).name
            _position(files, item)
            try:
                os.stat(dst, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise HotMethodError("new-file destination unexpectedly occupied")
            os.rename(src, dst, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
    else:
        files.link(item[desired + "_witness"], item["alias"], item[desired]["identity"])
        with files.parent(item["path"]) as (parent, name):
            _position(files, item)
            alias = Path(item["alias"]).name
            os.replace(alias, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
    if _position(files, item) != desired:
        raise HotMethodError("publication verification failed")


def _finish(files: _MethodFiles, transaction: dict, mode: str, *, recovery: bool) -> dict:
    identity = transaction["transaction_id"]
    desired = "after" if mode == "complete" else "before"
    if mode == "complete":
        _check_migration_runtime(files, transaction)
    _barriers(files, transaction)
    files.sync(HISTORY + "/pending.json")
    decision_path = _journal_path("decisions", identity)
    decision = _record(files, decision_path)
    if decision is not None and decision != _decision(transaction, mode):
        raise HotMethodError("recovery direction already fixed")
    # Whole-group guard precedes the first replacement; each path is guarded again.
    for item in transaction["files"]:
        _position(files, item, desired=desired)
    if recovery or decision is not None:
        files.create(decision_path, _json_bytes(_decision(transaction, mode)))
    for item in transaction["files"]:
        if mode == "complete" and item["path"] == str(MANIFEST_RELATIVE):
            _check_migration_runtime(files, transaction)
        _publish_item(files, item, desired)
    for item in transaction["files"]:
        if _position(files, item) != desired:
            raise HotMethodError("final group verification failed")
    files.create(decision_path, _json_bytes(_decision(transaction, mode)))
    receipt = _receipt(transaction, mode)
    files.create(_journal_path("receipts", identity), _json_bytes(receipt))
    with files.parent(HISTORY + "/pending.json") as (parent, name):
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
    return _outcome(files.repo, transaction, receipt, cleanup="confirmed")


def _outcome(repo: Path, transaction: dict, receipt: dict, *, cleanup: str = "not_attempted") -> dict:
    return {"status": "accepted" if receipt["outcome"] == "applied" else "restored",
            "transaction_id": transaction["transaction_id"], "outcome": receipt["outcome"],
            "receipt": receipt, "current": _current_state(repo), "cleanup_durability": cleanup,
            "recovery_command": shlex.join(["python3", str(repo / "tools/hot_method.py"), "--repo-root", str(repo),
                                             "--recover", transaction["transaction_id"], "--mode", receipt["mode"], "--json"])}


def _prepare(files: _MethodFiles, request: dict, before: dict, before_raw: bytes, update: dict,
             *, entry_migration: dict | None = None, rules_migration: dict | None = None) -> dict:
    identity = update["transaction_id"]
    # Input transport directories are transient and may reveal private sources.
    # Only publication/recovery paths belong in the persisted directory bindings.
    inputs = _MethodFiles(files.repo)
    after = _parse_manifest(_json_bytes(update["manifest"]), MANIFEST_RELATIVE)
    if before["bundled_root"] != METHOD_ROOT or before["root_env"] != "CCST_CLOWN_SNAPSHOT":
        raise HotMethodError("only the checkout method root is writable")
    if request["bootstrap"]:
        if before["schema"] != MANIFEST_SCHEMA or len(after["origins"]) != 62:
            raise HotMethodError("bootstrap requires v1 and exactly 62 origin records")
    elif before["schema"] != MANIFEST_V2:
        raise HotMethodError("ordinary apply requires v2")
    old_entries = {x["path"]: x for x in before["entries"] + before["context_files"]}
    new_entries = {x["path"]: x for x in after["entries"] + after["context_files"]}
    if before["schema"] == MANIFEST_V2:
        _validate_revision(files.repo, before, before_raw)
    approval_raw = None
    if entry_migration is not None:
        approval_raw = _check_entry_migration(files, before_raw, update, entry_migration)
    if rules_migration is not None:
        approval_raw = _check_rules_migration(files, before_raw, update, rules_migration)
    governance_migration = entry_migration is not None or rules_migration is not None
    for entry in old_entries.values():
        body, _ = files.read(METHOD_ROOT + "/" + entry["path"])
        if _digest(body) != entry["sha256"]:
            raise HotMethodError(f"current method changed: {entry['path']}")
    if not set(old_entries) <= set(new_entries):
        raise HotMethodError("maintenance cannot remove existing methods")
    changed = {item["path"]: item for item in update["files"]}
    if set(changed) - set(new_entries):
        raise HotMethodError("updated file missing from new manifest")
    if not request["bootstrap"] and not governance_migration:
        old_payload = json.loads(before_raw)
        candidate = update["manifest"]
        for key in set(old_payload) | set(candidate):
            if key not in {"entries", "context_files", "revision_ref"} and old_payload.get(key) != candidate.get(key):
                raise HotMethodError(f"ordinary maintenance cannot change {key}")
        for path, old in old_entries.items():
            new = new_entries[path]
            if {k: v for k, v in old.items() if k != "sha256"} != {k: v for k, v in new.items() if k != "sha256"}:
                raise HotMethodError("ordinary maintenance cannot change existing entry metadata")
    for path, entry in new_entries.items():
        if path in changed:
            if not request["bootstrap"] and not governance_migration and (entry["maintenance_scope"] not in {"method", "index"} or path.startswith("references/") or path.endswith("SKILL.md")):
                raise HotMethodError(f"governance/entry maintenance denied: {path}")
            if changed[path]["after_sha256"] != entry["sha256"]:
                raise HotMethodError("after manifest/body hash mismatch")
            if path not in old_entries and not request["bootstrap"]:
                _text(entry.get("id"), "new method ID")
        elif path not in old_entries or entry["sha256"] != old_entries[path]["sha256"]:
            raise HotMethodError("manifest changes lack candidate bytes")
    origins = {x["id"]: x for x in after["origins"]}
    materials = update.get("origin_materials", [])
    if not isinstance(materials, list):
        raise HotMethodError("origin_materials must be a list")
    material_map = {}
    for material in materials:
        if not isinstance(material, dict) or material.get("id") not in origins or material["id"] in material_map:
            raise HotMethodError("invalid or duplicate origin material")
        body, _ = inputs.read(_relative(material.get("content_path")))
        if _digest(body) != origins[material["id"]]["origin_sha256"]:
            raise HotMethodError("origin material hash conflict")
        material_map[material["id"]] = body
    if request["bootstrap"] and set(material_map) != set(origins):
        raise HotMethodError("bootstrap requires all 62 original bodies")
    for reference in update["review"]["admission"]:
        candidate = changed.get(reference["path"])
        if request["bootstrap"] and candidate and reference["sha256"] == candidate["after_sha256"]:
            body, _ = inputs.read(candidate["content_path"])
        else:
            body, _ = files.read(METHOD_ROOT + "/" + reference["path"])
        if _digest(body) != reference["sha256"]:
            raise HotMethodError("admission rule changed or missing")
    for source in update["review"]["sources"]:
        if source["kind"] == "origin":
            if source["id"] not in origins or source["sha256"] != origins[source["id"]]["origin_sha256"]:
                raise HotMethodError("unbound origin basis")
            if origins[source["id"]]["defects"]:
                raise HotMethodError("incomplete source cannot authorize maintenance")
        else:
            try:
                source_body, _ = inputs.read(source["content_path"])
            except FileNotFoundError as exc:
                raise HotMethodError("private_source_unavailable") from exc
            if _digest(source_body) != source["sha256"]:
                raise HotMethodError("private source hash mismatch")
    candidates = []
    for item in update["files"]:
        path = METHOD_ROOT + "/" + item["path"]
        current = files.optional(path)
        if item["before_sha256"] is None:
            if current is not None or item["path"] in old_entries:
                raise HotMethodError("new file already exists")
            metadata = {}
            for key in ("mode", "uid", "gid"):
                value = item.get(key)
                if type(value) is not int or value < 0 or key == "mode" and value > 0o777:
                    raise HotMethodError("new file requires explicit mode/uid/gid")
                metadata[key] = value
        else:
            old_entry = old_entries.get(item["path"])
            if (current is None or _digest(current[0]) != item["before_sha256"]
                    or old_entry is not None and old_entry["sha256"] != item["before_sha256"]
                    or old_entry is None and not request["bootstrap"]):
                raise HotMethodError("before body CAS conflict")
            current = files.read(path, metadata=True)
            metadata = current[1]
        body, _ = inputs.read(item["content_path"])
        body.decode("utf-8")
        if _digest(body) != item["after_sha256"]:
            raise HotMethodError("candidate body hash mismatch")
        candidates.append((path, current, body, metadata))
    manifest_current = files.read(str(MANIFEST_RELATIVE), metadata=True)
    candidates.append((str(MANIFEST_RELATIVE), manifest_current, _json_bytes(update["manifest"]), manifest_current[1]))
    # All byte/range/metadata checks above precede preparation; no live bytes change.
    for directory in (HISTORY, HISTORY + "/blobs", HISTORY + "/transactions", HISTORY + "/decisions",
                      HISTORY + "/receipts", HISTORY + "/witnesses", HISTORY + "/witnesses/" + identity):
        files.mkdir(directory)
    if approval_raw is not None:
        files.create(HISTORY + "/blobs/" + _digest(approval_raw), approval_raw)
    for origin in after["origins"]:
        path = METHOD_ROOT + "/" + origin["archive_path"]
        if origin["id"] in material_map:
            files.create(path, material_map[origin["id"]])
        body, _ = files.read(path)
        if _digest(body) != origin["origin_sha256"]:
            raise HotMethodError("origin archive missing or changed")
    records = []
    for number, (path, current, body, metadata) in enumerate(candidates):
        witness_root = f"{HISTORY}/witnesses/{identity}/{number}"
        key = _digest(path.encode())[:24]
        alias = str(Path(path).parent / f".hot-{identity}-{key}-replace")
        slot = str(Path(path).parent / f".hot-{identity}-{key}-slot") if current is None else None
        record = {"path": path, "before": None, "before_witness": None,
                  "after_witness": witness_root + "-after", "slot": slot, "alias": alias}
        if current is not None:
            files.create(HISTORY + "/blobs/" + _digest(current[0]), current[0])
            record["before"] = {"sha256": _digest(current[0]), "identity": current[1]}
            record["before_witness"] = witness_root + "-before"
            files.link(path, record["before_witness"], current[1])
        files.create(HISTORY + "/blobs/" + _digest(body), body)
        after_identity = files.create(record["after_witness"], body, metadata)
        record["after"] = {"sha256": _digest(body), "identity": after_identity}
        if slot:
            files.link(record["after_witness"], slot, after_identity)
        if files.optional(alias) is not None:
            raise HotMethodError("unexpected preparation replacement alias")
        _position(files, record)
        records.append(record)
    transaction = {"schema_version": 2 if governance_migration else 1,
                   "transaction_id": identity, "request": request,
                   "request_sha256": _digest(_json_bytes(request)), "files": records,
                   "directories": files.directories, "before_manifest": _digest(before_raw),
                   "after_manifest": _digest(_json_bytes(update["manifest"]))}
    files.create(_journal_path("transactions", identity), _json_bytes(transaction))
    return transaction

def apply_update(repo_root: Path | str, update: dict, *, expected_manifest: str | None = None,
                 bootstrap: bool = False, environ: dict[str, str] | None = None) -> dict:
    """Ordinary A (or initial bootstrap); cannot carry entry migration authority."""
    request = _request(update, expected_manifest, bootstrap)
    return _apply_request(repo_root, update, request, environ=environ)


def migrate_entry(repo_root: Path | str, update: dict, *, entry_migration: dict,
                  expected_manifest: str | None = None, environ: dict[str, str] | None = None) -> dict:
    """Explicit bounded governance migration using the existing publication owner."""
    request = _request(update, expected_manifest, False, entry_migration=entry_migration)
    return _apply_request(repo_root, update, request, entry_migration=entry_migration, environ=environ)


def import_rules(repo_root: Path | str, update: dict, *, rules_migration: dict,
                 expected_manifest: str | None = None, environ: dict[str, str] | None = None) -> dict:
    """Explicit original-rule import; normal method and entry maintenance stay bounded."""
    request = _request(update, expected_manifest, False, rules_migration=rules_migration)
    return _apply_request(repo_root, update, request, rules_migration=rules_migration, environ=environ)


def _apply_request(repo_root: Path | str, update: dict, request: dict,
                   *, entry_migration: dict | None = None, rules_migration: dict | None = None,
                   environ: dict[str, str] | None = None) -> dict:
    repo = _repo(repo_root)
    environment = os.environ if environ is None else environ
    if "CCST_CLOWN_SNAPSHOT" in environment:
        raise HotMethodError("origin_only: external source mutation forbidden")
    identity = request["update"]["transaction_id"]
    with _knowledge_lock(repo, exclusive=True):
        files = _MethodFiles(repo)
        transaction, decision, receipt, pending = _load_transaction(files, identity)
        if transaction is not None and transaction["request_sha256"] != _digest(_json_bytes(request)):
            raise HotMethodError("transaction ID material conflict")
        # Historical dispatch intentionally precedes current protocol, pending and CAS.
        if receipt is not None:
            return _outcome(repo, transaction, receipt)
        if pending is not None:
            raise HotMethodError(f"pending_update: use --recover {pending.get('transaction_id')} --mode complete|restore")
        if decision is not None:
            raise HotMethodError("decision without pending/receipt")
        before, before_raw = _capture_manifest(repo)
        if _digest(before_raw) != request["update"]["expected_manifest"]:
            raise HotMethodError("manifest CAS conflict")
        if transaction is None:
            transaction = _prepare(files, request, before, before_raw, update,
                                   entry_migration=entry_migration, rules_migration=rules_migration)
        else:
            files = _MethodFiles(repo, transaction["directories"])
            if any(_position(files, item) != "before" for item in transaction["files"]):
                raise HotMethodError("unstarted transaction no longer matches before")
        _barriers(files, transaction)
        pending = {"schema_version": 1, "transaction_id": identity,
                   "transaction_sha256": _digest(_json_bytes(transaction))}
        files.create(HISTORY + "/pending.json", _json_bytes(pending))
        return _finish(files, transaction, "complete", recovery=False)


def recover_update(repo_root: Path | str, transaction_id: str, *, mode: str = "complete",
                   environ: dict[str, str] | None = None) -> dict:
    repo = _repo(repo_root)
    identity = _transaction_id(transaction_id)
    if mode not in {"complete", "restore"}:
        raise HotMethodError("recover mode must be complete or restore")
    environment = os.environ if environ is None else environ
    if "CCST_CLOWN_SNAPSHOT" in environment:
        raise HotMethodError("origin_only: external recovery forbidden")
    with _knowledge_lock(repo, exclusive=True):
        files = _MethodFiles(repo)
        transaction, decision, receipt, pending = _load_transaction(files, identity)
        if transaction is None:
            raise HotMethodError("unknown transaction")
        if decision is not None and decision["mode"] != mode:
            raise HotMethodError("terminal_" + receipt["outcome"] if receipt else "recovery direction already fixed")
        ours = pending is not None and pending.get("transaction_id") == identity
        if receipt is not None:
            if ours:
                files = _MethodFiles(repo, transaction["directories"])
                desired = "after" if mode == "complete" else "before"
                if any(_position(files, item) != desired for item in transaction["files"]):
                    raise HotMethodError("terminal files no longer match; pending preserved")
                _barriers(files, transaction)
                files.sync(_journal_path("decisions", identity))
                files.sync(_journal_path("receipts", identity))
                with files.parent(HISTORY + "/pending.json") as (parent, name):
                    os.unlink(name, dir_fd=parent)
                    os.fsync(parent)
                return _outcome(repo, transaction, receipt, cleanup="confirmed")
            if pending is None:
                # Only the still-current terminal may repair cleanup durability.
                state = _current_state(repo)
                if state["manifest_sha256"] == receipt["manifest_sha256"]:
                    files = _MethodFiles(repo, transaction["directories"])
                    desired = "after" if mode == "complete" else "before"
                    if all(_position(files, item) == desired for item in transaction["files"]):
                        with files.parent(HISTORY + "/pending.json") as (parent, _):
                            os.fsync(parent)
                        return _outcome(repo, transaction, receipt, cleanup="confirmed")
            return _outcome(repo, transaction, receipt)
        if pending is None:
            if decision is not None:
                raise HotMethodError("decision without pending or receipt")
            return {"status": "not_started", "transaction_id": identity, "current": _current_state(repo)}
        if not ours:
            raise HotMethodError("another transaction is pending")
        files = _MethodFiles(repo, transaction["directories"])
        return _finish(files, transaction, mode, recovery=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect, read or explicitly maintain bundled methods.")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--focus", default="", help="current question; never filters the catalog")
    parser.add_argument("--catalog", action="store_true", help="expand every method, without ranking")
    parser.add_argument("--diagnostics", action="store_true")
    parser.add_argument("--json", action="store_true")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--read", action="append")
    operation.add_argument("--origin")
    operation.add_argument("--apply")
    operation.add_argument("--migrate-entry", help="explicit versioned entry_migration + update envelope")
    operation.add_argument("--import-rules", help="explicit original-rule rules_migration + update envelope")
    operation.add_argument("--recover")
    parser.add_argument("--expected-manifest")
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--mode", choices=("complete", "restore"))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    identity = args.recover
    repo = None
    try:
        repo = _repo(args.repo_root)
        if args.bootstrap and not args.apply or args.mode and not args.recover:
            raise HotMethodError("bootstrap requires apply; mode requires recover")
        if args.read:
            if not args.expected_manifest:
                raise HotMethodError("--read requires --expected-manifest")
            result = read_methods(args.repo_root, args.read, expected_manifest=args.expected_manifest)
        elif args.origin:
            result = read_origin(args.repo_root, args.origin)
        elif args.apply or args.migrate_entry or args.import_rules:
            if not args.expected_manifest:
                raise HotMethodError("publication requires --expected-manifest")
            payload = json.loads(_read_absolute(Path(args.apply or args.migrate_entry or args.import_rules).absolute())[0])
            if args.migrate_entry or args.import_rules:
                key = "entry_migration" if args.migrate_entry else "rules_migration"
                if not isinstance(payload, dict) or set(payload) != {key, "update"}:
                    raise HotMethodError(f"migration requires explicit {key} + update")
                update = payload["update"]
                if isinstance(update, dict):
                    identity = update.get("transaction_id")
                publisher = migrate_entry if args.migrate_entry else import_rules
                result = publisher(args.repo_root, update, **{key: payload[key]}, expected_manifest=args.expected_manifest)
            else:
                if isinstance(payload, dict):
                    identity = payload.get("transaction_id")
                result = apply_update(args.repo_root, payload, expected_manifest=args.expected_manifest, bootstrap=args.bootstrap)
        elif args.recover:
            if not args.mode:
                raise HotMethodError("--recover requires explicit --mode")
            result = recover_update(args.repo_root, args.recover, mode=args.mode)
        else:
            result = build_hot_method_projection(args.repo_root, focus=args.focus,
                                                 include_catalog=args.catalog, diagnostics=args.diagnostics)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        current = _current_state(repo) if repo is not None else {"health": "unknown", "pending": {"present": "unknown"}}
        result = {"status": "error", "error": str(exc), "current": current,
                  "outcome": "unknown", "cleanup_durability": "unconfirmed"}
        if identity and repo is not None:
            try:
                _, decision, receipt, _ = _load_transaction(_MethodFiles(_repo(args.repo_root)), _transaction_id(identity))
                result["outcome"] = receipt["outcome"] if receipt else None
                modes = [decision["mode"]] if decision else ["complete", "restore"]
                result["recovery_commands"] = [shlex.join(["python3", str(_repo(args.repo_root) / "tools/hot_method.py"),
                                                          "--repo-root", str(_repo(args.repo_root)), "--recover", identity,
                                                          "--mode", mode, "--json"]) for mode in modes]
            except (OSError, ValueError, KeyError, TypeError):
                result["journal_health"] = "unknown"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.recover and result["status"] == "restored":
        return 0
    return 0 if result["status"] in {"ready", "accepted", "origin_only"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
