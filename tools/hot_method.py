"""Read-only projection of the pinned clown hot-method snapshot.

The adapter exposes source identity and health without copying method bodies,
writing target state, or selecting an execution route.  Consumers may use only
entries whose current hash still matches the pinned manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = Path("knowledge/clown-hot-method-manifest.json")
MANIFEST_SCHEMA = "ccst-hot-method/1"
VALID_ROLES = frozenset({"entry", "shortlist", "method"})
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TOKEN_RE = re.compile(r"[a-z0-9]+|[\u3400-\u9fff]+", re.IGNORECASE)


class HotMethodError(ValueError):
    """Raised when a hot-method manifest cannot be trusted."""


def _manifest_path(repo_root: Path | str) -> Path:
    return Path(repo_root) / MANIFEST_RELATIVE


def _validate_relative_path(value: object, *, index: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HotMethodError(f"entries[{index}].path must be a non-empty string")
    path = value.strip().replace("\\", "/")
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts or path.startswith("/"):
        raise HotMethodError(f"entries[{index}].path must stay below the source root")
    if "." in candidate.parts or not candidate.parts:
        raise HotMethodError(f"entries[{index}].path contains an invalid component")
    return "/".join(candidate.parts)


def load_manifest(repo_root: Path | str = BASE_DIR) -> dict[str, Any]:
    """Load and validate the repository-owned manifest without reading sources."""

    path = _manifest_path(repo_root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HotMethodError(f"manifest missing: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HotMethodError(f"manifest unreadable: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise HotMethodError("manifest root must be an object")
    if payload.get("schema") != MANIFEST_SCHEMA:
        raise HotMethodError(f"unsupported manifest schema: {payload.get('schema')!r}")
    source_id = payload.get("source_id")
    if not isinstance(source_id, str) or not source_id.strip():
        raise HotMethodError("manifest source_id must be a non-empty string")
    default_root = payload.get("default_root")
    if not isinstance(default_root, str) or not default_root.strip():
        raise HotMethodError("manifest default_root must be a non-empty string")
    root_env = payload.get("root_env")
    if not isinstance(root_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", root_env):
        raise HotMethodError("manifest root_env must be an uppercase environment name")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise HotMethodError("manifest entries must be a non-empty list")

    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise HotMethodError(f"entries[{index}] must be an object")
        relative = _validate_relative_path(raw.get("path"), index=index)
        digest = raw.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise HotMethodError(f"entries[{index}].sha256 must be a 64-character hex digest")
        role = raw.get("role")
        if role not in VALID_ROLES:
            raise HotMethodError(f"entries[{index}].role must be one of {sorted(VALID_ROLES)}")
        if relative in seen:
            raise HotMethodError(f"manifest contains duplicate path: {relative}")
        seen.add(relative)
        entries.append({"path": relative, "sha256": digest.lower(), "role": role})

    return {
        "schema": MANIFEST_SCHEMA,
        "source_id": source_id.strip(),
        "default_root": default_root.strip(),
        "root_env": root_env,
        "entries": entries,
        "manifest_path": str(path),
    }


def _resolve_source_root(manifest: dict[str, Any], environ: dict[str, str] | None = None) -> Path:
    environ = os.environ if environ is None else environ
    raw_root = str(environ.get(manifest["root_env"]) or manifest["default_root"]).strip()
    if not raw_root:
        raise HotMethodError("hot-method source root is empty")
    root = Path(raw_root).expanduser()
    if not root.is_absolute():
        raise HotMethodError("hot-method source root must be absolute")
    return root


def _safe_source_path(root: Path, relative: str) -> Path:
    """Resolve a manifest path while rejecting symlink escapes."""

    root_resolved = root.resolve(strict=False)
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise HotMethodError(f"manifest path escapes source root: {relative}") from exc
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(token.casefold() for token in TOKEN_RE.findall(value))


def _entry_score(entry: dict[str, str], focus_tokens: tuple[str, ...]) -> tuple[int, int, str]:
    role_rank = {"entry": 0, "shortlist": 1, "method": 2}[entry["role"]]
    path_text = entry["path"].casefold()
    if entry["role"] in {"entry", "shortlist"}:
        return (100 - role_rank, 0, entry["path"])
    hits = sum(1 for token in focus_tokens if token and token in path_text)
    return (hits, -len(entry["path"]), entry["path"])


def _invalid_projection(repo_root: Path | str, error: str) -> dict[str, Any]:
    return {
        "status": "invalid_manifest",
        "source_id": "",
        "root": "",
        "root_env": "",
        "manifest_path": str(_manifest_path(repo_root)),
        "focus": "",
        "entries": [],
        "hot_methods": [],
        "summary": {"total": 0, "ready": 0, "missing": 0, "changed": 0, "selected": 0},
        "error": error,
    }


def build_hot_method_projection(
    repo_root: Path | str = BASE_DIR,
    *,
    focus: str = "",
    max_methods: int = 6,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return deterministic, read-only pointers for the current hot source."""

    repo = Path(repo_root)
    try:
        manifest = load_manifest(repo)
        root = _resolve_source_root(manifest, environ)
    except HotMethodError as exc:
        result = _invalid_projection(repo, str(exc))
        result["focus"] = focus
        return result

    if max_methods < 0:
        max_methods = 0
    focus_tokens = _tokens(focus)
    diagnostics: list[dict[str, Any]] = []
    counts = {"ready": 0, "missing": 0, "changed": 0}
    for entry in manifest["entries"]:
        item = {
            "source_id": manifest["source_id"],
            "path": entry["path"],
            "role": entry["role"],
            "sha256": entry["sha256"],
            "actual_sha256": "",
            "status": "missing",
            "usable": False,
            "selected": False,
            "selection_reason": "",
        }
        try:
            path = _safe_source_path(root, entry["path"])
            if not path.is_file():
                item["error"] = "source file missing"
            else:
                actual = _sha256(path)
                item["actual_sha256"] = actual
                if actual == entry["sha256"]:
                    item["status"] = "ready"
                    item["usable"] = True
                else:
                    item["status"] = "changed"
                    item["error"] = "sha256 does not match manifest"
        except (HotMethodError, OSError) as exc:
            item["error"] = str(exc)
        counts[item["status"]] = counts.get(item["status"], 0) + 1
        diagnostics.append(item)

    selected: list[dict[str, Any]] = []
    method_budget = max_methods
    for item in sorted(diagnostics, key=lambda value: _entry_score(value, focus_tokens), reverse=True):
        role = item["role"]
        if role in {"entry", "shortlist"}:
            item["selected"] = True
            item["selection_reason"] = role
            selected.append(item)
        elif focus_tokens and method_budget and _entry_score(item, focus_tokens)[0] > 0:
            item["selected"] = True
            item["selection_reason"] = "focus:path"
            selected.append(item)
            method_budget -= 1

    hot_methods = [item for item in selected if item["usable"]]
    if counts["missing"]:
        status = "missing"
    elif counts["changed"]:
        status = "changed"
    else:
        status = "ready"
    return {
        "status": status,
        "source_id": manifest["source_id"],
        "root": str(root),
        "root_env": manifest["root_env"],
        "manifest_path": str(manifest["manifest_path"]),
        "focus": focus,
        "entries": diagnostics,
        "hot_methods": hot_methods,
        "summary": {
            "total": len(diagnostics),
            "ready": counts["ready"],
            "missing": counts["missing"],
            "changed": counts["changed"],
            "selected": len(selected),
            "usable_selected": len(hot_methods),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect the pinned read-only hot-method source.")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--focus", default="")
    parser.add_argument("--max-methods", type=int, default=6)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    projection = build_hot_method_projection(
        args.repo_root,
        focus=args.focus,
        max_methods=args.max_methods,
    )
    if args.json:
        print(json.dumps(projection, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(projection, ensure_ascii=False, indent=2))
    return 0 if projection["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
