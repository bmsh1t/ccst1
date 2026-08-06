#!/usr/bin/env python3
"""Create and validate owner-generated batch-to-target continuation artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from tools.private_artifacts import copy_private_file, private_artifact_dir
    from tools.scope_context import ScopeContext, ScopeContextError
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from private_artifacts import copy_private_file, private_artifact_dir
    from scope_context import ScopeContext, ScopeContextError
    from target_paths import canonical_target_value, target_storage_key


SCHEMA_VERSION = 1


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _continuation_dir(repo_root: Path, parent_target: str) -> Path:
    return repo_root / "state" / target_storage_key(parent_target) / "continuations"


def _repo_relative(repo_root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(repo_root.resolve()))


def _invocation_id(scope: ScopeContext, selected_target: str, auth_digest: str) -> str:
    identity = "\n".join(
        (scope.source_ref or scope.root_target, scope.scope_hash, selected_target, auth_digest)
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def create_continuation(
    repo_root: str | Path,
    *,
    parent_target: str,
    selected_target: str,
    auth_file: str | Path | None = None,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    scope = ScopeContext.from_target(parent_target)
    selected = canonical_target_value(selected_target)
    if not scope.allows_active(selected):
        raise ScopeContextError(f"selected target is not in parent Scope: {selected}")

    auth_source = Path(auth_file).expanduser().resolve() if auth_file else None
    if auth_source is not None and not auth_source.is_file():
        raise ValueError(f"auth file is not readable: {auth_source}")
    auth_digest = _sha256_file(auth_source) if auth_source is not None else ""
    invocation_id = _invocation_id(scope, selected, auth_digest)

    auth_private_ref = ""
    if auth_source is not None:
        private_dir = private_artifact_dir(
            repo,
            "autopilot-continuation",
            target_storage_key(parent_target),
            invocation_id,
        )
        private_path = copy_private_file(auth_source, private_dir / f"auth{auth_source.suffix}")
        auth_private_ref = _repo_relative(repo, private_path)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "invocation_id": invocation_id,
        "selected_target": selected,
        "parent_target": canonical_target_value(parent_target),
        "scope_ref": scope.source_ref or scope.root_target,
        "scope_hash": scope.scope_hash,
        "auth_private_ref": auth_private_ref,
        "auth_sha256": auth_digest,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_action_id": f"batch-select:{scope.scope_hash.removeprefix('sha256:')[:12]}:{target_storage_key(selected)}",
    }
    path = _continuation_dir(repo, parent_target) / f"{target_storage_key(selected)}-{invocation_id}.json"
    _write_json_atomic(path, payload)
    return {"path": str(path), "relative_path": _repo_relative(repo, path), "continuation": payload}


def load_continuation(
    repo_root: str | Path,
    context_file: str | Path,
    *,
    selected_target: str,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    path = Path(context_file).expanduser().resolve()
    try:
        path.relative_to((repo / "state").resolve())
    except ValueError as exc:
        raise ValueError("continuation path must be under the repository state directory") from exc
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"continuation file is not readable: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid continuation JSON {path}: {exc.msg}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported continuation schema: {path}")

    selected = canonical_target_value(selected_target)
    if str(payload.get("selected_target") or "") != selected:
        raise ValueError("continuation selected target does not match invocation target")
    parent_target = str(payload.get("parent_target") or "")
    scope_ref = str(payload.get("scope_ref") or "")
    if parent_target != canonical_target_value(scope_ref):
        raise ValueError("continuation parent target does not match Scope owner")
    expected_dir = _continuation_dir(repo, parent_target).resolve()
    if path.parent != expected_dir:
        raise ValueError("continuation path does not match its parent target owner")

    scope = ScopeContext.from_target(scope_ref)
    if scope.scope_hash != str(payload.get("scope_hash") or ""):
        raise ValueError("continuation Scope hash is stale")
    if not scope.allows_active(selected):
        raise ScopeContextError(f"selected target is no longer in parent Scope: {selected}")

    auth_file = ""
    auth_ref = str(payload.get("auth_private_ref") or "")
    auth_digest = str(payload.get("auth_sha256") or "")
    if bool(auth_ref) != bool(auth_digest):
        raise ValueError("continuation auth ref and digest must be present together")
    if auth_ref:
        auth_path = (repo / auth_ref).resolve()
        try:
            auth_path.relative_to((repo / ".private").resolve())
        except ValueError as exc:
            raise ValueError("continuation auth ref must stay under .private") from exc
        if not auth_path.is_file() or _sha256_file(auth_path) != auth_digest:
            raise ValueError("continuation auth ref is missing or stale")
        auth_file = str(auth_path)

    invocation_id = _invocation_id(scope, selected, auth_digest)
    if str(payload.get("invocation_id") or "") != invocation_id:
        raise ValueError("continuation invocation identity is stale")
    if path.name != f"{target_storage_key(selected)}-{invocation_id}.json":
        raise ValueError("continuation path does not match its invocation identity")

    return {
        "path": str(path),
        "continuation": payload,
        "scope_context": scope,
        "auth_file": auth_file,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a batch Autopilot continuation")
    parser.add_argument("create", nargs="?")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--parent-target", required=True)
    parser.add_argument("--selected-target", required=True)
    parser.add_argument("--auth-file", default="")
    args = parser.parse_args()
    try:
        result = create_continuation(
            args.repo_root,
            parent_target=args.parent_target,
            selected_target=args.selected_target,
            auth_file=args.auth_file or None,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
