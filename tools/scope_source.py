"""Explicit target Scope configuration, independent of remembered target notes."""

from __future__ import annotations

import argparse
import hashlib
import os
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tools.scope_context import (
    SCHEMA_VERSION, ScopeContext, ScopeContextError, normalize_scope_source,
    read_scope_source, scope_limits, scope_source_path, write_scope_source_locked,
)
from tools.target_paths import canonical_target_value, classify_target

def scope_source_from_profile(profile: dict | None, target: str) -> dict:
    if profile is not None and (
        not isinstance(profile, dict)
        or not isinstance(profile.get("target"), str)
        or canonical_target_value(profile["target"]) != canonical_target_value(target)
    ):
        raise ScopeContextError(f"scope source target mismatch for {target}")
    snapshot = profile.get("scope_snapshot", {}) if profile else {}
    if not isinstance(snapshot, dict):
        raise ScopeContextError(f"invalid scope snapshot for {target}")
    try:
        return normalize_scope_source({"schema_version": SCHEMA_VERSION,
                                       "root_target": target, **snapshot}, target)
    except ScopeContextError as exc:
        raise ScopeContextError(f"invalid scope snapshot for {target}: {exc}") from exc


def load_scope_source(repo_root: str | Path, target: str, *, memory_dir: str | Path | None = None) -> dict:
    """Read explicit Scope before initialization without reviving Profile state."""
    from tools.target_store import StoreError, legacy_target_profile_path, target_backend

    backend = target_backend(repo_root, target)
    if backend == "preview":
        raise StoreError("preview Store cannot supply runtime Scope")
    path = scope_source_path(repo_root, target)
    if backend == "primary" or path.exists() or path.is_symlink():
        return read_scope_source(repo_root, target)
    memory = Path(memory_dir or os.environ.get("HUNT_MEMORY_DIR") or Path(repo_root) / "hunt-memory")
    profile = legacy_target_profile_path(memory, target)
    if profile.exists() or profile.is_symlink():
        raise ScopeContextError("legacy Scope requires explicit import; refusing implicit Profile fallback")
    # Scope is an execution prerequisite, not domain history. A fresh target
    # can be inspected before hunt explicitly initializes its Store.
    manifest = normalize_scope_source({"schema_version": SCHEMA_VERSION, "root_target": target}, target)
    return {"manifest": manifest, "source": "target", "path": "",
            "sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()}


def load_scope_context(repo_root: str | Path, target: str) -> ScopeContext:
    # A batch manifest is itself an explicit Scope input, not a target Store.
    if classify_target(target)["kind"] == "list":
        return ScopeContext.from_file(target)
    source = load_scope_source(repo_root, target)
    return ScopeContext.from_manifest(source["manifest"], source_ref=source["path"])


def publish_scope_source(repo_root: str | Path, target: str, payload: dict,
                         *, expected_sha256: str = "") -> dict:
    from tools.target_store import runtime_store, target_mutation_lock

    normalize_scope_source(payload, target)
    with target_mutation_lock(repo_root, target):
        runtime_store(repo_root, target)
        return write_scope_source_locked(repo_root, target, payload, expected_sha256=expected_sha256)


def main() -> int:
    parser = argparse.ArgumentParser(description="Show or explicitly publish target Scope configuration")
    parser.add_argument("command", choices=("show", "publish"))
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--target", required=True)
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument("--manifest", help="schema-v1 Scope JSON")
    sources.add_argument("--profile", help="explicit legacy Profile JSON to import Scope from")
    parser.add_argument("--expected-sha256", default="", help="current source digest when replacing Scope")
    args = parser.parse_args()
    try:
        if args.command == "show":
            if args.manifest or args.profile or args.expected_sha256:
                raise ScopeContextError("show does not accept publication arguments")
            result = load_scope_source(args.repo_root, args.target)
        else:
            if not (args.manifest or args.profile):
                raise ScopeContextError("publish requires --manifest or --profile")
            payload = json.loads(Path(args.manifest or args.profile).read_text(encoding="utf-8"))
            if args.profile:
                if not isinstance(payload, dict):
                    raise ScopeContextError("Profile must be an object")
                payload = scope_source_from_profile(payload, args.target)
            result = publish_scope_source(args.repo_root, args.target, payload,
                                          expected_sha256=args.expected_sha256)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(f"scope_source.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
