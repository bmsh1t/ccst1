#!/usr/bin/env python3
"""Check that every direct requirement is represented in the CI lock."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_REQ_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*(.*)$")
_LOCK_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")
_SOURCE_HASH_HEADER = "# source-sha256:"


def _included_requirement(line: str) -> str | None:
    for option in ("-r", "--requirement"):
        if line.startswith(f"{option} "):
            return line[len(option):].strip() or None
        if line.startswith(f"{option}="):
            return line[len(option) + 1:].strip() or None
    return None


def _requirement_sources(path: Path, seen: set[Path] | None = None) -> list[Path]:
    """Return root-first requirement files that affect the compiled lock."""
    seen = seen or set()
    path = path.resolve()
    if path in seen:
        return []
    seen.add(path)
    sources = [path]
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        included = _included_requirement(line)
        if included:
            sources.extend(_requirement_sources(path.parent / included, seen))
    return sources


def _requirement_names(path: Path, seen: set[Path] | None = None) -> dict[str, str]:
    seen = seen or set()
    path = path.resolve()
    if path in seen:
        return {}
    seen.add(path)
    requirements: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            included = _included_requirement(line)
            if included:
                requirements.update(_requirement_names(path.parent / included, seen))
            continue
        match = _REQ_RE.match(line)
        if match:
            requirements[match.group(1).lower().replace("_", "-")] = match.group(2).strip()
    return requirements


def _locked_versions(path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        match = _LOCK_RE.match(raw)
        if match:
            versions[match.group(1).lower().replace("_", "-")] = match.group(2)
    return versions


def _source_hashes(path: Path) -> dict[str, str]:
    root = ROOT.resolve()
    hashes = {}
    for source in _requirement_sources(path):
        try:
            name = source.relative_to(root).as_posix()
        except ValueError:
            name = str(source)
        hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    return hashes


def _locked_source_hashes(path: Path) -> dict[str, str] | None:
    header = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith(_SOURCE_HASH_HEADER):
            if header is not None:
                return None
            header = raw[len(_SOURCE_HASH_HEADER):].strip()
    if not header:
        return None
    parsed = {}
    for token in header.split():
        name, separator, digest = token.partition("=")
        if (
            not separator
            or not name
            or name in parsed
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            return None
        parsed[name] = digest
    return parsed or None


def main() -> int:
    requirements_path = ROOT / "requirements-dev.txt"
    lock_path = ROOT / "requirements-ci.lock"
    try:
        requirements = _requirement_names(requirements_path)
        expected_sources = _source_hashes(requirements_path)
        declared_sources = _locked_source_hashes(lock_path)
    except OSError as exc:
        print(f"Unable to read requirements or lock input: {exc}", file=sys.stderr)
        return 1
    if declared_sources != expected_sources:
        print(
            "requirements-ci.lock source hash mismatch; regenerate the lock from "
            "the current requirements files",
            file=sys.stderr,
        )
        return 1

    locked = _locked_versions(lock_path)
    missing = sorted(name for name in requirements if name not in locked)
    pinned_mismatch = sorted(
        f"{name} ({spec} vs {locked[name]})"
        for name, spec in requirements.items()
        if spec.startswith("==") and locked.get(name) != spec[2:].strip()
    )
    if missing or pinned_mismatch:
        if missing:
            print("Missing from requirements-ci.lock: " + ", ".join(missing), file=sys.stderr)
        if pinned_mismatch:
            print("Pinned requirement mismatch: " + ", ".join(pinned_mismatch), file=sys.stderr)
        return 1
    print(f"requirements-ci.lock covers {len(requirements)} direct requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
