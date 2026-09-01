#!/usr/bin/env python3
"""Check that every direct requirement is represented in the CI lock."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_REQ_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*(.*)$")
_LOCK_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")


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
            if line.startswith("-r "):
                requirements.update(_requirement_names(path.parent / line[3:].strip(), seen))
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


def main() -> int:
    requirements = _requirement_names(ROOT / "requirements-dev.txt")
    locked = _locked_versions(ROOT / "requirements-ci.lock")
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
