"""Exact reading compatibility for retired Skill identities; not a route catalog.

Standard library only: knowledge readers and the installer share this vocabulary
without importing the YAML registry or a target owner.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


CORE_SKILL_NAME = "src-hunter"
CORE_SKILL_PATH = f"skills/{CORE_SKILL_NAME}/SKILL.md"
INTERNAL_MODULE_NAMES = (
    "web2-recon", "whitebox-audit", "credential-attack", "triage-validation",
    "report-writing", "cicd-security", "mobile-pentest", "web3-audit", "meme-coin-audit",
)
LEGACY_SKILL_READ_PATHS = {
    "src-hunting": CORE_SKILL_PATH,
    **{name: f"skills/{CORE_SKILL_NAME}/modules/{name}.md" for name in INTERNAL_MODULE_NAMES},
}
RETIRED_SKILL_NAMES = frozenset(LEGACY_SKILL_READ_PATHS) | {
    "bug-bounty", "bb-methodology", "web2-vuln-classes", "security-arsenal",
}
KNOWN_ENTRY_NAMES = RETIRED_SKILL_NAMES | {CORE_SKILL_NAME}
_NAME = r"[a-z0-9]+(?:-[a-z0-9]+)*"


class SkillReferenceError(ValueError):
    """The reference is unknown, unsafe, or lacks its current reading asset."""


def resolve_skill_reference(reference: str, repo_root: Path | str) -> dict:
    """Return navigation only; never rewrite metadata, review identities or state."""
    if not isinstance(reference, str) or reference != reference.strip() or not reference:
        raise SkillReferenceError("Skill reference must be non-empty canonical text")
    value, separator, anchor = reference.partition("#")
    if separator and (not anchor or any(ord(c) < 32 for c in anchor)):
        raise SkillReferenceError(f"invalid Skill reference anchor: {reference!r}")
    match = re.fullmatch(rf"skills/({_NAME})/SKILL\.md", value)
    name = match.group(1) if match else value
    historical = name in LEGACY_SKILL_READ_PATHS
    if historical:
        path = LEGACY_SKILL_READ_PATHS[name]
    elif re.fullmatch(_NAME, name):
        path = f"skills/{name}/SKILL.md"
    elif value in LEGACY_SKILL_READ_PATHS.values():
        path = value
    else:
        raise SkillReferenceError(f"unknown Skill reference: {reference}")
    root = Path(repo_root)
    destination = root / path
    if not destination.resolve().is_relative_to(root.resolve()) or not destination.is_file():
        raise SkillReferenceError(f"Skill reference {reference!r} has no current reading file: {path}")
    return {
        "reference": reference,
        "entry": CORE_SKILL_PATH if historical or path in LEGACY_SKILL_READ_PATHS.values() else path,
        "read_path": path + ("#" + anchor if separator else ""),
        "historical_label": historical,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = resolve_skill_reference(args.reference, args.repo_root)
    except (OSError, SkillReferenceError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False) if args.json else result["read_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
