"""Build historical inputs for isolation/import tests, outside runtime writers."""

import json
from pathlib import Path

from memory.schemas import validate_pattern_entry, validate_target_profile
from memory.target_profile import target_profile_path


def write_legacy_profile(memory_dir, profile):
    profile = validate_target_profile(profile)
    path = target_profile_path(memory_dir, profile["target"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile) + "\n", encoding="utf-8")
    return path


def append_legacy_pattern(path, entry):
    path = Path(path)
    entry = validate_pattern_entry(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    return path
