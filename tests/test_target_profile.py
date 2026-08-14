"""Tests for memory/target_profile.py."""

import json
from pathlib import Path

import pytest

from memory.target_profile import (
    default_memory_dir,
    load_target_profile,
    make_target_profile,
    save_target_profile,
    target_filename,
    target_profile_path,
)


class TestTargetProfileHelpers:

    def test_target_filename_normalizes_domain(self):
        assert target_filename("api.target.com") == "api-target-com.json"

    def test_target_filename_reuses_canonical_host_list_path(self, tmp_path, monkeypatch):
        list_file = tmp_path / "scope.txt"
        list_file.write_text("api.target.com\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        assert target_filename("scope.txt") == target_filename(str(list_file.resolve()))

    def test_target_profile_path_uses_targets_dir(self, tmp_hunt_dir):
        path = target_profile_path(tmp_hunt_dir, "target.com")
        assert path.name == "target-com.json"
        assert path.parent.name == "targets"

    def test_make_save_and_load_profile(self, tmp_hunt_dir):
        profile = make_target_profile(
            "target.com",
            tested_endpoints=["/api/v1/users"],
            untested_endpoints=["/api/v2/export"],
            findings=[{"id": "idor_001", "severity": "high"}],
            hunt_sessions=1,
        )
        save_target_profile(tmp_hunt_dir, profile)
        loaded = load_target_profile(tmp_hunt_dir, "target.com")

        assert loaded is not None
        assert loaded["target"] == "target.com"
        assert loaded["tested_endpoints"] == ["/api/v1/users"]
        assert loaded["untested_endpoints"] == ["/api/v2/export"]
        assert loaded["hunt_sessions"] == 1

    def test_missing_profile_is_the_only_empty_state(self, tmp_hunt_dir):
        assert load_target_profile(tmp_hunt_dir, "missing.test") is None

        path = target_profile_path(tmp_hunt_dir, "broken.test")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{", encoding="utf-8")
        original = path.read_bytes()

        with pytest.raises(ValueError, match=str(path)):
            load_target_profile(tmp_hunt_dir, "broken.test")

        assert path.read_bytes() == original

    def test_invalid_profile_schema_fails_with_path(self, tmp_hunt_dir):
        path = target_profile_path(tmp_hunt_dir, "broken.test")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"target": "broken.test"}), encoding="utf-8")

        with pytest.raises(ValueError, match=str(path)):
            load_target_profile(tmp_hunt_dir, "broken.test")

    def test_invalid_profile_encoding_fails_with_path(self, tmp_hunt_dir):
        path = target_profile_path(tmp_hunt_dir, "broken.test")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\xff")

        with pytest.raises(ValueError, match=str(path)):
            load_target_profile(tmp_hunt_dir, "broken.test")

    def test_atomic_replace_failure_preserves_old_profile_and_retry_converges(
        self,
        tmp_hunt_dir,
        monkeypatch,
    ):
        old_profile = make_target_profile("target.com", tested_endpoints=["/old"], hunt_sessions=1)
        path = save_target_profile(tmp_hunt_dir, old_profile)
        old_bytes = path.read_bytes()
        new_profile = make_target_profile("target.com", tested_endpoints=["/old", "/new"], hunt_sessions=2)
        real_replace = Path.replace

        def fail_replace(_self, _target):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(Path, "replace", fail_replace)
        with pytest.raises(OSError, match="simulated replace failure"):
            save_target_profile(tmp_hunt_dir, new_profile)

        assert path.read_bytes() == old_bytes
        assert not list(path.parent.glob(f".{path.name}.*.tmp"))

        monkeypatch.setattr(Path, "replace", real_replace)
        save_target_profile(tmp_hunt_dir, new_profile)
        loaded = load_target_profile(tmp_hunt_dir, "target.com")
        assert loaded["tested_endpoints"] == ["/old", "/new"]
        assert loaded["hunt_sessions"] == 2

    def test_default_memory_dir_uses_base_dir(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HUNT_MEMORY_DIR", raising=False)
        assert default_memory_dir(tmp_path) == tmp_path / "hunt-memory"
