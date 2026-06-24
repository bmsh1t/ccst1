"""Tests for tools/learn.py output path resolution."""

from __future__ import annotations

from pathlib import Path

from tools.learn import resolve_output_path


def test_resolve_output_path_uses_storage_key_for_host_list_target(tmp_path: Path, monkeypatch) -> None:
    list_file = tmp_path / "scope.txt"
    list_file.write_text("api.example.com\nshop.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    output_path = resolve_output_path(target="scope.txt", repo_root=str(tmp_path))

    assert output_path == str(tmp_path / "recon" / "scope" / "intel.md")
    assert (tmp_path / "recon" / "scope").is_dir()


def test_resolve_output_path_keeps_cidr_under_storage_key(tmp_path: Path) -> None:
    output_path = resolve_output_path(target="1.2.3.0/24", repo_root=str(tmp_path))

    assert output_path == str(tmp_path / "recon" / "1.2.3.0_24" / "intel.md")
    assert (tmp_path / "recon" / "1.2.3.0_24").is_dir()


def test_resolve_output_path_preserves_explicit_output(tmp_path: Path) -> None:
    explicit = tmp_path / "custom" / "intel.md"

    output_path = resolve_output_path(output=str(explicit), repo_root=str(tmp_path))

    assert output_path == str(explicit)
