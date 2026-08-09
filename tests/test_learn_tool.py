"""Tests for tools/learn.py."""

from __future__ import annotations

import json
from pathlib import Path

from tools import learn
from tools.graphql_utils import escape_graphql_string
from tools.target_paths import target_storage_key


def test_resolve_output_path_uses_storage_key_for_host_list_target(tmp_path: Path, monkeypatch) -> None:
    list_file = tmp_path / "scope.txt"
    list_file.write_text("api.example.com\nshop.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    output_path = learn.resolve_output_path(target="scope.txt", repo_root=str(tmp_path))
    storage_key = target_storage_key(str(list_file))

    assert output_path == str(tmp_path / "recon" / storage_key / "intel.md")
    assert (tmp_path / "recon" / storage_key).is_dir()


def test_resolve_output_path_keeps_cidr_under_storage_key(tmp_path: Path) -> None:
    output_path = learn.resolve_output_path(target="1.2.3.0/24", repo_root=str(tmp_path))

    assert output_path == str(tmp_path / "recon" / "1.2.3.0_24" / "intel.md")
    assert (tmp_path / "recon" / "1.2.3.0_24").is_dir()


def test_resolve_output_path_preserves_explicit_output(tmp_path: Path) -> None:
    explicit = tmp_path / "custom" / "intel.md"

    output_path = learn.resolve_output_path(output=str(explicit), repo_root=str(tmp_path))

    assert output_path == str(explicit)


def test_escape_graphql_string_handles_graphql_control_characters() -> None:
    value = 'quote" slash\\ newline\ncarriage\r tab\t'

    assert escape_graphql_string(value) == 'quote\\" slash\\\\ newline\\ncarriage\\r tab\\t'


def test_hacktivity_query_escapes_keyword(monkeypatch) -> None:
    captured: dict[str, bytes] = {}

    def fake_fetch_url(url: str, headers: dict, data: bytes) -> dict:
        captured["data"] = data
        return {"data": {"hacktivity_items": {"nodes": []}}}

    monkeypatch.setattr(learn, "fetch_url", fake_fetch_url)
    keyword = 'x" } } injected\\\nnext'

    assert learn.fetch_hackerone_hacktivity(keyword) == []

    query = json.loads(captured["data"])["query"]
    assert f'_icontains: "{escape_graphql_string(keyword)}"' in query
