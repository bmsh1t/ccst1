"""Tests for tools/js_reader.prepare_materials."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.js_reader import (
    DEFAULT_MAX_FILES,
    _looks_like_vendor,
    prepare_materials,
)
from tools.target_paths import target_storage_key


def _write(path: Path, content: str = "// stub\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    """Provide an isolated repo root with empty recon/ and findings/."""
    (tmp_path / "recon").mkdir()
    (tmp_path / "findings").mkdir()
    return tmp_path


def test_no_recon_directory_returns_zero_materials(repo_root: Path) -> None:
    result = prepare_materials("ghost.example", repo_root=repo_root)

    assert result["selected_count"] == 0
    assert result["skipped_count"] == 0
    assert result["recon_artifacts_present"] is False
    assert result["source_intel_present"] is False

    materials = json.loads(Path(result["artifacts"]["materials"]).read_text(encoding="utf-8"))
    assert materials["target"] == "ghost.example"
    assert materials["selected_js_files"] == []
    assert materials["recon_extracted"] == {
        "js_urls": [],
        "endpoints": [],
        "endpoints_raw": [],
        "potential_secrets": [],
    }
    summary = Path(result["artifacts"]["summary"]).read_text(encoding="utf-8")
    assert "Run `/recon ghost.example` first" in summary


def test_collects_cached_js_files_and_recon_artifacts(repo_root: Path) -> None:
    target = "demo.app"
    _write(repo_root / "recon" / target / "js_dump" / "auth.js", "function login(){}\n")
    _write(repo_root / "recon" / target / "js_dump" / "api.js", "fetch('/api/users')\n")
    _write(
        repo_root / "recon" / target / "urls" / "js_files.txt",
        "https://demo.app/static/auth.js\nhttps://demo.app/static/api.js\n",
    )
    _write(
        repo_root / "recon" / target / "js" / "endpoints.txt",
        "/api/users\n/api/orders\n",
    )

    result = prepare_materials(target, repo_root=repo_root)

    assert result["selected_count"] == 2
    assert result["recon_artifacts_present"] is True

    materials = json.loads(Path(result["artifacts"]["materials"]).read_text(encoding="utf-8"))
    selected_paths = sorted(item["path"] for item in materials["selected_js_files"])
    assert selected_paths == [
        f"recon/{target}/js_dump/api.js",
        f"recon/{target}/js_dump/auth.js",
    ]
    assert materials["recon_extracted"]["endpoints"] == ["/api/users", "/api/orders"]
    assert materials["recon_extracted"]["js_urls"][0].startswith("https://demo.app/")


def test_prepare_materials_uses_storage_key_for_host_list_target(repo_root: Path) -> None:
    target_list = repo_root / "scope.txt"
    target_list.write_text("api.example.com\nshop.example.com\n", encoding="utf-8")
    stored_target = target_storage_key(str(target_list))

    _write(repo_root / "recon" / stored_target / "js_dump" / "app.js", "fetch('/api/users')\n")
    _write(
        repo_root / "recon" / stored_target / "urls" / "js_files.txt",
        "https://api.example.com/static/app.js\n",
    )

    result = prepare_materials(str(target_list), repo_root=repo_root)

    assert result["target"] == stored_target
    assert result["selected_count"] == 1

    materials = json.loads(Path(result["artifacts"]["materials"]).read_text(encoding="utf-8"))
    assert materials["target"] == stored_target
    assert materials["selected_js_files"][0]["path"] == f"recon/{stored_target}/js_dump/app.js"


def test_skips_oversize_and_vendor_files(repo_root: Path) -> None:
    target = "big.app"
    base = repo_root / "recon" / target / "js_dump"
    _write(base / "core.js", "// real app code\n")
    _write(base / "react.production.min.js", "// vendor bundle\n")
    _write(base / "huge.js", "x" * (300 * 1024))  # 300 KB > 200 KB cap

    result = prepare_materials(target, repo_root=repo_root, max_file_bytes=200 * 1024)
    materials = json.loads(Path(result["artifacts"]["materials"]).read_text(encoding="utf-8"))

    selected = [item["path"] for item in materials["selected_js_files"]]
    skipped = {item["path"]: item["reason"] for item in materials["skipped_js_files"]}

    assert selected == [f"recon/{target}/js_dump/core.js"]
    assert skipped[f"recon/{target}/js_dump/react.production.min.js"] == "vendor"
    assert skipped[f"recon/{target}/js_dump/huge.js"].startswith("oversize_")


def test_max_files_cap_is_respected(repo_root: Path) -> None:
    target = "many.app"
    base = repo_root / "recon" / target / "js_dump"
    for i in range(15):
        _write(base / f"file_{i:02d}.js", f"// {i}\n")

    result = prepare_materials(target, repo_root=repo_root, max_files=5)

    assert result["selected_count"] == 5


def test_loads_source_intel_when_present(repo_root: Path) -> None:
    target = "intel.app"
    _write(repo_root / "recon" / target / "js_dump" / "app.js")
    intel = {"hypotheses": [{"id": "h1", "title": "IDOR candidate"}]}
    _write(
        repo_root / "findings" / target / "source_intel" / "hypotheses.json",
        json.dumps(intel),
    )

    result = prepare_materials(target, repo_root=repo_root)

    assert result["source_intel_present"] is True
    materials = json.loads(Path(result["artifacts"]["materials"]).read_text(encoding="utf-8"))
    assert materials["source_intel"] == intel


def test_loads_current_source_intel_jsonl(repo_root: Path) -> None:
    target = "jsonl-intel.app"
    _write(repo_root / "recon" / target / "js_dump" / "app.js")
    _write(
        repo_root / "findings" / target / "source_intel" / "hypotheses.jsonl",
        json.dumps({"type": "idor", "candidate": "/api/users/{id}"}) + "\n"
        + json.dumps({"type": "business-logic", "candidate": "/api/orders/approve"}) + "\n",
    )
    _write(
        repo_root / "findings" / target / "source_intel" / "summary.md",
        "# Source Intelligence Summary\n",
    )

    result = prepare_materials(target, repo_root=repo_root)

    assert result["source_intel_present"] is True
    materials = json.loads(Path(result["artifacts"]["materials"]).read_text(encoding="utf-8"))
    assert materials["source_intel"]["format"] == "jsonl"
    assert [item["type"] for item in materials["source_intel"]["hypotheses"]] == [
        "idor",
        "business-logic",
    ]


def test_target_safe_path_normalization(repo_root: Path) -> None:
    """Targets with slashes / weird chars must not escape findings/."""
    weird = "a/b/../c.com"
    result = prepare_materials(weird, repo_root=repo_root)
    artifacts_path = Path(result["artifacts"]["materials"])
    assert artifacts_path.is_relative_to(repo_root / "findings")
    assert ".." not in artifacts_path.parts


def test_summary_markdown_mentions_caps_and_counts(repo_root: Path) -> None:
    target = "report.app"
    _write(repo_root / "recon" / target / "js_dump" / "x.js")
    result = prepare_materials(target, repo_root=repo_root)

    summary = Path(result["artifacts"]["summary"]).read_text(encoding="utf-8")
    assert f"max_files: {DEFAULT_MAX_FILES}" in summary
    assert "Selected JS files" in summary
    assert "Hand `materials.json` to the `js-reader` agent" in summary


def test_vendor_pattern_matcher() -> None:
    assert _looks_like_vendor(Path("react.production.min.js")) is True
    assert _looks_like_vendor(Path("vendors~main-abc.js")) is True
    assert _looks_like_vendor(Path("auth.js")) is False
