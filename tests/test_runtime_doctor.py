from __future__ import annotations

import json
import sys
from pathlib import Path

from tools import runtime_doctor


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _repo_fixture(root: Path) -> Path:
    _write(root / "commands" / "autopilot.md", "repo command\n")
    _write(root / "commands" / "sync-check.md", "repo sync-check\n")
    _write(root / "agents" / "autopilot.md", "repo agent\n")
    _write(root / "skills" / "bug-bounty" / "SKILL.md", "repo skill\n")
    return root


def _runtime_fixture(root: Path) -> Path:
    _write(root / "commands" / "autopilot.md", "repo command\n")
    _write(root / "commands" / "doctor.md", "stale runtime doctor\n")
    _write(root / "agents" / "claude-bug-bounty" / "autopilot.md", "old agent\n")
    _write(root / "skills" / "bug-bounty" / "SKILL.md", "repo skill\n")
    return root


def _runtime_fixture_with_disabled_command(root: Path) -> Path:
    _write(root / "commands" / "autopilot.md", "repo command\n")
    _write(root / "commands" / ".disabled.sync-check.md", "repo sync-check\n")
    _write(root / "commands" / "doctor.md", "stale runtime doctor\n")
    _write(root / "agents" / "claude-bug-bounty" / "autopilot.md", "old agent\n")
    _write(root / "skills" / "bug-bounty" / "SKILL.md", "repo skill\n")
    return root


def _runtime_fixture_with_external_skill(root: Path) -> Path:
    _write(root / "commands" / "autopilot.md", "repo command\n")
    _write(root / "agents" / "claude-bug-bounty" / "autopilot.md", "repo agent\n")
    _write(root / "skills" / "bug-bounty" / "SKILL.md", "repo skill\n")
    _write(root / "skills" / "playwright-cli" / "SKILL.md", "external skill\n")
    return root


def test_compare_runtime_reports_diff_missing_and_extra(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture(tmp_path / "runtime")

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
    )

    assert payload["clean"] is False
    assert payload["drift_count"] == 3

    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["commands"]["counts"] == {"ok": 1, "diff": 0, "missing": 1, "extra": 1}
    assert by_kind["agents"]["counts"] == {"ok": 0, "diff": 1, "missing": 0, "extra": 0}
    assert by_kind["skills"]["counts"] == {"ok": 1, "diff": 0, "missing": 0, "extra": 0}
    assert {
        (item["status"], item["relative_path"])
        for item in by_kind["commands"]["items"]
        if item["status"] != "ok"
    } == {
        ("missing", "sync-check.md"),
        ("extra", "doctor.md"),
    }

    report = runtime_doctor.format_report(payload)
    assert "DIFF" in report
    assert "MISSING" in report
    assert "EXTRA" in report
    assert "sync-check.md" in report
    assert "doctor.md" in report
    assert "--prune" in report


def test_sync_runtime_refreshes_runtime_files(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture(tmp_path / "runtime")

    changes = runtime_doctor.sync_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands", "agents"],
    )

    assert changes["copied"]
    assert changes["removed"] == []
    assert (
        runtime_root / "agents" / "claude-bug-bounty" / "autopilot.md"
    ).read_text(encoding="utf-8") == "repo agent\n"
    assert (
        runtime_root / "commands" / "sync-check.md"
    ).read_text(encoding="utf-8") == "repo sync-check\n"
    assert (
        runtime_root / "commands" / "doctor.md"
    ).read_text(encoding="utf-8") == "stale runtime doctor\n"

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands", "agents"],
    )

    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["agents"]["counts"] == {"ok": 1, "diff": 0, "missing": 0, "extra": 0}
    assert by_kind["commands"]["counts"] == {"ok": 2, "diff": 0, "missing": 0, "extra": 1}


def test_sync_runtime_can_prune_runtime_only_extras(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture(tmp_path / "runtime")

    changes = runtime_doctor.sync_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands"],
        prune=True,
    )

    assert str(runtime_root / "commands" / "doctor.md") in changes["removed"]
    assert not (runtime_root / "commands" / "doctor.md").exists()

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands"],
    )
    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["commands"]["counts"] == {"ok": 2, "diff": 0, "missing": 0, "extra": 0}


def test_compare_runtime_treats_disabled_command_as_expected_state(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture_with_disabled_command(tmp_path / "runtime")

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands"],
    )

    assert payload["clean"] is False
    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["commands"]["counts"] == {"ok": 2, "diff": 0, "missing": 0, "extra": 1}
    assert {
        (item["status"], item["relative_path"])
        for item in by_kind["commands"]["items"]
        if item["status"] != "ok"
    } == {
        ("extra", "doctor.md"),
    }


def test_sync_runtime_preserves_intentionally_disabled_command(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture_with_disabled_command(tmp_path / "runtime")

    changes = runtime_doctor.sync_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands"],
    )

    disabled_path = runtime_root / "commands" / ".disabled.sync-check.md"
    active_path = runtime_root / "commands" / "sync-check.md"

    assert str(disabled_path) in changes["copied"]
    assert disabled_path.read_text(encoding="utf-8") == "repo sync-check\n"
    assert not active_path.exists()

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands"],
    )
    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["commands"]["counts"] == {"ok": 2, "diff": 0, "missing": 0, "extra": 1}


def test_sync_runtime_prune_keeps_disabled_command_that_matches_repo(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture_with_disabled_command(tmp_path / "runtime")

    changes = runtime_doctor.sync_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["commands"],
        prune=True,
    )

    disabled_path = runtime_root / "commands" / ".disabled.sync-check.md"
    doctor_path = runtime_root / "commands" / "doctor.md"

    assert disabled_path.exists()
    assert str(doctor_path) in changes["removed"]
    assert str(disabled_path) not in changes["removed"]


def test_compare_runtime_ignores_unrelated_external_skills(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture_with_external_skill(tmp_path / "runtime")

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
    )

    assert payload["clean"] is True
    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["skills"]["counts"] == {"ok": 1, "diff": 0, "missing": 0, "extra": 0}


def test_compare_runtime_includes_shared_skill_markdown_files(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture(tmp_path / "runtime")
    _write(repo_root / "skills" / "runtime-protocol.md", "repo shared protocol\n")

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
    )

    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["skills"]["counts"] == {"ok": 1, "diff": 0, "missing": 1, "extra": 0}
    assert any(
        item["status"] == "missing" and item["relative_path"] == "runtime-protocol.md"
        for item in by_kind["skills"]["items"]
    )


def test_compare_and_sync_runtime_recursively_manages_skill_resources(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture_with_external_skill(tmp_path / "runtime")
    repo_reference = repo_root / "skills" / "bug-bounty" / "references" / "routing.md"
    runtime_reference = runtime_root / "skills" / "bug-bounty" / "references" / "routing.md"
    stale_reference = runtime_root / "skills" / "bug-bounty" / "references" / "stale.md"
    external_reference = runtime_root / "skills" / "playwright-cli" / "references" / "external.md"
    _write(repo_reference, "repo nested reference\n")
    _write(runtime_reference, "old nested reference\n")
    _write(stale_reference, "stale managed resource\n")
    _write(external_reference, "external resource\n")

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
    )

    skills = payload["kinds"][0]
    assert skills["counts"] == {"ok": 1, "diff": 1, "missing": 0, "extra": 1}
    assert {
        (item["status"], item["relative_path"])
        for item in skills["items"]
        if item["status"] != "ok"
    } == {
        ("diff", "bug-bounty/references/routing.md"),
        ("extra", "bug-bounty/references/stale.md"),
    }
    assert all("playwright-cli" not in item["relative_path"] for item in skills["items"])

    changes = runtime_doctor.sync_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
        prune=True,
    )

    assert runtime_reference.read_text(encoding="utf-8") == "repo nested reference\n"
    assert not stale_reference.exists()
    assert external_reference.read_text(encoding="utf-8") == "external resource\n"
    assert str(runtime_reference) in changes["copied"]
    assert str(stale_reference) in changes["removed"]
    assert runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
    )["clean"] is True


def test_compare_runtime_reports_missing_nested_skill_resource(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture(tmp_path / "runtime")
    _write(
        repo_root / "skills" / "bug-bounty" / "references" / "routing.md",
        "repo nested reference\n",
    )

    payload = runtime_doctor.compare_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
    )

    skills = payload["kinds"][0]
    assert skills["counts"] == {"ok": 1, "diff": 0, "missing": 1, "extra": 0}
    assert any(
        item["status"] == "missing"
        and item["relative_path"] == "bug-bounty/references/routing.md"
        for item in skills["items"]
    )

def test_sync_runtime_copies_shared_skill_markdown_files(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture(tmp_path / "runtime")
    _write(repo_root / "skills" / "runtime-protocol.md", "repo shared protocol\n")

    changes = runtime_doctor.sync_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
    )

    shared_path = runtime_root / "skills" / "runtime-protocol.md"
    assert str(shared_path) in changes["copied"]
    assert shared_path.read_text(encoding="utf-8") == "repo shared protocol\n"


def test_sync_runtime_prune_does_not_remove_unrelated_external_skills(tmp_path):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture_with_external_skill(tmp_path / "runtime")

    changes = runtime_doctor.sync_runtime(
        repo_root=repo_root,
        runtime_root=runtime_root,
        kinds=["skills"],
        prune=True,
    )

    external_skill = runtime_root / "skills" / "playwright-cli" / "SKILL.md"

    assert external_skill.exists()
    assert str(external_skill) not in changes["removed"]


def test_runtime_doctor_main_json_and_fail_on_drift(tmp_path, monkeypatch, capsys):
    repo_root = _repo_fixture(tmp_path / "repo")
    runtime_root = _runtime_fixture(tmp_path / "runtime")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "runtime_doctor.py",
            "--repo-root",
            str(repo_root),
            "--runtime-root",
            str(runtime_root),
            "--json",
        ],
    )

    assert runtime_doctor.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["clean"] is False
    by_kind = {item["kind"]: item for item in payload["kinds"]}
    assert by_kind["commands"]["counts"]["extra"] == 1
    assert any(
        item["status"] == "extra" and item["relative_path"] == "doctor.md"
        for item in by_kind["commands"]["items"]
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "runtime_doctor.py",
            "--repo-root",
            str(repo_root),
            "--runtime-root",
            str(runtime_root),
            "--fail-on-drift",
        ],
    )

    assert runtime_doctor.main() == 1
