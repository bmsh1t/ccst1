"""Tests for GitHub Actions / CI scanning."""

import repo_ci_scan


def test_scan_repo_ci_flags_pull_request_target_and_unpinned_actions(tmp_path):
    workflow_dir = tmp_path / "repo" / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "unsafe.yml").write_text(
        """
name: unsafe
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
""".strip()
        + "\n",
        encoding="utf-8",
    )

    findings = repo_ci_scan.scan_repo_ci(str(tmp_path / "repo"))

    rule_ids = {finding.rule_id for finding in findings}
    assert "pull-request-target-checkout" in rule_ids
    assert "unpinned-third-party-action" in rule_ids


def test_scan_repo_ci_flags_self_hosted_and_unsafe_interpolation(tmp_path):
    workflow_dir = tmp_path / "repo" / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "runner.yml").write_text(
        """
name: runner
on: pull_request
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    findings = repo_ci_scan.scan_repo_ci(str(tmp_path / "repo"))

    rule_ids = {finding.rule_id for finding in findings}
    assert "self-hosted-untrusted-trigger" in rule_ids
    assert "unsafe-user-input-in-run" in rule_ids


import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import source_hunt
from repo_scan_models import RepoSourceMeta
from repo_source_artifacts import load_repo_source_summary


def _workflow(root, name, content):
    path = root / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    return path


WORKFLOW = """on: pull_request_target
jobs:
  check:
    if: github.actor == 'trusted-maintainer'
    permissions: read-all
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: vendor/first@v1
      - uses: vendor/second@v2
"""


def test_ci_candidates_preserve_exact_sources_without_inventing_trust(tmp_path):
    repo, output = tmp_path / "source", tmp_path / "output"
    raw = ("\ufeff" + WORKFLOW).replace("\n", "\r\n").encode()
    path = _workflow(repo, "check.yml", raw)
    candidates = repo_ci_scan.scan_repo_ci(repo, artifact_dir=output, repo_commit="a" * 40)
    assert {row.rule_id for row in candidates} == {"pull-request-target-checkout", "unpinned-third-party-action"}
    for row in candidates:
        assert row.severity == row.confidence == "unknown"
        assert row.metadata["status"] == "candidate"
        assert "attacker-controlled code" not in row.title
        assert row.line_number == 4
        assert (output / row.metadata["workflow_artifact"]).read_bytes() == raw
        assert row.metadata["workflow_sha256"] == hashlib.sha256(raw).hexdigest()
    assert next(row for row in candidates if row.rule_id == "unpinned-third-party-action").metadata["uses"] == [
        "vendor/first@v1", "vendor/second@v2"]
    inventory = json.loads((output / "repo_workflows.json").read_text())
    assert inventory["status"] == "complete" and inventory["repo_commit"] == "a" * 40
    artifact = output / inventory["workflows"][0]["artifact"]
    before = artifact.stat().st_ino
    repo_ci_scan.scan_repo_ci(repo, artifact_dir=output)
    assert artifact.stat().st_ino == before and path.read_bytes() == raw
    assert artifact.stat().st_mode & 0o777 == 0o600


def test_workflows_without_patterns_and_bad_yaml_are_retained_together(tmp_path):
    repo, output = tmp_path / "source", tmp_path / "output"
    good = _workflow(repo, "a.yml", WORKFLOW)
    harmless = _workflow(repo, "b.yaml", "on: push\njobs: {}\n")
    bad = _workflow(repo, "c.yml", "jobs: [\n")
    candidates = repo_ci_scan.scan_repo_ci(repo, artifact_dir=output)
    manifest = json.loads((output / "repo_workflows.json").read_text())
    assert manifest["status"] == "partial" and len(candidates) == 2
    assert manifest["total_files"] == 3 and manifest["remaining_files"] == 0
    assert [row["status"] for row in manifest["workflows"]] == ["ok", "ok", "invalid"]
    assert {hashlib.sha256(p.read_bytes()).hexdigest() for p in (good, harmless, bad)} == {
        row["sha256"] for row in manifest["workflows"]}
    for row in manifest["workflows"]:
        assert (output / row["artifact"]).read_bytes() == (repo / row["file_path"]).read_bytes()
    with pytest.raises(ValueError, match="incomplete"):
        repo_ci_scan.scan_repo_ci(repo)


@pytest.mark.parametrize("text", ["[]", "jobs: []", "jobs: {bad: []}", "jobs: {bad: {steps: scalar}}", b"\xff"])
def test_invalid_workflow_shapes_remain_explicitly_incomplete(tmp_path, text):
    repo, output = tmp_path / "source", tmp_path / "output"
    _workflow(repo, "bad.yml", text)
    assert repo_ci_scan.scan_repo_ci(repo, artifact_dir=output) == []
    manifest = json.loads((output / "repo_workflows.json").read_text())
    assert manifest["status"] == "partial"
    assert manifest["workflows"][0]["status"] == "invalid"
    assert (output / manifest["workflows"][0]["artifact"]).is_file()


def test_invalid_job_does_not_erase_other_job_candidates(tmp_path):
    repo, output = tmp_path / "source", tmp_path / "output"
    _workflow(repo, "mixed.yml", WORKFLOW + "  broken: []\n")
    assert len(repo_ci_scan.scan_repo_ci(repo, artifact_dir=output)) == 2
    assert json.loads((output / "repo_workflows.json").read_text())["status"] == "partial"


@pytest.mark.parametrize("kind", ["file", "directory", "fifo"])
def test_ci_does_not_follow_source_links_or_open_nonregular_files(tmp_path, kind):
    repo, output = tmp_path / "source", tmp_path / "output"
    path = _workflow(repo, "unsafe.yml", "jobs: {}\n")
    external = tmp_path / "external"
    external.mkdir()
    secret = external / "private.yml"
    secret.write_text("private original")
    if kind == "file":
        path.unlink()
        path.symlink_to(secret)
    elif kind == "directory":
        path.unlink()
        path.parent.rmdir()
        path.parent.symlink_to(external, target_is_directory=True)
    else:
        path.unlink()
        os.mkfifo(path)
    assert repo_ci_scan.scan_repo_ci(repo, artifact_dir=output) == []
    assert json.loads((output / "repo_workflows.json").read_text())["status"] == "partial"
    assert not (output / "repo_workflows").exists()
    assert secret.read_text() == "private original"


def test_ci_limits_are_partial_not_empty_clean(tmp_path, monkeypatch):
    repo, output = tmp_path / "source", tmp_path / "output"
    _workflow(repo, "a.yml", WORKFLOW)
    _workflow(repo, "b.yml", "jobs: {}\n")
    monkeypatch.setattr(repo_ci_scan, "MAX_WORKFLOW_FILES", 1)
    monkeypatch.setattr(repo_ci_scan, "MAX_WORKFLOW_BYTES", 8)
    assert repo_ci_scan.scan_repo_ci(repo, artifact_dir=output) == []
    manifest = json.loads((output / "repo_workflows.json").read_text())
    assert manifest["status"] == "partial" and manifest["remaining_files"] == 1
    assert manifest["deferred_paths"] == [".github/workflows/b.yml"]
    assert manifest["workflows"][0]["status"] == "oversized"
    assert "artifact" not in manifest["workflows"][0]


def test_ci_snapshot_change_is_rejected_without_overwrite(tmp_path):
    repo, output = tmp_path / "source", tmp_path / "output"
    _workflow(repo, "a.yml", WORKFLOW)
    repo_ci_scan.scan_repo_ci(repo, artifact_dir=output)
    artifact = next((output / "repo_workflows").glob("*.yaml"))
    artifact.write_text("modified")
    before = (output / "repo_workflows.json").read_bytes()
    with pytest.raises(ValueError, match="content identity"):
        repo_ci_scan.scan_repo_ci(repo, artifact_dir=output)
    assert artifact.read_text() == "modified" and (output / "repo_workflows.json").read_bytes() == before


def test_source_hunt_keeps_sources_after_temporary_clone_cleanup(tmp_path, monkeypatch):
    tmp = tempfile.TemporaryDirectory()
    repo = Path(tmp.name) / "clone"
    original = _workflow(repo, "test.yml", WORKFLOW).read_bytes()
    meta = RepoSourceMeta(source_kind="github_public", repo_url="https://github.com/TARGET/REPO",
                          repo_ref="main", repo_commit="b" * 40, clone_performed=True)
    monkeypatch.setattr(source_hunt, "acquire_repo_source", lambda **kw: (meta, str(repo), tmp))
    monkeypatch.setattr(source_hunt, "scan_repo_secrets", lambda _: [])
    result = source_hunt.run_source_hunt(target="target.test", repo_url=meta.repo_url, repo_root=tmp_path)
    assert result["status"] == "ok" and not repo.exists()
    output = Path(result["exposure_dir"])
    manifest = json.loads((output / "repo_workflows.json").read_text())
    assert manifest["repo_commit"] == result["source_meta"]["repo_commit"] == "b" * 40
    assert (output / manifest["workflows"][0]["artifact"]).read_bytes() == original
    summary = load_repo_source_summary(tmp_path, "target.test")
    assert summary["ci_findings"] == 2 and summary["workflow_status"] == "complete"
    assert not (tmp_path / "state").exists()


def test_local_source_version_is_context_not_a_clean_tree_claim(tmp_path, monkeypatch):
    import repo_source
    repo = tmp_path / "source"
    path = _workflow(repo, "test.yml", WORKFLOW)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                    "commit", "-qm", "fixture"], check=True)
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    modified = WORKFLOW.replace("ref: main", "ref: changed-worktree")
    path.write_text(modified)
    monkeypatch.setattr(repo_source, "_github_get_json", lambda *a, **kw: pytest.fail("local source must not contact GitHub"))
    monkeypatch.setattr(source_hunt, "scan_repo_secrets", lambda _: [])
    result = source_hunt.run_source_hunt(target="target.test", repo_path=str(repo), repo_root=tmp_path)
    assert result["source_meta"]["repo_commit"] == commit
    manifest = json.loads((Path(result["exposure_dir"]) / "repo_workflows.json").read_text())
    assert (Path(result["exposure_dir"]) / manifest["workflows"][0]["artifact"]).read_bytes() == modified.encode()
    assert "working-tree bytes may differ" in (Path(result["exposure_dir"]) / "repo_summary.md").read_text()


def test_source_hunt_partial_workflow_inventory_is_visible_and_nonzero(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "source"
    _workflow(repo, "bad.yml", "jobs: [\n")
    monkeypatch.setattr(source_hunt, "scan_repo_secrets", lambda _: [])
    args = ["--target", "target.test", "--repo-path", str(repo), "--repo-root", str(tmp_path)]
    assert source_hunt.main(args) == 2
    assert "Workflow scan: partial" in capsys.readouterr().out
    summary = load_repo_source_summary(tmp_path, "target.test")
    assert summary["status"] == "partial" and summary["workflow_status"] == "partial"
    assert "workflows=partial" in summary["summary_hint"]


def test_confirmation_required_does_not_reuse_old_workflow_status(tmp_path, monkeypatch):
    from repo_source import RepoConfirmationRequired
    output = tmp_path / "findings/target.test/exposure"
    output.mkdir(parents=True)
    (output / "repo_workflows.json").write_text('{"status":"complete","remaining_files":0,"workflows":[]}')
    meta = RepoSourceMeta(source_kind="github_public", threshold_exceeded=True)
    def acquire(**kw):
        raise RepoConfirmationRequired(meta)
    monkeypatch.setattr(source_hunt, "acquire_repo_source", acquire)
    monkeypatch.setattr(source_hunt, "scan_repo_ci", lambda *a, **kw: pytest.fail("must not scan before approval"))
    result = source_hunt.run_source_hunt(target="target.test", repo_url="TARGET/REPO", repo_root=tmp_path)
    assert result["status"] == "confirmation_required"
    assert load_repo_source_summary(tmp_path, "target.test")["workflow_status"] == "not_run"


@pytest.mark.parametrize("payload", ["broken JSON", '[]', '{"status":"complete","remaining_files":0,"workflows":["bad"]}',
                                     '{"status":"complete","remaining_files":1,"workflows":[]}'])
def test_workflow_summary_corruption_does_not_look_complete(tmp_path, payload):
    output = tmp_path / "findings/target.test/exposure"
    output.mkdir(parents=True)
    (output / "repo_workflows.json").write_text(payload)
    assert load_repo_source_summary(tmp_path, "target.test")["workflow_status"] == "invalid"


def test_workflow_snapshot_publication_failure_keeps_old_manifest_and_cleans_clone(tmp_path, monkeypatch):
    temporary = tempfile.TemporaryDirectory()
    repo = Path(temporary.name) / "clone"
    _workflow(repo, "ci.yml", WORKFLOW)
    output = tmp_path / "findings/target.test/exposure"
    output.mkdir(parents=True)
    manifest = output / "repo_workflows.json"
    manifest.write_text("previous manifest")
    meta = RepoSourceMeta(source_kind="github_public", clone_performed=True)
    monkeypatch.setattr(source_hunt, "acquire_repo_source", lambda **kw: (meta, str(repo), temporary))
    monkeypatch.setattr(source_hunt, "scan_repo_secrets", lambda _: [])
    def fail(*a):
        raise OSError("injected snapshot publish failure")
    monkeypatch.setattr(repo_ci_scan.os, "link", fail)
    with pytest.raises(OSError, match="snapshot publish"):
        source_hunt.run_source_hunt(target="target.test", repo_url="TARGET/REPO", repo_root=tmp_path)
    assert manifest.read_text() == "previous manifest" and not repo.exists()
    assert list((output / "repo_workflows").iterdir()) == []


def test_recursive_yaml_values_are_not_stringified_as_ci_signals(tmp_path):
    repo, output = tmp_path / "source", tmp_path / "output"
    _workflow(repo, "recursive.yml", "on: pull_request_target\njobs:\n  check:\n    steps:\n      - uses: &cycle [*cycle]\n")
    assert repo_ci_scan.scan_repo_ci(repo, artifact_dir=output) == []
    manifest = json.loads((output / "repo_workflows.json").read_text())
    assert manifest["status"] == "partial"
    assert "uses/run must be strings" in manifest["workflows"][0]["error"]
