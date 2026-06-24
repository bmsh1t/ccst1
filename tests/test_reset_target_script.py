"""Regression tests for tools/reset_target.sh."""

import os
import subprocess
from pathlib import Path


def test_reset_target_bash_syntax_is_valid():
    script = Path(__file__).resolve().parent.parent / "tools" / "reset_target.sh"

    result = subprocess.run(
        ["bash", "-n", str(script)],
        cwd=script.resolve().parent.parent,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_reset_target_removes_target_scoped_state_only(tmp_path):
    repo_root = tmp_path / "repo"
    script = Path(__file__).resolve().parent.parent / "tools" / "reset_target.sh"
    env = os.environ.copy()
    env["BBHUNT_BASE_DIR"] = str(repo_root)

    (repo_root / "tools").mkdir(parents=True, exist_ok=True)
    (repo_root / "recon" / "target.com").mkdir(parents=True)
    (repo_root / "findings" / "target.com").mkdir(parents=True)
    (repo_root / "reports" / "target.com").mkdir(parents=True)
    (repo_root / "state" / "target.com").mkdir(parents=True)
    (repo_root / "targets" / "target.com" / "sessions" / "sess-001").mkdir(parents=True)
    (repo_root / "hunt-memory" / "targets").mkdir(parents=True)
    (repo_root / "hunt-memory" / "guards").mkdir(parents=True)

    (repo_root / "recon" / "target.com" / "live.txt").write_text("x\n", encoding="utf-8")
    (repo_root / "findings" / "target.com" / "summary.txt").write_text("x\n", encoding="utf-8")
    (repo_root / "reports" / "target.com" / "report.md").write_text("x\n", encoding="utf-8")
    (repo_root / "state" / "target.com" / "session.json").write_text("{}", encoding="utf-8")
    (repo_root / "targets" / "target.com" / "sessions" / "sess-001" / "agent_session.json").write_text("{}", encoding="utf-8")
    (repo_root / "hunt-memory" / "targets" / "target-com.json").write_text("{}", encoding="utf-8")
    (repo_root / "hunt-memory" / "guards" / "target-com.json").write_text("{}", encoding="utf-8")

    journal = repo_root / "hunt-memory" / "journal.jsonl"
    patterns = repo_root / "hunt-memory" / "patterns.jsonl"
    audit = repo_root / "hunt-memory" / "audit.jsonl"
    journal.write_text("journal\n", encoding="utf-8")
    patterns.write_text("patterns\n", encoding="utf-8")
    audit.write_text("audit\n", encoding="utf-8")

    result = subprocess.run(
        ["bash", str(script), "target.com"],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert not (repo_root / "recon" / "target.com").exists()
    assert not (repo_root / "findings" / "target.com").exists()
    assert not (repo_root / "reports" / "target.com").exists()
    assert not (repo_root / "state" / "target.com").exists()
    assert not (repo_root / "targets" / "target.com" / "sessions").exists()
    assert not (repo_root / "hunt-memory" / "targets" / "target-com.json").exists()
    assert not (repo_root / "hunt-memory" / "guards" / "target-com.json").exists()
    assert journal.read_text(encoding="utf-8") == "journal\n"
    assert patterns.read_text(encoding="utf-8") == "patterns\n"
    assert audit.read_text(encoding="utf-8") == "audit\n"
    assert "global journal/pattern memory stays intact" in result.stdout.lower()


def test_reset_target_print_only_keeps_files(tmp_path):
    repo_root = tmp_path / "repo"
    script = Path(__file__).resolve().parent.parent / "tools" / "reset_target.sh"
    env = os.environ.copy()
    env["BBHUNT_BASE_DIR"] = str(repo_root)

    (repo_root / "recon" / "target.com").mkdir(parents=True)

    result = subprocess.run(
        ["bash", str(script), "target.com", "--print-only"],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert (repo_root / "recon" / "target.com").exists()
    assert "[dry-run] No files were deleted." in result.stdout
