"""tools/legacy_bridge.py 的回归测试。"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

import legacy_bridge

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"


def run_import_check(*modules: str, pythonpath: list[Path]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in pythonpath)
    code = "; ".join([*(f"import {name}" for name in modules), "print('ok')"])
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_open_hunt_journal_returns_journal_jsonl_path(tmp_path):
    journal = legacy_bridge.open_hunt_journal(tmp_path)

    assert journal.path == Path(tmp_path) / "journal.jsonl"


def test_hunt_journal_stable_reexport_from_memory_package():
    from memory import HuntJournal

    assert HuntJournal is legacy_bridge.HuntJournal


@pytest.mark.parametrize(
    "module_name",
    [
        "tools.legacy_bridge",
        "tools.resume",
        "tools.remember",
    ],
)
def test_package_imports_work_from_repo_root_without_tools_on_pythonpath(module_name):
    result = run_import_check(module_name, pythonpath=[REPO_ROOT])

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_top_level_imports_still_work_when_tools_directory_is_on_pythonpath():
    result = run_import_check("legacy_bridge", "resume", "remember", pythonpath=[TOOLS_DIR, REPO_ROOT])

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_run_legacy_cve_hunt_delegates_to_cve_hunter_and_passes_domain(monkeypatch, tmp_path):
    captured = {}
    recon_dir = str(tmp_path / "recon data" / "example$(touch marker).com")

    def fake_run_shell_command(cmd, *, cwd=None, timeout=600):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        return True, "ok"

    monkeypatch.setattr(legacy_bridge, "run_shell_command", fake_run_shell_command)

    success, output = legacy_bridge.run_legacy_cve_hunt(
        "example.com",
        base_dir=str(tmp_path),
        recon_dir=recon_dir,
        timeout=77,
    )

    parts = shlex.split(captured["cmd"])

    assert success is True
    assert output == "ok"
    assert parts[0] == "python3"
    assert parts[1].endswith("tools/cve_hunter.py")
    assert parts[2] == "example.com"
    assert parts[3] == "--recon-dir"
    assert parts[4] == recon_dir
    assert shlex.quote(recon_dir) in captured["cmd"]
    assert captured["cwd"] == str(tmp_path)
    assert captured["timeout"] == 77


def test_run_legacy_cve_hunt_omits_recon_dir_flag_when_missing(monkeypatch, tmp_path):
    captured = {}

    def fake_run_shell_command(cmd, *, cwd=None, timeout=600):
        captured["cmd"] = cmd
        return True, "ok"

    monkeypatch.setattr(legacy_bridge, "run_shell_command", fake_run_shell_command)

    legacy_bridge.run_legacy_cve_hunt(
        "example.com",
        base_dir=str(tmp_path),
        recon_dir=None,
    )

    parts = shlex.split(captured["cmd"])

    assert "--recon-dir" not in parts
    assert parts[2] == "example.com"


def test_run_legacy_cve_hunt_shell_quotes_special_domain(monkeypatch, tmp_path):
    captured = {}
    dangerous_domain = "odd $(touch hacked).example"

    def fake_run_shell_command(cmd, *, cwd=None, timeout=600):
        captured["cmd"] = cmd
        return True, "ok"

    monkeypatch.setattr(legacy_bridge, "run_shell_command", fake_run_shell_command)

    legacy_bridge.run_legacy_cve_hunt(
        dangerous_domain,
        base_dir=str(tmp_path),
        recon_dir=None,
    )

    parts = shlex.split(captured["cmd"])

    assert shlex.quote(dangerous_domain) in captured["cmd"]
    assert parts[2] == dangerous_domain


def test_generate_legacy_reports_delegates_to_report_generator_and_passes_findings_dir(monkeypatch, tmp_path):
    captured = {}
    findings_dir = str(tmp_path / "findings data" / "example$(touch report).com")

    def fake_run_shell_command(cmd, *, cwd=None, timeout=600):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        return True, "generated"

    monkeypatch.setattr(legacy_bridge, "run_shell_command", fake_run_shell_command)

    success, output = legacy_bridge.generate_legacy_reports(
        findings_dir,
        base_dir=str(tmp_path),
        timeout=45,
    )

    parts = shlex.split(captured["cmd"])

    assert success is True
    assert output == "generated"
    assert parts[0] == "python3"
    assert parts[1].endswith("tools/report_generator.py")
    assert parts[2] == findings_dir
    assert shlex.quote(findings_dir) in captured["cmd"]
    assert captured["cwd"] == str(tmp_path)
    assert captured["timeout"] == 45
