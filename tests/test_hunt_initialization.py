import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import hunt
from memory.hunt_journal import HuntJournal
from tools.target_store import StoreError, TargetStore


def test_primary_hunt_summary_uses_store_without_rewriting_legacy_profile(tmp_path, monkeypatch):
    target = "hunt-summary.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="current-finding", finding_id="current-finding",
        endpoint=f"https://{target}/current", method="GET", family="Authz",
        title="Current claim", claim="Review owner boundary", actor="operator",
    )
    memory_dir = tmp_path / "hunt-memory"
    profile_path = memory_dir / "targets" / f"{target}.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text("{retired profile", encoding="utf-8")
    report_dir = tmp_path / "reports" / target
    report_dir.mkdir(parents=True)
    (report_dir / "INDEX.json").write_text(
        '{"reports":[{"id":"retired","type":"SQLi"}]}', encoding="utf-8",
    )
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "HUNT_MEMORY_DIR", memory_dir)
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    hunt._auto_log_session_summary(target, recon_completed=True)

    entries = HuntJournal(memory_dir / "journal.jsonl").query(target=target)
    assert profile_path.read_text(encoding="utf-8") == "{retired profile"
    assert len(entries) == 1
    assert "authz" in entries[0]["notes"]
    assert "sqli" not in entries[0]["notes"]
    assert "Findings: 1" in entries[0]["notes"]


def test_hunt_rejects_legacy_target_before_binding_auth_or_execution(tmp_path, monkeypatch):
    target = "legacy.test"
    legacy_path = tmp_path / "state" / target / "case_state.json"
    legacy_path.parent.mkdir(parents=True)
    legacy_bytes = b'{"sessions":[]}'
    legacy_path.write_bytes(legacy_bytes)
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    class AuthSession:
        bound_target = ""

        def is_empty(self):
            return False

        def bind_target(self, value):
            self.bound_target = value

    auth_session = AuthSession()
    monkeypatch.setattr(hunt, "_active_auth_session", lambda: auth_session)
    monkeypatch.setattr(
        hunt,
        "_hunt_target_impl",
        lambda *args, **kwargs: pytest.fail("target execution started after initialization refusal"),
    )

    with pytest.raises(StoreError, match="legacy target state exists"):
        hunt.hunt_target(target)

    assert auth_session.bound_target == target
    assert legacy_path.read_bytes() == legacy_bytes
    assert not (legacy_path.parent / "metadata.sqlite3").exists()


def test_hunt_initializes_after_auth_binding_and_before_target_work(tmp_path, monkeypatch):
    from tools.target_store import TargetStore

    target = "fresh.test"
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path / "wordlists"))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)

    class AuthSession:
        def is_empty(self):
            return False

        def bind_target(self, value):
            assert value == target
            assert not TargetStore(tmp_path, target).path.exists()

    monkeypatch.setattr(hunt, "_active_auth_session", AuthSession)
    monkeypatch.setattr(
        hunt,
        "_hunt_target_impl",
        lambda value, **kwargs: (
            value,
            TargetStore(tmp_path, target).backend(),
            kwargs,
        ),
    )

    result = hunt.hunt_target(target, quick=True)

    assert result[0:2] == (target, "primary")
    assert result[2]["quick"] is True


def test_hunt_batch_list_does_not_initialize_a_list_store(tmp_path, monkeypatch):
    from tools.target_store import TargetStore

    target_list = tmp_path / "targets.txt"
    target_list.write_text("one.test\ntwo.test\n", encoding="utf-8")
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path / "wordlists"))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)
    monkeypatch.setattr(hunt, "_active_auth_session", lambda: type("Auth", (), {"is_empty": lambda self: True})())
    monkeypatch.setattr(
        hunt,
        "_hunt_target_impl",
        lambda value, **kwargs: (value, kwargs),
    )

    result = hunt.hunt_target(str(target_list), recon_only=True)

    list_target = hunt.classify_target(str(target_list))["target"]
    assert result[0] == str(target_list)
    assert not TargetStore(tmp_path, list_target).path.exists()


def _run_report_only_cli(tmp_path, args, outcomes):
    script = tmp_path / "tools" / "hunt.py"
    script.parent.mkdir()
    shutil.copyfile(hunt.__file__, script)
    repo = Path(hunt.__file__).resolve().parents[1]
    code = textwrap.dedent(f"""
        import os
        import runpy
        import sys
        from pathlib import Path
        from unittest.mock import patch

        sys.path[:0] = [{str(repo)!r}, {str(repo / 'tools')!r}]
        from tools.auth_session import AuthSession

        root = Path({str(tmp_path)!r})
        outcomes = {outcomes!r}
        listdir = os.listdir

        def report_result(argv, **kwargs):
            assert argv[:2] == [sys.executable, str(root / 'tools' / 'report_generator.py')]
            assert kwargs == {{'cwd': str(root), 'timeout': 600, 'env': None}}
            target = Path(argv[2]).name
            with (root / 'calls.txt').open('a') as calls:
                calls.write(target + '\\n')
            success, output = outcomes[target]
            if success:
                marker = root / 'reports' / target / 'generated.txt'
                marker.parent.mkdir(parents=True)
                marker.write_text('preserved success', encoding='utf-8')
            return success, output

        sys.argv = [{str(script)!r}, '--report-only', *{args!r}]
        with (
            patch('tools.auth_session.session_from_args', return_value=AuthSession()),
            patch('tools.runtime_config.load_runtime_config', return_value={{}}),
            patch('tools.eburst_lane.resolve_eburst', return_value={{'status': 'missing'}}),
            patch('shutil.which', return_value=None),
            patch('os.listdir', side_effect=lambda path: sorted(listdir(path), reverse=True)),
            patch('runtime_exec.run_argv_command', side_effect=report_result),
            patch('subprocess.Popen', side_effect=AssertionError('unexpected child tool')),
            patch('socket.socket.connect', side_effect=AssertionError('unexpected network access')),
        ):
            runpy.run_path({str(script)!r}, run_name='__main__')
    """)
    return subprocess.run(
        [sys.executable, "-c", code], cwd=tmp_path,
        env={"HOME": str(tmp_path), "PATH": os.defpath, "PYTHONNOUSERSITE": "1"},
        text=True, capture_output=True, timeout=15,
    )


@pytest.mark.parametrize("success, output, category", [
    (False, "Command timed out after 600s", "execution"),
    (True, "unknown report result", "protocol"),
])
def test_report_only_single_failure_exits_two(tmp_path, success, output, category):
    target = "failed.test"
    (tmp_path / "findings" / target).mkdir(parents=True)

    result = _run_report_only_cli(tmp_path, ["--target", target], {target: (success, output)})

    assert result.returncode == 2, result.stderr
    assert target in result.stderr and category in result.stderr
    assert output in result.stderr
    assert f"--report-only --target {target}" in result.stderr
    assert "Traceback" not in result.stderr
    assert (tmp_path / "calls.txt").read_text().splitlines() == [target]


def test_report_only_batch_continues_after_failure_in_stable_order(tmp_path):
    outcomes = {
        "z-success.test": (True, "[+] Indexed 1 current reports"),
        "a-failed.test": (False, "report publication failed"),
    }
    for target in outcomes:
        (tmp_path / "findings" / target).mkdir(parents=True)
    (tmp_path / "findings" / "notes.txt").write_text("not a target")

    result = _run_report_only_cli(tmp_path, [], outcomes)

    assert result.returncode == 2, result.stderr
    assert (tmp_path / "calls.txt").read_text().splitlines() == sorted(outcomes)
    assert "a-failed.test" in result.stderr and "report publication failed" in result.stderr
    marker = tmp_path / "reports" / "z-success.test" / "generated.txt"
    assert marker.read_text() == "preserved success"


def test_report_only_batch_all_zero_is_success(tmp_path):
    outcomes = {target: (True, "[+] Indexed 0 current reports") for target in ("z.test", "a.test")}
    for target in outcomes:
        (tmp_path / "findings" / target).mkdir(parents=True)

    result = _run_report_only_cli(tmp_path, [], outcomes)

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert (tmp_path / "calls.txt").read_text().splitlines() == sorted(outcomes)


@pytest.mark.parametrize("state", ["missing", "empty", "file", "files-only"])
def test_report_only_without_target_directories_is_success(tmp_path, state):
    findings = tmp_path / "findings"
    if state in {"empty", "files-only"}:
        findings.mkdir()
    if state == "file":
        findings.write_text("not a directory")
    elif state == "files-only":
        (findings / "notes.txt").write_text("not a target")

    result = _run_report_only_cli(tmp_path, [], {})

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert not (tmp_path / "calls.txt").exists()
    assert not (tmp_path / "reports").exists()


@pytest.fixture
def isolated_hunt_main(monkeypatch):
    monkeypatch.setattr(hunt, "_AUTH_SESSION", None)
    monkeypatch.setattr(hunt, "session_from_args", Mock(return_value=hunt.AuthSession()))
    monkeypatch.setattr(hunt, "load_config", Mock(return_value={}))
    for name in ("show_status", "setup_wordlists", "check_tools", "hunt_target", "print_dashboard", "generate_reports"):
        monkeypatch.setattr(hunt, name, Mock())
    hunt.check_tools.return_value = ([], [])
    with patch.dict(os.environ, {}, clear=True):
        yield


@pytest.mark.parametrize("mode, success", [
    ("status", True), ("setup-wordlists", True), ("target", True), ("target", False),
])
def test_hunt_non_report_main_preserves_dispatch(monkeypatch, isolated_hunt_main, mode, success):
    args = ["hunt.py", f"--{mode}"]
    result = {"target": "ordinary.test", "success": success}
    if mode == "target":
        args += ["ordinary.test", "--quick", "--scanner-skip", "nuclei"]
        hunt.hunt_target.return_value = result
    monkeypatch.setattr(sys, "argv", args)

    assert hunt.main() == 0

    if mode == "target":
        hunt.check_tools.assert_called_once_with()
        hunt.hunt_target.assert_called_once_with(
            "ordinary.test", quick=True, deep=False, recon_only=False, scan_only=False,
            scanner_full=False, scanner_skip="nuclei", ctf_mode=False,
        )
        hunt.print_dashboard.assert_called_once_with([result])
    else:
        getattr(hunt, mode.replace("-", "_") if mode != "status" else "show_status").assert_called_once_with()
        hunt.check_tools.assert_not_called()
        hunt.hunt_target.assert_not_called()
        hunt.print_dashboard.assert_not_called()
    if mode != "status":
        hunt.show_status.assert_not_called()
    if mode != "setup-wordlists":
        hunt.setup_wordlists.assert_not_called()
    hunt.generate_reports.assert_not_called()


@pytest.mark.parametrize("error", [
    hunt.RuntimePhaseBusy("ordinary.test", "recon", Path("lock")),
    StoreError("damaged target"),
    ValueError("invalid target"),
])
def test_hunt_non_report_expected_errors_still_exit_two(monkeypatch, isolated_hunt_main, error):
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--target", "ordinary.test"])
    hunt.hunt_target.side_effect = error

    with pytest.raises(SystemExit) as exc:
        hunt.main()

    assert exc.value.code == 2
    hunt.print_dashboard.assert_not_called()
    hunt.generate_reports.assert_not_called()


def test_report_only_unexpected_error_is_not_swallowed(monkeypatch, isolated_hunt_main):
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--report-only", "--target", "ordinary.test"])
    hunt.generate_reports.side_effect = ValueError("unexpected report error")

    with pytest.raises(ValueError, match="unexpected report error"):
        hunt.main()
