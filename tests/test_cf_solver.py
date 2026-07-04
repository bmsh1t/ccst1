"""静态/本地行为测试：Cloudflare solver 保持手动可选，不触网。"""

from pathlib import Path

from tools import cf_solver


def test_cf_solver_check_cookie_without_saved_cookie_is_local_only(tmp_path, monkeypatch):
    monkeypatch.setattr(cf_solver, "BASE_DIR", tmp_path)

    assert cf_solver.check_cookie("https://example.test/") is None


def test_cf_solver_export_env_pairs_cookie_with_user_agent(capsys):
    headers = cf_solver.write_output(
        [{"name": "cf_clearance", "value": "token123"}],
        "https://example.test/",
        export_env=True,
    )

    output = capsys.readouterr().out
    assert "export BBHUNT_AUTH_HEADERS=" in output
    assert "cf_clearance=token123" in headers
    assert "User-Agent:" in headers
    assert cf_solver.CF_UA in headers


def test_cf_solver_is_documented_as_manual_optional_helper():
    repo = Path(__file__).resolve().parents[1]
    tool_index = (repo / "docs" / "tool-index.md").read_text(encoding="utf-8")
    config_example = (repo / "config.example.json").read_text(encoding="utf-8")
    source = (repo / "tools" / "cf_solver.py").read_text(encoding="utf-8")

    assert "tools/cf_solver.py" in tool_index
    assert "manual-only" in tool_index
    assert "Not auto-run by /autopilot" in config_example
    assert "BBHUNT_AUTH_HEADERS" in source
    assert "BBHUNT_COOKIE" not in source
