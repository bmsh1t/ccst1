"""静态/本地行为测试：Cloudflare solver 保持手动可选，不触网。"""

from pathlib import Path

from tools import cf_solver


def test_cf_solver_check_cookie_without_saved_cookie_is_local_only(tmp_path, monkeypatch):
    monkeypatch.setattr(cf_solver, "BASE_DIR", tmp_path)

    assert cf_solver.check_cookie("https://example.test/") is None


def test_cf_solver_export_env_pairs_cookie_with_user_agent(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(cf_solver, "BASE_DIR", tmp_path)
    headers = cf_solver.write_output(
        [{"name": "cf_clearance", "value": "token123"}],
        "https://example.test/",
        export_env=True,
    )

    output = capsys.readouterr().out
    assert "source " in output
    assert "token123" not in output
    assert "cf_clearance=token123" in headers
    assert "User-Agent:" in headers
    assert cf_solver.CF_UA in headers
    private_dir = tmp_path / ".private" / "cf" / "example.test"
    assert "token123" in (private_dir / "cf_cookies.txt").read_text(encoding="utf-8")
    assert "token123" not in (tmp_path / "recon" / "example.test" / "cf_cookies.txt").read_text(
        encoding="utf-8"
    )
    assert private_dir.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in private_dir.iterdir())


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


def test_cf_solver_never_prints_turnstile_token(monkeypatch, capsys):
    class Solver:
        def turnstile(self, **_kwargs):
            return {"code": "SECRET_TURNSTILE_TOKEN"}

    class Page:
        def add_init_script(self, _script):
            pass

        def goto(self, *_args, **_kwargs):
            pass

        def evaluate(self, expression, *_args):
            if "__tsParams" in expression:
                return {"sitekey": "public-sitekey", "pageurl": "https://example.test"}
            return None

        def wait_for_function(self, *_args, **_kwargs):
            pass

        def title(self):
            return "Ready"

        def content(self):
            return ""

    class Closable:
        def close(self):
            pass

        def stop(self):
            pass

    class Context:
        def cookies(self):
            return []

    monkeypatch.setattr(
        cf_solver,
        "launch_browser",
        lambda _headful: (Closable(), Closable(), Context(), Page()),
    )
    assert cf_solver.solve_tier2(Solver(), "https://example.test", False) is None
    assert "SECRET_TURNSTILE_TOKEN" not in capsys.readouterr().out
