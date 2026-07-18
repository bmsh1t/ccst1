"""Recon Surface finalizer 的端到端派生缓存契约。"""

from tools import autopilot_state as autopilot_state_module
from tools.autopilot_state import build_autopilot_bootstrap_state
from tools.surface_finalizer import finalize_surface, main
from tools.surface_index import load_surface_index_status
from tools.surface_projection import load_surface_projection


def _write_recon(repo_root):
    recon = repo_root / "recon" / "target.com"
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )
    (recon / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/admin/orders?account_id=1\n",
        encoding="utf-8",
    )
    (recon / "urls" / "with_params.txt").write_text(
        "https://api.target.com/admin/orders?account_id=1\n",
        encoding="utf-8",
    )


def test_finalizer_publishes_index_projection_and_warm_bootstrap(tmp_path):
    _write_recon(tmp_path)

    result = finalize_surface(tmp_path, "target.com")

    assert result["status"] == "ok"
    assert result["projection_status"] == "valid"
    assert load_surface_index_status(tmp_path, "target.com")["status"] == "valid"
    assert load_surface_projection(tmp_path, "target.com")["status"] == "valid"
    state = build_autopilot_bootstrap_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )
    assert state["surface_projection"]["status"] == "valid"
    assert state["next_action"] == "hunt_p1"


def test_full_state_reuses_exact_projection_without_ranking_again(tmp_path, monkeypatch):
    _write_recon(tmp_path)
    finalize_surface(tmp_path, "target.com")

    def unexpected(*_args, **_kwargs):
        raise AssertionError("exact projection hit must not rebuild surface")

    monkeypatch.setattr(autopilot_state_module, "load_surface_context", unexpected)
    monkeypatch.setattr(autopilot_state_module, "rank_surface", unexpected)

    state = autopilot_state_module.build_autopilot_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )
    assert state["surface_projection"]["status"] == "valid"
    assert state["next_action"] == "hunt_p1"


def test_finalizer_cli_reports_missing_recon_without_creating_success(tmp_path, capsys):
    code = main(["--repo-root", str(tmp_path), "--target", "target.com", "--json"])

    assert code == 2
    assert '"status":"error"' in capsys.readouterr().out
