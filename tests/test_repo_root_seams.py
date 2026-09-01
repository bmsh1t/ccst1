"""Contract and isolation checks for repository-root seams."""

from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
CLASSIFICATIONS = {
    "browser_evidence": "narrow-root-injected",
    "browser_playwright_fallback": "narrow-root-injected",
    "cf_solver": "repo-root-dependent",
    "hypothesis_worker": "import-only",
    "remember": "repo-root-dependent",
    "request_guard": "narrow-root-injected",
    "resume": "repo-root-dependent",
    "scanner_pass_writer": "narrow-root-injected",
    "sibling_worker": "repo-root-dependent",
    "source_hunt": "repo-root-dependent",
    "vision_browser": "narrow-root-injected",
    "zero_day_fuzzer": "repo-root-dependent",
}

ROOT_SYMBOLS = {
    "cf_solver": ("load_config", "check_cookie", "write_output"),
    "remember": (
        "resolve_validate_summary_path",
        "_is_repo_global_last_validate",
        "load_validate_prefill",
    ),
    "resume": ("load_resume_summary", "load_pickup_summary"),
    "sibling_worker": ("run_worker",),
    "source_hunt": ("_exposure_dir", "_write_result_bundle", "run_source_hunt"),
    "zero_day_fuzzer": ("ZeroDayFuzzer",),
}

NARROW_SYMBOLS = {
    "browser_evidence": {"load_last_browser_evidence": {"evidence_root"}},
    "browser_playwright_fallback": {
        "capture_with_playwright": {"evidence_root", "recon_root"},
    },
    "request_guard": {
        "preflight_request": {"memory_dir"},
        "record_request": {"memory_dir"},
        "load_guard_status": {"memory_dir"},
    },
    "scanner_pass_writer": {
        "write_scanner_pass": {"findings_dir", "recon_dir", "out_path"},
    },
    "vision_browser": {
        "find_latest_screenshot": {"evidence_root"},
        "list_screenshots": {"evidence_root"},
    },
}

CLI_MODULES = (
    "cf_solver",
    "remember",
    "resume",
    "sibling_worker",
    "source_hunt",
    "zero_day_fuzzer",
)


def _module(name: str):
    # conftest adds tools/ to sys.path because several legacy modules use
    # top-level imports when run as direct scripts.
    return importlib.import_module(name)


def test_all_candidates_are_documented_with_one_classification():
    document = (REPO_ROOT / "docs/repo-root-seams.md").read_text(
        encoding="utf-8"
    )
    for module, classification in CLASSIFICATIONS.items():
        assert f"| `{module}` | `{classification}` |" in document


def test_root_boundaries_have_explicit_parameters_and_import_only_stays_clean():
    for module_name, symbols in ROOT_SYMBOLS.items():
        module = _module(module_name)
        for symbol in symbols:
            assert "repo_root" in inspect.signature(getattr(module, symbol)).parameters, (
                f"{module_name}.{symbol} must accept repo_root"
            )

    for module_name, symbols in NARROW_SYMBOLS.items():
        module = _module(module_name)
        for symbol, expected in symbols.items():
            parameters = inspect.signature(getattr(module, symbol)).parameters
            assert expected.issubset(parameters), f"{module_name}.{symbol} lost its narrow root"
            assert "repo_root" not in parameters, f"{module_name}.{symbol} gained a cosmetic repo_root"

    assert "repo_root" not in inspect.signature(_module("hypothesis_worker").run_worker).parameters


@pytest.mark.parametrize("module_name", CLI_MODULES)
def test_repository_dependent_clis_expose_repo_root(module_name, monkeypatch, capsys):
    module = _module(module_name)
    main = module.main
    if "argv" in inspect.signature(main).parameters:
        with pytest.raises(SystemExit) as raised:
            main(["--help"])
    else:
        monkeypatch.setattr(sys, "argv", [module_name, "--help"])
        with pytest.raises(SystemExit) as raised:
            main()
    assert raised.value.code == 0
    assert "--repo-root" in capsys.readouterr().out


def test_cf_solver_explicit_root_contains_config_and_private_outputs(tmp_path, monkeypatch):
    import cf_solver

    legacy = tmp_path / "legacy"
    root = tmp_path / "isolated"
    monkeypatch.setattr(cf_solver, "BASE_DIR", legacy)
    root.mkdir(parents=True)
    (root / "config.json").write_text(
        '{"cf_solver":{"balance_check":false}}\n', encoding="utf-8"
    )

    assert cf_solver.load_config(root)["balance_check"] is False
    cf_solver.write_output(
        [{"name": "cf_clearance", "value": "TOKEN"}],
        "https://target.test/",
        export_env=False,
        repo_root=root,
    )

    assert (root / ".private/cf/target.test/cf_cookies.txt").is_file()
    assert (root / "recon/target.test/cf_cookies.txt").is_file()
    assert not legacy.exists()


def test_remember_cli_uses_explicit_root_for_default_memory(tmp_path, monkeypatch):
    import remember

    legacy = tmp_path / "legacy"
    root = tmp_path / "isolated"
    monkeypatch.setattr(remember, "BASE_DIR", str(legacy))
    monkeypatch.delenv("HUNT_MEMORY_DIR", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "remember.py",
            "--repo-root",
            str(root),
            "--target",
            "target.test",
            "--vuln-class",
            "IDOR",
            "--endpoint",
            "/orders/1",
            "--result",
            "partial",
        ],
    )

    remember.main()

    assert (root / "hunt-memory/targets/target-test.json").is_file()
    assert not legacy.exists()


def test_resume_explicit_root_reads_runtime_artifacts(tmp_path, monkeypatch):
    import resume
    from memory.target_profile import make_target_profile, save_target_profile
    from runtime_state import update_runtime_state

    legacy = tmp_path / "legacy"
    root = tmp_path / "isolated"
    memory_dir = root / "hunt-memory"
    memory_dir.mkdir(parents=True)
    save_target_profile(memory_dir, make_target_profile("target.test"))
    update_runtime_state(root, "target.test", last_executed_workflow="run_scan")
    monkeypatch.setattr(resume, "BASE_DIR", str(legacy))

    summary = resume.load_resume_summary(memory_dir, "target.test", repo_root=root)

    assert summary is not None
    assert summary["runtime_state"]["last_executed_workflow"] == "run_scan"
    assert not legacy.exists()


def test_sibling_worker_explicit_root_reads_recon_pool(tmp_path, monkeypatch):
    import sibling_worker

    legacy = tmp_path / "legacy"
    root = tmp_path / "isolated"
    target = "target.test"
    recon = root / "recon" / target / "urls"
    recon.mkdir(parents=True)
    (recon / "all.txt").write_text(
        "/api/users/1\n/api/orders/1\n/api/invoices/1\n", encoding="utf-8"
    )
    scratch = root / "evidence/worker"
    scratch.mkdir(parents=True)
    seed_path = scratch / "seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "worker_id": "w1",
                "target": target,
                "seed_finding": {"id": "f1", "endpoint": "/api/users/1", "vuln_class": "IDOR"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sibling_worker, "BASE_DIR", legacy)
    limiter = sibling_worker._select_global_limiter(scratch, root)
    assert limiter is not None
    assert (root / "hunt-memory/audit/parallel_lock.json").is_file()
    monkeypatch.setattr(sibling_worker, "_select_global_limiter", lambda *_args: None)
    monkeypatch.setattr(
        sibling_worker,
        "_http_probe",
        lambda _url: {"status": 200, "snippet": '{"id":1}', "content_type": "application/json"},
    )

    summary = sibling_worker.run_worker(seed_path, scratch, target, 2, repo_root=root)

    assert summary["probes_attempted"] == 2
    assert json.loads((scratch / "findings.json").read_text(encoding="utf-8"))
    assert not legacy.exists()


def test_source_hunt_explicit_root_contains_exposure_bundle(tmp_path, monkeypatch):
    import source_hunt
    from repo_scan_models import RepoFinding, RepoSourceMeta

    legacy = tmp_path / "legacy"
    root = tmp_path / "isolated"
    source_meta = RepoSourceMeta(source_kind="local_path", repo_path="/tmp/SAMPLE", probe_complete=True)
    monkeypatch.setattr(source_hunt, "BASE_DIR", legacy)
    monkeypatch.setattr(
        source_hunt,
        "acquire_repo_source",
        lambda **_kwargs: (source_meta, "/tmp/SAMPLE", None),
    )
    monkeypatch.setattr(
        source_hunt,
        "scan_repo_secrets",
        lambda _path: [
            RepoFinding(
                rule_id="test",
                category="secret",
                severity="low",
                confidence="medium",
                source="fixture",
                file_path="config.js",
                line_number=1,
                match_type="pattern",
                title="fixture",
            )
        ],
    )
    monkeypatch.setattr(source_hunt, "scan_repo_ci", lambda _path: [])

    result = source_hunt.run_source_hunt(target="target.test", repo_root=root)

    assert Path(result["exposure_dir"]).is_relative_to(root)
    assert (root / "findings/target.test/exposure/repo_summary.md").is_file()
    assert not legacy.exists()


def test_zero_day_fuzzer_explicit_root_contains_findings_dir(tmp_path, monkeypatch):
    from tools import zero_day_fuzzer
    from tools.scope_context import ScopeContext

    legacy = tmp_path / "legacy"
    root = tmp_path / "isolated"
    monkeypatch.setattr(zero_day_fuzzer, "BASE_DIR", str(legacy))
    fuzzer = zero_day_fuzzer.ZeroDayFuzzer(
        "https://target.test",
        repo_root=root,
        scope_target="target.test",
        scope_context=ScopeContext.from_target("target.test"),
        max_requests=1,
    )

    assert Path(fuzzer.findings_dir).is_relative_to(root)
    assert not legacy.exists()
