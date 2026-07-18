"""Claude inline `/autopilot` 只读 bootstrap 行为回归。"""

from __future__ import annotations

import json
import shlex

from tools import autopilot_bootstrap
from tools import autopilot_state as autopilot_state_module
from tools.runtime_state import update_runtime_state
from tools.surface_projection import build_surface_input_manifest, write_surface_projection


def _capabilities(_repo_root):
    return {
        "schema_version": 1,
        "checked": True,
        "status": "ready",
        "available": {
            "browser": ["playwright-cli"],
            "recon": ["httpx"],
            "scanner": ["nuclei"],
        },
        "session_managed": ["chrome-devtools-mcp", "playwright-mcp"],
        "fallbacks": ["curl-native-http"],
        "missing_core": [],
        "missing_optional": [],
        "recommended_paths": ["recon-engine-httpx"],
    }


def _clean_runtime(repo_root, runtime_root=None, kinds=None):
    return {
        "repo_root": str(repo_root),
        "runtime_root": str(runtime_root or "/tmp/staged-claude"),
        "clean": True,
        "drift_count": 0,
        "kinds": [
            {
                "kind": kind,
                "counts": {"ok": 1, "diff": 0, "missing": 0, "extra": 0},
                "items": [{"relative_path": "large-runtime-detail"}],
            }
            for kind in (kinds or [])
        ],
    }


def _state(_repo_root, target):
    return {
        "target": target,
        "target_kind": "domain",
        "has_recon": True,
        "next_action": "hunt_p1",
        "recon_in_progress": False,
        "scan_in_progress": False,
        "recon_artifacts": {
            "available": True,
            "ready": True,
            "host_inventory_ready": True,
            "large_detail": ["do-not-project"] * 100,
        },
        "structured_findings": {},
        "validation_runner_candidates": [],
        "surface": {"large_raw_surface": ["do-not-project"] * 100},
        "surface_review_candidates": [
            {
                "url": f"https://{target}/api/orders",
                "score": 12,
                "suggested": "review object ownership",
                "large_raw_payload": ["do-not-project"] * 100,
            }
        ],
    }


def test_root_and_nested_cwd_produce_the_same_repo_runtime_and_state(monkeypatch, tmp_path):
    nested = tmp_path / "tools" / "fixtures"
    nested.mkdir(parents=True)
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", _capabilities)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", _state)
    monkeypatch.setattr(autopilot_bootstrap, "is_ctf_mode_enabled", lambda _root: True)

    root_payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test", "--normal"],
        cwd=tmp_path,
        repo_root=tmp_path,
        runtime_root=tmp_path / "runtime",
    )
    nested_payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test", "--normal"],
        cwd=nested,
        repo_root=tmp_path,
        runtime_root=tmp_path / "runtime",
    )

    assert root_payload == nested_payload
    assert root_payload["action"] == "continue"
    assert root_payload["repo_root"] == str(tmp_path.resolve())
    assert shlex.split(root_payload["repo_root_shell"]) == [str(tmp_path.resolve())]
    assert root_payload["runtime"]["clean"] is True
    assert root_payload["capabilities"] == _capabilities(tmp_path)
    assert root_payload["ctf_mode"] is True
    assert root_payload["state"]["next_action"] == "hunt_p1"


def test_invalid_arguments_stop_before_runtime_or_target_state(monkeypatch, tmp_path):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("invalid arguments must not read runtime or target state")

    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", unexpected)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", unexpected)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", unexpected)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test", "--unknown"],
        cwd=tmp_path,
        repo_root=tmp_path,
    )

    assert payload["action"] == "stop_invalid_arguments"
    assert payload["runtime"]["checked"] is False
    assert payload["capabilities"]["checked"] is False
    assert payload["capabilities"]["reason"] == "not-checked"
    assert "state" not in payload


def test_bootstrap_projects_bounded_deep_invocation_batch(monkeypatch, tmp_path):
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", _capabilities)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", _state)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test", "--deep", "--normal", "--max-lanes", "3"],
        cwd=tmp_path,
        repo_root=tmp_path,
        runtime_root=tmp_path / "runtime",
    )

    assert payload["action"] == "continue"
    assert payload["arguments"]["max_lanes"] == 3
    assert payload["invocation_batch"] == {
        "bounded": True,
        "max_lanes": 3,
        "handoff": "checkpoint_and_handoff_after_max_lanes",
    }


def test_runtime_drift_stops_before_target_state(monkeypatch, tmp_path):
    monkeypatch.setattr(
        autopilot_bootstrap,
        "compare_runtime",
        lambda repo_root, runtime_root=None, kinds=None: {
            "repo_root": str(repo_root),
            "runtime_root": str(runtime_root or tmp_path / "runtime"),
            "clean": False,
            "drift_count": 2,
            "kinds": [
                {
                    "kind": "commands",
                    "counts": {"ok": 3, "diff": 1, "missing": 1, "extra": 0},
                    "items": [{"relative_path": "autopilot.md", "status": "diff"}],
                }
            ],
        },
    )
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_capability_profile",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("runtime drift must not read capabilities")
        ),
    )
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_autopilot_bootstrap_state",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("runtime drift must not read target state")
        ),
    )

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test"],
        cwd=tmp_path,
        repo_root=tmp_path,
    )

    assert payload["action"] == "stop_runtime_drift"
    assert payload["runtime"] == {
        "checked": True,
        "clean": False,
        "drift_count": 2,
        "runtime_root": str(tmp_path / "runtime"),
        "kinds": {
            "commands": {"ok": 3, "diff": 1, "missing": 1, "extra": 0}
        },
    }
    assert payload["capabilities"]["checked"] is False
    assert "state" not in payload


def test_bootstrap_state_is_compact_and_json_cli_is_single_line(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(autopilot_bootstrap, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", _capabilities)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", _state)

    assert autopilot_bootstrap.main(["--json", "--", "example.test"]) == 0
    output = capsys.readouterr().out.strip()
    payload = json.loads(output)

    assert "\n" not in output
    assert payload["state"]["surface_candidates"] == [
        {
            "url": "https://example.test/api/orders",
            "score": 12,
            "suggested": "review object ownership",
        }
    ]
    assert "surface" not in payload["state"]
    assert "items" not in payload["runtime"]
    assert "do-not-project" not in output


def test_capability_profile_runs_after_runtime_and_before_target_state(monkeypatch, tmp_path):
    calls = []

    def runtime(*args, **kwargs):
        calls.append("runtime")
        return _clean_runtime(*args, **kwargs)

    def capabilities(repo_root):
        calls.append("capabilities")
        return _capabilities(repo_root)

    def state(repo_root, target):
        calls.append("state")
        return _state(repo_root, target)

    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", capabilities)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", state)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test"],
        cwd=tmp_path,
        repo_root=tmp_path,
    )

    assert calls == ["runtime", "capabilities", "state"]
    assert payload["action"] == "continue"


def test_capability_profile_failure_is_advisory(monkeypatch, tmp_path):
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_capability_profile",
        lambda _repo_root: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", _state)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test"],
        cwd=tmp_path,
        repo_root=tmp_path,
    )

    assert payload["action"] == "continue"
    assert payload["state"]["next_action"] == "hunt_p1"
    assert payload["capabilities"] == {
        "schema_version": 1,
        "checked": False,
        "status": "unknown",
        "available": {"browser": [], "recon": [], "scanner": []},
        "session_managed": [],
        "fallbacks": [],
        "missing_core": [],
        "missing_optional": [],
        "recommended_paths": [],
        "reason": "profile-error",
    }


def test_bootstrap_projects_only_bounded_candidate_rubric():
    state = _state("/tmp/repo", "example.test")
    state["next_action"] = "collect_candidate_evidence"
    state["structured_findings"] = {
        "next_validation": {
            "id": "idor-orders",
            "url": "https://example.test/api/orders/7",
            "raw_request": "do-not-project",
            "rubric": {
                "rubric_id": "authz",
                "status": "needs-evidence",
                "ready": False,
                "score": 50,
                "satisfied_count": 2,
                "total": 5,
                "missing_labels": ["actor A", "actor B", "response diff", "impact"],
                "next_actions": [
                    "",
                    "compare the same object with two owned actors",
                    "capture the stable response difference",
                ],
                "missing": [{"id": "large-detail"}] * 100,
                "summary": "do-not-project",
                "raw_evidence": ["do-not-project"] * 100,
            },
        }
    }

    compact = autopilot_bootstrap.compact_autopilot_state(state)

    assert compact["structured_next"] == {
        "id": "idor-orders",
        "url": "https://example.test/api/orders/7",
        "rubric": {
            "rubric_id": "authz",
            "status": "needs-evidence",
            "ready": False,
            "score": 50,
            "satisfied_count": 2,
            "total": 5,
            "missing_labels": ["actor A", "actor B", "response diff"],
            "next_actions": ["compare the same object with two owned actors"],
        },
    }
    encoded = json.dumps(compact)
    assert "raw_request" not in encoded
    assert "raw_evidence" not in encoded
    assert "do-not-project" not in encoded


def test_bootstrap_projects_recovery_and_draft_completion_handoffs():
    state = _state("/tmp/repo", "example.test")
    state["next_action"] = "prepare_surface_context"
    state["fresh_recon_ready"] = True
    state["structured_findings"] = {
        "next_draft_completion": {
            "id": "sqli-report-draft",
            "url": "https://example.test/rest/products/search?q=test",
            "report_draft_path": "findings/example.test-sqli/hackerone-report.md",
            "report_draft_status": "incomplete",
            "report_draft_placeholder_count": 3,
        }
    }
    state["memory_candidate_next"] = {
        "id": "M1",
        "action": "Run /validate after reviewing the raw pair.",
        "command_hint": "/validate",
        "evidence_ref": "evidence/example.test/raw/pair.json",
        "evidence_available": True,
    }
    state["root_finding_claim_next"] = {
        "id": "claim_1a2b3c",
        "title": "Unverified SQLi claim",
        "type": "sqli",
        "url": "/rest/products/search",
        "claim_source_file": "manual-sqli.json",
        "source_file": "/tmp/repo/findings/example.test/manual-sqli.json",
        "validation_status": "candidate",
        "report_status": "not_generated",
        "poc": "do-not-project",
        "evidence_rubric": {
            "rubric_id": "sqli",
            "status": "needs-evidence",
            "ready": False,
            "score": 0,
            "satisfied_count": 0,
            "total": 4,
            "missing_labels": ["baseline", "stable diff", "impact", "repeat"],
            "next_actions": ["capture a baseline and controlled perturbation"],
            "raw_evidence": ["do-not-project"],
        },
    }

    compact = autopilot_bootstrap.compact_autopilot_state(state)

    assert compact["next_action"] == "prepare_surface_context"
    assert compact["recon"]["fresh_recon_ready"] is True
    assert compact["structured_next_kind"] == "draft_completion"
    assert compact["structured_next"]["report_draft_status"] == "incomplete"
    assert compact["memory_candidate_next"] == {
        "id": "M1",
        "action": "Run /validate after reviewing the raw pair.",
        "command_hint": "/validate",
        "evidence_ref": "evidence/example.test/raw/pair.json",
        "evidence_available": True,
    }
    assert compact["root_claim_next"] == {
        "id": "claim_1a2b3c",
        "title": "Unverified SQLi claim",
        "type": "sqli",
        "url": "/rest/products/search",
        "claim_source_file": "manual-sqli.json",
        "source_file": "/tmp/repo/findings/example.test/manual-sqli.json",
        "validation_status": "candidate",
        "report_status": "not_generated",
        "rubric": {
            "rubric_id": "sqli",
            "status": "needs-evidence",
            "ready": False,
            "score": 0,
            "satisfied_count": 0,
            "total": 4,
            "missing_labels": ["baseline", "stable diff", "impact"],
            "next_actions": ["capture a baseline and controlled perturbation"],
        },
    }
    encoded = json.dumps(compact)
    assert "do-not-project" not in encoded


def _write_fast_recon(repo_root, target: str = "target.com"):
    recon_dir = repo_root / "recon" / target
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://api.target.com/orders?id=1\n",
        encoding="utf-8",
    )
    return recon_dir


def test_compact_state_never_calls_full_surface_or_full_recon_inspection(monkeypatch, tmp_path):
    _write_fast_recon(tmp_path)
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "candidate-1",
                        "type": "idor",
                        "url": "https://api.target.com/orders/1",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                        "rubric": {"ready": False, "status": "needs-evidence"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("compact bootstrap must not enter the full surface path")

    monkeypatch.setattr(autopilot_state_module, "load_surface_context", unexpected)
    monkeypatch.setattr(autopilot_state_module, "rank_surface", unexpected)
    monkeypatch.setattr(autopilot_state_module, "inspect_recon_artifacts", unexpected)

    state = autopilot_state_module.build_autopilot_bootstrap_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )

    assert state["has_recon"] is True
    assert state["next_action"] == "collect_candidate_evidence"
    assert state["surface_projection"]["status"] == "missing"


def test_compact_state_requires_projection_then_consumes_exact_hit(tmp_path):
    _write_fast_recon(tmp_path)

    missing = autopilot_state_module.build_autopilot_bootstrap_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )
    assert missing["next_action"] == "prepare_surface_context"
    assert missing["surface_review_candidates"] == []

    ranked = {
        "available": True,
        "target": "target.com",
        "p1": [
            {
                "url": "https://api.target.com/orders?id=1",
                "host": "api.target.com",
                "score": 10,
                "suggested": "compare owned object access",
                "reasons": ["ID-bearing parameter"],
            }
        ],
        "p2": [],
        "review_pool": [
            {
                "url": "https://api.target.com/orders?id=1",
                "host": "api.target.com",
                "score": 10,
                "suggested": "compare owned object access",
                "review_reason": "top advisory score",
            }
        ],
        "stats": {"total_candidates": 1, "p1": 1, "p2": 0, "review_pool": 1},
    }
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", ranked, manifest=manifest)

    hit = autopilot_state_module.build_autopilot_bootstrap_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )
    assert hit["surface_projection"]["status"] == "valid"
    assert hit["next_action"] == "hunt_p1"
    assert hit["surface_review_candidates"][0]["url"].endswith("orders?id=1")


def test_exact_empty_projection_completes_fresh_recon_surface_handoff(tmp_path):
    _write_fast_recon(tmp_path)
    update_runtime_state(
        tmp_path,
        "target.com",
        mode="recon_only",
        last_executed_workflow="run_recon",
    )
    ranked = {
        "available": True,
        "target": "target.com",
        "p1": [],
        "p2": [],
        "review_pool": [],
        "stats": {"total_candidates": 1, "p1": 0, "p2": 0, "review_pool": 0},
    }
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", ranked, manifest=manifest)

    state = autopilot_state_module.build_autopilot_bootstrap_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )

    assert state["fresh_recon_ready"] is True
    assert state["surface_projection"]["status"] == "valid"
    assert state["next_action"] == "handoff"


def test_priority_bootstrap_does_not_open_large_artifacts_or_write_target_state(tmp_path, monkeypatch):
    recon_dir = _write_fast_recon(tmp_path)
    with_params = recon_dir / "urls" / "with_params.txt"
    with with_params.open("ab") as handle:
        handle.truncate(32 * 1024 * 1024)
    inventory = tmp_path / "state" / "target.com" / "observations.json"
    inventory.parent.mkdir(parents=True)
    with inventory.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024)

    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "candidate-large",
                        "type": "idor",
                        "url": "https://api.target.com/orders/1",
                        "validation_status": "candidate",
                        "report_status": "not_generated",
                        "rubric": {"ready": False, "status": "needs-evidence"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    before = {
        path.relative_to(tmp_path).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    original_open = type(with_params).open

    def guarded_open(self, mode="r", *args, **kwargs):
        if self in {with_params, inventory} and "r" in mode:
            raise AssertionError(f"bootstrap opened large artifact: {self}")
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(type(with_params), "open", guarded_open)

    state = autopilot_state_module.build_autopilot_bootstrap_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )
    after = {
        path.relative_to(tmp_path).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    assert state["next_action"] == "collect_candidate_evidence"
    assert state["observation_inventory"]["status"] == "summary_missing"
    assert before == after
