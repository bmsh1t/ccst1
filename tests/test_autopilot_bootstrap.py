"""Claude inline `/autopilot` 只读 bootstrap 行为回归。"""

from __future__ import annotations

import json
import shlex

from tools import autopilot_bootstrap


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
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_state", _state)
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
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_state", unexpected)

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
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_state", _state)

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
        "build_autopilot_state",
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
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_state", _state)

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
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_state", state)

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
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_state", _state)

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
