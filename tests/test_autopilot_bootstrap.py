"""Claude inline `/autopilot` 只读 bootstrap 行为回归。"""

from __future__ import annotations

import json
import shlex

from tools import autopilot_bootstrap
from tools import autopilot_state as autopilot_state_module
from tools.runtime_state import update_runtime_state
from tools.surface_projection import build_surface_input_manifest, write_surface_projection
from tools.technology_inventory import load_or_build_inventory


def test_compact_state_keeps_bounded_case_state_continuation():
    compact = autopilot_bootstrap.compact_autopilot_state({
        "next_action": "resume_case_state",
        "case_state": {
            "status": "valid",
            "pending_validation_backlog": 1,
            "top_next_action": {
                "next_action": "run_validation_runner",
                "backlog_id": "val_001",
                "redacted_command": "python3 tools/validation_runner.py idor-actor-pair --from-case-state",
            },
        },
    })

    assert compact["case_state"]["pending_validation_backlog"] == 1
    assert compact["case_state"]["top_next_action"]["backlog_id"] == "val_001"


def test_compact_state_exposes_surface_cursor_only_when_available():
    compact = autopilot_bootstrap.compact_autopilot_state({
        "surface_projection": {
            "status": "valid",
            "continuation": {
                "available": True,
                "next_cursor": "CURSOR",
                "command": "python3 tools/surface_index.py page --cursor CURSOR",
            },
        },
    })

    assert compact["surface_projection"]["continuation"] == {
        "available": True,
        "next_cursor": "CURSOR",
        "command": "python3 tools/surface_index.py page --cursor CURSOR",
    }


def test_compact_state_exposes_only_read_only_ranker_advisory():
    compact = autopilot_bootstrap.compact_autopilot_state({
        "next_action": "handoff",
        "enrichment_hints": [
            {
                "tool": "recon-ranker",
                "mode": "advisory",
                "executable": False,
                "reason": "valid Surface projection leaves a long tail",
            },
            {"tool": "run_js_read", "reason": "not part of startup projection"},
        ],
    })

    assert compact["enrichment_hints"] == [{
        "tool": "recon-ranker",
        "mode": "advisory",
        "reason": "valid Surface projection leaves a long tail",
    }]


def test_bootstrap_emits_ranker_advisory_for_valid_multi_source_long_tail(tmp_path):
    _write_fast_recon(tmp_path)
    ranked = {
        "available": True,
        "target": "target.com",
        "p1": [],
        "p2": [],
        "review_pool": [{
            "url": "https://api.target.com/orders",
            "score": 5,
            "tech_stack": ["nginx"],
        }],
        "browser": {"xhr_count": 1, "api_count": 0},
        "source_intel": {"hypothesis_count": 1},
        "stats": {
            "total_candidates": 8,
            "review_pool": 1,
            "semantic_shape_count": 3,
            "raw_urls": 8,
            "observation_untouched": 2,
        },
    }
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", ranked, manifest=manifest)

    state = autopilot_state_module.build_autopilot_bootstrap_state(
        str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory")
    )

    assert state["enrichment_hints"][0]["tool"] == "recon-ranker"
    assert state["enrichment_hints"][0]["mode"] == "advisory"
    assert state["next_tool_hint"] == ""


def test_compact_state_projects_only_the_next_lane_contract():
    expected = {
        "run_recon": "recon-surface",
        "collect_candidate_evidence": "recon-surface",
        "wait_recon": "state-and-queue",
        "wait_scan": "state-and-queue",
        "revalidate_finding_owner": "state-and-queue",
        "resume_action_queue": "state-and-queue",
        "report_finding": "state-and-queue",
        "recon_no_live_hosts": "state-and-queue",
        "resume_case_state": "workflow-case",
        "run_intel": "software-intel",
        "handoff": "controller",
    }
    for action, lane in expected.items():
        compact = autopilot_bootstrap.compact_autopilot_state({"next_action": action})
        assert compact["lane_contract"]["id"] == lane

    recon = autopilot_bootstrap.compact_autopilot_state({"next_action": "run_recon"})
    assert recon["lane_contract"]["ref"] == "docs/autopilot-lanes.md#recon-and-surface"

    browser = autopilot_bootstrap.compact_autopilot_state({
        "next_action": "handoff",
        "browser_required": True,
    })
    assert browser["lane_contract"]["id"] == "browser-source-js"


def test_compact_state_keeps_sql_matrix_and_js_lifecycle_projection():
    compact = autopilot_bootstrap.compact_autopilot_state({
        "sql_matrix": {
            "query": {
                "status": "candidate_pending",
                "path": "findings/example/poc/sql_matrix/query/summary.json",
                "input_fingerprint": "a" * 64,
                "request_count": 4,
                "candidates": [
                    {
                        "endpoint": "/search",
                        "field": "q",
                        "class": "sqli_error",
                        "signal": "database error",
                        "raw_body": "do-not-project",
                    }
                ],
            }
        },
        "js_intel": {
            "status": "prepared",
            "path": "findings/example/js_intel/materials.json",
            "hypotheses": ["do-not-project"],
        },
    })

    assert compact["sql_matrix"]["query"]["status"] == "candidate_pending"
    assert compact["sql_matrix"]["query"]["candidates"] == [{
        "endpoint": "/search",
        "field": "q",
        "class": "sqli_error",
        "signal": "database error",
    }]
    assert compact["js_intel"] == {
        "status": "prepared",
        "path": "findings/example/js_intel/materials.json",
    }
    assert "do-not-project" not in json.dumps(compact)


def test_state_read_error_is_structured_without_traceback(monkeypatch, tmp_path):
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", _capabilities)
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_autopilot_bootstrap_state",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad queue\nsecret body omitted")),
    )

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test"], repo_root=tmp_path, runtime_root=tmp_path / "runtime"
    )

    assert payload["action"] == "stop_state_error"
    assert payload["error"] == {"type": "ValueError", "reason": "bad queue secret body omitted"}
    assert "state" not in payload


def test_corrupt_runtime_state_stops_bootstrap_without_overwrite(monkeypatch, tmp_path):
    state_file = tmp_path / "state" / "example.test" / "session.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", _capabilities)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test"], repo_root=tmp_path, runtime_root=tmp_path / "runtime"
    )

    assert payload["action"] == "stop_state_error"
    assert payload["error"]["type"] == "ValueError"
    assert "invalid runtime state JSON" in payload["error"]["reason"]
    assert state_file.read_text(encoding="utf-8") == "{broken"


def test_runtime_read_error_is_structured_before_target_state(monkeypatch, tmp_path):
    monkeypatch.setattr(
        autopilot_bootstrap,
        "compare_runtime",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("runtime unreadable\nno traceback")),
    )
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_autopilot_bootstrap_state",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("target state read")),
    )

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test"], repo_root=tmp_path, runtime_root=tmp_path / "runtime"
    )

    assert payload["action"] == "stop_runtime_error"
    assert payload["error"] == {"type": "OSError", "reason": "runtime unreadable no traceback"}
    assert "state" not in payload


def _capabilities(_repo_root):
    return {
        "schema_version": 1,
        "checked": True,
        "status": "ready",
        "available": {
            "browser": [],
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
        "critical_clean": True,
        "drift_count": 0,
        "critical_drift_count": 0,
        "advisory_drift_count": 0,
        "critical_manifest": {
            "schema_version": 1,
            "status": "valid",
            "sha256": "sha256:fixture",
            "mcp_contracts": ["mcp__Playwright__*"],
        },
        "critical_drift": [],
        "missing_critical": [],
        "advisory_drift": [],
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


def test_scope_manifest_is_projected_and_invalid_manifest_stops_before_runtime(monkeypatch, tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps({
            "schema_version": 1,
            "in_scope": ["*.target.example"],
            "out_of_scope": ["admin.target.example"],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", _capabilities)
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_autopilot_bootstrap_state",
        lambda *_args, **_kwargs: {"target": str(scope.resolve()), "next_action": "run_recon"},
    )

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        [scope.name], cwd=tmp_path, repo_root=tmp_path, runtime_root=tmp_path / "runtime"
    )
    assert payload["action"] == "continue"
    assert payload["scope"]["scope_ref"] == str(scope.resolve())
    assert payload["scope"]["summary"]["out_of_scope_count"] == 1

    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version": 99, "in_scope": ["target.example"]}', encoding="utf-8")
    invalid_payload = autopilot_bootstrap.build_autopilot_bootstrap(
        [invalid.name], cwd=tmp_path, repo_root=tmp_path, runtime_root=tmp_path / "runtime"
    )
    assert invalid_payload["action"] == "stop_invalid_scope"
    assert invalid_payload["error"]["type"] == "ScopeContextError"


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
    assert payload["arguments"]["deep"] is True
    assert payload["arguments"]["max_lanes"] == 3
    assert payload["invocation_batch"] == {
        "bounded": True,
        "max_lanes": 3,
        "handoff": "checkpoint_and_handoff_after_max_lanes",
    }


def test_runtime_drift_stops_before_target_state(monkeypatch, tmp_path):
    (tmp_path / "config.json").write_text('{"ctf_mode": true}\n', encoding="utf-8")
    monkeypatch.setattr(
        autopilot_bootstrap,
        "compare_runtime",
        lambda repo_root, runtime_root=None, kinds=None: {
            "repo_root": str(repo_root),
            "runtime_root": str(runtime_root or tmp_path / "runtime"),
            "clean": False,
            "critical_clean": False,
            "drift_count": 2,
            "critical_drift_count": 2,
            "advisory_drift_count": 0,
            "critical_manifest": {
                "schema_version": 1,
                "status": "valid",
                "sha256": "sha256:fixture",
                "mcp_contracts": ["mcp__Playwright__*"],
            },
            "critical_drift": [
                {"kind": "commands", "relative_path": "autopilot.md", "status": "diff"}
            ],
            "missing_critical": [
                {"kind": "commands", "relative_path": "autopilot-round.md", "status": "missing"}
            ],
            "advisory_drift": [],
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
    assert payload["ctf_mode"] is True
    assert payload["runtime"] == {
        "checked": True,
        "clean": False,
        "critical_clean": False,
        "drift_count": 2,
        "critical_drift_count": 2,
        "advisory_drift_count": 0,
        "critical_manifest": {
            "schema_version": 1,
            "status": "valid",
            "sha256": "sha256:fixture",
            "mcp_contracts": ["mcp__Playwright__*"],
        },
        "critical_drift": [
            {"kind": "commands", "status": "diff", "relative_path": "autopilot.md"}
        ],
        "missing_critical": [
            {"kind": "commands", "status": "missing", "relative_path": "autopilot-round.md"}
        ],
        "advisory_drift": [],
        "runtime_root": str(tmp_path / "runtime"),
        "kinds": {
            "commands": {"ok": 3, "diff": 1, "missing": 1, "extra": 0}
        },
    }
    assert payload["capabilities"]["checked"] is False
    assert "state" not in payload


def test_advisory_runtime_drift_is_projected_without_blocking(monkeypatch, tmp_path):
    monkeypatch.setattr(
        autopilot_bootstrap,
        "compare_runtime",
        lambda repo_root, runtime_root=None, kinds=None: {
            "repo_root": str(repo_root),
            "runtime_root": str(runtime_root or tmp_path / "runtime"),
            "clean": False,
            "critical_clean": True,
            "drift_count": 1,
            "critical_drift_count": 0,
            "advisory_drift_count": 1,
            "critical_manifest": {
                "schema_version": 1,
                "status": "valid",
                "sha256": "sha256:fixture",
                "mcp_contracts": [],
            },
            "critical_drift": [],
            "missing_critical": [],
            "advisory_drift": [
                {"kind": "commands", "relative_path": "intel.md", "status": "diff"}
            ],
            "kinds": [],
        },
    )
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", _capabilities)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", _state)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test"],
        cwd=tmp_path,
        repo_root=tmp_path,
    )

    assert payload["action"] == "continue"
    assert payload["runtime"]["clean"] is False
    assert payload["runtime"]["critical_clean"] is True
    assert payload["runtime"]["advisory_drift"] == [
        {"kind": "commands", "status": "diff", "relative_path": "intel.md"}
    ]
    assert payload["state"]["next_action"] == "hunt_p1"


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


def test_compact_state_projects_bounded_ai_priority_contract():
    state = _state("/tmp/repo", "example.test")
    state.update({
        "fallback_action": "resume_action_queue",
        "selection_mode": "ai_priority",
        "hard_gate": {},
        "priority_frontier": [{
            "owner": "surface",
            "id": "https://example.test/api/orders",
            "lane": "recon-and-surface",
            "action": "review object ownership",
            "evidence_ref": "state/example.test/surface-projection.json",
            "expected_information_gain": "resolve an object authorization boundary",
            "impact_hint": "private order workflow",
            "stop_condition": "record an evidence-backed disposition",
            "evidence_status": "discovery",
            "closure_blocking": False,
            "continuity": False,
            "runnable": True,
            "raw": "do-not-project",
        }],
    })

    compact = autopilot_bootstrap.compact_autopilot_state(state)

    assert compact["fallback_action"] == "resume_action_queue"
    assert compact["selection_mode"] == "ai_priority"
    assert compact["hard_gate"] == {}
    assert compact["priority_frontier"][0]["owner"] == "surface"
    assert compact["priority_frontier"][0]["closure_blocking"] is False
    assert "raw" not in compact["priority_frontier"][0]


def test_compact_state_keeps_each_priority_frontier_owner_head():
    frontier = [
        {
            "owner": f"owner-{index}",
            "action": f"work-{index}",
            "evidence_ref": f"evidence/{index}.json",
            "expected_information_gain": f"resolve-{index}",
            "stop_condition": f"stop-{index}",
        }
        for index in range(12)
    ]

    compact = autopilot_bootstrap.compact_autopilot_state({
        "priority_frontier": frontier,
    })

    assert [item["owner"] for item in compact["priority_frontier"]] == [
        item["owner"] for item in frontier
    ]


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
    assert payload["capabilities"] == autopilot_bootstrap.unknown_capability_profile("profile-error")


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


def test_compact_bootstrap_preserves_bounded_workflow_leads():
    state = _state("/tmp/repo", "example.test")
    state["surface"] = {
        "workflow_leads": [
            json.dumps(
                {
                    "source": "recon_routing_candidate",
                    "category": "host-pivot",
                    "priority": "high",
                    "title": "Host pivot evidence is available",
                    "artifact": "recon/example.test/exposure/host_pivot_candidates.jsonl",
                    "next_action": "review with a default-vhost control",
                    "raw_rows": ["do-not-project"] * 100,
                }
            )
        ]
    }

    compact = autopilot_bootstrap.compact_autopilot_state(state)

    assert compact["workflow_leads"] == [
        {
            "source": "recon_routing_candidate",
            "category": "host-pivot",
            "priority": "high",
            "title": "Host pivot evidence is available",
            "artifact": "recon/example.test/exposure/host_pivot_candidates.jsonl",
            "next_action": "review with a default-vhost control",
        }
    ]
    assert "do-not-project" not in json.dumps(compact)


def test_bootstrap_projects_bounded_intel_continuation_details():
    state = _state("/tmp/repo", "example.test")
    state["next_action"] = "collect_web_intel"
    state["intel_continuation"] = {
        "action": "collect_web_intel",
        "reason": "official sources returned no advisory",
        "recommended": [
            {
                "subject": f"component-{index}@1.0",
                "intent": "component_advisory",
                "query": f"component-{index} 1.0 vulnerability advisory",
                "reasons": ["zero result", "degraded source", "recent component", "drop"],
                "raw_results": ["do-not-project"] * 20,
            }
            for index in range(8)
        ],
        "blocked": [{
            "subject": "blocked@1.0",
            "component": "blocked",
            "version": "1.0",
            "reason": "provider unavailable",
            "raw": "do-not-project",
        }],
        "advisory": {
            "id": "CVE-2026-63030",
            "aliases": ["CVE-2026-63030", "GHSA-AAAA-BBBB-CCCC"],
            "component": {
                "name": "givewp",
                "version": "4.16.3",
                "hosts": ["example.test"],
                "ports": [443],
                "cpes": ["do-not-project"],
            },
            "applicability": "affected",
            "severity": "CRITICAL",
            "score_hint": 100,
            "source_refs": [{
                "source": "web_intel",
                "url": "https://vendor.test/advisory",
                "body": "do-not-project",
            }],
            "summary": "do-not-project",
        },
    }

    compact = autopilot_bootstrap.compact_autopilot_state(state)

    continuation = compact["intel_continuation"]
    assert continuation["action"] == "collect_web_intel"
    assert len(continuation["recommended"]) == 3
    assert len(continuation["recommended"][0]["reasons"]) == 3
    assert continuation["blocked"][0]["subject"] == "blocked@1.0"
    assert continuation["advisory"]["id"] == "CVE-2026-63030"
    encoded = json.dumps(continuation)
    assert "do-not-project" not in encoded


def test_bootstrap_routes_bounded_intel_group_review():
    state = _state("/tmp/repo", "example.test")
    state["next_action"] = "review_intel_group"
    state["intel_continuation"] = {
        "action": "review_intel_group",
        "reason": "long-tail advisory facts remain",
        "review_group": {
            "group_key": "givewp@4.16.3",
            "component": {"name": "givewp", "version": "4.16.3"},
            "advisory_count": 20,
            "representative_count": 3,
            "omitted_count": 17,
            "reactivate_when": "new route evidence",
            "owner_binding": {"size": 100, "mtime_ns": 2},
            "query_command": "python3 tools/intel_artifact.py query --target example.test --component givewp --limit 8",
            "queue_metadata": {
                "intel_group_key": "givewp@4.16.3",
                "intel_owner_binding": {"size": 100, "mtime_ns": 2},
            },
            "raw": ["do-not-project"] * 20,
        },
        "review_projection": {
            "available": True,
            "path": "/tmp/repo/recon/example.test/intel-review.json",
            "group_count": 1,
            "advisory_count": 20,
            "omitted_group_count": 0,
            "owner_binding": {"size": 100, "mtime_ns": 2},
            "raw": "do-not-project",
        },
    }

    compact = autopilot_bootstrap.compact_autopilot_state(state)

    assert compact["lane_contract"]["id"] == "software-intel"
    assert compact["intel_continuation"]["review_group"]["omitted_count"] == 17
    assert compact["intel_continuation"]["review_group"]["queue_metadata"]["intel_group_key"] == "givewp@4.16.3"
    assert "do-not-project" not in json.dumps(compact["intel_continuation"])


def test_bootstrap_projects_bounded_cidr_continuation():
    state = _state("/tmp/repo", "10.0.0.0/19")
    state["recon_artifacts"]["cidr_continuation"] = {
        "status": "pending",
        "path": "/tmp/repo/recon/10.0.0.0_19/live/cidr_continuation.json",
        "next_offset": 4096,
        "remaining_hosts": 4094,
        "raw": "do-not-project",
    }

    compact = autopilot_bootstrap.compact_autopilot_state(state)

    assert compact["recon"]["cidr_continuation"] == {
        "status": "pending",
        "next_offset": 4096,
        "remaining_hosts": 4094,
    }
    assert "do-not-project" not in json.dumps(compact)


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


def test_bounded_full_state_entry_never_falls_back_to_surface_ranking(tmp_path, monkeypatch):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("bounded state must not load or rank the full surface")

    monkeypatch.setattr(autopilot_state_module, "load_surface_context", unexpected)
    monkeypatch.setattr(autopilot_state_module, "rank_surface", unexpected)

    state = autopilot_state_module.build_autopilot_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
        bounded=True,
    )

    assert state["target"] == "target.com"
    assert state["surface_projection"]["status"] == "missing"


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


def test_compact_state_keeps_intel_advisory_without_preempting_surface(tmp_path):
    _write_fast_recon(tmp_path)
    load_or_build_inventory(tmp_path, "target.com")
    ranked = {
        "available": True,
        "target": "target.com",
        "p1": [{
            "url": "https://api.target.com/orders?id=1",
            "host": "api.target.com",
            "score": 10,
            "suggested": "review object access",
        }],
        "p2": [],
        "review_pool": [],
        "stats": {"total_candidates": 1, "p1": 1, "p2": 0, "review_pool": 0},
    }
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", ranked, manifest=manifest)

    state = autopilot_state_module.build_autopilot_bootstrap_state(
        str(tmp_path),
        "target.com",
        memory_dir=str(tmp_path / "hunt-memory"),
    )

    assert state["primary_next_action"] == "hunt_p1"
    assert state["next_action"] == "hunt_p1"
    assert state["selection_mode"] == "ai_priority"
    assert {item["owner"] for item in state["priority_frontier"]} >= {"intel", "surface"}
    assert state["next_tool_hint"] == ""
    assert "Intel v2 has not processed" in state["intel_continuation"]["reason"]


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
