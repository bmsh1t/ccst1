"""Claude inline `/autopilot` 只读 bootstrap 行为回归。"""

from __future__ import annotations

import json
import shlex

from tools import autopilot_bootstrap


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
    assert root_payload["ctf_mode"] is True
    assert root_payload["state"]["next_action"] == "hunt_p1"


def test_invalid_arguments_stop_before_runtime_or_target_state(monkeypatch, tmp_path):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("invalid arguments must not read runtime or target state")

    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", unexpected)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_state", unexpected)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["example.test", "--unknown"],
        cwd=tmp_path,
        repo_root=tmp_path,
    )

    assert payload["action"] == "stop_invalid_arguments"
    assert payload["runtime"]["checked"] is False
    assert "state" not in payload


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
    assert "state" not in payload


def test_bootstrap_state_is_compact_and_json_cli_is_single_line(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(autopilot_bootstrap, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
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
