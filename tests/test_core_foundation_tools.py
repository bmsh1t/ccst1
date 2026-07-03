"""Behavior tests for core autopilot foundation tools.

These tests cover the small deterministic helpers that sit underneath the
/autopilot loop. They avoid network access and assert behavior at public helper
or CLI-function boundaries instead of implementation details.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools import action_queue, high_value_signals, noise_filter, parallel_workers, runtime_config, target_memory, target_paths, target_selector


def test_target_paths_canonicalizes_host_port_cidr_and_lists(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("api.example.test\nshop.example.test\n", encoding="utf-8")

    assert target_paths.classify_target("127.0.0.1:3000") == {
        "kind": "ip",
        "target": "127.0.0.1:3000",
    }
    assert target_paths.classify_target("192.168.1.1/24") == {
        "kind": "cidr",
        "target": "192.168.1.0/24",
    }
    assert target_paths.canonical_target_value(str(scope)) == str(scope.resolve())
    assert target_paths.target_storage_key(str(scope)) == "scope"
    assert target_paths.target_storage_key("192.168.1.0/24") == "192.168.1.0_24"
    assert target_paths.target_storage_key("app.example.test:8443") == "app.example.test:8443"


def test_target_memory_set_append_and_handoff_use_canonical_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(target_memory, "BASE_DIR", tmp_path)
    monkeypatch.setattr(target_memory, "GOALS_DIR", tmp_path / "memory" / "goals")
    monkeypatch.setattr(target_memory, "ACTIVE_PATH", tmp_path / "memory" / "goals" / "active.json")
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "memory" / "goals" / "targets")
    monkeypatch.setattr(target_memory, "SESSIONS_DIR", tmp_path / "memory" / "goals" / "sessions")

    summary = target_memory.set_active(
        argparse.Namespace(
            target="Example.COM",
            mode="hunt",
            phase="recon",
            goal="map auth boundaries",
            hypothesis="IDOR on orders",
            skill=["web2-vuln-classes"],
            knowledge=["api-idor"],
        )
    )
    assert "TARGET SET" in summary
    assert "Example.COM" in summary

    saved = target_memory.load_target_memory("Example.COM")
    assert saved["active_goal"] == "map auth boundaries"
    assert saved["selected_skills"] == ["web2-vuln-classes"]

    msg = target_memory.append_entry(
        argparse.Namespace(target=None, text=["Try", "two-account", "read-only", "diff"]),
        "next_actions",
        "NEXT",
    )
    assert "NEXT saved" in msg
    saved = target_memory.load_target_memory("Example.COM")
    assert saved["next_actions"][-1]["text"] == "Try two-account read-only diff"

    handoff = target_memory.write_handoff(
        argparse.Namespace(target="Example.COM", summary=["Recon", "complete"]),
    )
    assert "Handoff written" in handoff
    saved = target_memory.load_target_memory("Example.COM")
    handoff_path = tmp_path / saved["session_handoffs"][-1]["path"]
    assert handoff_path.is_file()
    assert "Try two-account read-only diff" in handoff_path.read_text(encoding="utf-8")


def test_target_selector_scores_and_extracts_scope_without_network(capsys):
    programs = [
        {
            "name": "Wide Scope",
            "handle": "wide",
            "url": "https://hackerone.com/wide",
            "managed": True,
            "bounty_max": 12000,
            "response_efficiency": 95,
            "has_wildcard": True,
            "assets": [
                {"asset_identifier": "*.wide.example", "asset_type": "WILDCARD"},
                {"asset_identifier": "https://api.wide.example/v1", "asset_type": "URL"},
            ],
            "started_accepting_at": "",
        },
        {
            "name": "Narrow Scope",
            "handle": "narrow",
            "url": "https://hackerone.com/narrow",
            "managed": False,
            "bounty_max": 0,
            "response_efficiency": 0,
            "has_wildcard": False,
            "assets": [],
            "started_accepting_at": "",
        },
    ]

    selected = target_selector.select_targets(programs, top_n=1)
    assert selected[0]["name"] == "Wide Scope"
    assert selected[0]["score"] > programs[1]["score"]
    assert selected[0]["scope_domains"] == ["wide.example", "api.wide.example"]
    assert "Wide Scope" in capsys.readouterr().out


def test_high_value_signal_combines_action_path_query_and_evidence():
    signal = high_value_signals.classify_high_value_signal(
        path="/api/v2/admin/orders/42/export",
        query_keys=["user_id", "redirect_uri"],
        item_type="candidate-evidence-gap",
        evidence="GraphQL resolver hints at IDOR and secret export",
    )

    assert signal.score >= 20
    assert "candidate-evidence-gap" in signal.classes
    assert "api" in signal.classes
    assert "id-ref" in signal.classes
    assert "server-side" in signal.classes
    summary = high_value_signals.summarize_high_value_signal(signal)
    assert summary.startswith("high-value:")
    assert f"(+{signal.score})" in summary


def test_action_queue_priority_precedes_relevance_for_next_action():
    """Checkpoint p80 actor gaps must not be displaced by lower-priority gaps.

    `/autopilot` surfaces a recommended_executable_action by priority; the
    durable action queue should preserve that ordering before applying
    relevance/high-value tie-breaks.
    """
    queue = {
        "actions": [
            {
                "id": "low-priority-high-relevance",
                "status": "queued",
                "type": "coverage-gap",
                "priority": 75,
                "action": "Cover /rest/admin x Authz",
                "metadata": {
                    "endpoint": "/rest/admin",
                    "vuln_class": "Authz",
                    "relevance_score": 9,
                },
            },
            {
                "id": "high-priority-actor-gap",
                "status": "queued",
                "type": "actor-gap",
                "priority": 80,
                "action": "Cover actor matrix gap",
                "metadata": {
                    "endpoint": "/rest/admin",
                    "vuln_class": "Authz",
                },
            },
        ],
    }

    assert action_queue.select_next_action(queue)["id"] == "high-priority-actor-gap"


def test_noise_filter_extracts_urls_and_builtin_dedup_keeps_param_signatures(tmp_path):
    raw = tmp_path / "urls.txt"
    out = tmp_path / "dedup.txt"
    raw.write_text(
        "prefix https://app.example.test/api/items?id=1&sort=asc extra\n"
        "https://app.example.test/api/items?sort=desc&id=2\n"
        "https://app.example.test/api/items?page=1\n"
        "not a url\n",
        encoding="utf-8",
    )

    assert noise_filter._extract_url("see https://app.example.test/x?q=1 now") == "https://app.example.test/x?q=1"
    assert noise_filter._extract_url("not a url") == ""

    kept_count = noise_filter._builtin_dedup(raw, out)
    kept = out.read_text(encoding="utf-8").splitlines()
    assert kept_count == 2
    assert kept == [
        "https://app.example.test/api/items?id=1&sort=asc",
        "https://app.example.test/api/items?page=1",
    ]


def test_runtime_config_is_fail_open_and_explicit_override_wins(tmp_path):
    assert runtime_config.load_runtime_config(tmp_path) == {}
    assert runtime_config.is_ctf_mode_enabled(tmp_path) is False
    assert runtime_config.is_ctf_mode_enabled(tmp_path, explicit=True) is True

    (tmp_path / "config.json").write_text('{"ctf_mode": true, "other": 1}\n', encoding="utf-8")
    assert runtime_config.load_runtime_config(tmp_path)["ctf_mode"] is True
    assert runtime_config.is_ctf_mode_enabled(tmp_path) is True
    assert runtime_config.is_ctf_mode_enabled(tmp_path, explicit=False) is False

    (tmp_path / "config.json").write_text("not-json", encoding="utf-8")
    assert runtime_config.load_runtime_config(tmp_path) == {}


def test_parallel_workers_join_consolidate_preserves_highest_severity_and_appends_once(tmp_path, monkeypatch):
    monkeypatch.setattr(parallel_workers, "_trigger_matrix_rebuild", lambda target, repo: True)
    results = [
        parallel_workers.WorkerResult(
            worker_id="w1",
            kind="hypothesis",
            scratch_dir="",
            completed=True,
            timed_out=False,
            exit_code=0,
            findings=[{"endpoint": "/api/orders/1", "vuln_class": "IDOR", "severity": "low"}],
        ),
        parallel_workers.WorkerResult(
            worker_id="w2",
            kind="hypothesis",
            scratch_dir="",
            completed=True,
            timed_out=False,
            exit_code=0,
            findings=[{"endpoint": "/api/orders/1", "vuln_class": "IDOR", "severity": "high"}],
        ),
    ]

    first = parallel_workers.join_and_consolidate(results, "target.test", repo_root=tmp_path)
    second = parallel_workers.join_and_consolidate(results, "target.test", repo_root=tmp_path)

    findings = json.loads((tmp_path / "findings" / "target.test" / "findings.json").read_text(encoding="utf-8"))
    assert first == {
        "workers_total": 2,
        "workers_completed": 2,
        "workers_timed_out": 0,
        "consolidated_findings": 1,
        "appended_to_findings": 1,
        "matrix_rebuilt": True,
    }
    assert second["appended_to_findings"] == 0
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["worker_id"] == "w2"
