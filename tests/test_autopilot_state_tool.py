"""Tests for tools/autopilot_state.py."""

import json
import time

from memory.hunt_journal import HuntJournal
from memory.pattern_db import PatternDB
from memory.schemas import make_journal_entry, make_pattern_entry
from memory.target_profile import make_target_profile, save_target_profile
from autopilot_state import (
    _build_recommended_targets,
    _filter_ranked_placeholders,
    _pick_next_action,
    build_autopilot_state,
    format_autopilot_state,
)
from request_guard import record_request
from runtime_state import update_runtime_state


class TestAutopilotState:

    def test_batch_state_selects_only_completed_domain_handoff(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\nbeta.test\ngamma.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / "targets"
        batch_dir.mkdir(parents=True)
        (batch_dir / "batch_manifest.jsonl").write_text(
            '{"target":"alpha.test","status":"ok"}\n'
            '{"target":"beta.test","status":"failed"}\n',
            encoding="utf-8",
        )
        (batch_dir / "failed_targets.txt").write_text("beta.test\n", encoding="utf-8")
        (batch_dir / "pending_targets.txt").write_text(
            "alpha.test\nbeta.test\ngamma.test\n",
            encoding="utf-8",
        )
        (batch_dir / "high_value_targets.json").write_text(
            json.dumps([
                {"target": "alpha.test", "score": "invalid", "top_signals": []},
                {"target": "uncompleted.test", "score": 99, "top_signals": []},
            ]),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))

        assert state["target_kind"] == "list"
        assert state["next_action"] == "select_completed_domain"
        assert state["batch"]["completed"] == ["alpha.test"]
        assert state["batch"]["failed"] == ["beta.test"]
        assert state["batch"]["pending"] == ["gamma.test"]
        assert [item["target"] for item in state["batch"]["candidates"]] == ["alpha.test"]
        assert state["batch"]["candidates"][0]["score"] == 0
        output = format_autopilot_state(state)
        assert "Completed-domain candidates:" in output
        assert "alpha.test" in output
        assert "Do not run surface, scan, or active hunting against the batch index." in output

    def test_empty_batch_is_terminal_instead_of_restarting_recon(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("# no current targets\n\n", encoding="utf-8")

        state = build_autopilot_state(str(tmp_path), str(scope))
        output = format_autopilot_state(state)

        assert state["next_action"] == "invalid_batch_target"
        assert state["batch"]["current_entries"] == []
        assert state["batch"]["pending"] == []
        assert "Stop: add at least one usable primary domain" in output

    def test_all_failed_current_batch_is_terminal(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\nbeta.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / "targets"
        batch_dir.mkdir(parents=True)
        (batch_dir / "failed_targets.txt").write_text(
            "alpha.test\nbeta.test\nold.test\n",
            encoding="utf-8",
        )
        (batch_dir / "pending_targets.txt").write_text(
            "old.test\n",
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))
        output = format_autopilot_state(state)

        assert state["next_action"] == "batch_failed"
        assert state["batch"]["failed"] == ["alpha.test", "beta.test"]
        assert state["batch"]["pending"] == []
        assert "do not retry the failed batch automatically" in output

    def test_changed_batch_input_filters_old_candidates_and_adds_current_pending(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("beta.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / "targets"
        batch_dir.mkdir(parents=True)
        (batch_dir / "completed_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (batch_dir / "pending_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (batch_dir / "high_value_targets.json").write_text(
            json.dumps([{"target": "alpha.test", "score": 99}]),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), str(scope))

        assert state["next_action"] == "run_batch_recon"
        assert state["batch"]["current_entries"] == ["beta.test"]
        assert state["batch"]["completed"] == []
        assert state["batch"]["candidates"] == []
        assert state["batch"]["pending"] == ["beta.test"]

    def test_partial_batch_keeps_current_pending_when_ranked_json_is_invalid(self, tmp_path):
        scope = tmp_path / "targets.txt"
        scope.write_text("alpha.test\nbeta.test\n", encoding="utf-8")
        batch_dir = tmp_path / "recon" / "targets"
        batch_dir.mkdir(parents=True)
        (batch_dir / "completed_targets.txt").write_text("alpha.test\n", encoding="utf-8")
        (batch_dir / "pending_targets.txt").write_text("beta.test\nold.test\n", encoding="utf-8")
        (batch_dir / "high_value_targets.json").write_text("{invalid", encoding="utf-8")

        state = build_autopilot_state(str(tmp_path), str(scope))

        assert state["next_action"] == "select_completed_domain"
        assert state["batch"]["pending"] == ["beta.test"]
        assert [item["target"] for item in state["batch"]["candidates"]] == ["alpha.test"]

    def test_ranked_filter_keeps_closed_history_but_removes_object_placeholders(self):
        kept_dead_end = {
            "url": "https://app.target.com/api/orders",
            "suggested": "avoid repeating remembered dead end unless new evidence changed",
        }
        kept_reported = {
            "url": "https://app.target.com/api/users",
            "suggested": "already reported/generated; avoid repeating exact lane",
        }
        placeholder = {"url": "https://app.target.com/rest/basket/NaN"}

        filtered = _filter_ranked_placeholders({
            "review_pool": [kept_dead_end, kept_reported, placeholder],
            "p1": [kept_dead_end, kept_reported, placeholder],
            "p2": [],
        })

        assert filtered["review_pool"] == [kept_dead_end, kept_reported]
        assert filtered["p1"] == [kept_dead_end, kept_reported]

    def test_recommended_targets_frontload_last_focus_within_same_guard_bucket(self):
        recommended = _build_recommended_targets(
            [
                {
                    "url": "https://api.target.com/api/v2/users/123",
                    "host": "api.target.com",
                    "suggested": "idor checks",
                    "score": 18,
                },
                {
                    "url": "https://api.target.com/graphql",
                    "host": "api.target.com",
                    "suggested": "field auth checks",
                    "score": 10,
                },
            ],
            {"hosts": []},
            ["/graphql"],
            prefer_resume_targets=True,
        )

        assert recommended[0]["url"] == "https://api.target.com/graphql"
        assert recommended[0]["matches_resume_target"] is True
        assert recommended[1]["matches_resume_target"] is False

    def test_recommended_targets_preserve_surface_review_order_over_score(self):
        recommended = _build_recommended_targets(
            [
                {
                    "url": "https://app.target.com/rest/languages",
                    "host": "app.target.com",
                    "suggested": "browser-observed workflow checks",
                    "score": 7,
                    "review_reason": "browser-observed API/workflow",
                },
                {
                    "url": "https://app.target.com/rest/continue-code/apply/",
                    "host": "app.target.com",
                    "suggested": "baseline checks",
                    "score": 11,
                    "review_reason": "top advisory score",
                },
            ],
            {"hosts": []},
        )

        assert recommended[0]["url"] == "https://app.target.com/rest/languages"
        assert recommended[0]["review_reason"] == "browser-observed API/workflow"

    def test_requires_recon_when_missing(self, tmp_path):
        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(memory_dir))
        assert state["has_recon"] is False
        assert state["has_memory"] is True
        assert state["next_action"] == "run_recon"

    def test_loads_target_goal_memory_into_state_and_output(self, tmp_path):
        repo_root = tmp_path
        goals_dir = repo_root / "memory" / "goals"
        target_dir = goals_dir / "targets"
        target_dir.mkdir(parents=True)
        (goals_dir / "active.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "active_goal": "test org API authorization",
                    "current_hypothesis": "org_id may be user-controlled",
                }
            ),
            encoding="utf-8",
        )
        (target_dir / "target.com.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "active_leads": [{"text": "/api/org/{id}/users"}],
                    "next_actions": [{"text": "run role_diff with two owned accounts"}],
                    "dead_ends": [{"text": "GraphQL introspection alone is not reportable"}],
                    "session_handoffs": [
                        {
                            "path": "memory/goals/sessions/example.md",
                            "summary": "continue org API role diff",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["target_goal_memory"]["active_matches"] is True
        assert state["target_goal_memory"]["active"]["active_goal"] == "test org API authorization"
        assert "Target memory:" in output
        assert "Goal: test org API authorization" in output
        assert "Hypothesis: org_id may be user-controlled" in output
        assert "/api/org/{id}/users" in output
        assert "run role_diff with two owned accounts" in output
        assert state["memory_action_queue"]
        assert state["memory_action_queue"][0]["command_hint"] == "role/object diff with low-risk replay"
        assert "Memory action queue:" in output
        assert "continue org API role diff" in output

    def test_host_list_relative_target_uses_batch_handoff_not_aggregate_surface(self, tmp_path, monkeypatch):
        repo_root = tmp_path
        list_file = repo_root / "scope.txt"
        list_file.write_text("api.target.com\n", encoding="utf-8")
        monkeypatch.chdir(repo_root)

        recon_dir = repo_root / "recon" / "scope"
        recon_dir.mkdir(parents=True)
        (recon_dir / "completed_targets.txt").write_text("api.target.com\n")
        (recon_dir / "high_value_targets.json").write_text(
            json.dumps([{"target": "api.target.com", "score": 12}]),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "scope.txt")

        assert state["resolved_target"] == str(list_file.resolve())
        assert state["target_kind"] == "list"
        assert state["has_recon"] is True
        assert state["next_action"] == "select_completed_domain"
        assert state["batch"]["candidates"][0]["target"] == "api.target.com"
        assert "surface" not in state
        assert "guard_status" not in state

    def test_all_hosts_tripped_pivots_to_cached_evidence_work(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,Cloudflare] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        record_request(
            memory_dir=memory_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=403,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=time.time(),
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["next_action"] == "guard_safe_pivot"
        assert state["guard_status"]["ready_hosts"] == 0
        assert state["next_tool_hint"] == "context_pack"
        assert "cached recon/browser/JS/source evidence" in output
        assert "residential" not in output.lower()

    def test_pending_structured_finding_collects_missing_candidate_evidence(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "sqli_pending",
                            "type": "sqli",
                            "severity": "high",
                            "confidence": "confirmed",
                            "url": "https://api.target.com/search?q=1",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                            "rubric": {
                                "rubric_id": "sqli",
                                "status": "needs-evidence",
                                "ready": False,
                                "score": 50,
                                "satisfied_count": 2,
                                "total": 4,
                                "missing_labels": [
                                    "paired baseline and probe",
                                    "stable response difference",
                                ],
                                "next_actions": [
                                    "capture a paired baseline/probe response diff",
                                ],
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["next_action"] == "collect_candidate_evidence"
        assert "collect candidate evidence for finding sqli_pending" in output
        assert "missing=paired baseline and probe, stable response difference" in output
        assert "Next evidence step: capture a paired baseline/probe response diff" in output
        assert "Structured findings: total=1, pending_validation=1" in output
        assert "Next validation: sqli_pending [high/confirmed] sqli https://api.target.com/search?q=1" in output
        assert state["next_tool_hint"] == ""

    def test_ready_and_legacy_structured_candidates_still_validate(self):
        ready = {
            "next_validation": {
                "id": "ready-candidate",
                "rubric": {"ready": True, "status": "candidate-ready"},
            }
        }
        legacy = {"next_validation": {"id": "legacy-candidate"}}

        assert _pick_next_action(True, {}, None, ready) == "validate_finding"
        assert _pick_next_action(True, {}, None, legacy) == "validate_finding"

    def test_wait_marker_preempts_missing_candidate_evidence(self):
        structured = {
            "next_validation": {
                "id": "waiting-candidate",
                "rubric": {"ready": False, "status": "needs-evidence"},
            }
        }

        assert (
            _pick_next_action(
                True,
                {},
                None,
                structured,
                recon_in_progress=True,
            )
            == "wait_recon"
        )

    def test_outputs_validation_runner_candidates_as_advisory_pool(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [API] [Express] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://target.com/rest/basket/6\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        validation_dir = repo_root / "evidence" / "target.com" / "validation" / "idor-basket"
        validation_dir.mkdir(parents=True)
        (validation_dir / "summary.json").write_text(
            json.dumps(
                {
                    "lane": "idor_actor_pair",
                    "finding_id": "idor-basket",
                    "url": "https://target.com/rest/basket/6",
                    "method": "GET",
                    "result": "tested_finding",
                    "candidate_ready": True,
                    "evidence_rubric": {
                        "status": "candidate-ready",
                        "ready": True,
                        "summary": "authz:candidate-ready",
                    },
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["validation_runner_candidates"][0]["id"] == "idor-basket"
        assert state["validation_runner_next"]["id"] == "idor-basket"
        assert state["next_action"] == "review_validation_candidate"
        assert "review validation-runner candidate idor-basket" in output
        assert "Validation runner candidates (advisory; require /validate before report):" in output
        assert "idor-basket [idor_actor_pair/tested_finding]" in output

    def test_substantive_durable_queue_preempts_fresh_recon(self, tmp_path):
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "actions": [
                    {
                        "id": "AQ-0001",
                        "target": "target.com",
                        "status": "candidate",
                        "type": "candidate-evidence-gap",
                        "priority": 95,
                        "action": "Review the exact owner/peer response diff.",
                        "command_hint": "/validate idor-orders",
                        "evidence": "runner summary is candidate-ready",
                    }
                ],
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )
        output = format_autopilot_state(state)

        assert state["has_recon"] is False
        assert state["action_queue_next"]["id"] == "AQ-0001"
        assert state["next_action"] == "resume_action_queue"
        assert "resume durable action AQ-0001" in output

    def test_advisory_queue_item_does_not_preempt_fresh_recon(self, tmp_path):
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "actions": [
                    {
                        "id": "AQ-0001",
                        "target": "target.com",
                        "status": "queued",
                        "type": "surface-review",
                        "priority": 92,
                        "action": "Review a score-only surface hint.",
                        "command_hint": "choose a route",
                        "evidence": "Reason: top advisory score",
                    }
                ],
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )

        assert state["action_queue_next"] == {}
        assert state["next_action"] == "run_recon"

    def test_completed_recon_without_live_hosts_is_terminal(self, tmp_path):
        recon_dir = tmp_path / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text("", encoding="utf-8")
        (recon_dir / "exposure").mkdir()
        (recon_dir / "exposure" / "config_files.txt").write_text(
            "https://target.com/.env\n",
            encoding="utf-8",
        )
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_only",
            last_executed_workflow="run_recon",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )
        output = format_autopilot_state(state)

        assert state["has_recon"] is False
        assert state["recon_completed_no_live_hosts"] is True
        assert state["next_action"] == "recon_no_live_hosts"
        assert "do not rerun recon automatically" in output
        assert "completed with no live host inventory" in state["recon_blocker"]
        inventory = state["observation_inventory"]
        assert inventory["total"] >= 1
        assert inventory["untouched"] >= 1
        assert "Observation inventory: total=" in output

    def test_missing_recon_precedes_validated_structured_finding_report(self, tmp_path):
        repo_root = tmp_path
        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "mfa_report",
                            "type": "mfa",
                            "severity": "medium",
                            "confidence": "high",
                            "url": "https://api.target.com/mfa",
                            "validation_status": "validated",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["next_action"] == "run_recon"
        assert "Next: run /recon target.com first." in output
        assert "Next report: mfa_report [medium/high] mfa https://api.target.com/mfa" in output

    def test_weak_generic_pending_does_not_mask_validated_report(self, tmp_path):
        repo_root = tmp_path
        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "metrics",
                            "type": "exposure",
                            "severity": "medium",
                            "confidence": "medium",
                            "title": "prometheus-metrics on https://target.com/metrics",
                            "summary": "[prometheus-metrics] [http] [medium] https://target.com/metrics",
                            "url": "https://target.com/metrics",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                        },
                        {
                            "id": "admin_config",
                            "type": "auth_bypass",
                            "severity": "high",
                            "confidence": "confirmed",
                            "url": "https://target.com/rest/admin/application-configuration",
                            "validation_status": "validated",
                            "report_status": "not_generated",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["structured_findings"]["pending_validation"] == 1
        assert "next_validation" not in state["structured_findings"]
        assert state["next_action"] == "run_recon"
        assert "Next: run /recon target.com first." in output
        assert "Next report: admin_config [high/confirmed] auth_bypass" in output
        assert "Next validation:" not in output

    def test_validated_report_does_not_preempt_live_surface_review(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/orders?id=42\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "mfa_report",
                            "type": "mfa",
                            "severity": "medium",
                            "confidence": "high",
                            "url": "https://api.target.com/mfa",
                            "validation_status": "validated",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["has_recon"] is True
        assert state["surface_review_candidates"]
        assert state["next_action"] == "hunt_p1"
        assert "Next step: review the top surface candidate" in output
        assert "Next report: mfa_report [medium/high] mfa https://api.target.com/mfa" in output
        assert "Next: generate a report for validated finding mfa_report." not in output

    def test_prefers_p1_targets_when_recon_ready(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/v2/report?id=123\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/api/v2/users/123"],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=2,
        ))
        PatternDB(memory_dir / "patterns.jsonl").save(make_pattern_entry(
            target="alpha.com",
            vuln_class="idor",
            technique="id_swap",
            tech_stack=["graphql"],
            payout=900,
        ))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["has_recon"] is True
        assert state["has_memory"] is True
        assert state["next_action"] == "hunt_p1"
        assert state["recommended_targets"]
        assert "graphql" in state["recommended_targets"][0]["url"]

    def test_build_autopilot_state_does_not_rewrite_surface_probe_log(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/search?q=%27%20or%20%271%27=%271\n"
            "https://api.target.com/api/org/123/users\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        probe_log = recon_dir / "urls" / "_filtered_attack_probes.txt"
        probe_log.write_text("sentinel\n", encoding="utf-8")

        build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert probe_log.read_text(encoding="utf-8") == "sentinel\n"

    def test_prefers_continue_last_focus_when_recent_session_exists(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/graphql"],
            untested_endpoints=["/api/v2/users/123"],
            hunt_sessions=2,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/graphql"],
            vuln_classes_tried=["recon", "idor"],
            findings_count=1,
            session_id="sess-focus",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["next_action"] == "continue_last_focus"
        assert state["resume_targets"] == ["/graphql"]
        assert state["recommended_targets"][0]["url"] == "https://api.target.com/graphql"

    def test_finalized_findings_do_not_drive_resume_but_do_not_hide_surface(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [API] [Express] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://target.com/api/Feedbacks\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "auth_bypass_feedbacks",
                            "type": "auth_bypass",
                            "url": "https://target.com/api/Feedbacks",
                            "validation_status": "rejected",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tested_endpoints=["/api/Feedbacks"],
            untested_endpoints=[],
            hunt_sessions=1,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/api/Feedbacks"],
            vuln_classes_tried=["authz"],
            findings_count=0,
            session_id="sess-closed",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["resume_targets"] == []
        assert state["surface_review_candidates"]
        assert state["surface_review_candidates"][0]["url"] == "https://target.com/api/Feedbacks"
        assert state["next_action"] == "hunt_p1"

    def test_build_autopilot_state_emits_enrichment_tool_hints(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [Admin Portal] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://app.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "urls" / "js_files.txt").write_text(
            "https://app.target.com/static/app.js\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("/api/v2/users\n")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["next.js", "graphql"],
            tested_endpoints=[],
            untested_endpoints=["/graphql"],
            hunt_sessions=1,
        ))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["next_tool_hint"] == "run_browser_probe"
        assert [item["tool"] for item in state["enrichment_hints"]] == [
            "run_browser_probe",
            "run_source_intel",
            "run_js_read",
        ]

    def test_format_autopilot_state_shows_enrichment_hints(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js", "graphql"],
            "next_action": "hunt_p1",
            "next_tool_hint": "run_browser_probe",
            "enrichment_hints": [
                {
                    "tool": "run_browser_probe",
                    "reason": "app-like or GraphQL surface signals were detected, but no browser-observed surface exists yet",
                },
                {
                    "tool": "run_js_read",
                    "reason": "cached JS artifacts exist, but js_intel materials have not been prepared yet",
                },
            ],
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": [],
            "recommended_targets": [],
        })

        assert "Next tool hint: run_browser_probe" in output
        assert "Enrichment hints:" in output
        assert "- run_browser_probe: app-like or GraphQL surface signals were detected" in output
        assert "- run_js_read: cached JS artifacts exist" in output

    def test_format_autopilot_state_shows_workflow_leads(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js", "graphql"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {
                "stats": {"p1": 1, "p2": 0},
                "workflow_leads": [
                    json.dumps(
                        {
                            "source": "js_intel",
                            "title": "Admin export IDOR",
                            "category": "idor",
                            "priority": "high",
                            "next_action": "swap order_id under a lower-privileged session",
                        }
                    )
                ],
            },
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": [],
            "recommended_targets": [],
        })

        assert "Workflow leads:" in output
        assert "[high] idor: Admin export IDOR" in output
        assert "Next: swap order_id under a lower-privileged session" in output

    def test_prefers_resume_untested_when_recent_session_has_no_endpoint_preview(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=2,
        ))
        HuntJournal(memory_dir / "journal.jsonl").log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=[],
            vuln_classes_tried=["recon"],
            findings_count=0,
            session_id="sess-resume",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["next_action"] == "resume_untested"
        assert state["resume_targets"] == ["/graphql", "/api/v2/report?id=123"]

    def test_formats_state(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js", "graphql"],
            "next_action": "hunt_p1",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql", "/api/users"],
                "latest_session_summary": {
                    "findings_count": 1,
                    "vuln_classes": ["recon", "idor"],
                    "endpoints_preview": ["/graphql"],
                },
            },
            "surface": {"stats": {"p1": 2, "p2": 1}},
            "guard_status": {"tracked_hosts": 1, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql"],
            "recommended_targets": [
                {
                    "url": "https://api.target.com/graphql",
                    "suggested": "field-level auth checks",
                    "score": 14,
                    "tripped": False,
                    "remaining_seconds": 0.0,
                }
            ],
        })
        assert "AUTOPILOT STATE: target.com" in output
        assert "Next action: hunt_p1" in output
        assert "Next step: review the top surface candidate, then choose the next evidence step: https://api.target.com/graphql." in output
        assert "https://api.target.com/graphql" in output
        assert "Last session: 1 finding(s), tried recon, idor" in output
        assert "Last endpoints: /graphql" in output
        assert "Resume targets: /graphql" in output

    def test_formats_continue_last_focus_with_human_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["graphql"],
            "next_action": "continue_last_focus",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql"],
                "latest_session_summary": {
                    "findings_count": 1,
                    "vuln_classes": ["recon", "idor"],
                    "endpoints_preview": ["/graphql"],
                },
            },
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql"],
            "recommended_targets": [],
        })

        assert "Next action: continue_last_focus" in output
        assert "Next step: continue testing the last focus first: /graphql." in output

    def test_formats_resume_untested_with_human_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["graphql"],
            "next_action": "resume_untested",
            "resume_summary": {
                "sessions": 2,
                "untested_endpoints": ["/graphql", "/api/v2/report?id=123"],
                "latest_session_summary": {
                    "findings_count": 0,
                    "vuln_classes": ["recon"],
                    "endpoints_preview": [],
                },
            },
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "resume_targets": ["/graphql", "/api/v2/report?id=123"],
            "recommended_targets": [],
        })

        assert "Next action: resume_untested" in output
        assert "Next step: resume the cached untested surface first: /graphql, /api/v2/report?id=123." in output

    def test_includes_guard_state_and_marks_tripped_hosts(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "\n".join([
                "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]",
                "https://files.target.com [200] [Files] [nginx] [1000]",
            ]) + "\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://files.target.com/download?id=1\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/download?id=1"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=2,
        ))
        now_ts = time.time()
        record_request(
            memory_dir=memory_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=now_ts,
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        assert state["guard_status"]["tracked_hosts"] == 1
        assert len(state["guard_status"]["tripped_hosts"]) == 1
        assert state["guard_status"]["tripped_hosts"][0]["host"] == "api.target.com"
        assert "cooling hosts" in state["guard_hint"]
        assert state["recommended_targets"][0]["host"] == "files.target.com"
        assert state["recommended_targets"][0]["tripped"] is False
        assert any(item["tripped"] for item in state["recommended_targets"])
        output = format_autopilot_state(state)
        assert "Guard hint:" in output
        assert "files.target.com" in output

    def test_build_autopilot_state_includes_recent_guard_advisories(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql"],
            tested_endpoints=[],
            untested_endpoints=["/graphql"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=1,
        ))
        HuntJournal(memory_dir / "journal.jsonl").append(make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="guard_advisory",
            endpoint="https://api.target.com/graphql",
            result="informational",
            severity="none",
            technique="request_guard",
            notes=(
                "request_guard advisory for GET https://api.target.com/graphql. "
                "Host: api.target.com. Action: breaker_advisory. "
                "Reason: circuit breaker active."
            ),
            tags=["guard_advisory", "auto_logged", "breaker_advisory"],
        ))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert len(state["recent_guard_advisories"]) == 1
        assert state["recent_guard_advisories"][0]["endpoint"] == "https://api.target.com/graphql"
        assert "breaker_advisory" in state["recent_guard_advisories"][0]["notes"]
        assert state["pivot_hint"] == ""

    def test_includes_repo_source_hint_when_artifacts_exist(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok"}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 1\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))
        output = format_autopilot_state(state)

        assert state["repo_source_available"] is True
        assert state["repo_source_artifacts"] == ["repo_source_meta.json", "repo_summary.md"]
        assert "Repo source: available" in output
        assert "read_repo_source_summary" in output

    def test_build_autopilot_state_includes_repo_source_summary(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 1\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile("target.com", hunt_sessions=1))

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["repo_source_summary"]["source_kind"] == "local_path"
        assert state["repo_source_summary"]["secret_findings"] == 2
        assert state["repo_source_summary"]["ci_findings"] == 1
        assert state["repo_source_summary"]["summary_hint"] == "local_path, secrets=2, ci=1"

    def test_build_autopilot_state_includes_runtime_state_and_recon_cache_summary(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "exposure" / "api_leaks").mkdir(parents=True)
        (recon_dir / "exposure" / "identity_intel").mkdir(parents=True)
        (recon_dir / "exposure" / "cloud").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "exposure" / "api_doc_candidates.txt").write_text(
            "[urls] https://api.target.com/openapi.json\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leak_candidates.txt").write_text(
            "https://www.postman.com/target/workspace/collection\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leak_trufflehog_verified.jsonl").write_text(
            '{"Verified":true}\n',
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leaks" / "swagger_leaks.txt").write_text(
            "https://api.target.com/swagger.json\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leaks" / "postman_leaks.txt").write_text(
            "postman collection: target\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "cloud_storage_candidates.txt").write_text(
            "https://target.s3.amazonaws.com/private/\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "identity_intel" / "emails.txt").write_text(
            "admin@target.com\nops@target.com\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "identity_intel" / "leaksearch.txt").write_text(
            "target leak hit\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "cloud" / "cloud_enum.txt").write_text(
            "target-backup\n",
            encoding="utf-8",
        )
        update_runtime_state(repo_root, "target.com", mode="agent", last_executed_workflow="run_vuln_scan")

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["runtime_state"]["last_executed_workflow"] == "run_vuln_scan"
        assert state["runtime_state"]["mode"] == "agent"
        assert state["recon_artifacts"]["ready"] is True
        assert "Last Workflow: run_vuln_scan" in output
        assert "Recon cache: hosts=1, surface=1" in output
        assert state["recon_artifacts"]["exposure_ready"] is True
        assert state["recon_artifacts"]["counts"]["api_doc_candidates"] == 1
        assert state["recon_artifacts"]["counts"]["identity_emails"] == 2
        assert "Exposure signals:" in output
        assert "- API docs: 1" in output
        assert "- API leaks: candidates=1, swagger=1, postman=1, postleaks=0, verified_secrets=1" in output
        assert "- Identity/cloud intel: emails=2, LeakSearch=1, cloud_enum=1" in output
        assert "Next exposure review:" in output
        assert "recon/target.com/exposure/api_doc_candidates.txt" in output
        assert "recon/target.com/exposure/api_leak_trufflehog_verified.jsonl" in output
        assert "recon/target.com/exposure/identity_intel/summary.md" in output

    def test_format_autopilot_state_surfaces_incomplete_cached_recon(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": False,
            "has_memory": False,
            "next_action": "run_recon",
            "resume_summary": {},
            "runtime_state": {"last_executed_workflow": "run_recon", "mode": "recon_only"},
            "recon_artifacts": {
                "available": True,
                "missing": ["live/httpx_full.txt"],
                "warnings": [],
            },
            "repo_source_available": False,
            "structured_findings": {},
            "recent_guard_advisories": [],
        })

        assert "Last Workflow: run_recon" in output
        assert "Recon cache issue: live/httpx_full.txt" in output
        assert "rerun /recon target.com; cached recon is incomplete" in output

    def test_recon_running_runtime_state_waits_instead_of_restart_loop(self, tmp_path):
        repo_root = tmp_path
        update_runtime_state(
            repo_root,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon_started",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["has_recon"] is False
        assert state["recon_in_progress"] is True
        assert state["next_action"] == "wait_recon"
        assert "Recon: in progress" in output
        assert "wait/poll the existing /recon target.com run; do not launch another recon" in output

    def test_recon_running_marker_preempts_validation_followup(self, tmp_path):
        findings_dir = tmp_path / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "idor_wait_recon",
                        "type": "idor",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": "https://target.com/api/orders/1",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                ],
            }),
            encoding="utf-8",
        )
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon_started",
        )

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["structured_findings"]["next_validation"]["id"] == "idor_wait_recon"
        assert state["next_action"] == "wait_recon"

    def test_recon_running_marker_preempts_runner_and_durable_queue(self, tmp_path):
        validation_dir = tmp_path / "evidence" / "target.com" / "validation" / "runner-wait"
        validation_dir.mkdir(parents=True)
        (validation_dir / "summary.json").write_text(
            json.dumps({
                "lane": "authz_role_replay",
                "finding_id": "runner-wait",
                "url": "https://target.com/api/admin",
                "method": "GET",
                "result": "tested_finding",
                "candidate_ready": True,
                "evidence_rubric": {"status": "candidate-ready", "ready": True},
            }),
            encoding="utf-8",
        )
        queue_dir = tmp_path / "state" / "target.com"
        queue_dir.mkdir(parents=True)
        (queue_dir / "action_queue.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "actions": [{
                    "id": "AQ-0001",
                    "status": "candidate",
                    "type": "candidate-evidence-gap",
                    "priority": 99,
                    "action": "review candidate evidence",
                    "command_hint": "/validate runner-wait",
                }],
            }),
            encoding="utf-8",
        )
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon_started",
        )

        state = build_autopilot_state(
            str(tmp_path),
            "target.com",
            memory_dir=str(tmp_path / "hunt-memory"),
        )

        assert state["validation_runner_next"]["id"] == "runner-wait"
        assert state["action_queue_next"]["id"] == "AQ-0001"
        assert state["next_action"] == "wait_recon"

    def test_stale_recon_running_marker_allows_single_rerun(self, tmp_path):
        state_dir = tmp_path / "state" / "target.com"
        state_dir.mkdir(parents=True)
        (state_dir / "session.json").write_text(
            json.dumps({
                "schema_version": 2,
                "target": "target.com",
                "storage_key": "target.com",
                "mode": "recon_running",
                "last_executed_workflow": "run_recon_started",
                "updated_at": "2000-01-01T00:00:00Z",
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["recon_in_progress"] is False
        assert state["next_action"] == "run_recon"

    def test_completed_recon_workflow_overrides_stale_running_mode(self, tmp_path):
        update_runtime_state(
            tmp_path,
            "target.com",
            mode="recon_running",
            last_executed_workflow="run_recon",
        )

        state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["recon_in_progress"] is False
        assert state["next_action"] != "wait_recon"

    def test_scan_running_runtime_state_waits_instead_of_restart_loop(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        update_runtime_state(
            repo_root,
            "target.com",
            mode="scan_running",
            last_executed_workflow="run_scan_started",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))
        output = format_autopilot_state(state)

        assert state["has_recon"] is True
        assert state["scan_in_progress"] is True
        assert state["next_action"] == "wait_scan"
        assert "Scan: in progress" in output
        assert "do not launch another scan-only quick" in output

    def test_scan_running_marker_preempts_validation_followup(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [HTML] [OK] [100]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://target.com/api/orders/1\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps({
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "idor_wait_scan",
                        "type": "idor",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": "https://target.com/api/orders/1",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                ],
            }),
            encoding="utf-8",
        )
        update_runtime_state(
            repo_root,
            "target.com",
            mode="scan_running",
            last_executed_workflow="run_scan_started",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["structured_findings"]["next_validation"]["id"] == "idor_wait_scan"
        assert state["scan_in_progress"] is True
        assert state["next_action"] == "wait_scan"

    def test_stale_scan_running_marker_allows_single_rerun(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        state_dir = repo_root / "state" / "target.com"
        state_dir.mkdir(parents=True)
        (state_dir / "session.json").write_text(
            json.dumps({
                "schema_version": 2,
                "target": "target.com",
                "storage_key": "target.com",
                "mode": "scan_running",
                "last_executed_workflow": "run_scan_started",
                "updated_at": "2000-01-01T00:00:00Z",
            }),
            encoding="utf-8",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["has_recon"] is True
        assert state["scan_in_progress"] is False
        assert state["next_action"] != "wait_scan"

    def test_completed_scan_workflow_overrides_stale_running_mode(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        update_runtime_state(
            repo_root,
            "target.com",
            mode="scan_running",
            last_executed_workflow="run_vuln_scan",
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(tmp_path / "hunt-memory"))

        assert state["has_recon"] is True
        assert state["scan_in_progress"] is False
        assert state["next_action"] != "wait_scan"

    def test_formats_recent_guard_advisories_section(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 1, "tripped_hosts": [], "settings": {}},
            "guard_hint": "prefer the ready host files.target.com via https://files.target.com/download?id=1",
            "repo_source_available": False,
            "resume_targets": [],
            "recommended_targets": [
                {
                    "url": "https://files.target.com/download?id=1",
                    "suggested": "idor checks",
                    "score": 9,
                    "tripped": False,
                    "remaining_seconds": 0.0,
                }
            ],
            "recent_guard_advisories": [
                {
                    "action": "hunt",
                    "endpoint": "https://api.target.com/graphql",
                    "notes": (
                        "request_guard advisory for GET https://api.target.com/graphql. "
                        "Host: api.target.com. Action: breaker_advisory. "
                        "Reason: circuit breaker active."
                    ),
                }
            ],
        })

        assert "Recent guard advisories:" in output
        assert "https://api.target.com/graphql" in output
        assert "breaker_advisory" in output

    def test_format_autopilot_state_shows_repo_source_summary(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {"tracked_hosts": 0, "tripped_hosts": [], "settings": {}},
            "guard_hint": "",
            "repo_source_available": True,
            "repo_source_summary": {
                "summary_hint": "local_path, secrets=2, ci=1",
                "source_kind": "local_path",
                "secret_findings": 2,
                "ci_findings": 1,
            },
            "resume_targets": [],
            "recommended_targets": [],
            "recent_guard_advisories": [],
        })

        assert "Repo source: local_path, secrets=2, ci=1" in output

    def test_build_autopilot_state_includes_repo_first_pivot_hint_when_guard_advisories_and_repo_findings_exist(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n"
            "https://files.target.com [200] [Files] [nginx] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://files.target.com/download?id=1\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")

        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 0\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=[],
            untested_endpoints=["/graphql", "/download?id=1"],
            scope_snapshot={"in_scope": ["target.com", "*.target.com"]},
            hunt_sessions=1,
        ))
        now_ts = time.time()
        record_request(
            memory_dir=memory_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=now_ts,
        )

        state = build_autopilot_state(str(repo_root), "target.com", memory_dir=str(memory_dir))

        assert state["pivot_hint"] == "live API has guard advisories; inspect repo source findings first."

    def test_build_autopilot_state_uses_cidr_storage_key_for_recon_findings_and_repo_source(self, tmp_path):
        repo_root = tmp_path
        stored_key = "1.2.3.0_24"
        recon_dir = repo_root / "recon" / stored_key
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://1.2.3.25 [200] [API] [nginx] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://1.2.3.25/api/v1/orders?id=42\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        findings_dir = repo_root / "findings" / stored_key
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "1.2.3.0/24",
                    "findings": [
                        {
                            "id": "idor_cidr",
                            "type": "idor",
                            "severity": "high",
                            "confidence": "confirmed",
                            "url": "https://1.2.3.25/api/v1/orders?id=42",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        exposure_dir = findings_dir / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 1\n- CI findings: 0\n",
            encoding="utf-8",
        )

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "1.2.3.0/24",
            tech_stack=["nginx"],
            tested_endpoints=[],
            untested_endpoints=["/api/v1/orders?id=42"],
            scope_snapshot={"in_scope": ["1.2.3.0/24"]},
            hunt_sessions=1,
        ))

        state = build_autopilot_state(str(repo_root), "1.2.3.0/24", memory_dir=str(memory_dir))

        assert state["has_recon"] is True
        assert state["structured_findings"]["total"] == 1
        assert state["structured_findings"]["next_validation"]["id"] == "idor_cidr"
        assert state["repo_source_available"] is True
        assert state["repo_source_summary"]["secret_findings"] == 1

    def test_format_autopilot_state_shows_pivot_hint(self):
        output = format_autopilot_state({
            "target": "target.com",
            "has_recon": True,
            "has_memory": True,
            "tech_stack": ["next.js"],
            "next_action": "hunt_p1",
            "resume_summary": {},
            "surface": {"stats": {"p1": 1, "p2": 0}},
            "guard_status": {
                "tracked_hosts": 1,
                "tripped_hosts": [{"host": "api.target.com", "remaining_seconds": 20.0}],
                "settings": {},
            },
            "guard_hint": (
                "cooling hosts: api.target.com (20.0s); prefer the ready host "
                "files.target.com via https://files.target.com/download?id=1"
            ),
            "repo_source_available": True,
            "repo_source_summary": {
                "summary_hint": "local_path, secrets=2, ci=0",
                "secret_findings": 2,
                "ci_findings": 0,
            },
            "resume_targets": [],
            "recommended_targets": [],
            "recent_guard_advisories": [],
            "pivot_hint": "live API has guard advisories; inspect repo source findings first.",
        })

        assert "Pivot hint: live API has guard advisories; inspect repo source findings first." in output
