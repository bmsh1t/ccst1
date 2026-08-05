"""Focused contract tests for the AI access-limit probe plan."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tools.autopilot_state import _is_substantive_queue_action
from tools.bypass_403_plan import build_plan_metadata, summarize_results, validate_plan

REPO = Path(__file__).resolve().parents[1]


def _plan(*probes: dict, budget: int = 4) -> dict:
    return {"schema_version": 1, "budget": {"max_requests": budget}, "probes": list(probes)}


def _probe(probe_id: str, url: str = "https://example.test/admin", **mutation: object) -> dict:
    request = {"url": url, "method": "GET", **mutation}
    return {
        "id": probe_id,
        "kind": "path",
        "mutation": request,
        "reason": "proxy and backend normalization may differ",
        "expected_signal": "protected-content-or-route-diff",
        "stop_condition": "same denial response",
    }


def test_plan_scope_and_auth_material_are_fail_closed() -> None:
    with pytest.raises(ValueError, match="outside target scope"):
        validate_plan(_plan(_probe("off", "https://other.test/admin")), target="example.test")

    with pytest.raises(ValueError, match="authentication material"):
        validate_plan(
            _plan(_probe("auth", headers={"Authorization": "Bearer secret"})),
            target="example.test",
        )

    with pytest.raises(ValueError, match="URL credentials"):
        validate_plan(_plan(_probe("userinfo", "https://user:pass@example.test/admin")), target="example.test")

    mismatched = _plan(_probe("declared"))
    mismatched["target"] = "other.test"
    with pytest.raises(ValueError, match="does not match"):
        validate_plan(mismatched, target="example.test")


def test_plan_budget_override_can_only_narrow_and_ids_are_unique() -> None:
    payload = _plan(_probe("one"), _probe("two"), budget=1)
    assert [item["id"] for item in validate_plan(payload, target="example.test", max_requests=20)] == ["one"]

    with pytest.raises(ValueError, match="duplicated"):
        validate_plan(_plan(_probe("same"), _probe("same")), target="example.test")


def test_plan_metadata_preserves_unexecuted_tail_and_round_identity(tmp_path) -> None:
    payload = _plan(_probe("one"), _probe("two"), _probe("three"), budget=1)
    payload.update(
        {
            "round": 1,
            "budget": {"max_requests": 1, "max_rounds": 2},
            "baseline_ref": "evidence/example.test/baseline.json",
        }
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    normalized = validate_plan(payload, target="example.test")
    metadata = build_plan_metadata(
        payload,
        normalized,
        target="example.test",
        request_budget=1,
        plan_path=str(plan_path),
    )
    assert metadata["executed_probe_ids"] == ["one"]
    assert metadata["skipped_probe_ids"] == ["two", "three"]
    assert metadata["budget_exhausted"] is True
    assert metadata["round"] == 1
    assert metadata["max_rounds"] == 2

    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps({"id": "one", "status": "blocked"}) + "\n", encoding="utf-8")
    metadata_path = tmp_path / "plan.meta.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    summary = summarize_results(
        results,
        target="example.test",
        plan_path=str(plan_path),
        plan_metadata_path=str(metadata_path),
    )
    assert summary["status"] == "partial"
    assert summary["skipped_probe_ids"] == ["two", "three"]
    assert "resume unexecuted" in summary["next_action"]


def test_bypass_action_with_target_summary_is_substantive() -> None:
    assert _is_substantive_queue_action(
        {
            "status": "queued",
            "type": "bypass-403",
            "evidence_type": "access-limit",
            "evidence": "bounded access-limit summary: findings/example/bypass/summary.json",
            "command_hint": "Review findings/example/bypass/summary.json",
        }
    ) is True


def test_plan_marks_unsafe_methods_without_executing_them() -> None:
    normalized = validate_plan(
        _plan(_probe("trace", method="TRACE")),
        target="example.test",
    )
    assert normalized[0]["unsafe"] is True
    assert normalized[0]["method"] == "TRACE"


def test_auth_file_is_bound_to_the_execution_target(tmp_path) -> None:
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps({"target": "example.test", "headers": ["Cookie: session=fixture"]}),
        encoding="utf-8",
    )
    assert validate_plan(_plan(_probe("auth-ok")), target="example.test", auth_file=str(auth_file))

    foreign = tmp_path / "foreign.json"
    foreign.write_text(
        json.dumps({"target": "other.test", "headers": ["Cookie: session=foreign"]}),
        encoding="utf-8",
    )
    # A foreign file-bound session is cleared and the plan continues anonymous;
    # it must never be rebound to the new target.
    assert validate_plan(_plan(_probe("auth-out")), target="example.test", auth_file=str(foreign))


def test_summary_counts_jsonl_and_retains_partial_semantics(tmp_path) -> None:
    results = tmp_path / "results.jsonl"
    results.write_text(
        "\n".join(
            [
                json.dumps({"id": "a", "status": "edge_passed"}),
                json.dumps(
                    {
                        "id": "b",
                        "status": "blocked",
                        "waf_context": "cloudflare",
                        "analyzer": {"verdict": "blocked"},
                    }
                ),
                "not-json",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    summary = summarize_results(results, target="example.test")
    assert summary["counts"] == {"edge_passed": 1, "blocked": 1}
    assert summary["request_count"] == 2
    assert summary["malformed_result_count"] == 1
    assert summary["status"] == "partial"
    assert summary["waf_contexts"] == ["cloudflare"]
    assert summary["analyzer_verdicts"] == ["blocked"]


def test_cli_rejects_off_scope_plan_before_network_and_without_banner_dependency(tmp_path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(_plan(_probe("off", "https://other.test/admin"))),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["BYPASS_OUT_DIR"] = str(tmp_path / "out")
    result = subprocess.run(
        ["bash", "tools/bypass_403.sh", "--plan", str(plan_path), "--target", "example.test"],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "outside target scope" in result.stderr
    assert "banner.sh" not in result.stderr

    invalid_list = tmp_path / "targets.txt"
    invalid_list.write_text("file:///tmp/not-http\n", encoding="utf-8")
    list_result = subprocess.run(
        ["bash", "tools/bypass_403.sh", "-l", str(invalid_list)],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert list_result.returncode == 2
    assert "outside target scope" in list_result.stderr


def test_byp4xx_compatibility_writes_manual_review_summary(tmp_path) -> None:
    fake_bin = tmp_path / "home" / "go" / "bin"
    fake_bin.mkdir(parents=True)
    fake_byp4xx = fake_bin / "byp4xx"
    fake_byp4xx.write_text("#!/bin/sh\nprintf '%s\\n' 'fixture output'\n", encoding="utf-8")
    fake_byp4xx.chmod(0o755)
    out_dir = tmp_path / "out"
    env = os.environ.copy()
    for key in ("BBHUNT_AUTH_HEADERS", "BBHUNT_SESSION_ID", "BBHUNT_AUTH_TARGET"):
        env.pop(key, None)
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "ALLOW_UNSAFE_HTTP_TESTS": "1",
            "BYPASS_OUT_DIR": str(out_dir),
            "BYP4XX_TIMEOUT": "2",
        }
    )
    result = subprocess.run(
        ["bash", "tools/bypass_403.sh", "https://example.test/admin"],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (out_dir / "byp4xx.txt").read_text(encoding="utf-8").strip() == "fixture output"
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "needs_review"
    assert summary["budget_enforced"] is False
    assert summary["request_count_known"] is False
    metadata = json.loads((out_dir / "byp4xx.meta.json").read_text(encoding="utf-8"))
    assert metadata["tool"] == "byp4xx"
    assert metadata["budget_enforced"] is False
