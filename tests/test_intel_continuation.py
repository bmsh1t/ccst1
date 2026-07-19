"""Autopilot Intel continuation 的只读派生状态回归。"""

import json
import os
from datetime import datetime, timedelta, timezone

from tools.action_queue import add_manual_action, resolve_action
from tools.intel_artifact import write_intel_artifact
from tools.intel_continuation import apply_intel_continuation, inspect_intel_continuation
from tools.technology_inventory import load_or_build_inventory
from tools.web_intel_artifact import load_web_intel_projection, record_web_intel


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _prepare_inventory(tmp_path):
    recon = tmp_path / "recon" / "target.test"
    live = recon / "live"
    live.mkdir(parents=True)
    raw = live / "httpx_full.txt"
    raw.write_text(
        "https://target.test [200] [100] [Target] [GiveWP:4.16.3]\n",
        encoding="utf-8",
    )
    load_or_build_inventory(tmp_path, "target.test")
    inventory = live / "technology_inventory.json"
    return recon, raw, inventory


def _intel(*, gaps=None, advisories=None, web_intel=None):
    advisories = advisories or []
    return {
        "schema_version": 2,
        "target": "target.test",
        "generated_at": "2026-07-19T12:00:00Z",
        "coverage_status": "ready",
        "inventory": {
            "status": "ready",
            "fingerprint": "",
            "components": [{"name": "givewp", "version": "4.16.3"}],
        },
        "sources": [{
            "source": "nvd",
            "status": "ok",
            "fetched_at": "2026-07-19T12:00:00Z",
            "cached": False,
            "error": "",
        }],
        "advisories": advisories,
        "critical": advisories,
        "high": [],
        "info": [],
        "intel_gaps": gaps or {
            "web_search_recommended": False,
            "recommended": [],
        },
        "web_intel": web_intel or {},
        "stats": {
            "component_count": 1,
            "advisory_count": len(advisories),
        },
    }


def _advisory():
    return {
        "id": "CVE-2026-63030",
        "aliases": ["CVE-2026-63030"],
        "component": {
            "name": "givewp",
            "version": "4.16.3",
            "hosts": ["target.test"],
            "ports": [443],
        },
        "applicability": "affected",
        "severity": "CRITICAL",
        "score_hint": 100,
        "source_refs": [{"source": "nvd", "url": "https://nvd.test/CVE-2026-63030"}],
    }


def _write_intel(tmp_path, payload):
    inventory = tmp_path / "recon" / "target.test" / "live" / "technology_inventory.json"
    payload["inventory"]["fingerprint"] = json.loads(
        inventory.read_text(encoding="utf-8")
    )["fingerprint"]
    return write_intel_artifact(tmp_path, "target.test", payload)


def test_inventory_without_intel_triggers_run_intel(tmp_path):
    _prepare_inventory(tmp_path)
    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "run_intel"
    assert "has not processed" in state["reason"]


def test_official_gap_triggers_web_intel(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(gaps={
        "web_search_recommended": True,
        "recommended": [{
            "subject": "givewp@4.16.3",
            "intent": "component_advisory",
            "query": "GiveWP 4.16.3 vulnerability advisory",
        }],
    }))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "collect_web_intel"
    assert state["recommended"][0]["subject"] == "givewp@4.16.3"


def test_newer_web_index_requires_intel_remerge(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel())
    index = tmp_path / "evidence" / "target.test" / "web-intel" / "index.json"
    index.parent.mkdir(parents=True)
    index.write_text("{}", encoding="utf-8")

    assert inspect_intel_continuation(tmp_path, "target.test", now=NOW)["action"] == "run_intel"


def test_inventory_fingerprint_mismatch_requires_intel_rebuild(tmp_path):
    _prepare_inventory(tmp_path)
    payload = _intel()
    payload["inventory"]["fingerprint"] = "b" * 64
    write_intel_artifact(tmp_path, "target.test", payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "run_intel"
    assert "different software/service inventory" in state["reason"]


def test_malformed_score_hint_does_not_break_advisory_selection(tmp_path):
    _prepare_inventory(tmp_path)
    advisory = _advisory()
    advisory["score_hint"] = "not-a-number"
    _write_intel(tmp_path, _intel(advisories=[advisory]))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "test_advisory_applicability"
    assert state["advisory"]["id"] == "CVE-2026-63030"


def test_blocked_web_intel_is_handoff_context_not_a_repeat_loop(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(gaps={
        "web_search_recommended": False,
        "recommended": [],
        "blocked": [{
            "subject": "givewp@4.16.3",
            "component": "givewp",
            "version": "4.16.3",
            "reason": "an unexpired Web Intel query is blocked or failed",
        }],
    }))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "complete"
    assert state["blocked"][0]["subject"] == "givewp@4.16.3"
    assert "continue other lanes" in state["reason"]


def test_high_value_advisory_triggers_applicability_and_final_queue_closes_it(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(advisories=[_advisory()]))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "test_advisory_applicability"
    assert state["advisory"]["id"] == "CVE-2026-63030"

    added = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="CVE-2026-63030 applies to observed GiveWP 4.16.3",
        next_question="Is the vulnerable route reachable?",
        action="Test CVE-2026-63030 applicability",
    )
    action_id = added["queue"]["actions"][0]["id"]
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=action_id,
        status="tested",
        result="CVE-2026-63030 route not reachable",
    )
    assert inspect_intel_continuation(tmp_path, "target.test", now=NOW)["action"] == "complete"


def test_high_value_advisory_preempts_web_intel_gap(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(
        advisories=[_advisory()],
        gaps={
            "web_search_recommended": True,
            "recommended": [{
                "subject": "other-plugin@1.0",
                "component": "other-plugin",
                "version": "1.0",
                "query": "other-plugin 1.0 vulnerability advisory",
            }],
            "blocked": [],
        },
    ))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "test_advisory_applicability"
    assert state["advisory"]["id"] == "CVE-2026-63030"


def test_critical_advisory_precedes_higher_score_high_advisory(tmp_path):
    _prepare_inventory(tmp_path)
    critical = _advisory()
    critical["id"] = "CVE-2026-11111"
    critical["aliases"] = ["CVE-2026-11111"]
    critical["severity"] = "CRITICAL"
    critical["score_hint"] = 50
    high = _advisory()
    high["id"] = "CVE-2026-22222"
    high["aliases"] = ["CVE-2026-22222"]
    high["severity"] = "HIGH"
    high["score_hint"] = 100
    _write_intel(tmp_path, _intel(advisories=[high, critical]))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "test_advisory_applicability"
    assert state["advisory"]["id"] == "CVE-2026-11111"


def test_final_disposition_for_old_component_version_does_not_close_new_version(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(advisories=[_advisory()]))
    added = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="CVE-2026-63030 reviewed against GiveWP 4.16.2",
        next_question="Is the old version reachable?",
        action="Test CVE-2026-63030 applicability on GiveWP 4.16.2",
    )
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=added["queue"]["actions"][0]["id"],
        status="tested",
        result="GiveWP 4.16.2 route not reachable",
    )

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "test_advisory_applicability"
    assert state["advisory"]["component"]["version"] == "4.16.3"


def test_unknown_version_requires_explicit_unknown_version_disposition(tmp_path):
    _prepare_inventory(tmp_path)
    advisory = _advisory()
    advisory["component"]["version"] = ""
    _write_intel(tmp_path, _intel(advisories=[advisory]))

    unrelated = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="CVE-2026-63030 reviewed for GiveWP",
        next_question="Is the component version known?",
        action="Review CVE-2026-63030",
    )
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=unrelated["queue"]["actions"][0]["id"],
        status="tested",
        result="No version evidence captured",
    )
    assert inspect_intel_continuation(tmp_path, "target.test", now=NOW)["action"] == (
        "test_advisory_applicability"
    )

    explicit = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="CVE-2026-63030 reviewed for GiveWP version unknown",
        next_question="Can reachability still be tested conservatively?",
        action="Test CVE-2026-63030 with GiveWP version unknown",
    )
    explicit_id = next(
        item["id"]
        for item in explicit["queue"]["actions"]
        if "version unknown" in item["evidence"]
    )
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=explicit_id,
        status="tested",
        result="GiveWP version unknown; vulnerable route not exposed",
    )
    assert inspect_intel_continuation(tmp_path, "target.test", now=NOW)["action"] == "complete"


def test_unbound_compatibility_raw_file_does_not_reopen_intel(tmp_path):
    recon = tmp_path / "recon" / "target.test"
    live = recon / "live"
    live.mkdir(parents=True)
    compatibility = live / "httpx_full.jsonl"
    compatibility.write_text("not-json\n", encoding="utf-8")
    (live / "httpx_full.txt").write_text(
        "https://target.test [200] [100] [Target] [GiveWP:4.16.3]\n",
        encoding="utf-8",
    )
    load_or_build_inventory(tmp_path, "target.test")
    _write_intel(tmp_path, _intel())
    future = NOW.timestamp() + 60
    os.utime(compatibility, (future, future))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "complete"


def test_bound_inventory_source_change_or_removal_reopens_intel(tmp_path):
    _recon, raw, inventory = _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel())
    newer = inventory.stat().st_mtime + 1
    os.utime(raw, (newer, newer))

    changed = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert changed["action"] == "run_intel"
    assert "observations are newer" in changed["reason"]

    raw.unlink()
    missing = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert missing["action"] == "run_intel"
    assert "source is missing" in missing["reason"]


def test_expired_intel_reopens_refresh(tmp_path):
    _prepare_inventory(tmp_path)
    old = NOW - timedelta(days=1)
    record_web_intel(tmp_path, "target.test", {
        "target": "target.test",
        "subject": "givewp@4.16.3",
        "intent": "component_advisory",
        "query": "GiveWP 4.16.3 vulnerability advisory",
        "provider": "test-provider",
        "status": "ok",
        "ttl_hours": 1,
        "results": [],
    }, now=old)
    projection = load_web_intel_projection(tmp_path, "target.test", now=old)
    payload = _intel(web_intel={
        "status": projection["status"],
        "fingerprint": projection["fingerprint"],
        "covered_subjects": projection["covered_subjects"],
        "blocked_subjects": projection["blocked_subjects"],
    })
    payload["generated_at"] = old.strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_intel(tmp_path, payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "run_intel"
    assert "refresh TTL" in state["reason"]


def test_expired_web_query_reopens_intel_merge(tmp_path):
    _prepare_inventory(tmp_path)
    old = NOW - timedelta(hours=2)
    record_web_intel(tmp_path, "target.test", {
        "target": "target.test",
        "subject": "givewp@4.16.3",
        "intent": "component_advisory",
        "query": "GiveWP 4.16.3 vulnerability advisory",
        "provider": "test-provider",
        "status": "ok",
        "ttl_hours": 1,
        "results": [],
    }, now=old)
    projection = load_web_intel_projection(tmp_path, "target.test", now=old)
    _write_intel(tmp_path, _intel(web_intel={
        "status": projection["status"],
        "fingerprint": projection["fingerprint"],
        "covered_subjects": projection["covered_subjects"],
        "blocked_subjects": projection["blocked_subjects"],
    }))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "run_intel"
    assert "Web Intel TTL/status changed" in state["reason"]


def test_continuation_only_preempts_generic_actions():
    continuation = {"action": "run_intel"}
    assert apply_intel_continuation("hunt_p1", continuation) == "run_intel"
    assert apply_intel_continuation("handoff", continuation) == "run_intel"
    assert apply_intel_continuation("validate_finding", continuation) == "validate_finding"
    assert apply_intel_continuation("prepare_surface_context", continuation) == "prepare_surface_context"
