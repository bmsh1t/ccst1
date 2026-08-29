"""Autopilot Intel continuation 的只读派生状态回归。"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

import intel_engine
import tools.intel_continuation as intel_continuation_module

from tools.action_queue import add_manual_action, resolve_action, save_queue
from tools.intel_artifact import (
    IntelArtifactError,
    load_intel_review_projection,
    query_intel_advisories,
    read_intel_artifact,
    write_intel_artifact,
)
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


def test_unavailable_advisory_coverage_with_queryable_inventory_reopens_intel(tmp_path):
    _prepare_inventory(tmp_path)
    payload = _intel()
    payload["coverage_status"] = "unavailable"
    payload["sources"] = [{
        "source": "nvd",
        "status": "unavailable",
        "stats": {"eligible_queries": 1},
    }]
    _write_intel(tmp_path, payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "run_intel"
    assert "coverage is unavailable" in state["reason"]


def test_network_unavailable_advisory_coverage_handoffs_without_retry(tmp_path):
    _prepare_inventory(tmp_path)
    payload = _intel()
    payload["coverage_status"] = "unavailable"
    payload["sources"] = [{
        "source": "nvd",
        "status": "unavailable",
        "network_unavailable": True,
        "stats": {"eligible_queries": 1},
    }]
    _write_intel(tmp_path, payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "handoff"
    assert state["network_unavailable"] is True
    assert "reuse preserved cache" in state["reason"]


@pytest.mark.parametrize("coverage_status", ["partial", "unavailable", "error"])
def test_degraded_advisory_coverage_without_eligible_queries_cannot_complete(
    tmp_path, coverage_status
):
    _prepare_inventory(tmp_path)
    payload = _intel()
    payload["coverage_status"] = coverage_status
    payload["sources"] = [{
        "source": "nvd",
        "status": coverage_status,
        "stats": {"eligible_queries": 0, "error_count": 1},
    }]
    _write_intel(tmp_path, payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "handoff"
    assert state["blocked"]
    assert coverage_status in state["reason"]


def test_partial_advisory_coverage_with_eligible_queries_requests_refresh(tmp_path):
    _prepare_inventory(tmp_path)
    payload = _intel()
    payload["coverage_status"] = "partial"
    payload["sources"] = [{
        "source": "nvd",
        "status": "partial",
        "stats": {"eligible_queries": 1, "error_count": 1},
    }]
    _write_intel(tmp_path, payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "run_intel"
    assert state["blocked"][0]["source"] == "nvd"


def test_intel_review_sidecar_is_bounded_and_stable(tmp_path, monkeypatch):
    _prepare_inventory(tmp_path)
    advisories = []
    for index in range(5):
        advisory = _advisory()
        advisory["id"] = f"CVE-2026-{63030 + index}"
        advisory["aliases"] = [advisory["id"]]
        advisory["score_hint"] = 100 - index
        advisories.append(advisory)
    other = _advisory()
    other["id"] = "CVE-2026-64000"
    other["aliases"] = [other["id"]]
    other["component"] = {**other["component"], "name": "other", "version": "1.0"}
    advisories.append(other)
    payload = _intel(advisories=advisories)
    _write_intel(tmp_path, payload)

    sidecar = load_intel_review_projection(
        tmp_path / "recon" / "target.test", "target.test"
    )
    assert sidecar["group_count"] == 2
    assert sidecar["advisory_count"] == 6
    givewp = next(group for group in sidecar["groups"] if group["group_key"] == "givewp@4.16.3")
    assert givewp["advisory_count"] == 5
    assert givewp["representative_count"] == 3
    assert givewp["omitted_count"] == 2
    assert len(sidecar["items"]) == 4

    path = tmp_path / "recon" / "target.test" / "intel-review.json"
    first_size = path.stat().st_size
    _write_intel(tmp_path, payload)
    refreshed = load_intel_review_projection(
        tmp_path / "recon" / "target.test", "target.test"
    )
    assert refreshed["groups"] == sidecar["groups"]
    assert refreshed["items"] == sidecar["items"]
    assert path.stat().st_size == first_size

    def fail_full_read(*_args, **_kwargs):
        raise AssertionError("valid sidecar must avoid parsing the full intel owner")

    monkeypatch.setattr(intel_continuation_module, "read_intel_artifact", fail_full_read)
    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert state["action"] == "test_advisory_applicability"


def test_intel_query_is_stable_paged_and_read_only(tmp_path):
    _prepare_inventory(tmp_path)
    advisories = []
    for index in range(5):
        advisory = _advisory()
        advisory["id"] = f"CVE-2026-{63030 + index}"
        advisory["aliases"] = [advisory["id"]]
        advisory["score_hint"] = 100 - index
        advisory["kev"] = index == 0
        advisories.append(advisory)
    not_affected = _advisory()
    not_affected["id"] = "CVE-2026-63999"
    not_affected["aliases"] = [not_affected["id"]]
    not_affected["applicability"] = "not_affected"
    advisories.append(not_affected)
    for index in range(33):
        advisory = _advisory()
        advisory["id"] = f"CVE-2026-{65000 + index}"
        advisory["aliases"] = [advisory["id"]]
        advisory["component"] = {
            **advisory["component"],
            "name": f"component-{index:02d}",
            "version": "1.0",
        }
        advisories.append(advisory)
    _write_intel(tmp_path, _intel(advisories=advisories))
    owner = tmp_path / "recon" / "target.test" / "intel.json"
    sidecar = tmp_path / "recon" / "target.test" / "intel-review.json"
    owner_bytes = owner.read_bytes()
    sidecar_bytes = sidecar.read_bytes()
    projection = load_intel_review_projection(sidecar.parent, "target.test")

    assert projection["total_group_count"] == 34
    assert projection["group_count"] == 32
    assert projection["omitted_group_count"] == 2
    assert len(projection["omitted_groups"]) == 2

    first = query_intel_advisories(owner, component="givewp", version="4.16.3", limit=2)
    second = query_intel_advisories(
        owner,
        component="givewp",
        version="4.16.3",
        limit=2,
        cursor=first["next_cursor"],
    )

    assert first["total_matches"] == 5
    assert [item["id"] for item in first["items"]] == [
        "CVE-2026-63030",
        "CVE-2026-63031",
    ]
    assert [item["id"] for item in second["items"]] == [
        "CVE-2026-63032",
        "CVE-2026-63033",
    ]
    assert set(item["id"] for item in first["items"]).isdisjoint(
        item["id"] for item in second["items"]
    )
    filtered = query_intel_advisories(
        owner,
        host="target.test",
        severity="critical",
        applicability="affected",
        kev=True,
        include_stale=True,
        limit=32,
    )
    assert [item["id"] for item in filtered["items"]] == ["CVE-2026-63030"]
    assert owner.read_bytes() == owner_bytes
    assert sidecar.read_bytes() == sidecar_bytes


def test_intel_query_rejects_stale_cursor_after_owner_refresh(tmp_path):
    _prepare_inventory(tmp_path)
    advisories = [_advisory(), {**_advisory(), "id": "CVE-2026-64000", "aliases": ["CVE-2026-64000"], "score_hint": 1}]
    _write_intel(tmp_path, _intel(advisories=advisories))
    owner = tmp_path / "recon" / "target.test" / "intel.json"
    first = query_intel_advisories(owner, component="givewp", limit=1)
    refreshed = _intel(advisories=advisories + [{**_advisory(), "id": "CVE-2026-65000", "aliases": ["CVE-2026-65000"], "score_hint": 1}])
    _write_intel(tmp_path, refreshed)

    with pytest.raises(IntelArtifactError, match="stale"):
        query_intel_advisories(owner, component="givewp", limit=1, cursor=first["next_cursor"])


def test_coverage_limited_source_keeps_fetched_advisory_fresh(tmp_path):
    _prepare_inventory(tmp_path)
    payload = _intel(advisories=[_advisory()])
    payload["sources"][0].update({
        "status": "partial",
        "items_fresh": True,
        "coverage_gaps": [{
            "source": "nvd",
            "gap_key": "nvd-long-tail:givewp@4.16.3",
            "component": {"name": "givewp", "version": "4.16.3"},
            "query": {"keywordSearch": "GiveWP"},
            "total_results": 401,
            "fetched_results": 200,
            "next_start_index": 200,
            "next_cursor": "CURSOR",
            "owner_binding": {"source": "nvd", "total_results": 401},
        }],
    })
    _write_intel(tmp_path, payload)

    stored = read_intel_artifact(
        tmp_path / "recon" / "target.test" / "intel.json"
    )

    assert stored["advisories"][0].get("stale") is not True


def test_nvd_source_gap_uses_existing_review_continuation(tmp_path):
    _prepare_inventory(tmp_path)
    payload = _intel()
    payload["sources"][0].update({
        "status": "partial",
        "items_fresh": True,
        "coverage_gaps": [{
            "source": "nvd",
            "gap_key": "nvd-long-tail:givewp@unknown",
            "query_mode": "versionless_product",
            "component": {"name": "givewp", "version": ""},
            "query": {"keywordSearch": "GiveWP"},
            "total_results": 401,
            "fetched_results": 200,
            "next_start_index": 200,
            "next_cursor": "CURSOR",
            "reason": "bounded representative page",
            "owner_binding": {"source": "nvd", "total_results": 401},
        }],
    })
    _write_intel(tmp_path, payload)

    sidecar = load_intel_review_projection(
        tmp_path / "recon" / "target.test", "target.test"
    )
    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert sidecar["source_coverage_gaps"][0]["next_cursor"] == "CURSOR"
    assert state["action"] == "review_intel_group"
    assert state["review_group"]["group_key"] == "nvd-long-tail:givewp@unknown"
    assert "tools/intel_sources.py nvd-page" in state["review_group"]["query_command"]
    assert "--cursor CURSOR" in state["review_group"]["query_command"]


def test_deferred_initial_nvd_query_continuation_has_no_empty_cursor(tmp_path):
    _prepare_inventory(tmp_path)
    payload = _intel()
    payload["sources"][0].update({
        "status": "partial",
        "coverage_gaps": [{
            "source": "nvd",
            "gap_key": "nvd-deferred:givewp@4.16.3",
            "query_mode": "versioned_keyword_fallback",
            "component": {"name": "givewp", "version": "4.16.3"},
            "query": {"keywordSearch": "GiveWP"},
            "initial_query_pending": True,
            "reason": "component limit",
        }],
    })
    _write_intel(tmp_path, payload)

    sidecar = load_intel_review_projection(
        tmp_path / "recon" / "target.test", "target.test"
    )
    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert sidecar["source_coverage_gaps"][0]["initial_query_pending"] is True
    assert state["action"] == "review_intel_group"
    command = state["review_group"]["query_command"]
    assert "tools/intel_sources.py nvd-page" in command
    assert "--cursor" not in command


def test_omitted_intel_group_requires_review_then_closes_by_queue(tmp_path):
    _prepare_inventory(tmp_path)
    advisories = []
    for index in range(5):
        advisory = _advisory()
        advisory["id"] = f"CVE-2026-{63030 + index}"
        advisory["aliases"] = [advisory["id"]]
        advisory["score_hint"] = 100 - index
        advisories.append(advisory)
    _write_intel(tmp_path, _intel(advisories=advisories))

    initial = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert initial["action"] == "test_advisory_applicability"
    sidecar = load_intel_review_projection(tmp_path / "recon" / "target.test", "target.test")
    representatives = sidecar["groups"][0]["representatives"]
    for advisory in representatives:
        added = add_manual_action(
            tmp_path,
            target="target.test",
            action_type="intel-advisory",
            evidence=f"{advisory['id']} reviewed against GiveWP 4.16.3",
            next_question="Is the advisory route reachable?",
            action=f"Review {advisory['id']}",
            metadata={
                "advisory_id": advisory["id"],
                "component": "givewp",
                "version": "4.16.3",
            },
        )
        action_id = next(
            item["id"]
            for item in added["queue"]["actions"]
            if (item.get("metadata") or {}).get("advisory_id") == advisory["id"]
        )
        resolve_action(
            tmp_path,
            target="target.test",
            action_id=action_id,
            status="tested",
            result=f"{advisory['id']} route not reachable",
        )

    group_state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)
    assert group_state["action"] == "review_intel_group"
    group = group_state["review_group"]
    assert group["group_key"] == "givewp@4.16.3"
    assert group["omitted_count"] == 2
    assert "intel_artifact.py query" in group["query_command"]

    added = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="GiveWP group long-tail reviewed; no reachable advisory route",
        next_question="Does the group need reactivation after a new owner refresh?",
        action="Review omitted GiveWP Intel group",
        metadata=group["queue_metadata"],
    )
    group_action_id = next(
        item["id"]
        for item in added["queue"]["actions"]
        if (item.get("metadata") or {}).get("intel_group_key") == group["group_key"]
    )
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=group_action_id,
        status="tested",
        result="GiveWP group reviewed with no reachable advisory route",
    )
    assert inspect_intel_continuation(tmp_path, "target.test", now=NOW)["action"] == "complete"

    refreshed = _intel(advisories=advisories + [{
        **_advisory(),
        "id": "CVE-2026-65000",
        "aliases": ["CVE-2026-65000"],
        "score_hint": 1,
    }])
    _write_intel(tmp_path, refreshed)
    assert inspect_intel_continuation(tmp_path, "target.test", now=NOW)["action"] == "review_intel_group"


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


def test_not_affected_advisory_spelling_does_not_reopen_applicability(tmp_path):
    _prepare_inventory(tmp_path)
    advisory = _advisory()
    advisory["applicability"] = "not affected"
    _write_intel(tmp_path, _intel(advisories=[advisory]))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "complete"


def test_stale_advisory_is_one_refresh_handoff(tmp_path):
    _prepare_inventory(tmp_path)
    advisory = _advisory()
    advisory["stale"] = True
    _write_intel(tmp_path, _intel(advisories=[advisory]))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "run_intel"
    assert "stale advisory" in state["reason"]
    assert state["blocked"][0]["id"] == "CVE-2026-63030"


def test_degraded_advisory_source_is_one_refresh_handoff(tmp_path):
    _prepare_inventory(tmp_path)
    advisory = _advisory()
    advisory["source_names"] = ["nvd"]
    payload = _intel(advisories=[advisory])
    payload["sources"][0]["status"] = "partial"
    _write_intel(tmp_path, payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "run_intel"
    assert state["blocked"][0]["id"] == "CVE-2026-63030"


def test_degraded_singular_advisory_source_is_one_refresh_handoff(tmp_path):
    _prepare_inventory(tmp_path)
    advisory = _advisory()
    advisory.pop("source_refs")
    advisory["source"] = "nvd"
    payload = _intel(advisories=[advisory])
    payload["sources"][0]["status"] = "partial"
    _write_intel(tmp_path, payload)

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "run_intel"
    assert state["blocked"][0]["id"] == "CVE-2026-63030"


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


def test_empty_version_web_intel_subject_does_not_repeat_collection(tmp_path):
    _prepare_inventory(tmp_path)
    record_web_intel(tmp_path, "target.test", {
        "target": "target.test",
        "subject": "cloudwaf@",
        "intent": "component_advisory",
        "query": "CloudWAF vulnerability advisory",
        "provider": "unavailable-provider",
        "status": "blocked",
        "results": [],
    }, now=NOW)
    projection = load_web_intel_projection(tmp_path, "target.test", now=NOW)
    gaps = intel_engine._web_intel_gap_projection(
        [{"name": "cloudwaf", "kind": "network_service"}],
        [{"source": "nvd", "status": "ok"}],
        [],
        projection,
    )
    web_intel = {
        field: projection[field]
        for field in ("status", "fingerprint", "covered_subjects", "blocked_subjects")
    }
    _write_intel(tmp_path, _intel(gaps=gaps, web_intel=web_intel))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "complete"
    assert state["blocked"][0]["subject"] == "cloudwaf"


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


def test_unrelated_final_action_does_not_close_advisory(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(advisories=[_advisory()]))
    added = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="validation",
        evidence="CVE-2026-63030 reviewed against GiveWP 4.16.3",
        next_question="Does an unrelated validation close Intel?",
        action="Validate another hypothesis",
    )
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=added["queue"]["actions"][0]["id"],
        status="tested",
        result="Unrelated validation completed",
    )

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "test_advisory_applicability"


def test_legacy_disposition_uses_exact_version_boundary(tmp_path):
    _prepare_inventory(tmp_path)
    advisory = _advisory()
    advisory["component"]["version"] = "1.2"
    _write_intel(tmp_path, _intel(advisories=[advisory]))
    added = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="CVE-2026-63030 reviewed against GiveWP 1.20",
        next_question="Is the other version reachable?",
        action="Test CVE-2026-63030 applicability on GiveWP 1.20",
    )
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=added["queue"]["actions"][0]["id"],
        status="tested",
        result="GiveWP 1.20 route not reachable",
    )

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "test_advisory_applicability"
    assert state["advisory"]["component"]["version"] == "1.2"


def test_exact_advisory_metadata_closes_without_legacy_text_binding(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(advisories=[_advisory()]))
    added = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="Structured advisory review",
        next_question="Is the exact bound advisory resolved?",
        action="Record the bound advisory result",
    )
    action = added["queue"]["actions"][0]
    action["metadata"] = {
        "advisory_id": "CVE-2026-63030",
        "component": "givewp",
        "version": "4.16.3",
    }
    save_queue(tmp_path, "target.test", added["queue"])
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=action["id"],
        status="tested",
        result="Bound advisory route not reachable",
    )

    assert inspect_intel_continuation(tmp_path, "target.test", now=NOW)["action"] == "complete"


def test_mismatched_advisory_metadata_does_not_fall_back_to_matching_text(tmp_path):
    _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel(advisories=[_advisory()]))
    added = add_manual_action(
        tmp_path,
        target="target.test",
        action_type="intel-advisory",
        evidence="CVE-2026-63030 reviewed against GiveWP 4.16.3",
        next_question="Does stale metadata override matching legacy text?",
        action="Test CVE-2026-63030 applicability on GiveWP 4.16.3",
    )
    action = added["queue"]["actions"][0]
    action["metadata"] = {
        "advisory_id": "CVE-2026-63030",
        "component": "givewp",
        "version": "4.16.2",
    }
    save_queue(tmp_path, "target.test", added["queue"])
    resolve_action(
        tmp_path,
        target="target.test",
        action_id=action["id"],
        status="tested",
        result="Legacy text matches, structured version does not",
    )

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "test_advisory_applicability"


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


def test_same_size_source_replacement_with_restored_mtime_reopens_intel(tmp_path):
    _recon, raw, _inventory = _prepare_inventory(tmp_path)
    _write_intel(tmp_path, _intel())
    original = raw.stat()
    original_bytes = raw.read_bytes()
    replacement = original_bytes.replace(b"4.16.3", b"4.16.4")
    assert len(replacement) == len(original_bytes)
    raw.write_bytes(replacement)
    os.utime(raw, ns=(original.st_atime_ns, original.st_mtime_ns))

    state = inspect_intel_continuation(tmp_path, "target.test", now=NOW)

    assert state["action"] == "run_intel"
    assert "binding changed" in state["reason"]


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


def test_continuation_preempts_handoff_but_preserves_surface_priority():
    continuation = {"action": "run_intel"}
    assert apply_intel_continuation("hunt_p1", continuation) == "hunt_p1"
    assert apply_intel_continuation("hunt_p2", continuation) == "hunt_p2"
    assert apply_intel_continuation("continue_last_focus", continuation) == "run_intel"
    assert apply_intel_continuation("resume_untested", continuation) == "run_intel"
    assert apply_intel_continuation("handoff", continuation) == "run_intel"
    assert apply_intel_continuation("validate_finding", continuation) == "validate_finding"
    assert apply_intel_continuation("prepare_surface_context", continuation) == "prepare_surface_context"
