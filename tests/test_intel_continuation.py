"""Intel residuals consume explicit Store dispositions without changing history."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from tools.action_queue import add_manual_action, claim_next_action, load_queue, resolve_action
from tools.intel_artifact import IntelArtifactError, query_intel_advisories, write_intel_artifact
from tools.intel_continuation import INTEL_REFRESH_TTL_SECONDS, inspect_intel_continuation
from tools.target_store import TargetStore
from tools.technology_inventory import load_or_build_inventory


NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
CVE = "CVE-2026-12345"
ALIAS = "GHSA-2345-6789-abcd"
BINDING = {"advisory_id": CVE, "component": {"name": "nginx", "version": "1.2"}}


def _intel(tmp_path, *, version="1.2", count=1):
    store = TargetStore(tmp_path, "intel.test")
    store.initialize()
    raw = tmp_path / "recon" / store.target / "live" / "httpx.jsonl"
    raw.parent.mkdir(parents=True)
    raw.write_text(json.dumps({"url": "https://intel.test", "tech": [f"nginx:{version}" if version else "nginx"]}) + "\n")
    inventory = load_or_build_inventory(tmp_path, store.target)
    payload = {
        "schema_version": 2, "target": store.target, "generated_at": NOW.isoformat(),
        "coverage_status": "ready", "inventory": inventory,
        "stats": {"component_count": 1},
        "sources": [{"source": "osv", "status": "ok", "stats": {"eligible_queries": 1}}],
        "advisories": [
            {"id": f"CVE-2026-{12345 + index}", "aliases": [ALIAS] if index == 0 else [],
             "component": {"name": "nginx", "version": version}, "applicability": "unknown"}
            for index in range(count)
        ],
        "critical": [], "high": [], "info": [],
    }
    write_intel_artifact(tmp_path, store.target, payload)
    return store, payload


def _action(store, metadata=None, *, status="blocked", action_id="review", prose_field="action", action_type="intel-advisory"):
    prose = f"Reviewed {CVE} nginx 1.2 nginx@unknown"
    text = {"action": "Review advisory", "evidence": "Recorded material", "result": "Review deferred", "notes": ""}
    if prose_field is not None:
        text[prose_field] = prose
    add_manual_action(
        store.root, target=store.target, action_id=action_id, action_type=action_type,
        action=text["action"], evidence=text["evidence"], next_question="Applicable?", metadata=metadata,
    )
    if status in {"claimed", "completed"}:
        claim_next_action(store.root, store.target, action_id=action_id)
    if status not in {"ready", "claimed"}:
        if status == "completed":
            proof = store.root / "evidence" / store.target / f"{action_id}.txt"
            proof.parent.mkdir(parents=True, exist_ok=True)
            proof.write_text("Reviewed advisory material\n")
            text["result"] += f" artifact={proof.relative_to(store.root)}"
        resolve_action(
            store.root, target=store.target, action_id=action_id,
            status={"completed": "tested", "cancelled": "n/a"}.get(status, status),
            result=text["result"], notes=text["notes"],
        )
    assert store.action(action_id)["status"] == status


def _inspect(store, *, now=NOW):
    # Compare logical domain/history rows, not SQLite WAL/SHM bookkeeping bytes.
    def history():
        with sqlite3.connect(f"file:{store.path}?mode=ro", uri=True) as conn:
            return tuple(conn.iterdump())

    before = store.binding(), load_queue(store.root, store.target), history()
    result = inspect_intel_continuation(store.root, store.target, now=now)
    assert (store.binding(), load_queue(store.root, store.target), history()) == before
    assert not (store.path.parent / "action_queue.json").exists()
    return result


@pytest.mark.parametrize("field", ["action", "evidence", "result", "notes", "metadata"])
def test_prose_only_dispositions_do_not_hide_advisories(tmp_path, field):
    store, _ = _intel(tmp_path)
    metadata = {"review": f"{CVE} nginx 1.2"} if field == "metadata" else None
    _action(store, metadata, prose_field=None if field == "metadata" else field)
    result = _inspect(store)
    assert result["action"] == "test_advisory_applicability"
    assert result["advisory"]["id"] == CVE


@pytest.mark.parametrize("status", ["blocked", "completed", "cancelled", "ready", "claimed"])
def test_only_terminal_structured_actions_suppress_advisories(tmp_path, status):
    store, _ = _intel(tmp_path)
    _action(store, BINDING, status=status)
    assert _inspect(store)["action"] == (
        "test_advisory_applicability" if status in {"ready", "claimed"} else "complete"
    )


@pytest.mark.parametrize("metadata,version,closed", [
    ({"advisory_id": ALIAS, "component": {"name": "nginx", "version": "1.2"}}, "1.2", True),
    ({"advisory_id": f" {CVE.lower()} ", "component_name": " NGINX ", "version": " 1.2 "}, "1.2", True),
    ({"advisory_id": CVE, "component": "nginx", "component_version": "1.2"}, "1.2", True),
    ({"advisory_id": CVE, "component": {"display_name": "nginx"}, "version": "1.2"}, "1.2", True),
    ({"advisory_id": CVE, "component_name": "nginx", "component_version": "1.2"}, "1.2", True),
    ({**BINDING, "advisory_id": "CVE-2026-99999"}, "1.2", False),
    ({**BINDING, "advisory_id": f"Reviewed {CVE}"}, "1.2", False),
    ({"advisory_id": CVE, "component": {"name": "other", "version": "1.2"}}, "1.2", False),
    (BINDING, "1.20", False),
    ({"component": BINDING["component"]}, "1.2", False),
    ({"advisory_id": CVE}, "1.2", False),
    ({"advisory_id": CVE, "component": {"version": "1.2"}}, "1.2", False),
    ({"advisory_id": CVE, "component": {"name": "nginx"}}, "1.2", False),
    ({"advisory_id": CVE, "component": {"name": "nginx", "version": ""}}, "", True),
    ({"advisory_id": CVE, "component_name": "nginx", "component_version": ""}, "", True),
    ({"advisory_id": CVE, "component": {"name": "nginx"}}, "", False),
    ({"advisory_id": CVE, "component_name": "nginx"}, "", False),
    ({"advisory_id": CVE, "component": {"name": "nginx", "version": "unknown"}}, "", False),
    ({"advisory_id": CVE, "component": {"name": "nginx", "version": ""}}, "1.2", False),
    (BINDING, "", False),
    ({}, "", False),
])
def test_binding_requires_exact_identity_and_explicit_version(tmp_path, metadata, version, closed):
    store, _ = _intel(tmp_path, version=version)
    _action(store, metadata)
    assert _inspect(store)["action"] == ("complete" if closed else "test_advisory_applicability")


def test_other_action_type_and_other_cve_in_prose_cannot_close_candidate(tmp_path):
    store, _ = _intel(tmp_path, count=2)
    _action(store, {**BINDING, "advisory_id": "CVE-2026-12346"})
    _action(store, BINDING, action_id="source", action_type="source-review")
    assert _inspect(store)["advisory"]["id"] == CVE


@pytest.mark.parametrize("sidecar", [True, False])
def test_explicit_binding_on_resolve_works_with_sidecar_or_raw_owner(tmp_path, sidecar):
    store, _ = _intel(tmp_path)
    if not sidecar:
        (tmp_path / "recon" / store.target / "intel-review.json").unlink()
    _action(store, status="ready")
    assert _inspect(store)["action"] == "test_advisory_applicability"
    resolve_action(store.root, target=store.target, action_id="review", status="blocked",
                   result="Review deferred", metadata=BINDING)
    assert _inspect(store)["action"] == "complete"


def test_long_tail_group_binding_and_query_cursor_expire_on_refresh(tmp_path):
    store, payload = _intel(tmp_path, count=5)
    for advisory in payload["advisories"][:3]:
        _action(store, {**BINDING, "advisory_id": advisory["id"]}, action_id=advisory["id"])
    result = _inspect(store)
    assert result["action"] == "review_intel_group"
    group = result["review_group"]
    assert (group["advisory_count"], group["representative_count"], group["omitted_count"]) == (5, 3, 2)
    assert "--component nginx --version 1.2" in group["query_command"]
    path = tmp_path / "recon" / store.target / "intel.json"
    page = query_intel_advisories(path, component="nginx", version="1.2", limit=3)
    tail = query_intel_advisories(path, component="nginx", version="1.2", cursor=page["next_cursor"], limit=3)
    assert [item["id"] for item in tail["items"]] == [item["id"] for item in payload["advisories"][3:]]
    assert not tail["has_more"]
    metadata = group["queue_metadata"]
    for index, wrong in enumerate((
        {"intel_group_key": metadata["intel_group_key"]},
        {**metadata, "intel_group_key": "other@1.2"},
        {**metadata, "intel_owner_binding": {}},
    )):
        _action(store, wrong, action_id=f"wrong-group-{index}")
        assert _inspect(store)["action"] == "review_intel_group"
    _action(store, metadata, action_id="group")
    assert _inspect(store)["action"] == "complete"
    payload["generated_at"] = (NOW + timedelta(seconds=1)).isoformat()
    write_intel_artifact(tmp_path, store.target, payload)
    assert _inspect(store)["action"] == "review_intel_group"
    with pytest.raises(IntelArtifactError, match="cursor"):
        query_intel_advisories(path, component="nginx", version="1.2", cursor=page["next_cursor"])


def test_nvd_tail_retains_query_cursor_and_source_failure_after_group_disposition(tmp_path):
    store, payload = _intel(tmp_path, version="")
    payload["advisories"] = []
    payload["coverage_status"] = "partial"
    payload["sources"] = [{"source": "nvd", "status": "partial", "stats": {"eligible_queries": 1},
                           "coverage_gaps": [{"gap_key": "nvd:nginx", "component": {"name": "nginx", "version": ""},
                                              "query": {"keywordSearch": "nginx server"}, "next_cursor": "source-cursor",
                                              "total_results": 20, "fetched_results": 8, "owner_binding": {"total": 20}}]}]
    write_intel_artifact(tmp_path, store.target, payload)
    result = _inspect(store)
    assert result["action"] == "review_intel_group"
    group = result["review_group"]
    assert group["omitted_count"] == 12
    assert group["query_command"] == "python3 tools/intel_sources.py nvd-page --component nginx --keyword 'nginx server' --cursor source-cursor --limit 8"
    assert group["queue_metadata"]["intel_source_owner_binding"] == {"total": 20}
    _action(store, group["queue_metadata"])
    result = _inspect(store)
    assert result["action"] == "run_intel"
    assert result["blocked"][0]["status"] == "partial"


@pytest.mark.parametrize("coverage,source,eligible,offline,expected", [
    ("partial", "partial", 1, False, "run_intel"),
    ("partial", "partial", 0, False, "handoff"),
    ("unavailable", "unavailable", 1, True, "handoff"),
    ("error", "error", 1, False, "run_intel"),
])
def test_source_health_is_not_closed_by_advisory_disposition(tmp_path, coverage, source, eligible, offline, expected):
    store, payload = _intel(tmp_path)
    _action(store, BINDING)
    payload["coverage_status"] = coverage
    payload["sources"] = [{"source": "osv", "status": source, "network_unavailable": offline,
                           "stats": {"eligible_queries": eligible, "error_count": 1}}]
    write_intel_artifact(tmp_path, store.target, payload)
    result = _inspect(store)
    assert result["action"] == expected
    if offline:
        assert result["network_unavailable"] is True
    assert _inspect(store, now=NOW + timedelta(seconds=INTEL_REFRESH_TTL_SECONDS + 1))["action"] == "run_intel"


@pytest.mark.parametrize("metadata,expected", [(None, "run_intel"), (BINDING, "complete")])
def test_stale_advisory_also_requires_structured_disposition(tmp_path, metadata, expected):
    store, payload = _intel(tmp_path)
    payload["advisories"][0]["stale"] = True
    write_intel_artifact(tmp_path, store.target, payload)
    _action(store, metadata)
    assert _inspect(store)["action"] == expected
