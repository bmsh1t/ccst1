"""Provider-neutral Web Intel artifact 与 Intel source 投影回归。"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from tools.web_intel_artifact import (
    WebIntelArtifactError,
    build_web_intel_source,
    load_web_intel_projection,
    record_web_intel,
)


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _payload(*, body_verified=True, version="4.16.3", group="vendor-advisory"):
    return {
        "target": "target.test",
        "subject": "givewp@4.16.3",
        "intent": "component_advisory",
        "query": '"GiveWP" "4.16.3" vulnerability advisory',
        "provider": "grok-search",
        "status": "ok",
        "results": [{
            "url": "https://vendor.test/security/advisory-1",
            "title": "GiveWP advisory",
            "source_tier": "A",
            "independent_source_group": group,
            "body_verified": body_verified,
            "claims": [{
                "identifiers": ["CVE-2026-63030"],
                "component": {
                    "name": "givewp",
                    "display_name": "GiveWP",
                    "version": version,
                },
                "applicability": "affected",
                "severity": "critical",
                "summary": "Verified vendor advisory",
                "fixed_versions": ["4.16.4"],
            }],
        }],
    }


def _components():
    return [{
        "name": "givewp",
        "display_name": "GiveWP",
        "version": "4.16.3",
        "host": "target.test",
        "url": "https://target.test",
        "kind": "web_component",
    }]


def test_verified_body_is_indexed_and_unverified_snippet_is_not(tmp_path):
    path, index = record_web_intel(tmp_path, "target.test", _payload(), now=NOW)
    assert path.is_file()
    assert index["stats"]["verified_claim_count"] == 1

    unverified = _payload(body_verified=False)
    unverified["query"] += " snippet-only"
    record_web_intel(tmp_path, "target.test", unverified, now=NOW)
    projection = load_web_intel_projection(tmp_path, "target.test", now=NOW)

    assert projection["status"] == "ready"
    assert len(projection["entries"]) == 2
    assert len(projection["verified_claims"]) == 1
    source = build_web_intel_source(projection, _components())
    assert source["status"] == "ok"
    assert source["items"][0]["id"] == "CVE-2026-63030"
    assert source["items"][0]["applicability"] == "affected"
    assert source["items"][0]["source_refs"][0]["body_verified"] is True


def test_same_independent_group_is_deduped_across_republished_results(tmp_path):
    payload = _payload()
    payload["results"].append({
        **payload["results"][0],
        "url": "https://news.test/reposted-advisory",
        "source_tier": "C",
    })
    record_web_intel(tmp_path, "target.test", payload, now=NOW)
    second = _payload()
    second["query"] += " vendor copy"
    second["provider"] = "smart-search"
    record_web_intel(tmp_path, "target.test", second, now=NOW)
    projection = load_web_intel_projection(tmp_path, "target.test", now=NOW)

    assert len(projection["verified_claims"]) == 1
    source = build_web_intel_source(projection, _components())
    assert len(source["items"]) == 1


def test_blocked_query_is_not_clean_and_does_not_repeat_within_ttl(tmp_path):
    payload = _payload()
    payload["status"] = "blocked"
    payload["error"] = "provider unavailable"
    payload["results"] = []
    record_web_intel(tmp_path, "target.test", payload, now=NOW)

    projection = load_web_intel_projection(tmp_path, "target.test", now=NOW)
    source = build_web_intel_source(projection, _components())

    assert projection["status"] == "blocked"
    assert projection["covered_subjects"] == []
    assert projection["blocked_subjects"] == ["givewp@4.16.3"]
    assert source["status"] == "unavailable"
    assert source["items"] == []
    assert "provider unavailable" in source["error"]


def test_version_mismatch_downgrades_web_claim_to_unknown(tmp_path):
    record_web_intel(tmp_path, "target.test", _payload(version="4.16.2"), now=NOW)
    projection = load_web_intel_projection(tmp_path, "target.test", now=NOW)
    source = build_web_intel_source(projection, _components())

    assert source["items"][0]["applicability"] == "unknown"


def test_expired_query_is_stale_and_not_merged(tmp_path):
    payload = _payload()
    payload["ttl_hours"] = 1
    record_web_intel(tmp_path, "target.test", payload, now=NOW)

    projection = load_web_intel_projection(
        tmp_path,
        "target.test",
        now=NOW + timedelta(hours=2),
    )
    assert projection["status"] == "stale"
    assert projection["verified_claims"] == []
    assert build_web_intel_source(projection, _components())["status"] == "partial"


def test_invalid_index_is_explicit_and_target_mismatch_fails(tmp_path):
    root = tmp_path / "evidence" / "target.test" / "web-intel"
    root.mkdir(parents=True)
    (root / "index.json").write_text("{broken", encoding="utf-8")
    assert load_web_intel_projection(tmp_path, "target.test")["status"] == "invalid"

    payload = _payload()
    payload["target"] = "other.test"
    with pytest.raises(WebIntelArtifactError, match="target mismatch"):
        record_web_intel(tmp_path, "target.test", payload, now=NOW)


def test_recorded_query_artifact_is_valid_json_and_bounded(tmp_path):
    payload = _payload()
    payload["results"] = payload["results"] * 25
    path, _index = record_web_intel(tmp_path, "target.test", payload, now=NOW)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["schema_version"] == 1
    assert len(saved["results"]) == 20
    assert not list(path.parent.glob(".*.tmp"))


@pytest.mark.parametrize("field,value", [
    ("results", {}),
    ("claims", {}),
    ("identifiers", "CVE-2026-63030"),
])
def test_non_array_collections_fail_fast(tmp_path, field, value):
    payload = _payload()
    if field == "results":
        payload["results"] = value
    elif field == "claims":
        payload["results"][0]["claims"] = value
    else:
        payload["results"][0]["claims"][0]["identifiers"] = value

    with pytest.raises(WebIntelArtifactError, match="must be an array"):
        record_web_intel(tmp_path, "target.test", payload, now=NOW)
