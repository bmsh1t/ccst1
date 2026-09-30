from __future__ import annotations

import json

import pytest

from closure_resolver import ClosureResolver
from identity_contract import (
    FAMILY_POLICIES,
    ClosureCellKey,
    EndpointKey,
    build_closure_cell,
    normalize_identity_candidate,
    validate_identity_candidate,
)


def _dims(family: str, suffix: str = "a") -> dict[str, str]:
    return {"method": "GET", **{field: f"{field}-{suffix}" for field in FAMILY_POLICIES[family] if field != "method"}}


def test_endpoint_key_preserves_absolute_asset_and_spa_route():
    key = EndpointKey.from_value("https://target.test/#/search?q=one")
    assert key.endpoint == "https://target.test/#/search?q=one"
    assert key.to_dict()["schema_version"] == 3
    assert EndpointKey.from_value("https://target.test/#/search?q=one") == key


def test_closure_encoding_is_deterministic_and_round_trips():
    result = build_closure_cell("https://target.test/api/users/", "sqli", {"parameter": "q", "method": "POST"}, technique="fixture_check")
    assert result.complete
    assert result.key is not None
    key = result.key
    assert key.canonical_encoding == json.dumps(key.to_dict(), sort_keys=True, separators=(",", ":"))
    assert ClosureCellKey.from_dict(key.to_dict()) == key
    assert key.dimension_map == {"method": "POST", "parameter": "q"}
    assert build_closure_cell(
        "https://target.test/api/users", "nosqli", {"method": "POST", "parameter": "q"}
    , technique="fixture_check").family == "NoSQLi"
    assert build_closure_cell(
        "https://target.test/api/users",
        "deserialization",
        {"method": "POST", "input_field": "blob", "sink": "pickle"},
     technique="fixture_check").family == "RCE"


def test_technique_is_part_of_identity_and_legacy_missing_technique_is_rejected():
    time_based = build_closure_cell(
        "https://target.test/api/search",
        "SQLi",
        {"method": "GET", "parameter": "q"},
        technique="time-based",
    ).key
    boolean = build_closure_cell(
        "https://target.test/api/search",
        "SQLi",
        {"method": "GET", "parameter": "q"},
        technique="boolean blind",
    ).key
    assert time_based != boolean
    assert time_based.to_dict()["technique"] == "time_based"

    legacy = time_based.to_dict()
    legacy.pop("technique")
    with pytest.raises(ValueError, match="technique"):
        ClosureCellKey.from_dict(legacy)
    assert not build_closure_cell("https://target.test/api/search", "SQLi", {"method": "GET", "parameter": "q"}).complete


def test_semantic_families_do_not_cross_close_same_parameter():
    sqli = build_closure_cell(
        "https://target.test/api/search", "SQLi", {"method": "GET", "parameter": "q"}
    , technique="fixture_check").key
    nosqli = build_closure_cell(
        "https://target.test/api/search", "NoSQLi", {"method": "GET", "parameter": "q"}
    , technique="fixture_check").key
    resolver = ClosureResolver({
        "closed_cells_v2": [{"identity_v2": sqli.to_dict(), "result": "tested_clean"}],
    })
    assert resolver.is_closure_closed(sqli)
    assert not resolver.is_closure_closed(nosqli)


def test_persisted_identity_requires_known_kinds_and_versions():
    identity = build_closure_cell(
        "https://target.test/api/users",
        "SQLi",
        {"method": "GET", "parameter": "q"},
     technique="fixture_check").key.to_dict()

    with pytest.raises(ValueError, match="closure identity kind"):
        ClosureCellKey.from_dict({**identity, "kind": "legacy"})
    with pytest.raises(ValueError, match="endpoint identity schema"):
        ClosureCellKey.from_dict({
            **identity,
            "endpoint": {**identity["endpoint"], "schema_version": 1},
        })


@pytest.mark.parametrize("family", tuple(FAMILY_POLICIES))
def test_every_family_has_positive_and_one_dimension_negative(family: str):
    positive = build_closure_cell("https://target.test/same", family, _dims(family), technique="fixture_check")
    assert positive.complete, (family, positive.to_dict())
    changed = _dims(family)
    changed[FAMILY_POLICIES[family][0]] = "POST" if FAMILY_POLICIES[family][0] == "method" else "different"
    negative = build_closure_cell("https://target.test/same", family, changed, technique="fixture_check")
    assert negative.complete
    assert negative.key != positive.key
    resolver = ClosureResolver({
        "closed_cells_v2": [{
            "identity_v2": positive.key.to_dict(),
            "result": "tested_clean",
        }],
    })
    assert resolver.is_closure_closed(positive.key)
    assert not resolver.is_closure_closed(negative.key)


def test_endpoint_method_field_actor_and_object_stay_distinct():
    base = build_closure_cell("https://target.test/#/admin", "Authz", {"method": "GET", "actor_role": "member", "object_scope": "own"}, technique="fixture_check")
    assert base.complete
    assert not build_closure_cell("https://target.test/#/other", "Authz", {"method": "GET", "actor_role": "member", "object_scope": "own"}, technique="fixture_check").key == base.key
    assert build_closure_cell("https://target.test/#/admin", "Authz", {"method": "POST", "actor_role": "member", "object_scope": "own"}, technique="fixture_check").key != base.key
    assert build_closure_cell("https://target.test/#/admin", "Authz", {"method": "GET", "actor_role": "admin", "object_scope": "own"}, technique="fixture_check").key != base.key
    assert build_closure_cell("https://target.test/#/admin", "Authz", {"method": "GET", "actor_role": "member", "object_scope": "other"}, technique="fixture_check").key != base.key


def test_missing_method_is_incomplete_and_unknown_family_is_open():
    result = build_closure_cell("https://target.test/api/search", "SQLi", {"parameter": "q"}, technique="fixture_check")
    assert result.key is None
    assert result.complete is False
    assert "method" in result.missing_fields

    workflow = build_closure_cell(
        "https://target.test/api/checkout",
        "Workflow",
        {"method": "POST", "workflow": "checkout", "transition": "pay", "actor": "owner"},
     technique="fixture_check")
    assert workflow.complete
    unknown = build_closure_cell("https://target.test/api/search", "NotDefined", {"method": "GET"}, technique="fixture_check")
    assert unknown.key is not None
    assert unknown.complete is True


def test_extra_dimensions_are_retained_not_silently_dropped():
    result = build_closure_cell("https://target.test/api/search", "SQLi", {"method": "GET", "parameter": "q", "actor": "admin"}, technique="fixture_check")
    assert result.key.dimension_map["actor"] == "admin"
    assert not result.conflicts


def test_ai_candidate_is_persistable_but_low_confidence_needs_follow_up():
    candidate = normalize_identity_candidate({
        "family": "sql-injection",
        "endpoint": "https://target.test/api/search/",
        "dimensions": {"method": "POST", "parameter": "query"},
        "confidence": 0.5,
        "provenance": ["evidence/response.json"],
        "evidence_refs": ["ev-1"],
        "aliases": {"body_field": "parameter"},
        "follow_up_tests": [{"field": "query"}],
    })
    assert candidate.family == "SQLi"
    assert candidate.endpoint == "https://target.test/api/search/"
    assert candidate.dimensions == {"method": "POST", "parameter": "query"}
    assert "low_confidence" in candidate.conflicts
    validated = validate_identity_candidate(candidate)
    assert validated.identity is None
    assert validated.accepted is False
    assert validated.follow_up_required is True
    assert validated.follow_up_action["kind"] == "identity_follow_up"
    assert validated.candidate.to_dict()["provenance"] == ["evidence/response.json"]


def test_ai_candidate_complete_high_confidence_builds_identity_but_candidate_is_not_closure():
    validated = validate_identity_candidate({
        "family": "XSS",
        "endpoint": "https://target.test/profile",
        "dimensions": {"method": "GET", "source_parameter": "name", "output_sink": "html"},
        "confidence": 0.95,
        "technique": "fixture_check",
        "provenance": ["browser:123"],
        "evidence_refs": ["ev-2"],
    })
    assert validated.accepted is True
    assert validated.closeable is True
    assert validated.identity is not None
    assert validated.identity.family == "XSS"
    assert "identity_v2" not in validated.candidate.to_dict()


def test_complete_rce_and_unknown_family_candidates_preserve_declared_conditions():
    rce = validate_identity_candidate({
        "family": "RCE",
        "endpoint": "https://target.test/render",
        "dimensions": {"method": "POST", "input_field": "template", "sink": "renderer"},
        "confidence": 0.95,
        "technique": "fixture_check",
        "provenance": ["evidence/render-response.json"],
        "evidence_refs": ["evidence/render-response.json"],
    })
    unknown = validate_identity_candidate({
        "family": "custom-sandbox-boundary",
        "endpoint": "https://target.test/render",
        "dimensions": {"method": "POST"},
        "confidence": 0.95,
        "technique": "fixture_check",
        "provenance": ["evidence/render-response.json"],
        "evidence_refs": ["evidence/render-response.json"],
    })

    assert rce.closeable is True
    assert rce.identity is not None and rce.identity.family == "RCE"
    assert unknown.closeable is True
    assert unknown.identity.family == "custom-sandbox-boundary"


def test_candidate_conflicts_and_missing_provenance_fail_open():
    validated = validate_identity_candidate({
        "family": "IDOR",
        "endpoint": "https://target.test/users/{id}",
        "dimensions": {"path_template": "https://target.test/users/{id}", "method": "GET", "actor_relation": "peer"},
        "confidence": 1.0,
        "conflicts": ["evidence_disagreement"],
    })
    assert validated.identity is None
    assert validated.follow_up_required is True
    assert validated.candidate.missing_fields == ("technique",)
    assert "evidence_disagreement" in validated.candidate.conflicts
    assert "missing_provenance" in validated.candidate.conflicts
    assert "missing_evidence_refs" in validated.candidate.conflicts
