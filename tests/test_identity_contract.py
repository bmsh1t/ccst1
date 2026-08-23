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
    return {field: f"{field}-{suffix}" for field in FAMILY_POLICIES[family]}


def test_endpoint_key_reuses_canonical_endpoint_and_preserves_spa_route():
    key = EndpointKey.from_value("https://Example.test/#/search?q=one")
    assert key.endpoint == "/#/search?q=one"
    assert key.to_dict()["schema_version"] == 2
    assert EndpointKey.from_value("/#/search?q=one") == key


def test_closure_encoding_is_deterministic_and_round_trips():
    result = build_closure_cell("/api/users/", "sqli", {"parameter": "q", "method": "post"})
    assert result.complete
    assert result.key is not None
    key = result.key
    assert key.canonical_encoding == json.dumps(key.to_dict(), sort_keys=True, separators=(",", ":"))
    assert ClosureCellKey.from_dict(key.to_dict()) == key
    assert key.dimension_map == {"method": "POST", "parameter": "q"}
    assert build_closure_cell(
        "/api/users", "nosqli", {"method": "POST", "parameter": "q"}
    ).family == "SQLi"
    assert build_closure_cell(
        "/api/users",
        "deserialization",
        {"method": "POST", "input_field": "blob", "sink": "pickle"},
    ).family == "RCE"


def test_persisted_identity_requires_v2_kinds_and_versions():
    identity = build_closure_cell(
        "/api/users",
        "SQLi",
        {"method": "GET", "parameter": "q"},
    ).key.to_dict()

    with pytest.raises(ValueError, match="closure identity kind"):
        ClosureCellKey.from_dict({**identity, "kind": "legacy"})
    with pytest.raises(ValueError, match="endpoint identity schema"):
        ClosureCellKey.from_dict({
            **identity,
            "endpoint": {**identity["endpoint"], "schema_version": 1},
        })


@pytest.mark.parametrize("family", tuple(FAMILY_POLICIES))
def test_every_family_has_positive_and_one_dimension_negative(family: str):
    positive = build_closure_cell("/same", family, _dims(family))
    assert positive.complete, (family, positive.to_dict())
    changed = _dims(family)
    changed[FAMILY_POLICIES[family][0]] = "different"
    negative = build_closure_cell("/same", family, changed)
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
    base = build_closure_cell("/#/admin", "Authz", {"method": "GET", "actor_role": "member", "object_scope": "own"})
    assert base.complete
    assert not build_closure_cell("/#/other", "Authz", {"method": "GET", "actor_role": "member", "object_scope": "own"}).key == base.key
    assert build_closure_cell("/#/admin", "Authz", {"method": "POST", "actor_role": "member", "object_scope": "own"}).key != base.key
    assert build_closure_cell("/#/admin", "Authz", {"method": "GET", "actor_role": "admin", "object_scope": "own"}).key != base.key
    assert build_closure_cell("/#/admin", "Authz", {"method": "GET", "actor_role": "member", "object_scope": "other"}).key != base.key


def test_missing_dimensions_are_incomplete_and_fail_open():
    result = build_closure_cell("/api/search", "SQLi", {"method": "GET"})
    assert result.key is None
    assert result.complete is False
    assert "parameter" in result.missing_fields

    workflow = build_closure_cell(
        "/api/checkout",
        "Workflow",
        {"workflow": "checkout", "transition": "pay", "actor": "owner"},
    )
    assert workflow.complete
    unknown = build_closure_cell("/api/search", "NotDefined", {})
    assert unknown.key is None
    assert unknown.complete is False
    assert "family_policy" in unknown.missing_fields


def test_extra_dimensions_are_conflicts_not_silently_dropped():
    result = build_closure_cell("/api/search", "SQLi", {"method": "GET", "parameter": "q", "actor": "admin"})
    assert result.key is None
    assert "unexpected_dimension:actor" in result.conflicts


def test_ai_candidate_is_persistable_but_low_confidence_needs_follow_up():
    candidate = normalize_identity_candidate({
        "family": "sql-injection",
        "endpoint": "https://target.test/api/search/",
        "dimensions": {"http_method": "post", "body_field": "query"},
        "confidence": 0.5,
        "provenance": ["evidence/response.json"],
        "evidence_refs": ["ev-1"],
        "aliases": {"body_field": "parameter"},
        "follow_up_tests": [{"field": "query"}],
    })
    assert candidate.family == "SQLi"
    assert candidate.endpoint == "/api/search"
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
        "endpoint": "/profile",
        "dimensions": {"source_parameter": "name", "output_sink": "html"},
        "confidence": 0.95,
        "provenance": ["browser:123"],
        "evidence_refs": ["ev-2"],
    })
    assert validated.accepted is True
    assert validated.closeable is True
    assert validated.identity is not None
    assert validated.identity.family == "XSS"
    assert "identity_v2" not in validated.candidate.to_dict()


def test_complete_rce_candidate_projects_but_unknown_family_stays_open():
    rce = validate_identity_candidate({
        "family": "RCE",
        "endpoint": "/render",
        "dimensions": {"method": "POST", "input_field": "template", "sink": "renderer"},
        "confidence": 0.95,
        "provenance": ["evidence/render-response.json"],
        "evidence_refs": ["evidence/render-response.json"],
    })
    unknown = validate_identity_candidate({
        "family": "custom-sandbox-boundary",
        "endpoint": "/render",
        "dimensions": {},
        "confidence": 0.95,
        "provenance": ["evidence/render-response.json"],
        "evidence_refs": ["evidence/render-response.json"],
    })

    assert rce.closeable is True
    assert rce.identity is not None and rce.identity.family == "RCE"
    assert unknown.closeable is False
    assert unknown.identity is None
    assert "family_policy" in unknown.candidate.missing_fields


def test_candidate_conflicts_and_missing_provenance_fail_open():
    validated = validate_identity_candidate({
        "family": "IDOR",
        "endpoint": "/users/{id}",
        "dimensions": {"path_template": "/users/{id}", "method": "GET", "actor_relation": "peer"},
        "confidence": 1.0,
        "conflicts": ["evidence_disagreement"],
    })
    assert validated.identity is None
    assert validated.follow_up_required is True
    assert "object_scope" in validated.candidate.missing_fields
    assert "evidence_disagreement" in validated.candidate.conflicts
    assert "missing_provenance" in validated.candidate.conflicts
    assert "missing_evidence_refs" in validated.candidate.conflicts
