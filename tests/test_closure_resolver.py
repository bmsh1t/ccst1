"""Tests for tools/closure_resolver.py."""

from __future__ import annotations

import pytest
from pathlib import Path

from closure_resolver import (
    CANONICAL_VULN_CLASSES,
    CLOSURE_FAMILIES,
    ClosureResolver,
    canonical_endpoint_identity,
    canonical_endpoint_path,
    canonical_vuln_class,
    extract_endpoint_parts,
    extract_endpoint_path,
    from_summary,
)
from coverage_matrix import normalize_vuln_class
from identity_contract import build_closure_cell


def test_endpoint_normalization_strips_query_fragment_and_trailing_slash():
    assert canonical_endpoint_path("https://x.test/api/Users/?q=1#frag") == "/api/Users"
    assert canonical_endpoint_path("/rest/admin/") == "/rest/admin"
    assert canonical_endpoint_path("api/x") == "/api/x"
    assert canonical_endpoint_path("/") == "/"
    assert canonical_endpoint_path("") == ""
    assert extract_endpoint_path("https://x.test/api/Users/?q=1#frag") == "/api/Users/"
    assert extract_endpoint_parts("https://x.test/#/search?q=marker") == ("/", "/search?q=marker")


def test_endpoint_identity_preserves_query_and_spa_routes():
    assert canonical_endpoint_identity("https://x.test/api/Users/?q=1#frag") == "/api/Users?q=1"
    assert canonical_endpoint_identity("https://x.test/#/search?q=marker") == "/#/search?q=marker"
    assert canonical_endpoint_identity("/#/admin") == "/#/admin"
    assert canonical_endpoint_path("/#/search?q=marker") == "/#/search"
    assert canonical_endpoint_path("/#/admin") == "/#/admin"


def test_vuln_normalization_unknown_and_generic_fail_open():
    assert canonical_vuln_class("sql-injection") == "SQLi"
    assert canonical_vuln_class("auth_bypass") == "Authz"
    assert canonical_vuln_class("ssti") == "RCE"
    assert canonical_vuln_class("deserialization") == "RCE"
    assert canonical_vuln_class("nosqli") == "NoSQLi"
    assert canonical_vuln_class("rfi") == "Path"
    assert canonical_vuln_class("open-redirect") == "OpenRedirect"
    assert canonical_vuln_class("prototype-pollution") == "PrototypePollution"
    assert canonical_vuln_class("business-logic") == "BusinessLogic"
    assert canonical_vuln_class("generic") == ""
    assert canonical_vuln_class("totally-unknown") == ""
    assert canonical_vuln_class("") == ""


def test_workflow_is_closeable_without_expanding_coverage_taxonomy():
    assert "Workflow" in CLOSURE_FAMILIES
    assert "Workflow" not in CANONICAL_VULN_CLASSES
    assert canonical_vuln_class("workflow") == "Workflow"

    cell = build_closure_cell(
        "/checkout",
        "workflow",
        {"workflow": "checkout", "transition": "pay", "actor": "owner"},
    )
    assert cell.complete and cell.key is not None
    resolver = ClosureResolver({
        "closed_cells_v2": [{
            "identity_v2": cell.key.to_dict(),
            "result": "tested_clean",
        }],
    })
    assert resolver.is_closure_closed(cell.key)
    assert resolver.closed_result(
        "/checkout", "Workflow", identity_v2=cell.key
    ) == "tested_clean"

    with pytest.raises(ValueError, match="unknown vuln_class"):
        normalize_vuln_class("Workflow")


def test_closed_cell_from_ledger_closed_cells():
    resolver = from_summary({
        "closed_cells": [
            {"endpoint": "/api/Users", "vuln_class": "Authz", "ts": "2026-01-01T00:00:00Z"},
        ]
    })

    assert resolver.is_cell_closed("/api/Users", "Authz") is True
    assert resolver.is_cell_closed("https://x.test/api/Users?p=1", "authz") is False
    assert resolver.is_cell_closed("/api/Users", "SQLi") is False
    assert resolver.is_cell_closed("/other", "Authz") is False


def test_spa_hash_routes_do_not_close_each_other_or_root():
    resolver = from_summary({
        "closed_cells": [
            {"endpoint": "/#/search", "vuln_class": "XSS", "ts": "2026-01-01T00:00:00Z"},
        ]
    })

    assert resolver.is_cell_closed("/#/search", "XSS") is True
    assert resolver.is_cell_closed("/#/admin", "XSS") is False
    assert resolver.is_cell_closed("/", "XSS") is False


def test_unknown_vuln_class_never_closes_as_authz():
    resolver = from_summary({
        "closed_cells": [
            {"endpoint": "/api/Users", "vuln_class": "Authz", "ts": "2026-01-01T00:00:00Z"},
        ]
    })

    assert resolver.is_cell_closed("/api/Users", "generic") is False
    assert resolver.is_cell_closed("/api/Users", "totally-unknown") is False
    assert resolver.are_endpoints_closed(["/api/Users"], required_classes={"generic"}) is False


def test_authz_and_idor_do_not_close_each_other():
    resolver = from_summary({
        "closed_cells": [
            {"endpoint": "/api/Cards", "vuln_class": "IDOR", "ts": "2026-01-01T00:00:00Z"},
        ]
    })

    assert resolver.is_cell_closed("/api/Cards", "IDOR") is True
    assert resolver.is_cell_closed("/api/Cards", "Authz") is False


def test_recent_entries_never_author_closure():
    resolver = from_summary({
        "recent_entries": [
            {"endpoint": "/a", "vuln_class": "XSS", "result": "tested_clean"},
            {"endpoint": "/b", "vuln_class": "XSS", "result": "candidate"},
            {"endpoint": "/c", "vuln_class": "XSS", "result": "signal"},
            {"endpoint": "/d", "vuln_class": "SSRF", "result": "blocked_redline"},
        ]
    })

    assert resolver.is_cell_closed("/a", "XSS") is False
    assert resolver.is_cell_closed("/b", "XSS") is False
    assert resolver.is_cell_closed("/c", "XSS") is False
    assert resolver.is_cell_closed("/d", "SSRF") is False
    assert resolver.closed_result("/a/", "xss") == ""
    assert resolver.closed_result("/d", "ssrf") == ""
    assert resolver.closed_result("/b", "XSS") == ""


def test_matrix_terminals_do_not_authorize_closure_without_ledger():
    matrix = {
        "endpoints": [
            {
                "endpoint": "/m",
                "cells": {
                    "SQLi": {"status": "tested_clean"},
                    "XSS": {"status": "untested"},
                    "IDOR": {"status": "n_a"},
                    "unknown": {"status": "tested_clean"},
                },
            }
        ]
    }
    resolver = ClosureResolver(evidence_summary={}, matrix=matrix)

    assert resolver.is_cell_closed("/m", "SQLi") is False
    assert resolver.is_cell_closed("/m", "IDOR") is False
    assert resolver.is_cell_closed("/m", "XSS") is False
    assert resolver.is_cell_closed("/m", "unknown") is False


def test_legacy_matrix_status_cannot_close_a_v2_identity():
    resolver = ClosureResolver(
        evidence_summary={},
        matrix={
            "endpoints": [{
                "endpoint": "/api/search",
                "cells": {"SQLi": {"status": "tested_clean"}},
            }],
        },
    )
    identity = {
        "schema_version": 2,
        "kind": "closure_cell",
        "endpoint": {"schema_version": 2, "kind": "endpoint", "endpoint": "/api/search"},
        "family": "SQLi",
        "dimensions": {"method": "GET", "parameter": "q"},
    }

    assert resolver.is_cell_closed("/api/search", "SQLi") is False
    assert resolver.is_closure_closed(identity) is False


def test_v2_query_rejects_endpoint_family_and_schema_disagreement():
    identity = {
        "schema_version": 2,
        "kind": "closure_cell",
        "endpoint": {"schema_version": 2, "kind": "endpoint", "endpoint": "/api/search"},
        "family": "SQLi",
        "dimensions": {"method": "GET", "parameter": "q"},
    }
    resolver = ClosureResolver({
        "closed_cells_v2": [{"identity_v2": identity, "result": "tested_clean"}],
    })

    assert resolver.is_cell_closed("/other", "SQLi", identity_v2=identity) is False
    assert resolver.is_cell_closed("/api/search", "XSS", identity_v2=identity) is False
    malformed = {
        **identity,
        "endpoint": {**identity["endpoint"], "schema_version": 1},
    }
    assert resolver.is_closure_closed(malformed) is False


def test_endpoint_batch_requires_all_endpoints_closed_with_required_class():
    resolver = from_summary({
        "closed_cells": [
            {"endpoint": "/a", "vuln_class": "Authz", "ts": "t"},
            {"endpoint": "/b", "vuln_class": "Authz", "ts": "t"},
            {"endpoint": "/c", "vuln_class": "SQLi", "ts": "t"},
        ]
    })

    assert resolver.are_endpoints_closed(["/a", "/b"], required_classes={"Authz"}) is True
    assert resolver.are_endpoints_closed(["/a", "/b", "/missing"], required_classes={"Authz"}) is False
    assert resolver.are_endpoints_closed(["/a"], required_classes={"SQLi"}) is False
    assert resolver.are_endpoints_closed(["/c"]) is True
    assert resolver.are_endpoints_closed([]) is False


def test_closed_after_uses_newer_final_rows_only():
    resolver = from_summary({
        "closed_cells": [
            {"endpoint": "/a", "vuln_class": "Authz", "ts": "2026-06-01T00:00:00Z"},
        ]
    })

    assert resolver.closed_after(["/a"], "2026-05-01T00:00:00Z") is True
    assert resolver.closed_after(["/a"], "2026-07-01T00:00:00Z") is False
    assert resolver.closed_after(["/other"], "2026-05-01T00:00:00Z") is False
    assert resolver.closed_after(["/a"], "") is False


def test_empty_or_malformed_inputs_fail_open():
    resolver = from_summary({
        "closed_cells": ["bad", {"endpoint": "", "vuln_class": "XSS"}],
        "recent_entries": [None, 42],
    })

    assert resolver.is_cell_closed("/a", "XSS") is False
    assert resolver.are_endpoints_closed(["/a"]) is False
    assert resolver.closed_after(["/a"], "2026-01-01T00:00:00Z") is False


def test_terminal_vocabulary_is_defined_once_for_ledger_and_closure():
    """Coverage/Closure must not restate what "closed" means in separate copies."""
    from evidence_identity import (
        CLOSED_LEDGER_RESULTS, CLOSED_MATRIX_STATUSES, COVERING_RESULTS, LEDGER_RESULTS,
    )
    import closure_resolver
    import evidence_ledger

    assert closure_resolver.CLOSED_LEDGER_RESULTS == CLOSED_LEDGER_RESULTS
    assert closure_resolver.CLOSED_MATRIX_STATUSES == CLOSED_MATRIX_STATUSES
    assert set(evidence_ledger.RESULTS) == set(LEDGER_RESULTS)
    assert evidence_ledger.CLOSED_CELL_RESULTS == set(CLOSED_LEDGER_RESULTS)
    assert evidence_ledger.COVERING_RESULTS == COVERING_RESULTS
    # The invariant is "one definition": consumers must import, not restate.
    tools = Path(__file__).resolve().parents[1] / "tools"
    for name in ("closure_resolver.py", "evidence_ledger.py"):
        source = (tools / name).read_text()
        assert "CLOSED_LEDGER_RESULTS = {" not in source, f"{name} restates the terminal set"
        assert "CLOSED_MATRIX_STATUSES = {" not in source, f"{name} restates the matrix status set"
        assert "COVERING_RESULTS = {" not in source, f"{name} restates the covering set"


def test_closure_projection_is_defined_once_and_fed_by_both_producers():
    """One cell-closing projection; producers only supply canonical records."""
    from tools import closure_projection, current_truth

    assert closure_projection.derive_identity_fields.__module__.endswith("closure_projection")
    assert current_truth.build_current_cell_projection is closure_projection.build_current_cell_projection
    assert current_truth.suppress_unauthorized_closures is closure_projection.suppress_unauthorized_closures

    tools = Path(__file__).resolve().parents[1] / "tools"
    ledger = (tools / "evidence_ledger.py").read_text()
    # The ledger consumes the projection (and the damage rule) but never
    # re-exports it: a second import path is how a second definition appears.
    assert "build_current_cell_projection" not in ledger, "evidence_ledger carries projection code"
    assert "suppress_unauthorized_closures(" not in ledger, "evidence_ledger restates the damage rule"
    assert "def _project_v2_cells" not in ledger, "evidence_ledger restates the v2 projection"
    assert "def _project_legacy_cells" not in ledger, "evidence_ledger restates the legacy projection"
    assert "def _identity_fact_conflicts" not in ledger, "evidence_ledger restates identity fact conflicts"
    store = (tools / "target_store.py").read_text()
    assert "identity_status" not in store, "the store must not derive identity status itself"

    # A raw record (dimensions, no stored status) is derived by the projection.
    record = {
        "event_id": "op:0", "raw_endpoint": "https://x.test/api/orders/42",
        "endpoint": "/api/orders/42", "method": "GET", "vuln_class": "SQLi", "result": "tested_clean",
        "ts": "2026-09-20T01:00:00Z", "identity_dimensions": {"method": "get", "parameter": "id"},
    }
    projection = closure_projection.build_current_cell_projection([record])
    assert [cell["vuln_class"] for cell in projection["closed_cells_v2"]] == ["SQLi"]
    assert projection["closed_cells_v2"][0]["identity_v2"]["dimensions"] == {"method": "GET", "parameter": "id"}
    # Records without dimensions stay in the legacy endpoint projection only.
    assert projection["closed_cells"] == []
    legacy = {**record, "event_id": "op:1", "family": "SQLi"}
    legacy.pop("identity_dimensions")
    legacy.pop("vuln_class")
    legacy["vuln_class"] = "SQLi"
    plain = closure_projection.build_current_cell_projection([legacy])
    assert plain["closed_cells_v2"] == [] and plain["closed_cells"][0]["vuln_class"] == "SQLi"


def test_endpoint_shape_helpers_are_defined_once_and_stay_policy_free():
    """Coverage consumes endpoint-shape utilities; it must not keep a second copy.

    ``collapse_dynamic_path_segments`` owns segment collapsing only. Admission
    (static asset / public metadata short circuit) stays in Coverage, so the
    helper must not decide what deserves a coverage cell.
    """
    from evidence_identity import (
        collapse_dynamic_path_segments, path_with_query, query_param_names, split_path_query,
    )
    import coverage_matrix

    # Both sys.path forms (`tools.x` / `x`) may be live in one interpreter, so
    # compare provenance rather than object identity.
    for name in ("collapse_dynamic_path_segments", "path_with_query", "query_param_names"):
        borrowed = getattr(coverage_matrix, name)
        assert borrowed.__module__.endswith("evidence_identity"), f"{name} is not imported from evidence_identity"
        assert borrowed.__qualname__ == name
    assert collapse_dynamic_path_segments("/a/12345") == coverage_matrix.collapse_dynamic_path_segments("/a/12345")
    assert path_with_query("/a?b=1") == coverage_matrix.path_with_query("/a?b=1")
    assert query_param_names("/a?b=1") == coverage_matrix.query_param_names("/a?b=1")

    tools = Path(__file__).resolve().parents[1] / "tools"
    source = (tools / "coverage_matrix.py").read_text()
    for definition in (
        "def collapse_dynamic_path_segments",
        "def split_path_query",
        "def path_with_query",
        "def query_param_names",
        "_ROUTE_UUID_RE = ",
        "_ROUTE_NUMBER_RE = ",
    ):
        assert definition not in source, f"coverage_matrix.py restates {definition}"

    assert collapse_dynamic_path_segments("/api/orders/3f2b1c4d-5e6a-4b7c-8d9e-0f1a2b3c4d5e") == "/api/orders/{uuid}"
    assert collapse_dynamic_path_segments("/api/orders/12345/items") == "/api/orders/{id}/items"
    # Segment-level collapse only: a date glued into a filename is not a route token.
    assert collapse_dynamic_path_segments("/exports/2024-05-01/json") == "/exports/{date}/json"
    assert collapse_dynamic_path_segments("/exports/2024-05-01.csv") == "/exports/2024-05-01.csv"
    assert collapse_dynamic_path_segments("/api/session/deadbeefdeadbeefdeadbeefdeadbeef") == "/api/session/{hash}"
    assert split_path_query("https://x.test/api/a?q=1#f") == ("/api/a", "q=1")
    assert path_with_query("/api/a?b=1") == "/api/a?b=1"
    assert query_param_names("https://x.test/api/a?debug=1&isAdmin") == {"debug", "isAdmin"}

    # Admission is still Coverage's own policy, not the shared helper's.
    assert coverage_matrix._route_template("/assets/app.js") == "/assets/app.js"
    assert coverage_matrix._route_template("https://x.test/api/orders/42/reviews") == "/api/orders/{id}/reviews"
    assert coverage_matrix._route_template("https://x.test/api/orders/7/reviews") == "/api/orders/7/reviews"
