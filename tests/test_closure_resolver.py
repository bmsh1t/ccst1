"""Tests for tools/closure_resolver.py."""

from __future__ import annotations

from closure_resolver import ClosureResolver, canonical_endpoint_path, canonical_vuln_class, from_summary


def test_endpoint_normalization_strips_query_fragment_and_trailing_slash():
    assert canonical_endpoint_path("https://x.test/api/Users/?q=1#frag") == "/api/Users"
    assert canonical_endpoint_path("/rest/admin/") == "/rest/admin"
    assert canonical_endpoint_path("api/x") == "/api/x"
    assert canonical_endpoint_path("/") == "/"
    assert canonical_endpoint_path("") == ""


def test_vuln_normalization_unknown_and_generic_fail_open():
    assert canonical_vuln_class("sql-injection") == "SQLi"
    assert canonical_vuln_class("auth_bypass") == "Authz"
    assert canonical_vuln_class("ssti") == "RCE"
    assert canonical_vuln_class("generic") == ""
    assert canonical_vuln_class("totally-unknown") == ""
    assert canonical_vuln_class("") == ""


def test_closed_cell_from_ledger_closed_cells():
    resolver = from_summary({
        "closed_cells": [
            {"endpoint": "/api/Users", "vuln_class": "Authz", "ts": "2026-01-01T00:00:00Z"},
        ]
    })

    assert resolver.is_cell_closed("/api/Users", "Authz") is True
    assert resolver.is_cell_closed("https://x.test/api/Users?p=1", "authz") is True
    assert resolver.is_cell_closed("/api/Users", "SQLi") is False
    assert resolver.is_cell_closed("/other", "Authz") is False


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


def test_recent_entries_close_only_final_results_including_blocked_redline():
    resolver = from_summary({
        "recent_entries": [
            {"endpoint": "/a", "vuln_class": "XSS", "result": "tested_clean"},
            {"endpoint": "/b", "vuln_class": "XSS", "result": "candidate"},
            {"endpoint": "/c", "vuln_class": "XSS", "result": "signal"},
            {"endpoint": "/d", "vuln_class": "SSRF", "result": "blocked_redline"},
        ]
    })

    assert resolver.is_cell_closed("/a", "XSS") is True
    assert resolver.is_cell_closed("/b", "XSS") is False
    assert resolver.is_cell_closed("/c", "XSS") is False
    assert resolver.is_cell_closed("/d", "SSRF") is True
    assert resolver.closed_result("/a/", "xss") == "tested_clean"
    assert resolver.closed_result("/d", "ssrf") == "blocked_redline"
    assert resolver.closed_result("/b", "XSS") == ""


def test_matrix_closed_statuses_are_auxiliary_closed_source():
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

    assert resolver.is_cell_closed("/m", "SQLi") is True
    assert resolver.is_cell_closed("/m", "IDOR") is True
    assert resolver.is_cell_closed("/m", "XSS") is False
    assert resolver.is_cell_closed("/m", "unknown") is False


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
