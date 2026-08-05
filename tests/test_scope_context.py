import json

import pytest

from tools.scope_context import ScopeContext, ScopeContextError
from tools.target_paths import target_list_entries, url_belongs_to_target


def test_single_target_keeps_subdomain_and_exclusion_precedence():
    context = ScopeContext(
        root_target="target.example",
        out_of_scope=["admin.target.example"],
    )

    assert context.classify("https://api.target.example/v1")["status"] == "in_scope"
    excluded = context.classify("https://admin.target.example/login")
    assert excluded["status"] == "excluded"
    assert context.allows_active("https://admin.target.example/login") is False


def test_manifest_patterns_support_wildcard_port_and_cidr(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "in_scope": ["*.partner.example", "api.example:8443", "203.0.113.0/24"],
                "out_of_scope": ["payments.partner.example"],
            }
        ),
        encoding="utf-8",
    )
    context = ScopeContext.from_file(path)

    assert context.classify("https://edge.partner.example")["status"] == "in_scope"
    assert context.classify("https://payments.partner.example")["status"] == "excluded"
    assert context.classify("https://api.example:8443")["status"] == "in_scope"
    assert context.classify("https://api.example:443")["status"] != "in_scope"
    assert context.classify("https://203.0.113.17")["status"] == "in_scope"


def test_text_list_is_lossless_and_uses_list_target_semantics(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("# comment\nExample.com\n*.partner.example\n", encoding="utf-8")
    context = ScopeContext.from_file(path)

    assert context.classify("https://api.example.com")["status"] == "in_scope"
    assert context.classify("https://edge.partner.example")["status"] == "in_scope"
    assert context.summary()["source_ref"] == str(path.resolve())


def test_external_context_and_scope_review_are_distinct():
    context = ScopeContext.from_target("target.example")

    assert context.classify("https://supplier.example")["status"] == "external-chain-context"
    assert (
        context.classify("https://subsidiary.example", provenance="subsidiary")["status"]
        == "scope-review"
    )
    assert context.classify("AS64500")["status"] == "unknown"
    assert context.classify("ftp://supplier.example")["status"] == "invalid"


def test_fingerprint_changes_with_manifest_content(tmp_path):
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    payload = {"schema_version": 1, "in_scope": ["target.example"]}
    first.write_text(json.dumps(payload), encoding="utf-8")
    second.write_text(
        json.dumps({"schema_version": 1, "in_scope": ["target.example", "api.example"]}),
        encoding="utf-8",
    )

    assert ScopeContext.from_file(first).scope_hash != ScopeContext.from_file(second).scope_hash


def test_legacy_target_paths_accept_json_manifest_without_reimplementing_matchers(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "in_scope": ["*.target.example", "203.0.113.0/24"],
            "out_of_scope": ["admin.target.example"],
        }),
        encoding="utf-8",
    )

    assert url_belongs_to_target("https://api.target.example", str(path)) is True
    assert url_belongs_to_target("https://admin.target.example", str(path)) is False
    assert target_list_entries(str(path), preserve_wildcards=True) == [
        "*.target.example",
        "203.0.113.0/24",
    ]


def test_manifest_root_target_stays_in_active_asset_list(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "root_target": "target.example",
                "in_scope": ["api.example"],
            }
        ),
        encoding="utf-8",
    )

    assert target_list_entries(str(path), preserve_wildcards=True) == [
        "target.example",
        "api.example",
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 2, "in_scope": ["target.example"]},
        {"schema_version": 1, "in_scope": "target.example"},
    ],
)
def test_invalid_manifest_fails_before_network_io(tmp_path, payload):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ScopeContextError):
        ScopeContext.from_file(path)


def test_from_manifest_uses_the_same_schema_validation():
    with pytest.raises(ScopeContextError):
        ScopeContext.from_manifest({"schema_version": 1, "in_scope": "target.example"})
