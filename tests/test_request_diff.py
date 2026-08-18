from __future__ import annotations

import pytest

from tools.request_diff import RequestPairError, request_pair_digest, validate_request_pair


def _pair(**overrides):
    spec = {
        "schema_version": 1,
        "baseline_request": {
            "method": "POST",
            "url": "https://target.test/search",
            "headers": {"Content-Type": "application/json"},
            "body": {"filter": {"name": "SAMPLE"}},
        },
        "variant_request": {
            "method": "POST",
            "url": "https://target.test/search",
            "headers": {"Content-Type": "application/json"},
            "body": {"filter": {"name": "PAYLOAD"}},
        },
        "active_dimension": "body:/filter/name",
        "classifier": "sqli",
    }
    spec.update(overrides)
    return spec


def test_validate_request_pair_keeps_structured_json_and_digest_stable():
    normalized = validate_request_pair(_pair())
    assert normalized["baseline_request"]["body"]["filter"]["name"] == "SAMPLE"
    assert request_pair_digest(_pair()) == request_pair_digest(_pair())


@pytest.mark.parametrize(
    "spec, message",
    [
        (_pair(variant_request={"method": "POST", "url": "https://target.test/search", "headers": {"Content-Type": "application/json"}, "body": {"filter": {"name": "PAYLOAD"}, "page": 2}}), "only request difference"),
        (_pair(baseline_request={"method": "POST", "url": "https://target.test/search", "headers": {"Content-Type": "multipart/form-data"}, "body": "bytes"}, variant_request={"method": "POST", "url": "https://target.test/search", "headers": {"Content-Type": "multipart/form-data"}, "body": "other"}), "manual_required"),
    ],
)
def test_validate_request_pair_rejects_ambiguous_or_unsupported_pairs(spec, message):
    with pytest.raises(RequestPairError, match=message):
        validate_request_pair(spec)
