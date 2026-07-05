import json

from tools.public_exposure_signals import (
    classify_public_response,
    looks_like_standard_public_metadata,
    standard_public_metadata_kind,
)


def test_csaf_provider_metadata_is_treated_as_standard_public_metadata():
    body = json.dumps(
        {
            "canonical_url": "https://example.com/.well-known/csaf/provider-metadata.json",
            "distributions": [],
            "metadata_version": "2.0",
            "public_openpgp_keys": [],
            "publisher": {"name": "Example"},
            "role": "csaf_provider",
        }
    )

    result = classify_public_response(
        "https://example.com/.well-known/csaf/provider-metadata.json",
        body,
        status=200,
    )

    assert standard_public_metadata_kind(
        "https://example.com/.well-known/csaf/provider-metadata.json",
        body,
    ) == "csaf-provider-metadata"
    assert looks_like_standard_public_metadata(
        "https://example.com/.well-known/csaf/provider-metadata.json",
        body,
        status=200,
    )
    assert result["standard_public_metadata"] is True
    assert result["candidate_ready"] is False


def test_openid_configuration_is_treated_as_standard_public_metadata():
    body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks.json",
        }
    )

    assert standard_public_metadata_kind(
        "https://example.com/.well-known/openid-configuration",
        body,
    ) == "oidc-discovery"
    assert looks_like_standard_public_metadata(
        "https://example.com/.well-known/openid-configuration",
        body,
        status=200,
    )


def test_standard_metadata_with_secret_like_body_is_not_suppressed():
    body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks.json",
            "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        }
    )

    result = classify_public_response(
        "https://example.com/.well-known/openid-configuration",
        body,
        status=200,
    )

    assert result["standard_public_metadata_kind"] == "oidc-discovery"
    assert result["candidate_ready"] is True
    assert result["standard_public_metadata"] is False
    assert not looks_like_standard_public_metadata(
        "https://example.com/.well-known/openid-configuration",
        body,
        status=200,
    )


def test_plain_prometheus_metrics_is_review_lead_not_candidate():
    body = "\n".join(
        [
            "# HELP http_requests_total Total HTTP requests",
            "# TYPE http_requests_total counter",
            'http_requests_total{method="get",route="/api/products",status="200"} 42',
            'process_cpu_seconds_total 12.3',
        ]
    )

    result = classify_public_response(
        "https://example.com/metrics",
        body,
        status=200,
    )

    assert result["candidate_ready"] is False
    assert result["standard_public_metadata"] is False
    assert result["markers"] == []
