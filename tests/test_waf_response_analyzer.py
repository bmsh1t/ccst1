from __future__ import annotations

from tools.waf_response_analyzer import (
    EMPTY_BASELINE,
    LogIDExtractor,
    ResponseClassifier,
    ResponseFingerprint,
    WAFSignatureDB,
    diff_bodies,
)


def test_classifier_projects_routing_context_without_cookie_values() -> None:
    db = WAFSignatureDB()
    fingerprint = ResponseFingerprint.build(
        '{"user_id":"fixture"}',
        "HTTP/1.1 302 Found\n"
        "Location: /login?next=secret\n"
        "Content-Type: application/json\n"
        "Server: nginx\n"
        "Set-Cookie: session=secret; Path=/\n",
        status_code=302,
        body_length=21,
        response_time_ms=120,
        db=db,
        extractor=LogIDExtractor(db),
    )

    result = ResponseClassifier().classify(fingerprint, EMPTY_BASELINE)

    assert result["header_context"] == {
        "content_type": "application/json",
        "location": "/login",
        "server": "nginx",
        "via": "",
        "www_authenticate": False,
        "set_cookie_names": ["session"],
    }
    assert result["protected_content_hint"] is True
    assert "secret" not in str(result["header_context"])


def test_waf_block_has_priority_over_business_hint() -> None:
    db = WAFSignatureDB()
    fingerprint = ResponseFingerprint.build(
        '<html><title>Access Denied</title>Cloudflare Ray ID: abc123456789'
        '<form csrf_token="x"></form></html>',
        "HTTP/1.1 200 OK\nContent-Type: text/html\n",
        status_code=200,
        body_length=105,
        response_time_ms=40,
        db=db,
        extractor=LogIDExtractor(db),
    )

    result = ResponseClassifier().classify(fingerprint, EMPTY_BASELINE)

    assert result["verdict"] == "blocked"
    assert result["protected_content_hint"] is True


def test_body_diff_projects_business_and_waf_shape_changes() -> None:
    report = diff_bodies(
        '<html><title>Access Denied</title>Cloudflare Ray ID: abc123456789</html>',
        '{"user":{"id":"fixture"},"items":[{"id":1}]}',
    )

    assert report["context_a"]["vendor_hits"] == ["cloudflare"]
    assert report["context_a"]["has_block_title"] is True
    assert report["context_b"]["has_business_signal"] is True
    assert "user" in report["json_keys_added"]
    assert report["json_shape_changed"] is True
