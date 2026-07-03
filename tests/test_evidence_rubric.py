"""Tests for high-value candidate evidence rubric."""

from evidence_rubric import evaluate_candidate_evidence, rubric_for


def test_sqli_rubric_detects_ready_candidate_from_replay_evidence():
    finding = {
        "type": "sqli",
        "confidence": "confirmed",
        "summary": (
            "SQLI-POC-VERIFIED baseline vs single-variable perturbation on q "
            "produced stable PostgreSQL syntax error and 3/3 deterministic "
            "read-only DB fingerprint evidence"
        ),
        "raw": "curl request and response diff captured",
    }

    result = evaluate_candidate_evidence(finding)

    assert result["rubric_id"] == "sqli"
    assert result["ready"] is True
    assert result["status"] == "candidate-ready"
    assert result["score"] >= 90


def test_idor_rubric_returns_missing_next_actions_for_weak_signal():
    finding = {
        "type": "idor",
        "severity": "high",
        "summary": "GET /api/orders/42 returns 200 and looks interesting",
    }

    result = evaluate_candidate_evidence(finding)

    assert result["rubric_id"] == "authz"
    assert result["ready"] is False
    assert result["missing"]
    assert any("two-actor" in action for action in result["next_actions"])


def test_authz_public_admin_config_exposure_does_not_require_actor_diff():
    finding = {
        "type": "auth_bypass",
        "title": "AUTH_BYPASS on https://target.test/rest/admin/application-configuration",
        "summary": "200 23577 https://target.test/rest/admin/application-configuration",
        "url": "https://target.test/rest/admin/application-configuration",
        "source_file": "auth_bypass/unauth_api_access.txt",
        "raw": "200 23577 https://target.test/rest/admin/application-configuration",
    }

    result = evaluate_candidate_evidence(finding)

    assert result["rubric_id"] == "authz"
    assert result["ready"] is True
    assert result["status"] == "candidate-ready"
    assert "actor / role / object boundary difference" not in result["missing_labels"]


def test_authz_plain_public_catalog_api_still_needs_actor_diff():
    finding = {
        "type": "auth_bypass",
        "title": "AUTH_BYPASS on https://target.test/api/Products",
        "summary": "200 16011 https://target.test/api/Products",
        "url": "https://target.test/api/Products",
        "source_file": "auth_bypass/unauth_api_access.txt",
        "raw": "200 16011 https://target.test/api/Products",
    }

    result = evaluate_candidate_evidence(finding)

    assert result["rubric_id"] == "authz"
    assert result["ready"] is False
    assert "actor / role / object boundary difference" in result["missing_labels"]


def test_secret_text_uses_secret_rubric_even_when_scanner_type_is_exposure():
    rubric = rubric_for("exposure", text="GitHub token leaked in JS bundle")

    assert rubric.id == "secret"


def test_race_rubric_uses_race_family_and_returns_bounded_replay_guidance():
    finding = {
        "type": "race",
        "summary": "parallel coupon checkout looks interesting on /api/cart/checkout",
    }

    result = evaluate_candidate_evidence(finding)

    assert result["rubric_id"] == "race"
    assert result["ready"] is False
    assert result["missing"]
    assert any("pre/post state" in action for action in result["next_actions"])
    assert any("red-line safety" in action for action in result["next_actions"])


def test_toctou_alias_maps_to_race_rubric():
    rubric = rubric_for("toctou", text="parallel quota bypass candidate")

    assert rubric.id == "race"
