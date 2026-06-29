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


def test_secret_text_uses_secret_rubric_even_when_scanner_type_is_exposure():
    rubric = rubric_for("exposure", text="GitHub token leaked in JS bundle")

    assert rubric.id == "secret"
