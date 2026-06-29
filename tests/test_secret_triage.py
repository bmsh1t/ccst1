"""Tests for secret/key triage."""

from secret_triage import compact_secret_triage, triage_secret_finding


def test_secret_triage_classifies_github_token_and_missing_context():
    triage = triage_secret_finding({
        "rule_id": "github-token",
        "category": "secret",
        "confidence": "high",
        "source": "builtin",
        "file_path": "static/app.js",
        "line_number": 7,
        "secret_preview": "ghp_...abcd",
        "evidence_snippet": "const token = 'ghp_example_secret_value';",
    })

    assert triage["type"] == "github-token"
    assert triage["provider"] == "GitHub"
    assert triage["candidate_status"] == "needs-safe-verification"
    assert "target ownership/context" in triage["missing"]
    assert "minimal token identity/scope check" in triage["next_action"]


def test_secret_triage_promotes_verified_target_owned_key():
    triage = triage_secret_finding({
        "rule_id": "aws-access-key",
        "category": "secret",
        "confidence": "high",
        "source": "trufflehog",
        "file_path": "target-owned production config",
        "line_number": 3,
        "evidence_snippet": "verified valid identity scope permission for target-owned production account",
    })

    assert triage["candidate_status"] == "candidate-ready"
    assert triage["has_target_context"] is True
    assert triage["has_validity"] is True
    assert compact_secret_triage(triage)["type"] == "aws-access-key"
