#!/usr/bin/env python3
"""Secret/key triage helper.

The goal is to turn "a key was found" into an executable minimal validation
plan: type, source, confidence, verification safety, candidate status, and
next action.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any


TYPE_HINTS: list[tuple[str, tuple[str, ...], str, str]] = [
    (
        "aws-access-key",
        ("aws-access-key", "AKIA", "ASIA", "AWS_ACCESS_KEY_ID"),
        "AWS",
        "If the matching secret key is available, run a minimal STS GetCallerIdentity-style identity check; otherwise map source ownership and search paired config safely.",
    ),
    (
        "github-token",
        ("github-token", "ghp_", "github_pat_", "GITHUB_TOKEN"),
        "GitHub",
        "Run a minimal token identity/scope check only if safe, then map repo/org ownership and accessible scope without changing repo state.",
    ),
    (
        "stripe-key",
        ("stripe-key", "sk_live_", "sk_test_", "STRIPE"),
        "Stripe",
        "Use the smallest account/key metadata check if safe; do not create charges, refunds, customers, or modify billing state.",
    ),
    (
        "slack-token",
        ("slack-token", "xoxb-", "xoxa-", "xoxp-", "SLACK"),
        "Slack",
        "Use a minimal auth.test-style identity check if safe, then map workspace ownership and scopes without reading private content.",
    ),
    (
        "private-key",
        ("private-key", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY"),
        "Private key",
        "Identify key purpose from file path, comments, host/user naming, and deployment context; avoid logging into target infrastructure automatically.",
    ),
    (
        "bearer-token",
        ("bearer-token", "Bearer "),
        "Bearer token",
        "Identify the API/provider from surrounding URL/client code, then attempt only a minimal identity/scope endpoint if safe.",
    ),
    (
        "oauth-client-secret",
        ("client_secret", "client-secret", "oauth", "OIDC", "CLIENT_SECRET"),
        "OAuth/OIDC",
        "Map client id, redirect URIs, environment, and whether the secret enables token exchange in a target-owned app.",
    ),
    (
        "password-config",
        ("password", "passwd", "pwd", "DB_PASSWORD", "DATABASE_URL"),
        "Password / config credential",
        "Identify service type, environment, and whether a non-destructive login/identity check is possible without lockout or data changes.",
    ),
    (
        "generic-api-key",
        ("api_key", "api-key", "apikey", "secret_key", "secret-key", "token", "key"),
        "Generic API key",
        "Use surrounding host/package/client code to identify provider before any live validation.",
    ),
]

SIDE_EFFECT_RISK_HINTS = re.compile(
    r"\b(charge|refund|delete|remove|write|deploy|publish|send|email|sms|"
    r"invite|add[-_ ]?member|remove[-_ ]?member|grant[-_ ]?role|revoke[-_ ]?role)\b",
    re.I,
)
TARGET_CONTEXT_HINTS = re.compile(
    r"\b(target-owned|owned|domain|repo|organization|org|workspace|tenant|"
    r"production|staging|bundle|environment|account)\b",
    re.I,
)
VALIDITY_HINTS = re.compile(
    r"\b(verified|valid|auth success|identity|scope|permission|usable|"
    r"unexpired|trufflehog.*verified|verification blocker)\b",
    re.I,
)


def _to_dict(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return finding if isinstance(finding, dict) else {}


def _text(finding: dict[str, Any]) -> str:
    parts = []
    for key in (
        "rule_id", "category", "severity", "confidence", "source",
        "file_path", "source_file", "line_number", "match_type", "title",
        "secret_preview", "evidence_snippet", "summary", "raw",
    ):
        value = finding.get(key)
        if value not in (None, ""):
            parts.append(str(value))
    metadata = finding.get("metadata")
    if metadata:
        parts.append(str(metadata))
    return "\n".join(parts)


def classify_secret_type(finding: Any) -> dict[str, str]:
    """Classify provider/type from rule id, preview, and surrounding text."""
    data = _to_dict(finding)
    haystack = _text(data)
    lower = haystack.lower()
    for type_id, hints, provider, validation_hint in TYPE_HINTS:
        for hint in hints:
            if hint.lower() in lower:
                return {
                    "type": type_id,
                    "provider": provider,
                    "validation_hint": validation_hint,
                }
    return {
        "type": "generic-secret",
        "provider": "Unknown",
        "validation_hint": "Identify the provider and target-owned context from surrounding code, endpoint, file path, or bundle provenance before live validation.",
    }


def triage_secret_finding(finding: Any) -> dict[str, Any]:
    """Return deterministic triage metadata and next action for a secret hit."""
    data = _to_dict(finding)
    haystack = _text(data)
    classified = classify_secret_type(data)

    confidence = str(data.get("confidence", "") or "").lower()
    source = str(data.get("source", "") or "").lower()
    rule_id = str(data.get("rule_id", "") or "")
    file_path = str(data.get("file_path") or data.get("source_file") or "")
    line_number = data.get("line_number")
    source_ref = f"{file_path}:{line_number}" if file_path and line_number else file_path

    has_source = bool(source_ref or data.get("evidence_snippet") or data.get("raw"))
    has_target_context = bool(TARGET_CONTEXT_HINTS.search(haystack))
    has_validity = bool(VALIDITY_HINTS.search(haystack)) or source == "trufflehog" and "verified" in haystack.lower()
    high_signal = confidence in {"high", "confirmed"} or classified["type"] not in {"generic-secret", "generic-api-key", "password-config"}
    side_effect_risk = bool(SIDE_EFFECT_RISK_HINTS.search(haystack))

    if has_validity and has_target_context:
        candidate_status = "candidate-ready"
    elif high_signal and has_source:
        candidate_status = "needs-safe-verification"
    else:
        candidate_status = "context-needed"

    if side_effect_risk:
        verification_safety = "manual-review"
    elif classified["type"] in {"stripe-key", "private-key", "password-config"}:
        verification_safety = "bounded-manual-or-readonly"
    else:
        verification_safety = "minimal-readonly-check"

    missing: list[str] = []
    if not has_source:
        missing.append("exact source artifact/line")
    if not has_target_context:
        missing.append("target ownership/context")
    if not has_validity:
        missing.append("validity/usability evidence or safe-verification blocker")
    if candidate_status != "candidate-ready":
        missing.append("concrete impact path")

    next_action = classified["validation_hint"]
    if not has_target_context:
        next_action = (
            "First map target ownership/context from source path, bundle provenance, "
            "domain strings, repo/org names, and environment naming; then " + next_action
        )
    elif not has_validity:
        next_action = classified["validation_hint"]
    else:
        next_action = "Document provider identity, scope, target ownership, and impact path; then move to /validate if evidence is reproducible."

    return {
        "type": classified["type"],
        "provider": classified["provider"],
        "rule_id": rule_id,
        "source_ref": source_ref,
        "confidence": confidence or "unknown",
        "verification_safety": verification_safety,
        "candidate_status": candidate_status,
        "high_signal": high_signal,
        "has_source": has_source,
        "has_target_context": has_target_context,
        "has_validity": has_validity,
        "missing": missing,
        "next_action": next_action,
        "summary": (
            f"{classified['type']} via {source_ref or 'unknown-source'}: "
            f"{candidate_status}, safety={verification_safety}"
        ),
    }


def compact_secret_triage(triage: dict[str, Any]) -> dict[str, Any]:
    """Compact shape suitable for repo finding metadata."""
    return {
        "type": str(triage.get("type", "")),
        "provider": str(triage.get("provider", "")),
        "source_ref": str(triage.get("source_ref", "")),
        "verification_safety": str(triage.get("verification_safety", "")),
        "candidate_status": str(triage.get("candidate_status", "")),
        "missing": [str(item) for item in (triage.get("missing") or [])[:4]],
        "next_action": str(triage.get("next_action", "")),
        "summary": str(triage.get("summary", "")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage secret/key findings and suggest minimal safe validation.")
    parser.add_argument("--file", required=True, help="JSON file containing one finding or a list of findings.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    args = parser.parse_args(argv)

    with open(args.file, encoding="utf-8") as handle:
        payload = json.load(handle)
    findings = payload if isinstance(payload, list) else [payload]
    triaged = [triage_secret_finding(item) for item in findings if isinstance(item, dict)]

    if args.json:
        print(json.dumps(triaged, ensure_ascii=False, indent=2))
        return 0

    for item in triaged:
        print(item["summary"])
        if item.get("missing"):
            print(f"- Missing: {', '.join(item['missing'])}")
        print(f"- Next: {item.get('next_action', '')}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
