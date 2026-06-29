#!/usr/bin/env python3
"""High-value candidate evidence rubric.

This module only identifies evidence gaps and suggests next steps.  It does
not block exploration: the agent can keep hunting, fill missing evidence,
downgrade to a signal, or continue to validation/report when appropriate.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceRequirement:
    """One evidence item a candidate should ideally have before validation."""

    id: str
    label: str
    keywords: tuple[str, ...]
    next_action: str


@dataclass(frozen=True)
class EvidenceRubric:
    """Minimum candidate evidence model for one vulnerability family."""

    id: str
    title: str
    requirements: tuple[EvidenceRequirement, ...]


def _req(req_id: str, label: str, keywords: tuple[str, ...], next_action: str) -> EvidenceRequirement:
    return EvidenceRequirement(req_id, label, keywords, next_action)


RUBRICS: dict[str, EvidenceRubric] = {
    "authz": EvidenceRubric(
        id="authz",
        title="Authz / IDOR / Access-control candidate evidence",
        requirements=(
            _req(
                "actor_object_diff",
                "actor / role / object boundary difference",
                (
                    "actor", "role", "user a", "user b", "attacker", "victim",
                    "owner", "other user", "other-user", "cross account",
                    "cross-account", "tenant", "org", "workspace", "role diff",
                ),
                "Build a two-actor or two-role replay: baseline as owner, then replay the same object/action as non-owner or lower-privileged actor.",
            ),
            _req(
                "exact_request",
                "exact replayable request",
                (
                    "request", "curl", "http", "method", "header", "body",
                    "replay", "endpoint", "burp", "browser evidence",
                ),
                "Capture the exact method, URL, headers, body, auth context, and replay command for the candidate request.",
            ),
            _req(
                "response_or_action_delta",
                "observable response/data/action difference",
                (
                    "private data", "pii", "403", "401", "200", "unauthorized",
                    "forbidden", "response diff", "status diff", "action completed",
                    "other user's", "cross-tenant", "data exposure", "privilege",
                ),
                "Compare owner vs non-owner responses and record the smallest stable status/body/data/action difference.",
            ),
            _req(
                "business_impact",
                "target-owned business impact",
                (
                    "impact", "invoice", "billing", "payment", "order", "export",
                    "admin", "account takeover", "ato", "email", "token",
                    "workspace", "organization", "sensitive",
                ),
                "Tie the diff to concrete target-owned impact: data exposed, privileged action, tenant escape, or account/workflow consequence.",
            ),
        ),
    ),
    "sqli": EvidenceRubric(
        id="sqli",
        title="SQLi / NoSQLi candidate evidence",
        requirements=(
            _req(
                "input_and_baseline",
                "input surface plus baseline/perturbation pair",
                (
                    "baseline", "control", "single variable", "single-variable",
                    "perturb", "parameter", "param", "query", "body", "header",
                    "cookie", "path", "payload", "quote", "injection",
                ),
                "Replay a clean baseline and one controlled single-variable perturbation on the same input surface.",
            ),
            _req(
                "stable_differential_signal",
                "stable SQL/NoSQL differential signal",
                (
                    "sql syntax", "mysql", "postgres", "postgresql", "oracle",
                    "sqlite", "mssql", "mongodb", "nosql", "boolean", "time delay",
                    "delay", "length diff", "status diff", "db error", "syntax error",
                    "sqli-poc-verified", "verified",
                ),
                "Record a reproducible error/boolean/time/status/length/data-shape difference and repeat it enough to rule out routing/WAF noise.",
            ),
            _req(
                "reproducibility",
                "reproducible and deterministic behavior",
                (
                    "reproduced", "repeat", "stable", "deterministic", "3/3",
                    "2/2", "consistent", "confirmed", "verified",
                ),
                "Repeat the baseline-vs-perturbation pair and keep only stable differences as candidate evidence.",
            ),
            _req(
                "safe_impact",
                "safe read-only impact proof",
                (
                    "db fingerprint", "database", "table", "row count", "read-only",
                    "controlled marker", "non-destructive", "no destructive",
                    "sqli-poc-verified", "data exposure",
                ),
                "If needed, prove impact with the smallest read-only DBMS/data-shape marker; do not modify or bulk-extract target data.",
            ),
        ),
    ),
    "ssrf": EvidenceRubric(
        id="ssrf",
        title="SSRF candidate evidence",
        requirements=(
            _req(
                "controlled_fetch",
                "controlled server-side fetch/callback proof",
                (
                    "oast", "interactsh", "collaborator", "callback", "dns",
                    "http callback", "server-side request", "server side request",
                    "blind ssrf", "fetch", "webhook",
                ),
                "Use a controlled callback/OAST or known safe URL to prove the server performs the fetch.",
            ),
            _req(
                "server_side_context",
                "server-side context evidence",
                (
                    "source ip", "user-agent", "user agent", "response body",
                    "metadata", "169.254", "localhost", "internal", "redirect followed",
                    "outbound", "egress",
                ),
                "Capture source IP/header/body/redirect behavior that distinguishes server-side fetch from client-side/browser behavior.",
            ),
            _req(
                "impact_boundary",
                "internal/metadata/target-owned impact path",
                (
                    "internal service", "cloud metadata", "metadata service",
                    "credential", "admin panel", "target-owned", "read-only",
                    "safe proof", "intranet", "localhost",
                ),
                "Show a safe target-owned impact path such as internal metadata/service reachability or protected content access.",
            ),
            _req(
                "exact_request",
                "exact replayable request",
                ("request", "curl", "http", "method", "header", "body", "endpoint", "replay"),
                "Capture the exact request that injects the URL/host and the observed callback/response evidence.",
            ),
        ),
    ),
    "code-exec": EvidenceRubric(
        id="code-exec",
        title="RCE / SSTI / command injection / deserialization candidate evidence",
        requirements=(
            _req(
                "inert_marker",
                "inert marker or safe calculation",
                (
                    "marker", "safe calculation", "calculation", "computed",
                    "template expression", "ssti-confirmed", "rce-poc",
                    "command output", "inert",
                ),
                "Prove evaluation/execution with an inert marker or safe calculation before any broader exploit chain.",
            ),
            _req(
                "execution_context",
                "execution/evaluation context",
                (
                    "template rendered", "stack trace", "stderr", "stdout",
                    "process", "user", "working directory", "deserialization",
                    "gadget", "sandbox", "environment",
                ),
                "Record what context executed/evaluated the marker: template engine, process boundary, error path, or deserialization sink.",
            ),
            _req(
                "exact_request",
                "exact replayable request",
                ("request", "curl", "http", "method", "header", "body", "endpoint", "replay", "payload"),
                "Capture the exact request/body/file that triggers the safe marker.",
            ),
            _req(
                "safe_impact",
                "bounded impact proof",
                (
                    "read-only", "non-destructive", "no destructive", "safe proof",
                    "controlled marker", "no persistent", "rce-poc", "ssti-confirmed",
                ),
                "Keep proof bounded to safe marker/output and document the realistic impact path without destructive commands.",
            ),
        ),
    ),
    "upload": EvidenceRubric(
        id="upload",
        title="Upload / parser / file-flow candidate evidence",
        requirements=(
            _req(
                "upload_accepted",
                "upload accepted with controlled file metadata",
                (
                    "upload accepted", "multipart", "filename", "content-type",
                    "file id", "file_id", "stored", "accepted", "201", "200",
                ),
                "Capture the upload request and response proving the controlled file is accepted/stored.",
            ),
            _req(
                "parser_or_storage_path",
                "parser/storage/render/download transition",
                (
                    "storage path", "download", "preview", "render", "thumbnail",
                    "parser", "transform", "metadata", "public url", "file url",
                ),
                "Follow the file through storage, parser, preview, render, or download endpoints and record each transition.",
            ),
            _req(
                "impact_transition",
                "execution/read/SSRF/XXE/path impact transition",
                (
                    "executable", "interpreted", "xxe", "ssrf", "path traversal",
                    "lfi", "rce", "html render", "stored file accessible",
                    "content sniff", "polyglot",
                ),
                "Prove the concrete transition from upload to executable/readable/parser-impact behavior with the smallest safe artifact.",
            ),
            _req(
                "safe_proof",
                "bounded non-destructive proof",
                ("read-only", "non-destructive", "safe proof", "controlled marker", "no destructive"),
                "Use a harmless marker/file and avoid persistent harmful payloads or target data modification.",
            ),
        ),
    ),
    "secret": EvidenceRubric(
        id="secret",
        title="Secret / key exposure candidate evidence",
        requirements=(
            _req(
                "type_and_source",
                "secret type plus exact source artifact/line",
                (
                    "aws", "github", "slack", "stripe", "token", "api key",
                    "private key", "client secret", "password", "source file",
                    "line", "artifact", "js bundle", "repo", "secret_triage",
                ),
                "Classify the secret type/provider and preserve exact source artifact, line, and masked preview.",
            ),
            _req(
                "ownership_context",
                "target-owned ownership/context",
                (
                    "target-owned", "domain", "org", "organization", "repo",
                    "account", "environment", "production", "staging", "bundle",
                    "owned", "workspace",
                ),
                "Map the hit to target ownership: domain, repo/org, app environment, bundle provenance, or account identity.",
            ),
            _req(
                "validity_usability",
                "validity/usability or explicit safe-verification blocker",
                (
                    "verified", "valid", "auth success", "identity", "scope",
                    "permission", "usable", "unexpired", "needs-verification",
                    "verification blocker",
                ),
                "Run or record the minimal safe provider identity/scope check, or document why only manual verification is possible.",
            ),
            _req(
                "impact_path",
                "concrete security impact path",
                (
                    "read data", "repo access", "cloud access", "deploy", "ci",
                    "signing", "billing", "admin", "account takeover", "ato",
                    "data exposure", "permission", "scope",
                ),
                "Tie the key to a concrete impact path such as repo/cloud/data access, deployment, signing, or account/workflow control.",
            ),
        ),
    ),
    "file-read": EvidenceRubric(
        id="file-read",
        title="XXE / LFI / path traversal candidate evidence",
        requirements=(
            _req(
                "controlled_read",
                "controlled file/entity/read-only proof",
                (
                    "xxe", "entity", "file read", "local file", "lfi",
                    "path traversal", "traversal", "include", "read-only",
                    "controlled read",
                ),
                "Use a controlled read-only proof and record the exact file/entity/path transformation.",
            ),
            _req(
                "baseline_diff",
                "normal baseline vs traversal/entity variant",
                (
                    "baseline", "normal file", "variant", "diff", "status diff",
                    "length diff", "response diff", "encoded", "double encoded",
                ),
                "Compare a normal baseline with one traversal/entity variant and keep the stable diff.",
            ),
            _req(
                "boundary_impact",
                "target-owned readable boundary/impact",
                (
                    "config", "source", "metadata", "secret", "credential",
                    "target-owned", "read-only", "safe proof", "data exposure",
                ),
                "Show why the read crosses a sensitive boundary without bulk harvesting target data.",
            ),
            _req(
                "exact_request",
                "exact replayable request",
                ("request", "curl", "http", "method", "header", "body", "endpoint", "replay", "payload"),
                "Capture the exact request/payload that triggers the read-only proof.",
            ),
        ),
    ),
    "known-software": EvidenceRubric(
        id="known-software",
        title="Known software / CVE applicability candidate evidence",
        requirements=(
            _req(
                "component_version",
                "component/product/plugin/theme and version",
                (
                    "component", "product", "plugin", "theme", "version",
                    "wordpress", "library", "framework", "service",
                ),
                "Identify exact component/product/plugin/theme/library version and where it was observed.",
            ),
            _req(
                "advisory_mapping",
                "advisory/CVE affected range mapping",
                (
                    "cve", "advisory", "affected", "vulnerable range",
                    "fixed version", "patch", "exploit-db", "nvd",
                ),
                "Map the observed version to a specific advisory/CVE affected range and fixed version.",
            ),
            _req(
                "reachability",
                "reachable feature/route/precondition",
                (
                    "reachable", "route", "endpoint", "feature enabled",
                    "plugin active", "unauth", "authenticated", "precondition",
                ),
                "Verify the vulnerable feature/route/precondition is reachable in this target.",
            ),
            _req(
                "safe_poc",
                "safe non-destructive applicability proof",
                (
                    "safe poc", "non-destructive", "read-only", "exact request",
                    "response marker", "confirmed", "verified", "poc",
                ),
                "Run the smallest non-destructive applicability proof before promoting to candidate.",
            ),
        ),
    ),
    "generic": EvidenceRubric(
        id="generic",
        title="Generic candidate evidence",
        requirements=(
            _req(
                "exact_request",
                "exact replayable request or browser flow",
                ("request", "curl", "http", "browser", "flow", "method", "endpoint", "replay"),
                "Capture the exact request or browser flow needed to reproduce the signal.",
            ),
            _req(
                "reproducible_diff",
                "reproducible behavior difference",
                ("baseline", "diff", "reproduced", "stable", "deterministic", "confirmed", "verified"),
                "Create a baseline-vs-variant comparison and keep only reproducible behavior differences.",
            ),
            _req(
                "impact",
                "concrete target-owned impact",
                ("impact", "data exposure", "privilege", "account", "admin", "sensitive", "business"),
                "Tie the behavior to concrete target-owned security impact.",
            ),
        ),
    ),
}


ALIASES = {
    "idor": "authz",
    "authz": "authz",
    "auth": "authz",
    "auth-bypass": "authz",
    "auth_bypass": "authz",
    "access-control": "authz",
    "access_control": "authz",
    "business-logic": "authz",
    "business_logic": "authz",
    "mfa": "authz",
    "saml": "authz",
    "oauth": "authz",
    "jwt": "authz",
    "reset": "authz",
    "sqli": "sqli",
    "sql": "sqli",
    "sql-injection": "sqli",
    "sql injection": "sqli",
    "nosqli": "sqli",
    "nosql": "sqli",
    "ssrf": "ssrf",
    "rce": "code-exec",
    "ssti": "code-exec",
    "command-injection": "code-exec",
    "command_injection": "code-exec",
    "deserialization": "code-exec",
    "insecure-deserialization": "code-exec",
    "upload": "upload",
    "file-upload": "upload",
    "secret": "secret",
    "secrets": "secret",
    "key": "secret",
    "credential": "secret",
    "exposure": "secret",
    "xxe": "file-read",
    "lfi": "file-read",
    "rfi": "file-read",
    "path-traversal": "file-read",
    "path_traversal": "file-read",
    "file-read": "file-read",
    "file_read": "file-read",
    "cve": "known-software",
    "known-software": "known-software",
}

STRONG_EVIDENCE_MARKERS = (
    "SQLI-POC-VERIFIED",
    "SSTI-CONFIRMED",
    "RCE-POC",
    "SAML-SIG-STRIP",
    "confirmed exploit",
    "verified poc",
)

SECRET_HINT_RE = re.compile(
    r"\b(secret|token|api[_ -]?key|client[_ -]?secret|password|private key|aws|github|stripe|slack)\b",
    re.I,
)


def normalize_vuln_type(vuln_type: str, *, text: str = "") -> str:
    """Normalize scanner/tool labels to one rubric family."""
    raw = str(vuln_type or "").strip().lower().replace("_", "-")
    raw = re.sub(r"\s+", " ", raw)
    if raw in ALIASES:
        return ALIASES[raw]
    dashed = raw.replace(" ", "-")
    if dashed in ALIASES:
        return ALIASES[dashed]
    if raw == "exposure" and not SECRET_HINT_RE.search(text or ""):
        return "generic"
    if SECRET_HINT_RE.search(" ".join([raw, text or ""])):
        return "secret"
    return "generic"


def rubric_for(vuln_type: str, *, text: str = "") -> EvidenceRubric:
    """Return the best rubric for a vulnerability type and optional evidence text."""
    family = normalize_vuln_type(vuln_type, text=text)
    return RUBRICS.get(family, RUBRICS["generic"])


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def candidate_evidence_text(finding: Any) -> str:
    """Build a searchable evidence string from a finding-like object."""
    if hasattr(finding, "to_dict"):
        finding = finding.to_dict()
    if not isinstance(finding, dict):
        return _stringify(finding)

    fields = [
        "type", "category", "rule_id", "title", "summary", "url",
        "source_file", "file_path", "line_number", "template_id", "raw",
        "confidence", "severity", "validation_status", "evidence_snippet",
        "secret_preview", "match_type", "source",
    ]
    parts = [_stringify(finding.get(field)) for field in fields if finding.get(field) not in (None, "")]
    metadata = finding.get("metadata")
    if metadata:
        parts.append(_stringify(metadata))
    return "\n".join(parts)


def _is_satisfied(req: EvidenceRequirement, haystack: str) -> bool:
    lower = haystack.lower()
    return any(keyword.lower() in lower for keyword in req.keywords)


def _has_strong_evidence(haystack: str, finding: dict | None = None) -> bool:
    lower = haystack.lower()
    if any(marker.lower() in lower for marker in STRONG_EVIDENCE_MARKERS):
        return True
    if finding:
        confidence = str(finding.get("confidence", "") or "").lower()
        raw = str(finding.get("raw", "") or finding.get("summary", "") or "").lower()
        if confidence == "confirmed" and any(token in raw for token in ("poc", "verified", "confirmed")):
            return True
    return False


def evaluate_candidate_evidence(finding: Any, *, vuln_type: str = "") -> dict[str, Any]:
    """Evaluate a finding-like object against the relevant candidate rubric.

    The return value is a soft signal: ``ready=False`` means the agent should
    fill evidence or downgrade to a signal, not that exploration must stop.
    """
    finding_dict = finding.to_dict() if hasattr(finding, "to_dict") else finding
    finding_dict = finding_dict if isinstance(finding_dict, dict) else {}
    haystack = candidate_evidence_text(finding)
    resolved_type = vuln_type or str(
        finding_dict.get("type")
        or finding_dict.get("category")
        or finding_dict.get("rule_id")
        or ""
    )
    rubric = rubric_for(resolved_type, text=haystack)

    satisfied: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    next_actions: list[str] = []
    for requirement in rubric.requirements:
        item = {"id": requirement.id, "label": requirement.label}
        if _is_satisfied(requirement, haystack):
            satisfied.append(item)
        else:
            missing.append(item)
            next_actions.append(requirement.next_action)

    strong = _has_strong_evidence(haystack, finding_dict)
    total = len(rubric.requirements)
    satisfied_count = len(satisfied)
    missing_count = len(missing)
    ready = missing_count == 0 or (strong and satisfied_count >= max(1, total - 1))
    if ready:
        status = "candidate-ready"
    elif satisfied_count == 0:
        status = "signal-only"
    else:
        status = "needs-evidence"

    score = max(0, min(100, int((satisfied_count / max(1, total)) * 100) + (10 if strong else 0)))
    if ready:
        score = max(score, 90)

    missing_labels = [item["label"] for item in missing]
    summary = (
        f"{rubric.id}:{status} score={score} "
        f"satisfied={satisfied_count}/{total}"
    )
    if missing_labels:
        summary += " missing=" + "; ".join(missing_labels[:3])

    return {
        "rubric_id": rubric.id,
        "title": rubric.title,
        "status": status,
        "ready": ready,
        "score": score,
        "satisfied_count": satisfied_count,
        "total": total,
        "satisfied": satisfied,
        "missing": missing,
        "missing_labels": missing_labels,
        "next_actions": next_actions[:4],
        "strong_evidence": strong,
        "summary": summary,
    }


def compact_evidence_rubric(evaluation: dict[str, Any], *, missing_limit: int = 3) -> dict[str, Any]:
    """Return a compact JSON-safe rubric summary for state/context output."""
    if not evaluation:
        return {}
    return {
        "rubric_id": evaluation.get("rubric_id", ""),
        "status": evaluation.get("status", ""),
        "ready": bool(evaluation.get("ready", False)),
        "score": int(evaluation.get("score", 0) or 0),
        "satisfied_count": int(evaluation.get("satisfied_count", 0) or 0),
        "total": int(evaluation.get("total", 0) or 0),
        "missing": [
            str(item.get("id") or item.get("label") or "")
            for item in (evaluation.get("missing") or [])[:missing_limit]
            if isinstance(item, dict)
        ],
        "missing_labels": [
            str(item) for item in (evaluation.get("missing_labels") or [])[:missing_limit]
        ],
        "next_actions": [
            str(item) for item in (evaluation.get("next_actions") or [])[:missing_limit]
        ],
        "summary": str(evaluation.get("summary") or ""),
    }


def first_missing_action(evaluation: dict[str, Any]) -> str:
    """Return the highest-priority evidence action for a missing rubric item."""
    for action in evaluation.get("next_actions") or []:
        clean = str(action or "").strip()
        if clean:
            return clean
    return ""
