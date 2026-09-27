#!/usr/bin/env python3
"""
HackerOne Report Generator
Generates formatted bug bounty reports from scan findings.

Usage:
    python3 report_generator.py <findings_dir>
    python3 report_generator.py --finding <finding_file> --type <vuln_type>
    python3 report_generator.py --manual --type xss --url <url> --param <param>
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from finding_index import _finding_backend_context
    from target_paths import target_storage_key
    from target_store import ConflictError, StoreError, TargetStore, runtime_store, target_mutation_lock, target_switch_lock
except ImportError:  # pragma: no cover - package import path
    from tools.finding_index import _finding_backend_context
    from tools.target_paths import target_storage_key
    from tools.target_store import ConflictError, StoreError, TargetStore, runtime_store, target_mutation_lock, target_switch_lock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def _write_text_atomic(path: str | Path, content: str) -> None:
    """Replace one report index file without exposing a partial document."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(destination)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


# Severity mappings
SEVERITY_MAP = {
    "critical": {"cvss_range": "9.0-10.0", "color": "CRITICAL"},
    "high": {"cvss_range": "7.0-8.9", "color": "HIGH"},
    "medium": {"cvss_range": "4.0-6.9", "color": "MEDIUM"},
    "low": {"cvss_range": "0.1-3.9", "color": "LOW"},
    "info": {"cvss_range": "0.0", "color": "INFO"},
}

# Report templates by vulnerability type
VULN_TEMPLATES = {
    "xss": {
        "title": "Cross-Site Scripting (XSS) on {domain}",
        "severity": "medium",
        "impact": (
            "An attacker can execute arbitrary JavaScript in the context of the victim's browser session. "
            "This can lead to session hijacking, credential theft, defacement, or redirection to malicious sites. "
            "If the affected user is an administrator, this could lead to full account takeover."
        ),
        "remediation": (
            "1. Implement proper output encoding/escaping for all user-supplied input\n"
            "2. Use Content-Security-Policy (CSP) headers to restrict script execution\n"
            "3. Enable HttpOnly and Secure flags on session cookies\n"
            "4. Use a templating engine that auto-escapes by default"
        ),
        "cwe": "CWE-79",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    },
    "takeover": {
        "title": "Subdomain Takeover on {domain}",
        "severity": "high",
        "impact": (
            "The subdomain points to a third-party service that is no longer claimed. "
            "An attacker can claim this service and serve arbitrary content on the subdomain. "
            "This enables phishing attacks, cookie theft (if parent domain cookies are scoped broadly), "
            "and can bypass Content-Security-Policy restrictions."
        ),
        "remediation": (
            "1. Remove the dangling DNS record (CNAME/A) pointing to the unclaimed service\n"
            "2. If the service is still needed, reclaim it on the third-party platform\n"
            "3. Audit all DNS records for similar dangling references\n"
            "4. Implement monitoring for subdomain takeover conditions"
        ),
        "cwe": "CWE-284",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
            "https://github.com/EdOverflow/can-i-take-over-xyz"
        ]
    },
    "cors": {
        "title": "CORS Misconfiguration on {domain}",
        "severity": "medium",
        "impact": (
            "The application reflects arbitrary origins in the Access-Control-Allow-Origin header "
            "with Access-Control-Allow-Credentials: true. This allows an attacker to read sensitive "
            "data from authenticated API responses via a malicious website."
        ),
        "remediation": (
            "1. Implement a strict whitelist of allowed origins\n"
            "2. Never reflect the Origin header value directly\n"
            "3. Avoid using Access-Control-Allow-Credentials: true with wildcard origins\n"
            "4. Validate the Origin header against a known list of trusted domains"
        ),
        "cwe": "CWE-942",
        "references": [
            "https://portswigger.net/web-security/cors",
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
        ]
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF) on {domain}",
        "severity": "high",
        "impact": (
            "An attacker can make the server perform requests to arbitrary internal or external resources. "
            "This can be used to scan internal networks, access cloud metadata endpoints (e.g., AWS IMDSv1 at 169.254.169.254), "
            "read internal services, or bypass firewall restrictions."
        ),
        "remediation": (
            "1. Implement a strict allowlist of permitted URLs/domains\n"
            "2. Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)\n"
            "3. Disable unnecessary URL schemes (file://, gopher://, dict://)\n"
            "4. Use a dedicated egress proxy for outbound requests\n"
            "5. Enable IMDSv2 on cloud instances to prevent metadata access"
        ),
        "cwe": "CWE-918",
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://portswigger.net/web-security/ssrf"
        ]
    },
    "redirect": {
        "title": "Open Redirect on {domain}",
        "severity": "low",
        "impact": (
            "An attacker can craft a URL that redirects victims to a malicious website. "
            "This can be used for phishing (the URL appears to come from a trusted domain), "
            "OAuth token theft, or as a component in chained attacks."
        ),
        "remediation": (
            "1. Avoid user-controlled redirect destinations\n"
            "2. If redirects are necessary, use a whitelist of allowed destinations\n"
            "3. Use relative paths instead of full URLs for internal redirects\n"
            "4. Display a warning page before redirecting to external domains"
        ),
        "cwe": "CWE-601",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"
        ]
    },
    "exposure": {
        "title": "Sensitive Data Exposure on {domain}",
        "severity": "medium",
        "impact": (
            "Sensitive files or information are publicly accessible. Depending on the exposed data, "
            "this could reveal source code (.git), environment variables (.env), database credentials, "
            "API keys, or internal configuration that aids further attacks."
        ),
        "remediation": (
            "1. Remove or restrict access to exposed sensitive files\n"
            "2. Configure web server to deny access to hidden files/directories (.*)\n"
            "3. Review deployment process to prevent accidental file exposure\n"
            "4. Rotate any credentials that may have been exposed\n"
            "5. Add these paths to .gitignore and web server deny rules"
        ),
        "cwe": "CWE-200",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
        ]
    },
    "cve": {
        "title": "Known CVE ({cve_id}) on {domain}",
        "severity": "high",
        "impact": (
            "The application is running a version of software with a known vulnerability. "
            "Impact depends on the specific CVE — see references for details."
        ),
        "remediation": (
            "1. Update the affected software to the latest patched version\n"
            "2. If immediate patching is not possible, apply vendor-recommended mitigations\n"
            "3. Monitor for exploitation attempts via WAF/IDS rules"
        ),
        "cwe": "CWE-1035",
        "references": []
    },
    "misconfig": {
        "title": "Security Misconfiguration on {domain}",
        "severity": "medium",
        "impact": (
            "The application or server has a security misconfiguration that could be exploited. "
            "This may include missing security headers, verbose error messages, default configurations, "
            "or unnecessary features/services enabled."
        ),
        "remediation": (
            "1. Review and harden server/application configuration\n"
            "2. Implement all recommended security headers\n"
            "3. Disable verbose error messages in production\n"
            "4. Remove default/sample pages and credentials\n"
            "5. Follow vendor security hardening guides"
        ),
        "cwe": "CWE-16",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR) on {domain}",
        "severity": "high",
        "impact": (
            "An attacker can access or modify resources belonging to other users by manipulating "
            "object references (IDs, filenames, keys) in API requests. This can lead to unauthorized "
            "access to user data, account takeover, or data manipulation."
        ),
        "remediation": (
            "1. Implement proper authorization checks on every resource access\n"
            "2. Use indirect references (UUIDs) instead of sequential IDs\n"
            "3. Validate that the authenticated user owns the requested resource\n"
            "4. Apply the principle of least privilege for all API endpoints"
        ),
        "cwe": "CWE-639",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://portswigger.net/web-security/access-control/idor"
        ]
    },
    "auth_bypass": {
        "title": "Authentication/Authorization Bypass on {domain}",
        "severity": "critical",
        "impact": (
            "An attacker can bypass authentication or authorization controls to access protected "
            "resources or functionality. This may allow unauthenticated access to admin panels, "
            "API endpoints, or user data without proper credentials."
        ),
        "remediation": (
            "1. Enforce authentication on all protected endpoints\n"
            "2. Implement server-side authorization checks (not client-side)\n"
            "3. Use a centralized authentication/authorization middleware\n"
            "4. Deny by default — explicitly allow access only where needed\n"
            "5. Test all HTTP methods (GET, POST, PUT, DELETE) for each endpoint"
        ),
        "cwe": "CWE-287",
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        ]
    },
    "info_disclosure": {
        "title": "Information Disclosure on {domain}",
        "severity": "high",
        "impact": (
            "Sensitive internal information is exposed to unauthenticated users. This may include "
            "production configuration, internal service URLs, API tokens, SSO endpoints, employee data, "
            "or infrastructure details that aid further targeted attacks."
        ),
        "remediation": (
            "1. Remove or restrict access to configuration files (env.js, app_env.js)\n"
            "2. Move sensitive config to server-side environment variables\n"
            "3. Strip internal headers (X-Backend-Host, X-Powered-By) from responses\n"
            "4. Remove developer comments from production HTML\n"
            "5. Rotate any exposed credentials or tokens"
        ),
        "cwe": "CWE-200",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
            "https://cwe.mitre.org/data/definitions/497.html"
        ]
    }
}

VULN_TEMPLATES.update({
    "rce": {
        "title": "Remote Code Execution on {domain}",
        "severity": "critical",
        "impact": (
            "An attacker can execute attacker-controlled code or commands on the affected server. "
            "This can lead to service takeover, data theft, lateral movement, or complete compromise of "
            "the application environment."
        ),
        "remediation": (
            "1. Remove direct execution of user-controlled input\n"
            "2. Use fixed command allowlists and safe process APIs where execution is unavoidable\n"
            "3. Run application services with least privilege\n"
            "4. Add regression tests for the affected input and execution path"
        ),
        "cwe": "CWE-78",
        "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
    },
    "deserialization": {
        "title": "Unsafe Deserialization on {domain}",
        "severity": "critical",
        "impact": (
            "Attacker-controlled serialized data is processed by an unsafe deserializer. Depending on the "
            "available gadget chains and application behavior, this can lead to code execution, privilege "
            "escalation, or tampering with trusted application state."
        ),
        "remediation": (
            "1. Do not deserialize untrusted native object formats\n"
            "2. Use data-only formats with strict schemas\n"
            "3. Authenticate and integrity-protect any serialized state\n"
            "4. Apply allowlists and update vulnerable serialization libraries"
        ),
        "cwe": "CWE-502",
        "references": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
    },
    "xxe": {
        "title": "XML External Entity Injection on {domain}",
        "severity": "high",
        "impact": (
            "An attacker can cause the XML parser to resolve external entities. This may expose local files, "
            "reach internal services, or enable denial of service depending on parser and network settings."
        ),
        "remediation": (
            "1. Disable DTDs and external entity resolution\n"
            "2. Use hardened XML parser settings for every parser instance\n"
            "3. Prefer data formats that do not support external entities\n"
            "4. Add parser configuration regression tests"
        ),
        "cwe": "CWE-611",
        "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    },
    "path_traversal": {
        "title": "Path Traversal on {domain}",
        "severity": "high",
        "impact": (
            "An attacker can influence a filesystem path outside the intended directory. This may expose "
            "sensitive files, alter application data, or create a path to server-side code execution."
        ),
        "remediation": (
            "1. Resolve paths against a fixed base directory\n"
            "2. Reject traversal sequences and absolute paths after canonicalization\n"
            "3. Use opaque server-side file identifiers instead of user-supplied paths\n"
            "4. Test encoded and platform-specific path variants"
        ),
        "cwe": "CWE-22",
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    "csrf": {
        "title": "Cross-Site Request Forgery on {domain}",
        "severity": "medium",
        "impact": (
            "A third-party site can cause an authenticated browser to perform an unintended state-changing "
            "request. Impact depends on the protected action and may include account or data changes."
        ),
        "remediation": (
            "1. Require server-validated, session-bound anti-CSRF tokens\n"
            "2. Enforce SameSite cookies where compatible\n"
            "3. Validate Origin or Referer on sensitive requests\n"
            "4. Require re-authentication for high-impact actions"
        ),
        "cwe": "CWE-352",
        "references": ["https://owasp.org/www-community/attacks/csrf"],
    },
    "business_logic": {
        "title": "Business Logic Flaw on {domain}",
        "severity": "high",
        "impact": (
            "An attacker can violate an intended workflow or business invariant. Depending on the affected "
            "operation, this can enable unauthorized state changes, financial loss, or access beyond the "
            "intended product rules."
        ),
        "remediation": (
            "1. Enforce workflow invariants server-side\n"
            "2. Validate state transitions, ownership, and limits on every request\n"
            "3. Make sensitive operations idempotent where appropriate\n"
            "4. Add end-to-end tests for invalid transition sequences"
        ),
        "cwe": "CWE-840",
        "references": ["https://cwe.mitre.org/data/definitions/840.html"],
    },
    "race": {
        "title": "Race Condition on {domain}",
        "severity": "high",
        "impact": (
            "Concurrent requests can violate an intended state transition or limit. This may lead to duplicate "
            "actions, inconsistent records, unauthorized balances, or bypassed business controls."
        ),
        "remediation": (
            "1. Make the state transition atomic in the authoritative datastore\n"
            "2. Use transactions, conditional updates, or locking for contested resources\n"
            "3. Enforce idempotency keys for repeatable operations\n"
            "4. Add concurrent-request regression tests"
        ),
        "cwe": "CWE-362",
        "references": ["https://cwe.mitre.org/data/definitions/362.html"],
    },
    "sqli": {
        "title": "SQL Injection on {domain}",
        "severity": "high",
        "impact": (
            "An attacker may be able to alter backend SQL queries, extract or modify data, "
            "bypass authorization checks, or escalate impact depending on database privileges."
        ),
        "remediation": (
            "1. Use parameterized queries or prepared statements everywhere\n"
            "2. Avoid string concatenation for SQL construction\n"
            "3. Apply least-privilege database accounts\n"
            "4. Add regression tests for the affected parameter"
        ),
        "cwe": "CWE-89",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    "upload": {
        "title": "Unsafe File Upload on {domain}",
        "severity": "high",
        "impact": (
            "An attacker may upload unexpected file types or executable content. If uploaded files "
            "are web-accessible or executed server-side, this can lead to stored content abuse or RCE."
        ),
        "remediation": (
            "1. Enforce server-side extension and MIME allowlists\n"
            "2. Store uploads outside the web root\n"
            "3. Rename uploaded files and strip active content\n"
            "4. Disable script execution in upload directories"
        ),
        "cwe": "CWE-434",
        "references": ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
    },
    "ssti": {
        "title": "Server-Side Template Injection on {domain}",
        "severity": "critical",
        "impact": (
            "Template expressions are evaluated server-side. Depending on the engine, this can lead "
            "to sensitive data disclosure, server-side code execution, or full application compromise."
        ),
        "remediation": (
            "1. Do not render user input as template source\n"
            "2. Use safe template contexts and strict escaping\n"
            "3. Disable dangerous template functions where possible\n"
            "4. Add tests for expression payloads on the affected parameter"
        ),
        "cwe": "CWE-1336",
        "references": ["https://portswigger.net/web-security/server-side-template-injection"],
    },
    "mfa": {
        "title": "MFA Workflow Weakness on {domain}",
        "severity": "medium",
        "impact": (
            "Weak MFA controls may allow attackers to brute-force OTPs, skip verification steps, "
            "or manipulate client-visible verification responses."
        ),
        "remediation": (
            "1. Rate-limit and lock out repeated OTP attempts\n"
            "2. Bind MFA completion to the authenticated server-side session\n"
            "3. Never trust client-side success flags\n"
            "4. Log and alert on repeated failed verification attempts"
        ),
        "cwe": "CWE-287",
        "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    },
    "saml": {
        "title": "SAML/SSO Validation Weakness on {domain}",
        "severity": "high",
        "impact": (
            "Improper SAML validation can allow authentication bypass, account impersonation, "
            "or exposure of identity provider metadata that assists further attacks."
        ),
        "remediation": (
            "1. Require signed assertions/responses as appropriate\n"
            "2. Validate issuer, audience, recipient, and timestamps\n"
            "3. Reject unsigned or modified assertions\n"
            "4. Keep SP/IdP metadata private unless intentionally published"
        ),
        "cwe": "CWE-287",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "jwt": {
        "title": "JWT Validation Weakness on {domain}",
        "severity": "high",
        "impact": (
            "Weak JWT validation can allow attackers to forge token claims, bypass role checks, "
            "or access protected user or administrative data without the intended privileges."
        ),
        "remediation": (
            "1. Reject unsigned tokens and disallow the none algorithm\n"
            "2. Pin the expected signing algorithm server-side\n"
            "3. Verify signatures, issuer, audience, expiry, and role claims on every request\n"
            "4. Keep authorization decisions on the server, not in client-decoded token state"
        ),
        "cwe": "CWE-347",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_JWT",
            "https://portswigger.net/web-security/jwt",
        ],
    },
})

# finding_index 使用 ``authentication_bypass`` 作为 canonical type，而报告模板沿用
# 历史 ``auth_bypass`` key。报告生成是 finding lifecycle 的消费者，必须在这里显式
# 归一，避免有效 finding 被错误落到 misconfig 模板。
REPORT_VULN_TYPE_ALIASES = {
    "authentication_bypass": "auth_bypass",
    "auth_bypass": "auth_bypass",
    "authorization_bypass": "auth_bypass",
    # closure 词汇（validation_runner/closure_resolver 用 Authz 归一）；
    # 词汇统一（310c9ef）后 canonical type 可能为 Authz——报告模板同义。
    "authz": "auth_bypass",
    "authorization": "auth_bypass",
    "access_control": "auth_bypass",
    "remote_code_execution": "rce",
    "command_injection": "rce",
    "os_command_injection": "rce",
    "unsafe_deserialization": "deserialization",
    "deserialisation": "deserialization",
    "xml_external_entity": "xxe",
    "xml_injection": "xxe",
    "pathtraversal": "path_traversal",
    "directory_traversal": "path_traversal",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "xsrf": "csrf",
    "race_condition": "race",
    "toctou": "race",
}


def _report_vuln_type(finding):
    """将结构化 finding 类型归一为受支持的报告模板类型。"""
    raw_type = str(finding.get("type") or finding.get("category") or "misconfig").strip()
    normalized = raw_type.lower().replace("-", "_")
    normalized = REPORT_VULN_TYPE_ALIASES.get(normalized, normalized)
    return normalized if normalized in VULN_TEMPLATES else "misconfig"


def parse_nuclei_line(line):
    """Parse a nuclei output line into structured data."""
    # Nuclei format: [template-id] [protocol] [severity] url [extra-info]
    # Example: [git-config] [http] [medium] https://example.com/.git/config
    parts = line.strip()
    if not parts:
        return None

    result = {
        "raw": parts,
        "template_id": "",
        "severity": "medium",
        "url": "",
        "extra": ""
    }

    # Extract bracketed fields
    brackets = re.findall(r'\[([^\]]+)\]', parts)
    if len(brackets) >= 3:
        result["template_id"] = brackets[0]
        result["severity"] = brackets[2].lower()
    if len(brackets) >= 1:
        result["template_id"] = brackets[0]

    # Extract URL
    url_match = re.search(r'(https?://\S+)', parts)
    if url_match:
        result["url"] = url_match.group(1)

    return result


def extract_domain(url):
    """Extract domain from URL."""
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1) if match else "unknown"


def format_finding_reference(finding):
    """Format optional structured finding metadata for report traceability."""
    references = []
    field_labels = (
        ("id", "Finding ID"),
        ("type", "Claim family"),
        ("source_file", "Source artifact"),
        ("line_number", "Source line"),
        ("confidence", "Confidence"),
        ("summary", "Finding summary"),
    )
    for key, label in field_labels:
        value = finding.get(key)
        if value in (None, ""):
            continue
        references.append(f"- **{label}:** {value}")

    assessment = finding.get("assessment") or {}
    if isinstance(assessment, dict):
        for key, label in (("id", "Assessment"), ("boundary", "Boundary"), ("impact", "Assessed impact")):
            if assessment.get(key):
                references.append(f"- **{label}:** {assessment[key]}")
    for ref in finding.get("evidence") or []:
        if isinstance(ref, dict) and ref.get("operation_id") and "step" in ref:
            references.append(f"- **Observation:** {ref['operation_id']}:{ref['step']}")

    if not references:
        return ""
    return "\n".join(references)


def _load_json_file(path):
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_validation_summary(finding, *, repo_root=None):
    """Load optional validation summary JSON for a structured finding."""
    path = str(finding.get("validation_summary") or "").strip()
    if not path:
        return {}
    if repo_root is None and Path(path).expanduser().is_absolute():
        summary_path = Path(path).expanduser()
        return _load_json_file(summary_path) if summary_path.is_file() else {}
    root = Path(repo_root).resolve() if repo_root is not None else Path(BASE_DIR).resolve()
    summary_path = (root / path).expanduser().resolve()
    try:
        summary_path.relative_to(root)
    except ValueError:
        return {}
    return _load_json_file(summary_path) if summary_path.is_file() else {}


def _validation_cvss_score(validation):
    """Return a bounded numeric CVSS score from the attached summary."""
    if not isinstance(validation, dict):
        return None
    candidates = [validation.get("cvss_score")]
    cvss = validation.get("cvss")
    if isinstance(cvss, dict):
        candidates.extend(
            cvss.get(key)
            for key in ("score", "base_score", "cvss_score", "baseScore")
        )
        data = cvss.get("cvssData")
        if isinstance(data, dict):
            candidates.extend(data.get(key) for key in ("baseScore", "score"))
    elif cvss is not None:
        candidates.append(cvss)
    for value in candidates:
        if isinstance(value, bool):
            continue
        try:
            score = float(value)
        except (TypeError, ValueError):
            continue
        if 0.0 <= score <= 10.0:
            return score
    return None


def _validation_cvss_labels(validation):
    """Return recorded CVSS version/vector text without deriving new values."""
    if not isinstance(validation, dict):
        return "", ""
    cvss = validation.get("cvss")
    nested = cvss if isinstance(cvss, dict) else {}
    data = nested.get("cvssData") if isinstance(nested.get("cvssData"), dict) else {}
    version = str(
        validation.get("cvss_version")
        or nested.get("version")
        or data.get("version")
        or ""
    ).strip()
    vector = str(
        validation.get("cvss_vector")
        or nested.get("vector")
        or nested.get("vectorString")
        or data.get("vectorString")
        or ""
    ).strip()
    return version, vector


def declared_report_severity(content: str) -> dict:
    """Read only explicit Severity fields outside fenced examples."""
    values = []
    pending = False
    fence = ""
    for line in content.splitlines():
        raw = line.strip()
        if raw.startswith(("```", "~~~")):
            marker = raw[:3]
            fence = "" if fence == marker else (fence or marker)
            continue
        if fence:
            continue
        text = raw.replace("**", "").replace("`", "")
        if re.fullmatch(r"#{1,6}\s+Severity\s*:? *", text, re.I):
            pending = True
            continue
        field = re.match(r"(?:[-*]\s+)?Severity\s*:\s*(.*)$", text, re.I)
        if field or (pending and text):
            value = field.group(1) if field else text
            match = re.match(r"(critical|high|medium|low|info|unknown)(?=$|\s|[(:—–-])", value, re.I)
            values.append(match.group(1).lower() if match else "invalid")
            pending = False
    if pending:
        values.append("invalid")
    if not values:
        return {"severity": "unknown", "reason": "no explicit severity declaration"}
    if "invalid" in values or len(set(values)) != 1:
        return {"severity": "unknown", "reason": "invalid or conflicting severity declarations"}
    return {"severity": values[0], "reason": "explicit report declaration"}


def _report_severity(finding, validation, template):
    """Reuse recorded severity without recalculating it from legacy CVSS."""
    summary_severity = str((validation or {}).get("severity") or "").strip().lower()
    if summary_severity in SEVERITY_MAP:
        return summary_severity
    finding_severity = str(finding.get("severity") or "unknown").strip().lower()
    return finding_severity if finding_severity in SEVERITY_MAP else "unknown"


def _auth_bypass_narrative(finding, validation):
    """Render a concrete narrative from validated auth/public-exposure evidence.

    Public exposure runners provide a ``baseline.status`` response and can safely
    use the classic "anonymous GET returned 200" wording. Manual/AI validated
    authz findings can be write sinks or business-logic sinks, so this function
    must fall back to the validated summary fields instead of inventing a GET/200
    exposure narrative.
    """
    url = finding.get("url", "N/A")
    baseline = validation.get("baseline") if isinstance(validation.get("baseline"), dict) else {}
    status = baseline.get("status")
    markers = validation.get("markers") if isinstance(validation.get("markers"), list) else []
    marker_set = {str(item) for item in markers}

    if "secret-like" in marker_set:
        return {
            "title": "Unauthenticated Sensitive Data Exposure on {domain}",
            "summary": (
                f"An unauthenticated request to `{url}` returned HTTP {status or '200'} and exposed "
                "feedback records containing sensitive secret-like data in the response body."
            ),
            "impact": (
                "Anonymous users can retrieve feedback records that include high-value secret-like "
                "material in application data. This exposes credentials, recovery material, or other "
                "sensitive user/operational data and can directly enable chained account or environment compromise."
            ),
        }

    if marker_set & {"admin", "configuration", "oauth", "security-answer"}:
        return {
            "title": "Unauthenticated Admin Configuration Exposure on {domain}",
            "summary": (
                f"An unauthenticated request to `{url}` returned HTTP {status or '200'} and exposed "
                "application/admin configuration data, including OAuth and account-recovery related fields."
            ),
            "impact": (
                "Anonymous users can retrieve internal application configuration from an admin-named endpoint. "
                "Exposed OAuth/client configuration, security-question related settings, and deployment details "
                "materially reduce attacker effort for targeted auth abuse, recovery attacks, environment fingerprinting, "
                "and chained compromise."
            ),
        }

    method = str(validation.get("method") or finding.get("method") or "request").strip().upper()
    finding_summary = str(finding.get("summary") or "").strip()
    ai_assessment = str(validation.get("ai_assessment") or "").strip()

    if marker_set & {"anonymous_state_change", "author_spoof", "public_ui_visibility"}:
        summary = (
            f"An unauthenticated `{method}` request to `{url}` can create attacker-controlled "
            "content that is publicly rendered under a forged author identity."
        )
        if finding_summary:
            summary += f" {finding_summary}"
        if ai_assessment:
            summary += f" {ai_assessment}"
        return {
            "title": "Unauthenticated Content Impersonation on {domain}",
            "summary": summary,
            "impact": (
                "Attackers can create public content under another user's or privileged user's identity. "
                "This undermines content integrity, auditability, and user trust, and can be chained with "
                "social engineering or reputation abuse when the forged identity is trusted."
            ),
        }

    if finding_summary or ai_assessment:
        details = " ".join(part for part in (finding_summary, ai_assessment) if part)
        return {
            "title": "Authentication/Authorization Bypass on {domain}",
            "summary": f"Validated `{method}` authorization/business-logic evidence was recorded for `{url}`. {details}",
            "impact": ai_assessment or VULN_TEMPLATES["auth_bypass"]["impact"],
        }

    if status:
        summary = (
            f"An unauthenticated request to `{url}` returned HTTP {status} and exposed "
            "protected application data without the expected access control."
        )
    else:
        summary = f"Validated authorization bypass evidence was recorded for `{url}`."

    return {
        "title": "Authentication/Authorization Bypass on {domain}",
        "summary": summary,
        "impact": VULN_TEMPLATES["auth_bypass"]["impact"],
    }


def _validation_evidence_block(validation):
    if not validation:
        return ""
    lines = []
    seven_status = validation.get("seven_question_gate_decision")
    if seven_status:
        seven_pass = "PASS" if validation.get("seven_question_gate_passed") else "NEEDS REVIEW"
        lines.append(f"**7-Question Gate:** `{seven_pass}` (`{seven_status}`)")
    if "four_validation_gates_passed" in validation:
        four_pass = "PASS" if validation.get("four_validation_gates_passed") else "NEEDS REVIEW"
        lines.append(f"**Four Validation Gates:** `{four_pass}`")
    if "all_gates_passed" in validation:
        combined = "PASS" if validation.get("all_gates_passed") else "NEEDS REVIEW"
        lines.append(f"**Combined Report Readiness:** `{combined}`")
    markers = validation.get("markers") if isinstance(validation.get("markers"), list) else []
    if markers:
        lines.append(f"**Observed Markers:** `{', '.join(str(item) for item in markers)}`")
    if validation.get("summary_path"):
        lines.append(f"**Validation Summary:** `{validation['summary_path']}`")
    artifacts = validation.get("artifacts") if isinstance(validation.get("artifacts"), dict) else {}
    if artifacts.get("baseline_request"):
        lines.append(f"**Baseline Request:** `{artifacts['baseline_request']}`")
    if artifacts.get("baseline_response"):
        lines.append(f"**Baseline Response:** `{artifacts['baseline_response']}`")
    return "\n".join(lines)


def _reproduction_steps_block(finding, validation, url):
    """Render method-aware reproduction steps for the report body."""
    method = str(
        validation.get("method") or finding.get("method") or "GET"
    ).strip().upper() or "GET"
    if method == "GET":
        return f"""1. Navigate to the following URL:
   ```
   {url}
   ```
2. Observe the vulnerable behavior as described below."""

    artifacts = validation.get("artifacts") if isinstance(validation.get("artifacts"), dict) else {}
    request_artifact = (
        artifacts.get("anonymous_request")
        or artifacts.get("baseline_request")
        or artifacts.get("request")
        or ""
    )
    response_artifact = (
        artifacts.get("anonymous_response_body")
        or artifacts.get("baseline_response")
        or artifacts.get("response")
        or ""
    )
    lines = [
        f"1. Send a `{method}` request to the affected endpoint:",
        "   ```",
        f"   {url}",
        "   ```",
    ]
    if request_artifact:
        lines.append(f"2. Use the request shape captured in `{request_artifact}`.")
    else:
        lines.append("2. Use the request shape captured in the validation evidence.")
    if response_artifact:
        lines.append(f"3. Observe the response and follow-up behavior captured in `{response_artifact}`.")
    else:
        lines.append("3. Observe the response and follow-up behavior described below.")
    return "\n".join(lines)


def _native_report_body(finding, *, repo_root=None) -> str:
    """Return the Claude-written report body saved by /validate, if any.

    decision.report.content 经 _write_machine_report 写入
    validation_report_path（绑定 findings/<target>/<finding-id>-report.md）。
    读取失败或不存在时返回空串——调用方回退到兼容模板叙述。
    """
    path_str = str(finding.get("validation_report_path") or "").strip()
    if not path_str:
        return ""
    path = Path(path_str)
    if not path.is_absolute():
        repo = Path(repo_root) if repo_root else Path(BASE_DIR)
        path = repo / path
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    return text.strip()


def _title_from_native_body(body: str) -> str:
    """Extract the H1 title line from a native report body."""
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("# ") and not stripped.startswith("## "):
            return stripped[2:].strip()
        if stripped:
            break
    return ""


def generate_report(finding, vuln_type, target_name=None, *, repo_root=None):
    """Generate a HackerOne-formatted report for a finding.

    Native-body-first（原生能力审计 2026-09-13）：/validate 已保存 Claude
    撰写的报告正文（decision.report.content → validation_report_path）。
    该正文是第一选择——生成器不再从类别模板重写 Summary/Impact/
    Remediation。模板叙述仅在没有原生正文时作为兼容回退（legacy 草稿、
    手动路径），且类别默认值不得覆盖已验证的 canonical CVSS/severity。
    """
    template = VULN_TEMPLATES.get(vuln_type, VULN_TEMPLATES["misconfig"])

    url = finding.get("url", "N/A")
    domain = extract_domain(url) if url != "N/A" else (target_name or "unknown")
    validation = _load_validation_summary(finding, repo_root=repo_root)

    native_body = _native_report_body(finding, repo_root=repo_root)
    if native_body:
        return native_body, _title_from_native_body(native_body) or (
            template["title"].format(
                domain=domain,
                cve_id=finding.get("template_id", "Unknown CVE"),
            )
        )

    narrative = _auth_bypass_narrative(finding, validation) if vuln_type == "auth_bypass" else {}

    # Build title
    title = (narrative.get("title") or template["title"]).format(
        domain=domain,
        cve_id=finding.get("template_id", "Unknown CVE")
    )

    severity = _report_severity(finding, validation, template)
    cvss_score = _validation_cvss_score(validation)
    cvss_version, cvss_vector = _validation_cvss_labels(validation)
    severity_label = f"**{severity.upper()}**"
    if cvss_score is not None:
        severity_label += f" (CVSS: {cvss_score:g})"
    cvss_details = ""
    if cvss_version:
        cvss_details += f"\nCVSS Version: `{cvss_version}`"
    if cvss_vector:
        cvss_details += f"\nCVSS Vector: `{cvss_vector}`"
    finding_reference = format_finding_reference(finding)
    validation_evidence = _validation_evidence_block(validation)
    reproduction_steps = _reproduction_steps_block(finding, validation, url)
    summary_text = narrative.get("summary") or f"A {vuln_type} vulnerability was discovered on `{domain}`. {template['impact'][:200]}..."
    impact_text = narrative.get("impact") or template["impact"]

    report = f"""# {title}

## Severity
{severity_label}{cvss_details}

## Vulnerability Type
{template.get('cwe', 'N/A')} — {vuln_type.upper()}

## Summary
{summary_text}

## Affected URL
```
{url}
```

## Steps to Reproduce
{reproduction_steps}

## Evidence / Proof of Concept
**Scanner Output:**
```
{finding.get('raw', 'N/A')}
```

**Template/Check:** `{finding.get('template_id', 'manual')}`
"""

    if finding_reference:
        report += f"""
**Finding Reference:**
{finding_reference}
"""

    if validation_evidence:
        report += f"""

**Validation Evidence:**
{validation_evidence}
"""

    report += f"""

## Impact
{impact_text}

## Remediation
{template['remediation']}

## References
"""
    for ref in template.get("references", []):
        report += f"- {ref}\n"

    if finding.get("template_id", "").startswith("CVE-"):
        report += f"- https://nvd.nist.gov/vuln/detail/{finding['template_id']}\n"

    report += f"""
---
*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*Scanner: Automated Bug Bounty Pipeline*
"""
    return report, title


def _is_reportable_structured_finding(finding):
    """Require a confirmed assessment and its current eligible delivery."""
    if not isinstance(finding, dict) or not finding.get("url"):
        return False
    assessment = finding.get("assessment") or {}
    return assessment.get("verdict") == "confirmed" and any(
        item.get("status") == "eligible" and not item.get("stale")
        and item.get("assessment_id") == assessment.get("id")
        for item in finding.get("deliveries", [])
    )


def _report_file_matches_finding(report_file, finding):
    """Return whether an existing draft can be reused for this finding."""
    finding_id = str(finding.get("id") or "").strip()
    if not finding_id:
        return False
    try:
        text = Path(report_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return f"- **Finding ID:** {finding_id}" in text


_REPORT_TERMINATOR = "*Scanner: Automated Bug Bounty Pipeline*"


def _report_artifact_is_complete(report_file) -> bool:
    """产物完整性：报告必须写到终结标记，崩溃残片不算完整。

    报告正文以 "*Scanner: Automated Bug Bounty Pipeline*" 结尾；只写到
    Finding ID 行的半份文件（审计 F3 的 776 字节残片）不含该标记。
    """
    try:
        text = Path(report_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _REPORT_TERMINATOR in text and text.rstrip().endswith("*")


def _occupied_report_ids(structured_findings, report_dir):
    """Collect report IDs and their known finding owners from state and disk."""
    occupied = {}
    for finding in structured_findings:
        if not isinstance(finding, dict):
            continue
        report_id = str(finding.get("report_id") or "").strip()
        if report_id:
            occupied.setdefault(report_id, str(finding.get("id") or ""))

    index_path = Path(report_dir) / "INDEX.json"
    try:
        index_payload = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        index_payload = {}
    for entry in index_payload.get("reports", []) if isinstance(index_payload, dict) else []:
        if not isinstance(entry, dict):
            continue
        report_id = str(entry.get("id") or "").strip()
        if report_id:
            occupied.setdefault(report_id, str(entry.get("finding_id") or ""))

    for path in Path(report_dir).glob("*.md"):
        if path.name == "SUMMARY.md":
            continue
        occupied.setdefault(path.stem, "")
    return occupied


def _next_report_id(vuln_type, finding, report_dir, occupied):
    """Allocate a stable, unoccupied numeric report ID for one finding."""
    finding_id = str(finding.get("id") or "").strip()
    requested = str(finding.get("report_id") or "").strip()
    pattern = re.compile(rf"^{re.escape(vuln_type)}_(\d+)$")

    # Recover a draft written immediately before the finding-status update.
    for path in sorted(Path(report_dir).glob(f"{vuln_type}_*.md")):
        if not pattern.fullmatch(path.stem):
            continue
        owner = occupied.get(path.stem)
        if owner in (None, "", finding_id) and _report_file_matches_finding(path, finding):
            return path.stem

    if requested and pattern.fullmatch(requested):
        owner = occupied.get(requested)
        report_file = Path(report_dir) / f"{requested}.md"
        owner_matches = owner in (None, "", finding_id)
        file_matches = not report_file.exists() or _report_file_matches_finding(report_file, finding)
        if owner_matches and file_matches:
            return requested

    highest = 0
    for report_id in occupied:
        match = pattern.fullmatch(str(report_id))
        if match:
            highest = max(highest, int(match.group(1)))

    sequence = highest + 1
    while True:
        report_id = f"{vuln_type}_{sequence:03d}"
        report_file = Path(report_dir) / f"{report_id}.md"
        if report_id not in occupied and not report_file.exists():
            return report_id
        sequence += 1


def _create_or_reuse_report(report_file, report_content, finding):
    """Create without overwrite, or recover a same-finding crash artifact.

    审计 F3：文件已存在时区分三种情况——
    - 完整且属于同一 finding：复用（幂等重跑）。
    - 属于同一 finding 但不完整（崩溃残片）：原子替换为完整内容（恢复）。
    - 属于其他 finding 或无法确认归属：拒绝（raise），不覆盖人工产物。
    """
    path = Path(report_file)
    try:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                             prefix=f".{path.name}.", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(report_content)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink()
        return "created"
    except FileExistsError:
        if not _report_file_matches_finding(path, finding):
            raise
        if _report_artifact_is_complete(path):
            return "reused"
        _write_text_atomic(path, report_content)
        return "recovered"


def _primary_findings(store: TargetStore) -> list[dict]:
    """Project Store findings into the report renderer's read-only shape."""
    findings = []
    page = store.finding_page(limit=1000)
    while True:
        for item in page.get("items", []):
            if not isinstance(item, dict):
                continue
            finding = item
            assessment = finding.get("assessment") or {}
            reports = finding.get("reports") or []
            report = next((item for item in reversed(reports) if not item.get("stale")), {})
            artifact_ref = str(report.get("artifact_ref") or "").strip()
            report_file = str(store.root / artifact_ref) if artifact_ref else ""
            findings.append({
                "id": finding["id"],
                "type": finding["family"],
                "category": finding["family"],
                "title": finding["title"],
                "summary": finding["claim"],
                "url": finding["endpoint"],
                "method": finding["method"],
                "severity": "unknown",
                "confidence": assessment.get("verdict", ""),
                "validation_status": "validated" if assessment.get("verdict") == "confirmed" else "",
                "report_status": "generated" if report_file else "not_generated",
                "report_id": report.get("id", ""),
                "report_file": report_file,
                "raw": finding["claim"],
                "assessment": assessment,
                "deliveries": finding.get("deliveries", []),
                "reports": reports,
                "evidence": finding.get("evidence", []),
            })
        if not page.get("has_more"):
            break
        page = store.finding_page(limit=1000, cursor=page.get("next_cursor"))
    return findings


def _process_primary_reports(store, report_dir, target_name):
    """Publish report artifacts, then rebuild the index only from Store facts."""
    for finding in _primary_findings(store):
        if not _is_reportable_structured_finding(finding):
            continue
        assessment_id = finding["assessment"]["id"]
        deliveries = [item for item in finding["deliveries"]
                      if item["status"] == "eligible" and not item["stale"]
                      and item["assessment_id"] == assessment_id]
        registered_pairs = {
            (report["assessment_id"], report["delivery_id"])
            for report in finding["reports"]
        }
        for delivery in deliveries:
            pair = (assessment_id, delivery["id"])
            # Registered bodies are immutable, including damaged historical artifacts.
            if pair in registered_pairs:
                continue
            binding = json.dumps([store.target, finding["id"], assessment_id, delivery["id"]])
            report_id = "report_" + hashlib.sha256(binding.encode("utf-8")).hexdigest()
            report_file = str(Path(report_dir) / f"{report_id}.md")
            content, _ = generate_report(finding, _report_vuln_type(finding), target_name,
                                         repo_root=store.root)
            _create_or_reuse_report(report_file, content, finding)
            store.register_report(
                command_id=f"report:{report_id}", report_id=report_id, finding_id=finding["id"],
                assessment_id=assessment_id, delivery_id=delivery["id"], artifact=report_file,
                actor="report-generator",
            )
            registered_pairs.add(pair)

    source_binding = store.binding()
    as_of = datetime.now(timezone.utc).isoformat()
    entries = []
    for finding in _primary_findings(store):
        for report in finding["reports"]:
            if report["stale"]:
                continue
            report_bytes = (store.root / report["artifact_ref"]).read_bytes()
            if hashlib.sha256(report_bytes).hexdigest() != report["artifact_sha256"]:
                raise StoreError("registered report changed while reading severity; retry after evidence repair")
            severity = declared_report_severity(report_bytes.decode("utf-8"))
            entries.append({
                "id": report["id"], "finding_id": finding["id"],
                "title": finding["title"], "severity": severity["severity"],
                "severity_reason": severity["reason"],
                "url": finding["url"], "file": str(store.root / report["artifact_ref"]),
                "type": _report_vuln_type(finding), "family": finding["type"], "confidence": finding["confidence"],
                "assessment_id": report["assessment_id"], "delivery_id": report["delivery_id"],
                "destination": report["destination"], "artifact_sha256": report["artifact_sha256"],
                "queue_sync": {"status": "skipped", "reason": "primary store owns report lifecycle"},
                "canonical_lifecycle": True,
            })
    return write_report_index(report_dir, target_name, len(entries), entries, write_empty=True,
                              store=store, source_binding=source_binding, as_of=as_of)


def process_findings_dir(findings_dir):
    """Publish reports from the target Store and rebuild its bound index."""
    repo_root, target = _finding_backend_context(findings_dir)
    runtime_store(repo_root, target)
    with target_switch_lock(repo_root, target):
        _finding_backend_context(findings_dir, target)
        store = runtime_store(repo_root, target)
        report_dir = store.root / "reports" / store.key
        if report_dir != report_dir.resolve():
            raise StoreError(f"report output does not match directory owner: {report_dir}")
        report_dir.mkdir(parents=True, exist_ok=True)
        return _process_primary_reports(store, str(report_dir), store.key)


def write_report_index(report_dir, target_name, total_reports, report_index, *, write_empty=False,
                       store, source_binding, as_of):
    """Publish the index only while its source snapshot is still current."""
    with target_mutation_lock(store.root, store.target):
        if store.binding() != source_binding:
            raise ConflictError("report index source snapshot changed; regenerate reports")
        return _write_report_index(report_dir, target_name, total_reports, report_index,
                                   write_empty=write_empty, source_binding=source_binding, as_of=as_of)


def _write_report_index(report_dir, target_name, total_reports, report_index, *, write_empty=False,
                        source_binding=None, as_of=None):
    if report_index or write_empty:
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        report_index.sort(key=lambda x: severity_order.get(x["severity"], 5))

        index_file = os.path.join(report_dir, "INDEX.json")
        _write_text_atomic(
            index_file,
            json.dumps(
                {
                    "target": target_name,
                    "generated_at": datetime.now().isoformat(),
                    "total_reports": total_reports,
                    "reports": report_index,
                    **({"source_binding": source_binding, "as_of": as_of} if source_binding else {}),
                },
                indent=2,
            )
            + "\n",
        )

        # Also generate a summary markdown
        summary_file = os.path.join(report_dir, "SUMMARY.md")
        summary_lines = [
            f"# Bug Bounty Report Summary — {target_name}\n",
            "\n",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "\n",
            f"Total findings: {total_reports}\n",
            "\n",
            "| # | Severity | Type | Title | URL |\n",
            "|---|----------|------|-------|-----|\n",
        ]
        if source_binding:
            summary_lines[1:1] = [f"Snapshot as of: {as_of}; store {source_binding['store_id']}; "
                                  f"revision {source_binding['revision']}\n"]
        summary_lines.extend(
            f"| {r['id']} | {r['severity'].upper()} | {r['type']} | "
            f"{r['title'][:50]} | {r['url'][:60]} |\n"
            for r in report_index
        )
        _write_text_atomic(summary_file, "".join(summary_lines))

    return total_reports, report_index


def create_manual_report(vuln_type, url, param=None, evidence=None):
    """Write an unregistered manual draft without changing target facts."""
    target_name = target_storage_key(url)
    report_dir = os.path.join(REPORTS_DIR, target_name, "drafts")
    os.makedirs(report_dir, exist_ok=True)

    finding = {
        "raw": evidence or f"Manual finding: {vuln_type} on {url}",
        "url": url,
        "template_id": "manual",
        "severity": VULN_TEMPLATES.get(vuln_type, {}).get("severity", "medium"),
    }

    if param:
        finding["raw"] += f"\nParameter: {param}"

    report_content, title = generate_report(finding, vuln_type, target_name)
    report_content = "> Manual draft — not assessed, registered, or submitted.\n\n" + report_content

    occupied_report_ids = _occupied_report_ids([], report_dir)
    while True:
        report_id = _next_report_id(vuln_type, finding, report_dir, occupied_report_ids)
        report_file = os.path.join(report_dir, f"{report_id}.md")
        try:
            _create_or_reuse_report(report_file, report_content, finding)
            break
        except FileExistsError:
            occupied_report_ids[report_id] = ""

    print(f"[+] Manual draft saved: {report_file}")
    return report_file


def attach_poc_images(report_file, image_paths):
    """Append PoC image references to an existing report."""
    import shutil

    report_dir = os.path.dirname(report_file)
    poc_dir = os.path.join(report_dir, "poc_screenshots")
    os.makedirs(poc_dir, exist_ok=True)

    image_section = "\n\n## PoC Screenshots\n\n"
    for i, img_path in enumerate(image_paths, 1):
        if os.path.exists(img_path):
            filename = os.path.basename(img_path)
            dest = os.path.join(poc_dir, filename)
            if os.path.abspath(img_path) != os.path.abspath(dest):
                shutil.copy2(img_path, dest)
            image_section += f"### Screenshot {i}: {filename}\n"
            image_section += f"![PoC {i}](poc_screenshots/{filename})\n\n"
            print(f"[+] Attached PoC image: {filename}")
        else:
            print(f"[!] Image not found: {img_path}")

    with open(report_file, "a") as f:
        f.write(image_section)

    print(f"[+] PoC images attached to {report_file}")


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Report Generator")
    parser.add_argument("findings_dir", nargs="?", help="Directory containing scan findings")
    parser.add_argument("--manual", action="store_true", help="Create manual report")
    parser.add_argument("--type", type=str, help="Vulnerability type (xss, ssrf, takeover, etc.)")
    parser.add_argument("--url", type=str, help="Affected URL (for manual reports)")
    parser.add_argument("--param", type=str, help="Affected parameter (for manual reports)")
    parser.add_argument("--evidence", type=str, help="Evidence/PoC text (for manual reports)")
    parser.add_argument("--poc-images", type=str, nargs="+", help="PoC screenshot PNG files to attach")
    args = parser.parse_args()

    print("=============================================")
    print("  Bug Bounty Report Generator")
    print("=============================================")

    if args.manual:
        if not args.type or not args.url:
            print("[-] Manual mode requires --type and --url")
            print("    Types: xss, ssrf, takeover, cors, redirect, exposure, cve, misconfig, idor, auth_bypass, info_disclosure")
            sys.exit(1)
        report_file = create_manual_report(args.type, args.url, args.param, args.evidence)
        # Attach PoC images if provided
        if args.poc_images and report_file:
            attach_poc_images(report_file, args.poc_images)
        return

    if not args.findings_dir:
        print("[-] Please provide a findings directory or use --manual mode")
        print("    Usage: python3 report_generator.py <findings_dir>")
        print("    Usage: python3 report_generator.py --manual --type xss --url https://example.com/search?q=test")
        sys.exit(1)

    if not os.path.isdir(args.findings_dir):
        print(f"[-] Not a directory: {args.findings_dir}")
        sys.exit(1)

    total, index = process_findings_dir(args.findings_dir)

    print(f"\n[+] Generated {total} reports")
    if index:
        print("\nFindings by severity:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for r in index if r["severity"] == sev)
            if count > 0:
                print(f"  {sev.upper()}: {count}")

        report_dir = Path(index[0]["file"]).parent
        print(f"\nReports saved to: {report_dir}/")
        print(f"Summary: {report_dir}/SUMMARY.md")
    else:
        print("\n[*] No reportable findings to generate reports for.")


if __name__ == "__main__":
    main()
