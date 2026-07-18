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
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    from action_queue import ACTIVE_STATUSES, load_queue, resolve_action
    from finding_index import (
        load_finding_index,
        update_finding_status,
        verify_finalized_finding_owner_provenance,
    )
    from target_paths import target_storage_key
except ImportError:  # pragma: no cover - package import path
    from tools.action_queue import ACTIVE_STATUSES, load_queue, resolve_action
    from tools.finding_index import (
        load_finding_index,
        update_finding_status,
        verify_finalized_finding_owner_provenance,
    )
    from tools.target_paths import target_storage_key

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def _report_action_matches(action, finding, report_file):
    """Return whether an active queue item represents this generated report."""
    finding_id = str(finding.get("id") or "").strip()
    url = str(finding.get("url") or "").strip()
    report_file = str(report_file or "").strip()
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    haystack = " ".join(
        str(value or "")
        for value in (
            action.get("id"),
            action.get("source_id"),
            action.get("type"),
            action.get("evidence"),
            action.get("next_question"),
            action.get("action"),
            action.get("command_hint"),
            metadata.get("finding_id"),
            metadata.get("url"),
            metadata.get("report_file"),
        )
    )
    if finding_id and finding_id in haystack:
        return True
    if str(action.get("type") or "").lower() == "report":
        return bool((url and url in haystack) or (report_file and report_file in haystack))
    return False


def sync_report_action_queue(target_name, finding, report_file):
    """Best-effort close report queue items after a report draft is generated."""
    try:
        repo_root = Path(BASE_DIR)
        queue = load_queue(repo_root, str(target_name or ""))
        matched = None
        for action in queue.get("actions", []):
            if not isinstance(action, dict):
                continue
            if str(action.get("status") or "queued") not in ACTIVE_STATUSES:
                continue
            if _report_action_matches(action, finding, report_file):
                matched = action
                break
        if not matched:
            return {"status": "skipped", "reason": "no matching active report action"}
        resolved = resolve_action(
            repo_root,
            target=str(target_name or ""),
            action_id=str(matched.get("id") or ""),
            status="reported",
            result=f"report_file={report_file}",
            notes=f"finding_id={finding.get('id', '')}",
        )
        return {
            "status": "updated",
            "id": resolved.get("id", ""),
            "action_status": resolved.get("status", ""),
        }
    except Exception as exc:  # pragma: no cover - queue sync must not block reports
        return {"status": "error", "error": str(exc)}

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


def parse_dalfox_line(line):
    """Parse a dalfox output line."""
    parts = line.strip()
    if not parts:
        return None

    result = {
        "raw": parts,
        "url": "",
        "payload": "",
        "severity": "medium"
    }

    url_match = re.search(r'(https?://\S+)', parts)
    if url_match:
        result["url"] = url_match.group(1)

    if "POC" in parts or "Verified" in parts:
        result["severity"] = "high"

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

    if not references:
        return ""
    return "\n".join(references)


def _load_validation_summary(finding):
    """Load optional validation summary JSON for a structured finding."""
    path = str(finding.get("validation_summary") or "").strip()
    if not path:
        return {}
    summary_path = Path(path)
    if not summary_path.is_absolute():
        summary_path = Path(BASE_DIR) / summary_path
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _validation_summary_is_report_ready(finding, validation):
    """Return whether an attached validation summary is a report-readiness gate."""
    path = str(finding.get("validation_summary") or "").strip()
    if not path:
        return None
    gate_fields = {
        "all_gates_passed",
        "seven_question_gate_passed",
        "four_validation_gates_passed",
        "seven_question_gate_decision",
    }
    if not validation or not any(field in validation for field in gate_fields):
        return False
    if validation.get("all_gates_passed") is False:
        return False
    if validation.get("seven_question_gate_passed") is False:
        return False
    if validation.get("four_validation_gates_passed") is False:
        return False
    decision = str(validation.get("seven_question_gate_decision") or "").strip().lower()
    if decision in {"kill", "chain_required", "needs_review"}:
        return False
    return bool(validation.get("all_gates_passed") or validation.get("seven_question_gate_passed"))


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
    rubric = validation.get("evidence_rubric") if isinstance(validation.get("evidence_rubric"), dict) else {}
    if rubric.get("summary"):
        lines.append(f"**Evidence Rubric:** `{rubric['summary']}`")
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


def generate_report(finding, vuln_type, target_name=None):
    """Generate a HackerOne-formatted report for a finding."""
    template = VULN_TEMPLATES.get(vuln_type, VULN_TEMPLATES["misconfig"])

    url = finding.get("url", "N/A")
    domain = extract_domain(url) if url != "N/A" else (target_name or "unknown")
    validation = _load_validation_summary(finding)
    narrative = _auth_bypass_narrative(finding, validation) if vuln_type == "auth_bypass" else {}

    # Build title
    title = (narrative.get("title") or template["title"]).format(
        domain=domain,
        cve_id=finding.get("template_id", "Unknown CVE")
    )

    severity = finding.get("severity", template["severity"])
    severity_info = SEVERITY_MAP.get(severity, SEVERITY_MAP["medium"])
    finding_reference = format_finding_reference(finding)
    validation_evidence = _validation_evidence_block(validation)
    reproduction_steps = _reproduction_steps_block(finding, validation, url)
    summary_text = narrative.get("summary") or f"A {vuln_type} vulnerability was discovered on `{domain}`. {template['impact'][:200]}..."
    impact_text = narrative.get("impact") or template["impact"]

    report = f"""# {title}

## Severity
**{severity.upper()}** (CVSS: {severity_info['cvss_range']})

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


def _is_reportable_structured_finding(
    finding,
    *,
    findings_dir: str | os.PathLike | None = None,
    target: str | None = None,
):
    """Return whether a structured finding should enter auto-report generation."""
    if not isinstance(finding, dict) or not finding.get("url"):
        return False

    validation_status = str(finding.get("validation_status", "") or "").strip().lower()
    report_status = str(finding.get("report_status", "") or "").strip().lower()

    # Backward compatibility: older structured findings may not carry validation
    # state yet; keep them reportable instead of breaking historical workflows.
    if validation_status and validation_status != "validated":
        return False
    if validation_status == "validated":
        # A direct JSON edit is not enough to enter report generation.  The
        # report writer is a lifecycle consumer, so require the same owner
        # provenance that runtime state and checkpoint use.
        if not findings_dir:
            return False
        provenance = verify_finalized_finding_owner_provenance(
            findings_dir,
            finding,
            target=target,
        )
        if not provenance.get("valid"):
            return False
    validation = _load_validation_summary(finding)
    if _validation_summary_is_report_ready(finding, validation) is False:
        return False

    if report_status == "generated":
        return False

    return True


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
    """Create without overwrite, or reuse a same-finding crash artifact."""
    path = Path(report_file)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(report_content)
        return "created"
    except FileExistsError:
        if _report_file_matches_finding(path, finding):
            return "reused"
        raise


def process_findings_dir(findings_dir):
    """Process all findings in a directory and generate reports."""
    structured_index = load_finding_index(findings_dir)
    target_name = _report_target_name(structured_index, findings_dir)
    report_dir = os.path.join(REPORTS_DIR, target_name)
    os.makedirs(report_dir, exist_ok=True)

    # Map finding directories to vuln types
    dir_type_map = {
        "upload": "upload",
        "sqli": "sqli",
        "xss": "xss",
        "ssti": "ssti",
        "takeover": "takeover",
        "misconfig": "misconfig",
        "exposure": "exposure",
        "ssrf": "ssrf",
        "cves": "cve",
        "redirects": "redirect",
        "idor": "idor",
        "auth_bypass": "auth_bypass",
        "mfa": "mfa",
        "saml": "saml",
        "jwt": "jwt",
    }

    total_reports = 0
    report_index = []

    structured_findings = structured_index.get("findings", []) if isinstance(structured_index, dict) else []
    provenance_target = str(structured_index.get("target") or "").strip() if isinstance(structured_index, dict) else ""
    provenance_target = provenance_target or target_name
    if structured_findings:
        report_index.extend(
            _existing_structured_report_entries(
                structured_findings,
                findings_dir=findings_dir,
                target=provenance_target,
            )
        )
        total_reports = len(report_index)
        occupied_report_ids = _occupied_report_ids(structured_findings, report_dir)

        reportable_findings = [
            finding
            for finding in structured_findings
            if _is_reportable_structured_finding(
                finding,
                findings_dir=findings_dir,
                target=provenance_target,
            )
        ]
        for finding in reportable_findings:

            vuln_type = _report_vuln_type(finding)

            report_content, title = generate_report(finding, vuln_type, target_name)

            while True:
                report_id = _next_report_id(
                    vuln_type,
                    finding,
                    report_dir,
                    occupied_report_ids,
                )
                report_file = os.path.join(report_dir, f"{report_id}.md")
                try:
                    _create_or_reuse_report(report_file, report_content, finding)
                    break
                except FileExistsError:
                    # Another writer claimed the candidate after allocation.
                    occupied_report_ids[report_id] = ""
            occupied_report_ids[report_id] = str(finding.get("id") or "")

            if finding.get("id"):
                update_finding_status(
                    findings_dir,
                    finding.get("id", ""),
                    report_status="generated",
                    report_file=report_file,
                    report_id=report_id,
                )
            queue_sync = sync_report_action_queue(target_name, finding, report_file)

            total_reports += 1
            report_index.append({
                "id": report_id,
                "finding_id": finding.get("id", ""),
                "title": title,
                "severity": finding.get("severity", "medium"),
                "url": finding.get("url", ""),
                "file": report_file,
                "type": vuln_type,
                "source_file": finding.get("source_file", ""),
                "confidence": finding.get("confidence", ""),
                "queue_sync": queue_sync,
            })

        return write_report_index(report_dir, target_name, total_reports, report_index)

    for subdir, vuln_type in dir_type_map.items():
        subdir_path = os.path.join(findings_dir, subdir)
        if not os.path.isdir(subdir_path):
            continue

        for filename in os.listdir(subdir_path):
            filepath = os.path.join(subdir_path, filename)
            if not os.path.isfile(filepath) or not filename.endswith(".txt"):
                continue
            if "manual" in filename:
                continue  # Skip manual review files

            with open(filepath) as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue

                # Parse based on source
                if "dalfox" in filename:
                    finding = parse_dalfox_line(line)
                else:
                    finding = parse_nuclei_line(line)

                if not finding or not finding.get("url"):
                    continue

                # Generate report
                report_content, title = generate_report(finding, vuln_type, target_name)

                # Save report
                report_id = f"{vuln_type}_{i+1:03d}"
                report_file = os.path.join(report_dir, f"{report_id}.md")
                with open(report_file, "w") as rf:
                    rf.write(report_content)

                total_reports += 1
                report_index.append({
                    "id": report_id,
                    "title": title,
                    "severity": finding.get("severity", "medium"),
                    "url": finding.get("url", ""),
                    "file": report_file,
                    "type": vuln_type
                })

    return write_report_index(report_dir, target_name, total_reports, report_index)


def _report_target_name(structured_index, findings_dir):
    """Return canonical target storage key for report output paths."""
    raw_target = ""
    if isinstance(structured_index, dict):
        raw_target = str(structured_index.get("target") or "").strip()
    raw_target = raw_target or os.path.basename(str(findings_dir).rstrip(os.sep))
    return target_storage_key(raw_target)


def _existing_structured_report_entries(
    structured_findings,
    *,
    findings_dir: str | os.PathLike,
    target: str | None = None,
):
    """Build report index rows for findings already marked as generated.

    Report generation can be called repeatedly as new candidates pass
    `/validate`. The index should describe the current report set, not only the
    reports created in this invocation.
    """
    entries = []
    seen = set()
    for finding in structured_findings:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("report_status") or "").strip().lower() != "generated":
            continue
        provenance = verify_finalized_finding_owner_provenance(
            findings_dir,
            finding,
            target=target,
        )
        if not provenance.get("valid"):
            continue
        report_file = str(finding.get("report_file") or "").strip()
        if not report_file:
            continue
        report_id = str(finding.get("report_id") or "").strip() or Path(report_file).stem
        key = str(finding.get("id") or "") or report_file
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "id": report_id,
            "finding_id": finding.get("id", ""),
            "title": finding.get("title") or f"{str(finding.get('type') or 'finding').upper()} on {finding.get('url', '')}",
            "severity": finding.get("severity", "medium"),
            "url": finding.get("url", ""),
            "file": report_file,
            "type": finding.get("type") or finding.get("category") or "misconfig",
            "source_file": finding.get("source_file", ""),
            "confidence": finding.get("confidence", ""),
            "queue_sync": finding.get("queue_sync", {}),
        })
    return entries


def write_report_index(report_dir, target_name, total_reports, report_index):
    """Save report index and summary markdown."""
    if report_index:
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        report_index.sort(key=lambda x: severity_order.get(x["severity"], 5))

        index_file = os.path.join(report_dir, "INDEX.json")
        with open(index_file, "w") as f:
            json.dump({
                "target": target_name,
                "generated_at": datetime.now().isoformat(),
                "total_reports": total_reports,
                "reports": report_index
            }, f, indent=2)

        # Also generate a summary markdown
        summary_file = os.path.join(report_dir, "SUMMARY.md")
        with open(summary_file, "w") as f:
            f.write(f"# Bug Bounty Report Summary — {target_name}\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total findings: {total_reports}\n\n")
            f.write("| # | Severity | Type | Title | URL |\n")
            f.write("|---|----------|------|-------|-----|\n")
            for r in report_index:
                f.write(f"| {r['id']} | {r['severity'].upper()} | {r['type']} | {r['title'][:50]} | {r['url'][:60]} |\n")

    return total_reports, report_index


def create_manual_report(vuln_type, url, param=None, evidence=None):
    """Create a report from manual findings."""
    domain = extract_domain(url)
    target_name = domain.replace(".", "_")
    report_dir = os.path.join(REPORTS_DIR, target_name)
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

    report_id = f"{vuln_type}_manual_{datetime.now().strftime('%H%M%S')}"
    report_file = os.path.join(report_dir, f"{report_id}.md")
    with open(report_file, "w") as f:
        f.write(report_content)

    print(f"[+] Report saved: {report_file}")
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

        target_name = os.path.basename(args.findings_dir)
        print(f"\nReports saved to: {REPORTS_DIR}/{target_name}/")
        print(f"Summary: {REPORTS_DIR}/{target_name}/SUMMARY.md")
    else:
        print("\n[*] No reportable findings to generate reports for.")


if __name__ == "__main__":
    main()
