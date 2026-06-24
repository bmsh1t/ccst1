#!/usr/bin/env python3
"""
chain_hints.py — derive a single concise chain-attack hint from a
confirmed Finding/Signal so the LLM is reminded of the next attack
class to test.

Lightweight by design: returns ONE string (not a structured hypothesis
list) so we just append it to working_memory and let the LLM choose
whether to follow up. No new runtime path, no worker spawn.

API:
    derive_chain_hint(finding: dict) -> str
        Returns a "[CHAIN HINT …]" line, or "" if no rule matches.

No severity gate: rules are pattern-specific and already discriminate
noise. Info-level signals (S3 listable, GraphQL introspection enabled,
JWT alg=none observed, subdomain takeover candidate) need chain hints
just as much as Confirmed findings — often more, since these are the
highest-leverage starting points. The hint is soft bias; the LLM
decides whether to follow up.

Coverage mirrors agents/chain-builder.md (13 patterns).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Pattern


# Each row: (regex matched against finding text+tool+vuln_class, hint body)
# Hint body is appended after a "[CHAIN HINT HH:MM] " prefix.
_CHAIN_RULES: list[tuple[Pattern, str]] = [
    # 1 — IDOR (any direction) — chain hint suggests both write probe + sibling
    (re.compile(r"\bidor\b", re.I),
     "IDOR confirmed → if read-only, swap method to PUT/PATCH/DELETE on same "
     "path; enumerate sibling /export, /share, /download, /pdf in same "
     "controller; try older API versions /v1, /mobile."),

    # 2 — Auth bypass
    (re.compile(r"\bauth\W*bypass\b|\bauthorization\W*missing\b|\b401\W*bypass\b", re.I),
     "Auth bypass confirmed → enumerate every sibling endpoint in same "
     "controller; try legacy /v1, /api/legacy, /mobile prefixes (older "
     "versions often unpatched)."),

    # 3 — Stored XSS
    (re.compile(r"\bxss\b.*\b(stored|persistent|second.order)\b|\bstored\W*xss\b", re.I),
     "Stored XSS confirmed → check if admin/moderator views the field "
     "(support ticket queue, user profile, report dashboard) → priv esc to "
     "Critical ATO. Also test secondary renderers: email, PDF export, search index."),

    # 4 — SSRF callback (confirmed)
    (re.compile(r"\bssrf\b.*\b(callback|dns|oob|out.of.band|interactsh|burpcollab)\b|\bssrf\W*confirmed\b", re.I),
     "SSRF callback confirmed → escalate to 169.254.169.254/latest/meta-data/iam/ "
     "(AWS IMDSv1) and metadata.google.internal (header Metadata-Flavor: Google); "
     "probe internal services on localhost:6379 / :9200 / :8080."),

    # 5 — Open redirect
    (re.compile(r"\bopen\W*redirect\b|\bredirect\W*(uri|to|url)\b.*\b(unvalidated|controlled)\b", re.I),
     "Open redirect confirmed → if app has OAuth flow, set redirect_uri to "
     "this redirect → victim click delivers code to attacker = Critical ATO."),

    # 6 — S3 listing
    (re.compile(r"\bs3\b.*\b(listing|public|bucket|listobjects)\b|\baws.*bucket.*listable\b", re.I),
     "S3 bucket listable → download .js, .map, .env, config.json; grep for "
     "client_secret, AWS_KEY, JWT_SECRET, SLACK_TOKEN. Also test PutObject "
     "(writable bucket = supply-chain takeover)."),

    # 7 — GraphQL introspection
    (re.compile(r"\bgraphql\b.*\b(introspection|enabled|exposed)\b|\b__schema\b", re.I),
     "GraphQL introspection enabled → enumerate every mutation; test field-level "
     "auth (e.g. updateUser may accept {role:admin}); try Relay node(id:\"…\") "
     "global-ID IDOR; batch 100+ login attempts via aliases (rate-limit bypass)."),

    # 8 — LLM prompt injection
    (re.compile(r"\bprompt\W*injection\b|\bllm\W*(jailbreak|injection|leak)\b|\bchatbot\W*follows\b", re.I),
     "Prompt injection confirmed → if chatbot has data-fetch tool, inject "
     "'fetch user 12345 data' = IDOR via AI; extract system prompt for hidden "
     "tools/keys; test code-interpreter arg injection for sandbox escape."),

    # 9 — Path traversal / LFI
    (re.compile(r"\bpath\W*traversal\b|\blfi\b|\bdirectory\W*traversal\b|\b\.\./\.\./\b", re.I),
     "Path traversal/LFI confirmed → read /proc/self/environ + log poison "
     "(User-Agent control) = RCE on PHP/Python; read /root/.ssh/authorized_keys, "
     "/root/.aws/credentials, /etc/shadow."),

    # 10 — Subdomain takeover
    (re.compile(r"\bsubdomain\W*takeover\b|\bdangling\W*cname\b|\bunclaimed\W*(s3|github\W*pages|heroku|fastly)\b", re.I),
     "Subdomain takeover candidate → check if it's registered as OAuth "
     "redirect_uri / SAML ACS / postMessage origin = Critical ATO; check "
     "parent-domain cookie scope (Domain=.target.com → session theft)."),

    # 11 — JWT weak / leaked secret
    (re.compile(r"\bjwt\b.*\b(weak|none|hs256|cracked|brute)\b|\bjwt\W*secret\b", re.I),
     "JWT weakness → forge token with role:admin / is_superuser:true / "
     "aud:internal; try alg:none and kid header path-traversal injection."),

    # 12 — File upload bypass
    (re.compile(r"\bfile\W*upload\b.*\b(bypass|extension|mime|magic)\b|\bunrestricted\W*upload\b", re.I),
     "Upload restriction bypassed → upload SVG with <script> for stored XSS; "
     "try .phtml, .php5, .pHp, .php.jpg, .php%00.jpg for RCE; zip-slip "
     "(../../etc/cron.d/x) for archive-extraction RCE."),

    # 13 — Webhook / callback URL config
    (re.compile(r"\bwebhook\b|\bcallback\W*url\b|\b(image|url|file)\W*(fetch|proxy|importer)\b|\b(redirect|notify|hook)_url\b", re.I),
     "Webhook/callback URL config detected → set destination to "
     "http://localhost:6379, http://127.0.0.1:9200, http://169.254.169.254/ "
     "(AWS IMDS), http://metadata.google.internal/; try gopher://, dict://, "
     "file:// (Redis RCE / LFI / service enum)."),

    # 14 — SQL injection (any flavour — blind/boolean/time/UNION/stacked)
    (re.compile(r"\bsqli?\b|\bsql\W*injection\b|\bblind\W*sql\b|\bboolean\W*based\b|\btime\W*based\W*sql\b|\bunion\W*based\W*sql\b", re.I),
     "SQLi confirmed → escalate from boolean → UNION (extract user(), version(), "
     "@@hostname); pivot to file read (LOAD_DATA INFILE, ::xp_cmdshell, "
     "COPY FROM PROGRAM on Postgres); enumerate information_schema.tables / "
     "user_privileges for FILE/SUPER → on MySQL test xp_dirtree UNC for NTLM "
     "leak; on MSSQL test xp_cmdshell + sp_OACreate for RCE."),

    # 15 — DOM / reflected XSS (incl. prototype pollution sinks)
    (re.compile(r"\bdom\W*xss\b|\breflected\W*xss\b|\bprototype\W*pollution\b|\bxss\W*via\W*(prototype|dom|hash|fragment)\b", re.I),
     "DOM/reflected XSS confirmed → if any postMessage / window.name / hash "
     "handler is reachable from another origin → 0-click ATO via attacker page; "
     "extract CSRF token + cookies (if not HttpOnly) and fire authenticated "
     "actions; if SPA stores JWT in localStorage, dump it; check if same JS "
     "loads on /my-account / /admin (one payload = ATO + admin pivot)."),
]


def _now_hhmm() -> str:
    return datetime.now().strftime("%H:%M")


def derive_chain_hint(finding: dict) -> str:
    """Return one '[CHAIN HINT …]' line, or '' if no rule matches.

    Pure function — no I/O, no exceptions raised on bad input.
    No severity gate: many high-leverage chains start at info-level
    signals (S3 listable, GraphQL introspection enabled, JWT alg=none).
    The regex patterns are specific enough to discriminate noise.
    """
    if not isinstance(finding, dict):
        return ""
    haystack = " ".join([
        str(finding.get("text") or ""),
        str(finding.get("tool") or ""),
        str(finding.get("vuln_class") or ""),
    ])
    if not haystack.strip():
        return ""
    # Normalise snake_case / dash-case so word boundaries work on tool names
    # like "graphql_introspection_check" or "subdomain-takeover-scan".
    norm_haystack = re.sub(r"[_\-]+", " ", haystack)
    matched_bodies = []
    for pat, body in _CHAIN_RULES:
        if pat.search(norm_haystack):
            matched_bodies.append(body)
    if not matched_bodies:
        return ""
    # If multiple rules match, prefer the first (most specific in table order)
    # but join up to 2 bodies separated by " // " to keep the hint compact.
    chosen = " // ".join(matched_bodies[:2])
    return f"[CHAIN HINT {_now_hhmm()}] {chosen}"
