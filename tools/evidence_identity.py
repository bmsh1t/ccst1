"""Low-dependency evidence identity and optional Coverage vocabulary.

Evidence families are open-ended. Canonical classes restrict Coverage mapping,
not admission of observations. No executor, projection or persistence imports.
"""

from __future__ import annotations

import re
from typing import Mapping, Any
from urllib.parse import parse_qsl, urlparse


ACTOR_ALIASES = {
    "unknown": "unknown",
    "anonymous": "anonymous",
    "anon": "anonymous",
    "unauth": "anonymous",
    "unauthenticated": "anonymous",
    "owner": "owner",
    "self": "owner",
    "user_a": "owner",
    "peer": "peer",
    "other": "peer",
    "victim": "peer",
    "user_b": "peer",
    "low_role": "low_role",
    "low-role": "low_role",
    "lowpriv": "low_role",
    "member": "low_role",
    "admin": "admin",
    "cross_tenant": "cross_tenant",
    "cross-tenant": "cross_tenant",
    "tenant_b": "cross_tenant",
}

OBJECT_ALIASES = {
    "none": "none",
    "na": "none",
    "own": "own_object",
    "own_object": "own_object",
    "self": "own_object",
    "other": "other_object_same_org",
    "peer": "other_object_same_org",
    "same_org_other": "other_object_same_org",
    "other_object_same_org": "other_object_same_org",
    "cross_tenant": "cross_tenant_object",
    "cross-tenant": "cross_tenant_object",
    "tenant_b": "cross_tenant_object",
    "cross_tenant_object": "cross_tenant_object",
    "admin": "admin_object",
    "admin_object": "admin_object",
    "unknown": "unknown",
}

VARIANT_ALIASES = {
    "baseline": "baseline",
    "allow": "baseline",
    "unauth": "unauth_denied",
    "unauth_denied": "unauth_denied",
    "anonymous_denied": "unauth_denied",
    "id_swap": "id_swap",
    "idswap": "id_swap",
    "object_swap": "id_swap",
    "role_diff": "role_diff",
    "role": "role_diff",
    "tenant_diff": "tenant_diff",
    "tenant": "tenant_diff",
    "method_diff": "method_diff",
    "method": "method_diff",
    "version_diff": "version_diff",
    "version": "version_diff",
    "token_missing": "token_missing",
    "csrf_missing": "token_missing",
    "origin_diff": "origin_diff",
    "referer_diff": "origin_diff",
    "replay": "replay",
    "browser_observed": "browser_observed",
}


def _normalize_observation_value(value: str, aliases: dict[str, str], field: str) -> str:
    key = str(value or "").strip().lower().replace(" ", "_")
    if key in aliases:
        return aliases[key]
    by_canonical: dict[str, list[str]] = {}
    for input_key, canonical in aliases.items():
        by_canonical.setdefault(canonical, []).append(input_key)

    groups = []
    for canonical in sorted(by_canonical):
        accepted_inputs = sorted(by_canonical[canonical])
        if accepted_inputs == [canonical]:
            groups.append(canonical)
        else:
            groups.append(f"{canonical} (input: {', '.join(accepted_inputs)})")
    raise ValueError(f"unknown {field}: {value!r}. Accepted inputs: {'; '.join(groups)}")


def normalize_actor(value: str) -> str:
    return _normalize_observation_value(value or "owner", ACTOR_ALIASES, "actor")


def normalize_object_scope(value: str) -> str:
    return _normalize_observation_value(value or "unknown", OBJECT_ALIASES, "object_scope")


def normalize_variant(value: str) -> str:
    return _normalize_observation_value(value or "baseline", VARIANT_ALIASES, "variant")


CANONICAL_VULN_CLASSES = (
    "IDOR", "SSRF", "XSS", "Race", "Authz",
    "GraphQL", "OAuth", "Upload", "Webhook", "JWT",
    "SQLi", "XXE", "RCE", "Path", "CSRF",
    "NoSQLi", "PrototypePollution", "OpenRedirect", "BusinessLogic",
)
# Shared terminal vocabulary: the Evidence Ledger owns observed terminal
# results, and Closure consumes the same definition instead of restating it.
# Coverage/Closure must agree on what "closed" means; one definition here.
LEDGER_RESULTS = (
    "lead", "signal", "candidate", "tested_clean", "tested_finding",
    "dead_end", "blocked_redline", "not_applicable",
)
COVERING_RESULTS = frozenset({"signal", "candidate", "tested_clean", "tested_finding", "dead_end"})
CLOSED_LEDGER_RESULTS = frozenset({"tested_clean", "tested_finding", "dead_end", "not_applicable", "blocked_redline"})
CLOSED_MATRIX_STATUSES = frozenset({"tested_clean", "tested_finding", "n_a"})
# Coverage uses the append-only Web2 classes above. Workflow
# is a closeable evidence family, but remains outside that matrix taxonomy.
CLOSURE_ONLY_FAMILIES = ("Workflow",)
CLOSURE_FAMILIES = CANONICAL_VULN_CLASSES + CLOSURE_ONLY_FAMILIES


def observation_supports_coverage(record: Mapping[str, Any]) -> bool:
    """Recorded incompleteness or unchecked side effects cannot authorize coverage."""
    return (
        record.get("outcome", "complete") == "complete"
        and not record.get("error")
        and not record.get("truncated")
        and not (record.get("state_changing") and not record.get("redline_checked"))
    )

VULN_CLASS_ALIASES = {
    **{vuln_class.lower(): vuln_class for vuln_class in CLOSURE_FAMILIES},
    "auth": "Authz",
    "access": "Authz",
    "access-control": "Authz",
    "auth-bypass": "Authz",
    "authentication-bypass": "Authz",
    "authorization-bypass": "Authz",
    "public-exposure": "Authz",
    "business-logic": "BusinessLogic",
    "businesslogic": "BusinessLogic",
    "mfa": "Authz",
    "saml": "Authz",
    "sql": "SQLi",
    "sql-injection": "SQLi",
    "sqlinjection": "SQLi",
    "sqlblind": "SQLi",
    "sqli-blind": "SQLi",
    "sqli-time": "SQLi",
    "blindsqli": "SQLi",
    "nosqli": "NoSQLi",
    "nosql-injection": "NoSQLi",
    "nosqlinjection": "NoSQLi",
    "cross-site-scripting": "XSS",
    "xss-dom": "XSS",
    "dom-xss": "XSS",
    "domxss": "XSS",
    "prototype-pollution": "PrototypePollution",
    "prototypepollution": "PrototypePollution",
    "pp": "PrototypePollution",
    "toctou": "Race",
    "file-upload": "Upload",
    "openredirect": "OpenRedirect",
    "open-redirect": "OpenRedirect",
    "redirect": "OpenRedirect",
    "oscommand": "RCE",
    "os-command": "RCE",
    "cmdinjection": "RCE",
    "cmd-injection": "RCE",
    "commandinjection": "RCE",
    "ssti": "RCE",
    "command-injection": "RCE",
    "deser": "RCE",
    "deserialization": "RCE",
    "unserialize": "RCE",
    "template-injection": "RCE",
    "templateinjection": "RCE",
    "lfi": "Path",
    "rfi": "Path",
    "pathtraversal": "Path",
    "path-traversal": "Path",
    "directory-traversal": "Path",
    "directorytraversal": "Path",
    "csrf-token": "CSRF",
    "xsrf": "CSRF",
    "xxe-blind": "XXE",
    "xml-injection": "XXE",
    "xmlinjection": "XXE",
    "xinclude": "XXE",
}


def canonical_vuln_class(vuln_hint: str) -> str:
    """归一化 closure 用的漏洞类名；未知/空/generic 返回空字符串。

    返回空字符串代表 fail-open：调用方不得把该线索视为已关闭。
    """
    value = str(vuln_hint or "").strip().lower().replace("_", "-")
    if not value or value == "generic":
        return ""
    return VULN_CLASS_ALIASES.get(value, "")


def extract_endpoint_parts(value: str) -> tuple[str, str]:
    """Return an endpoint's path and fragment using one URL parser."""
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            path = parsed.path or "/"
            fragment = parsed.fragment
        except ValueError:
            path, _, fragment = raw.partition("#")
    else:
        path, _, fragment = raw.partition("#")
    return path.split("?", 1)[0], fragment


def extract_endpoint_path(value: str) -> str:
    """Project a URL or endpoint to its path without identity normalization."""
    return extract_endpoint_parts(value)[0]


def _normalize_endpoint_path(path: str) -> str:
    path = str(path or "").strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    if path != "/":
        path = path.rstrip("/")
    return path


def canonical_endpoint_identity(value: str) -> str:
    """Return an exact endpoint identity while discarding document fragments."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw) if "://" in raw else urlparse(f"local://host/{raw.lstrip('/')}")
        path = _normalize_endpoint_path(parsed.path or "/")
        query = parsed.query
        fragment = parsed.fragment
    except ValueError:
        base, _, fragment = raw.partition("#")
        path, separator, query = base.partition("?")
        query = query if separator else ""
        path = _normalize_endpoint_path(path)
    if not path:
        return ""
    identity = f"{path}?{query}" if query else path
    if fragment.startswith("/"):
        identity = f"{identity}#{fragment}"
    return identity


def canonical_endpoint_path(value: str) -> str:
    """Normalize to a path while retaining semantic SPA hash routes."""
    identity = canonical_endpoint_identity(value)
    if not identity:
        return ""
    server_route, separator, fragment = identity.partition("#")
    path = server_route.split("?", 1)[0]
    if not separator:
        return path
    return f"{path}#{fragment.split('?', 1)[0]}"


def split_path_query(url: str) -> tuple[str, str]:
    """Return (path, query) for full or relative URLs.

    ``extract_endpoint_path`` intentionally drops query strings so endpoint
    rows dedupe correctly.  Callers that rank or resume still need the
    parameter names, so this keeps the query available without storing values.
    """
    raw = str(url or "").strip()
    if not raw:
        return "", ""
    if "://" in raw:
        try:
            parsed = urlparse(raw)
        except ValueError:
            return "", ""
        return parsed.path or "/", parsed.query or ""
    raw = raw.split("#", 1)[0]
    if "?" not in raw:
        return raw, ""
    path, query = raw.split("?", 1)
    return path or "/", query


def path_with_query(url: str) -> str:
    """Return relative path plus query, suitable for value/semantic scoring."""
    path, query = split_path_query(url)
    if not path:
        return ""
    return f"{path}?{query}" if query else path


def query_param_names(url: str) -> set[str]:
    """Extract query parameter names without storing parameter values."""
    _path, query = split_path_query(url)
    if not query:
        return set()
    out: set[str] = set()
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        pairs = []
    for key, _value in pairs:
        key = str(key or "").strip()
        if key:
            out.add(key[:80])
    # parse_qsl may ignore malformed fragments; keep a conservative fallback.
    for chunk in query.split("&"):
        key = chunk.split("=", 1)[0].strip()
        if key:
            out.add(key[:80])
    return out


_ROUTE_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
_ROUTE_HEX_RE = re.compile(r"^[0-9a-f]{16,64}$", re.I)
_ROUTE_DATE_RE = re.compile(r"^(?:19|20)\d{2}[-_/](?:0[1-9]|1[0-2])[-_/](?:0[1-9]|[12]\d|3[01])$")
_ROUTE_NUMBER_RE = re.compile(r"^\d{2,}$")


def collapse_dynamic_path_segments(path: str) -> str:
    """Collapse obvious dynamic path tokens; shape only, no Coverage policy.

    Coverage admission (static asset / public metadata short circuits) stays in
    the Coverage projection and reuses this function.
    """
    parts = []
    for segment in str(path or "").strip("/").split("/"):
        if _ROUTE_UUID_RE.fullmatch(segment):
            segment = "{uuid}"
        elif _ROUTE_HEX_RE.fullmatch(segment):
            segment = "{hash}"
        elif _ROUTE_DATE_RE.fullmatch(segment):
            segment = "{date}"
        elif _ROUTE_NUMBER_RE.fullmatch(segment):
            segment = "{id}"
        parts.append(segment)
    return "/" + "/".join(parts) if parts else "/"


def normalize_vuln_class(name: str) -> str:
    """Resolve operator-typed vuln_class to its canonical form.

    Accepts canonical names case-insensitively and a curated alias
    set (LFI/RFI -> Path, OSCommand -> RCE, etc. — see
    `VULN_CLASS_ALIASES`). Returns the canonical name (the form
    stored on disk).

    Raises `ValueError` on unrecognised input with a message that
    lists the canonical names so the operator can pick the right one.
    """
    canonical = canonical_vuln_class(name)
    if canonical in CANONICAL_VULN_CLASSES:
        return canonical
    raise ValueError(
        f"unknown vuln_class: {name!r}. "
        f"Canonical names: {', '.join(CANONICAL_VULN_CLASSES)}. "
        f"Aliases like 'lfi'->'Path', 'ssti'->'RCE', 'sql-injection'->'SQLi' "
        f"are also accepted (case-insensitive)."
    )

def normalize_family(value: str) -> str:
    """Preserve valid unknown families; normalize only registered aliases."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("family must be a non-empty string")
    if len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("family must be at most 256 characters without control characters")
    return canonical_vuln_class(value) or value.strip()


def coverage_family(value: str) -> str | None:
    """Return an optional canonical Coverage label, never invent a mapping."""
    canonical = canonical_vuln_class(normalize_family(value))
    return canonical if canonical in CANONICAL_VULN_CLASSES else None
