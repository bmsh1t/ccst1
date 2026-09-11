"""Validation and normalization for AI-supplied request-pair evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class RequestPairError(ValueError):
    """Raised when a request pair is not an exact, single-dimension replay."""


# Needle facts carry an AI-supplied literal substring after '::' (e.g.
# variant_body_contains::"UserId":24). The name is validated against the
# runner's vocabulary; the needle is kept verbatim.
NEEDLE_FACT_NAMES = ("variant_body_contains", "baseline_body_lacks")
NEEDLE_FACT_RE = re.compile(r"^([a-z_]+)::(.+)$", re.S)
NEEDLE_MIN_CHARS = 4
NEEDLE_MAX_CHARS = 200


def expected_fact_vocabulary() -> frozenset[str]:
    """Return the runner's wire-fact vocabulary used to validate ``expected``.

    The vocabulary lives here (parser side) so the parser stays knowledge-free:
    it validates names, never interprets them. The runner computes the facts.
    """
    # Imported lazily to avoid a parser->runner dependency cycle at import time.
    from validation_runner import WIRE_FACT_NAMES

    return WIRE_FACT_NAMES


_UNSUPPORTED_CONTENT_TYPES = (
    "multipart/",
    "application/grpc",
    "application/x-protobuf",
    "application/protobuf",
)


def _headers(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RequestPairError("request headers must be an object")
    return {str(key): str(item) for key, item in value.items()}


def _request(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RequestPairError(f"{name} must be an object")
    method = str(value.get("method") or "GET").upper()
    url = str(value.get("url") or "").strip()
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise RequestPairError(f"{name}.method is unsupported")
    if not url or not urlsplit(url).scheme or not urlsplit(url).netloc:
        raise RequestPairError(f"{name}.url must be an absolute URL")
    headers = _headers(value.get("headers"))
    content_type = next(
        (item for key, item in headers.items() if key.lower() == "content-type"),
        "",
    ).lower()
    if any(content_type.startswith(prefix) for prefix in _UNSUPPORTED_CONTENT_TYPES):
        raise RequestPairError("manual_required: binary or multipart request body")
    if "content-encoding" in {key.lower() for key in headers}:
        raise RequestPairError("manual_required: compressed request body")
    body = value.get("body", "")
    if not isinstance(body, (str, dict, list, int, float, bool)) and body is not None:
        raise RequestPairError("manual_required: request body is not text or JSON")
    return {"method": method, "url": url, "headers": headers, "body": body if body is not None else ""}


def _header_key(name: str) -> str:
    return str(name).strip().lower()


def _cookie_values(headers: dict[str, str]) -> dict[str, str]:
    raw = next((str(value) for key, value in headers.items() if key.lower() == "cookie"), "")
    values: dict[str, str] = {}
    for item in raw.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _body_leaf_paths(value: Any, prefix: str = "body", content_type: str = "") -> dict[str, Any]:
    if isinstance(value, str):
        if "application/x-www-form-urlencoded" in content_type and "=" in value:
            pairs = parse_qsl(value, keep_blank_values=True)
            if pairs:
                return {f"{prefix}/{key}": item for key, item in pairs}
        if "json" in content_type:
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                parsed = None
            if parsed is not None:
                return _body_leaf_paths(parsed, prefix, content_type)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            out.update(_body_leaf_paths(child, f"{prefix}/{key}", content_type))
        return out or {prefix: {}}
    if isinstance(value, list):
        out = {}
        for index, child in enumerate(value):
            out.update(_body_leaf_paths(child, f"{prefix}/{index}", content_type))
        return out or {prefix: []}
    return {prefix: value}


def _normalized_url(url: str) -> str:
    parsed = urlsplit(url)
    pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", urlencode(pairs), ""))


def _difference_paths(baseline: dict[str, Any], variant: dict[str, Any]) -> list[str]:
    differences: list[str] = []
    if baseline["method"] != variant["method"]:
        differences.append("method")
    if _normalized_url(baseline["url"]) != _normalized_url(variant["url"]):
        differences.append("url")
    base_headers = {_header_key(k): v for k, v in baseline["headers"].items()}
    variant_headers = {_header_key(k): v for k, v in variant["headers"].items()}
    for key in sorted(set(base_headers) | set(variant_headers)):
        if base_headers.get(key) != variant_headers.get(key):
            differences.append(f"header:{key}")
    base_content_type = next((str(value).lower() for key, value in baseline["headers"].items() if key.lower() == "content-type"), "")
    variant_content_type = next((str(value).lower() for key, value in variant["headers"].items() if key.lower() == "content-type"), "")
    base_body = _body_leaf_paths(baseline["body"], content_type=base_content_type)
    variant_body = _body_leaf_paths(variant["body"], content_type=variant_content_type)
    for key in sorted(set(base_body) | set(variant_body)):
        if base_body.get(key) != variant_body.get(key):
            differences.append(key)
    return differences


def validate_request_pair(spec: dict[str, Any]) -> dict[str, Any]:
    """Validate and copy one exact baseline/variant pair.

    The runner owns scope, auth, and side-effect checks. This helper only makes
    sure the AI supplied two comparable requests and named their one active
    dimension.
    """
    if not isinstance(spec, dict):
        raise RequestPairError("request spec must be an object")
    if int(spec.get("schema_version", 1) or 1) != 1:
        raise RequestPairError("request spec schema_version must be 1")
    baseline = _request(spec.get("baseline_request"), "baseline_request")
    variant = _request(spec.get("variant_request"), "variant_request")
    if baseline["method"] != variant["method"]:
        raise RequestPairError("baseline and variant methods must match")
    differences = _difference_paths(baseline, variant)
    if not differences:
        raise RequestPairError("baseline and variant must differ")
    active = str(spec.get("active_dimension") or "").strip()
    if not active:
        raise RequestPairError("active_dimension is required")
    # Query/path dimensions are represented by URL; body/header dimensions keep
    # their exact path so a pair cannot silently mutate multiple inputs.
    if active.startswith("query:"):
        base_url = urlsplit(baseline["url"])
        variant_url = urlsplit(variant["url"])
        if (base_url.scheme.lower(), base_url.netloc.lower(), base_url.path, base_url.fragment) != (
            variant_url.scheme.lower(), variant_url.netloc.lower(), variant_url.path, variant_url.fragment
        ):
            raise RequestPairError("active query dimension cannot change path or origin")
        name = active[6:].strip()
        base_query = dict(parse_qsl(base_url.query, keep_blank_values=True))
        variant_query = dict(parse_qsl(variant_url.query, keep_blank_values=True))
        changed_keys = sorted(key for key in set(base_query) | set(variant_query) if base_query.get(key) != variant_query.get(key))
        if changed_keys != [name]:
            raise RequestPairError("active query dimension must be the only URL difference")
    elif active.startswith("path:"):
        base_url = urlsplit(baseline["url"])
        variant_url = urlsplit(variant["url"])
        if (base_url.scheme.lower(), base_url.netloc.lower(), base_url.query, base_url.fragment) != (
            variant_url.scheme.lower(), variant_url.netloc.lower(), variant_url.query, variant_url.fragment
        ) or base_url.path == variant_url.path:
            raise RequestPairError("active path dimension must be the only URL difference")
    elif active.startswith(("header:", "cookie:")):
        if len(differences) != 1 or not differences[0].startswith("header:"):
            raise RequestPairError("active header dimension must be the only request difference")
        if active.startswith("header:") and _header_key(active[7:]) != differences[0][7:]:
            raise RequestPairError("active header dimension does not match the changed header")
        if active.startswith("cookie:"):
            name = active[7:].strip()
            base_cookies = _cookie_values(baseline["headers"])
            variant_cookies = _cookie_values(variant["headers"])
            changed_cookies = sorted(
                key for key in set(base_cookies) | set(variant_cookies)
                if base_cookies.get(key) != variant_cookies.get(key)
            )
            if changed_cookies != [name] or differences[0] != "header:cookie":
                raise RequestPairError("active cookie dimension does not match the changed cookie")
    elif active.startswith("body:"):
        expected = active[5:].strip()
        if expected in {"", "/", "body"}:
            expected = "body"
        elif not expected.startswith("body"):
            expected = "body" + expected if expected.startswith("/") else f"body/{expected}"
        text_placeholder = isinstance(baseline["body"], str) and isinstance(variant["body"], str)
        if len(differences) != 1 or (differences[0] != expected and not (text_placeholder and differences[0] == "body")):
            raise RequestPairError("active body dimension must be the only request difference")
    else:
        raise RequestPairError("active_dimension must use query:, path:, header:, cookie:, or body:")
    repeat = max(1, int(spec.get("repeat", 1) or 1))
    classifier = str(spec.get("classifier") or "generic").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", classifier):
        raise RequestPairError("classifier must be a simple identifier")
    # AI-declared judgment: the caller asserts this endpoint is expected to
    # require authentication. The parser carries the boolean unchanged; it
    # never infers the expectation from the host, path, or response shape.
    expect_auth_raw = spec.get("expect_auth", False)
    if isinstance(expect_auth_raw, bool):
        expect_auth = expect_auth_raw
    elif expect_auth_raw in (None, ""):
        expect_auth = False
    else:
        raise RequestPairError("expect_auth must be a boolean when present")
    # AI-declared expectation: the caller states which wire facts it expects
    # the replay to show. The parser validates the names against the runner's
    # vocabulary (a typo is a hard input error, never silently ignored) and
    # carries them unchanged; interpreting facts is the runner's job and
    # interpreting the evidence is the AI review's job.
    expected_raw = spec.get("expected", [])
    if expected_raw in (None, ""):
        expected_raw = []
    if not isinstance(expected_raw, (list, tuple)):
        raise RequestPairError("expected must be a list of fact names when present")
    vocabulary = expected_fact_vocabulary()
    expected: list[str] = []
    for item in expected_raw:
        name = str(item or "").strip()
        if not name:
            continue
        # Needle facts: name::needle. The needle is an AI-supplied literal
        # substring kept verbatim; the runner verifies it mechanically. The
        # combined entry is the fact identity for reconciliation and digest.
        needle_match = NEEDLE_FACT_RE.match(name)
        if needle_match:
            fact_name, needle = needle_match.group(1), needle_match.group(2)
            if fact_name not in NEEDLE_FACT_NAMES:
                raise RequestPairError(
                    f"expected contains an unknown fact name: {fact_name!r}; "
                    f"known facts: {', '.join(sorted(vocabulary))}"
                )
            if not (NEEDLE_MIN_CHARS <= len(needle) <= NEEDLE_MAX_CHARS):
                raise RequestPairError(
                    f"expected needle for {fact_name} must be "
                    f"{NEEDLE_MIN_CHARS}-{NEEDLE_MAX_CHARS} characters"
                )
            if name not in expected:
                expected.append(name)
            continue
        if name not in vocabulary:
            raise RequestPairError(
                f"expected contains an unknown fact name: {name!r}; "
                f"known facts: {', '.join(sorted(vocabulary))}"
            )
        if name not in expected:
            expected.append(name)
    expected_note = str(spec.get("expected_note") or "").strip()
    if len(expected_note) > 500:
        raise RequestPairError("expected_note must be at most 500 characters")
    return {
        "schema_version": 1,
        "baseline_request": copy.deepcopy(baseline),
        "variant_request": copy.deepcopy(variant),
        "active_dimension": active,
        "evidence_shape": str(spec.get("evidence_shape") or "request_diff").strip().lower(),
        "classifier": classifier,
        "vuln_class": str(spec.get("vuln_class") or "").strip(),
        "expected_signal": str(spec.get("expected_signal") or "").strip(),
        "expect_auth": expect_auth,
        "expected": expected,
        "expected_note": expected_note,
        "repeat": repeat,
    }


def request_pair_digest(spec: dict[str, Any]) -> str:
    normalized = validate_request_pair(spec)
    encoded = json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
