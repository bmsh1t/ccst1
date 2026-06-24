#!/usr/bin/env python3
"""Lightweight source/JS business-logic intelligence extractor."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - exercised when run as a script
    sys.path.insert(0, str(TOOLS_DIR))
    from target_paths import target_storage_key
SCAN_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".vue", ".py", ".rb", ".go", ".java", ".kt", ".php", ".cs", ".graphql", ".gql"}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "coverage", "__pycache__", "vendor", ".next"}
AUTH_KEYWORDS = ("auth", "login", "logout", "session", "token", "jwt", "role", "admin", "tenant", "account", "user", "owner", "permission")
OBJECT_KEYWORDS = ("id", "user_id", "account_id", "tenant_id", "order_id", "invoice_id", "object_id", "profile_id")
OBJECT_PARAM_KEYS = {
    "id", "uuid", "user_id", "userid", "account_id", "accountid",
    "tenant_id", "tenantid", "order_id", "orderid", "invoice_id",
    "invoiceid", "object_id", "objectid", "profile_id", "profileid",
    "channel_id", "channelid", "room_id", "roomid", "conversation_id",
    "conversationid",
}
BUSINESS_VERBS = ("approve", "reject", "submit", "export", "download", "invite", "order", "invoice", "report", "refund", "delete", "update")
WEBSOCKET_KEYWORDS = ("websocket", "socket.io", "sockjs", "signalr", "stomp", "subscription")
WEBSOCKET_ROUTE_WORDS = ("ws", "socket", "realtime", "cable", "hub", "subscriptions")
SSRF_PARAM_KEYS = ("url", "uri", "dest", "destination", "target", "image_url", "avatar_url", "file_url", "callback_url", "webhook_url", "fetch_url")
SSRF_ROUTE_WORDS = ("fetch", "proxy", "preview", "render", "import", "scrape", "avatar", "image")
WEBHOOK_ROUTE_WORDS = ("webhook", "callback", "notify", "hook")
OAUTH_ROUTE_WORDS = ("oauth", "oidc", "sso", "saml", "authorize")
OAUTH_PARAM_KEYS = ("redirect_uri", "client_id", "state", "code_challenge", "id_token", "samlresponse")
UPLOAD_ROUTE_WORDS = ("upload", "import", "convert", "parser", "archive", "attachment", "file")
CSRF_MARKERS = ("csrf_token", "csrftoken", "csrfmiddlewaretoken", "__requestverificationtoken", "x-csrf-token", "xsrf", "samesite")
FRAMEWORK_MARKERS = (
    "__next_data__", "/_next/static", "_buildmanifest", "buildmanifest",
    "sourcemappingurl", ".js.map", "__nuxt__", "/_nuxt/", "middleware-manifest",
    "server actions", "serveractions",
)
ROUTE_RE = re.compile(r"""(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS)?\s*["'`]((?:(?:https?|wss?)://[^"'`\s]+)|(?:/[A-Za-z0-9._~:/?#[\]@!$&()*+,;=%{}-]{2,}))["'`]""", re.I)
FRAMEWORK_ROUTE_RE = re.compile(r"""\b(?:app|router|route|fastify)\.(?P<method>get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]""", re.I)
GRAPHQL_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?", re.I)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_target(target: str) -> str:
    return target_storage_key(target)


def _dedupe(items: list[dict], key_fields: tuple[str, ...]) -> list[dict]:
    seen = set()
    out = []
    for item in items:
        key = tuple(str(item.get(field, "")) for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _iter_source_files(repo_path: str) -> list[Path]:
    if not repo_path:
        return []
    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"repo_path not found: {repo_path}")
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() in SCAN_EXTENSIONS and path.stat().st_size <= 512 * 1024:
                files.append(path)
            if len(files) >= 5000:
                return files
    return files


def _read_recon_js_artifacts(repo_root: Path, target_key: str) -> list[tuple[str, str]]:
    recon_dir = repo_root / "recon" / target_key
    artifacts = []
    for rel in ("js/endpoints.txt", "js/endpoints_raw.txt", "urls/api_endpoints.txt", "browser/api_endpoints.txt", "browser/xhr_endpoints.txt"):
        path = recon_dir / rel
        if path.is_file():
            artifacts.append((f"recon/{target_key}/{rel}", path.read_text(encoding="utf-8", errors="replace")))
    for path in sorted((recon_dir / "js").glob("*.js")) if (recon_dir / "js").is_dir() else []:
        if path.stat().st_size <= 512 * 1024:
            artifacts.append((f"recon/{target_key}/js/{path.name}", path.read_text(encoding="utf-8", errors="replace")))
    return artifacts


def _route_param_keys(route: str) -> set[str]:
    """Return lower-cased query/body-like keys visible in a route string."""
    return {
        key.lower()
        for key in re.findall(r"[?&]([^=&?#]+)=", route)
        if key
    }


def _object_like_param_keys(route: str) -> set[str]:
    """Return query keys that look like object/tenant/channel identifiers."""
    keys = _route_param_keys(route)
    out = set()
    oauth_keys = set(OAUTH_PARAM_KEYS) | {"client_id", "redirect_uri"}
    for key in keys:
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if key in oauth_keys:
            continue
        if key in OBJECT_PARAM_KEYS or normalized in OBJECT_PARAM_KEYS:
            out.add(key)
            continue
        if key.endswith("_id") and key not in oauth_keys:
            out.add(key)
    return out


def _contains_wordish(value: str, words: tuple[str, ...]) -> bool:
    """Conservative substring helper for source-intel classification."""
    lower = value.lower()
    return any(word in lower for word in words)


def _route_has_marker(route: str, markers: tuple[str, ...]) -> bool:
    """Return True when a route contains a path/query marker as a token.

    This avoids treating unrelated words such as /news as a /ws endpoint.
    """
    lower = route.lower()
    for marker in markers:
        escaped = re.escape(marker.lower())
        if re.search(rf"(^|[/:?&#._=-]){escaped}($|[/:?&#._=-])", lower):
            return True
    return False


def _is_interesting_route(route: str) -> bool:
    """Keep routes that can change the next Web hunting lane.

    This intentionally stays broader than pure API extraction but still avoids
    generic static assets: realtime, auth, upload/import, webhook/fetch, and
    framework/API surfaces are useful for Claude's next-tool choice.
    """
    lower = route.lower()
    if route.startswith(("ws://", "wss://")):
        return True
    return bool(
        re.search(r"(/api/|/graphql\b|/rest/|/v\d+/)", route, re.I)
        or _contains_wordish(lower, AUTH_KEYWORDS)
        or _contains_wordish(lower, OBJECT_KEYWORDS)
        or _contains_wordish(lower, BUSINESS_VERBS)
        or _route_has_marker(lower, WEBSOCKET_ROUTE_WORDS)
        or _route_has_marker(lower, SSRF_ROUTE_WORDS)
        or _route_has_marker(lower, WEBHOOK_ROUTE_WORDS)
        or _route_has_marker(lower, OAUTH_ROUTE_WORDS)
        or _route_has_marker(lower, UPLOAD_ROUTE_WORDS)
    )


def _extract_routes(text: str, source: str) -> list[dict]:
    routes = []
    for line in text.splitlines():
        value = line.strip()
        if value.startswith(("http://", "https://", "ws://", "wss://", "/")) and _is_interesting_route(value):
            routes.append({"route": value, "method": "", "source": source})
    for match in FRAMEWORK_ROUTE_RE.finditer(text):
        routes.append({"route": match.group(2), "method": match.group("method").upper(), "source": source})
    for match in ROUTE_RE.finditer(text):
        route = match.group(2)
        if _is_interesting_route(route):
            routes.append({"route": route, "method": (match.group("method") or "").upper(), "source": source})
    return _dedupe(routes, ("route", "method", "source"))


def _extract_graphql(text: str, source: str) -> list[dict]:
    ops = []
    for match in GRAPHQL_RE.finditer(text):
        ops.append({"operation": match.group(1).lower(), "name": match.group(2) or "", "source": source})
    return _dedupe(ops, ("operation", "name", "source"))


def _keyword_counts(texts: list[str]) -> dict:
    haystack = "\n".join(texts).lower()
    groups = {
        "auth_role_tenant": AUTH_KEYWORDS,
        "object_ids": OBJECT_KEYWORDS,
        "business_verbs": BUSINESS_VERBS,
    }
    return {group: {word: haystack.count(word.lower()) for word in words if haystack.count(word.lower())} for group, words in groups.items()}


def _route_tags(route: str) -> list[str]:
    lower = route.lower()
    param_keys = _route_param_keys(route)
    object_keys = _object_like_param_keys(route)
    tags = []
    if object_keys or re.search(r"/[:{]?[A-Za-z_]*(?:id|uuid)[}A-Za-z_]*", lower):
        tags.append("object_id")
    if _route_has_marker(lower, AUTH_KEYWORDS) or bool(param_keys & {"role", "tenant", "account", "user", "owner", "permission"}):
        tags.append("auth_role_tenant")
    if any(word in lower for word in BUSINESS_VERBS):
        tags.append("business_workflow")
    if "graphql" in lower:
        tags.append("graphql")
    if route.startswith(("ws://", "wss://")) or _route_has_marker(lower, WEBSOCKET_ROUTE_WORDS):
        tags.append("websocket")
    if _route_has_marker(lower, OAUTH_ROUTE_WORDS) or bool(param_keys & set(OAUTH_PARAM_KEYS)) or (
        "callback" in lower and any(marker in lower for marker in ("oauth", "oidc", "sso", "saml", "auth"))
    ):
        tags.append("oauth")
    if _route_has_marker(lower, UPLOAD_ROUTE_WORDS):
        tags.append("upload")
    if _route_has_marker(lower, WEBHOOK_ROUTE_WORDS) and "oauth" not in tags:
        tags.append("webhook")
    if bool(param_keys & set(SSRF_PARAM_KEYS)) or (
        _route_has_marker(lower, SSRF_ROUTE_WORDS)
        and any(token in lower for token in ("url", "uri", "target", "image", "avatar", "fetch", "proxy"))
    ):
        tags.append("ssrf")
    return tags


def _first_matching_line(text: str, patterns: tuple[str, ...]) -> str:
    """Return a compact evidence line for a source-level signal."""
    lowered_patterns = tuple(pattern.lower() for pattern in patterns)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(pattern in lower for pattern in lowered_patterns):
            return stripped[:180]
    return ""


def _extract_source_signals(text: str, source: str) -> list[dict]:
    """Extract non-route signals that should steer Claude's next lane.

    These are deliberately hypothesis fuel, not findings. They avoid payload
    generation and only point the agent toward the right read-only/manual lane.
    """
    lower = text.lower()
    signals: list[dict] = []

    if (
        "new websocket" in lower
        or "wss://" in lower
        or "ws://" in lower
        or any(keyword in lower for keyword in WEBSOCKET_KEYWORDS)
    ):
        signals.append({
            "type": "websocket",
            "candidate": f"WebSocket/realtime code in {source}",
            "reason": "source references WebSocket/realtime transport; inspect handshake, Origin, and frame-level authz",
            "source": source,
            "evidence": _first_matching_line(text, ("new WebSocket", "wss://", "ws://", "socket.io", "SockJS", "SignalR", "subscription")),
        })

    if any(marker in lower for marker in FRAMEWORK_MARKERS):
        signals.append({
            "type": "framework-intel",
            "candidate": f"Framework/source-map signal in {source}",
            "reason": "framework marker or source-map hint may expose routes, build manifests, middleware, or hidden JS surface",
            "source": source,
            "evidence": _first_matching_line(text, ("__NEXT_DATA__", "/_next/static", "sourceMappingURL", ".js.map", "__NUXT__", "/_nuxt/", "middleware-manifest", "serverActions")),
        })

    if any(marker in lower for marker in CSRF_MARKERS):
        signals.append({
            "type": "csrf",
            "candidate": f"CSRF/SameSite handling in {source}",
            "reason": "CSRF/SameSite signal found; analyze token binding and request shape before any state-changing test",
            "source": source,
            "evidence": _first_matching_line(text, ("csrf_token", "csrfToken", "X-CSRF-Token", "xsrf", "SameSite", "__RequestVerificationToken")),
        })

    if ("redirect_uri" in lower and ("client_id" in lower or "state" in lower)) or "code_challenge" in lower or "email_verified" in lower:
        signals.append({
            "type": "oauth",
            "candidate": f"OAuth/OIDC flow code in {source}",
            "reason": "OAuth/OIDC flow markers found; inspect redirect/state/session binding and email-normalization/account-linking logic",
            "source": source,
            "evidence": _first_matching_line(text, ("redirect_uri", "client_id", "state", "code_challenge", "email_verified")),
        })

    return signals


def _build_hypotheses(routes: list[dict], graphql_ops: list[dict], source_signals: list[dict] | None = None) -> list[dict]:
    hypotheses = []
    for route in routes:
        tags = _route_tags(route["route"])
        if "object_id" in tags:
            hypotheses.append({"type": "idor", "candidate": route["route"], "reason": "route contains object/account/user id marker", "source": route["source"]})
        if "auth_role_tenant" in tags:
            hypotheses.append({"type": "auth-bypass", "candidate": route["route"], "reason": "route mentions auth/role/tenant/account boundary", "source": route["source"]})
        if "business_workflow" in tags:
            hypotheses.append({"type": "business-logic", "candidate": route["route"], "reason": "route contains high-impact workflow verb", "source": route["source"]})
        if "websocket" in tags:
            hypotheses.append({"type": "websocket", "candidate": route["route"], "reason": "realtime/WebSocket route should be checked for Origin and frame-level authz", "source": route["source"]})
        if "oauth" in tags:
            hypotheses.append({"type": "oauth", "candidate": route["route"], "reason": "OAuth/OIDC/SSO route should be reviewed for redirect/state/session and email-linking boundaries", "source": route["source"]})
        if "upload" in tags:
            hypotheses.append({"type": "upload", "candidate": route["route"], "reason": "upload/import/convert route may hide parser, file-read, or authz boundaries", "source": route["source"]})
        if "webhook" in tags:
            hypotheses.append({"type": "webhook", "candidate": route["route"], "reason": "webhook/callback route may need signature, replay, and ownership review", "source": route["source"]})
        if "ssrf" in tags:
            hypotheses.append({"type": "ssrf", "candidate": route["route"], "reason": "route exposes URL/fetch-like input; prove server-side fetch before OAST/internal follow-up", "source": route["source"]})
        route["tags"] = tags
    for op in graphql_ops:
        if op["operation"] == "mutation":
            hypotheses.append({"type": "business-logic", "candidate": op.get("name") or "GraphQL mutation", "reason": "GraphQL mutation can hide workflow authz checks", "source": op["source"]})
        if op["operation"] == "subscription":
            hypotheses.append({"type": "websocket", "candidate": op.get("name") or "GraphQL subscription", "reason": "GraphQL subscription can expose realtime authz gaps across roles/tenants", "source": op["source"]})
    route_backed_types = {
        item["type"]
        for item in hypotheses
        if str(item.get("candidate", "")).startswith(("http://", "https://", "ws://", "wss://", "/"))
    }
    for signal in source_signals or []:
        # 如果已经有具体 route/URL，避免再用同类“source contains X”挤占 Workflow Leads。
        if signal.get("type") in route_backed_types and signal.get("type") in {"websocket", "oauth", "ssrf", "upload", "webhook"}:
            continue
        hypotheses.append(signal)
    return _dedupe(hypotheses, ("type", "candidate", "source"))


def _write_outputs(out_dir: Path, target: str, routes: list[dict], graphql_ops: list[dict], keywords: dict, hypotheses: list[dict], sources: list[str]) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "routes.json").write_text(json.dumps({"routes": routes, "graphql_operations": graphql_ops}, indent=2) + "\n", encoding="utf-8")
    (out_dir / "keywords.json").write_text(json.dumps(keywords, indent=2) + "\n", encoding="utf-8")
    with (out_dir / "hypotheses.jsonl").open("w", encoding="utf-8") as handle:
        for item in hypotheses:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
    summary = render_summary(target, routes, graphql_ops, keywords, hypotheses, sources)
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")
    return {"summary": str(out_dir / "summary.md"), "routes": str(out_dir / "routes.json"), "keywords": str(out_dir / "keywords.json"), "hypotheses": str(out_dir / "hypotheses.jsonl")}


def render_summary(target: str, routes: list[dict], graphql_ops: list[dict], keywords: dict, hypotheses: list[dict], sources: list[str]) -> str:
    lines = [
        "# Source Intelligence Summary",
        "",
        f"- Target: {target}",
        f"- Generated at: {_now_utc()}",
        f"- Sources read: {len(sources)}",
        f"- Routes/API endpoints: {len(routes)}",
        f"- GraphQL operations: {len(graphql_ops)}",
        f"- Hypotheses: {len(hypotheses)}",
    ]
    for item in hypotheses[:12]:
        lines.append(f"- [{item['type']}] {item['candidate']} :: {item['reason']} ({item['source']})")
    if not hypotheses:
        lines.append("- No high-signal hypotheses yet; add repo_path or recon JS artifacts for richer results.")
    return "\n".join(lines) + "\n"


def run_source_intel(*, target: str, repo_path: str = "", repo_root: str | Path | None = None) -> dict:
    root = Path(repo_root) if repo_root else BASE_DIR
    target_key = _safe_target(target)
    texts: list[tuple[str, str]] = []
    for path in _iter_source_files(repo_path):
        try:
            rel = str(path.relative_to(Path(repo_path).expanduser().resolve()))
        except ValueError:
            rel = path.name
        texts.append((f"repo:{rel}", path.read_text(encoding="utf-8", errors="replace")))
    texts.extend(_read_recon_js_artifacts(root, target_key))

    routes = _dedupe([route for source, text in texts for route in _extract_routes(text, source)], ("route", "method", "source"))
    graphql_ops = _dedupe([op for source, text in texts for op in _extract_graphql(text, source)], ("operation", "name", "source"))
    keywords = _keyword_counts([text for _, text in texts])
    source_signals = _dedupe([signal for source, text in texts for signal in _extract_source_signals(text, source)], ("type", "candidate", "source"))
    hypotheses = _build_hypotheses(routes, graphql_ops, source_signals)
    out_dir = root / "findings" / target_key / "source_intel"
    artifacts = _write_outputs(out_dir, target, routes, graphql_ops, keywords, hypotheses, [source for source, _ in texts])
    return {
        "status": "ok",
        "target": target,
        "source_count": len(texts),
        "route_count": len(routes),
        "graphql_count": len(graphql_ops),
        "hypothesis_count": len(hypotheses),
        "artifacts": artifacts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract source intelligence hypotheses from local source and recon JS artifacts")
    parser.add_argument("--target", required=True, help="Target name used under findings/<target>/")
    parser.add_argument("--repo-path", default="", help="Optional local repository path to inspect")
    parser.add_argument("--repo-root", default=str(BASE_DIR), help="Repository root containing recon/ and findings/")
    args = parser.parse_args()
    result = run_source_intel(target=args.target, repo_path=args.repo_path, repo_root=args.repo_root)
    print(Path(result["artifacts"]["summary"]).read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
