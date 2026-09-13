#!/usr/bin/env python3
"""Extract route, method, GraphQL and source-marker observations for Claude."""

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
WEBSOCKET_KEYWORDS = ("websocket", "socket.io", "sockjs", "signalr", "stomp", "subscription")
CSRF_MARKERS = ("csrf_token", "csrftoken", "csrfmiddlewaretoken", "__requestverificationtoken", "x-csrf-token", "xsrf", "samesite")
FRAMEWORK_MARKERS = (
    "__next_data__", "/_next/static", "_buildmanifest", "buildmanifest",
    "sourcemappingurl", ".js.map", "__nuxt__", "/_nuxt/", "middleware-manifest",
    "server actions", "serveractions",
)
ROUTE_RE = re.compile(r"""(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS)?\s*["'`]((?:(?:https?|wss?)://[^"'`\s]+)|(?:/[A-Za-z0-9._~:/?#[\]@!$&()*+,;=%{}-]*))["'`]""", re.I)
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


def _extract_routes(text: str, source: str) -> list[dict]:
    routes = []
    for line in text.splitlines():
        value = line.strip()
        if re.fullmatch(r"(?:https?|wss?)://[^\s\"'`]+|/[^\s\"'`]*", value):
            routes.append({"route": value, "method": "", "source": source})
    for match in FRAMEWORK_ROUTE_RE.finditer(text):
        routes.append({"route": match.group(2), "method": match.group("method").upper(), "source": source})
    for match in ROUTE_RE.finditer(text):
        route = match.group(2)
        routes.append({"route": route, "method": (match.group("method") or "").upper(), "source": source})
    return _dedupe(routes, ("route", "method", "source"))


def _extract_graphql(text: str, source: str) -> list[dict]:
    ops = []
    for match in GRAPHQL_RE.finditer(text):
        ops.append({"operation": match.group(1).lower(), "name": match.group(2) or "", "source": source})
    return _dedupe(ops, ("operation", "name", "source"))


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
    """Return actual marker lines, without assigning risk or a testing method."""
    signals = []
    for kind, markers in (
        ("realtime", ("new websocket", "ws://", "wss://", *WEBSOCKET_KEYWORDS)),
        ("framework", FRAMEWORK_MARKERS),
        ("csrf_fields", CSRF_MARKERS),
        ("oauth_fields", ("redirect_uri", "client_id", "code_challenge", "email_verified")),
    ):
        evidence = _first_matching_line(text, markers)
        if evidence:
            signals.append({"kind": kind, "source": source, "evidence": evidence})
    return signals


def _write_outputs(out_dir: Path, target: str, observations: dict, sources: list[str]) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "routes.json").write_text(json.dumps(observations, indent=2) + "\n", encoding="utf-8")
    summary = render_summary(target, observations, sources)
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")
    return {"summary": str(out_dir / "summary.md"), "routes": str(out_dir / "routes.json")}


def render_summary(target: str, observations: dict, sources: list[str]) -> str:
    routes = observations["routes"]
    lines = [
        "# Source Observations", "",
        f"- Target: {target}",
        f"- Generated at: {_now_utc()}",
        f"- Sources read: {len(sources)}",
        f"- Routes: {len(routes)}",
        f"- GraphQL operations: {len(observations['graphql_operations'])}",
        f"- Source markers: {len(observations['signals'])}",
        "- Full observations: routes.json; interpretation and test selection belong to Claude.",
    ]
    for item in routes[:12]:
        lines.append(f"- {item['method']} {item['route']} ({item['source']})")
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
    source_signals = _dedupe([signal for source, text in texts for signal in _extract_source_signals(text, source)], ("kind", "source", "evidence"))
    out_dir = root / "findings" / target_key / "source_intel"
    artifacts = _write_outputs(out_dir, target, {
        "routes": routes, "graphql_operations": graphql_ops, "signals": source_signals,
    }, [source for source, _ in texts])
    return {
        "status": "ok",
        "target": target,
        "source_count": len(texts),
        "route_count": len(routes),
        "graphql_count": len(graphql_ops),
        "signal_count": len(source_signals),
        "artifacts": artifacts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract route and source observations from local source and recon JS artifacts")
    parser.add_argument("--target", required=True, help="Target name used under findings/<target>/")
    parser.add_argument("--repo-path", default="", help="Optional local repository path to inspect")
    parser.add_argument("--repo-root", default=str(BASE_DIR), help="Repository root containing recon/ and findings/")
    args = parser.parse_args()
    result = run_source_intel(target=args.target, repo_path=args.repo_path, repo_root=args.repo_root)
    print(Path(result["artifacts"]["summary"]).read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
