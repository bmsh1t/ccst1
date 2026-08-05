#!/usr/bin/env python3
"""Choose bounded, rotating FFUF targets from the live HTTPX inventory.

The complete live URL list remains the recon source of truth.  This module
only owns the derived directory-fuzzing queue, so a five-host per-run budget
does not mark the remaining services as covered.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.technology_inventory import parse_httpx_text_line
    from tools.scope_context import ScopeContext, ScopeContextError
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from technology_inventory import parse_httpx_text_line  # type: ignore
    from scope_context import ScopeContext, ScopeContextError  # type: ignore


STATE_SCHEMA = 1
_CATEGORY_WEIGHTS = {
    "api": 80,
    "admin": 76,
    "auth": 72,
    "graphql": 68,
    "openapi": 62,
    "nonstandard-port": 58,
    "gated": 52,
}
_CATEGORY_PATTERNS = {
    "api": re.compile(r"(?:^|[./_-])(api|rest|v[0-9]+)(?:$|[./_-])"),
    "admin": re.compile(r"(?:^|[./_-])(admin|administrator|manage|management|console)(?:$|[./_-])"),
    "auth": re.compile(r"(?:^|[./_-])(auth|login|signin|sso|account|oauth)(?:$|[./_-])"),
    "graphql": re.compile(r"(?:^|[./_-])(graphql|gql)(?:$|[./_-])"),
    "openapi": re.compile(r"(?:^|[./_-])(swagger|openapi|api-docs)(?:$|[./_-])"),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def _atomic_json(path: Path, payload: dict) -> None:
    _atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint_urls(urls: list[str]) -> str:
    material = "\n".join(sorted(urls)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _normalize_url(raw: str) -> str:
    value = str(raw or "").strip()
    if not value.startswith(("http://", "https://")):
        return ""
    parsed = urlsplit(value)
    if not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), "", ""))


def _target_host(target: str) -> str:
    value = str(target or "").strip()
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return (parsed.hostname or "").lower()


def _target_port(target: str) -> int | None:
    value = str(target or "").strip()
    parsed = urlsplit(value if "://" in value else f"//{value}")
    try:
        return parsed.port
    except ValueError:
        return None


def _httpx_candidate(raw: str, target: str) -> dict | None:
    parsed = parse_httpx_text_line(raw)
    if parsed is not None:
        raw_url = str(parsed.get("url") or "")
        status = str(parsed.get("status") or "")
        technologies = tuple(
            sorted(
                {
                    str(item.get("name") or "").strip().lower()
                    for item in (parsed.get("components") or [])
                    if str(item.get("name") or "").strip()
                }
            )
        )
    else:
        raw_url = str(raw).strip().split(maxsplit=1)[0] if str(raw).strip() else ""
        status = ""
        technologies = ()

    url = _normalize_url(raw_url)
    if not url or not url_belongs_to_target(url, target):
        return None
    parsed_url = urlsplit(url)
    host = (parsed_url.hostname or "").lower()
    path_tokens = f"{host}{parsed_url.path.lower()}"
    tags = set()
    reasons = []
    if host == _target_host(target) and parsed_url.path in {"", "/"}:
        tags.add("root")
        reasons.append("target-root")
    for category, pattern in _CATEGORY_PATTERNS.items():
        if pattern.search(path_tokens):
            tags.add(category)
            reasons.append(category)
    try:
        port = parsed_url.port
    except ValueError:
        port = None
    target_port = _target_port(target)
    if port is not None and port not in {80, 443} and port != target_port:
        tags.add("nonstandard-port")
        reasons.append("nonstandard-port")
    status_code = status.split(",", 1)[0]
    if status_code in {"401", "403"}:
        tags.add("gated")
        reasons.append("auth-gated")

    return {
        "url": url,
        "host": host,
        "status": status,
        "technologies": list(technologies),
        "tags": sorted(tags),
        "reasons": reasons or ["live-host"],
    }


def _read_candidates(httpx_path: Path, urls_path: Path, target: str) -> list[dict]:
    candidates: list[dict] = []
    seen: set[str] = set()
    for path in (httpx_path, urls_path):
        if not path.is_file():
            continue
        with path.open(encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                candidate = _httpx_candidate(raw, target)
                if candidate and candidate["url"] not in seen:
                    seen.add(candidate["url"])
                    candidate["order"] = len(candidates)
                    candidates.append(candidate)
    return candidates


def _scope_identity(target: str) -> tuple[str, str]:
    try:
        context = ScopeContext.from_target(target)
    except ScopeContextError as exc:
        raise ValueError(f"invalid target Scope: {exc}") from exc
    return context.source_ref or context.root_target, context.scope_hash


def _load_state(
    path: Path,
    target: str,
    wordlist_sha256: str,
    urls: set[str],
    *,
    scope_ref: str = "",
    scope_hash: str = "",
) -> dict:
    canonical_target = canonical_target_value(target)
    if not path.exists():
        return {
            "schema": STATE_SCHEMA,
            "target": canonical_target,
            "wordlist_sha256": wordlist_sha256,
            "inventory_fingerprint": _fingerprint_urls(sorted(urls)),
            "scope_ref": scope_ref,
            "scope_hash": scope_hash,
            "completed": {},
            "active": [],
            "updated_at": _utc_now(),
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid FFUF target state: {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA:
        raise ValueError(f"invalid FFUF target state schema: {path}")
    if str(payload.get("target") or "") != canonical_target:
        raise ValueError(f"FFUF target state belongs to a different target: {path}")
    completed = payload.get("completed")
    if not isinstance(completed, dict):
        raise ValueError(f"invalid completed map in FFUF target state: {path}")
    active = payload.get("active", [])
    if not isinstance(active, list) or any(not isinstance(item, str) for item in active):
        raise ValueError(f"invalid active batch in FFUF target state: {path}")
    if str(payload.get("wordlist_sha256") or "") != wordlist_sha256:
        completed = {}
    if payload.get("scope_hash") and str(payload.get("scope_hash")) != scope_hash:
        completed = {}
    payload["completed"] = {
        url: value
        for url, value in completed.items()
        if url in urls and isinstance(value, dict) and value.get("status") == "ok"
    }
    payload["wordlist_sha256"] = wordlist_sha256
    payload["scope_ref"] = scope_ref
    payload["scope_hash"] = scope_hash
    payload["inventory_fingerprint"] = _fingerprint_urls(sorted(urls))
    payload["active"] = []
    return payload


def _pick_batch(candidates: list[dict], completed: set[str], limit: int) -> list[dict]:
    pending = [item for item in candidates if item["url"] not in completed]
    if not pending or limit <= 0:
        return []

    selected: list[dict] = []
    covered_tags: set[str] = set()
    covered_hosts: set[str] = set()
    covered_technologies: set[str] = set()
    root = next((item for item in pending if "root" in item["tags"]), None)
    if root is not None:
        selected.append(root)
        covered_tags.update(root["tags"])
        covered_hosts.add(root["host"])
        covered_technologies.update(root["technologies"])

    while len(selected) < limit and len(selected) < len(pending):
        remaining = [item for item in pending if item not in selected]
        def key(item: dict) -> tuple[int, int]:
            new_tags = set(item["tags"]) - covered_tags
            new_tech = set(item["technologies"]) - covered_technologies
            score = sum(_CATEGORY_WEIGHTS.get(tag, 0) for tag in new_tags)
            if item["host"] not in covered_hosts:
                score += 12
            score += len(new_tech) * 4
            return score, -int(item["order"])
        choice = max(remaining, key=key)
        selected.append(choice)
        covered_tags.update(choice["tags"])
        covered_hosts.add(choice["host"])
        covered_technologies.update(choice["technologies"])
    return selected


def select_targets(
    *,
    target: str,
    httpx_path: Path,
    urls_path: Path,
    state_path: Path,
    plan_path: Path,
    targets_path: Path,
    wordlist_path: Path,
    limit: int,
) -> dict:
    if limit < 1:
        raise ValueError("target selection limit must be positive")
    wordlist_sha256 = _sha256_file(wordlist_path)
    scope_ref, scope_hash = _scope_identity(target)
    candidates = _read_candidates(httpx_path, urls_path, target)
    urls = {item["url"] for item in candidates}
    state = _load_state(
        state_path,
        target,
        wordlist_sha256,
        urls,
        scope_ref=scope_ref,
        scope_hash=scope_hash,
    )
    completed = set(state["completed"])
    selected = _pick_batch(candidates, completed, limit)
    plan = {
        "schema": STATE_SCHEMA,
        "target": canonical_target_value(target),
        "scope_ref": scope_ref,
        "scope_hash": scope_hash,
        "limit": limit,
        "eligible_count": len(candidates),
        "completed_count": len(completed),
        "pending_count": max(0, len(candidates) - len(completed)),
        "remaining_count": max(0, len(candidates) - len(completed) - len(selected)),
        "exhausted": bool(candidates) and not selected and len(completed) >= len(candidates),
        "selected": selected,
        "generated_at": _utc_now(),
    }
    state["active"] = [item["url"] for item in selected]
    state["updated_at"] = _utc_now()
    _atomic_json(state_path, state)
    _atomic_json(plan_path, plan)
    _atomic_write(targets_path, "".join(f"{item['url']}\n" for item in selected))
    return plan


def record_results(*, target: str, state_path: Path, results_path: Path) -> dict:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid FFUF target state: {state_path}: {exc}") from exc
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        raise ValueError(f"invalid FFUF target state schema: {state_path}")
    if str(state.get("target") or "") != canonical_target_value(target):
        raise ValueError(f"FFUF target state belongs to a different target: {state_path}")
    _scope_ref, scope_hash = _scope_identity(target)
    if state.get("scope_hash") and str(state.get("scope_hash")) != scope_hash:
        raise ValueError(f"FFUF target state Scope changed: {state_path}")
    active_raw = state.get("active", [])
    if not isinstance(active_raw, list) or any(not isinstance(item, str) for item in active_raw):
        raise ValueError(f"invalid active batch in FFUF target state: {state_path}")
    active = set(active_raw)
    completed = state.get("completed")
    if not isinstance(completed, dict):
        raise ValueError(f"invalid completed map in FFUF target state: {state_path}")

    seen: set[str] = set()
    for raw in results_path.read_text(encoding="utf-8", errors="replace").splitlines():
        url, separator, status = raw.partition("\t")
        if not separator or not url or status not in {"ok", "partial", "failed"}:
            raise ValueError(f"invalid FFUF target result row: {results_path}")
        if url not in active:
            raise ValueError(f"FFUF result is not part of active target batch: {url}")
        if url in seen:
            raise ValueError(f"duplicate FFUF target result row: {url}")
        seen.add(url)
        if status == "ok":
            completed[url] = {"status": "ok", "completed_at": _utc_now()}
        else:
            completed.pop(url, None)
    state["completed"] = completed
    state["active"] = sorted(active - seen)
    state["updated_at"] = _utc_now()
    _atomic_json(state_path, state)
    return {
        "recorded": len(seen),
        "completed_count": len(completed),
        "active_count": len(state["active"]),
    }


def load_rotation_status(repo_root: str | Path, target: str) -> dict:
    """Read the compact rotation ledger for Autopilot next-action routing."""
    recon_dir = Path(repo_root) / "recon" / target_storage_key(target)
    plan_path = recon_dir / "dirs" / "ffuf_target_plan.json"
    state_path = recon_dir / "dirs" / "ffuf_target_state.json"
    if not plan_path.is_file() or not state_path.is_file():
        return {"status": "unavailable", "pending": False, "remaining": 0}
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(plan, dict) or plan.get("schema") != STATE_SCHEMA:
            raise ValueError("invalid plan schema")
        if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
            raise ValueError("invalid state schema")
        completed = state.get("completed")
        eligible_count = int(plan.get("eligible_count", 0))
        if not isinstance(completed, dict) or eligible_count < 0:
            raise ValueError("invalid rotation counters")
        scope_ref, scope_hash = _scope_identity(target)
        for payload in (plan, state):
            recorded_hash = str(payload.get("scope_hash") or "")
            if recorded_hash and recorded_hash != scope_hash:
                raise ValueError("Scope changed; FFUF rotation must restart")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "status": "invalid",
            "pending": False,
            "remaining": 0,
            "reason": str(exc),
        }
    remaining = max(0, eligible_count - len(completed))
    return {
        "status": "pending" if remaining else ("exhausted" if eligible_count else "empty"),
        "pending": bool(remaining),
        "remaining": remaining,
        "eligible": eligible_count,
        "completed": len(completed),
        "scope_ref": scope_ref,
        "scope_hash": scope_hash,
        "plan": str(plan_path),
        "state": str(state_path),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Select rotating bounded FFUF targets")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--select", action="store_true")
    mode.add_argument("--record-results", action="store_true")
    parser.add_argument("--target", required=True)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--httpx", type=Path, default=Path("live/httpx_full.txt"))
    parser.add_argument("--urls", type=Path, default=Path("live/urls.txt"))
    parser.add_argument("--plan", type=Path, default=Path("dirs/ffuf_target_plan.json"))
    parser.add_argument("--targets", type=Path, default=Path("dirs/ffuf_targets.txt"))
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--limit", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.select:
            if args.wordlist is None:
                raise ValueError("--wordlist is required with --select")
            payload = select_targets(
                target=args.target,
                httpx_path=args.httpx,
                urls_path=args.urls,
                state_path=args.state,
                plan_path=args.plan,
                targets_path=args.targets,
                wordlist_path=args.wordlist,
                limit=args.limit,
            )
        else:
            if args.results is None:
                raise ValueError("--results is required with --record-results")
            payload = record_results(target=args.target, state_path=args.state, results_path=args.results)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
