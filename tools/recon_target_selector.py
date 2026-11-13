#!/usr/bin/env python3
"""Choose bounded, rotating collection inputs from the live inventory.

The complete live URL list remains the recon source of truth.  This module
only owns derived sampling progress; collection receipts never establish
vulnerability coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    from tools.artifact_io import publish_bytes_create_only, write_text_atomic as _atomic_write
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import publish_bytes_create_only, write_text_atomic as _atomic_write


try:
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.technology_inventory import parse_httpx_text_line
    from tools.scope_context import ScopeContext, url_belongs_to_target
    from tools.scope_source import load_scope_context
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from technology_inventory import parse_httpx_text_line  # type: ignore
    from scope_context import ScopeContext, url_belongs_to_target  # type: ignore
    from scope_source import load_scope_context  # type: ignore


STATE_SCHEMA = 1
FFUF_INPUT_POLICY = hashlib.sha256(b"ffuf:exact-selected-origin:unfiltered-http-receipts:v2").hexdigest()
BASE_DIR = Path(__file__).resolve().parents[1]

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _word_progress(state: dict) -> dict[str, int]:
    """Validate optional FFUF progress without changing shared collection state."""
    if "word_count" not in state and "word_offsets" not in state:
        return {}
    total, offsets = state.get("word_count"), state.get("word_offsets")
    if (type(total) is not int or total <= 0 or not isinstance(offsets, dict)
            or any(not isinstance(url, str) or type(offset) is not int
                   or not 0 <= offset <= total for url, offset in offsets.items())):
        raise ValueError("invalid FFUF word progress")
    if any(offset == total and url not in state.get("completed", {}) for url, offset in offsets.items()):
        raise ValueError("FFUF word progress is complete without a completed target")
    return offsets


def _word_accounting(state: dict, eligible: int) -> dict:
    offsets = _word_progress(state)
    if "word_count" not in state:
        return {}
    completed = state["completed"]
    if len(set(offsets) | set(completed)) > eligible:
        raise ValueError("FFUF word progress exceeds eligible targets")
    total = state["word_count"] * eligible
    done = state["word_count"] * len(completed) + sum(
        offset for url, offset in offsets.items() if url not in completed
    )
    return {"word_count": state["word_count"], "words_total": total,
            "words_completed": done, "words_remaining": total - done}


def _normalize_url(raw: str) -> str:
    value = str(raw or "").strip()
    if not value.startswith(("http://", "https://")):
        return ""
    parsed = urlsplit(value)
    if not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), "", ""))


def _httpx_candidate(raw: str, target: str, context: ScopeContext) -> dict | None:
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
    if not url or not context.allows_active(url):
        return None
    parsed_url = urlsplit(url)
    host = (parsed_url.hostname or "").lower()
    return {
        "url": url,
        "host": host,
        "status": status,
        "technologies": list(technologies),
    }


def _read_candidates(httpx_path: Path, urls_path: Path, target: str, context: ScopeContext) -> list[dict]:
    candidates: list[dict] = []
    seen: set[str] = set()
    for path in (httpx_path, urls_path):
        if not path.is_file():
            continue
        with path.open(encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                candidate = _httpx_candidate(raw, target, context)
                if candidate and candidate["url"] not in seen:
                    seen.add(candidate["url"])
                    candidates.append(candidate)
    return candidates


def _load_state(
    path: Path,
    target: str,
    wordlist_sha256: str,
    urls: set[str],
    *,
    scope_ref: str = "",
    scope_hash: str = "",
    fingerprint_field: str = "wordlist_sha256",
) -> dict:
    canonical_target = canonical_target_value(target)
    if not path.exists():
        return {
            "schema": STATE_SCHEMA,
            "target": canonical_target,
            fingerprint_field: wordlist_sha256,
            **({"input_policy_sha256": FFUF_INPUT_POLICY} if fingerprint_field == "wordlist_sha256" else {}),
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
        raise ValueError(f"invalid Recon sampling state: {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA:
        raise ValueError(f"invalid Recon sampling state schema: {path}")
    if str(payload.get("target") or "") != canonical_target:
        raise ValueError(f"Recon sampling state belongs to a different target: {path}")
    if not isinstance(payload.get("last_selected", ""), str):
        raise ValueError(f"invalid selection position: {path}")
    completed = payload.get("completed")
    if not isinstance(completed, dict):
        raise ValueError(f"invalid completed map in Recon sampling state: {path}")
    active = payload.get("active", [])
    if not isinstance(active, list) or any(not isinstance(item, str) for item in active):
        raise ValueError(f"invalid active batch in Recon sampling state: {path}")
    if (str(payload.get(fingerprint_field) or "") != wordlist_sha256
            or str(payload.get("scope_hash") or "") != scope_hash
            or (fingerprint_field == "wordlist_sha256"
                and payload.get("input_policy_sha256") != FFUF_INPUT_POLICY)):
        completed = {}
        payload["last_selected"] = ""
        for name in ("word_count", "word_offsets", "active_word_pages"):
            payload.pop(name, None)
    if fingerprint_field == "wordlist_sha256":
        payload["input_policy_sha256"] = FFUF_INPUT_POLICY
        offsets = _word_progress(payload)
        if "word_count" in payload:
            payload["word_offsets"] = {url: offset for url, offset in offsets.items() if url in urls}
        payload.pop("active_word_pages", None)
    payload["completed"] = {
        url: value
        for url, value in completed.items()
        if url in urls and isinstance(value, dict) and value.get("status") == "ok"
    }
    payload[fingerprint_field] = wordlist_sha256
    payload["scope_ref"] = scope_ref
    payload["scope_hash"] = scope_hash
    payload["inventory_fingerprint"] = _fingerprint_urls(sorted(urls))
    payload["active"] = []
    return payload


def _pick_batch(candidates: list[dict], completed: set[str], limit: int, after: str = "",
                preferred: list[str] | None = None) -> list[dict]:
    """Apply the batch budget in explicit URL order, without category preferences."""
    if limit <= 0:
        return []
    pending = sorted((item for item in candidates if item["url"] not in completed),
                     key=lambda item: item["url"])
    pending = ([item for item in pending if item["url"] > after]
               + [item for item in pending if item["url"] <= after])
    if preferred is not None:
        order = list(dict.fromkeys(preferred))
        if after in order:
            position = order.index(after) + 1
            order = order[position:] + order[:position]
        positions = {url: index for index, url in enumerate(order)}
        pending = sorted((item for item in pending if item["url"] in positions),
                         key=lambda item: positions[item["url"]])
    return pending[:limit]


def batch_progress(targets: list[str], completed: list[str], failed: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Keep untried targets first, then failures in least-recently-attempted order."""
    current = set(targets)
    completed = list(dict.fromkeys(item for item in completed if item in current))
    done = set(completed)
    failed = list(reversed(dict.fromkeys(
        item for item in reversed(failed) if item in current and item not in done
    )))
    attempted = done | set(failed)
    pending = [item for item in dict.fromkeys(targets) if item not in attempted]
    return completed, failed, [*pending, *failed]


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
    repo_root: str | Path = BASE_DIR,
    word_limit: int = 0,
    wordlist_dir: Path | None = None,
    preferred: list[str] | None = None,
) -> dict:
    if limit < 1:
        raise ValueError("target selection limit must be positive")
    if type(word_limit) is not int or word_limit < 0 or (word_limit and wordlist_dir is None):
        raise ValueError("word_limit must be nonnegative; paging requires wordlist_dir")
    words = None
    if word_limit:
        with wordlist_path.open("rb") as handle:
            words = list(handle)
        if not words:
            raise ValueError("cannot page an empty FFUF wordlist")
        wordlist_sha256 = hashlib.sha256(b"".join(words)).hexdigest()
    else:
        wordlist_sha256 = _sha256_file(wordlist_path)
    context = load_scope_context(repo_root, target)
    scope_ref, scope_hash = context.source_ref or context.root_target, context.scope_hash
    candidates = _read_candidates(httpx_path, urls_path, target, context)
    urls = {item["url"] for item in candidates}
    state = _load_state(
        state_path,
        target,
        wordlist_sha256,
        urls,
        scope_ref=scope_ref,
        scope_hash=scope_hash,
    )
    if words is not None:
        if "word_count" in state and state["word_count"] != len(words):
            raise ValueError("FFUF word count disagrees with the bound wordlist")
        state["word_count"] = len(words)
        state.setdefault("word_offsets", {})
    return _publish_selection(target, candidates, state, state_path, plan_path, targets_path,
                              limit, words=words, word_limit=word_limit, wordlist_dir=wordlist_dir,
                              preferred=[_normalize_url(url) for url in preferred] if preferred is not None else None)


def select_collection(*, target: str, urls: list[str], identity: str, state_path: Path,
                      plan_path: Path, targets_path: Path, limit: int,
                      repo_root: str | Path = BASE_DIR, origins_only: bool = False,
                      preferred: list[str] | None = None) -> dict:
    """Select collection seeds; only published result receipts can complete them."""
    if limit < 1 or not identity.strip():
        raise ValueError("collection identity and positive limit are required")
    context = load_scope_context(repo_root, target)
    eligible = set()
    for url in urls:
        url = url.strip()
        if not url or not url_belongs_to_target(url, target) or not context.allows_active(url):
            continue
        if origins_only:
            parsed = urlsplit(url)
            url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            if not context.allows_active(url):
                continue
        eligible.add(url)
    if preferred is not None:
        preferred = [url.strip() for url in preferred if url.strip()]
        if origins_only:
            preferred = [urlunsplit((*urlsplit(url)[:2], "", "", "")) for url in preferred]
    fingerprint = _fingerprint_urls([identity, f"origins_only={origins_only}"])
    state = _load_state(state_path, target, fingerprint, eligible,
                        scope_ref=context.source_ref or context.root_target,
                        scope_hash=context.scope_hash, fingerprint_field="collection_fingerprint")
    return _publish_selection(target, [{"url": url} for url in sorted(eligible)], state,
                              state_path, plan_path, targets_path, limit,
                              preferred=preferred)


def _publish_selection(target: str, candidates: list[dict], state: dict, state_path: Path,
                       plan_path: Path, targets_path: Path, limit: int, *,
                       words: list[bytes] | None = None, word_limit: int = 0,
                       wordlist_dir: Path | None = None, preferred: list[str] | None = None) -> dict:
    completed = set(state["completed"])
    selected = _pick_batch(candidates, completed, limit, str(state.get("last_selected") or ""), preferred)
    if words is not None:
        state["active_word_pages"] = {}
        for number, item in enumerate(selected, 1):
            start = state["word_offsets"].get(item["url"], 0)
            end = min(start + word_limit, len(words))
            if start >= end:
                raise ValueError("FFUF word progress is complete without a completed target")
            binding = [state["target"], state["scope_hash"], FFUF_INPUT_POLICY,
                       state["wordlist_sha256"], item["url"], start, end]
            receipt = hashlib.sha256(json.dumps(binding).encode()).hexdigest()
            page = {"start": start, "end": end, "receipt": receipt}
            path = wordlist_dir / f"{number:04d}.txt"
            publish_bytes_create_only(path, b"".join(words[start:end]))
            state["active_word_pages"][item["url"]] = page
            item["word_page"] = {**page, "path": str(path)}
    plan = {
        "schema": STATE_SCHEMA,
        "target": canonical_target_value(target),
        "scope_ref": state["scope_ref"],
        "scope_hash": state["scope_hash"],
        **({"input_policy_sha256": state["input_policy_sha256"]} if "wordlist_sha256" in state else {}),
        "limit": limit,
        "order": "selected-input" if preferred is not None else "rotating-url",
        "eligible_count": len(candidates),
        "completed_count": len(completed),
        "pending_count": max(0, len(candidates) - len(completed)),
        "remaining_count": max(0, len(candidates) - len(completed) - len(selected)),
        "exhausted": bool(candidates) and len(completed) >= len(candidates),
        "selected": selected,
        "generated_at": _utc_now(),
        **_word_accounting(state, len(candidates)),
    }
    state["active"] = [item["url"] for item in selected]
    state["eligible_count"] = len(candidates)
    if selected:
        state["last_selected"] = selected[-1]["url"]
    state["updated_at"] = _utc_now()
    _atomic_json(state_path, state)
    _atomic_json(plan_path, plan)
    _atomic_write(targets_path, "".join(f"{item['url']}\n" for item in selected))
    return plan


def record_results(*, target: str, state_path: Path, results_path: Path,
                   repo_root: str | Path = BASE_DIR) -> dict:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid Recon sampling state: {state_path}: {exc}") from exc
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        raise ValueError(f"invalid Recon sampling state schema: {state_path}")
    if str(state.get("target") or "") != canonical_target_value(target):
        raise ValueError(f"Recon sampling state belongs to a different target: {state_path}")
    if "wordlist_sha256" in state and state.get("input_policy_sha256") != FFUF_INPUT_POLICY:
        raise ValueError("FFUF input policy changed or missing; select targets again before recording")
    scope_hash = load_scope_context(repo_root, target).scope_hash
    if str(state.get("scope_hash") or "") != scope_hash:
        raise ValueError(f"Recon sampling state Scope changed or binding missing: {state_path}")
    active_raw = state.get("active", [])
    if not isinstance(active_raw, list) or any(not isinstance(item, str) for item in active_raw):
        raise ValueError(f"invalid active batch in Recon sampling state: {state_path}")
    active = set(active_raw)
    completed = state.get("completed")
    if not isinstance(completed, dict):
        raise ValueError(f"invalid completed map in Recon sampling state: {state_path}")
    offsets = _word_progress(state)
    pages = state.get("active_word_pages", {})
    if (not isinstance(pages, dict)
            or ("active_word_pages" in state and set(pages) != active)):
        raise ValueError("invalid FFUF active word pages")

    seen: set[str] = set()
    for raw in results_path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = raw.split("\t")
        if len(fields) not in (2, 3):
            raise ValueError(f"invalid Recon sampling result row: {results_path}")
        url, status = fields[:2]
        if not url or status not in {"ok", "partial", "failed"}:
            raise ValueError(f"invalid Recon sampling result row: {results_path}")
        if url not in active:
            raise ValueError(f"Recon sampling result is not part of active target batch: {url}")
        if url in seen:
            raise ValueError(f"duplicate Recon sampling result row: {url}")
        page = pages.get(url)
        if page is not None:
            if (not isinstance(page, dict) or len(fields) != 3
                    or fields[2] != page.get("receipt")
                    or type(page.get("start")) is not int or type(page.get("end")) is not int
                    or page["start"] != offsets.get(url, 0)
                    or not 0 <= page["start"] < page["end"] <= state.get("word_count", 0)):
                raise ValueError("FFUF result does not match the active word page")
        elif len(fields) != 2 or pages:
            raise ValueError("FFUF result has no matching active word page")
        seen.add(url)
        if status == "ok":
            if page is not None:
                offsets[url] = page["end"]
            if page is None or page["end"] == state["word_count"]:
                completed[url] = {"status": "ok", "completed_at": _utc_now()}
        else:
            completed.pop(url, None)
    state["completed"] = completed
    state["active"] = sorted(active - seen)
    if "active_word_pages" in state:
        state["active_word_pages"] = {url: page for url, page in pages.items() if url not in seen}
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
        context = load_scope_context(repo_root, target)
        scope_ref, scope_hash = context.source_ref or context.root_target, context.scope_hash
        for payload in (plan, state):
            if payload.get("input_policy_sha256") != FFUF_INPUT_POLICY:
                raise ValueError("FFUF input policy changed or missing; rotation must restart")
            recorded_hash = str(payload.get("scope_hash") or "")
            if recorded_hash != scope_hash:
                raise ValueError("Scope changed or binding missing; FFUF rotation must restart")
        words = _word_accounting(state, eligible_count)
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
        **words,
    }


def collection_accounting(*, target: str, state_path: Path, plan_path: Path,
                          repo_root: str | Path = BASE_DIR) -> str:
    """Describe published collection progress, refusing mismatched snapshots."""
    state = json.loads(state_path.read_text(encoding="utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    scope_hash = load_scope_context(repo_root, target).scope_hash
    for payload in (state, plan):
        if (not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA
                or payload.get("target") != canonical_target_value(target)
                or payload.get("scope_hash") != scope_hash):
            raise ValueError("collection accounting target/schema/Scope mismatch")
    total = plan.get("eligible_count")
    completed = state.get("completed")
    selected = plan.get("selected")
    if (type(total) is not int or total < 0 or total != state.get("eligible_count")
            or not isinstance(completed, dict) or len(completed) > total
            or any(not isinstance(item, dict) or item.get("status") != "ok" for item in completed.values())
            or not isinstance(selected, list) or len(selected) > total):
        raise ValueError("invalid collection accounting counts")
    words = "; ".join(f"{key}={value}" for key, value in _word_accounting(state, total).items())
    return (f"input_total={total}; selected={len(completed)}; remaining={total-len(completed)}; "
            f"batch_selected={len(selected)}; selected_means=collected_successfully"
            + (f"; {words}" if words else ""))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Select rotating bounded Recon inputs")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--select", action="store_true")
    mode.add_argument("--record-results", action="store_true")
    mode.add_argument("--accounting", action="store_true")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", type=Path, default=BASE_DIR)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--httpx", type=Path, default=Path("live/httpx_full.txt"))
    parser.add_argument("--urls", type=Path, default=Path("live/urls.txt"))
    parser.add_argument("--plan", type=Path, default=Path("dirs/ffuf_target_plan.json"))
    parser.add_argument("--targets", type=Path, default=Path("dirs/ffuf_targets.txt"))
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--word-limit", type=int, default=0,
                        help="Maximum words per selected FFUF target; zero keeps the complete wordlist")
    parser.add_argument("--wordlist-dir", type=Path, help="Run-local directory for selected word pages")
    parser.add_argument("--collection-identity")
    parser.add_argument("--origins-only", action="store_true")
    parser.add_argument("--prefer", type=Path, help="Select from this explicit subset without dropping inventory progress")
    parser.add_argument("--results", type=Path)
    parser.add_argument("--limit", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.accounting:
            print(collection_accounting(target=args.target, state_path=args.state,
                                        plan_path=args.plan, repo_root=args.repo_root))
            return 0
        if args.select and args.collection_identity:
            preferred = args.prefer.read_text(encoding="utf-8").splitlines() if args.prefer else None
            payload = select_collection(
                target=args.target, urls=args.urls.read_text(encoding="utf-8").splitlines(),
                identity=args.collection_identity, state_path=args.state, plan_path=args.plan,
                targets_path=args.targets, limit=args.limit, repo_root=args.repo_root,
                origins_only=args.origins_only,
                preferred=preferred,
            )
        elif args.select:
            if args.wordlist is None:
                raise ValueError("--wordlist is required with --select")
            payload = select_targets(
                target=args.target,
                repo_root=args.repo_root,
                httpx_path=args.httpx,
                urls_path=args.urls,
                state_path=args.state,
                plan_path=args.plan,
                targets_path=args.targets,
                wordlist_path=args.wordlist,
                limit=args.limit,
                word_limit=args.word_limit,
                wordlist_dir=args.wordlist_dir,
                preferred=args.prefer.read_text(encoding="utf-8").splitlines() if args.prefer else None,
            )
        else:
            if args.results is None:
                raise ValueError("--results is required with --record-results")
            payload = record_results(target=args.target, state_path=args.state,
                                     results_path=args.results, repo_root=args.repo_root)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
