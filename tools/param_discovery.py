#!/usr/bin/env python3
"""Scope- and auth-aware hidden-parameter discovery."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urljoin, urlsplit

BASE_DIR = Path(__file__).resolve().parents[1]
MAX_URLS = 5
DEFAULT_TIMEOUT = 180
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.action_queue import build_action, load_queue, queue_mutation_lock, save_queue, upsert_actions
    from tools.auth_session import AuthSession, add_cli_args, session_from_args
    from tools.browser_surface import public_url_shape
    from tools.private_artifacts import private_artifact_dir, write_private_text
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.validation_runner import request_once
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import build_action, load_queue, queue_mutation_lock, save_queue, upsert_actions  # type: ignore
    from auth_session import AuthSession, add_cli_args, session_from_args  # type: ignore
    from browser_surface import public_url_shape  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_text  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from validation_runner import request_once  # type: ignore


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_lines(path: Path, limit: int = 1000) -> list[str]:
    if not path.is_file():
        return []
    result: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = raw.strip()
        if value and not value.startswith("#"):
            result.append(value)
        if len(result) >= limit:
            break
    return result


def _line_url(value: str) -> str:
    value = str(value or "").strip()
    return value.split()[0].rstrip(",;") if value else ""


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    return public_url_shape(f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}")


def _validate_urls(values: Iterable[str], target: str) -> tuple[list[str], list[dict[str, str]]]:
    accepted: list[str] = []
    rejected: list[dict[str, str]] = []
    for raw in _unique(_line_url(value) for value in values):
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            rejected.append({"url": raw[:240], "reason": "absolute HTTP(S) URL required"})
        elif not url_belongs_to_target(raw, target):
            rejected.append({"url": _safe_url(raw), "reason": "outside target scope"})
        else:
            accepted.append(raw)
    return accepted, rejected


def _recon_inputs(repo_root: Path, target: str, method: str) -> list[str]:
    recon_dir = repo_root / "recon" / target_storage_key(canonical_target_value(target))
    names = ("urls/with_params.txt", "urls/all.txt", "live/urls.txt") if method == "GET" else ("live/urls.txt", "live/httpx_full.txt")
    values: list[str] = []
    for name in names:
        values.extend(_line_url(line) for line in _read_lines(recon_dir / name))
    return _unique(values)


class _PostFormParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.current: dict[str, Any] | None = None
        self.forms: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            if attrs_map.get("method", "get").lower() == "post":
                self.current = {"source": self.page_url, "action": attrs_map.get("action") or self.page_url, "params": []}
            return
        if self.current is not None and tag.lower() in {"input", "textarea", "select", "button"}:
            name = attrs_map.get("name", "").strip()
            if name and name not in self.current["params"]:
                self.current["params"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.current is not None:
            if self.current["params"]:
                self.forms.append(self.current)
            self.current = None


def _extract_post_forms(page_url: str, body: str) -> list[dict[str, Any]]:
    parser = _PostFormParser(page_url)
    parser.feed(body)
    parser.close()
    return [{**form, "action": urljoin(page_url, str(form["action"]))} for form in parser.forms]


def _fetch_forms(
    url: str,
    *,
    target: str,
    session: AuthSession,
    timeout: int,
    fetch_html: Callable[[str], tuple[int | None, str]] | None,
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        if fetch_html is None:
            response = request_once(
                target=target,
                url=url,
                headers=session.headers_for_url(url),
                timeout=min(timeout, 30),
                max_body_bytes=2 * 1024 * 1024,
            )
            status, body = int(response["status"]), str(response.get("body") or "")
        else:
            status, body = fetch_html(url)
        if status != 200 or not body:
            return [], f"form fetch returned status {status}"
        forms = _extract_post_forms(url, body)
        return [form for form in forms if url_belongs_to_target(str(form["action"]), target)], None
    except Exception as exc:
        return [], f"form fetch failed: {type(exc).__name__}: {exc}"


def _raw_request_file(private_dir: Path, url: str, session: AuthSession, method: str) -> Path:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    headers = {"Host": parsed.netloc, **session.headers_for_url(url)}
    request_text = method.upper() + " " + path + " HTTP/1.1\r\n" + "\r\n".join(
        f"{name}: {value}" for name, value in headers.items()
    ) + "\r\n\r\n"
    fd, raw_path = tempfile.mkstemp(prefix="request-", suffix=".http", dir=private_dir)
    os.close(fd)
    path_obj = Path(raw_path)
    write_private_text(path_obj, request_text)
    return path_obj


def _parse_output(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    names: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in {"params", "parameters", "found_parameters", "parameter_names"}:
                    if isinstance(item, list):
                        names.extend(str(entry).strip() for entry in item if str(entry).strip())
                    elif isinstance(item, str):
                        names.extend(part.strip() for part in re.split(r"[,\s]+", item) if part.strip())
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    try:
        visit(json.loads(text))
    except (json.JSONDecodeError, TypeError):
        pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        names.extend(match.group(1) for match in re.finditer(r"(?:[?&]|\b)([A-Za-z_][A-Za-z0-9_.-]{0,80})=", line))
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,80}", line):
            names.append(line)
    return _unique(names)


def _run_tool(argv: list[str], *, cwd: Path, timeout: int) -> tuple[int, str]:
    try:
        completed = subprocess.run(argv, cwd=str(cwd), text=True, capture_output=True, timeout=timeout, check=False)
        return int(completed.returncode), (completed.stderr or "")[-500:]
    except subprocess.TimeoutExpired:
        return 124, "subprocess timeout"
    except OSError as exc:
        return 127, f"subprocess error: {exc}"


def _tool_for(session: AuthSession, tool_exists: Callable[[str], bool]) -> str:
    if not session.is_empty():
        # Arjun has no private request-file path here; never silently turn an
        # authenticated run into anonymous probing.
        return "x8" if tool_exists("x8") else ""
    if tool_exists("arjun"):
        return "arjun"
    if tool_exists("x8"):
        return "x8"
    return ""


def _run_discovery(*, repo_root: Path, target: str, method: str, urls: list[str], session: AuthSession, timeout: int, tool_exists: Callable[[str], bool]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    tool = _tool_for(session, tool_exists)
    runs: list[dict[str, Any]] = []
    discoveries: list[dict[str, Any]] = []
    errors: list[str] = []
    if not tool:
        reason = "x8 is required for authenticated parameter discovery" if not session.is_empty() else "neither arjun nor x8 is installed"
        return runs, discoveries, [reason]
    output_dir = repo_root / "recon" / target_storage_key(canonical_target_value(target)) / "params"
    output_dir.mkdir(parents=True, exist_ok=True)
    private_dir = private_artifact_dir(repo_root, "param_discovery", target_storage_key(canonical_target_value(target)))
    wordlist = BASE_DIR / "wordlists" / "params.txt"
    for index, url in enumerate(urls[:MAX_URLS], start=1):
        output_path = output_dir / f"{tool}_{method.lower()}_{index}.txt"
        output_path.unlink(missing_ok=True)
        request_path: Path | None = None
        if tool == "arjun":
            argv = ["arjun", "-u", url, "-m", method, "-oT", str(output_path), "-q", "-t", "5", "-T", str(max(1, min(timeout, 60)))]
            if wordlist.is_file():
                argv.extend(["-w", str(wordlist)])
        else:
            argv = ["x8", "-o", str(output_path), "-O", "json", "--remove-empty", "--disable-progress-bar", "--timeout", str(max(1, min(timeout, 60))), "-X", method]
            if session.is_empty():
                argv.extend(["-u", url])
            else:
                request_path = _raw_request_file(private_dir, url, session, method)
                parsed = urlsplit(url)
                argv.extend(["-r", str(request_path), "--proto", parsed.scheme, "--port", str(parsed.port or (443 if parsed.scheme == "https" else 80))])
            if wordlist.is_file():
                argv.extend(["-w", str(wordlist)])
        code, error = _run_tool(argv, cwd=repo_root, timeout=max(1, timeout))
        names = _parse_output(output_path)
        runs.append({"tool": tool, "method": method, "endpoint": _safe_url(url), "status": "ok" if code == 0 else "failed", "exit_code": code, "output": str(output_path.relative_to(repo_root)), "params": names[:100]})
        if code != 0:
            errors.append(f"{tool} {method} {_safe_url(url)} exit={code}: {error}".strip())
        discoveries.extend({"endpoint": _safe_url(url), "method": method, "param": name, "source": tool} for name in names[:100])
        if request_path is not None:
            request_path.unlink(missing_ok=True)
    return runs, discoveries, errors


def _sync_action_queue(repo_root: Path, target: str, summary: dict[str, Any]) -> dict[str, Any]:
    counts = summary["counts"]
    if summary["status"] == "blocked":
        status, priority, question = "blocked", 55, "Install Arjun or x8, then resume hidden-parameter discovery."
    elif summary["status"] in {"partial", "no_input"}:
        status, priority, question = "lead", 60, "Review parameter discovery errors or provide a target-owned endpoint list, then resume."
    elif counts["discoveries"]:
        status, priority, question = "signal", 78, "Review discovered parameters and route each high-value shape into the matching validation runner."
    else:
        status, priority, question = "tested", 45, "No hidden parameter signal was observed; continue with the next evidence-backed lane."
    summary_ref = str(summary["artifacts"]["summary"])
    action = build_action(
        target=target,
        action_type="parameter-discovery",
        evidence=f"Hidden parameter discovery summary: {summary_ref}",
        next_question=question,
        action="Review the structured summary and preserve discovered parameter names as inert surface shapes.",
        priority=priority,
        command_hint=f"python3 tools/param_discovery.py --target {shlex.quote(target)} --from-recon --method {shlex.quote(summary['method'])} --repo-root {shlex.quote(str(repo_root))}",
        evidence_type="parameter-discovery-summary",
        source="param_discovery",
        source_id="hidden-parameters",
        metadata={"summary_path": summary_ref, "method": summary["method"], "counts": counts, "session_id": summary.get("session_id", "")},
    )
    action["status"] = status
    with queue_mutation_lock(repo_root, target):
        queue = load_queue(repo_root, target)
        existing = next((item for item in queue.get("actions", []) if isinstance(item, dict) and item.get("source") == "param_discovery" and item.get("source_id") == "hidden-parameters"), None)
        if existing is None:
            upsert_actions(queue, [action])
            existing = action
        else:
            prior = str(existing.get("status") or "queued")
            effective = prior if prior in {"signal", "candidate"} and status == "tested" else status
            existing.update({"status": effective, "priority": max(int(existing.get("priority", 50) or 50), priority), "evidence": action["evidence"], "next_question": action["next_question"] if effective != "signal" else existing.get("next_question", question), "action": action["action"], "command_hint": action["command_hint"], "result": f"parameter-discovery status={summary['status']}; summary={summary_ref}", "updated_at": action["updated_at"], "metadata": action.get("metadata", {})})
        path = save_queue(repo_root, target, queue)
    return {"status": "updated", "path": str(path.relative_to(repo_root)), "action_id": existing.get("id", ""), "queue_status": existing.get("status", status)}


def discover_parameters(*, repo_root: Path | str = BASE_DIR, target: str, urls: Iterable[str] | None = None, methods: Iterable[str] = ("GET",), session: AuthSession | None = None, max_urls: int = MAX_URLS, timeout: int = DEFAULT_TIMEOUT, fetch_html: Callable[[str], tuple[int | None, str]] | None = None, tool_exists: Callable[[str], bool] | None = None) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    resolved_target = canonical_target_value(target)
    active_session = (session or AuthSession()).bind_target(target)
    tool_exists = tool_exists or (lambda name: shutil.which(name) is not None)
    selected_methods = tuple(dict.fromkeys(str(method).upper() for method in methods if str(method).upper() in {"GET", "POST"}))
    if not selected_methods:
        raise ValueError("methods must include GET or POST")
    max_urls = max(1, min(int(max_urls or MAX_URLS), MAX_URLS))
    source_values = list(urls) if urls is not None else []
    from_recon = urls is None
    rejected: list[dict[str, str]] = []
    all_runs: list[dict[str, Any]] = []
    all_discoveries: list[dict[str, Any]] = []
    errors: list[str] = []
    existing_params: list[str] = []
    post_forms: dict[str, dict[str, Any]] = {}
    for method in selected_methods:
        values = source_values if not from_recon else _recon_inputs(repo, target, method)
        accepted, refused = _validate_urls(values, target)
        rejected.extend(refused)
        accepted = accepted[:max_urls]
        if method == "GET":
            for url in accepted:
                existing_params.extend(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True))
            if accepted:
                runs, discoveries, run_errors = _run_discovery(repo_root=repo, target=target, method=method, urls=accepted, session=active_session, timeout=timeout, tool_exists=tool_exists)
            else:
                runs, discoveries, run_errors = [], [], []
        else:
            targets: list[str] = []
            for url in accepted:
                forms, form_error = _fetch_forms(url, target=target, session=active_session, timeout=timeout, fetch_html=fetch_html)
                if form_error:
                    errors.append(f"{_safe_url(url)}: {form_error}")
                for form in forms:
                    action_url = str(form["action"])
                    if not url_belongs_to_target(action_url, target):
                        rejected.append({"url": _safe_url(action_url), "reason": "form action outside target scope"})
                        continue
                    entry = post_forms.setdefault(action_url, {"source": _safe_url(str(form["source"])), "params": []})
                    entry["params"] = _unique([*entry["params"], *form["params"]])
                    targets.append(action_url)
            if not from_recon and accepted and not targets:
                targets = accepted
            scan_targets = _unique(targets)[:max_urls]
            if scan_targets:
                runs, discoveries, run_errors = _run_discovery(repo_root=repo, target=target, method=method, urls=scan_targets, session=active_session, timeout=timeout, tool_exists=tool_exists)
            else:
                runs, discoveries, run_errors = [], [], []
        all_runs.extend(runs)
        all_discoveries.extend(discoveries)
        errors.extend(run_errors)
    params_dir = repo / "recon" / target_storage_key(resolved_target) / "params"
    params_dir.mkdir(parents=True, exist_ok=True)
    if "GET" in selected_methods:
        names = _unique([*existing_params, *[item["param"] for item in all_discoveries if item["method"] == "GET"]])
        (params_dir / "interesting_params.txt").write_text("\n".join(names) + ("\n" if names else ""), encoding="utf-8")
    if "POST" in selected_methods:
        (params_dir / "post_params.json").write_text(json.dumps(post_forms, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not all_runs and any(
        "neither arjun" in error or "x8 is required" in error
        for error in errors
    ):
        status = "blocked"
    elif errors or rejected:
        status = "partial"
    elif not all_runs and not source_values and from_recon:
        status = "no_input"
    else:
        status = "completed"
    summary_path = params_dir / "summary.json"
    summary: dict[str, Any] = {"schema_version": 1, "target": resolved_target, "method": "+".join(selected_methods), "status": status, "source": "recon" if from_recon else "explicit", "session_id": active_session.session_id(), "scope": {"accepted": len(set(run["endpoint"] for run in all_runs)), "rejected": rejected}, "runs": all_runs, "discoveries": all_discoveries, "post_forms": {key: {"source": value["source"], "params": value["params"]} for key, value in post_forms.items()}, "errors": errors[:100], "counts": {"runs": len(all_runs), "discoveries": len(all_discoveries), "post_forms": len(post_forms), "rejected": len(rejected), "errors": len(errors)}, "artifacts": {"summary": str(summary_path.relative_to(repo))}}
    # Persist the scan facts before the optional queue projection so a queue
    # lock/corruption/permission failure cannot erase the durable summary.
    _atomic_json(summary_path, summary)
    try:
        summary["action_queue"] = _sync_action_queue(repo, target, summary)
    except (OSError, ValueError) as exc:
        summary["status"] = "partial" if summary["status"] == "completed" else summary["status"]
        message = f"action queue sync failed: {type(exc).__name__}: {exc}"
        summary["errors"].append(message)
        summary["counts"]["errors"] += 1
        summary["action_queue"] = {"status": "error", "error": message}
    _atomic_json(summary_path, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scope- and auth-aware hidden HTTP parameter discovery")
    parser.add_argument("legacy_url", nargs="?", help="One URL (legacy shorthand for --url)")
    parser.add_argument("--target", help="Canonical target scope")
    parser.add_argument("--url", action="append", default=[], help="Target-owned endpoint (repeatable)")
    parser.add_argument("-l", "--list", dest="list_path", help="File containing target-owned endpoints")
    parser.add_argument("--from-recon", action="store_true", help="Read endpoints from recon artifacts")
    parser.add_argument("--method", choices=("GET", "POST", "BOTH"), default="GET")
    parser.add_argument("--max-urls", type=int, default=MAX_URLS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    add_cli_args(parser)
    args = parser.parse_args(argv)
    urls = list(args.url)
    if args.legacy_url:
        urls.append(args.legacy_url)
    if args.list_path:
        urls.extend(_read_lines(Path(args.list_path), limit=1000))
    target = args.target or (urls[0] if len(urls) == 1 and "://" in urls[0] else "")
    if not target:
        parser.error("--target is required for a URL list or --from-recon")
    source = None if args.from_recon or not urls else urls
    methods = ("GET", "POST") if args.method == "BOTH" else (args.method,)
    try:
        summary = discover_parameters(repo_root=Path(args.repo_root), target=target, urls=source, methods=methods, session=session_from_args(args), max_urls=args.max_urls, timeout=args.timeout)
    except (OSError, ValueError) as exc:
        print(f"param discovery error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["status"] in {"completed", "no_input"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
